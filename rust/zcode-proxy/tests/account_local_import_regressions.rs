use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::types::Value as SqlValue;
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_proxy::{
    account_bundle::BundleAccount,
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
    store,
    vault::Vault,
};

const IMPORT: &str = "/api/accounts/import/local";
const SESSION: &str = "PUBLIC-local-import-session";
const ROOT: &str = "PUBLIC-local-import-root-key";

type Snapshot = (
    Vec<Vec<SqlValue>>,
    Vec<Value>,
    BTreeMap<i64, (String, String)>,
);

struct LocalFiles(PathBuf);

impl LocalFiles {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "zcode-local-import-{}-{:032x}",
            std::process::id(),
            rand::random::<u128>()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn credentials(&self) -> PathBuf {
        self.0.join("credentials.json")
    }

    fn write(&self, credentials: &str, config: Option<&str>, telemetry: Option<&str>) {
        fs::write(self.credentials(), credentials).unwrap();
        for (name, value) in [("config.json", config), ("telemetry-state.json", telemetry)] {
            let path = self.0.join(name);
            if let Some(value) = value {
                fs::write(path, value).unwrap();
            } else if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
    }

    fn assert_redacted(&self, reply: &Reply, secrets: &[&str]) {
        for secret in secrets.iter().filter(|secret| !secret.is_empty()) {
            assert!(
                !reply.raw.contains(secret),
                "response leaked credential data"
            );
        }
        assert!(
            !reply.raw.contains(self.0.to_str().unwrap()),
            "response leaked the local credential path"
        );
        assert!(!reply.raw.contains("vault1:"), "response leaked ciphertext");
        fn visit(value: &Value) {
            match value {
                Value::Object(object) => {
                    for (key, value) in object {
                        assert!(
                            ![
                                "access_token",
                                "refresh_token",
                                "zcode_jwt",
                                "api_key",
                                "user_info",
                                "creds_raw",
                            ]
                            .contains(&key.as_str()),
                            "response exposed credential field {key}"
                        );
                        visit(value);
                    }
                }
                Value::Array(values) => values.iter().for_each(visit),
                _ => {}
            }
        }
        visit(&reply.json);
    }
}

impl Drop for LocalFiles {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Reply {
    status: StatusCode,
    json: Value,
    raw: String,
}

struct Fixture(Arc<AppState>);

impl Fixture {
    fn new(files: &LocalFiles, accounts: &[BundleAccount]) -> Self {
        let mut db = store::open(":memory:");
        let vault = Vault::from_secret("PUBLIC local import fixture vault seed").unwrap();
        let encrypted: Vec<_> = accounts
            .iter()
            .cloned()
            .map(|mut account| {
                for field in [
                    &mut account.access_token,
                    &mut account.refresh_token,
                    &mut account.zcode_jwt,
                    &mut account.api_key,
                    &mut account.user_info,
                    &mut account.creds_raw,
                ] {
                    *field = vault.encrypt(field).unwrap();
                }
                account
            })
            .collect();
        store::import_bundle_accounts(&mut db, &vault, &encrypted).unwrap();
        let mut state = AppState::try_from_db_with_vault(
            ROOT.into(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
            db,
            vault,
        )
        .unwrap();
        state.local_credentials_path = Some(files.credentials());
        Self::from_state(state)
    }

    fn from_state(state: AppState) -> Self {
        {
            let mut sessions = state.sessions.lock().unwrap();
            sessions.insert(SESSION.into(), now_secs() + 3600);
            sessions.insert("PUBLIC-local-expired-session".into(), 0);
        }
        Self(Arc::new(state))
    }

    fn reload(self, files: &LocalFiles) -> Self {
        let state = Arc::try_unwrap(self.0).ok().unwrap();
        let mut state = AppState::try_from_db_with_vault(
            state.root_key,
            state.upstream,
            state.db.into_inner().unwrap(),
            state.vault,
        )
        .unwrap();
        state.local_credentials_path = Some(files.credentials());
        Self::from_state(state)
    }

    async fn request(&self, body: &str, session: Option<&str>, origin: Option<&str>) -> Reply {
        let mut request = Request::builder()
            .method("POST")
            .uri(IMPORT)
            .header("host", "localhost:8080")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {ROOT}"));
        if let Some(session) = session {
            request = request.header("cookie", format!("{SESSION_COOKIE}={session}"));
        }
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        let response = build_router(self.0.clone())
            .oneshot(request.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        Reply {
            status,
            json: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            raw: String::from_utf8(bytes.to_vec()).unwrap(),
        }
    }

    async fn import(&self, files: &LocalFiles, body: &str, secrets: &[&str]) -> Value {
        let reply = self.request(body, Some(SESSION), None).await;
        assert_eq!(reply.status, StatusCode::OK, "local import must be mounted");
        assert_eq!(reply.json["success"], true);
        files.assert_redacted(&reply, secrets);
        let account = reply.json["account"].clone();
        assert!(account["id"].as_i64().unwrap() > 0);
        account
    }

    fn rows(&self) -> Vec<(i64, BundleAccount)> {
        store::load_bundle_accounts(&self.0.db.lock().unwrap(), &self.0.vault).unwrap()
    }

    fn assert_saved(&self, id: i64, expected: &BundleAccount) {
        let rows = self.rows();
        let actual = &rows.iter().find(|(row_id, _)| *row_id == id).unwrap().1;
        let mut actual_metadata = serde_json::to_value(actual).unwrap();
        let mut expected_metadata = serde_json::to_value(expected).unwrap();
        actual_metadata.as_object_mut().unwrap().remove("creds_raw");
        expected_metadata
            .as_object_mut()
            .unwrap()
            .remove("creds_raw");
        assert_eq!(actual_metadata, expected_metadata, "full account metadata");
        assert_eq!(
            serde_json::from_str::<Value>(&actual.creds_raw).unwrap(),
            serde_json::from_str::<Value>(&expected.creds_raw).unwrap(),
            "snapshot must preserve the exact source file strings"
        );
        let live = self.0.accounts.lock().unwrap();
        let live = live.iter().find(|account| account.id == id).unwrap();
        assert_eq!(live.email, expected.email);
        assert_eq!(live.provider, expected.provider);
        assert_eq!(live.account_group, expected.account_group);
        assert_eq!(live.zcode_jwt, expected.zcode_jwt);
        assert_eq!(live.api_key, expected.api_key);
        assert!(live.enabled);
        assert_eq!(live.status, "active");
        let creds = self.0.creds.lock().unwrap();
        assert_eq!(creds[&id].zcode_jwt, expected.zcode_jwt);
        assert_eq!(creds[&id].api_key, expected.api_key);
        let db = self.0.db.lock().unwrap();
        let stored: Vec<String> = db
            .query_row(
                "SELECT access_token,refresh_token,zcode_jwt,api_key,user_info,creds_raw
                 FROM accounts WHERE id=?1",
                [id],
                |row| (0..6).map(|index| row.get(index)).collect(),
            )
            .unwrap();
        for (encrypted, plain) in stored.iter().zip([
            &actual.access_token,
            &actual.refresh_token,
            &actual.zcode_jwt,
            &actual.api_key,
            &actual.user_info,
            &actual.creds_raw,
        ]) {
            assert_eq!(self.0.vault.decrypt(encrypted).unwrap(), *plain);
            if !plain.is_empty() {
                assert!(encrypted.starts_with("vault1:"), "credential at rest");
                assert!(!encrypted.contains(plain.as_str()));
            }
        }
    }

    fn snapshot(&self) -> Snapshot {
        let db = self.0.db.lock().unwrap();
        let mut statement = db.prepare("SELECT * FROM accounts ORDER BY id").unwrap();
        let columns = statement.column_count();
        let stored = statement
            .query_map([], |row| {
                (0..columns)
                    .map(|index| row.get(index))
                    .collect::<rusqlite::Result<Vec<SqlValue>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let accounts = self
            .0
            .accounts
            .lock()
            .unwrap()
            .iter()
            .map(|account| {
                json!({
                    "id":account.id,"email":account.email,"provider":account.provider,
                    "enabled":account.enabled,"status":account.status,
                    "cooling_until":account.cooling_until,
                    "paid_cooling_until":account.paid_cooling_until,
                    "paid_fallback":account.paid_fallback,"zcode_jwt":account.zcode_jwt,
                    "api_key":account.api_key,"account_group":account.account_group,
                    "remaining":account.remaining,"priority":account.priority,
                })
            })
            .collect();
        let credentials = self
            .0
            .creds
            .lock()
            .unwrap()
            .iter()
            .map(|(&id, creds)| (id, (creds.zcode_jwt.clone(), creds.api_key.clone())))
            .collect();
        (stored, accounts, credentials)
    }
}

fn jwt(claims: Value) -> String {
    format!(
        "e30.{}.PUBLIC-not-a-real-signature",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    )
}

fn snapshot(credentials: &str, config: Option<&str>) -> String {
    let mut raw = json!({"credentials.json": credentials});
    if let Some(config) = config {
        raw["config.json"] = config.into();
    }
    raw.to_string()
}

#[tokio::test]
async fn local_import_reads_go_flat_credentials_siblings_and_encrypts_full_metadata_on_reload() {
    let files = LocalFiles::new();
    let token = jwt(json!({"user_id":"PUBLIC-jwt-not-the-profile-identity"}));
    let user_info = json!({
        "user_id":"PUBLIC-local-profile","id":"PUBLIC-not-the-user-id",
        "email":"local@example.invalid","name":"PUBLIC local name",
        "username":"PUBLIC lower-precedence-name","extra":"PUBLIC private profile metadata",
    })
    .to_string();
    let credentials = format!(
        " {}\n",
        json!({
            "zcodejwttoken":token,"oauth:zai:access_token":"PUBLIC-local-access",
            "oauth:zai:refresh_token":"PUBLIC-local-refresh-not-imported-by-go",
            "oauth:zai:user_info":user_info,
        })
    );
    let config = r#" {"provider":{"zai-coding-plan":{"options":{"apiKey":"PUBLIC-local-api-key"}},"other":{"options":{"apiKey":"PUBLIC-not-coding-plan"}}}} 
"#;
    files.write(
        &credentials,
        Some(config),
        Some(r#"{"deviceMid":"PUBLIC-local-device"}"#),
    );
    let fixture = Fixture::new(&files, &[]);
    let public = fixture
        .import(
            &files,
            r#"{"group":"eu,failover"}"#,
            &[
                &token,
                &user_info,
                "PUBLIC-local-access",
                "PUBLIC-local-api-key",
                &credentials,
            ],
        )
        .await;
    assert_eq!(public["user_id"], "PUBLIC-local-profile");
    assert_eq!(public["provider"], "zai");
    assert_eq!(public["email"], "local@example.invalid");
    assert_eq!(public["display_name"], "PUBLIC local name");
    assert_eq!(public["group"], "eu,failover");
    assert_eq!(public["auth_type"], "jwt");
    assert_eq!(public["has_jwt"], true);
    assert_eq!(public["has_api_key"], true);
    let expected = BundleAccount {
        user_id: "PUBLIC-local-profile".into(),
        email: "local@example.invalid".into(),
        display_name: "PUBLIC local name".into(),
        provider: "zai".into(),
        auth_type: "jwt".into(),
        access_token: "PUBLIC-local-access".into(),
        zcode_jwt: token,
        api_key: "PUBLIC-local-api-key".into(),
        user_info,
        device_mid: "PUBLIC-local-device".into(),
        creds_raw: snapshot(&credentials, Some(config)),
        account_group: "eu,failover".into(),
        remark: "本地客户端导入".into(),
        ..Default::default()
    };
    let id = public["id"].as_i64().unwrap();
    fixture.assert_saved(id, &expected);
    fixture.reload(&files).assert_saved(id, &expected);
}

#[tokio::test]
async fn local_import_uses_identity_fallbacks_and_returns_the_upserted_id_without_erasing_metadata()
{
    let files = LocalFiles::new();
    let first = BundleAccount {
        user_id: "PUBLIC-local-existing".into(),
        email: "shared@example.invalid".into(),
        display_name: "PUBLIC preserved name".into(),
        provider: "zai".into(),
        auth_type: "jwt".into(),
        access_token: "PUBLIC-preserved-local-access".into(),
        refresh_token: "PUBLIC-preserved-local-refresh".into(),
        zcode_jwt: "PUBLIC-old-local-jwt".into(),
        api_key: "PUBLIC-preserved-local-key".into(),
        user_info: r#"{"PUBLIC":"preserved private profile"}"#.into(),
        device_mid: "PUBLIC-preserved-local-device".into(),
        creds_raw: snapshot("PUBLIC previous source", None),
        account_group: "original".into(),
        remark: "PUBLIC previous remark".into(),
    };
    let second = BundleAccount {
        user_id: "PUBLIC-local-unrelated-last-insert".into(),
        ..first.clone()
    };
    let fixture = Fixture::new(&files, &[first.clone(), second.clone()]);
    let rows = fixture.rows();
    let first_id = rows[0].0;
    let second_id = rows[1].0;
    let token = jwt(json!({"user_id":first.user_id,"sub":"PUBLIC-not-the-user-id"}));
    let credentials = json!({"zcodejwttoken":token}).to_string();
    files.write(&credentials, None, None);
    let mut expected = first;
    expected.zcode_jwt = token.clone();
    expected.creds_raw = snapshot(&credentials, None);
    expected.remark = "本地客户端导入".into();
    for body in ["", "{}"] {
        let public = fixture.import(&files, body, &[&token, &credentials]).await;
        assert_eq!(
            public["id"], first_id,
            "return the natural-key match, not last insert ID"
        );
        fixture.assert_saved(first_id, &expected);
        fixture.assert_saved(second_id, &second);
        assert_eq!(
            fixture.rows().len(),
            2,
            "repeat import must not create a duplicate"
        );
    }
    for (provider, profile, token_claims, access_claims, user_id, name) in [
        (
            "custom-provider",
            json!({"id":"PUBLIC-local-profile-id","username":"PUBLIC username"}),
            json!({"sub":"PUBLIC-profile-must-win"}),
            Value::Null,
            "PUBLIC-local-profile-id",
            "PUBLIC username",
        ),
        (
            "zai",
            json!({"displayName":"PUBLIC displayName"}),
            json!({"sub":"PUBLIC-local-jwt-sub"}),
            Value::Null,
            "PUBLIC-local-jwt-sub",
            "PUBLIC displayName",
        ),
        (
            "zai",
            json!({}),
            Value::Null,
            json!({"user_id":"PUBLIC-local-access-id","sub":"PUBLIC-access-not-the-id"}),
            "PUBLIC-local-access-id",
            "",
        ),
        (
            "zai",
            json!({}),
            Value::Null,
            json!({"sub":"PUBLIC-local-access-sub"}),
            "PUBLIC-local-access-sub",
            "",
        ),
    ] {
        let token = if token_claims.is_null() {
            String::new()
        } else {
            jwt(token_claims)
        };
        let access = if access_claims.is_null() {
            String::new()
        } else {
            jwt(access_claims)
        };
        let profile = profile.to_string();
        let credentials = json!({
            "oauth:active_provider":provider,"zcodejwttoken":token,
            format!("oauth:{provider}:access_token"):access,
            format!("oauth:{provider}:user_info"):profile,
        })
        .to_string();
        files.write(
            &credentials,
            None,
            Some(r#"{"deviceMid":"PUBLIC-fallback-device"}"#),
        );
        let public = fixture.import(&files, "{}", &[&token, &access]).await;
        assert_eq!(public["user_id"], user_id);
        assert_eq!(public["provider"], provider);
        assert_eq!(public["display_name"], name);
        assert_eq!(
            public["auth_type"],
            if token.is_empty() { "apikey" } else { "jwt" }
        );
        fixture.assert_saved(
            public["id"].as_i64().unwrap(),
            &BundleAccount {
                user_id: user_id.into(),
                display_name: name.into(),
                provider: provider.into(),
                auth_type: if token.is_empty() {
                    "apikey".into()
                } else {
                    "jwt".into()
                },
                zcode_jwt: token,
                access_token: access,
                user_info: profile,
                device_mid: "PUBLIC-fallback-device".into(),
                creds_raw: snapshot(&credentials, None),
                remark: "本地客户端导入".into(),
                ..Default::default()
            },
        );
    }
    assert_eq!(fixture.rows().len(), 6);
}

#[tokio::test]
async fn local_import_requires_an_admin_session_and_same_origin_before_mutation() {
    let files = LocalFiles::new();
    let token = jwt(json!({"sub":"PUBLIC-local-session-user"}));
    files.write(&json!({"zcodejwttoken":token}).to_string(), None, None);
    let fixture = Fixture::new(&files, &[]);
    let before = fixture.snapshot();
    for session in [
        None,
        Some("PUBLIC-invalid-local-session"),
        Some("PUBLIC-local-expired-session"),
    ] {
        let reply = fixture.request("{}", session, None).await;
        assert_eq!(
            reply.status,
            StatusCode::UNAUTHORIZED,
            "root bearer is not an admin session"
        );
        files.assert_redacted(&reply, &[&token]);
        assert_eq!(fixture.snapshot(), before);
    }
    for origin in [
        "https://other.example.invalid",
        "http://localhost:8081",
        "null",
    ] {
        let reply = fixture.request("{}", Some(SESSION), Some(origin)).await;
        assert_eq!(
            reply.status,
            StatusCode::FORBIDDEN,
            "unsafe mutation Origin"
        );
        files.assert_redacted(&reply, &[&token]);
        assert_eq!(fixture.snapshot(), before);
    }
    let reply = fixture
        .request("{}", Some(SESSION), Some("http://localhost:8080"))
        .await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "matching Origin must allow local import"
    );
    assert_eq!(reply.json["success"], true);
    files.assert_redacted(&reply, &[&token]);
    assert_eq!(fixture.rows().len(), 1);
}

#[tokio::test]
async fn local_import_rejects_bad_requests_missing_files_and_unusable_credentials_without_leaks_or_writes(
) {
    let files = LocalFiles::new();
    let token = jwt(json!({"sub":"PUBLIC-local-rejected-user"}));
    let valid = json!({"zcodejwttoken":token}).to_string();
    files.write(&valid, None, None);
    let fixture = Fixture::new(&files, &[]);
    let before = fixture.snapshot();
    for body in [
        "{",
        "[]",
        r#"{"group":false}"#,
        r#"{"group":{}}"#,
        r#"{"group":"PUBLIC-rejected-group","#,
    ] {
        let reply = fixture.request(body, Some(SESSION), None).await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "invalid local import request"
        );
        files.assert_redacted(&reply, &[&token, "PUBLIC-rejected-group"]);
        assert_eq!(fixture.snapshot(), before);
    }
    fs::remove_file(files.credentials()).unwrap();
    let reply = fixture.request("{}", Some(SESSION), None).await;
    assert_eq!(
        reply.status,
        StatusCode::BAD_REQUEST,
        "missing local credentials"
    );
    files.assert_redacted(&reply, &["No such file", "os error", "credentials.json"]);
    assert_eq!(fixture.snapshot(), before);
    for credentials in [
        "{",
        "[]",
        r#"{"zcodejwttoken":123}"#,
        "{}",
        r#"{"oauth:zai:user_info":"{\"user_id\":\"PUBLIC-id-with-no-login\"}"}"#,
        r#"{"zcodejwttoken":"PUBLIC-no-identity-login"}"#,
        r#"{"zcodejwttoken":"enc:v1:PUBLIC-corrupt-ciphertext","oauth:zai:user_info":"{\"user_id\":\"PUBLIC-must-not-admit-ciphertext\"}"}"#,
    ] {
        files.write(credentials, None, None);
        let reply = fixture.request("{}", Some(SESSION), None).await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "invalid or unusable local credentials"
        );
        assert!(reply.json.is_object(), "errors must be sanitized JSON");
        files.assert_redacted(
            &reply,
            &[
                "PUBLIC-no-identity-login",
                "PUBLIC-corrupt-ciphertext",
                "PUBLIC-id-with-no-login",
                "PUBLIC-must-not-admit-ciphertext",
                "SQLITE",
                "accounts.",
                "at line",
                "at column",
            ],
        );
        assert_eq!(fixture.snapshot(), before, "rejected import changed state");
    }
}
