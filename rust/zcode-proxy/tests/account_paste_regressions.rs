use std::{collections::BTreeMap, sync::Arc};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::types::Value as SqlValue;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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

const IMPORT: &str = "/api/accounts/import/paste";
const SESSION: &str = "PUBLIC-paste-session";
const ROOT: &str = "PUBLIC-paste-root-api-key";

type Snapshot = (
    Vec<Vec<SqlValue>>,
    Vec<Value>,
    BTreeMap<i64, (String, String)>,
);

struct Reply {
    status: StatusCode,
    json: Value,
    raw: String,
}

struct Fixture(Arc<AppState>);

impl Fixture {
    fn new(accounts: &[BundleAccount]) -> Self {
        let mut db = store::open(":memory:");
        let vault = Vault::from_secret("PUBLIC paste fixture vault seed").unwrap();
        let encrypted: Vec<_> = accounts
            .iter()
            .cloned()
            .map(|mut a| {
                for field in [
                    &mut a.access_token,
                    &mut a.refresh_token,
                    &mut a.zcode_jwt,
                    &mut a.api_key,
                    &mut a.user_info,
                    &mut a.creds_raw,
                ] {
                    *field = vault.encrypt(field).unwrap();
                }
                a
            })
            .collect();
        store::import_bundle_accounts(&mut db, &vault, &encrypted).unwrap();
        Self::from_state(
            AppState::try_from_db_with_vault(
                ROOT.into(),
                UpstreamUrls {
                    zai: "http://127.0.0.1:1/unused".into(),
                    zai_fallback: "http://127.0.0.1:1/unused".into(),
                },
                db,
                vault,
            )
            .unwrap(),
        )
    }

    fn from_state(state: AppState) -> Self {
        {
            let mut sessions = state.sessions.lock().unwrap();
            sessions.insert(SESSION.into(), now_secs() + 3600);
            sessions.insert("PUBLIC-expired-paste-session".into(), 0);
        }
        Self(Arc::new(state))
    }

    fn reload(self) -> Self {
        let state = Arc::try_unwrap(self.0).ok().unwrap();
        Self::from_state(
            AppState::try_from_db_with_vault(
                state.root_key,
                state.upstream,
                state.db.into_inner().unwrap(),
                state.vault,
            )
            .unwrap(),
        )
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: &str,
        session: Option<&str>,
        origin: Option<&str>,
    ) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
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

    async fn import(&self, body: Value) -> Value {
        let reply = self
            .request("POST", IMPORT, &body.to_string(), Some(SESSION), None)
            .await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "Go-compatible paste import route must accept this credential"
        );
        assert_eq!(reply.json["success"], true);
        assert!(reply.json["account"]["id"].as_i64().unwrap() > 0);
        assert_redacted(&reply, &[body["secret"].as_str().unwrap().trim()]);
        reply.json["account"].clone()
    }

    fn rows(&self) -> Vec<(i64, BundleAccount)> {
        store::load_bundle_accounts(&self.0.db.lock().unwrap(), &self.0.vault).unwrap()
    }

    fn assert_saved(&self, id: i64, expected: &BundleAccount) {
        let rows = self.rows();
        let (_, actual) = rows.iter().find(|(row_id, _)| *row_id == id).unwrap();
        let mut actual_metadata = serde_json::to_value(actual).unwrap();
        let mut expected_metadata = serde_json::to_value(expected).unwrap();
        if expected.device_mid.is_empty() {
            actual_metadata
                .as_object_mut()
                .unwrap()
                .remove("device_mid");
            expected_metadata
                .as_object_mut()
                .unwrap()
                .remove("device_mid");
        }
        assert_eq!(
            actual_metadata, expected_metadata,
            "persisted full account metadata"
        );
        let live = self.0.accounts.lock().unwrap();
        let live = live.iter().find(|a| a.id == id).unwrap();
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
                |row| (0..6).map(|i| row.get(i)).collect(),
            )
            .unwrap();
        for (encrypted, plain) in stored.iter().zip([
            &expected.access_token,
            &expected.refresh_token,
            &expected.zcode_jwt,
            &expected.api_key,
            &expected.user_info,
            &expected.creds_raw,
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
        let mut stmt = db.prepare("SELECT * FROM accounts ORDER BY id").unwrap();
        let columns = stmt.column_count();
        let stored = stmt
            .query_map([], |row| {
                (0..columns)
                    .map(|i| row.get(i))
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
            .map(|a| {
                json!({
                    "id":a.id,"email":a.email,"provider":a.provider,"enabled":a.enabled,
                    "status":a.status,"cooling_until":a.cooling_until,
                    "paid_cooling_until":a.paid_cooling_until,"paid_fallback":a.paid_fallback,
                    "zcode_jwt":a.zcode_jwt,"api_key":a.api_key,
                    "account_group":a.account_group,"remaining":a.remaining,"priority":a.priority,
                })
            })
            .collect();
        let credentials = self
            .0
            .creds
            .lock()
            .unwrap()
            .iter()
            .map(|(&id, c)| (id, (c.zcode_jwt.clone(), c.api_key.clone())))
            .collect();
        (stored, accounts, credentials)
    }
}

// Claims are deliberately unsigned: paste import reads identity, not authentication validity.
fn jwt(claims: Value) -> String {
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()),
        URL_SAFE_NO_PAD.encode(b"PUBLIC-not-a-real-signature"),
    )
}

fn hash_identity(provider: &str, secret: &str) -> String {
    let digest = Sha256::digest(format!("{provider}:{secret}"));
    let suffix: String = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{provider}-{suffix}")
}

fn pasted(provider: &str, user_id: &str, secret: &str, auth_type: &str) -> BundleAccount {
    BundleAccount {
        user_id: user_id.into(),
        provider: provider.into(),
        auth_type: auth_type.into(),
        zcode_jwt: if auth_type == "jwt" {
            secret.into()
        } else {
            String::new()
        },
        api_key: if auth_type == "apikey" {
            secret.into()
        } else {
            String::new()
        },
        remark: "粘贴导入".into(),
        ..Default::default()
    }
}

fn assert_redacted(reply: &Reply, secrets: &[&str]) {
    for secret in secrets.iter().filter(|s| !s.is_empty()) {
        assert!(!reply.raw.contains(*secret), "response leaked a credential");
    }
    assert!(!reply.raw.contains("vault1:"), "response leaked ciphertext");
    fn visit(value: &Value) {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    assert!(
                        ![
                            "secret",
                            "zcode_jwt",
                            "api_key",
                            "access_token",
                            "refresh_token",
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

#[tokio::test]
async fn paste_jwt_reads_user_id_then_sub_without_email_or_signature_validation() {
    let fixture = Fixture::new(&[]);
    for (claims, user_id) in [
        (
            json!({"user_id":"PUBLIC-paste-user-a","sub":"PUBLIC-not-the-identity",
                "email":"shared@example.invalid","exp":1}),
            "PUBLIC-paste-user-a",
        ),
        (
            json!({"user_id":"","sub":"PUBLIC-paste-user-b","email":"shared@example.invalid"}),
            "PUBLIC-paste-user-b",
        ),
    ] {
        let secret = jwt(claims);
        let public = fixture
            .import(json!({"provider":"","name":"  PUBLIC pasted name \t",
                "secret":format!(" \n{secret}\t"),"group":"eu,failover"}))
            .await;
        assert_eq!(public["user_id"], user_id);
        assert_eq!(public["provider"], "zai");
        assert_eq!(public["email"], "");
        assert_eq!(public["display_name"], "PUBLIC pasted name");
        assert_eq!(public["auth_type"], "jwt");
        assert_eq!(public["has_jwt"], true);
        assert_eq!(public["has_api_key"], false);
        assert_eq!(public["group"], "eu,failover");
        let mut expected = pasted("zai", user_id, &secret, "jwt");
        expected.display_name = "PUBLIC pasted name".into();
        expected.account_group = "eu,failover".into();
        fixture.assert_saved(public["id"].as_i64().unwrap(), &expected);
    }
    assert_eq!(
        fixture.rows().len(),
        2,
        "email claims must not merge distinct identities"
    );
}

#[tokio::test]
async fn paste_shape_detection_is_zai_only_and_hash_fallback_accepts_opaque_credentials() {
    let fixture = Fixture::new(&[]);
    let shaped = jwt(json!({"user_id":"PUBLIC-ignore-for-other-providers"}));
    let claimless = jwt(json!({"email":"ignored@example.invalid"}));
    for (provider, secret, auth_type) in [
        ("", "PUBLIC-opaque-api-key", "apikey"),
        ("arbitrary-provider", shaped.as_str(), "apikey"),
        ("ZAI", shaped.as_str(), "apikey"),
        ("zai", "e30.bm90LWpzb24.PUBLICsignature", "jwt"),
        ("zai", claimless.as_str(), "jwt"),
        ("zai", "PUBLIC.two-segments", "apikey"),
        ("zai", "PUBLIC.e30=.signature", "apikey"),
    ] {
        let public = fixture
            .import(json!({"provider":provider,"secret":format!(" \t{secret}\n")}))
            .await;
        let provider = if provider.is_empty() { "zai" } else { provider };
        let user_id = hash_identity(provider, secret);
        assert_eq!(public["user_id"], user_id);
        assert_eq!(public["provider"], provider);
        assert_eq!(public["email"], "");
        assert_eq!(public["auth_type"], auth_type);
        assert_eq!(public["has_jwt"], auth_type == "jwt");
        assert_eq!(public["has_api_key"], auth_type == "apikey");
        fixture.assert_saved(
            public["id"].as_i64().unwrap(),
            &pasted(provider, &user_id, secret, auth_type),
        );
    }
    assert_eq!(fixture.rows().len(), 7);
}

#[tokio::test]
async fn paste_reuses_identity_preserves_full_metadata_and_survives_reload_encrypted() {
    let first = BundleAccount {
        user_id: "PUBLIC-existing-paste-a".into(),
        email: "shared@example.invalid".into(),
        display_name: "PUBLIC original name".into(),
        provider: "zai".into(),
        auth_type: "jwt".into(),
        access_token: "PUBLIC-preserved-access-token".into(),
        refresh_token: "PUBLIC-preserved-refresh-token".into(),
        zcode_jwt: "PUBLIC-original-jwt".into(),
        api_key: "PUBLIC-preserved-api-key".into(),
        user_info: "{\"PUBLIC\":\"preserved-user-info\"}".into(),
        device_mid: "PUBLIC-preserved-device-mid".into(),
        creds_raw: "PUBLIC-preserved-credentials-snapshot".into(),
        account_group: "original".into(),
        remark: "PUBLIC original remark".into(),
    };
    let second = BundleAccount {
        user_id: "PUBLIC-existing-paste-b".into(),
        zcode_jwt: "PUBLIC-survivor-jwt".into(),
        ..first.clone()
    };
    let fixture = Fixture::new(&[first.clone(), second.clone()]);
    let rows = fixture.rows();
    let id_a = rows
        .iter()
        .find(|(_, a)| a.user_id == first.user_id)
        .unwrap()
        .0;
    let id_b = rows
        .iter()
        .find(|(_, a)| a.user_id == second.user_id)
        .unwrap()
        .0;
    let secret = jwt(json!({"user_id":first.user_id,"email":"different@example.invalid"}));
    let mut expected = first.clone();
    expected.zcode_jwt = secret.clone();
    expected.display_name = "PUBLIC replacement name".into();
    expected.account_group = "replacement".into();
    expected.remark = "粘贴导入".into();
    for name in [" PUBLIC replacement name ", ""] {
        let public = fixture
            .import(json!({"provider":"zai","name":name,"secret":secret,
                "group":if name.is_empty() { "" } else { "replacement" }}))
            .await;
        assert_eq!(
            public["id"], id_a,
            "upsert must return the matched account ID"
        );
        fixture.assert_saved(id_a, &expected);
        fixture.assert_saved(id_b, &second);
        assert_eq!(
            fixture.rows().len(),
            2,
            "repeat import must not insert a duplicate"
        );
    }
    let key = "PUBLIC-repeatable-api-key";
    let body = json!({"secret":key});
    let key_id = fixture.import(body.clone()).await["id"].as_i64().unwrap();
    assert_eq!(fixture.import(body).await["id"], key_id);
    let expected_key = pasted("zai", &hash_identity("zai", key), key, "apikey");
    let fixture = fixture.reload();
    assert_eq!(fixture.rows().len(), 3);
    fixture.assert_saved(id_a, &expected);
    fixture.assert_saved(id_b, &second);
    fixture.assert_saved(key_id, &expected_key);
    let reply = fixture
        .request("GET", "/api/accounts", "", Some(SESSION), None)
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json["accounts"].as_array().unwrap().len(), 3);
    assert_redacted(
        &reply,
        &[
            &secret,
            key,
            &first.access_token,
            &first.refresh_token,
            &first.api_key,
            &first.user_info,
            &first.creds_raw,
            &second.zcode_jwt,
        ],
    );
}

#[tokio::test]
async fn paste_rejects_bad_bodies_and_requires_session_and_same_origin_without_writes() {
    let fixture = Fixture::new(&[pasted(
        "zai",
        "PUBLIC-untouched-paste-user",
        "PUBLIC-untouched-paste-key",
        "apikey",
    )]);
    let before = fixture.snapshot();
    for body in [
        "",
        "{",
        "[]",
        "{}",
        "null",
        r#"{"secret":""}"#,
        r#"{"secret":" \t "}"#,
        "{\"secret\":123}",
        "{\"provider\":123,\"secret\":\"PUBLIC-rejected-key\"}",
        "{\"secret\":\"PUBLIC-rejected-key\",\"name\":false}",
        "{\"secret\":\"PUBLIC-rejected-key\",\"group\":{}}",
        "{\"secret\":\"PUBLIC-rejected-key\",",
    ] {
        let reply = fixture
            .request("POST", IMPORT, body, Some(SESSION), None)
            .await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "invalid paste request body"
        );
        assert_redacted(&reply, &["PUBLIC-rejected-key"]);
        assert_eq!(
            fixture.snapshot(),
            before,
            "rejected body changed account state"
        );
    }
    let body = json!({"secret":"PUBLIC-session-gated-key"}).to_string();
    for session in [
        None,
        Some("PUBLIC-invalid-session"),
        Some("PUBLIC-expired-paste-session"),
    ] {
        let reply = fixture.request("POST", IMPORT, &body, session, None).await;
        assert_eq!(
            reply.status,
            StatusCode::UNAUTHORIZED,
            "root bearer is not an admin session"
        );
        assert_redacted(&reply, &["PUBLIC-session-gated-key"]);
        assert_eq!(fixture.snapshot(), before);
    }
    for origin in [
        "https://other.example.invalid",
        "http://localhost:8081",
        "null",
    ] {
        let reply = fixture
            .request("POST", IMPORT, &body, Some(SESSION), Some(origin))
            .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "unsafe origin");
        assert_redacted(&reply, &["PUBLIC-session-gated-key"]);
        assert_eq!(fixture.snapshot(), before);
    }
    let reply = fixture
        .request(
            "POST",
            IMPORT,
            &body,
            Some(SESSION),
            Some("http://localhost:8080"),
        )
        .await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "matching origin must allow paste import"
    );
    assert_eq!(reply.json["success"], true);
    assert_redacted(&reply, &["PUBLIC-session-gated-key"]);
    assert_eq!(fixture.rows().len(), 2);
}
