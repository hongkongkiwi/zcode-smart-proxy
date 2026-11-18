use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use rusqlite::types::Value as SqlValue;
use serde::Deserialize;
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
    store,
    vault::Vault,
};

const SESSION: &str = "PUBLIC-desktop-crypto-session";
const API_KEY: &str = "PUBLIC-desktop-coding-plan-key";
const VAULT_SECRET: &str = "PUBLIC separate database vault secret";

#[derive(Deserialize)]
struct Vector {
    value: String,
    plaintext: String,
}

#[derive(Deserialize)]
struct Invalid {
    id: String,
    value: String,
    wrong_secret: bool,
}

#[derive(Deserialize)]
struct Vectors {
    secret: String,
    wrong_secret: String,
    vectors: BTreeMap<String, Vector>,
    invalid: Vec<Invalid>,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("fixtures/desktop_enc_v1.json")).unwrap()
}

struct LocalFiles(PathBuf);

impl LocalFiles {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "zcode-desktop-crypto-{}-{:032x}",
            std::process::id(),
            rand::random::<u128>()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn credentials(&self) -> PathBuf {
        self.0.join("credentials.json")
    }

    fn write(&self, credentials: &Value) -> String {
        let raw = format!(" {credentials}\n");
        fs::write(self.credentials(), &raw).unwrap();
        raw
    }
}

impl Drop for LocalFiles {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn state(files: &LocalFiles, secret: &str) -> Arc<AppState> {
    let mut state = AppState::try_from_db_with_vault(
        "PUBLIC-desktop-crypto-root".into(),
        UpstreamUrls {
            zai: "http://127.0.0.1:1/unused".into(),
            zai_fallback: "http://127.0.0.1:1/unused".into(),
        },
        store::open(":memory:"),
        Vault::from_secret(VAULT_SECRET).unwrap(),
    )
    .unwrap();
    state.local_credentials_path = Some(files.credentials());
    state.local_credentials_secret = Some(secret.to_owned().into());
    state
        .sessions
        .lock()
        .unwrap()
        .insert(SESSION.into(), now_secs() + 3600);
    Arc::new(state)
}

async fn import(state: &Arc<AppState>) -> (StatusCode, Value, String) {
    let response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/accounts/import/local")
                .header("host", "localhost:8080")
                .header("content-type", "application/json")
                .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
                .body(Body::from(r#"{"group":"PUBLIC-desktop-group"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let raw = String::from_utf8(bytes.to_vec()).unwrap();
    (status, serde_json::from_str(&raw).unwrap(), raw)
}

fn assert_redacted(raw: &str, files: &LocalFiles, vectors: &Vectors) {
    for secret in [
        vectors.secret.as_str(),
        vectors.wrong_secret.as_str(),
        VAULT_SECRET,
        API_KEY,
        "PUBLIC profile metadata",
        files.0.to_str().unwrap(),
        "enc:v1:",
        "vault1:",
    ] {
        assert!(!raw.contains(secret), "response leaked private import data");
    }
    for id in ["jwt", "access", "access_jwt", "profile"] {
        assert!(
            !raw.contains(&vectors.vectors[id].plaintext),
            "response leaked decrypted {id}"
        );
    }
    for field in [
        "access_token",
        "refresh_token",
        "zcode_jwt",
        "api_key",
        "user_info",
        "creds_raw",
    ] {
        assert!(
            !raw.contains(&format!("\"{field}\":")),
            "response exposed credential field {field}"
        );
    }
}

fn credentials(vectors: &Vectors, encrypted: bool) -> Value {
    let value = |id: &str| {
        let vector = &vectors.vectors[id];
        if encrypted {
            vector.value.clone()
        } else {
            vector.plaintext.clone()
        }
    };
    json!({
        "oauth:active_provider": value("provider"),
        "zcodejwttoken": value("jwt"),
        "oauth:public-provider:access_token": value("access"),
        "oauth:public-provider:user_info": value("profile"),
        // Go imports neither refresh tokens nor unselected providers from this flat map.
        "oauth:public-provider:refresh_token": "enc:v1:PUBLIC-unselected-refresh",
        "oauth:zai:access_token": "enc:v1:PUBLIC-unselected-provider",
    })
}

fn saved_credentials(state: &AppState) -> Vec<String> {
    state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT access_token,refresh_token,zcode_jwt,api_key,user_info,creds_raw FROM accounts",
            [],
            |row| (0..6).map(|index| row.get(index)).collect(),
        )
        .unwrap()
}

type Snapshot = (
    u64,
    Vec<Vec<SqlValue>>,
    Vec<Value>,
    BTreeMap<i64, (String, String)>,
);

fn snapshot(state: &AppState) -> Snapshot {
    let db = state.db.lock().unwrap();
    let mut statement = db.prepare("SELECT * FROM accounts ORDER BY id").unwrap();
    let columns = statement.column_count();
    let rows = statement
        .query_map([], |row| {
            (0..columns)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<SqlValue>>>()
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    let accounts = state.accounts.lock().unwrap().iter().map(|a| json!({
        "id":a.id,"email":a.email,"provider":a.provider,"enabled":a.enabled,
        "status":a.status,"cooling_until":a.cooling_until,"paid_cooling_until":a.paid_cooling_until,
        "paid_fallback":a.paid_fallback,"zcode_jwt":a.zcode_jwt,"api_key":a.api_key,
        "group":a.account_group,"remaining":a.remaining,"priority":a.priority,
    })).collect();
    let creds = state
        .creds
        .lock()
        .unwrap()
        .iter()
        .map(|(&id, c)| (id, (c.zcode_jwt.clone(), c.api_key.clone())))
        .collect();
    (db.total_changes(), rows, accounts, creds)
}

#[tokio::test]
async fn go_encrypted_local_credentials_decode_selected_provider_then_reencrypt_all_storage_fields()
{
    let vectors = vectors();
    let files = LocalFiles::new();
    let source = files.write(&credentials(&vectors, true));
    let config = format!(
        " {{\"provider\":{{\"public-provider-coding-plan\":{{\"options\":{{\"apiKey\":\"{API_KEY}\"}}}}}}}}\n"
    );
    fs::write(files.0.join("config.json"), &config).unwrap();
    let state = state(&files, &vectors.secret);
    let (status, reply, raw) = import(&state).await;
    assert_eq!(status, StatusCode::OK, "valid Go enc:v1 must import");
    assert_eq!(reply["success"], true);
    assert_eq!(reply["account"]["user_id"], "PUBLIC-desktop-profile");
    assert_eq!(reply["account"]["provider"], "public-provider");
    assert_eq!(reply["account"]["email"], "desktop@example.invalid");
    assert_eq!(reply["account"]["display_name"], "PUBLIC desktop name");
    assert_eq!(reply["account"]["has_jwt"], true);
    assert_eq!(reply["account"]["has_access_token"], true);
    assert_eq!(reply["account"]["has_api_key"], true);
    assert_redacted(&raw, &files, &vectors);

    let expected_snapshot = json!({"credentials.json":source,"config.json":config}).to_string();
    let expected = [
        vectors.vectors["access"].plaintext.as_str(),
        "",
        vectors.vectors["jwt"].plaintext.as_str(),
        API_KEY,
        vectors.vectors["profile"].plaintext.as_str(),
        &expected_snapshot,
    ];
    for (encrypted, plain) in saved_credentials(&state).iter().zip(expected) {
        assert_eq!(state.vault.decrypt(encrypted).unwrap(), plain);
        if plain.is_empty() {
            assert_eq!(encrypted, "");
        } else {
            assert!(encrypted.starts_with("vault1:"));
            assert_ne!(encrypted, plain);
        }
    }
    let rows = store::load_bundle_accounts(&state.db.lock().unwrap(), &state.vault).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1.access_token, expected[0]);
    assert_eq!(rows[0].1.refresh_token, "");
    assert_eq!(rows[0].1.zcode_jwt, expected[2]);
    assert_eq!(rows[0].1.api_key, API_KEY);
    assert_eq!(rows[0].1.user_info, expected[4]);
    assert_eq!(rows[0].1.account_group, "PUBLIC-desktop-group");
    assert_eq!(
        serde_json::from_str::<Value>(&rows[0].1.creds_raw).unwrap(),
        json!({"credentials.json":source,"config.json":config})
    );
    let id = reply["account"]["id"].as_i64().unwrap();
    assert_eq!(state.creds.lock().unwrap()[&id].zcode_jwt, expected[2]);
    assert_eq!(state.creds.lock().unwrap()[&id].api_key, API_KEY);
    assert_eq!(fs::read_to_string(files.credentials()).unwrap(), source);
}

#[tokio::test]
async fn selected_bad_desktop_ciphertext_is_redacted_400_without_any_database_or_live_mutation() {
    let vectors = vectors();
    let files = LocalFiles::new();
    files.write(&credentials(&vectors, false));
    let mut state = state(&files, &vectors.secret);
    assert_eq!(import(&state).await.0, StatusCode::OK);
    for invalid in &vectors.invalid {
        Arc::get_mut(&mut state).unwrap().local_credentials_secret = Some(
            if invalid.wrong_secret {
                &vectors.wrong_secret
            } else {
                &vectors.secret
            }
            .to_owned()
            .into(),
        );
        for field in [
            "oauth:active_provider",
            "zcodejwttoken",
            "oauth:public-provider:access_token",
            "oauth:public-provider:user_info",
        ] {
            let mut input = credentials(&vectors, false);
            input[field] = invalid.value.clone().into();
            let source = files.write(&input);
            let before = snapshot(&state);
            let (status, reply, raw) = import(&state).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{} in {field}", invalid.id);
            assert_eq!(reply["success"], false);
            assert_redacted(&raw, &files, &vectors);
            assert_eq!(snapshot(&state), before, "{} in {field}", invalid.id);
            assert_eq!(fs::read_to_string(files.credentials()).unwrap(), source);
        }
    }
}

#[tokio::test]
async fn legacy_plaintext_and_encrypted_empty_values_preserve_provider_and_claim_fallbacks() {
    let vectors = vectors();
    for case in ["plaintext", "encrypted_empty", "jwt_claims"] {
        let files = LocalFiles::new();
        let mut input = credentials(&vectors, false);
        let (secret, expected_id, expected_provider, expected_auth, expected_jwt, expected_access) =
            if case == "plaintext" {
                (
                    &vectors.wrong_secret,
                    "PUBLIC-desktop-profile",
                    "public-provider",
                    "jwt",
                    vectors.vectors["jwt"].plaintext.as_str(),
                    vectors.vectors["access"].plaintext.as_str(),
                )
            } else {
                let empty = vectors.vectors["empty"].value.as_str();
                input["oauth:active_provider"] = empty.into();
                input["oauth:zai:user_info"] = empty.into();
                if case == "encrypted_empty" {
                    input["zcodejwttoken"] = empty.into();
                    input["oauth:zai:access_token"] =
                        vectors.vectors["access_jwt"].value.clone().into();
                    (
                        &vectors.secret,
                        "PUBLIC-desktop-access-identity",
                        "zai",
                        "apikey",
                        "",
                        vectors.vectors["access_jwt"].plaintext.as_str(),
                    )
                } else {
                    input["zcodejwttoken"] = vectors.vectors["jwt"].value.clone().into();
                    input["oauth:zai:access_token"] = empty.into();
                    (
                        &vectors.secret,
                        "PUBLIC-jwt-not-profile",
                        "zai",
                        "jwt",
                        vectors.vectors["jwt"].plaintext.as_str(),
                        "",
                    )
                }
            };
        files.write(&input);
        let state = state(&files, secret);
        let (status, reply, raw) = import(&state).await;
        assert_eq!(status, StatusCode::OK, "{case}");
        assert_eq!(reply["account"]["user_id"], expected_id, "{case}");
        assert_eq!(reply["account"]["provider"], expected_provider, "{case}");
        assert_eq!(reply["account"]["auth_type"], expected_auth, "{case}");
        assert_redacted(&raw, &files, &vectors);
        let rows = store::load_bundle_accounts(&state.db.lock().unwrap(), &state.vault).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1.zcode_jwt, expected_jwt, "{case}");
        assert_eq!(rows[0].1.access_token, expected_access, "{case}");
        if case != "plaintext" {
            assert_eq!(rows[0].1.user_info, "", "{case}");
        }
    }
}
