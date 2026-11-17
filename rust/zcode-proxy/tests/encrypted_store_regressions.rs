use std::{collections::BTreeMap, sync::Arc};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
    vault::Vault,
};

const SESSION: &str = "PUBLIC-persistence-test-session";

struct Fixture {
    state: Arc<AppState>,
}

impl Fixture {
    fn new() -> Self {
        let state = Arc::new(AppState::new(
            String::new(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
        ));
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        Self { state }
    }

    async fn request(&self, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
        let response = build_router(self.state.clone())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("content-type", "application/json")
                    .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    fn sql(&self, sql: &str) {
        self.state.db.lock().unwrap().execute_batch(sql).unwrap();
    }

    // Seed legacy plaintext directly so failure tests do not depend on successful secret writes.
    fn seed_setting(&self, key: &str, value: &str) {
        self.state
            .db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO settings(key, value) VALUES(?1, ?2)",
                [key, value],
            )
            .unwrap();
        self.state
            .settings
            .lock()
            .unwrap()
            .insert(key.into(), value.into());
    }

    fn stored_settings(&self) -> BTreeMap<String, String> {
        let db = self.state.db.lock().unwrap();
        let mut stmt = db.prepare("SELECT key, value FROM settings ORDER BY key").unwrap();
        let settings = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        settings
    }

    fn memory_settings(&self) -> BTreeMap<String, String> {
        self.state
            .settings
            .lock()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    fn assert_no_accounts(&self) {
        let count: i64 = self
            .state
            .db
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM accounts", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0, "failed account write reached SQLite");
        assert!(self.state.accounts.lock().unwrap().is_empty());
        assert!(self.state.creds.lock().unwrap().is_empty());
    }
}

fn assert_encrypted(stored: &str, plain: &str, label: &str) {
    assert!(stored.starts_with("vault1:"), "{label} is not encrypted at rest");
    assert_ne!(stored, plain, "{label} was stored as plaintext");
}

#[tokio::test]
async fn account_add_encrypts_credentials_but_keeps_live_values_and_redacts_listing() {
    let f = Fixture::new();
    let jwt = format!("PUBLIC-jwt-{:032x}", rand::random::<u128>());
    let key = format!("PUBLIC-api-key-{:032x}", rand::random::<u128>());
    let (status, reply) = f
        .request(
            "POST",
            "/api/accounts/add",
            json!({"email":"encrypted@example.invalid", "zcode_jwt":jwt, "api_key":key}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let id = reply["id"].as_i64().unwrap();
    let stored: (String, String) = f
        .state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT zcode_jwt, api_key FROM accounts WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_encrypted(&stored.0, &jwt, "account JWT");
    assert_encrypted(&stored.1, &key, "account API key");
    {
        let accounts = f.state.accounts.lock().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, id);
        assert_eq!(accounts[0].zcode_jwt, jwt);
        assert_eq!(accounts[0].api_key, key);
        let creds = f.state.creds.lock().unwrap();
        assert_eq!(creds[&id].zcode_jwt, jwt);
        assert_eq!(creds[&id].api_key, key);
    }
    let (status, listed) = f.request("GET", "/api/accounts", Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    let listed = listed.to_string();
    assert!(!listed.contains(&jwt));
    assert!(!listed.contains(&key));
    assert!(!listed.contains("vault1:"));
}

#[tokio::test]
async fn account_add_preserves_empty_optional_credentials() {
    let f = Fixture::new();
    let (status, reply) = f
        .request(
            "POST",
            "/api/accounts/add",
            json!({"email":"empty@example.invalid", "zcode_jwt":"", "api_key":""}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let id = reply["id"].as_i64().unwrap();
    let stored: (String, String) = f
        .state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT zcode_jwt, api_key FROM accounts WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(stored, (String::new(), String::new()));
    let accounts = f.state.accounts.lock().unwrap();
    assert!(!accounts[0].paid_fallback);
    assert_eq!(f.state.creds.lock().unwrap()[&id].zcode_jwt, "");
}

#[tokio::test]
async fn account_insert_failure_does_not_publish_credentials_or_report_success() {
    let f = Fixture::new();
    f.sql(
        "CREATE TRIGGER fail_account_insert BEFORE INSERT ON accounts
         BEGIN SELECT RAISE(FAIL, 'PUBLIC injected account failure'); END;",
    );
    let (status, _) = f
        .request(
            "POST",
            "/api/accounts/add",
            json!({"email":"failure@example.invalid", "zcode_jwt":"PUBLIC jwt", "api_key":"PUBLIC key"}),
        )
        .await;
    assert!(status.is_server_error(), "failed insert returned {status}");
    f.assert_no_accounts();
}

#[tokio::test]
async fn invalid_or_foreign_account_envelopes_are_not_accepted_as_credentials() {
    let foreign = Vault::from_secret("PUBLIC foreign test seed").unwrap();
    for field in ["zcode_jwt", "api_key"] {
        for value in [
            "vault1:PUBLIC-invalid-envelope".to_owned(),
            foreign.encrypt("PUBLIC foreign credential").unwrap(),
        ] {
            let f = Fixture::new();
            let mut body = json!({"email":"invalid@example.invalid"});
            body[field] = json!(value);
            let (status, _) = f.request("POST", "/api/accounts/add", body).await;
            assert!(status.is_server_error(), "invalid {field} returned {status}");
            f.assert_no_accounts();
        }
    }
}

#[tokio::test]
async fn password_change_encrypts_hash_and_retains_a_usable_live_hash() {
    let f = Fixture::new();
    let password = format!("PUBLIC-new-password-{:032x}", rand::random::<u128>());
    let (status, _) = f
        .request(
            "POST",
            "/api/auth/password",
            json!({"current_password":"", "new_password":password}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let hash = f.state.setting("admin_password_hash").unwrap();
    assert!(bcrypt::verify(&password, &hash).unwrap());
    assert_encrypted(&f.stored_settings()["admin_password_hash"], &hash, "admin hash");
    assert!(f.state.sessions.lock().unwrap().is_empty());
    let (status, reply) = f
        .request("POST", "/api/login", json!({"password":password}))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reply["success"], true);
}

#[tokio::test]
async fn failed_password_write_keeps_old_hash_and_existing_sessions() {
    let f = Fixture::new();
    let password = format!("PUBLIC-old-password-{:032x}", rand::random::<u128>());
    f.seed_setting("admin_password_hash", &bcrypt::hash(&password, 4).unwrap());
    let before_db = f.stored_settings();
    let before_memory = f.memory_settings();
    let before_sessions = f.state.sessions.lock().unwrap().clone();
    f.sql(
        "CREATE TRIGGER fail_password_write BEFORE INSERT ON settings
         WHEN NEW.key = 'admin_password_hash'
         BEGIN SELECT RAISE(FAIL, 'PUBLIC injected password failure'); END;",
    );
    let (status, _) = f
        .request(
            "POST",
            "/api/auth/password",
            json!({"current_password":password, "new_password":"PUBLIC replacement password"}),
        )
        .await;
    assert!(status.is_server_error(), "failed password write returned {status}");
    assert_eq!(f.stored_settings(), before_db);
    assert_eq!(f.memory_settings(), before_memory);
    assert_eq!(*f.state.sessions.lock().unwrap(), before_sessions);
}

#[tokio::test]
async fn public_settings_stay_plaintext_and_secret_keys_remain_outside_the_http_whitelist() {
    let f = Fixture::new();
    let (status, reply) = f
        .request(
            "PUT",
            "/api/settings",
            json!({"gateway_paused":"1", "selection_strategy":"priority", "admin_password_hash":"PUBLIC forbidden hash", "totp_secret":"PUBLIC forbidden secret"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reply["updated"].as_array().unwrap().len(), 2);
    assert_eq!(f.stored_settings()["gateway_paused"], "1");
    assert_eq!(f.stored_settings()["selection_strategy"], "priority");
    assert_eq!(f.memory_settings(), f.stored_settings());
    assert_eq!(f.state.setting("admin_password_hash"), None);
    assert_eq!(f.state.setting("totp_secret"), None);
}

#[tokio::test]
async fn failed_public_settings_batch_rolls_back_database_and_memory() {
    let f = Fixture::new();
    f.seed_setting("gateway_paused", "0");
    f.seed_setting("selection_strategy", "round_robin");
    let before_db = f.stored_settings();
    let before_memory = f.memory_settings();
    f.sql(
        "CREATE TRIGGER fail_second_setting BEFORE INSERT ON settings
         WHEN NEW.key = 'selection_strategy'
         BEGIN SELECT RAISE(FAIL, 'PUBLIC injected setting failure'); END;",
    );
    let (status, _) = f
        .request(
            "PUT",
            "/api/settings",
            json!({"gateway_paused":"1", "selection_strategy":"priority"}),
        )
        .await;
    assert!(status.is_server_error(), "failed settings batch returned {status}");
    assert_eq!(f.stored_settings(), before_db);
    assert_eq!(f.memory_settings(), before_memory);
}

#[tokio::test]
async fn totp_setup_and_confirmation_encrypt_secrets_and_recovery_hashes() {
    let f = Fixture::new();
    let (status, setup) = f.request("POST", "/api/auth/totp/setup", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let secret = setup["secret"].as_str().unwrap();
    assert_eq!(f.state.setting("totp_secret_pending").as_deref(), Some(secret));
    assert_encrypted(&f.stored_settings()["totp_secret_pending"], secret, "pending TOTP secret");
    let decoded = zcode_core::base32_decode(secret).unwrap();
    let code = zcode_core::totp_now(&decoded, now_secs());
    let (status, confirmed) = f
        .request("POST", "/api/auth/totp/confirm", json!({"code":code}))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(confirmed["enabled"], true);
    let stored = f.stored_settings();
    assert_encrypted(&stored["totp_secret"], secret, "active TOTP secret");
    let hashes = f.state.setting("recovery_codes").unwrap();
    assert_encrypted(&stored["recovery_codes"], &hashes, "recovery code hashes");
    assert_eq!(stored["totp_enabled"], "1");
    assert_eq!(f.state.setting("totp_secret").as_deref(), Some(secret));
    assert!(f.state.setting("totp_secret_pending").unwrap_or_default().is_empty());
    assert!(stored.get("totp_secret_pending").is_none_or(String::is_empty));
    let hashes = zcode_core::recovery_codes_from_json(Some(&hashes));
    let codes = confirmed["recovery_codes"].as_array().unwrap();
    assert_eq!(codes.len(), 10);
    for code in codes {
        assert!(zcode_core::consume_recovery_code(&hashes, code.as_str().unwrap()).is_some());
    }
}

#[tokio::test]
async fn failed_totp_setup_does_not_publish_a_new_pending_secret() {
    let f = Fixture::new();
    f.seed_setting("totp_secret_pending", &zcode_core::new_totp_secret());
    let before_db = f.stored_settings();
    let before_memory = f.memory_settings();
    f.sql(
        "CREATE TRIGGER fail_pending_secret BEFORE INSERT ON settings
         WHEN NEW.key = 'totp_secret_pending'
         BEGIN SELECT RAISE(FAIL, 'PUBLIC injected setup failure'); END;",
    );
    let (status, _) = f.request("POST", "/api/auth/totp/setup", json!({})).await;
    assert!(status.is_server_error(), "failed TOTP setup returned {status}");
    assert_eq!(f.stored_settings(), before_db);
    assert_eq!(f.memory_settings(), before_memory);
}

#[tokio::test]
async fn failed_totp_confirmation_does_not_partially_enable_enrollment() {
    let f = Fixture::new();
    let secret = zcode_core::new_totp_secret();
    f.seed_setting("totp_secret_pending", &secret);
    f.seed_setting("totp_enabled", "0");
    let before_db = f.stored_settings();
    let before_memory = f.memory_settings();
    f.sql(
        "CREATE TRIGGER fail_recovery_codes BEFORE INSERT ON settings
         WHEN NEW.key = 'recovery_codes'
         BEGIN SELECT RAISE(FAIL, 'PUBLIC injected confirmation failure'); END;",
    );
    let decoded = zcode_core::base32_decode(&secret).unwrap();
    let code = zcode_core::totp_now(&decoded, now_secs());
    let (status, _) = f
        .request("POST", "/api/auth/totp/confirm", json!({"code":code}))
        .await;
    assert!(status.is_server_error(), "failed TOTP confirmation returned {status}");
    assert_eq!(f.stored_settings(), before_db);
    assert_eq!(f.memory_settings(), before_memory);
}

#[tokio::test]
async fn failed_recovery_consumption_does_not_issue_a_session_or_consume_memory() {
    let f = Fixture::new();
    let password = format!("PUBLIC-recovery-password-{:032x}", rand::random::<u128>());
    let (codes, hashes) = zcode_core::generate_recovery_codes(2);
    f.seed_setting("admin_password_hash", &bcrypt::hash(&password, 4).unwrap());
    f.seed_setting("totp_enabled", "1");
    f.seed_setting("recovery_codes", &zcode_core::recovery_codes_to_json(&hashes));
    f.state.sessions.lock().unwrap().clear();
    let before_db = f.stored_settings();
    let before_memory = f.memory_settings();
    f.sql(
        "CREATE TRIGGER fail_recovery_consumption BEFORE INSERT ON settings
         WHEN NEW.key = 'recovery_codes'
         BEGIN SELECT RAISE(FAIL, 'PUBLIC injected consumption failure'); END;",
    );
    let (status, _) = f
        .request("POST", "/api/login", json!({"password":password, "code":codes[0]}))
        .await;
    assert!(status.is_server_error(), "failed recovery consumption returned {status}");
    assert_eq!(f.stored_settings(), before_db);
    assert_eq!(f.memory_settings(), before_memory);
    assert!(f.state.sessions.lock().unwrap().is_empty());
}
