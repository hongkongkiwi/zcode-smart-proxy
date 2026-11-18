use std::{fs, path::PathBuf, sync::Arc};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
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

struct Fixture {
    directory: PathBuf,
    state: Arc<AppState>,
    credentials: String,
}

impl Fixture {
    fn new(profile: Value) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "zcode-local-edge-{}-{:032x}",
            std::process::id(),
            rand::random::<u128>()
        ));
        fs::create_dir(&directory).unwrap();
        let token = format!(
            "e30.{}.PUBLIC-not-a-real-signature",
            URL_SAFE_NO_PAD.encode(br#"{"sub":"PUBLIC-local-edge-jwt-sub"}"#)
        );
        let credentials = json!({
            "zcodejwttoken":token,
            "oauth:zai:user_info":profile.to_string(),
        })
        .to_string();
        let path = directory.join("credentials.json");
        fs::write(&path, &credentials).unwrap();
        let mut state = AppState::try_from_db_with_vault(
            String::new(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
            store::open(":memory:"),
            Vault::from_secret("PUBLIC local edge fixture vault seed").unwrap(),
        )
        .unwrap();
        state.local_credentials_path = Some(path);
        state
            .sessions
            .lock()
            .unwrap()
            .insert("PUBLIC-local-edge-session".into(), now_secs() + 3600);
        Self {
            directory,
            state: Arc::new(state),
            credentials,
        }
    }

    async fn import(&self, context: &str) -> (Value, BundleAccount) {
        let response = build_router(self.state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/accounts/import/local")
                    .header("host", "localhost:8080")
                    .header("origin", "http://localhost:8080")
                    .header("content-type", "application/json")
                    .header(
                        "cookie",
                        format!("{SESSION_COOKIE}=PUBLIC-local-edge-session"),
                    )
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "valid main credentials must import: {context}"
        );
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let reply: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(reply["success"], true);
        let rows =
            store::load_bundle_accounts(&self.state.db.lock().unwrap(), &self.state.vault).unwrap();
        assert_eq!(rows.len(), 1);
        let (id, saved) = rows.into_iter().next().unwrap();
        assert_eq!(reply["account"]["id"], id);
        let snapshot: Value = serde_json::from_str(&saved.creds_raw).unwrap();
        assert_eq!(snapshot["credentials.json"], self.credentials);
        (reply["account"].clone(), saved)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[tokio::test]
async fn local_import_skips_unreadable_invalid_utf8_and_oversized_optional_siblings() {
    for name in ["config.json", "telemetry-state.json"] {
        for kind in ["missing", "directory", "invalid-utf8", "oversized"] {
            let fixture = Fixture::new(json!({"user_id":"PUBLIC-local-edge-profile"}));
            let path = fixture.directory.join(name);
            match kind {
                "missing" => {}
                "directory" => fs::create_dir(path).unwrap(),
                "invalid-utf8" => fs::write(path, [0xff, 0xfe]).unwrap(),
                "oversized" => {
                    let content = json!({
                        "provider":{"zai-coding-plan":{"options":{"apiKey":"PUBLIC-must-be-skipped-key"}}},
                        "deviceMid":"PUBLIC-must-be-skipped-device",
                        "padding":"x".repeat(2 << 20),
                    });
                    fs::write(path, content.to_string()).unwrap();
                }
                _ => unreachable!(),
            }
            let (public, saved) = fixture.import(&format!("{kind} {name}")).await;
            assert_eq!(public["user_id"], "PUBLIC-local-edge-profile");
            assert_eq!(public["has_jwt"], true);
            assert_eq!(public["has_api_key"], false);
            assert!(saved.api_key.is_empty(), "invalid optional API key source");
            assert!(
                saved.device_mid.is_empty(),
                "invalid optional device source"
            );
        }
    }
    let fixture = Fixture::new(json!({"user_id":"PUBLIC-local-edge-profile"}));
    fs::write(
        fixture.directory.join("config.json"),
        r#"{"provider":{"zai-coding-plan":{"options":{"apiKey":"PUBLIC-valid-optional-key"}}}}"#,
    )
    .unwrap();
    fs::write(
        fixture.directory.join("telemetry-state.json"),
        r#"{"deviceMid":"PUBLIC-valid-optional-device"}"#,
    )
    .unwrap();
    let (public, saved) = fixture.import("valid optional siblings").await;
    assert_eq!(public["has_api_key"], true);
    assert_eq!(saved.api_key, "PUBLIC-valid-optional-key");
    assert_eq!(saved.device_mid, "PUBLIC-valid-optional-device");
}

#[tokio::test]
async fn local_import_skips_whitespace_profile_identity_and_name_but_preserves_nonblank_values() {
    for (profile, expected_id, expected_name) in [
        (
            json!({"user_id":" \t\n","id":" \r ","name":" \t ","username":"PUBLIC fallback username"}),
            "PUBLIC-local-edge-jwt-sub",
            "PUBLIC fallback username",
        ),
        (
            json!({"user_id":" \t ","id":" PUBLIC profile id ","name":" \r\n ","username":" PUBLIC padded username "}),
            " PUBLIC profile id ",
            " PUBLIC padded username ",
        ),
    ] {
        let fixture = Fixture::new(profile);
        let (public, saved) = fixture.import("whitespace-only profile candidates").await;
        assert_eq!(
            public["user_id"], expected_id,
            "Go firstNonEmpty identity fallback"
        );
        assert_eq!(
            public["display_name"], expected_name,
            "Go firstNonEmpty name fallback"
        );
        assert_eq!(saved.user_id, expected_id);
        assert_eq!(saved.display_name, expected_name);
        let accounts = fixture.state.accounts.lock().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, public["id"].as_i64().unwrap());
        assert!(!accounts[0].zcode_jwt.is_empty());
    }
}
