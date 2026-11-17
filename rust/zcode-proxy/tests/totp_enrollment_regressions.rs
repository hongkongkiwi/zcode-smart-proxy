use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_proxy::{
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
};

const PASSWORD: &str = "PUBLIC-totp-enrollment-password";

struct Fixture {
    state: Arc<AppState>,
    app: Router,
    cookie: String,
}

impl Fixture {
    async fn new() -> Self {
        let state = Arc::new(AppState::new(
            String::new(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
        ));
        state
            .persist_settings(&[("admin_password_hash", &bcrypt::hash(PASSWORD, 4).unwrap())])
            .unwrap();
        let app = build_router(state.clone());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/login")
                    .header("host", "localhost:8080")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"password": PASSWORD}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get("set-cookie")
            .expect("password login must issue a session before enrollment")
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        Self { state, app, cookie }
    }

    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("host", "localhost:8080")
                    .header("cookie", &self.cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn setup(&self) -> String {
        // Go permits session-only setup; the password step-up belongs to confirmation.
        let (status, reply) = self.post("/api/auth/totp/setup", json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "session-only setup must remain allowed"
        );
        let secret = reply["secret"]
            .as_str()
            .expect("setup must return a secret");
        assert!(zcode_core::base32_decode(secret).is_some());
        secret.to_string()
    }

    fn seed_active_factor(&self) -> (String, String) {
        let secret = zcode_core::new_totp_secret();
        let (_, hashes) = zcode_core::generate_recovery_codes(10);
        let recovery = zcode_core::recovery_codes_to_json(&hashes);
        self.state
            .persist_settings(&[
                ("totp_enabled", "1"),
                ("totp_secret", &secret),
                ("recovery_codes", &recovery),
            ])
            .unwrap();
        (secret, recovery)
    }

    fn assert_active_factor(&self, secret: &str, recovery: &str) {
        assert_eq!(self.state.setting("totp_enabled").as_deref(), Some("1"));
        assert!(
            self.state.setting("totp_secret").as_deref() == Some(secret),
            "rejected enrollment mutation must preserve the active TOTP secret"
        );
        assert!(
            self.state.setting("recovery_codes").as_deref() == Some(recovery),
            "rejected enrollment mutation must preserve recovery codes"
        );
    }
}

fn code(secret: &str) -> String {
    zcode_core::totp_now(&zcode_core::base32_decode(secret).unwrap(), now_secs())
}

#[tokio::test]
async fn confirmation_requires_current_password_but_setup_does_not() {
    let f = Fixture::new().await;
    let pending = f.setup().await;
    assert_ne!(f.state.setting("totp_enabled").as_deref(), Some("1"));
    assert!(f
        .state
        .setting("totp_secret")
        .unwrap_or_default()
        .is_empty());

    for password in [None, Some("PUBLIC-wrong-password")] {
        let mut body = json!({"code": code(&pending)});
        if let Some(password) = password {
            body["current_password"] = json!(password);
        }
        let (status, reply) = f.post("/api/auth/totp/confirm", body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "valid pending TOTP proof cannot replace current-password step-up"
        );
        assert!(reply.get("recovery_codes").is_none_or(Value::is_null));
        assert_ne!(f.state.setting("totp_enabled").as_deref(), Some("1"));
        assert!(f
            .state
            .setting("totp_secret")
            .unwrap_or_default()
            .is_empty());
        assert!(f
            .state
            .setting("recovery_codes")
            .unwrap_or_default()
            .is_empty());
    }

    let (status, reply) = f
        .post(
            "/api/auth/totp/confirm",
            json!({"code": code(&pending), "current_password": PASSWORD}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "correct password must complete fresh setup"
    );
    assert_eq!(reply["enabled"], true);
    assert_eq!(reply["recovery_codes"].as_array().unwrap().len(), 10);
    assert!(f.state.setting("totp_secret").as_deref() == Some(pending.as_str()));
}

#[tokio::test]
async fn session_cannot_replace_active_totp_without_current_password() {
    let f = Fixture::new().await;
    let (active, recovery) = f.seed_active_factor();
    let pending = f.setup().await;
    f.assert_active_factor(&active, &recovery);

    let (status, reply) = f
        .post("/api/auth/totp/confirm", json!({"code": code(&pending)}))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "session and attacker-owned pending TOTP must not replace an active factor"
    );
    assert!(reply.get("recovery_codes").is_none_or(Value::is_null));
    f.assert_active_factor(&active, &recovery);
}

#[tokio::test]
async fn expired_or_missing_pending_deadline_cannot_enable_totp() {
    for deadline in [Some((now_secs() - 1).to_string()), None] {
        let f = Fixture::new().await;
        let pending = if let Some(deadline) = deadline {
            let pending = f.setup().await;
            f.state
                .persist_settings(&[("totp_setup_expires_at", &deadline)])
                .unwrap();
            pending
        } else {
            let pending = zcode_core::new_totp_secret();
            f.state
                .persist_settings(&[("totp_secret_pending", &pending)])
                .unwrap();
            pending
        };
        let (status, reply) = f
            .post(
                "/api/auth/totp/confirm",
                json!({"code": code(&pending), "current_password": PASSWORD}),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "fresh TOTP and password cannot revive an expired or undated pending setup"
        );
        assert!(reply.get("recovery_codes").is_none_or(Value::is_null));
        assert_ne!(f.state.setting("totp_enabled").as_deref(), Some("1"));
        assert!(f
            .state
            .setting("totp_secret")
            .unwrap_or_default()
            .is_empty());
        assert!(f
            .state
            .setting("recovery_codes")
            .unwrap_or_default()
            .is_empty());
    }
}

#[tokio::test]
async fn disable_password_failures_are_throttled_before_valid_credentials_can_mutate() {
    let f = Fixture::new().await;
    let (active, recovery) = f.seed_active_factor();
    for _ in 0..5 {
        let (status, _) = f
            .post(
                "/api/auth/totp/disable",
                json!({
                    "current_password": "PUBLIC-wrong-password",
                    "password": "PUBLIC-wrong-password",
                    "code": code(&active),
                }),
            )
            .await;
        assert!(
            matches!(status, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED),
            "wrong password must be rejected, got {status}"
        );
        f.assert_active_factor(&active, &recovery);
    }

    let (status, _) = f
        .post(
            "/api/auth/totp/disable",
            json!({"current_password": PASSWORD, "password": PASSWORD, "code": code(&active)}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "five failed disable password proofs must throttle even a correct proof"
    );
    f.assert_active_factor(&active, &recovery);
}
