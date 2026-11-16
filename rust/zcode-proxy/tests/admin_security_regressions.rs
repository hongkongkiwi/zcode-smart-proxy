use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;
use zcode_proxy::{
    admin::LoginGuard,
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
    store,
};

const HOST: &str = "localhost:8080";

struct Fixture {
    state: Arc<AppState>,
    app: Router,
    password: String,
    totp_secret: Vec<u8>,
}

struct LoginReply {
    status: StatusCode,
    body: Value,
    cookie: Option<String>,
}

impl Fixture {
    fn new(totp: bool) -> Self {
        let password = format!("admin-test-{:032x}", rand::random::<u128>());
        let secret = zcode_core::new_totp_secret();
        let totp_secret = zcode_core::base32_decode(&secret).unwrap();
        let db = store::open(":memory:");
        store::set_setting(
            &db,
            "admin_password_hash",
            &bcrypt::hash(&password, 4).unwrap(),
        );
        store::set_setting(&db, "gateway_paused", "0");
        if totp {
            store::set_setting(&db, "totp_enabled", "1");
            store::set_setting(&db, "totp_secret", &secret);
        }
        let state = Arc::new(AppState::from_db(
            String::new(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
            db,
        ));
        let app = build_router(state.clone());
        Self {
            state,
            app,
            password,
            totp_secret,
        }
    }

    fn code(&self) -> String {
        zcode_core::totp_now(&self.totp_secret, now_secs())
    }

    async fn login(&self, password: &str, code: Option<&str>, xff: Option<&str>) -> LoginReply {
        let mut body = json!({"password": password});
        if let Some(code) = code {
            body["code"] = json!(code);
        }
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/login")
            .header("host", HOST)
            .header("content-type", "application/json");
        if let Some(xff) = xff {
            req = req.header("x-forwarded-for", xff);
        }
        let resp = self
            .app
            .clone()
            .oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let cookie = resp.headers().get("set-cookie").map(|value| {
            value
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_string()
        });
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        LoginReply {
            status,
            body: serde_json::from_slice(&bytes).unwrap(),
            cookie,
        }
    }

    async fn cookie(&self) -> String {
        let code = self.code();
        let reply = self.login(&self.password, Some(&code), None).await;
        assert_eq!(reply.status, StatusCode::OK, "body={}", reply.body);
        assert_eq!(reply.body["success"], true);
        reply.cookie.expect("successful login must issue a session")
    }

    async fn put_settings(&self, cookie: &str, origin: Option<&str>) -> StatusCode {
        let mut req = Request::builder()
            .method("PUT")
            .uri("/api/settings")
            .header("host", HOST)
            .header("cookie", cookie)
            .header("content-type", "application/json");
        if let Some(origin) = origin {
            req = req.header("origin", origin);
        }
        self.app
            .clone()
            .oneshot(
                req.body(Body::from(json!({"gateway_paused": "1"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    fn assert_paused(&self, expected: &str) {
        assert_eq!(
            self.state.setting("gateway_paused").as_deref(),
            Some(expected)
        );
        assert_eq!(
            store::get_setting(&self.state.db.lock().unwrap(), "gateway_paused").as_deref(),
            Some(expected)
        );
    }
}

fn assert_denied(reply: &LoginReply) {
    assert!(
        matches!(
            reply.status,
            StatusCode::UNAUTHORIZED | StatusCode::TOO_MANY_REQUESTS
        ),
        "locked login must be rejected, status={}, body={}",
        reply.status,
        reply.body
    );
    assert_eq!(reply.body["success"], false);
    assert!(
        reply.cookie.is_none(),
        "rejected login must not issue a session"
    );
}

#[tokio::test]
async fn correct_password_cannot_bypass_five_failed_passwords() {
    let f = Fixture::new(false);
    for _ in 0..5 {
        assert_denied(&f.login("incorrect-password", None, None).await);
    }
    assert_denied(&f.login(&f.password, None, None).await);
}

#[tokio::test]
async fn password_and_totp_failures_share_lockout_and_valid_totp_cannot_bypass() {
    // Exercise both TOTP-only guessing and a mixed password/TOTP failure window.
    for password_failures in [0, 3] {
        let f = Fixture::new(true);
        for _ in 0..password_failures {
            assert_denied(&f.login("incorrect-password", None, None).await);
        }
        for _ in password_failures..5 {
            // A nonnumeric code is invalid at every time step.
            assert_denied(&f.login(&f.password, Some("invalid-code"), None).await);
        }
        assert_denied(&f.login(&f.password, Some(&f.code()), None).await);
    }
}

#[tokio::test]
async fn rotating_untrusted_forwarded_for_cannot_bypass_default_lockout() {
    let f = Fixture::new(false);
    for xff in [
        "192.0.2.1",
        "192.0.2.2",
        "192.0.2.3",
        "192.0.2.4",
        "192.0.2.5",
    ] {
        assert_denied(&f.login("incorrect-password", None, Some(xff)).await);
    }
    assert_denied(&f.login(&f.password, None, Some("192.0.2.6")).await);
}

#[tokio::test]
async fn successful_full_login_resets_failures_before_the_threshold() {
    let f = Fixture::new(true);
    for _ in 0..4 {
        assert_denied(&f.login(&f.password, Some("invalid-code"), None).await);
    }
    let _ = f.cookie().await;
    assert_denied(&f.login("incorrect-password", None, None).await);
    let _ = f.cookie().await;
}

#[test]
fn login_guard_locks_at_five_and_allows_attempts_after_expiry() {
    let mut guard = LoginGuard::default();
    let start = 10_000;
    for _ in 0..4 {
        guard.record_failure("client", start);
        assert_eq!(guard.check("client", start), 0);
    }
    guard.record_failure("client", start);
    assert!(guard.check("client", start) > 0);
    assert!(guard.check("client", start + 899) > 0);
    assert_eq!(guard.check("other-client", start + 899), 0);
    assert_eq!(guard.check("client", start + 901), 0);
}

#[test]
fn expired_failure_window_starts_a_fresh_count_and_lockout() {
    let mut guard = LoginGuard::default();
    let start = 10_000;
    for _ in 0..4 {
        guard.record_failure("client", start);
    }
    let fresh = start + 901;
    assert_eq!(guard.check("client", fresh), 0);
    for _ in 0..4 {
        guard.record_failure("client", fresh);
        assert_eq!(guard.check("client", fresh), 0);
    }
    guard.record_failure("client", fresh);
    assert!(
        guard.check("client", fresh) > 0,
        "fresh failures must trigger a new lockout"
    );
    assert!(guard.check("client", fresh + 899) > 0);
    assert_eq!(guard.check("client", fresh + 901), 0);
}

async fn assert_origin_rejected(origin: &str) {
    let f = Fixture::new(false);
    let cookie = f.cookie().await;
    f.assert_paused("0");
    let status = f.put_settings(&cookie, Some(origin)).await;
    f.assert_paused("0");
    assert_eq!(status, StatusCode::FORBIDDEN, "origin={origin}");
}

#[tokio::test]
async fn authenticated_mutation_rejects_same_host_different_port() {
    assert_origin_rejected("http://localhost:8081").await;
}

#[tokio::test]
async fn authenticated_mutation_rejects_non_http_origin_scheme() {
    assert_origin_rejected("ftp://localhost:8080").await;
}

#[tokio::test]
async fn authenticated_mutation_rejects_origin_with_path() {
    assert_origin_rejected("http://localhost:8080/not-an-origin").await;
}

#[tokio::test]
async fn authenticated_mutation_accepts_missing_or_valid_same_origin() {
    for origin in [None, Some("http://localhost:8080")] {
        let f = Fixture::new(false);
        let cookie = f.cookie().await;
        assert_eq!(f.put_settings(&cookie, origin).await, StatusCode::OK);
        f.assert_paused("1");
    }
}
