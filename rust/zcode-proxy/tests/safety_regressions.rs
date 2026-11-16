use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Json, Router,
};
use rand::{distributions::Alphanumeric, Rng};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tower::ServiceExt;
use zcode_core::AccountView;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::key_hash,
    build_router, engine,
    state::{AppState, Creds, NamedKey, UpstreamUrls},
    store,
};

const MESSAGE_URIS: &[&str] = &[
    "/v1/messages",
    "/api/v1/ultra/anthropic/v1/messages",
    "/api/v1/ultra-zai/anthropic/v1/messages",
    "/api/v1/highspeed/anthropic/v1/messages",
    "/api/v1/off-peak/anthropic/v1/messages",
    "/api/v1/zcode-plan/anthropic/v1/messages",
];

fn secret() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(40)
        .map(char::from)
        .collect()
}

fn success_body() -> Value {
    json!({
        "id": "msg_safety", "type": "message", "role": "assistant",
        "model": "GLM-5.3", "content": [{"type": "text", "text": "SAFETY-OK"}],
        "stop_reason": "end_turn", "usage": {"input_tokens": 1, "output_tokens": 1}
    })
}

struct Fixture {
    state: Arc<AppState>,
    root: String,
    named: String,
    free_calls: Arc<AtomicUsize>,
    paid_calls: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn new(captcha: bool) -> Self {
        let free_calls = Arc::new(AtomicUsize::new(0));
        let paid_calls = Arc::new(AtomicUsize::new(0));
        let free_counter = free_calls.clone();
        let paid_counter = paid_calls.clone();
        let upstream = Router::new()
            .route(
                "/free",
                post(move || {
                    let counter = free_counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        if captcha {
                            (
                                StatusCode::BAD_REQUEST,
                                Json(json!({"error": {"message": "captcha rejected"}})),
                            )
                        } else {
                            (StatusCode::OK, Json(success_body()))
                        }
                    }
                }),
            )
            .route(
                "/paid",
                post(move || {
                    let counter = paid_counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Json(success_body())
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let root = secret();
        let named = secret();
        let state = Arc::new(AppState::from_db(
            root.clone(),
            UpstreamUrls {
                zai: format!("http://{addr}/free"),
                zai_fallback: format!("http://{addr}/paid"),
            },
            store::open(":memory:"),
        ));
        state.named_keys.lock().unwrap().push(NamedKey {
            id: 1,
            name: "safety-test".into(),
            key_hash: key_hash(&named),
            enabled: true,
            models: "".into(),
            rpm_limit: 0,
            rate_5h: 0,
            rate_1d: 0,
            rate_7d: 0,
            quota_total: 0,
            quota_used: 0,
        });
        Self {
            state,
            root,
            named,
            free_calls,
            paid_calls,
            server,
        }
    }

    fn account(&self, enabled: bool, has_jwt: bool, paid_fallback: bool, paid_cooling: i64) {
        let jwt = if has_jwt { secret() } else { String::new() };
        let api_key = secret();
        self.state.accounts.lock().unwrap().push(AccountView {
            id: 1,
            provider: "zai".into(),
            enabled,
            status: "active".into(),
            zcode_jwt: jwt.clone(),
            api_key: api_key.clone(),
            paid_fallback,
            paid_cooling_until: paid_cooling,
            ..Default::default()
        });
        self.state.creds.lock().unwrap().insert(
            1,
            Creds {
                zcode_jwt: jwt,
                api_key,
            },
        );
    }

    fn setting(&self, key: &str, value: &str) {
        self.state
            .settings
            .lock()
            .unwrap()
            .insert(key.into(), value.into());
        store::set_setting(&self.state.db.lock().unwrap(), key, value);
    }

    fn calls(&self) -> (usize, usize) {
        (
            self.free_calls.load(Ordering::SeqCst),
            self.paid_calls.load(Ordering::SeqCst),
        )
    }

    fn app(&self) -> Router {
        build_router(self.state.clone())
    }
}

async fn send(app: Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = tokio::time::timeout(std::time::Duration::from_secs(15), app.oneshot(request))
        .await
        .expect("local router request timed out")
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).expect("JSON response"),
    )
}

async fn message(f: &Fixture, uri: &str, key: &str, user: Option<&str>) -> (StatusCode, Value) {
    let mut body = json!({
        "model": "glm-5.3", "stream": false,
        "messages": [{"role": "user", "content": "hi"}]
    });
    if let Some(user) = user {
        body["metadata"] = json!({"user_id": user});
    }
    send(
        f.app(),
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("x-api-key", key)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn disabled_active_account_never_uses_free_channel() {
    let f = Fixture::new(false).await;
    f.account(false, true, true, 0);
    let (status, _) = message(&f, MESSAGE_URIS[0], &f.root, None).await;
    assert_eq!(
        f.calls(),
        (0, 0),
        "disabled active account reached upstream"
    );
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn disabled_active_account_never_uses_paid_only_channel() {
    let f = Fixture::new(false).await;
    f.setting("paid_fallback_mode", "never");
    f.account(false, false, false, 0);
    let (status, _) = message(&f, MESSAGE_URIS[0], &f.root, None).await;
    assert_eq!(
        f.calls(),
        (0, 0),
        "disabled paid-only account reached upstream"
    );
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn sticky_sessions_revalidate_enabled_flag_on_both_channels() {
    let mut violations = Vec::new();
    for has_jwt in [true, false] {
        let f = Fixture::new(false).await;
        f.setting("paid_fallback_mode", "never");
        f.account(true, has_jwt, false, 0);
        let user = secret();
        let (warm_status, warm_body) = message(&f, MESSAGE_URIS[0], &f.root, Some(&user)).await;
        assert_eq!(warm_status, StatusCode::OK);
        assert_eq!(warm_body["content"][0]["text"], "SAFETY-OK");
        let before = f.calls();
        assert_eq!(before, if has_jwt { (1, 0) } else { (0, 1) });
        f.state.accounts.lock().unwrap()[0].enabled = false;
        let (status, _) = message(&f, MESSAGE_URIS[0], &f.root, Some(&user)).await;
        let after = f.calls();
        if after != before || status != StatusCode::SERVICE_UNAVAILABLE {
            violations.push(format!(
                "has_jwt={has_jwt}: status={status}, calls before={before:?}, after={after:?}"
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "disabled sticky reuse: {violations:?}"
    );
}

#[tokio::test]
async fn enabled_free_and_pure_paid_accounts_remain_usable_in_never_mode() {
    for has_jwt in [true, false] {
        let f = Fixture::new(false).await;
        f.setting("paid_fallback_mode", "never");
        f.account(true, has_jwt, false, 0);
        let (status, body) = message(&f, MESSAGE_URIS[0], &f.root, None).await;
        assert_eq!(status, StatusCode::OK, "has_jwt={has_jwt}");
        assert_eq!(body["content"][0]["text"], "SAFETY-OK");
        assert_eq!(f.calls(), if has_jwt { (1, 0) } else { (0, 1) });
    }
}

async fn balanced_paid_veto(paid_fallback: bool, paid_cooling: i64) {
    let f = Fixture::new(true).await;
    f.setting("paid_fallback_mode", "balanced");
    f.account(true, true, paid_fallback, paid_cooling);
    let (status, _) = message(&f, MESSAGE_URIS[0], &f.root, None).await;
    assert_eq!(
        f.calls().0,
        1,
        "must exercise the free HTTP 400 captcha response"
    );
    assert_eq!(
        f.calls().1,
        0,
        "balanced captcha cascade bypassed paid eligibility"
    );
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn balanced_captcha_respects_paid_fallback_false() {
    balanced_paid_veto(false, 0).await;
}

#[tokio::test]
async fn balanced_captcha_respects_future_paid_cooling() {
    balanced_paid_veto(true, engine::now_secs() + 86_400).await;
}

#[tokio::test]
async fn balanced_captcha_allows_eligible_paid_fallback() {
    let f = Fixture::new(true).await;
    f.setting("paid_fallback_mode", "balanced");
    f.account(true, true, true, engine::now_secs() - 1);
    let (status, body) = message(&f, MESSAGE_URIS[0], &f.root, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["content"][0]["text"], "SAFETY-OK");
    assert_eq!(f.calls(), (1, 1));
}

#[tokio::test]
async fn paused_gateway_blocks_all_message_aliases_for_root_and_named_keys() {
    let f = Fixture::new(false).await;
    f.account(true, true, true, 0);
    f.setting("gateway_paused", "1");
    let mut violations = Vec::new();
    for (kind, key) in [("root", &f.root), ("named", &f.named)] {
        for uri in MESSAGE_URIS {
            let before = f.calls();
            let (status, body) = message(&f, uri, key, None).await;
            let after = f.calls();
            if status != StatusCode::SERVICE_UNAVAILABLE
                || after != before
                || body["type"] != "error"
                || body["error"]["message"].as_str().unwrap_or("").is_empty()
            {
                violations.push(format!(
                    "{kind} {uri}: status={status}, calls before={before:?}, after={after:?}"
                ));
            }
        }
    }
    assert!(violations.is_empty(), "pause gate bypasses: {violations:?}");
    assert_eq!(f.calls(), (0, 0));
}

#[tokio::test]
async fn unpaused_gateway_serves_all_message_aliases_for_root_and_named_keys() {
    let f = Fixture::new(false).await;
    f.account(true, true, true, 0);
    f.setting("gateway_paused", "1");
    f.setting("gateway_paused", "0");
    for key in [&f.root, &f.named] {
        for uri in MESSAGE_URIS {
            let before = f.calls();
            let (status, body) = message(&f, uri, key, None).await;
            assert_eq!(status, StatusCode::OK, "uri={uri}");
            assert_eq!(body["content"][0]["text"], "SAFETY-OK");
            assert_eq!(f.calls(), (before.0 + 1, before.1), "uri={uri}");
        }
    }
}

#[tokio::test]
async fn authenticated_settings_exposes_only_supported_public_settings() {
    let f = Fixture::new(false).await;
    let public = [
        ("paid_fallback_mode", "balanced"),
        ("selection_strategy", "round_robin"),
        ("sticky_sessions", "1"),
        ("gateway_paused", "0"),
    ];
    for (key, value) in public {
        f.setting(key, value);
    }
    for key in [
        "admin_password_hash",
        "totp_secret",
        "totp_secret_pending",
        "recovery_codes",
        "future_service_credential",
        "arbitrary_private_setting",
    ] {
        f.setting(key, &secret());
    }
    let unauthenticated = Request::builder()
        .uri("/api/settings")
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(f.app(), unauthenticated).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let session = secret();
    f.state
        .sessions
        .lock()
        .unwrap()
        .insert(session.clone(), engine::now_secs() + 3600);
    let authenticated = Request::builder()
        .uri("/api/settings")
        .header("cookie", format!("{SESSION_COOKIE}={session}"))
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(f.app(), authenticated).await;
    assert_eq!(status, StatusCode::OK);
    let settings = body.as_object().expect("settings object");
    for (key, value) in public {
        assert_eq!(
            settings.get(key).and_then(Value::as_str),
            Some(value),
            "public setting {key}"
        );
    }
    // Report key names only, never secret values, if the boundary leaks.
    let leaked: Vec<&str> = settings
        .keys()
        .map(String::as_str)
        .filter(|key| !public.iter().any(|(allowed, _)| key == allowed))
        .collect();
    assert!(leaked.is_empty(), "non-public settings exposed: {leaked:?}");
    assert_eq!(f.calls(), (0, 0));
}

// ---- Slice A: login lockout + CSRF origin gate on Rust admin ----

// Cross-origin login (Origin host != our Host) is rejected 403 before the
// password is even checked — a no-cors fetch from another local port cannot
// ride the admin session (review finding: SameSite does not separate ports).
#[tokio::test]
async fn login_rejects_cross_origin_without_password_check() {
    let f = Fixture::new(false).await;
    f.state
        .settings
        .lock()
        .unwrap()
        .insert("admin_password_hash".into(), "$2y$10$fakehashforcsrf".into());
    let req = Request::builder()
        .method("POST")
        .uri("/api/login")
        .header("content-type", "application/json")
        .header("origin", "http://evil-port.example:9999")
        .body(Body::from(r#"{"password":"anything"}"#))
        .unwrap();
    let resp = zcode_proxy::build_router(f.state.clone())
        .oneshot(req)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// Same-origin and no-origin login requests pass through to the password
// check (not CSRF-blocked).
#[tokio::test]
async fn login_same_origin_and_no_origin_accepted_shape() {
    let f = Fixture::new(false).await;
    f.state
        .settings
        .lock()
        .unwrap()
        .insert("admin_password_hash".into(), "$2y$10$fakehashforcsrf".into());
    let app = zcode_proxy::build_router(f.state.clone());
    // Same origin: passes the CSRF gate (fails on password, which is fake).
    let req = Request::builder()
        .method("POST")
        .uri("/api/login")
        .header("host", "127.0.0.1")
        .header("origin", "http://127.0.0.1")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"password":"x"}"#))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    // No origin header (curl/SDK): also passes the CSRF gate.
    let req2 = Request::builder()
        .method("POST")
        .uri("/api/login")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"password":"x"}"#))
        .unwrap();
    let resp2 = app.oneshot(req2).await.unwrap();
    assert_ne!(resp2.status(), StatusCode::FORBIDDEN);
}

// Login lockout (Slice A): after LOCKOUT_THRESHOLD failures from one client
// within the window, further attempts are locked out even with the correct
// password.
#[tokio::test]
async fn login_lockout_after_repeated_failures() {
    let f = Fixture::new(false).await;
    f.state
        .settings
        .lock()
        .unwrap()
        .insert("admin_password_hash".into(), "$2y$10$fakehashforcsrf".into());
    let mut guard = f.state.login_guard.lock().unwrap();
    // Simulate threshold failures through the guard directly (the full
    // bcrypt+lockout flow is slower; the guard is the logic under test).
    let now = 1_700_000_000;
    for _ in 0..LOCKOUT_THRESHOLD_TEST {
        guard.record_failure("evil-client", now);
    }
    assert!(
        guard.check("evil-client", now + 1) > 0,
        "client must be locked out after {LOCKOUT_THRESHOLD_TEST} failures"
    );
    assert_eq!(guard.check("other-client", now), 0, "other clients unaffected");
    // Window lapse clears the lockout.
    assert_eq!(guard.check("evil-client", now + LOCKOUT_WINDOW_SECS_TEST + 1), 0);
    drop(guard);
}

const LOCKOUT_THRESHOLD_TEST: usize = 5;
const LOCKOUT_WINDOW_SECS_TEST: i64 = 900;
