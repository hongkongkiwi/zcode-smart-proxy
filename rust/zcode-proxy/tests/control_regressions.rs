use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tower::ServiceExt;
use zcode_core::AccountView;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    build_router,
    engine::now_secs,
    state::{AppState, Creds, UpstreamUrls},
    store,
};

struct Fixture {
    state: Arc<AppState>,
    free: Arc<AtomicUsize>,
    paid: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn new(free_failure: bool, paid_failure: bool) -> Self {
        Self::with_paid_status(
            free_failure,
            if paid_failure {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::OK
            },
        )
        .await
    }
    async fn with_paid_status(free_failure: bool, paid_status: StatusCode) -> Self {
        let free = Arc::new(AtomicUsize::new(0));
        let paid = Arc::new(AtomicUsize::new(0));
        let fc = free.clone();
        let pc = paid.clone();
        let upstream = Router::new()
            .route(
                "/free",
                post(move || {
                    let c = fc.clone();
                    async move {
                        c.fetch_add(1, Ordering::SeqCst);
                        if free_failure {
                            (
                                StatusCode::BAD_REQUEST,
                                Json(json!({"error":{"message":"captcha rejected"}})),
                            )
                        } else {
                            (
                                StatusCode::OK,
                                Json(json!({"content":[{"type":"text","text":"ok"}]})),
                            )
                        }
                    }
                }),
            )
            .route(
                "/paid",
                post(move || {
                    let c = pc.clone();
                    async move {
                        c.fetch_add(1, Ordering::SeqCst);
                        if paid_status != StatusCode::OK {
                            (paid_status, Json(json!({"error":{"message":"rate limit"}})))
                        } else {
                            (
                                StatusCode::OK,
                                Json(json!({"content":[{"type":"text","text":"ok"}]})),
                            )
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let state = Arc::new(AppState::from_db(
            "root".into(),
            UpstreamUrls {
                zai: format!("http://{addr}/free"),
                zai_fallback: format!("http://{addr}/paid"),
            },
            store::open(":memory:"),
        ));
        state
            .sessions
            .lock()
            .unwrap()
            .insert("session".into(), now_secs() + 3600);
        Self {
            state,
            free,
            paid,
            server,
        }
    }
    fn account(&self, id: i64, remaining: f64) {
        self.state.accounts.lock().unwrap().push(AccountView {
            id,
            provider: "zai".into(),
            enabled: true,
            status: "active".into(),
            zcode_jwt: format!("jwt{id}"),
            api_key: format!("key{id}"),
            paid_fallback: true,
            remaining,
            ..Default::default()
        });
        self.state.creds.lock().unwrap().insert(
            id,
            Creds {
                zcode_jwt: format!("jwt{id}"),
                api_key: format!("key{id}"),
            },
        );
    }
    fn pure_key_account(&self, paid_fallback: bool) {
        self.account(1, 1.0);
        let mut accounts = self.state.accounts.lock().unwrap();
        accounts[0].zcode_jwt.clear();
        accounts[0].paid_fallback = paid_fallback;
        self.state
            .creds
            .lock()
            .unwrap()
            .get_mut(&1)
            .unwrap()
            .zcode_jwt
            .clear();
    }
    async fn put(&self, body: Value) -> StatusCode {
        let req = Request::builder()
            .method("PUT")
            .uri("/api/settings")
            .header("cookie", format!("{SESSION_COOKIE}=session"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        build_router(self.state.clone())
            .oneshot(req)
            .await
            .unwrap()
            .status()
    }
    async fn message(&self, user: Option<&str>) -> StatusCode {
        let mut body =
            json!({"model":"glm-5.3", "stream":false, "messages":[{"role":"user","content":"hi"}]});
        if let Some(user) = user {
            body["metadata"] = json!({"user_id":user});
        }
        let req = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header("x-api-key", "root")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        build_router(self.state.clone())
            .oneshot(req)
            .await
            .unwrap()
            .status()
    }
    fn last_account(&self) -> i64 {
        self.state.usage.lock().unwrap().last().unwrap().account_id
    }
}

#[tokio::test]
async fn pure_key_opt_out_is_not_used_in_default_or_balanced_mode() {
    for mode in [None, Some("balanced")] {
        let f = Fixture::new(false, false).await;
        f.pure_key_account(false);
        if let Some(mode) = mode {
            assert_eq!(
                f.put(json!({"paid_fallback_mode":mode})).await,
                StatusCode::OK
            );
        }
        assert_eq!(
            f.message(None).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "{mode:?}"
        );
        assert_eq!(f.free.load(Ordering::SeqCst), 0, "{mode:?}");
        assert_eq!(f.paid.load(Ordering::SeqCst), 0, "{mode:?}");
    }
}

#[tokio::test]
async fn pure_key_unauthorized_paid_attempt_is_not_repeated() {
    for mode in [None, Some("balanced")] {
        let f = Fixture::with_paid_status(false, StatusCode::UNAUTHORIZED).await;
        f.pure_key_account(true);
        if let Some(mode) = mode {
            assert_eq!(
                f.put(json!({"paid_fallback_mode":mode})).await,
                StatusCode::OK
            );
        }
        assert_eq!(
            f.message(None).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "{mode:?}"
        );
        assert_eq!(f.free.load(Ordering::SeqCst), 0, "{mode:?}");
        assert_eq!(f.paid.load(Ordering::SeqCst), 1, "{mode:?}");
    }
}

#[tokio::test]
async fn invalid_settings_are_rejected_atomically() {
    let f = Fixture::new(false, false).await;
    assert_eq!(f.put(json!({"gateway_paused":"0", "paid_fallback_mode":"never", "selection_strategy":"round_robin", "sticky_sessions":"1"})).await, StatusCode::OK);
    for (key, value) in [
        ("gateway_paused", "true"),
        ("paid_fallback_mode", "Never"),
        ("selection_strategy", "bogus"),
        ("sticky_sessions", "true"),
    ] {
        let mut body = json!({"gateway_paused":"1", "paid_fallback_mode":"balanced"});
        body[key] = json!(value);
        assert_eq!(f.put(body).await, StatusCode::BAD_REQUEST, "{key}");
        assert_eq!(f.state.setting("gateway_paused").as_deref(), Some("0"));
        assert_eq!(
            f.state.setting("paid_fallback_mode").as_deref(),
            Some("never")
        );
        assert_eq!(
            f.state.setting("selection_strategy").as_deref(),
            Some("round_robin")
        );
        assert_eq!(f.state.setting("sticky_sessions").as_deref(), Some("1"));
    }
}

#[tokio::test]
async fn strategy_and_sticky_edits_take_effect_without_resetting_rotation() {
    let f = Fixture::new(false, false).await;
    f.account(1, 1.0);
    f.account(2, 10.0);
    assert_eq!(f.message(None).await, StatusCode::OK);
    assert_eq!(f.last_account(), 1);
    assert_eq!(
        f.put(json!({"selection_strategy":"best_quota"})).await,
        StatusCode::OK
    );
    assert_eq!(f.message(None).await, StatusCode::OK);
    assert_eq!(f.last_account(), 2);
    assert_eq!(
        f.put(json!({"selection_strategy":"round_robin", "sticky_sessions":"0"}))
            .await,
        StatusCode::OK
    );
    assert_eq!(f.message(Some("same")).await, StatusCode::OK);
    assert_eq!(f.last_account(), 2);
    assert_eq!(f.message(Some("same")).await, StatusCode::OK);
    assert_eq!(f.last_account(), 1);
    assert_eq!(f.put(json!({"sticky_sessions":"1"})).await, StatusCode::OK);
    assert_eq!(f.message(Some("new")).await, StatusCode::OK);
    let selected = f.last_account();
    assert_eq!(f.message(Some("new")).await, StatusCode::OK);
    assert_eq!(f.last_account(), selected);
}

#[tokio::test]
async fn balanced_failed_cascade_is_not_retried_and_cools_paid_channel() {
    let f = Fixture::new(true, true).await;
    f.account(1, 1.0);
    assert_eq!(
        f.put(json!({"paid_fallback_mode":"balanced"})).await,
        StatusCode::OK
    );
    assert_eq!(f.message(None).await, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(f.free.load(Ordering::SeqCst), 1);
    assert_eq!(f.paid.load(Ordering::SeqCst), 1);
    let accounts = f.state.accounts.lock().unwrap();
    assert_eq!(accounts[0].status, "cooling");
    assert!(accounts[0].cooling_until > now_secs());
    assert!(accounts[0].paid_cooling_until > now_secs());
}

#[tokio::test]
async fn free_first_still_attempts_paid_and_balanced_success_works() {
    for mode in ["free_first", "balanced"] {
        let f = Fixture::new(true, false).await;
        f.account(1, 1.0);
        assert_eq!(
            f.put(json!({"paid_fallback_mode":mode})).await,
            StatusCode::OK
        );
        assert_eq!(f.message(None).await, StatusCode::OK, "{mode}");
        assert_eq!(f.free.load(Ordering::SeqCst), 1);
        assert_eq!(f.paid.load(Ordering::SeqCst), 1);
    }
}
