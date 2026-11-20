use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::Value;
use tower::ServiceExt;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
};

const SESSION: &str = "PUBLIC-account-refresh-route-session";

fn fixture() -> Arc<AppState> {
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
    state
}

async fn refresh(state: Arc<AppState>, authenticated: bool, origin: &str) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/accounts/987654321/refresh")
        .header("host", "localhost:8080")
        .header("origin", origin);
    if authenticated {
        request = request.header("cookie", format!("{SESSION_COOKIE}={SESSION}"));
    }
    let response = build_router(state)
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn refresh_route_requires_session_and_rejects_foreign_origin() {
    let state = fixture();
    let (status, _) = refresh(state.clone(), false, "http://localhost:8080").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = refresh(state, true, "https://foreign.example.invalid").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn refresh_missing_account_returns_api_error_not_unmounted_route() {
    let (status, body) = refresh(fixture(), true, "http://localhost:8080").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["type"], "api_error");
    assert!(body["error"]["message"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
}
