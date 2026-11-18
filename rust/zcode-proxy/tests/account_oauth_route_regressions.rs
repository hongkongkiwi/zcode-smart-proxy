use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
};

const SESSION: &str = "PUBLIC-oauth-route-session";
const ROOT: &str = "PUBLIC-oauth-route-root-key";
const START: &str = "/api/accounts/oauth/start";
const MANUAL: &str = "/api/accounts/oauth/manual";
const STATUS: &str = "/api/accounts/oauth/status?state=PUBLIC-unknown-oauth-state";

fn fixture(token_url: String) -> Arc<AppState> {
    let mut state = AppState::new(
        ROOT.into(),
        UpstreamUrls {
            zai: "http://127.0.0.1:1/unused".into(),
            zai_fallback: "http://127.0.0.1:1/unused".into(),
        },
    );
    state.management.oauth_token = token_url;
    state
        .sessions
        .lock()
        .unwrap()
        .insert(SESSION.into(), now_secs() + 3600);
    state
        .sessions
        .lock()
        .unwrap()
        .insert("PUBLIC-expired-oauth-route-session".into(), 0);
    Arc::new(state)
}

async fn request(
    state: Arc<AppState>,
    method: &str,
    path: &str,
    body: Value,
    session: Option<&str>,
    origin: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost:8787")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {ROOT}"));
    if let Some(session) = session {
        request = request.header("cookie", format!("{SESSION_COOKIE}={session}"));
    }
    if let Some(origin) = origin {
        request = request.header("origin", origin);
    }
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        build_router(state).oneshot(request.body(Body::from(body.to_string())).unwrap()),
    )
    .await
    .expect("OAuth route request deadline")
    .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn oauth_management_routes_require_session_and_same_origin_for_mutations() {
    let state = fixture("http://127.0.0.1:1/unused-token".into());
    for (method, path, body) in [
        ("POST", START, json!({"manual":true})),
        (
            "POST",
            MANUAL,
            json!({"state":"PUBLIC-unknown-oauth-state","input":"PUBLIC-auth-code"}),
        ),
        ("GET", STATUS, Value::Null),
    ] {
        for session in [None, Some("PUBLIC-expired-oauth-route-session")] {
            let (status, _, _) = request(
                state.clone(),
                method,
                path,
                body.clone(),
                session,
                Some("http://localhost:8787"),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{method} {path} must require an admin session, not a gateway API key"
            );
        }
        if method == "POST" {
            let (status, _, _) = request(
                state.clone(),
                method,
                path,
                body,
                Some(SESSION),
                Some("https://foreign.example.invalid"),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path} Origin gate");
        }
    }
    assert!(state.accounts.lock().unwrap().is_empty());
    assert!(state.creds.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unknown_oauth_state_cannot_exchange_and_callback_needs_no_admin_cookie() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let token_url = format!("http://{}/token", listener.local_addr().unwrap());
    let app = Router::new().fallback(move || {
        let seen = seen.clone();
        async move {
            seen.fetch_add(1, Ordering::SeqCst);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    });
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let state = fixture(token_url);

    let (status, headers, html) = request(
        state.clone(),
        "GET",
        "/oauth/callback?state=PUBLIC-unknown-oauth-state&code=PUBLIC-auth-code",
        Value::Null,
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the public callback must render an unknown/expired-flow result, not require a session"
    );
    assert!(headers["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    assert!(!html.is_empty());
    assert!(!html.contains("PUBLIC-auth-code"));
    assert!(!headers.contains_key("location"));

    let (status, _, _) = request(
        state.clone(),
        "POST",
        MANUAL,
        json!({"state":"PUBLIC-unknown-oauth-state","input":"PUBLIC-auth-code"}),
        Some(SESSION),
        Some("http://localhost:8787"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unknown manual flow");
    let (status, _, _) = request(
        state.clone(),
        "GET",
        STATUS,
        Value::Null,
        Some(SESSION),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unknown status lookup");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "unknown state cannot reach token exchange"
    );
    assert!(state.accounts.lock().unwrap().is_empty());
    assert!(state.creds.lock().unwrap().is_empty());
    server.abort();
}
