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

const SESSION: &str = "PUBLIC-billing-route-session";
const ACTIONS: &[(&str, &str)] = &[
    ("POST", "detect"),
    ("POST", "claim"),
    ("POST", "activate"),
    ("POST", "reset"),
    ("GET", "reset-status"),
];

fn fixture() -> Arc<AppState> {
    let state = Arc::new(AppState::new(
        String::new(),
        UpstreamUrls {
            zai: "http://127.0.0.1:1/unused-relay".into(),
            zai_fallback: "http://127.0.0.1:1/unused-paid-relay".into(),
        },
    ));
    state
        .sessions
        .lock()
        .unwrap()
        .insert(SESSION.into(), now_secs() + 3600);
    state
}

async fn request(
    state: &Arc<AppState>,
    method: &str,
    id: &str,
    action: &str,
    authenticated: bool,
    origin: &str,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(format!("/api/accounts/{id}/{action}"))
        .header("host", "localhost:8080")
        .header("origin", origin);
    if authenticated {
        request = request.header("cookie", format!("{SESSION_COOKIE}={SESSION}"));
    }
    let response = build_router(state.clone())
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
async fn billing_actions_require_admin_session_and_same_origin_before_account_lookup() {
    let state = fixture();
    let mut failures = Vec::new();
    for &(method, action) in ACTIONS {
        let (status, _) = request(
            &state,
            method,
            "999999",
            action,
            false,
            "http://localhost:8080",
        )
        .await;
        if status != StatusCode::UNAUTHORIZED {
            failures.push(format!(
                "{method} {action}: no session returned {status}, expected 401"
            ));
        }
        if method == "POST" {
            let (status, _) = request(
                &state,
                method,
                "999999",
                action,
                true,
                "https://untrusted.example.invalid",
            )
            .await;
            if status != StatusCode::FORBIDDEN {
                failures.push(format!(
                    "{method} {action}: cross-origin returned {status}, expected 403"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn canonical_billing_actions_distinguish_malformed_ids_from_missing_accounts() {
    let state = fixture();
    let mut failures = Vec::new();
    for &(method, action) in ACTIONS {
        for (id, expected) in [
            ("not-an-id", StatusCode::BAD_REQUEST),
            ("999999", StatusCode::NOT_FOUND),
        ] {
            let (status, body) =
                request(&state, method, id, action, true, "http://localhost:8080").await;
            if status != expected || !body["error"]["message"].is_string() {
                failures.push(format!(
                    "{method} /api/accounts/{id}/{action}: got {status} {body}, expected {expected} with a JSON message"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(state.accounts.lock().unwrap().is_empty());
    assert!(state.creds.lock().unwrap().is_empty());
}
