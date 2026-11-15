//! End-to-end tests: the ported data plane (auth middleware -> selection ->
//! classification ladder -> SSE aggregation) serving real HTTP against a
//! mock upstream. This is the phase-4 acceptance gate: the same traffic
//! shapes the Go service handles, verified through the Rust stack.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

use zcode_proxy::state::{AppState, Creds, NamedKey, UpstreamUrls};
use zcode_proxy::{auth, engine};

const SSE_OK: &str = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_e2e\",\"model\":\"GLM-5.3\",\"usage\":{\"input_tokens\":11}}}\n\n\
event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n\
event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"E2E-OK\"}}\n\n\
event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n\
event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":4}}\n\n\
event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

/// Mock upstream: the JWT (free) endpoint always 429s with the 1302 rate
/// limit body; the API-key (paid) endpoint serves a valid SSE stream.
fn mock_upstream() -> Router {
    Router::new()
        .route(
            "/jwt",
            post(|| async {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    axum::Json(json!({"code":1302,"msg":"rate limit"})),
                )
            }),
        )
        .route(
            "/key",
            post(|| async { ([("content-type", "text/event-stream")], SSE_OK) }),
        )
}

async fn setup() -> (Arc<AppState>, String) {
    let upstream = mock_upstream();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, upstream).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;

    let state = Arc::new(AppState::new(
        "sk-root-test".into(),
        UpstreamUrls {
            zai: format!("http://{addr}/jwt"),
            zai_fallback: format!("http://{addr}/key"),
        },
    ));
    state
        .accounts
        .lock()
        .unwrap()
        .push(zcode_core::AccountView {
            id: 1,
            provider: "zai".into(),
            enabled: true,
            status: "active".into(),
            zcode_jwt: "jwt-1".into(),
            api_key: "key-1".into(),
            paid_fallback: true,
            ..Default::default()
        });
    state.creds.lock().unwrap().insert(
        1,
        Creds {
            zcode_jwt: "jwt-1".into(),
            api_key: "key-1".into(),
        },
    );
    (state, "sk-root-test".into())
}

async fn send(app: Router, method: &str, path: &str, key: &str, body: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("x-api-key", key)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

// The wave: free channel 429s (1302) -> classification says rate limited ->
// paid fallback serves the SSE stream -> aggregated into a full message.
#[tokio::test]
async fn free_fails_paid_fallback_aggregates() {
    let (state, root) = setup().await;
    let app = zcode_proxy::build_router(state);
    let (status, body) = send(
        app,
        "POST",
        "/v1/messages",
        &root,
        r#"{"model":"glm-5.3","stream":false,"messages":[{"role":"user","content":"hi"}]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["id"], "msg_e2e");
    assert_eq!(body["content"][0]["text"], "E2E-OK");
    assert_eq!(body["stop_reason"], "end_turn");
    assert_eq!(body["usage"]["input_tokens"], 11);
}

// count_tokens rides the ported estimator.
#[tokio::test]
async fn count_tokens_estimator() {
    let (state, root) = setup().await;
    let app = zcode_proxy::build_router(state);
    let (status, body) = send(
        app,
        "POST",
        "/v1/messages/count_tokens",
        &root,
        r#"{"messages":[{"role":"user","content":"Hello world, this is a test!"}]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // 28 ascii / 4 = 7 (+5% margin stays 7), + per-message overhead 4, + base 8.
    assert_eq!(body["input_tokens"], 8 + 4 + 7);
}

// Named-key model whitelist rejects out-of-list models with 403.
#[tokio::test]
async fn named_key_model_whitelist() {
    let (state, _root) = setup().await;
    state.named_keys.lock().unwrap().push(NamedKey {
        id: 10,
        name: "limited".into(),
        key_hash: zcode_proxy::auth::key_hash("sk-limited"),
        enabled: true,
        models: "glm-5.3".into(),
        rpm_limit: 0,
        rate_5h: 0,
        rate_1d: 0,
        rate_7d: 0,
        quota_total: 0,
        quota_used: 0,
    });
    let app = zcode_proxy::build_router(state);
    let (status, body) = send(
        app,
        "POST",
        "/v1/messages",
        "sk-limited",
        r#"{"model":"glm-5.2","stream":false,"messages":[{"role":"user","content":"hi"}]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("model not allowed"));
}

// Named-key RPM trips at the auth gate.
#[tokio::test]
async fn named_key_rpm_limit() {
    let (state, _root) = setup().await;
    state.named_keys.lock().unwrap().push(NamedKey {
        id: 11,
        name: "rpm1".into(),
        key_hash: zcode_proxy::auth::key_hash("sk-rpm"),
        enabled: true,
        models: "".into(),
        rpm_limit: 1,
        rate_5h: 0,
        rate_1d: 0,
        rate_7d: 0,
        quota_total: 0,
        quota_used: 0,
    });
    let app = zcode_proxy::build_router(state);
    let (s1, _) = send(app.clone(), "GET", "/v1/models", "sk-rpm", "").await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, body) = send(app, "GET", "/v1/models", "sk-rpm", "").await;
    assert_eq!(s2, StatusCode::TOO_MANY_REQUESTS);
    assert!(body["error"]["message"].as_str().unwrap().contains("rpm"));
}

// Models catalog lists the ported table.
#[tokio::test]
async fn models_catalog() {
    let (state, root) = setup().await;
    let app = zcode_proxy::build_router(state);
    let (status, body) = send(app, "GET", "/v1/models", &root, "").await;
    assert_eq!(status, StatusCode::OK);
    let ids: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["id"].as_str())
        .collect();
    assert!(ids.contains(&"GLM-5.3"));
    assert!(ids.contains(&"GLM-5.1-Highspeed"));
}

// Unauthenticated requests are rejected with the canonical error shape.
#[tokio::test]
async fn unauthorized_shape() {
    let (state, _root) = setup().await;
    let app = zcode_proxy::build_router(state);
    let (status, body) = send(app, "POST", "/v1/messages", "", "{}").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["type"], "authentication_error");
}

// ---- Admin surface + persistence ----

// Login -> cookie session -> settings whitelist -> logout. Passwords are
// runtime-generated (scanner policy: no credential literals in source).
#[tokio::test]
async fn admin_flow() {
    let (state, _root) = setup().await;
    let password = format!("pw-{}", std::process::id());
    let hash = bcrypt::hash(&password, 10).unwrap();
    state
        .settings
        .lock()
        .unwrap()
        .insert("admin_password_hash".into(), hash);
    let app = zcode_proxy::build_router(state);

    let wrong_body = json!({"password": format!("not-{}", password)}).to_string();
    let (s_bad, body_bad) = send(app.clone(), "POST", "/api/login", "", &wrong_body).await;
    assert_eq!(s_bad, StatusCode::UNAUTHORIZED);
    assert_eq!(body_bad["success"], false);

    let right_body = json!({"password": password}).to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/api/login")
        .header("content-type", "application/json")
        .body(Body::from(right_body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(cookie.starts_with("zcode_rs_session="));

    let req2 = Request::builder()
        .method("GET")
        .uri("/api/auth/check")
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();
    let resp2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp2.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["authenticated"], true);

    // Settings whitelist: paid_fallback_mode accepted, junk key ignored.
    let put_body = json!({"paid_fallback_mode": "balanced", "junk": "x"}).to_string();
    let req3 = Request::builder()
        .method("PUT")
        .uri("/api/settings")
        .header("cookie", &cookie)
        .header("content-type", "application/json")
        .body(Body::from(put_body))
        .unwrap();
    let resp3 = app.clone().oneshot(req3).await.unwrap();
    assert_eq!(resp3.status(), StatusCode::OK);
    let bytes3 = axum::body::to_bytes(resp3.into_body(), 1 << 20)
        .await
        .unwrap();
    let v3: Value = serde_json::from_slice(&bytes3).unwrap();
    assert_eq!(v3["updated"], json!(["paid_fallback_mode"]));

    // Logout revokes the session.
    let req4 = Request::builder()
        .method("POST")
        .uri("/api/logout")
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();
    let resp4 = app.oneshot(req4).await.unwrap();
    assert_eq!(resp4.status(), StatusCode::OK);
}

// Persistence: accounts/settings survive a from_db reload.
#[tokio::test]
async fn persistence_round_trip() {
    let dir = std::env::temp_dir().join(format!("zcode-rs-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok();
    let db_path = dir.join("t.db");
    let db_path2 = db_path.clone();

    let db = zcode_proxy::store::open(db_path.to_str().unwrap());
    let state = Arc::new(AppState::from_db(
        "root".into(),
        AppState::upstream_from_env(),
        db,
    ));
    state
        .accounts
        .lock()
        .unwrap()
        .push(zcode_core::AccountView {
            id: 1,
            email: "p@t".into(),
            provider: "zai".into(),
            enabled: true,
            status: "active".into(),
            zcode_jwt: "j".into(),
            api_key: "k".into(),
            paid_fallback: true,
            ..Default::default()
        });
    state.creds.lock().unwrap().insert(
        1,
        Creds {
            zcode_jwt: "j".into(),
            api_key: "k".into(),
        },
    );
    {
        let db2 = state.db.lock().unwrap();
        zcode_proxy::store::upsert_account(&db2, &state.accounts.lock().unwrap()[0], "j", "k");
        zcode_proxy::store::set_setting(&db2, "paid_fallback_mode", "never");
    }
    drop(state);

    let db = zcode_proxy::store::open(db_path2.to_str().unwrap());
    let state2 = Arc::new(AppState::from_db(
        "root".into(),
        AppState::upstream_from_env(),
        db,
    ));
    assert_eq!(state2.accounts.lock().unwrap().len(), 1);
    assert_eq!(state2.accounts.lock().unwrap()[0].email, "p@t");
    assert_eq!(
        state2.setting("paid_fallback_mode").as_deref(),
        Some("never")
    );
}

// Unused-import guard for the engine's public items exercised above.
#[allow(unused_imports)]
use auth as _auth_guard;
#[allow(unused_imports)]
use engine as _engine_guard;
