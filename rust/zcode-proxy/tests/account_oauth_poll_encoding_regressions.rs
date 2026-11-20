use std::{sync::Arc, time::Duration};

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, PollOAuthUrls, UpstreamUrls},
    store,
};

const SESSION: &str = "PUBLIC-poll-encoding-session";
const FLOW: &str = "PUBLIC-poll-encoding-flow";
const JWT: &str = "PUBLIC-poll-encoding-jwt";
const DEADLINE: Duration = Duration::from_secs(2);

struct Mock {
    base: String,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Mock {
    async fn start(expiration_json: &str, interval_json: &str) -> Self {
        // Raw JSON preserves decimal and exponent spelling through the HTTP boundary.
        let init = format!(
            r#"{{"code":0,"data":{{"flow_id":"{FLOW}","authorize_url":"https://chat.z.ai/api/oauth/authorize","expires_at":{expiration_json},"poll_interval_sec":{interval_json}}}}}"#
        );
        let app = Router::new()
            .route(
                "/api/v1/oauth/cli/init",
                post(move || async move { ([("content-type", "application/json")], init) }),
            )
            .route(
                "/api/v1/oauth/cli/poll/PUBLIC-poll-encoding-flow",
                get(|| async {
                    Json(json!({"code":0,"data":{"status":"ready","token":JWT,
                        "user":{"user_id":"PUBLIC-poll-encoding-user","email":"encoding@example.invalid"}}}))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base, server }
    }
}

async fn request(
    state: &Arc<AppState>,
    method: &str,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost:8787")
        .header("origin", "http://localhost:8787")
        .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = tokio::time::timeout(DEADLINE, build_router(state.clone()).oneshot(request))
        .await
        .expect("loopback numeric-encoding request deadline")
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn assert_encoding_reaches_ready(expiration_json: &str, interval_json: &str) {
    let mock = Mock::start(expiration_json, interval_json).await;
    let mut state = AppState::new(
        String::new(),
        UpstreamUrls {
            zai: format!("{}/unused-relay", mock.base),
            zai_fallback: format!("{}/unused-fallback", mock.base),
        },
    );
    state.oauth_poll = PollOAuthUrls {
        init: format!("{}/api/v1/oauth/cli/init", mock.base),
        poll_base: format!("{}/api/v1/oauth/cli/poll", mock.base),
        interval_override: None,
        flow_ttl: Duration::from_secs(3),
    };
    state.oauth.userinfo = format!("{}/unused-userinfo", mock.base);
    state.oauth.business_login = format!("{}/unused-business-login", mock.base);
    state.oauth.customer_info = format!("{}/unused-customer", mock.base);
    state.oauth.project_keys_base = format!("{}/unused-keys", mock.base);
    state.management.oauth_token = format!("{}/unused-token", mock.base);
    state.management.billing_base = format!("{}/unused-billing", mock.base);
    state.management.quota_limit = format!("{}/unused-quota", mock.base);
    state.management.subscription = format!("{}/unused-subscription", mock.base);
    state
        .sessions
        .lock()
        .unwrap()
        .insert(SESSION.into(), now_secs() + 3600);
    let state = Arc::new(state);
    let (status, started) = request(
        &state,
        "POST",
        "/api/accounts/oauth/start",
        json!({"poll":true}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Go-compatible expires_at={expiration_json}, poll_interval_sec={interval_json}: {started}"
    );
    assert_eq!(started["poll"], true);
    assert_eq!(started["state"], FLOW);
    let ready = tokio::time::timeout(DEADLINE, async {
        loop {
            let (status, flow) = request(
                &state,
                "GET",
                &format!("/api/accounts/oauth/status?state={FLOW}"),
                Value::Null,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "flow disappeared: {flow}");
            match flow["status"].as_str() {
                Some("ready") => return flow,
                Some("pending" | "exchanging") => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                _ => panic!("numeric init encoding failed after start: {flow}"),
            }
        }
    })
    .await
    .expect("first ready poll must not wait for the production polling interval");
    let id = ready["account_id"].as_i64().filter(|id| *id > 0).unwrap();
    let rows = store::load_bundle_accounts(&state.db.lock().unwrap(), &state.vault).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, id);
    assert_eq!(rows[0].1.user_id, "PUBLIC-poll-encoding-user");
    assert_eq!(rows[0].1.zcode_jwt, JWT);
    assert_eq!(state.creds.lock().unwrap()[&id].zcode_jwt, JWT);
}

#[tokio::test]
async fn poll_init_accepts_string_expiration_and_integral_decimal_interval_like_go() {
    let future = now_secs() + 60;
    assert_encoding_reaches_ready(&format!(r#""{future}""#), "2.0").await;
}

#[tokio::test]
async fn poll_init_accepts_integral_decimal_and_exponent_expiration_like_go() {
    let future = now_secs() + 60;
    for expiration in [format!("{future}.0"), format!("{future}e0")] {
        assert_encoding_reaches_ready(&expiration, "2").await;
    }
}
