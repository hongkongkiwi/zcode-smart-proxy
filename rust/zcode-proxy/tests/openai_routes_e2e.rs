use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Json, Router,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_proxy::state::{AppState, Creds, UpstreamUrls};

const SSE: &str = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_test\",\"model\":\"GLM-5.3\",\"usage\":{\"input_tokens\":11}}}\n\n\
event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n\
event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" world\"}}\n\n\
event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n\
event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":4}}\n\n\
event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

async fn setup() -> (Router, String, Arc<Mutex<Vec<Value>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let captured = seen.clone();
    let upstream = Router::new()
        .route(
            "/free",
            post(|| async { (StatusCode::TOO_MANY_REQUESTS, Json(json!({"code":1302}))) }),
        )
        .route(
            "/paid",
            post(move |Json(body): Json<Value>| {
                let captured = captured.clone();
                async move {
                    captured.lock().unwrap().push(body);
                    ([("content-type", "text/event-stream")], SSE)
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, upstream).await.unwrap();
    });
    let key = format!("test-root-{}", std::process::id());
    let state = Arc::new(AppState::new(
        key.clone(),
        UpstreamUrls {
            zai: format!("http://{addr}/free"),
            zai_fallback: format!("http://{addr}/paid"),
        },
    ));
    let jwt = format!("test-jwt-{}", std::process::id());
    let api_key = format!("test-key-{}", std::process::id());
    state
        .accounts
        .lock()
        .unwrap()
        .push(zcode_core::AccountView {
            id: 1,
            provider: "zai".into(),
            enabled: true,
            status: "active".into(),
            zcode_jwt: jwt.clone(),
            api_key: api_key.clone(),
            paid_fallback: true,
            ..Default::default()
        });
    state.creds.lock().unwrap().insert(
        1,
        Creds {
            zcode_jwt: jwt,
            api_key,
        },
    );
    (zcode_proxy::build_router(state), key, seen)
}

async fn send(app: Router, key: &str, path: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::post(path)
                .header("x-api-key", key)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn chat_uses_fallback_and_converts_sse() {
    let (app, key, seen) = setup().await;
    let (status, body) = send(
        app,
        &key,
        "/v1/chat/completions",
        json!({"model":"glm-5.3","messages":[{"role":"user","content":"hi"}]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["object"], "chat.completion");
    assert_eq!(body["choices"][0]["message"]["content"], " world");
    assert_eq!(body["usage"]["total_tokens"], 15);
    assert_eq!(
        seen.lock().unwrap()[0]["messages"][0]["content"][0]["text"],
        "hi"
    );
}

#[tokio::test]
async fn completions_echo_and_options() {
    let (app, key, seen) = setup().await;
    let (status, body) = send(app, &key, "/v1/completions", json!({"prompt":"hello","echo":true,"max_tokens":12,"temperature":0.5,"top_p":0.8,"stop":"end"})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["object"], "text_completion");
    assert_eq!(body["choices"][0]["text"], "hello world");
    let seen = seen.lock().unwrap();
    assert!(seen[0]["system"]
        .as_str()
        .unwrap()
        .starts_with("You are a text completion engine."));
    assert_eq!(seen[0]["max_tokens"], 12);
    assert_eq!(seen[0]["temperature"], 0.5);
    assert_eq!(seen[0]["top_p"], 0.8);
    assert_eq!(seen[0]["stop_sequences"], json!(["end"]));
}

#[tokio::test]
async fn responses_rejects_state_and_images() {
    let (app, key, _) = setup().await;
    let (status, body) = send(
        app.clone(),
        &key,
        "/v1/responses",
        json!({"previous_response_id":"resp_old","input":"hi"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["type"], "api_error");
    let (status, _) = send(app, &key, "/v1/responses", json!({"input":[{"type":"message","role":"user","content":[{"type":"input_image","image_url":"x"}]}]})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn responses_returns_output_text() {
    let (app, key, seen) = setup().await;
    let (status, body) = send(
        app,
        &key,
        "/v1/responses",
        json!({"input":"hello", "instructions":"be brief", "max_output_tokens":8}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["object"], "response");
    assert_eq!(body["output_text"], " world");
    assert_eq!(seen.lock().unwrap()[0]["system"], "be brief");
}
