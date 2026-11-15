use axum::{
    body::{Body, Bytes},
    http::{Request, StatusCode},
    routing::post,
    Json, Router,
};
use futures_util::{stream, StreamExt};
use rand::{distributions::Alphanumeric, Rng};
use serde_json::{json, Value};
use std::{
    convert::Infallible,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use tower::ServiceExt;
use zcode_core::AccountView;
use zcode_proxy::{
    auth::key_hash,
    build_router,
    state::{AppState, NamedKey, UpstreamUrls},
    store,
};

const INITIAL_QUOTA: i64 = 7;
const TOKEN_CHARGE: i64 = 45; // 11 + 4 + 20 + 100 / 10.
const TEXT: &str = "EARLY 香港 🦀";

fn secret() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(40)
        .map(char::from)
        .collect()
}

fn event(kind: &str, data: Value) -> String {
    format!("event: {kind}\ndata: {data}\n\n")
}

fn stream_prefix() -> String {
    event(
        "message_start",
        json!({"type": "message_start", "message": {
            "id": "msg_accounting", "type": "message", "role": "assistant",
            "model": "GLM-5.3", "content": [], "usage": {
                "input_tokens": 11, "output_tokens": 0,
                "cache_creation_input_tokens": 20, "cache_read_input_tokens": 100
            }
        }}),
    ) + &event(
        "content_block_start",
        json!({"type": "content_block_start", "index": 0,
            "content_block": {"type": "text", "text": ""}}),
    ) + &event(
        "content_block_delta",
        json!({"type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": TEXT}}),
    )
}

fn stream_suffix() -> String {
    event(
        "content_block_stop",
        json!({"type": "content_block_stop", "index": 0}),
    ) + &event(
        "message_delta",
        json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"},
            "usage": {"output_tokens": 4}}),
    ) + &event("message_stop", json!({"type": "message_stop"}))
}

fn valid_stream() -> Vec<u8> {
    (stream_prefix() + &stream_suffix()).into_bytes()
}

fn chunked_sse(bytes: Vec<u8>) -> Body {
    // Split every byte, including UTF-8 code points and SSE delimiters.
    Body::from_stream(stream::iter(
        bytes
            .into_iter()
            .map(|b| Ok::<_, Infallible>(Bytes::from(vec![b]))),
    ))
}

struct Fixture {
    state: Arc<AppState>,
    named: String,
    account_id: i64,
    key_id: i64,
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
    async fn new(content_type: &'static str, body: Body, balanced: bool) -> Self {
        let free_calls = Arc::new(AtomicUsize::new(0));
        let paid_calls = Arc::new(AtomicUsize::new(0));
        let response_body = Arc::new(Mutex::new(Some(body)));
        let free_counter = free_calls.clone();
        let paid_counter = paid_calls.clone();
        let free_body = response_body.clone();
        let paid_body = response_body.clone();
        let upstream = Router::new()
            .route(
                "/free",
                post(move || {
                    let counter = free_counter.clone();
                    let body = free_body.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        if balanced {
                            use axum::response::IntoResponse;
                            (
                                StatusCode::BAD_REQUEST,
                                Json(json!({"error": {"message": "captcha rejected"}})),
                            )
                                .into_response()
                        } else {
                            axum::response::Response::builder()
                                .header("content-type", content_type)
                                .body(body.lock().unwrap().take().expect("one terminal attempt"))
                                .unwrap()
                        }
                    }
                }),
            )
            .route(
                "/paid",
                post(move || {
                    let counter = paid_counter.clone();
                    let body = paid_body.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        axum::response::Response::builder()
                            .header("content-type", content_type)
                            .body(body.lock().unwrap().take().expect("one terminal attempt"))
                            .unwrap()
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let db = store::open(":memory:");
        let named = secret();
        store::upsert_gateway_key(
            &db,
            &NamedKey {
                id: 0,
                name: "accounting-test".into(),
                key_hash: key_hash(&named),
                enabled: true,
                models: "".into(),
                rpm_limit: 0,
                rate_5h: 0,
                rate_1d: 0,
                rate_7d: 0,
                quota_total: 200,
                quota_used: INITIAL_QUOTA,
            },
        );
        let keys = store::list_gateway_keys(&db);
        assert_eq!(keys.len(), 1, "fixture must persist its named key");
        let key_id = keys[0].id;
        let account_id = store::upsert_account(
            &db,
            &AccountView {
                provider: "zai".into(),
                enabled: true,
                status: "active".into(),
                paid_fallback: true,
                ..Default::default()
            },
            &secret(),
            &secret(),
        );
        store::set_setting(
            &db,
            "paid_fallback_mode",
            if balanced { "balanced" } else { "free_first" },
        );
        let state = Arc::new(AppState::from_db(
            secret(),
            UpstreamUrls {
                zai: format!("http://{addr}/free"),
                zai_fallback: format!("http://{addr}/paid"),
            },
            db,
        ));
        assert_eq!(state.named_keys.lock().unwrap()[0].id, key_id);
        Self {
            state,
            named,
            account_id,
            key_id,
            free_calls,
            paid_calls,
            server,
        }
    }

    fn request(&self, streaming: bool) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header("x-api-key", &self.named)
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"model": "glm-5.3", "stream": streaming,
                    "messages": [{"role": "user", "content": "hi"}]})
                .to_string(),
            ))
            .unwrap()
    }

    async fn send(&self, streaming: bool) -> (StatusCode, Vec<u8>) {
        tokio::time::timeout(Duration::from_secs(5), async {
            let response = build_router(self.state.clone())
                .oneshot(self.request(streaming))
                .await
                .unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            (status, bytes.to_vec())
        })
        .await
        .expect("local upstream request/body timed out")
    }

    fn calls(&self) -> (usize, usize) {
        (
            self.free_calls.load(Ordering::SeqCst),
            self.paid_calls.load(Ordering::SeqCst),
        )
    }

    async fn assert_accounting(&self, status: u16, charge: i64) {
        // Stream completion may publish its terminal record in a spawned task.
        let _ = tokio::time::timeout(Duration::from_secs(1), async {
            while self.state.usage.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await;
        let memory_records: Vec<_> = self
            .state
            .usage
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.summary())
            .collect();
        let memory_quota = self.state.named_keys.lock().unwrap()[0].quota_used;
        let (db_records, db_quota) = {
            let db = self.state.db.lock().unwrap();
            (
                store::list_usage(&db, 100)
                    .into_iter()
                    .map(|(_, a, s, k, c)| (a, s, k, c))
                    .collect::<Vec<_>>(),
                store::list_gateway_keys(&db)[0].quota_used,
            )
        };
        // Move the same in-memory database through the real startup loader.
        let db = std::mem::replace(&mut *self.state.db.lock().unwrap(), store::open(":memory:"));
        let reloaded = AppState::from_db(secret(), self.state.upstream.clone(), db);
        let reloaded_quota = reloaded.named_keys.lock().unwrap()[0].quota_used;
        let reloaded_records: Vec<_> = store::list_usage(&reloaded.db.lock().unwrap(), 100)
            .into_iter()
            .map(|(_, a, s, k, c)| (a, s, k, c))
            .collect();
        let expected = vec![(self.account_id, status, self.key_id, charge)];
        assert_eq!(
            (
                memory_records,
                db_records,
                reloaded_records,
                memory_quota,
                db_quota,
                reloaded_quota,
            ),
            (
                expected.clone(),
                expected.clone(),
                expected,
                INITIAL_QUOTA + charge,
                INITIAL_QUOTA + charge,
                INITIAL_QUOTA + charge,
            ),
            "terminal records (memory, DB, reload) and named-key quota (memory, DB, reload)"
        );
    }
}

fn sse_values(bytes: &[u8]) -> Vec<Value> {
    std::str::from_utf8(bytes)
        .expect("response must preserve UTF-8")
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .map(|data| serde_json::from_str(data).expect("SSE data must be JSON"))
        .collect()
}

fn assert_message(bytes: &[u8]) {
    let body: Value = serde_json::from_slice(bytes).expect("aggregated Anthropic message");
    assert_eq!(body["type"], "message");
    assert_eq!(body["content"][0]["text"], TEXT);
    assert_eq!(body["stop_reason"], "end_turn");
    assert_eq!(body["usage"]["input_tokens"], 11);
    assert_eq!(body["usage"]["output_tokens"], 4);
}

#[tokio::test]
async fn stream_delivers_start_and_text_before_upstream_finishes() {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(2);
    let body = Body::from_stream(stream::unfold(rx, |mut rx| async {
        rx.recv()
            .await
            .map(|bytes| (Ok::<_, Infallible>(Bytes::from(bytes)), rx))
    }));
    let f = Fixture::new("text/event-stream", body, false).await;
    let (finish, finish_gate) = oneshot::channel();
    let producer = tokio::spawn(async move {
        tx.send(stream_prefix().into_bytes()).await.unwrap();
        let _ = finish_gate.await;
        // A timed-out buffered proxy may have disconnected before cleanup.
        let _ = tx.send(stream_suffix().into_bytes()).await;
    });
    let early = tokio::time::timeout(Duration::from_secs(1), async {
        let response = build_router(f.state.clone())
            .oneshot(f.request(true))
            .await
            .unwrap();
        let status = response.status();
        let mut body = response.into_body().into_data_stream();
        let first = body.next().await.expect("first stream chunk").unwrap();
        let mut bytes = first.to_vec();
        while !(bytes.ends_with(b"\n\n") && bytes.windows(TEXT.len()).any(|s| s == TEXT.as_bytes()))
        {
            match body.next().await {
                Some(chunk) => bytes.extend_from_slice(&chunk.unwrap()),
                None => break,
            }
        }
        (status, bytes, body)
    })
    .await;
    // Always release EOF before asserting the timing result.
    let _ = finish.send(());
    tokio::time::timeout(Duration::from_secs(2), producer)
        .await
        .expect("upstream producer cleanup timed out")
        .unwrap();
    let (status, mut bytes, mut body) = early
        .expect("no first response chunk/text within 1s while upstream finish gate was closed");
    assert_eq!(status, StatusCode::OK);
    let values = sse_values(&bytes);
    assert!(values.iter().any(|v| v["type"] == "message_start"));
    assert!(values.iter().any(|v| v["delta"]["text"] == TEXT));
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(chunk) = body.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
    })
    .await
    .expect("stream did not finish after gate release");
    assert_eq!(bytes, valid_stream());
    assert_eq!(f.calls(), (1, 0));
}

#[tokio::test]
async fn stream_preserves_exact_utf8_and_sse_bytes_across_split_chunks() {
    let expected = valid_stream();
    let f = Fixture::new("text/event-stream", chunked_sse(expected.clone()), false).await;
    let (status, bytes) = f.send(true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, expected);
    assert!(sse_values(&bytes)
        .iter()
        .any(|v| v["delta"]["text"] == TEXT));
    assert_eq!(f.calls(), (1, 0));
}

async fn assert_empty_stream_fails(bytes: Vec<u8>) {
    let f = Fixture::new("text/event-stream", chunked_sse(bytes), false).await;
    let (status, bytes) = f.send(true).await;
    assert!(status == StatusCode::OK || status == StatusCode::BAD_GATEWAY);
    let values = if status == StatusCode::BAD_GATEWAY {
        vec![serde_json::from_slice::<Value>(&bytes).expect("Anthropic JSON error")]
    } else {
        sse_values(&bytes)
    };
    let has_error = values.iter().any(|v| {
        v["type"] == "error"
            && v["error"]["type"].as_str().is_some_and(|s| !s.is_empty())
            && v["error"]["message"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
    });
    // Check both signals together so baseline output shows the fake-success record too.
    let recorded: Vec<_> = f
        .state
        .usage
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.status)
        .collect();
    assert!(
        has_error,
        "empty stream omitted Anthropic error; terminal statuses={recorded:?}"
    );
    assert_eq!(f.calls(), (1, 0));
    f.assert_accounting(502, 0).await;
}

#[tokio::test]
async fn zero_event_stream_emits_error_and_records_502_once() {
    assert_empty_stream_fails(Vec::new()).await;
}

#[tokio::test]
async fn start_stop_empty_stream_emits_error_and_records_502_once() {
    let bytes = (event(
        "message_start",
        json!({"type": "message_start", "message": {
            "id": "msg_empty", "content": [], "usage": {"input_tokens": 0}
        }}),
    ) + &event(
        "message_delta",
        json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"},
            "usage": {"output_tokens": 0}}),
    ) + &event("message_stop", json!({"type": "message_stop"})))
        .into_bytes();
    assert_empty_stream_fails(bytes).await;
}

#[tokio::test]
async fn normal_aggregate_charges_tokens_in_memory_db_and_reload_once() {
    let f = Fixture::new("text/event-stream", chunked_sse(valid_stream()), false).await;
    let (status, bytes) = f.send(false).await;
    assert_eq!(status, StatusCode::OK);
    assert_message(&bytes);
    assert_eq!(f.calls(), (1, 0));
    f.assert_accounting(200, TOKEN_CHARGE).await;
}

#[tokio::test]
async fn balanced_paid_aggregate_charges_only_terminal_success_once() {
    let f = Fixture::new("text/event-stream", chunked_sse(valid_stream()), true).await;
    let (status, bytes) = f.send(false).await;
    assert_eq!(status, StatusCode::OK);
    assert_message(&bytes);
    assert_eq!(f.calls(), (1, 1), "exercise same-account balanced cascade");
    f.assert_accounting(200, TOKEN_CHARGE).await;
}

#[tokio::test]
async fn json_success_charges_tokens_in_memory_db_and_reload_once() {
    let body = json!({
        "id": "msg_accounting", "type": "message", "role": "assistant",
        "model": "GLM-5.3", "content": [{"type": "text", "text": TEXT}],
        "stop_reason": "end_turn", "usage": {
            "input_tokens": 11, "output_tokens": 4,
            "cache_creation_input_tokens": 20, "cache_read_input_tokens": 100
        }
    });
    let f = Fixture::new("application/json", Body::from(body.to_string()), false).await;
    let (status, bytes) = f.send(false).await;
    assert_eq!(status, StatusCode::OK);
    assert_message(&bytes);
    assert_eq!(f.calls(), (1, 0));
    f.assert_accounting(200, TOKEN_CHARGE).await;
}

#[tokio::test]
async fn streamed_success_charges_tokens_in_memory_db_and_reload_once() {
    let expected = valid_stream();
    let f = Fixture::new("text/event-stream", chunked_sse(expected.clone()), false).await;
    let (status, bytes) = f.send(true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, expected);
    assert_eq!(f.calls(), (1, 0));
    f.assert_accounting(200, TOKEN_CHARGE).await;
}
