use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::{Body, Bytes},
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use futures_util::{stream, StreamExt};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tower::ServiceExt;
use zcode_proxy::{
    auth::key_hash,
    state::{AppState, NamedKey, StreamTimings, UpstreamUrls},
    store,
    vault::Vault,
};

const ROUTES: [&str; 2] = ["/v1/chat/completions", "/v1/responses"];
const KEY: &str = "PUBLIC stream silence gateway key";
const TEXT: &str = "PUBLIC partial text before silence";
const INITIAL_QUOTA: i64 = 7;

fn event(kind: &str, data: Value) -> String {
    format!("event: {kind}\ndata: {data}\n\n")
}

fn prefix() -> Vec<u8> {
    (event(
        "message_start",
        json!({"type":"message_start","message":{
            "id":"msg_PUBLIC_silence","type":"message","role":"assistant",
            "model":"GLM-5.3","content":[],"usage":{"input_tokens":11,"output_tokens":0}
        }}),
    ) + &event(
        "content_block_start",
        json!({"type":"content_block_start","index":0,
            "content_block":{"type":"text","text":""}}),
    ) + &event(
        "content_block_delta",
        json!({"type":"content_block_delta","index":0,
            "delta":{"type":"text_delta","text":TEXT}}),
    ) + &event(
        "message_delta",
        json!({"type":"message_delta","delta":{},"usage":{"output_tokens":4}}),
    ))
        .into_bytes()
}

struct Fixture {
    state: Arc<AppState>,
    account_id: i64,
    key_id: i64,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn new() -> (Self, mpsc::Sender<Vec<u8>>) {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(2);
        let body = Body::from_stream(stream::unfold(rx, |mut rx| async {
            rx.recv()
                .await
                .map(|bytes| (Ok::<_, Infallible>(Bytes::from(bytes)), rx))
        }));
        let body = Arc::new(Mutex::new(Some(body)));
        let upstream = Router::new().route(
            "/messages",
            post(move || {
                let body = body.clone();
                async move {
                    axum::response::Response::builder()
                        .header("content-type", "text/event-stream")
                        .body(body.lock().unwrap().take().expect("one loopback request"))
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
        store::upsert_gateway_key(
            &db,
            &NamedKey {
                id: 0,
                name: "PUBLIC silence accounting".into(),
                key_hash: key_hash(KEY),
                enabled: true,
                models: String::new(),
                rpm_limit: 0,
                rate_5h: 0,
                rate_1d: 0,
                rate_7d: 0,
                quota_total: 1000,
                quota_used: INITIAL_QUOTA,
            },
        );
        let key_id = store::list_gateway_keys(&db)[0].id;
        let account_id = store::upsert_account(
            &db,
            &zcode_core::AccountView {
                provider: "zai".into(),
                enabled: true,
                status: "active".into(),
                ..Default::default()
            },
            "PUBLIC silence upstream JWT",
            "",
        );
        let mut state = AppState::try_from_db_with_vault(
            String::new(),
            UpstreamUrls {
                zai: format!("http://{addr}/messages"),
                zai_fallback: format!("http://{addr}/messages"),
            },
            db,
            Vault::from_secret("PUBLIC stream silence vault seed").unwrap(),
        )
        .unwrap();
        assert_eq!(
            state.stream_timings.heartbeat_interval,
            Duration::from_secs(15)
        );
        assert_eq!(
            state.stream_timings.silence_timeout,
            Duration::from_secs(120)
        );
        state.stream_timings = StreamTimings {
            heartbeat_interval: Duration::from_millis(25),
            silence_timeout: Duration::from_millis(100),
        };
        (
            Self {
                state: Arc::new(state),
                account_id,
                key_id,
                server,
            },
            tx,
        )
    }

    async fn request(&self, path: &str) -> axum::response::Response {
        let body = if path == "/v1/responses" {
            json!({"model":"glm-5.3","input":"hi","stream":true})
        } else {
            json!({"model":"glm-5.3","messages":[{"role":"user","content":"hi"}],"stream":true})
        };
        let response = zcode_proxy::build_router(self.state.clone())
            .oneshot(
                Request::post(path)
                    .header("x-api-key", KEY)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert!(response.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream"));
        response
    }

    async fn assert_failed_accounting_once(&self) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.state.usage.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("silence failure did not publish terminal usage within 2s");
        let memory: Vec<_> = self
            .state
            .usage
            .lock()
            .unwrap()
            .iter()
            .map(|record| record.summary())
            .collect();
        let (durable, quota) = {
            let db = self.state.db.lock().unwrap();
            (
                store::list_usage(&db, 10)
                    .into_iter()
                    .map(|(_, account, status, key, charge)| (account, status, key, charge))
                    .collect::<Vec<_>>(),
                store::list_gateway_keys(&db)[0].quota_used,
            )
        };
        let expected = vec![(self.account_id, 502, self.key_id, 15)];
        assert_eq!((memory, durable), (expected.clone(), expected));
        assert_eq!(
            quota,
            INITIAL_QUOTA + 15,
            "silence must charge the observed 11 + 4 tokens once"
        );
        assert_eq!(self.state.named_keys.lock().unwrap()[0].quota_used, quota);
    }
}

fn blocks(bytes: &[u8]) -> Vec<&str> {
    let wire = std::str::from_utf8(bytes).expect("OpenAI output must be UTF-8");
    let Some(end) = wire.rfind("\n\n") else {
        return Vec::new();
    };
    wire[..end].split("\n\n").collect()
}

fn heartbeat_count(bytes: &[u8]) -> usize {
    blocks(bytes)
        .iter()
        .filter(|block| {
            block.lines().any(|line| line.starts_with(':'))
                && block
                    .lines()
                    .all(|line| line.is_empty() || line.starts_with(':'))
        })
        .count()
}

fn values(bytes: &[u8]) -> Vec<Value> {
    blocks(bytes)
        .into_iter()
        .filter_map(|block| {
            let data = block
                .lines()
                .filter_map(|line| line.strip_prefix("data:").map(str::trim_start))
                .collect::<Vec<_>>()
                .join("\n");
            if data.is_empty() || data == "[DONE]" {
                None
            } else {
                Some(serde_json::from_str(&data).expect("OpenAI SSE data must be JSON"))
            }
        })
        .collect()
}

fn is_failure(value: &Value, path: &str) -> bool {
    if path == "/v1/responses" {
        value["type"] == "response.failed"
    } else {
        value["error"].is_object()
    }
}

fn is_success(value: &Value) -> bool {
    value["type"] == "response.completed"
        || value["choices"].as_array().is_some_and(|choices| {
            choices
                .iter()
                .any(|choice| !choice["finish_reason"].is_null())
        })
}

#[tokio::test]
async fn timer_emits_comment_heartbeat_without_any_upstream_body_bytes() {
    for path in ROUTES {
        let (fixture, eof_gate) = Fixture::new().await;
        let early = tokio::time::timeout(Duration::from_secs(2), async {
            let mut body = fixture.request(path).await.into_body().into_data_stream();
            let mut bytes = Vec::new();
            while heartbeat_count(&bytes) == 0 {
                let chunk = body
                    .next()
                    .await
                    .expect("timer heartbeat before EOF")
                    .unwrap();
                bytes.extend_from_slice(&chunk);
            }
            (bytes, body)
        })
        .await;
        // No send occurred, and retaining this sender kept upstream EOF closed during the wait.
        drop(eof_gate);
        let (bytes, body) =
            early.expect("no timer-generated SSE comment within 2s without upstream bytes");
        assert!(
            !values(&bytes)
                .iter()
                .any(|value| is_failure(value, path) || is_success(value)),
            "{path}: heartbeat must not fail or finish the response"
        );
        drop(body);
    }
}

#[tokio::test]
async fn upstream_silence_times_out_despite_generated_heartbeats_and_records_502_once() {
    for path in ROUTES {
        let (fixture, eof_gate) = Fixture::new().await;
        eof_gate.send(prefix()).await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let response = fixture.request(path).await;
            axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap()
        })
        .await;
        // EOF is released only after completion or timeout, so missing message_stop is not the trigger.
        drop(eof_gate);
        let bytes = result.expect("100ms upstream silence did not end the response within 2s");
        assert!(
            heartbeat_count(&bytes) > 0,
            "{path}: expected timer heartbeat before silence failure"
        );
        let values = values(&bytes);
        assert!(
            !values.iter().any(is_success),
            "{path}: silence emitted a successful finish"
        );
        let failures: Vec<_> = values
            .iter()
            .filter(|value| is_failure(value, path))
            .collect();
        assert_eq!(
            failures.len(),
            1,
            "{path}: silence must emit exactly one OpenAI failure"
        );
        let error = if path == "/v1/responses" {
            assert_eq!(failures[0]["response"]["status"], "failed");
            &failures[0]["response"]["error"]
        } else {
            &failures[0]["error"]
        };
        assert!(error["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()));
        let text: String = values
            .iter()
            .filter_map(|value| {
                if path == "/v1/responses" && value["type"] == "response.output_text.delta" {
                    value["delta"].as_str()
                } else {
                    value["choices"][0]["delta"]["content"].as_str()
                }
            })
            .collect();
        assert_eq!(
            text, TEXT,
            "{path}: timeout must preserve already received text"
        );
        fixture.assert_failed_accounting_once().await;
    }
}
