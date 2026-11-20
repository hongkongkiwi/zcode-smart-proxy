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
use tokio::sync::{mpsc, oneshot};
use tower::ServiceExt;
use zcode_proxy::{
    auth::key_hash,
    state::{AppState, NamedKey, UpstreamUrls},
    store,
    vault::Vault,
};

const ROUTES: [&str; 2] = ["/v1/chat/completions", "/v1/responses"];
const KEY: &str = "PUBLIC OpenAI stream failure gateway key";
const TEXT: &str = "PUBLIC partial text";
const INITIAL_QUOTA: i64 = 7;

fn event(kind: &str, data: Value) -> String {
    format!("event: {kind}\ndata: {data}\n\n")
}

fn start() -> String {
    event(
        "message_start",
        json!({"type":"message_start","message":{
            "id":"msg_PUBLIC_failure","type":"message","role":"assistant",
            "model":"GLM-5.3","content":[],"usage":{"input_tokens":11,"output_tokens":0}
        }}),
    )
}

fn text_prefix() -> String {
    start()
        + &event(
            "content_block_start",
            json!({"type":"content_block_start","index":0,
                "content_block":{"type":"text","text":""}}),
        )
        + &event(
            "content_block_delta",
            json!({"type":"content_block_delta","index":0,
                "delta":{"type":"text_delta","text":TEXT}}),
        )
}

fn finish(reason: &str) -> String {
    event(
        "message_delta",
        json!({"type":"message_delta","delta":{"stop_reason":reason},
            "usage":{"output_tokens":4}}),
    ) + &event("message_stop", json!({"type":"message_stop"}))
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
    async fn new(body: Body) -> Self {
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
                name: "PUBLIC failure accounting".into(),
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
            "PUBLIC upstream JWT",
            "",
        );
        let state = Arc::new(
            AppState::try_from_db_with_vault(
                String::new(),
                UpstreamUrls {
                    zai: format!("http://{addr}/messages"),
                    zai_fallback: format!("http://{addr}/messages"),
                },
                db,
                Vault::from_secret("PUBLIC stream failure vault seed").unwrap(),
            )
            .unwrap(),
        );
        Self {
            state,
            account_id,
            key_id,
            server,
        }
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

    async fn collect(&self, path: &str) -> Vec<Value> {
        tokio::time::timeout(Duration::from_secs(2), async {
            let response = self.request(path).await;
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            frames(&bytes)
        })
        .await
        .expect("loopback stream did not finish within 2s")
    }

    async fn assert_one_failed_charge(&self) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.state.usage.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("terminal usage was not published within 2s");
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
        assert_eq!(
            (memory, durable),
            (expected.clone(), expected),
            "failed OpenAI conversion must record one 502 with the observed 11 + 4 tokens"
        );
        assert_eq!(quota, INITIAL_QUOTA + 15, "durable charge must occur once");
        assert_eq!(self.state.named_keys.lock().unwrap()[0].quota_used, quota);
    }
}

fn frames(bytes: &[u8]) -> Vec<Value> {
    let wire = std::str::from_utf8(bytes).expect("OpenAI output must be valid UTF-8");
    wire.replace("\r\n", "\n")
        .split_terminator("\n\n")
        .filter_map(|frame| {
            let data = frame
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

fn failure<'a>(values: &'a [Value], path: &str) -> Option<&'a Value> {
    if path == "/v1/responses" {
        values
            .iter()
            .find(|value| value["type"] == "response.failed")
            .map(|value| &value["response"]["error"])
    } else {
        values
            .iter()
            .find(|value| value["error"].is_object())
            .map(|value| &value["error"])
    }
}

fn assert_failed(values: &[Value], path: &str) {
    assert!(
        !values.iter().any(|value| {
            value["type"] == "response.completed"
                || value["choices"].as_array().is_some_and(|choices| {
                    choices
                        .iter()
                        .any(|choice| !choice["finish_reason"].is_null())
                })
        }),
        "{path}: corrupt or failed upstream stream emitted a successful finish"
    );
    let error = failure(values, path).expect("OpenAI failure envelope must be emitted");
    assert!(error["message"]
        .as_str()
        .is_some_and(|message| !message.is_empty()));
}

#[tokio::test]
async fn inband_error_after_partial_text_is_emitted_before_gated_upstream_eof() {
    for path in ROUTES {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(2);
        let body = Body::from_stream(stream::unfold(rx, |mut rx| async {
            rx.recv()
                .await
                .map(|bytes| (Ok::<_, Infallible>(Bytes::from(bytes)), rx))
        }));
        let fixture = Fixture::new(body).await;
        let (release, gate) = oneshot::channel();
        let producer = tokio::spawn(async move {
            let _ = tx.send(text_prefix().into_bytes()).await;
            let _ = tx
                .send(
                    event(
                        "error",
                        json!({"type":"error","error":{"type":"overloaded_error",
                            "message":"PUBLIC gated upstream overload"}}),
                    )
                    .into_bytes(),
                )
                .await;
            let _ = gate.await;
            drop(tx);
        });
        let early = tokio::time::timeout(Duration::from_secs(2), async {
            let mut body = fixture.request(path).await.into_body().into_data_stream();
            let mut bytes = Vec::new();
            while let Some(chunk) = body.next().await {
                bytes.extend_from_slice(&chunk.unwrap());
                let Some(end) = bytes.windows(2).rposition(|window| window == b"\n\n") else {
                    continue;
                };
                let values = frames(&bytes[..end + 2]);
                if failure(&values, path).is_some() {
                    return values;
                }
            }
            frames(&bytes)
        })
        .await;
        // Release EOF before reporting a timeout, so the synthetic producer cannot hang.
        let _ = release.send(());
        tokio::time::timeout(Duration::from_secs(2), producer)
            .await
            .expect("gated upstream cleanup timed out")
            .unwrap();
        let values =
            early.expect("OpenAI error waited for upstream EOF instead of arriving within 2s");
        assert_failed(&values, path);
        assert!(failure(&values, path).unwrap()["message"]
            .as_str()
            .unwrap()
            .contains("PUBLIC gated upstream overload"));
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
            "{path}: partial text preceding the error was lost"
        );
    }
}

#[tokio::test]
async fn invalid_tool_json_at_eof_emits_failure_and_records_one_durable_502_charge() {
    // A terminal stop is present; malformed tool JSON, not a missing stop, is the failure.
    let upstream = start()
        + &event(
            "content_block_start",
            json!({"type":"content_block_start","index":0,"content_block":{
                "type":"tool_use","id":"call_PUBLIC_cut","name":"weather","input":{}}}),
        )
        + &event(
            "content_block_delta",
            json!({"type":"content_block_delta","index":0,
                "delta":{"type":"input_json_delta","partial_json":"{\"city\":"}}),
        )
        + &finish("tool_use");
    for path in ROUTES {
        let fixture = Fixture::new(Body::from(upstream.clone())).await;
        let values = fixture.collect(path).await;
        assert_failed(&values, path);
        fixture.assert_one_failed_charge().await;
    }
}

#[tokio::test]
async fn malformed_json_or_invalid_utf8_between_valid_frames_cannot_finish_successfully() {
    let suffix = event(
        "content_block_stop",
        json!({"type":"content_block_stop","index":0}),
    ) + &finish("end_turn");
    for path in ROUTES {
        let control = Fixture::new(Body::from(
            text_prefix() + ": PUBLIC valid SSE keepalive\n\n" + &suffix,
        ))
        .await;
        let control_values = control.collect(path).await;
        assert!(
            failure(&control_values, path).is_none(),
            "{path}: SSE comment is not corrupt data"
        );
        assert!(
            control_values.iter().any(|value| {
                value["type"] == "response.completed"
                    || value["choices"][0]["finish_reason"] == "stop"
            }),
            "{path}: valid stream containing an SSE comment must finish successfully"
        );
        for invalid in [
            b"event: content_block_delta\ndata: {PUBLIC invalid JSON}\n\n".as_slice(),
            b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"\xff\"}}\n\n".as_slice(),
        ] {
            let mut upstream = text_prefix().into_bytes();
            upstream.extend_from_slice(invalid);
            upstream.extend_from_slice(suffix.as_bytes());
            let fixture = Fixture::new(Body::from(upstream)).await;
            let values = fixture.collect(path).await;
            assert_failed(&values, path);
        }
    }
}
