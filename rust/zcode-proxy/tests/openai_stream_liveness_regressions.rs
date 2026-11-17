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
use zcode_proxy::state::{AppState, Creds, UpstreamUrls};

const ROUTES: [&str; 2] = ["/v1/chat/completions", "/v1/responses"];
const KEY: &str = "PUBLIC stream liveness root key";
const TEXT: &str = "PUBLIC text before heartbeat";

fn event(kind: &str, data: Value) -> String {
    format!("event: {kind}\ndata: {data}\n\n")
}

fn prefix() -> String {
    event(
        "message_start",
        json!({"type":"message_start","message":{
            "id":"msg_PUBLIC_liveness","type":"message","role":"assistant",
            "model":"GLM-5.3","content":[],"usage":{"input_tokens":11}
        }}),
    ) + &event(
        "content_block_start",
        json!({"type":"content_block_start","index":0,
            "content_block":{"type":"text","text":""}}),
    ) + &event(
        "content_block_delta",
        json!({"type":"content_block_delta","index":0,
            "delta":{"type":"text_delta","text":TEXT}}),
    )
}

fn suffix() -> String {
    event(
        "content_block_stop",
        json!({"type":"content_block_stop","index":0}),
    ) + &event(
        "message_delta",
        json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},
            "usage":{"output_tokens":4}}),
    ) + &event("message_stop", json!({"type":"message_stop"}))
}

struct Fixture {
    app: Router,
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
        let state = Arc::new(AppState::new(
            KEY.into(),
            UpstreamUrls {
                zai: format!("http://{addr}/messages"),
                zai_fallback: format!("http://{addr}/messages"),
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
                zcode_jwt: "PUBLIC liveness JWT".into(),
                ..Default::default()
            });
        state.creds.lock().unwrap().insert(
            1,
            Creds {
                zcode_jwt: "PUBLIC liveness JWT".into(),
                api_key: String::new(),
            },
        );
        Self {
            app: zcode_proxy::build_router(state),
            server,
        }
    }

    async fn request(&self, path: &str) -> axum::response::Response {
        let body = if path == "/v1/responses" {
            json!({"model":"glm-5.3","input":"hi","stream":true})
        } else {
            json!({"model":"glm-5.3","messages":[{"role":"user","content":"hi"}],"stream":true})
        };
        self.app
            .clone()
            .oneshot(
                Request::post(path)
                    .header("x-api-key", KEY)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }
}

fn complete_blocks(bytes: &[u8]) -> Vec<&str> {
    let wire = std::str::from_utf8(bytes).expect("OpenAI output must be UTF-8");
    let Some(end) = wire.rfind("\n\n") else {
        return Vec::new();
    };
    wire[..end].split("\n\n").collect()
}

fn values(bytes: &[u8]) -> Vec<Value> {
    complete_blocks(bytes)
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

fn text(bytes: &[u8], path: &str) -> String {
    values(bytes)
        .iter()
        .filter_map(|value| {
            if path == "/v1/responses" && value["type"] == "response.output_text.delta" {
                value["delta"].as_str()
            } else {
                value["choices"][0]["delta"]["content"].as_str()
            }
        })
        .collect()
}

#[tokio::test]
async fn upstream_ping_yields_openai_comment_heartbeat_before_gated_eof() {
    for path in ROUTES {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(2);
        let body = Body::from_stream(stream::unfold(rx, |mut rx| async {
            rx.recv()
                .await
                .map(|bytes| (Ok::<_, Infallible>(Bytes::from(bytes)), rx))
        }));
        let fixture = Fixture::new(body).await;
        let (send_ping, ping_gate) = oneshot::channel();
        let (release, eof_gate) = oneshot::channel();
        let producer = tokio::spawn(async move {
            let _ = tx.send(prefix().into_bytes()).await;
            let _ = ping_gate.await;
            let _ = tx
                .send(event("ping", json!({"type":"ping"})).into_bytes())
                .await;
            let _ = eof_gate.await;
            let _ = tx.send(suffix().into_bytes()).await;
        });
        let early = tokio::time::timeout(Duration::from_secs(2), async {
            let response = fixture.request(path).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert!(response.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/event-stream"));
            let mut body = response.into_body().into_data_stream();
            let mut bytes = Vec::new();
            while text(&bytes, path) != TEXT {
                let chunk = body
                    .next()
                    .await
                    .expect("partial text before ping")
                    .unwrap();
                bytes.extend_from_slice(&chunk);
            }
            let ping_offset = bytes.len();
            send_ping.send(()).unwrap();
            loop {
                let chunk = body.next().await.expect("heartbeat before EOF").unwrap();
                bytes.extend_from_slice(&chunk);
                let heartbeat = complete_blocks(&bytes[ping_offset..]).iter().any(|block| {
                    block.lines().any(|line| line.starts_with(':'))
                        && block
                            .lines()
                            .all(|line| line.is_empty() || line.starts_with(':'))
                });
                if heartbeat {
                    return (bytes, body);
                }
            }
        })
        .await;
        // Always release the producer before asserting the heartbeat deadline.
        let _ = release.send(());
        tokio::time::timeout(Duration::from_secs(2), producer)
            .await
            .expect("gated ping producer cleanup timed out")
            .unwrap();
        let (mut bytes, mut body) =
            early.expect("upstream ping produced no OpenAI comment heartbeat within 2s before EOF");
        assert_eq!(text(&bytes, path), TEXT);
        assert!(
            !values(&bytes).iter().any(|value| {
                value["type"] == "ping"
                    || value["type"] == "response.completed"
                    || value["choices"][0]["finish_reason"].is_string()
            }),
            "{path}: heartbeat must not leak Anthropic ping or finish the response"
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(chunk) = body.next().await {
                bytes.extend_from_slice(&chunk.unwrap());
            }
        })
        .await
        .expect("stream did not complete after EOF gate release");
        assert!(
            values(&bytes).iter().any(|value| {
                value["type"] == "response.completed"
                    || value["choices"][0]["finish_reason"] == "stop"
            }),
            "{path}: heartbeat must allow the later successful finish"
        );
        assert_eq!(text(&bytes, path), TEXT);
    }
}
