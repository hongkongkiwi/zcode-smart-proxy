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

const MODEL: &str = "glm-5.3";
const TEXT: &str = "Hello 香港";
const ROUTES: [&str; 3] = ["/v1/chat/completions", "/v1/completions", "/v1/responses"];

fn event(kind: &str, data: Value) -> String {
    format!("event: {kind}\ndata: {data}\n\n")
}

fn start() -> String {
    event(
        "message_start",
        json!({"type":"message_start", "message":{
            "id":"msg_stream_fixture", "type":"message", "role":"assistant",
            "model":"GLM-5.3", "content":[], "usage":{"input_tokens":11,"output_tokens":0}
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
            "delta":{"type":"text_delta","text":"Hello "}}),
        )
        + &event(
            "content_block_delta",
            json!({"type":"content_block_delta","index":0,
            "delta":{"type":"text_delta","text":"香港"}}),
        )
}

fn finish(reason: &str) -> String {
    event(
        "message_delta",
        json!({"type":"message_delta","delta":{"stop_reason":reason},
        "usage":{"output_tokens":4}}),
    ) + &event("message_stop", json!({"type":"message_stop"}))
}

fn text_suffix(reason: &str) -> String {
    event(
        "content_block_stop",
        json!({"type":"content_block_stop","index":0}),
    ) + &finish(reason)
}

fn tool_start(index: usize, id: &str, name: &str) -> String {
    event(
        "content_block_start",
        json!({"type":"content_block_start","index":index,
        "content_block":{"type":"tool_use","id":id,"name":name,"input":{}}}),
    )
}

fn tool_delta(index: usize, fragment: &str) -> String {
    event(
        "content_block_delta",
        json!({"type":"content_block_delta","index":index,
        "delta":{"type":"input_json_delta","partial_json":fragment}}),
    )
}

struct Fixture {
    app: Router,
    key: String,
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
                        .body(
                            body.lock()
                                .unwrap()
                                .take()
                                .expect("one synthetic upstream request"),
                        )
                        .unwrap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let key = "synthetic-stream-root".to_string();
        let state = Arc::new(AppState::new(
            key.clone(),
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
                zcode_jwt: "synthetic-stream-jwt".into(),
                api_key: "synthetic-stream-key".into(),
                ..Default::default()
            });
        state.creds.lock().unwrap().insert(
            1,
            Creds {
                zcode_jwt: "synthetic-stream-jwt".into(),
                api_key: "synthetic-stream-key".into(),
            },
        );
        Self {
            app: zcode_proxy::build_router(state),
            key,
            server,
        }
    }

    async fn request(&self, path: &str, body: Value) -> axum::response::Response {
        self.app
            .clone()
            .oneshot(
                Request::post(path)
                    .header("x-api-key", &self.key)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn collect(&self, path: &str, body: Value) -> (StatusCode, String) {
        tokio::time::timeout(Duration::from_secs(5), async {
            let response = self.request(path, body).await;
            let status = response.status();
            assert!(
                response.headers()["content-type"]
                    .to_str()
                    .unwrap()
                    .starts_with("text/event-stream"),
                "{path}: streaming response must advertise SSE"
            );
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            (
                status,
                String::from_utf8(bytes.to_vec()).expect("UTF-8 stream"),
            )
        })
        .await
        .expect("loopback stream did not finish within 5s")
    }
}

fn request_body(path: &str) -> Value {
    match path {
        "/v1/completions" => json!({"model":MODEL,"prompt":"PROMPT:","stream":true}),
        "/v1/responses" => json!({"model":MODEL,"input":"hi","stream":true}),
        _ => json!({"model":MODEL,"messages":[{"role":"user","content":"hi"}],"stream":true}),
    }
}

#[derive(Debug)]
struct Frame {
    event: Option<String>,
    data: Value,
    done: bool,
}

fn frames(wire: &str) -> Vec<Frame> {
    wire.replace("\r\n", "\n")
        .split("\n\n")
        .filter_map(|block| {
            let event = block
                .lines()
                .find_map(|s| s.strip_prefix("event:").map(|s| s.trim().to_string()));
            let data = block
                .lines()
                .filter_map(|s| s.strip_prefix("data:").map(str::trim_start))
                .collect::<Vec<_>>()
                .join("\n");
            if data.is_empty() {
                return None;
            }
            let done = data == "[DONE]";
            Some(Frame {
                event,
                data: if done {
                    Value::Null
                } else {
                    serde_json::from_str(&data).expect("SSE data must be JSON or [DONE]")
                },
                done,
            })
        })
        .collect()
}

fn assert_no_anthropic_frames(frames: &[Frame]) {
    let anthropic = [
        "message_start",
        "message_delta",
        "message_stop",
        "content_block_start",
        "content_block_delta",
        "content_block_stop",
    ];
    assert!(!frames.is_empty(), "stream must contain frames");
    for frame in frames {
        assert!(
            !frame
                .event
                .as_deref()
                .is_some_and(|s| anthropic.contains(&s)),
            "Anthropic event leaked to OpenAI client: {frame:?}"
        );
        assert!(
            !frame.data["type"]
                .as_str()
                .is_some_and(|s| anthropic.contains(&s)),
            "Anthropic payload leaked to OpenAI client: {frame:?}"
        );
    }
}

fn assert_done(frames: &[Frame]) {
    assert_eq!(
        frames.iter().filter(|f| f.done).count(),
        1,
        "one [DONE] terminator"
    );
    assert!(frames.last().unwrap().done, "[DONE] must be last");
}

fn chunks(frames: &[Frame], object: &str) -> Vec<Value> {
    assert_no_anthropic_frames(frames);
    assert_done(frames);
    let values: Vec<_> = frames
        .iter()
        .filter(|f| !f.done)
        .map(|f| f.data.clone())
        .collect();
    assert!(!values.is_empty());
    let id = values[0]["id"].as_str().expect("chunk id");
    assert!(!id.is_empty());
    for value in &values {
        assert_eq!(value["object"], object);
        assert_eq!(value["id"], id, "one identity across the stream");
        assert_eq!(value["model"], MODEL, "preserve requested model alias");
        assert!(value["created"].as_i64().is_some_and(|n| n > 0));
        assert!(value["choices"].is_array());
    }
    values
}

fn choices(values: &[Value]) -> Vec<&Value> {
    values
        .iter()
        .flat_map(|v| v["choices"].as_array().unwrap())
        .collect()
}

#[tokio::test]
async fn chat_stream_converts_role_text_finish_and_done() {
    let f = Fixture::new(Body::from(text_prefix() + &text_suffix("end_turn"))).await;
    let (status, wire) = f.collect(ROUTES[0], request_body(ROUTES[0])).await;
    assert_eq!(status, StatusCode::OK);
    let values = chunks(&frames(&wire), "chat.completion.chunk");
    let choices = choices(&values);
    assert_eq!(choices[0]["delta"]["role"], "assistant");
    assert_eq!(
        choices
            .iter()
            .filter(|c| c["delta"]["role"] == "assistant")
            .count(),
        1
    );
    assert!(choices.iter().all(|c| c["index"] == 0));
    let text: String = choices
        .iter()
        .filter_map(|c| c["delta"]["content"].as_str())
        .collect();
    assert_eq!(text, TEXT);
    let terminal: Vec<_> = choices
        .iter()
        .filter(|c| !c["finish_reason"].is_null())
        .collect();
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0]["finish_reason"], "stop");
    assert_eq!(choices.last().unwrap()["finish_reason"], "stop");
}

#[tokio::test]
async fn chat_tool_stream_preserves_partial_json_and_dense_call_indices() {
    let mut upstream = start();
    for (source_index, id, name, fragments) in [
        (2, "call_city", "weather", vec!["{\"city\":", "\"香港\"}"]),
        (7, "call_unit", "units", vec!["{\"unit\":\"", "celsius\"}"]),
    ] {
        upstream += &tool_start(source_index, id, name);
        for fragment in fragments {
            upstream += &tool_delta(source_index, fragment);
        }
        upstream += &event(
            "content_block_stop",
            json!({"type":"content_block_stop","index":source_index}),
        );
    }
    upstream += &finish("tool_use");
    let bytes = upstream.into_bytes();
    let body = Body::from_stream(stream::iter(
        bytes
            .chunks(7)
            .map(|b| Ok::<_, Infallible>(Bytes::copy_from_slice(b)))
            .collect::<Vec<_>>(),
    ));
    let f = Fixture::new(body).await;
    let mut request = request_body(ROUTES[0]);
    request["tools"] = json!([
        {"type":"function","function":{"name":"weather","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}},
        {"type":"function","function":{"name":"units","parameters":{"type":"object","properties":{"unit":{"type":"string"}}}}}
    ]);
    let (status, wire) = f.collect(ROUTES[0], request).await;
    assert_eq!(status, StatusCode::OK);
    let values = chunks(&frames(&wire), "chat.completion.chunk");
    let choices = choices(&values);
    let calls: Vec<_> = choices
        .iter()
        .filter_map(|c| c["delta"]["tool_calls"].as_array())
        .flatten()
        .collect();
    assert!(!calls.is_empty(), "tool deltas must be emitted");
    assert!(calls.iter().all(|c| c["index"] == 0 || c["index"] == 1));
    for (index, id, name, expected_fragments, expected_args) in [
        (
            0,
            "call_city",
            "weather",
            vec!["{\"city\":", "\"香港\"}"],
            json!({"city":"香港"}),
        ),
        (
            1,
            "call_unit",
            "units",
            vec!["{\"unit\":\"", "celsius\"}"],
            json!({"unit":"celsius"}),
        ),
    ] {
        let deltas: Vec<_> = calls.iter().filter(|c| c["index"] == index).collect();
        assert_eq!(deltas[0]["id"], id);
        assert_eq!(deltas[0]["type"], "function");
        assert_eq!(deltas[0]["function"]["name"], name);
        let fragments: Vec<_> = deltas
            .iter()
            .filter_map(|d| d["function"]["arguments"].as_str())
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(
            fragments, expected_fragments,
            "forward each partial_json as an argument delta"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&fragments.concat()).unwrap(),
            expected_args
        );
    }
    let finishes: Vec<_> = choices
        .iter()
        .filter_map(|c| c["finish_reason"].as_str())
        .collect();
    assert_eq!(finishes, ["tool_calls"]);
}

#[tokio::test]
async fn completions_stream_uses_text_completion_shape_and_echo_once() {
    for echo in [false, true] {
        let f = Fixture::new(Body::from(text_prefix() + &text_suffix("max_tokens"))).await;
        let mut request = request_body(ROUTES[1]);
        request["echo"] = json!(echo);
        let (status, wire) = f.collect(ROUTES[1], request).await;
        assert_eq!(status, StatusCode::OK);
        let values = chunks(&frames(&wire), "text_completion");
        let choices = choices(&values);
        for choice in &choices {
            assert_eq!(choice["index"], 0);
            assert!(choice["text"].is_string());
            assert!(
                choice.get("delta").is_none(),
                "legacy completion must not use chat delta"
            );
        }
        let text: String = choices.iter().filter_map(|c| c["text"].as_str()).collect();
        assert_eq!(
            text,
            if echo {
                format!("PROMPT:{TEXT}")
            } else {
                TEXT.into()
            }
        );
        if echo {
            assert_eq!(choices[0]["text"], "PROMPT:Hello ");
        }
        let finishes: Vec<_> = choices
            .iter()
            .filter_map(|c| c["finish_reason"].as_str())
            .collect();
        assert_eq!(finishes, ["length"]);
        assert_eq!(choices.last().unwrap()["text"], "");
        assert_eq!(choices.last().unwrap()["finish_reason"], "length");
    }
}

#[tokio::test]
async fn responses_stream_emits_typed_lifecycle_and_consistent_output_identity() {
    let f = Fixture::new(Body::from(text_prefix() + &text_suffix("end_turn"))).await;
    let (status, wire) = f.collect(ROUTES[2], request_body(ROUTES[2])).await;
    assert_eq!(status, StatusCode::OK);
    let frames = frames(&wire);
    assert_no_anthropic_frames(&frames);
    assert!(
        frames.iter().all(|f| !f.done),
        "Responses ends with a typed terminal, not [DONE]"
    );
    let created = &frames[0];
    assert_eq!(created.event.as_deref(), Some("response.created"));
    assert_eq!(created.data["response"]["object"], "response");
    assert_eq!(created.data["response"]["status"], "in_progress");
    assert_eq!(created.data["response"]["model"], MODEL);
    let id = created.data["response"]["id"]
        .as_str()
        .expect("response id");
    assert!(!id.is_empty());
    let mut previous = None;
    for frame in &frames {
        assert_eq!(
            frame.data["type"].as_str(),
            frame.event.as_deref(),
            "typed Responses event"
        );
        let sequence = frame.data["sequence_number"]
            .as_u64()
            .expect("sequence_number");
        assert!(
            previous.is_none_or(|n| sequence > n),
            "event sequence must increase"
        );
        previous = Some(sequence);
    }
    let deltas: Vec<_> = frames
        .iter()
        .filter(|f| f.event.as_deref() == Some("response.output_text.delta"))
        .collect();
    assert!(!deltas.is_empty());
    let text: String = deltas
        .iter()
        .map(|f| f.data["delta"].as_str().expect("string text delta"))
        .collect();
    assert_eq!(text, TEXT);
    let item_id = deltas[0].data["item_id"].as_str().expect("output item id");
    assert!(!item_id.is_empty());
    for delta in &deltas {
        assert_eq!(delta.data["item_id"], item_id);
        assert_eq!(delta.data["output_index"], 0);
        assert_eq!(delta.data["content_index"], 0);
    }
    let terminal = frames.last().unwrap();
    assert_eq!(terminal.event.as_deref(), Some("response.completed"));
    let response = &terminal.data["response"];
    assert_eq!(response["id"], id);
    assert_eq!(response["object"], "response");
    assert_eq!(response["status"], "completed");
    assert_eq!(response["model"], MODEL);
    assert_eq!(response["output"][0]["id"], item_id);
    assert_eq!(response["output"][0]["type"], "message");
    assert_eq!(response["output"][0]["role"], "assistant");
    assert_eq!(response["output"][0]["status"], "completed");
    assert_eq!(response["output"][0]["content"][0]["type"], "output_text");
    assert_eq!(response["output"][0]["content"][0]["text"], TEXT);
}

#[tokio::test]
async fn truncated_tool_arguments_and_inband_errors_never_emit_success_terminal() {
    // Go tolerates a missing message_stop; invalid nonempty tool JSON is truncation.
    let truncated = start() + &tool_start(2, "call_cut", "weather") + &tool_delta(2, "{\"city\":");
    let upstream_error = text_prefix()
        + &event(
            "error",
            json!({"type":"error",
        "error":{"type":"overloaded_error","message":"synthetic upstream overload"}}),
        );
    for path in ROUTES {
        for (kind, upstream) in [
            ("truncated arguments", &truncated),
            ("inband error", &upstream_error),
        ] {
            let f = Fixture::new(Body::from(upstream.as_str().to_owned())).await;
            let (status, wire) = f.collect(path, request_body(path)).await;
            assert_eq!(status, StatusCode::OK, "{path}: {kind}");
            let frames = frames(&wire);
            assert_no_anthropic_frames(&frames);
            assert!(
                !frames.iter().any(|f| f.data["choices"]
                    .as_array()
                    .is_some_and(|choices| choices.iter().any(|c| !c["finish_reason"].is_null()))),
                "{path}: {kind} must not synthesize a successful finish"
            );
            assert!(
                !frames
                    .iter()
                    .any(|f| f.event.as_deref() == Some("response.completed")),
                "{path}: {kind} must not complete successfully"
            );
            let error = if path == ROUTES[2] {
                let failed = frames
                    .iter()
                    .find(|f| f.event.as_deref() == Some("response.failed"))
                    .expect("Responses failure must emit response.failed");
                assert_eq!(failed.data["response"]["status"], "failed");
                assert_eq!(
                    frames.last().unwrap().event.as_deref(),
                    Some("response.failed")
                );
                &failed.data["response"]["error"]
            } else {
                assert_done(&frames);
                &frames
                    .iter()
                    .find(|f| f.data["error"].is_object())
                    .expect("failed OpenAI stream must emit an error envelope")
                    .data["error"]
            };
            let message = error["message"].as_str().expect("error message");
            assert!(!message.is_empty());
            if kind == "inband error" {
                assert!(message.contains("synthetic upstream overload"));
            }
        }
    }
}

#[tokio::test]
async fn converted_text_arrives_before_upstream_close_on_each_openai_route() {
    for path in ROUTES {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(2);
        let body = Body::from_stream(stream::unfold(rx, |mut rx| async {
            rx.recv()
                .await
                .map(|bytes| (Ok::<_, Infallible>(Bytes::from(bytes)), rx))
        }));
        let f = Fixture::new(body).await;
        let (release, gate) = oneshot::channel();
        let producer = tokio::spawn(async move {
            tx.send(text_prefix().into_bytes()).await.unwrap();
            let _ = gate.await;
            let _ = tx.send(text_suffix("end_turn").into_bytes()).await;
        });
        let early = tokio::time::timeout(Duration::from_secs(2), async {
            let response = f.request(path, request_body(path)).await;
            let status = response.status();
            let mut body = response.into_body().into_data_stream();
            let mut bytes = Vec::new();
            loop {
                let chunk = body.next().await.expect("text before EOF").unwrap();
                bytes.extend_from_slice(&chunk);
                let Ok(wire) = std::str::from_utf8(&bytes) else {
                    continue;
                };
                let Some(end) = wire.rfind("\n\n") else {
                    continue;
                };
                let complete = frames(&wire[..end + 2]);
                let text: String = complete
                    .iter()
                    .filter_map(|f| match path {
                        "/v1/responses" if f.data["type"] == "response.output_text.delta" => {
                            f.data["delta"].as_str()
                        }
                        "/v1/completions" => f.data["choices"][0]["text"].as_str(),
                        "/v1/chat/completions" => f.data["choices"][0]["delta"]["content"].as_str(),
                        _ => None,
                    })
                    .collect();
                if text == TEXT {
                    break;
                }
            }
            (status, bytes, body)
        })
        .await;
        // Release EOF even when the incremental-delivery assertion will fail.
        let _ = release.send(());
        tokio::time::timeout(Duration::from_secs(2), producer)
            .await
            .expect("synthetic producer cleanup timed out")
            .unwrap();
        let (status, mut bytes, mut body) =
            early.expect("converted text did not arrive within 2s while upstream EOF was gated");
        assert_eq!(status, StatusCode::OK, "{path}");
        let early_frames = frames(
            std::str::from_utf8(&bytes)
                .unwrap()
                .rsplit_once("\n\n")
                .unwrap()
                .0,
        );
        assert_no_anthropic_frames(&early_frames);
        assert!(!early_frames
            .iter()
            .any(|f| f.done || f.data["type"] == "response.completed"));
        tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(chunk) = body.next().await {
                bytes.extend_from_slice(&chunk.unwrap());
            }
        })
        .await
        .expect("converted stream did not finish after EOF gate release");
        let complete = frames(std::str::from_utf8(&bytes).unwrap());
        if path == ROUTES[2] {
            assert_eq!(
                complete.last().unwrap().event.as_deref(),
                Some("response.completed")
            );
        } else {
            assert_done(&complete);
        }
    }
}
