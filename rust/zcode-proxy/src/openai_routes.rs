//! OpenAI request adapters over the existing messages ladder.

use std::sync::Arc;

use axum::{
    body::to_bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use rand::RngCore;
use serde_json::{json, Value};
use zcode_core::openai::{
    anthropic_to_chat, anthropic_to_responses, chat_to_anthropic, completions_prompt,
    completions_response, flatten_responses_body,
};

use crate::openai_stream::Output;
use crate::{auth::ResolvedKey, engine, openai_stream, state::AppState};

fn error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({"type":"error", "error":{"type":"api_error", "message":message}})),
    )
        .into_response()
}

fn parse(body: &str) -> Result<Value, &'static str> {
    let value: Value = serde_json::from_str(body).map_err(|_| "body is not valid JSON")?;
    if !value.is_object() {
        return Err("body must be an object");
    }
    if value.get("stream").is_some_and(|v| !v.is_boolean()) {
        return Err("stream must be a boolean");
    }
    Ok(value)
}

fn contains_input_image(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            object.get("type").and_then(Value::as_str) == Some("input_image")
                || object.values().any(contains_input_image)
        }
        Value::Array(items) => items.iter().any(contains_input_image),
        _ => false,
    }
}

async fn relay(
    state: State<Arc<AppState>>,
    key: Extension<ResolvedKey>,
    headers: HeaderMap,
    body: &Value,
    mut anthropic: Value,
    output: Output,
) -> Response {
    let stream = body.get("stream").and_then(Value::as_bool).unwrap_or(false);
    anthropic["stream"] = json!(stream);
    let timings = state.stream_timings;
    let response = engine::handle_messages(state, key, headers, anthropic.to_string()).await;
    if !response.status().is_success() {
        return response;
    }
    if stream {
        if !response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("text/event-stream"))
        {
            return error(
                StatusCode::BAD_GATEWAY,
                "upstream did not return an SSE stream",
            );
        }
        let fallback = match &output {
            Output::Chat => "gpt-4o",
            Output::Completion { .. } => "gpt-3.5-turbo-instruct",
            Output::Responses => "GLM-5.3",
        };
        let model = body["model"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or(fallback);
        let include_usage = body["stream_options"]["include_usage"]
            .as_bool()
            .unwrap_or(false);
        return openai_stream::response(response, output, model.into(), include_usage, timings);
    }
    let bytes = match to_bytes(response.into_body(), 64 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return error(
                StatusCode::BAD_GATEWAY,
                "upstream response could not be read",
            )
        }
    };
    let mut message: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => {
            return error(
                StatusCode::BAD_GATEWAY,
                "upstream response is not valid JSON",
            )
        }
    };
    if message.get("type").and_then(Value::as_str) == Some("error")
        || message.get("error").is_some()
    {
        return (StatusCode::OK, Json(message)).into_response();
    }
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let now = engine::now_secs();
    let result = match output {
        Output::Chat => match anthropic_to_chat(&message, model.unwrap_or("gpt-4o"), now) {
            Ok(value) => value,
            Err(_) => {
                return error(
                    StatusCode::BAD_GATEWAY,
                    "upstream response conversion failed",
                )
            }
        },
        Output::Completion { prompt, echo } => {
            let text = message
                .get("content")
                .and_then(Value::as_array)
                .map(|blocks| {
                    blocks
                        .iter()
                        .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                        .filter_map(|b| b.get("text").and_then(Value::as_str))
                        .collect::<String>()
                })
                .unwrap_or_default();
            let usage = zcode_core::StreamUsage {
                input_tokens: message["usage"]["input_tokens"].as_i64().unwrap_or(0),
                output_tokens: message["usage"]["output_tokens"].as_i64().unwrap_or(0),
                stop_reason: message["stop_reason"].as_str().unwrap_or("").to_string(),
                ..Default::default()
            };
            completions_response(
                model.unwrap_or("gpt-3.5-turbo-instruct"),
                &text,
                Some(&usage),
                echo,
                &prompt,
                now,
            )
        }
        Output::Responses => {
            message["model"] = json!(model.unwrap_or("GLM-5.3"));
            let id = format!("resp_{:016x}", rand::thread_rng().next_u64());
            anthropic_to_responses(&message, &id, now)
        }
    };
    Json(result).into_response()
}

pub async fn handle_chat(
    state: State<Arc<AppState>>,
    key: Extension<ResolvedKey>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let body = match parse(&body) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    let anth = match chat_to_anthropic(&body) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e),
    };
    relay(state, key, headers, &body, anth, Output::Chat).await
}

pub async fn handle_completions(
    state: State<Arc<AppState>>,
    key: Extension<ResolvedKey>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let body = match parse(&body) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    let prompt = match completions_prompt(body.get("prompt")) {
        Ok(v) if !v.is_empty() => v,
        Ok(_) => return error(StatusCode::BAD_REQUEST, "prompt must not be empty"),
        Err(e) => return error(StatusCode::BAD_REQUEST, &e),
    };
    let mut chat = json!({"model":body.get("model"), "messages":[
        {"role":"system", "content":"You are a text completion engine. Continue the user's text seamlessly; output only the continuation, never repeat the prompt and add no commentary."},
        {"role":"user", "content":prompt}
    ]});
    for name in ["max_tokens", "temperature", "top_p", "stop"] {
        if let Some(value) = body.get(name) {
            chat[name] = value.clone();
        }
    }
    let anth = match chat_to_anthropic(&chat) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e),
    };
    let echo = body.get("echo").and_then(Value::as_bool).unwrap_or(false);
    relay(
        state,
        key,
        headers,
        &body,
        anth,
        Output::Completion { prompt, echo },
    )
    .await
}

pub async fn handle_responses(
    state: State<Arc<AppState>>,
    key: Extension<ResolvedKey>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let body = match parse(&body) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    if body
        .get("previous_response_id")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty())
    {
        return error(StatusCode::BAD_REQUEST, "this gateway is stateless: previous_response_id is not supported; send the full conversation input each time");
    }
    if body.get("input").is_some_and(contains_input_image) {
        return error(
            StatusCode::BAD_REQUEST,
            "input_image is not supported by the upstream",
        );
    }
    let mut messages = match flatten_responses_body(&body) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e),
    };
    if messages.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "input must contain at least one message",
        );
    }
    for message in &mut messages {
        if let Some(parts) = message.get_mut("content").and_then(Value::as_array_mut) {
            for part in parts {
                match part.get("type").and_then(Value::as_str) {
                    Some("input_text" | "output_text") => part["type"] = json!("text"),
                    Some("tool_result") => {
                        let id = part["tool_use_id"].clone();
                        let content = part["content"].clone();
                        *message = json!({"role":"tool", "tool_call_id":id, "content":content});
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
    if let Some(instructions) = body
        .get("instructions")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        messages.insert(0, json!({"role":"system", "content":instructions}));
    }
    let mut chat = json!({"model":body.get("model"), "messages":messages});
    for name in ["temperature", "top_p", "tools", "tool_choice", "reasoning"] {
        if let Some(value) = body.get(name) {
            chat[name] = value.clone();
        }
    }
    if let Some(value) = body
        .get("max_output_tokens")
        .filter(|v| !v.is_null())
        .or_else(|| body.get("max_tokens"))
    {
        chat["max_tokens"] = value.clone();
    }
    let anth = match chat_to_anthropic(&chat) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e),
    };
    relay(state, key, headers, &body, anth, Output::Responses).await
}
