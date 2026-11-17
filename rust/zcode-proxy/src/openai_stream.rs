//! Pull-based OpenAI framing over the messages relay's accounting body.

use std::{collections::BTreeMap, pin::Pin};

use axum::{
    body::{Body, Bytes},
    response::{IntoResponse, Response},
};
use futures_util::{stream, Stream, StreamExt};
use rand::RngCore;
use serde_json::{json, Value};
use zcode_core::{SseEvent, SseParser};

const MAX_OUTPUT: usize = 64 << 20;
const MAX_ARGUMENTS: usize = 16 << 20;
const MAX_BLOCKS: usize = 4096;

#[derive(Default)]
struct StrictParser {
    frame: Vec<u8>,
    parser: SseParser,
}

impl StrictParser {
    fn feed(&mut self, byte: u8, converter: &mut Converter) -> Result<(), String> {
        if self.frame.len() == 16 << 20 {
            return Err("upstream SSE frame exceeds 16MiB".into());
        }
        self.frame.push(byte);
        if self.frame.ends_with(b"\n\n") || self.frame.ends_with(b"\r\n\r\n") {
            self.flush(converter)?;
        }
        Ok(())
    }

    fn flush(&mut self, converter: &mut Converter) -> Result<(), String> {
        if self.frame.is_empty() {
            return Ok(());
        }
        let text =
            std::str::from_utf8(&self.frame).map_err(|_| "upstream SSE contains invalid UTF-8")?;
        let data = text
            .trim_start_matches('\u{feff}')
            .lines()
            .filter_map(|line| line.strip_prefix("data:").map(str::trim))
            .collect::<Vec<_>>()
            .join("\n");
        if !data.is_empty() && data != "[DONE]" {
            let value: Value =
                serde_json::from_str(&data).map_err(|_| "upstream SSE data is not valid JSON")?;
            if !value.is_object() {
                return Err("upstream SSE data must be an object".into());
            }
        }
        self.parser
            .feed(&self.frame, &mut |event| converter.handle(event))
            .map_err(|_| "upstream SSE frame exceeds 16MiB")?;
        self.parser.flush(&mut |event| converter.handle(event));
        self.frame.clear();
        Ok(())
    }
}

type Upstream = Pin<Box<dyn Stream<Item = Result<Bytes, axum::Error>> + Send>>;

pub(crate) enum Output {
    Chat,
    Completion { prompt: String, echo: bool },
    Responses,
}

fn id(prefix: &str) -> String {
    format!("{prefix}{:016x}", rand::thread_rng().next_u64())
}

fn string(value: &Value, key: &str) -> String {
    value.get(key).and_then(Value::as_str).unwrap_or("").into()
}

struct Block {
    kind: String,
    item_id: String,
    call_id: String,
    name: String,
    output_index: usize,
    tool_index: usize,
    text: String,
    arguments: String,
    start_arguments: String,
    args_seen: bool,
    closed: bool,
}

struct Converter {
    output: Output,
    model: String,
    id: String,
    created: i64,
    sequence: u64,
    include_usage: bool,
    input_tokens: i64,
    output_tokens: i64,
    cached_tokens: i64,
    stop_reason: String,
    started: bool,
    stopped: bool,
    content: bool,
    role_sent: bool,
    blocks: BTreeMap<u64, Block>,
    next_output: usize,
    next_tool: usize,
    retained: usize,
    failure: Option<String>,
    wire: String,
}

impl Converter {
    fn new(output: Output, model: String, include_usage: bool) -> Self {
        let prefix = match &output {
            Output::Chat => "chatcmpl-",
            Output::Completion { .. } => "cmpl-",
            Output::Responses => "resp_",
        };
        Self {
            output,
            model,
            id: id(prefix),
            created: crate::engine::now_secs(),
            sequence: 0,
            include_usage,
            input_tokens: 0,
            output_tokens: 0,
            cached_tokens: 0,
            stop_reason: String::new(),
            started: false,
            stopped: false,
            content: false,
            role_sent: false,
            blocks: BTreeMap::new(),
            next_output: 0,
            next_tool: 0,
            retained: 0,
            failure: None,
            wire: String::new(),
        }
    }

    fn fail(&mut self, message: impl Into<String>) {
        if self.failure.is_none() {
            self.failure = Some(message.into());
        }
    }

    fn reserve(&mut self, bytes: usize) -> bool {
        if bytes > MAX_OUTPUT - self.retained {
            self.fail("upstream output exceeds 64MiB");
            return false;
        }
        self.retained += bytes;
        true
    }

    fn data(&mut self, value: Value) {
        self.wire.push_str(&format!("data: {value}\n\n"));
    }

    fn event(&mut self, name: &str, mut value: Value) {
        value["type"] = json!(name);
        value["sequence_number"] = json!(self.sequence);
        self.sequence += 1;
        self.wire
            .push_str(&format!("event: {name}\ndata: {value}\n\n"));
    }

    fn response(&self, status: &str) -> Value {
        json!({"id":self.id,"object":"response","created_at":self.created,
            "status":status,"model":self.model,"output":[]})
    }

    fn chunk(&mut self, choices: Value, usage: Option<Value>) {
        let object = if matches!(self.output, Output::Chat) {
            "chat.completion.chunk"
        } else {
            "text_completion"
        };
        let mut value = json!({"id":self.id,"object":object,"created":self.created,
            "model":self.model,"choices":choices});
        if self.include_usage && matches!(self.output, Output::Chat) {
            value["usage"] = Value::Null;
        }
        if let Some(usage) = usage {
            value["usage"] = usage;
        }
        self.data(value);
    }

    fn chat(&mut self, delta: Value, finish: Option<&str>) {
        self.chunk(
            json!([{"index":0,"delta":delta,"finish_reason":finish}]),
            None,
        );
    }

    fn role(&mut self) {
        if matches!(self.output, Output::Chat) && !self.role_sent {
            self.role_sent = true;
            self.chat(json!({"role":"assistant","content":""}), None);
        }
    }

    fn completion(&mut self, text: &str, finish: Option<&str>) {
        self.chunk(
            json!([{"index":0,"text":text,"logprobs":null,"finish_reason":finish}]),
            None,
        );
    }

    fn usage(&mut self, value: &Value) {
        for (target, key) in [
            (&mut self.input_tokens, "input_tokens"),
            (&mut self.output_tokens, "output_tokens"),
            (&mut self.cached_tokens, "cache_read_input_tokens"),
        ] {
            *target = (*target).max(value[key].as_i64().unwrap_or(0));
        }
    }

    fn open_item(&mut self, block: &mut Block) {
        if !block.item_id.is_empty() || !matches!(self.output, Output::Responses) {
            return;
        }
        block.output_index = self.next_output;
        self.next_output += 1;
        let (prefix, item) = match block.kind.as_str() {
            "text" => (
                "msg_",
                json!({"type":"message","status":"in_progress","role":"assistant","content":[]}),
            ),
            "thinking" => ("rs_", json!({"type":"reasoning","summary":[]})),
            "tool_use" => (
                "fc_",
                json!({"type":"function_call","status":"in_progress","call_id":block.call_id,"name":block.name,"arguments":""}),
            ),
            _ => return,
        };
        block.item_id = id(prefix);
        let mut item = item;
        item["id"] = json!(block.item_id);
        self.event(
            "response.output_item.added",
            json!({"output_index":block.output_index,"item":item}),
        );
        match block.kind.as_str() {
            "text" => self.event("response.content_part.added", json!({"item_id":block.item_id,"output_index":block.output_index,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}})),
            "thinking" => self.event("response.reasoning_summary_part.added", json!({"item_id":block.item_id,"output_index":block.output_index,"summary_index":0,"part":{"type":"summary_text","text":""}})),
            _ => {}
        }
    }

    fn text(&mut self, block: &mut Block, text: &str) {
        if text.is_empty() || !self.reserve(text.len()) {
            return;
        }
        self.content = true;
        match &mut self.output {
            Output::Chat => {
                self.role();
                let key = if block.kind == "thinking" {
                    "reasoning_content"
                } else {
                    "content"
                };
                self.chat(json!({key:text}), None);
            }
            Output::Completion { prompt, echo } if block.kind == "text" => {
                let text = if *echo {
                    *echo = false;
                    format!("{prompt}{text}")
                } else {
                    text.to_owned()
                };
                self.completion(&text, None);
            }
            Output::Responses => {
                self.open_item(block);
                block.text.push_str(text);
                if block.kind == "thinking" {
                    self.event("response.reasoning_summary_text.delta", json!({"item_id":block.item_id,"output_index":block.output_index,"summary_index":0,"delta":text}));
                } else {
                    self.event("response.output_text.delta", json!({"item_id":block.item_id,"output_index":block.output_index,"content_index":0,"delta":text}));
                }
            }
            _ => {}
        }
    }

    fn arguments(&mut self, block: &mut Block, fragment: &str) {
        if fragment.len() > MAX_ARGUMENTS - block.arguments.len() {
            self.fail("upstream tool arguments exceed 16MiB");
            return;
        }
        if !self.reserve(fragment.len()) {
            return;
        }
        block.args_seen = true;
        block.arguments.push_str(fragment);
        match self.output {
            Output::Chat => self.chat(json!({"tool_calls":[{"index":block.tool_index,"function":{"arguments":fragment}}]}), None),
            Output::Responses => self.event("response.function_call_arguments.delta", json!({"item_id":block.item_id,"output_index":block.output_index,"delta":fragment})),
            Output::Completion { .. } => {}
        }
    }

    fn item(block: &Block) -> Value {
        match block.kind.as_str() {
            "tool_use" => {
                json!({"id":block.item_id,"type":"function_call","status":"completed","call_id":block.call_id,"name":block.name,"arguments":block.arguments})
            }
            "thinking" => {
                json!({"id":block.item_id,"type":"reasoning","summary":[{"type":"summary_text","text":block.text}]})
            }
            _ => {
                json!({"id":block.item_id,"type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":block.text,"annotations":[]}]})
            }
        }
    }

    fn close(&mut self, block: &mut Block) {
        if block.closed {
            return;
        }
        if block.kind == "tool_use" {
            if !block.args_seen {
                let args = std::mem::take(&mut block.start_arguments);
                self.arguments(block, &args);
            }
            match serde_json::from_str::<Value>(&block.arguments) {
                Ok(Value::Object(_) | Value::Null) => {}
                _ => {
                    self.fail("upstream tool arguments truncated");
                    return;
                }
            }
        }
        if self.failure.is_some() {
            return;
        }
        block.closed = true;
        if !matches!(self.output, Output::Responses) || block.item_id.is_empty() {
            return;
        }
        let base = json!({"item_id":block.item_id,"output_index":block.output_index});
        match block.kind.as_str() {
            "tool_use" => {
                let mut event = base;
                event["arguments"] = json!(block.arguments);
                self.event("response.function_call_arguments.done", event);
            }
            "thinking" => {
                let mut event = base;
                event["summary_index"] = json!(0);
                event["text"] = json!(block.text);
                self.event("response.reasoning_summary_text.done", event.clone());
                event.as_object_mut().unwrap().remove("text");
                event["part"] = json!({"type":"summary_text","text":block.text});
                self.event("response.reasoning_summary_part.done", event);
            }
            _ => {
                let mut event = base;
                event["content_index"] = json!(0);
                event["text"] = json!(block.text);
                self.event("response.output_text.done", event.clone());
                event.as_object_mut().unwrap().remove("text");
                event["part"] = json!({"type":"output_text","text":block.text,"annotations":[]});
                self.event("response.content_part.done", event);
            }
        }
        self.event(
            "response.output_item.done",
            json!({"output_index":block.output_index,"item":Self::item(block)}),
        );
    }

    fn handle(&mut self, event: SseEvent) {
        if self.failure.is_some() {
            return;
        }
        let kind = if event.event.is_empty() {
            event.data["type"].as_str().unwrap_or("")
        } else {
            &event.event
        };
        let data = &event.data;
        match kind {
            "ping" => self.wire.push_str(": keepalive\n\n"),
            "error" => {
                let message = data["error"]["message"]
                    .as_str()
                    .unwrap_or("upstream stream error");
                self.fail(message);
            }
            "message_start" => {
                self.started = true;
                self.usage(&data["message"]["usage"]);
            }
            "message_delta" => {
                self.usage(&data["usage"]);
                let reason = string(&data["delta"], "stop_reason");
                if !reason.is_empty() {
                    self.stop_reason = reason;
                }
            }
            "message_stop" => self.stopped = true,
            "content_block_start" => {
                let index = data["index"].as_u64().unwrap_or(0);
                if self.blocks.len() == MAX_BLOCKS || self.blocks.contains_key(&index) {
                    self.fail("upstream content block limit or duplicate index");
                    return;
                }
                let source = &data["content_block"];
                let kind = string(source, "type");
                if !matches!(kind.as_str(), "text" | "thinking" | "tool_use") {
                    return;
                }
                let mut block = Block {
                    kind,
                    item_id: String::new(),
                    call_id: string(source, "id"),
                    name: string(source, "name"),
                    output_index: 0,
                    tool_index: self.next_tool,
                    text: String::new(),
                    arguments: String::new(),
                    start_arguments: String::new(),
                    args_seen: false,
                    closed: false,
                };
                if block.kind == "tool_use" {
                    self.content = true;
                    self.next_tool += 1;
                    if block.call_id.is_empty() {
                        block.call_id = id("call_");
                    }
                    if block.name.is_empty() {
                        block.name = "tool".into();
                    }
                    block.start_arguments = source
                        .get("input")
                        .filter(|v| !v.is_null())
                        .map(Value::to_string)
                        .unwrap_or_else(|| "{}".into());
                    if block.start_arguments.len() > MAX_ARGUMENTS {
                        self.fail("upstream tool arguments exceed 16MiB");
                        return;
                    }
                    if !self.reserve(
                        block.start_arguments.len() + block.name.len() + block.call_id.len(),
                    ) {
                        return;
                    }
                    self.role();
                    if matches!(self.output, Output::Chat) {
                        self.chat(json!({"tool_calls":[{"index":block.tool_index,"id":block.call_id,"type":"function","function":{"name":block.name,"arguments":""}}]}), None);
                    }
                    self.open_item(&mut block);
                } else {
                    let field = if block.kind == "thinking" {
                        "thinking"
                    } else {
                        "text"
                    };
                    self.text(&mut block, &string(source, field));
                }
                self.blocks.insert(index, block);
            }
            "content_block_delta" | "content_block_stop" => {
                let index = data["index"].as_u64().unwrap_or(0);
                let Some(mut block) = self.blocks.remove(&index) else {
                    return;
                };
                if !block.closed {
                    if kind == "content_block_stop" {
                        self.close(&mut block);
                    } else {
                        let delta = &data["delta"];
                        match (block.kind.as_str(), delta["type"].as_str().unwrap_or("")) {
                            ("tool_use", "input_json_delta") => {
                                self.arguments(&mut block, &string(delta, "partial_json"))
                            }
                            ("text", "text_delta") => self.text(&mut block, &string(delta, "text")),
                            ("thinking", "thinking_delta") => {
                                self.text(&mut block, &string(delta, "thinking"))
                            }
                            _ => {}
                        }
                    }
                }
                self.blocks.insert(index, block);
            }
            _ => {}
        }
    }

    fn prepare_finish(&mut self) {
        if self.failure.is_none() && (!self.started || !self.content) {
            self.fail("upstream stream ended without any content");
        }
        if self.failure.is_none() && !self.stopped && self.stop_reason.is_empty() {
            self.fail("upstream stream interrupted before completion");
        }
        if self.failure.is_none() {
            let mut blocks = std::mem::take(&mut self.blocks);
            for block in blocks.values_mut() {
                self.close(block);
                if self.failure.is_some() {
                    break;
                }
            }
            self.blocks = blocks;
        }
    }

    fn finish(&mut self) {
        if let Some(message) = self.failure.clone() {
            let error = json!({"type":"api_error","code":"stream_error","message":message});
            if matches!(self.output, Output::Responses) {
                let mut response = self.response("failed");
                response["error"] = error;
                self.event("response.failed", json!({"response":response}));
            } else {
                self.data(json!({"error":error}));
                self.wire.push_str("data: [DONE]\n\n");
            }
            return;
        }
        if matches!(self.output, Output::Responses) {
            let incomplete = self.stop_reason == "max_tokens";
            let status = if incomplete {
                "incomplete"
            } else {
                "completed"
            };
            let mut response = self.response(status);
            let mut blocks: Vec<_> = self
                .blocks
                .values()
                .filter(|b| !b.item_id.is_empty())
                .collect();
            blocks.sort_by_key(|b| b.output_index);
            response["output"] = json!(blocks.iter().map(|b| Self::item(b)).collect::<Vec<_>>());
            response["output_text"] = json!(blocks
                .iter()
                .filter(|b| b.kind == "text")
                .map(|b| b.text.as_str())
                .collect::<String>());
            response["usage"] = self.final_usage(true);
            if incomplete {
                response["incomplete_details"] = json!({"reason":"max_output_tokens"});
            }
            self.event(
                if incomplete {
                    "response.incomplete"
                } else {
                    "response.completed"
                },
                json!({"response":response}),
            );
        } else {
            if matches!(self.output, Output::Chat) {
                self.role();
                let reason = match self.stop_reason.as_str() {
                    "max_tokens" => "length",
                    "refusal" => "content_filter",
                    "tool_use" => "tool_calls",
                    _ if self.next_tool > 0 => "tool_calls",
                    _ => "stop",
                };
                self.chat(json!({}), Some(reason));
            } else {
                if let Output::Completion { prompt, echo: true } = &self.output {
                    self.completion(&prompt.clone(), None);
                }
                self.completion(
                    "",
                    Some(zcode_core::openai::completions_finish(&self.stop_reason)),
                );
            }
            if self.include_usage {
                self.chunk(json!([]), Some(self.final_usage(false)));
            }
            self.wire.push_str("data: [DONE]\n\n");
        }
    }

    fn final_usage(&self, responses: bool) -> Value {
        let (input, output, details) = if responses {
            ("input_tokens", "output_tokens", "input_tokens_details")
        } else {
            (
                "prompt_tokens",
                "completion_tokens",
                "prompt_tokens_details",
            )
        };
        let mut usage = json!({input:self.input_tokens,output:self.output_tokens,
            "total_tokens":self.input_tokens.saturating_add(self.output_tokens)});
        if self.cached_tokens > 0 {
            usage[details] = json!({"cached_tokens":self.cached_tokens});
        }
        usage
    }
}

struct Relay {
    upstream: Upstream,
    completion: Option<crate::streaming::Completion>,
    parser: StrictParser,
    converter: Converter,
    chunk: Bytes,
    offset: usize,
    done: bool,
    timings: crate::state::StreamTimings,
    last_activity: tokio::time::Instant,
    last_heartbeat: tokio::time::Instant,
}

impl Relay {
    fn finish(&mut self) {
        self.converter.prepare_finish();
        if let Some(completion) = self.completion.take() {
            let status = if self.converter.failure.is_some() {
                502
            } else {
                200
            };
            if let Err(error) = completion.finish(status) {
                self.converter.fail(error);
            }
        }
        self.converter.finish();
        self.done = true;
        self.chunk = Bytes::new();
        self.upstream = Box::pin(stream::empty());
    }
}

pub(crate) fn response(
    mut response: Response,
    output: Output,
    model: String,
    include_usage: bool,
    timings: crate::state::StreamTimings,
) -> Response {
    let mut converter = Converter::new(output, model, include_usage);
    if matches!(converter.output, Output::Responses) {
        converter.event(
            "response.created",
            json!({"response":converter.response("in_progress")}),
        );
    }
    let completion = response
        .extensions_mut()
        .remove::<crate::streaming::Completion>();
    if let Some(completion) = &completion {
        completion.defer();
    }
    let now = tokio::time::Instant::now();
    if timings.heartbeat_interval.is_zero() || timings.silence_timeout.is_zero() {
        converter.fail("stream timing intervals must be positive");
    }
    let relay = Relay {
        upstream: Box::pin(response.into_body().into_data_stream()),
        completion,
        parser: StrictParser::default(),
        converter,
        chunk: Bytes::new(),
        offset: 0,
        done: false,
        timings,
        last_activity: now,
        last_heartbeat: now,
    };
    let body = stream::unfold(relay, |mut relay| async move {
        loop {
            if !relay.converter.wire.is_empty() {
                let bytes = Bytes::from(std::mem::take(&mut relay.converter.wire));
                return Some((Ok::<_, std::io::Error>(bytes), relay));
            }
            if relay.done {
                return None;
            }
            if relay.converter.failure.is_some() {
                relay.finish();
                continue;
            }
            // Process at most one input event before yielding its converted frames.
            // Keeping the original body here propagates cancellation to its Recorder.
            while relay.offset < relay.chunk.len() && relay.converter.wire.is_empty() {
                let byte = relay.chunk[relay.offset];
                relay.offset += 1;
                let converter = &mut relay.converter;
                if let Err(error) = relay.parser.feed(byte, converter) {
                    relay.converter.fail(error);
                }
                if relay.converter.failure.is_some() {
                    relay.finish();
                    break;
                }
            }
            if !relay.converter.wire.is_empty() || relay.done {
                continue;
            }
            let next = tokio::select! {
                biased;
                _ = tokio::time::sleep_until(relay.last_activity + relay.timings.silence_timeout) => {
                    relay.converter.fail("upstream stream silence timeout");
                    relay.finish();
                    continue;
                }
                _ = tokio::time::sleep_until(relay.last_heartbeat + relay.timings.heartbeat_interval) => {
                    relay.last_heartbeat = tokio::time::Instant::now();
                    relay.converter.wire.push_str(": keepalive\n\n");
                    continue;
                }
                next = relay.upstream.next() => next,
            };
            match next {
                Some(Ok(bytes)) => {
                    if !bytes.is_empty() {
                        relay.last_activity = tokio::time::Instant::now();
                    }
                    relay.chunk = bytes;
                    relay.offset = 0;
                }
                Some(Err(error)) => {
                    relay
                        .converter
                        .fail(format!("upstream stream interrupted: {error}"));
                    relay.finish();
                }
                None => {
                    if let Err(error) = relay.parser.flush(&mut relay.converter) {
                        relay.converter.fail(error);
                    }
                    relay.finish();
                }
            }
        }
    });
    (
        [
            ("content-type", "text/event-stream"),
            ("cache-control", "no-cache"),
        ],
        Body::from_stream(body),
    )
        .into_response()
}
