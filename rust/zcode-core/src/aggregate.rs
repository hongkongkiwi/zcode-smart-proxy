//! Port of offpeak.go's aggregateAnthropicStream + anthropicAgg.
//!
//! The anti-fake-success contract, all failure paths preserved:
//! - inline `error` event wins the stream
//! - tool-argument buffer that fails to parse = truncated, never a {}
//!   success (the 2026-10-26 dead-branch fix; literal null stays tolerated)
//! - clean EOF with zero events fails
//! - stream without a message_delta and no stop_reason fails (mid-stream cut)
//! - start-frame tool input survives when no delta ever arrives
//! - usage max() semantics on message_start/message_delta (cache tokens too)

use serde_json::{Map, Value};
use std::collections::BTreeMap;

use crate::sse::{SseEvent, SseParser};

#[derive(Debug, Clone, Default)]
pub struct StreamUsage {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_read_tokens: i64,
    pub cache_creation_tokens: i64,
    /// "ERR:"-prefixed when the stream carried an inline error.
    pub stop_reason: String,
}

struct ToolBuf {
    buf: String,
}

#[derive(Default)]
struct Agg {
    id: String,
    model: String,
    blocks: Vec<Option<Map<String, Value>>>,
    stop_reason: String,
    stop_sequence: Option<Value>,
    saw_message_delta: bool,
    stream_error: String,
    tool_truncated: bool,
    input_t: i64,
    output_t: i64,
    cache_read: i64,
    cache_creation: i64,
    tool_json: BTreeMap<usize, ToolBuf>,
}

impl Agg {
    fn ensure_block(&mut self, idx: usize) -> &mut Map<String, Value> {
        while self.blocks.len() <= idx {
            self.blocks.push(None);
        }
        if self.blocks[idx].is_none() {
            self.blocks[idx] = Some(Map::new());
        }
        self.blocks[idx].as_mut().unwrap()
    }

    /// Shared by content_block_stop and the EOF flush: consume a tool buffer,
    /// applying the F2 semantics (err -> truncated + {}, null -> {}).
    fn settle_tool_buffer(&mut self, idx: usize) {
        if let Some(tb) = self.tool_json.remove(&idx) {
            let raw = tb.buf;
            if idx >= self.blocks.len() || self.blocks[idx].is_none() {
                return;
            }
            if !raw.is_empty() {
                let parsed: Result<Value, _> = serde_json::from_str(&raw);
                let value = match parsed {
                    Err(_) => {
                        self.tool_truncated = true;
                        Value::Object(Map::new())
                    }
                    Ok(Value::Null) => Value::Object(Map::new()),
                    Ok(v) => v,
                };
                if let Some(b) = self.blocks[idx].as_mut() {
                    b.insert("input".to_string(), value);
                }
            }
        }
    }
}

pub fn aggregate_anthropic_stream(
    reader: &mut dyn std::io::Read,
) -> Result<(Vec<u8>, Option<StreamUsage>), String> {
    let mut p = SseParser::new();
    let mut agg = Agg::default();

    let on_event = |ev: SseEvent, agg: &mut Agg| {
        match ev.event.as_str() {
            "message_start" => {
                if let Some(msg) = ev.data.get("message") {
                    if let Some(s) = msg.get("id").and_then(Value::as_str) {
                        agg.id = s.to_string();
                    }
                    if let Some(s) = msg.get("model").and_then(Value::as_str) {
                        agg.model = s.to_string();
                    }
                    if let Some(u) = msg.get("usage") {
                        let i = u.get("input_tokens").and_then(Value::as_i64).unwrap_or(0);
                        if i > agg.input_t {
                            agg.input_t = i;
                        }
                        let cr = u
                            .get("cache_read_input_tokens")
                            .and_then(Value::as_i64)
                            .unwrap_or(0);
                        if cr > agg.cache_read {
                            agg.cache_read = cr;
                        }
                        let cc = u
                            .get("cache_creation_input_tokens")
                            .and_then(Value::as_i64)
                            .unwrap_or(0);
                        if cc > agg.cache_creation {
                            agg.cache_creation = cc;
                        }
                    }
                }
            }
            "content_block_start" => {
                let idx = ev.data.get("index").and_then(Value::as_i64).unwrap_or(-1);
                if idx < 0 {
                    return;
                }
                let idx = idx as usize;
                let blk = ev.data.get("content_block");
                let mut nb = Map::new();
                let ty = blk
                    .and_then(|b| b.get("type"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                nb.insert("type".to_string(), Value::String(ty.clone()));
                match ty.as_str() {
                    "text" => {
                        nb.insert("text".to_string(), Value::String(String::new()));
                    }
                    "thinking" => {
                        nb.insert("thinking".to_string(), Value::String(String::new()));
                        if let Some(sig) =
                            blk.and_then(|b| b.get("signature")).and_then(Value::as_str)
                        {
                            if !sig.is_empty() {
                                nb.insert("signature".to_string(), Value::String(sig.to_string()));
                            }
                        }
                    }
                    "tool_use" => {
                        if let Some(id) = blk.and_then(|b| b.get("id")) {
                            nb.insert("id".to_string(), id.clone());
                        }
                        if let Some(name) = blk.and_then(|b| b.get("name")) {
                            nb.insert("name".to_string(), name.clone());
                        }
                        // Start frame may carry the full input; fall back to {}
                        // when no (or unparseable) delta follows.
                        match blk.and_then(|b| b.get("input")) {
                            Some(v @ Value::Object(_)) => {
                                nb.insert("input".to_string(), v.clone());
                            }
                            _ => {
                                nb.insert("input".to_string(), Value::Object(Map::new()));
                            }
                        }
                        agg.tool_json.insert(idx, ToolBuf { buf: String::new() });
                    }
                    "redacted_thinking" => {
                        if let Some(d) = blk.and_then(|b| b.get("data")) {
                            nb.insert("data".to_string(), d.clone());
                        }
                    }
                    _ => {}
                }
                agg.ensure_block(idx);
                agg.blocks[idx] = Some(nb);
            }
            "content_block_delta" => {
                let idx = ev.data.get("index").and_then(Value::as_i64).unwrap_or(-1);
                if idx < 0 {
                    return;
                }
                let idx = idx as usize;
                if idx >= agg.blocks.len() || agg.blocks[idx].is_none() {
                    return;
                }
                let delta = match ev.data.get("delta") {
                    Some(d @ Value::Object(_)) => d.clone(),
                    _ => return,
                };
                match delta.get("type").and_then(Value::as_str) {
                    Some("signature_delta") => {
                        if let Some(s) = delta.get("signature").and_then(Value::as_str) {
                            if !s.is_empty() {
                                let b = agg.blocks[idx].as_mut().unwrap();
                                let prev = b
                                    .get("signature")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string();
                                b.insert("signature".to_string(), Value::String(prev + s));
                            }
                        }
                    }
                    Some("text_delta") => {
                        if let Some(s) = delta.get("text").and_then(Value::as_str) {
                            let b = agg.blocks[idx].as_mut().unwrap();
                            let prev = b
                                .get("text")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string();
                            b.insert("text".to_string(), Value::String(prev + s));
                        }
                    }
                    Some("thinking_delta") => {
                        if let Some(s) = delta.get("thinking").and_then(Value::as_str) {
                            let b = agg.blocks[idx].as_mut().unwrap();
                            let prev = b
                                .get("thinking")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string();
                            b.insert("thinking".to_string(), Value::String(prev + s));
                        }
                    }
                    Some("input_json_delta") => {
                        if let Some(s) = delta.get("partial_json").and_then(Value::as_str) {
                            if let Some(tb) = agg.tool_json.get_mut(&idx) {
                                tb.buf.push_str(s);
                            }
                        }
                    }
                    _ => {}
                }
            }
            "content_block_stop" => {
                let idx = ev.data.get("index").and_then(Value::as_i64).unwrap_or(-1);
                if idx >= 0 {
                    agg.settle_tool_buffer(idx as usize);
                }
            }
            "message_delta" => {
                if let Some(u) = ev.data.get("usage") {
                    let o = u.get("output_tokens").and_then(Value::as_i64).unwrap_or(0);
                    if o > 0 {
                        agg.output_t = o;
                    }
                    let i = u.get("input_tokens").and_then(Value::as_i64).unwrap_or(0);
                    if i > agg.input_t {
                        agg.input_t = i;
                    }
                    let cr = u
                        .get("cache_read_input_tokens")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    if cr > agg.cache_read {
                        agg.cache_read = cr;
                    }
                    let cc = u
                        .get("cache_creation_input_tokens")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    if cc > agg.cache_creation {
                        agg.cache_creation = cc;
                    }
                }
                if let Some(d) = ev.data.get("delta") {
                    agg.saw_message_delta = true;
                    if let Some(sr) = d.get("stop_reason").and_then(Value::as_str) {
                        if !sr.is_empty() {
                            agg.stop_reason = sr.to_string();
                        }
                    }
                    if let Some(ss) = d.get("stop_sequence") {
                        agg.stop_sequence = Some(ss.clone());
                    }
                }
            }
            "error" => {
                let msg = ev
                    .data
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("upstream stream error");
                agg.stream_error = msg.to_string();
            }
            _ => {}
        }
    };

    let mut buf = vec![0u8; 32 << 10];
    loop {
        let n = reader.read(&mut buf).map_err(|e| e.to_string())?;
        if n > 0 {
            let chunk = &buf[..n];
            let mut sink = |ev: SseEvent| on_event(ev, &mut agg);
            p.feed(chunk, &mut sink).map_err(|e| match e {
                crate::sse::SseParseError::Overflow => "sse buffer overflow".to_string(),
            })?;
        }
        if n == 0 {
            break;
        }
    }
    {
        let mut sink = |ev: SseEvent| on_event(ev, &mut agg);
        p.flush(&mut sink);
    }

    // EOF flush of leftover tool buffers, ordered by index; buffers for
    // missing blocks are dropped (Go: delete + continue).
    let idxs: Vec<usize> = agg.tool_json.keys().copied().collect();
    for idx in idxs {
        agg.settle_tool_buffer(idx);
    }

    let content: Vec<Value> = agg
        .blocks
        .iter()
        .filter_map(|b| b.as_ref().map(|m| Value::Object(m.clone())))
        .collect();

    if !agg.stream_error.is_empty() {
        return Err(agg.stream_error);
    }
    if agg.tool_truncated {
        return Err("upstream tool arguments truncated".to_string());
    }
    if agg.id.is_empty() && content.is_empty() {
        return Err("upstream stream ended without any events".to_string());
    }
    if !agg.saw_message_delta && agg.stop_reason.is_empty() {
        return Err("upstream stream truncated before message_delta".to_string());
    }
    let stop_reason = if agg.stop_reason.is_empty() {
        "end_turn".to_string()
    } else {
        agg.stop_reason.clone()
    };

    let usage = Some(StreamUsage {
        input_tokens: agg.input_t,
        output_tokens: agg.output_t,
        cache_read_tokens: agg.cache_read,
        cache_creation_tokens: agg.cache_creation,
        stop_reason: String::new(),
    });

    let mut out = Map::new();
    out.insert("id".to_string(), Value::String(agg.id.clone()));
    out.insert("type".to_string(), Value::String("message".to_string()));
    out.insert("role".to_string(), Value::String("assistant".to_string()));
    out.insert("model".to_string(), Value::String(agg.model.clone()));
    out.insert("content".to_string(), Value::Array(content));
    out.insert("stop_reason".to_string(), Value::String(stop_reason));
    out.insert(
        "stop_sequence".to_string(),
        agg.stop_sequence.clone().unwrap_or(Value::Null),
    );
    let mut u = Map::new();
    u.insert("input_tokens".to_string(), Value::from(agg.input_t));
    u.insert("output_tokens".to_string(), Value::from(agg.output_t));
    u.insert(
        "cache_read_input_tokens".to_string(),
        Value::from(agg.cache_read),
    );
    u.insert(
        "cache_creation_input_tokens".to_string(),
        Value::from(agg.cache_creation),
    );
    out.insert("usage".to_string(), Value::Object(u));

    let raw = serde_json::to_vec(&Value::Object(out)).map_err(|e| e.to_string())?;
    Ok((raw, usage))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn agg(sse: &str) -> Result<(Value, Option<StreamUsage>), String> {
        let mut c = Cursor::new(sse.as_bytes());
        let (raw, usage) = aggregate_anthropic_stream(&mut c)?;
        Ok((
            serde_json::from_slice(&raw).map_err(|e| e.to_string())?,
            usage,
        ))
    }

    fn msg_start(id: &str) -> String {
        format!(
            "event: message_start\ndata: {{\"type\":\"message_start\",\"message\":{{\"id\":\"{id}\",\"model\":\"GLM-5.3\",\"usage\":{{\"input_tokens\":9}}}}}}\n\n"
        )
    }

    #[test]
    fn happy_text_stream() {
        let sse = format!(
            "{}event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"text\",\"text\":\"\"}}}}\n\nevent: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"HS-OK\"}}}}\n\nevent: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":0}}\n\nevent: message_delta\ndata: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"end_turn\"}},\"usage\":{{\"output_tokens\":3}}}}\n\nevent: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n",
            msg_start("m1")
        );
        let (msg, usage) = agg(&sse).expect("success");
        assert_eq!(msg["id"], "m1");
        assert_eq!(msg["content"][0]["text"], "HS-OK");
        assert_eq!(msg["stop_reason"], "end_turn");
        assert_eq!(usage.as_ref().unwrap().input_tokens, 9);
        assert_eq!(usage.as_ref().unwrap().output_tokens, 3);
    }

    #[test]
    fn zero_event_clean_eof_fails() {
        let err = agg("event: ping\ndata: {}\n\n").unwrap_err();
        assert_eq!(err, "upstream stream ended without any events");
    }

    // The M1 regression shape: start -> delta -> stop with no content blocks.
    // The AGGREGATOR passes it (id present, saw_message_delta true); the
    // passthrough empty-content guard lives in the lane callers, not here.
    #[test]
    fn start_stop_empty_content_succeeds() {
        let sse = format!(
            "{}event: message_delta\ndata: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"end_turn\"}}}}\n\nevent: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n",
            msg_start("m2")
        );
        let (msg, _) = agg(&sse).expect("aggregator passes this shape");
        assert_eq!(msg["content"].as_array().unwrap().len(), 0);
    }

    // F2: an unparseable tool-arg buffer must fail the aggregate, never
    // launder into an empty-input success.
    #[test]
    fn truncated_tool_args_fail() {
        let sse = format!(
            "{}event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"tool_use\",\"id\":\"t1\",\"name\":\"edit\",\"input\":{{}}}}}}\n\nevent: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"input_json_delta\",\"partial_json\":\"{{\\\"file\\\": \\\"x\\\"\"}}}}\n\nevent: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":0}}\n\nevent: message_delta\ndata: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"tool_use\"}},\"usage\":{{\"output_tokens\":4}}}}\n\n",
            msg_start("m3")
        );
        let err = agg(&sse).unwrap_err();
        assert_eq!(err, "upstream tool arguments truncated");
    }

    #[test]
    fn null_tool_args_tolerated() {
        let sse = format!(
            "{}event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"tool_use\",\"id\":\"t1\",\"name\":\"ping\",\"input\":{{}}}}}}\n\nevent: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"input_json_delta\",\"partial_json\":\"null\"}}}}\n\nevent: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":0}}\n\nevent: message_delta\ndata: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"tool_use\"}}}}\n\n",
            msg_start("m4")
        );
        let (msg, _) = agg(&sse).expect("null tolerated");
        assert_eq!(msg["content"][0]["input"], serde_json::json!({}));
    }

    #[test]
    fn start_frame_input_survives_without_delta() {
        let sse = format!(
            "{}event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"tool_use\",\"id\":\"t1\",\"name\":\"bash\",\"input\":{{\"command\":\"ls\"}}}}}}\n\nevent: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":0}}\n\nevent: message_delta\ndata: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"tool_use\"}}}}\n\n",
            msg_start("m5")
        );
        let (msg, _) = agg(&sse).expect("start-frame input kept");
        assert_eq!(msg["content"][0]["input"]["command"], "ls");
    }

    #[test]
    fn inline_error_event_fails_stream() {
        let sse = format!(
            "{}event: error\ndata: {{\"type\":\"error\",\"error\":{{\"message\":\"quota out\"}}}}\n\n",
            msg_start("m6")
        );
        let err = agg(&sse).unwrap_err();
        assert_eq!(err, "quota out");
    }

    #[test]
    fn truncated_before_message_delta_fails() {
        let sse = format!(
            "{}event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"text\",\"text\":\"\"}}}}\n\n",
            msg_start("m7")
        );
        let err = agg(&sse).unwrap_err();
        assert_eq!(err, "upstream stream truncated before message_delta");
    }

    #[test]
    fn signature_delta_accumulates() {
        let sse = format!(
            "{}event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"thinking\",\"thinking\":\"\",\"signature\":\"ab\"}}}}\n\nevent: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"thinking_delta\",\"thinking\":\"deep\"}}}}\n\nevent: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"signature_delta\",\"signature\":\"cd\"}}}}\n\nevent: message_delta\ndata: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"end_turn\"}}}}\n\n",
            msg_start("m8")
        );
        let (msg, _) = agg(&sse).expect("ok");
        assert_eq!(msg["content"][0]["signature"], "abcd");
        assert_eq!(msg["content"][0]["thinking"], "deep");
    }
}
