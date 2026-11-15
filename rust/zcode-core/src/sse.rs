//! Port of convert.go's incremental SSE parser.
//!
//! Framing contract: LF (`\n\n`) and CRLF (`\r\n\r\n`) frames, LF wins ties;
//! UTF-8 BOM stripped once from the stream head; 16MB buffer cap (upstream
//! that never sends blank lines must fail the stream, not OOM); data-only
//! error frames normalize to `error` events.

use serde_json::Value;

pub const MAX_SSE_BUFFER: usize = 16 << 20;

#[derive(Debug, Clone)]
pub struct SseEvent {
    pub event: String,
    pub data: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SseParseError {
    /// Buffer exceeded MAX_SSE_BUFFER with no frame boundary; the stream is
    /// unrecoverable (Go errSSEOverflow).
    Overflow,
}

/// Incremental parser handling frames split across chunks.
pub struct SseParser {
    buf: Vec<u8>,
    bom_done: bool,
}

impl Default for SseParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SseParser {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            bom_done: false,
        }
    }

    /// Feed a chunk, invoking `fn` for each complete event. Returns Overflow
    /// (buffer reset) when the framing cap trips.
    pub fn feed(&mut self, chunk: &[u8], f: &mut dyn FnMut(SseEvent)) -> Result<(), SseParseError> {
        for &byte in chunk {
            if self.buf.len() == MAX_SSE_BUFFER {
                self.buf.clear();
                return Err(SseParseError::Overflow);
            }
            self.buf.push(byte);
            if self.buf.ends_with(b"\n\n") || self.buf.ends_with(b"\r\n\r\n") {
                self.flush(f);
            }
        }
        Ok(())
    }

    /// Decode only complete frames so split UTF-8 and BOM bytes stay intact.
    pub fn flush(&mut self, f: &mut dyn FnMut(SseEvent)) {
        let mut frame = self.buf.as_slice();
        if !self.bom_done {
            self.bom_done = true;
            frame = frame.strip_prefix(b"\xef\xbb\xbf").unwrap_or(frame);
        }
        if let Ok(block) = std::str::from_utf8(frame) {
            if let Some(ev) = parse_sse_block(block) {
                f(ev);
            }
        }
        self.buf.clear();
    }
}

fn parse_sse_block(block: &str) -> Option<SseEvent> {
    let mut event = String::new();
    let mut data_lines: Vec<&str> = Vec::new();
    for line in block.split('\n') {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("event:") {
            event = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("data:") {
            data_lines.push(rest.trim());
        }
    }
    let data_str = data_lines.join("\n");
    if data_str.is_empty() || data_str == "[DONE]" {
        return None;
    }
    let data: Value = match serde_json::from_str(&data_str) {
        Ok(v @ (Value::Object(_) | Value::Null)) => v,
        _ => return None,
    };
    let mut event_val = event;
    if event_val.is_empty() && is_data_error_frame(&data) {
        event_val = "error".to_string();
    }
    // Go: ok = ev.Event != "" || ev.Data != nil (nil map = JSON null or parse
    // failure, both already handled above).
    if event_val.is_empty() && data.is_null() {
        return None;
    }
    Some(SseEvent {
        event: event_val,
        data,
    })
}

/// data-only frame with an embedded error: top-level `error` field or
/// `type == "error"`.
fn is_data_error_frame(data: &Value) -> bool {
    if data.get("type").and_then(Value::as_str) == Some("error") {
        return true;
    }
    let e = data.get("error");
    matches!(e, Some(v) if !v.is_null())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn collect(parser: &mut SseParser, chunks: Vec<&[u8]>) -> Vec<SseEvent> {
        let out: Rc<RefCell<Vec<SseEvent>>> = Rc::new(RefCell::new(Vec::new()));
        let sink = out.clone();
        let mut f = move |ev: SseEvent| sink.borrow_mut().push(ev);
        for c in chunks {
            parser.feed(c, &mut f).expect("no overflow");
        }
        parser.flush(&mut f);
        let events = out.borrow().clone();
        events
    }

    #[test]
    fn basic_lf_framing() {
        let mut p = SseParser::new();
        let evs = collect(
            &mut p,
            vec![b"event: message_start\ndata: {\"type\":\"message_start\"}\n\n"],
        );
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].event, "message_start");
    }

    #[test]
    fn frame_split_across_chunks() {
        let mut p = SseParser::new();
        let evs = collect(
            &mut p,
            vec![
                b"event: content_block",
                b"_delta\ndata: {\"type\":\"text",
                b"_delta\",\"text\":\"hi\"}\n\n",
            ],
        );
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].event, "content_block_delta");
    }

    #[test]
    fn crlf_framing_and_done_skip() {
        let mut p = SseParser::new();
        let evs = collect(
            &mut p,
            vec![
                b"event: a\r\ndata: {\"x\":1}\r\n\r\n",
                b"event: b\ndata: [DONE]\n\n",
                b"event: c\ndata: {\"y\":2}\n\n",
            ],
        );
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].event, "a");
        assert_eq!(evs[1].event, "c");
    }

    #[test]
    fn bom_stripped_once() {
        let mut p = SseParser::new();
        let mut first: Vec<u8> = vec![0xEF, 0xBB, 0xBF];
        first.extend_from_slice(b"data: {\"z\":3}\n\n");
        let evs = collect(&mut p, vec![first.as_slice(), b"data: {\"w\":4}\n\n"]);
        assert_eq!(evs.len(), 2);
    }

    #[test]
    fn data_only_error_frame_normalized() {
        let mut p = SseParser::new();
        let evs = collect(
            &mut p,
            vec![b"data: {\"error\":{\"message\":\"boom\"}}\n\n"],
        );
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].event, "error");
    }

    #[test]
    fn only_objects_and_named_null_events_are_accepted() {
        for data in ["1", "true", "\"text\"", "[]", "[{}]"] {
            assert!(parse_sse_block(&format!("event: message_stop\ndata: {data}")).is_none());
        }
        assert!(parse_sse_block("data: null").is_none());
        assert!(parse_sse_block("data: {}").is_some());
        let event = parse_sse_block("event: message_stop\ndata: null").unwrap();
        assert_eq!(event.event, "message_stop");
        assert!(event.data.is_null());
    }

    #[test]
    fn malformed_data_dropped() {
        let mut p = SseParser::new();
        let evs = collect(&mut p, vec![b"event: x\ndata: not-json\n\n"]);
        assert!(evs.is_empty());
    }

    #[test]
    fn multi_line_data_joined() {
        let mut p = SseParser::new();
        let evs = collect(
            &mut p,
            vec![b"data: {\"a\":\ndata: 1}\n\nevent: after\ndata: {}\n\n"],
        );
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].data["a"], 1);
    }

    #[test]
    fn split_unicode_and_bom_preserved() {
        let bytes = "\u{feff}data: {\"text\":\"香港 🦀\"}\n\n".as_bytes();
        let mut parser = SseParser::new();
        let events = collect(&mut parser, bytes.chunks(1).collect());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data["text"], "香港 🦀");
    }

    #[test]
    fn overflow_errors_and_resets() {
        let mut p = SseParser::new();
        let big = vec![b'x'; MAX_SSE_BUFFER + 1];
        let out: Rc<RefCell<Vec<SseEvent>>> = Rc::new(RefCell::new(Vec::new()));
        let sink = out.clone();
        let mut f = move |ev: SseEvent| sink.borrow_mut().push(ev);
        let res = p.feed(&big, &mut f);
        assert_eq!(res, Err(SseParseError::Overflow));
    }
}
