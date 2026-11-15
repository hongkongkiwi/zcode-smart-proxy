use std::{pin::Pin, sync::Arc};

use axum::{
    body::{Body, Bytes},
    response::IntoResponse,
};
use futures_util::{stream, Stream, StreamExt};
use serde_json::{json, Value};
use zcode_core::{SseEvent, SseParser, StreamUsage};

use crate::state::{AppState, UsageRecord};

pub const MAX_RESPONSE_BYTES: usize = 64 << 20;

#[derive(Default)]
pub(crate) struct UsageSniffer {
    parser: SseParser,
    usage: StreamUsage,
    content: bool,
    terminal: bool,
    error: bool,
}

impl UsageSniffer {
    fn event(&mut self, event: SseEvent) {
        let kind = if event.event.is_empty() {
            event.data.get("type").and_then(Value::as_str).unwrap_or("")
        } else {
            &event.event
        };
        match kind {
            "message_start" => {
                if let Some(usage) = event.data.get("message").and_then(|m| m.get("usage")) {
                    merge_usage(&mut self.usage, usage);
                }
            }
            "message_delta" => {
                if let Some(usage) = event.data.get("usage") {
                    merge_usage(&mut self.usage, usage);
                }
                self.terminal |= event.data.get("delta").is_some_and(|d| {
                    d.get("stop_reason")
                        .and_then(Value::as_str)
                        .is_some_and(|s| !s.is_empty())
                });
            }
            "content_block_start" => self.content = true,
            "message_stop" => self.terminal = true,
            "error" => self.error = true,
            _ => {}
        }
    }

    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Result<(), String> {
        let mut parser = std::mem::take(&mut self.parser);
        let result = parser.feed(bytes, &mut |event| self.event(event));
        self.parser = parser;
        result.map_err(|_| "upstream SSE frame exceeds 16MiB".into())
    }

    pub(crate) fn flush(&mut self) {
        let mut parser = std::mem::take(&mut self.parser);
        parser.flush(&mut |event| self.event(event));
        self.parser = parser;
    }

    pub(crate) fn charge(&self) -> i64 {
        zcode_core::quota_charge(
            self.usage.input_tokens,
            self.usage.output_tokens,
            self.usage.cache_read_tokens,
            self.usage.cache_creation_tokens,
        )
    }

    pub(crate) fn failure(&self) -> Option<&'static str> {
        if self.error {
            Some("upstream stream error")
        } else if !self.content {
            Some("upstream returned an empty response (no content blocks)")
        } else if !self.terminal {
            Some("upstream stream interrupted before completion")
        } else {
            None
        }
    }
}

fn merge_usage(usage: &mut StreamUsage, value: &Value) {
    for (target, name) in [
        (&mut usage.input_tokens, "input_tokens"),
        (&mut usage.output_tokens, "output_tokens"),
        (&mut usage.cache_read_tokens, "cache_read_input_tokens"),
        (
            &mut usage.cache_creation_tokens,
            "cache_creation_input_tokens",
        ),
    ] {
        *target = (*target).max(value.get(name).and_then(Value::as_i64).unwrap_or(0));
    }
}

pub(crate) fn json_charge(bytes: &[u8]) -> i64 {
    let mut usage = StreamUsage::default();
    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        if let Some(value) = value.get("usage") {
            merge_usage(&mut usage, value);
        }
    }
    zcode_core::quota_charge(
        usage.input_tokens,
        usage.output_tokens,
        usage.cache_read_tokens,
        usage.cache_creation_tokens,
    )
}

pub(crate) async fn collect_bounded(
    mut response: reqwest::Response,
    mut sniff: Option<&mut UsageSniffer>,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("upstream read failed: {e}"))?
    {
        if chunk.len() > MAX_RESPONSE_BYTES - bytes.len() {
            return Err("upstream response exceeds 64MiB".into());
        }
        if let Some(sniff) = sniff.as_deref_mut() {
            sniff.feed(&chunk)?;
        }
        bytes.extend_from_slice(&chunk);
    }
    if let Some(sniff) = sniff {
        sniff.flush();
    }
    Ok(bytes)
}

struct Recorder {
    state: Arc<AppState>,
    record: Option<UsageRecord>,
    sniff: UsageSniffer,
}

impl Recorder {
    fn finish(&mut self, status: u16) -> rusqlite::Result<()> {
        if let Some(mut record) = self.record.take() {
            self.sniff.flush();
            record.status = status;
            record.quota_charge = self.sniff.charge();
            crate::admin::record_usage_db(&self.state, record)?;
        }
        Ok(())
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        if self.record.is_some() {
            self.sniff.flush();
            if let Err(error) = self.finish(499) {
                eprintln!("disconnect accounting failed: {error}");
            }
        }
    }
}

type Upstream = Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>;

struct Relay {
    upstream: Upstream,
    recorder: Recorder,
    done: bool,
    status: u16,
}

fn error_frame(message: &str) -> Bytes {
    Bytes::from(format!(
        "\n\nevent: error\ndata: {}\n\n",
        json!({
            "type": "error", "error": {"type": "api_error", "message": message}
        })
    ))
}

pub(crate) fn response(
    upstream: reqwest::Response,
    state: Arc<AppState>,
    account_id: i64,
    gateway_key_id: i64,
) -> axum::response::Response {
    let status = upstream.status();
    let relay = Relay {
        upstream: Box::pin(upstream.bytes_stream()),
        recorder: Recorder {
            state,
            record: Some(UsageRecord {
                account_id,
                gateway_key_id,
                status: 499,
                quota_charge: 0,
            }),
            sniff: UsageSniffer::default(),
        },
        done: false,
        status: status.as_u16(),
    };
    let body = stream::unfold(relay, |mut relay| async move {
        if relay.done {
            return None;
        }
        let failure = match relay.upstream.next().await {
            Some(Ok(bytes)) => match relay.recorder.sniff.feed(&bytes) {
                Ok(()) => return Some((Ok::<_, std::io::Error>(bytes), relay)),
                Err(error) => Some(error),
            },
            Some(Err(error)) => Some(format!("upstream stream interrupted: {error}")),
            None => {
                relay.recorder.sniff.flush();
                relay.recorder.sniff.failure().map(str::to_owned)
            }
        };
        relay.done = true;
        let status = if failure.is_some() { 502 } else { relay.status };
        let accounting = relay.recorder.finish(status);
        let failure = match accounting {
            Ok(()) => failure,
            Err(error) => {
                eprintln!("stream accounting failed: {error}");
                Some("durable usage accounting failed".into())
            }
        };
        failure.map(|message| (Ok(error_frame(&message)), relay))
    });
    (
        status,
        [("content-type", "text/event-stream")],
        Body::from_stream(body),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_error_keeps_partial_usage_and_fails_terminal_status() {
        let mut sniff = UsageSniffer::default();
        sniff.feed(b"event: message_start\ndata: {\"message\":{\"usage\":{\"input_tokens\":11}}}\n\nevent: error\ndata: {\"error\":{\"message\":\"interrupted\"}}\n\n").unwrap();
        assert_eq!(sniff.failure(), Some("upstream stream error"));
        assert_eq!(sniff.charge(), 11);
    }

    #[test]
    fn disconnect_records_partial_usage_once() {
        let state = Arc::new(AppState::new(String::new(), AppState::upstream_from_env()));
        let mut recorder = Recorder {
            state: state.clone(),
            record: Some(UsageRecord {
                account_id: 3,
                gateway_key_id: 0,
                status: 200,
                quota_charge: 0,
            }),
            sniff: UsageSniffer::default(),
        };
        recorder.sniff.feed(b"event: message_start\ndata: {\"message\":{\"usage\":{\"input_tokens\":11,\"cache_creation_input_tokens\":20,\"cache_read_input_tokens\":100}}}\n\n").unwrap();
        drop(recorder);
        let usage = state.usage.lock().unwrap();
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].summary(), (3, 499, 0, 41));
        assert_eq!(
            crate::store::list_usage(&state.db.lock().unwrap(), 10).len(),
            1
        );
    }

    #[test]
    fn upstream_error_flushes_unterminated_usage_before_accounting() {
        let state = Arc::new(AppState::new(String::new(), AppState::upstream_from_env()));
        let mut recorder = Recorder {
            state: state.clone(),
            record: Some(UsageRecord {
                account_id: 3,
                gateway_key_id: 0,
                status: 200,
                quota_charge: 0,
            }),
            sniff: UsageSniffer::default(),
        };
        recorder
            .sniff
            .feed(b"event: message_delta\ndata: {\"usage\":{\"output_tokens\":4}}")
            .unwrap();
        assert_eq!(recorder.sniff.charge(), 0);
        recorder.finish(502).unwrap();
        drop(recorder);
        let usage = state.usage.lock().unwrap();
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].summary(), (3, 502, 0, 4));
        assert_eq!(
            crate::store::list_usage(&state.db.lock().unwrap(), 10)[0].4,
            4
        );
    }

    #[test]
    fn terminal_recorder_does_not_record_disconnect_on_drop() {
        let state = Arc::new(AppState::new(String::new(), AppState::upstream_from_env()));
        let mut recorder = Recorder {
            state: state.clone(),
            record: Some(UsageRecord {
                account_id: 3,
                gateway_key_id: 0,
                status: 200,
                quota_charge: 0,
            }),
            sniff: UsageSniffer::default(),
        };
        recorder.finish(502).unwrap();
        recorder.finish(200).unwrap();
        drop(recorder);
        let usage = state.usage.lock().unwrap();
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].status, 502);
    }
}
