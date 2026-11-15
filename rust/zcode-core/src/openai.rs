//! Pure OpenAI chat and Anthropic message conversions.

use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Map, Value};
use std::fmt::Write;

fn random_hex(bytes: usize) -> String {
    let mut random = vec![0; bytes];
    OsRng.fill_bytes(&mut random);
    let mut result = String::with_capacity(bytes * 2);
    for byte in random {
        write!(result, "{byte:02x}").unwrap();
    }
    result
}

fn string(value: Option<&Value>) -> &str {
    value.and_then(Value::as_str).unwrap_or("")
}

fn append_message(messages: &mut Vec<Value>, role: &str, blocks: Vec<Value>) {
    if blocks.is_empty() {
        return;
    }
    if let Some(last) = messages.last_mut() {
        if last["role"] == role {
            last["content"].as_array_mut().unwrap().extend(blocks);
            return;
        }
    }
    messages.push(json!({"role": role, "content": blocks}));
}

/// Convert an OpenAI chat request to an Anthropic messages request.
pub fn chat_to_anthropic(body: &Value) -> Result<Value, String> {
    let model = string(body.get("model"));
    let mut messages = Vec::new();
    let mut system = Vec::new();
    if let Some(raw_messages) = body.get("messages").and_then(Value::as_array) {
        for msg in raw_messages.iter().filter(|m| m.is_object()) {
            let role = string(msg.get("role"));
            let content = msg.get("content");
            if role == "system" || role == "developer" {
                if let Some(text) = content.and_then(Value::as_str) {
                    system.push(text.to_owned());
                } else if let Some(parts) = content.and_then(Value::as_array) {
                    for part in parts {
                        if part.get("type").and_then(Value::as_str) == Some("text") {
                            if let Some(text) = part.get("text").and_then(Value::as_str) {
                                system.push(text.to_owned());
                            }
                        }
                    }
                }
                continue;
            }
            if role == "tool" {
                let id = string(msg.get("tool_call_id"));
                if !id.is_empty() {
                    let result = content
                        .filter(|v| v.is_string() || v.is_array())
                        .cloned()
                        .unwrap_or(json!(""));
                    append_message(
                        &mut messages,
                        "user",
                        vec![json!({"type":"tool_result", "tool_use_id":id, "content":result})],
                    );
                }
                continue;
            }
            if role != "user" && role != "assistant" {
                continue;
            }
            let mut blocks = Vec::new();
            if let Some(text) = content.and_then(Value::as_str) {
                if !text.is_empty() {
                    blocks.push(json!({"type":"text", "text":text}));
                }
            } else if let Some(parts) = content.and_then(Value::as_array) {
                for part in parts.iter().filter(|p| p.is_object()) {
                    match string(part.get("type")) {
                        "text" => {
                            let text = string(part.get("text"));
                            if !text.is_empty() {
                                blocks.push(json!({"type":"text", "text":text}));
                            }
                        }
                        "image_url" => {
                            let url = string(part.get("image_url").filter(|v| v.is_object()).and_then(|v| v.get("url")));
                            if let Some(rest) = url.strip_prefix("data:") {
                                if let Some((mime, data)) = rest.split_once(";base64,") {
                                    blocks.push(json!({"type":"image", "source":{"type":"base64", "media_type":if mime.is_empty() {"image/png"} else {mime}, "data":data}}));
                                    continue;
                                }
                            }
                            return Err("image_url must be an object with a data: base64 URL; other image forms are not supported by the upstream".into());
                        }
                        ty => return Err(format!("unsupported content part type: {ty}; the upstream supports only text and image_url parts")),
                    }
                }
            }
            if role == "assistant" {
                if let Some(calls) = msg.get("tool_calls").and_then(Value::as_array) {
                    for call in calls {
                        let Some(function) = call.get("function").filter(|v| v.is_object()) else {
                            continue;
                        };
                        let name = string(function.get("name"));
                        if name.is_empty() {
                            continue;
                        }
                        let input = match function.get("arguments") {
                            Some(Value::String(args)) => {
                                match serde_json::from_str::<Value>(args) {
                                    Ok(Value::Object(map)) => Value::Object(map),
                                    Ok(Value::Null) => json!({}),
                                    _ => json!({"_raw_arguments":args}),
                                }
                            }
                            Some(Value::Object(map)) => Value::Object(map.clone()),
                            _ => json!({}),
                        };
                        let id = string(call.get("id"));
                        let id = if id.is_empty() {
                            format!("call_{}", random_hex(4))
                        } else {
                            id.to_owned()
                        };
                        blocks
                            .push(json!({"type":"tool_use", "id":id, "name":name, "input":input}));
                    }
                }
            }
            append_message(&mut messages, role, blocks);
        }
    }
    let mut out = Map::new();
    out.insert(
        "model".into(),
        json!(if model.is_empty() { "GLM-5.3" } else { model }),
    );
    out.insert("messages".into(), json!(messages));
    if !system.is_empty() {
        out.insert("system".into(), json!(system.join("\n\n")));
    }
    let max = body
        .get("max_completion_tokens")
        .filter(|v| !v.is_null())
        .or_else(|| body.get("max_tokens").filter(|v| !v.is_null()))
        .cloned()
        .unwrap_or(json!(4096));
    out.insert("max_tokens".into(), max);
    if let Some(t) = body.get("temperature").filter(|v| !v.is_null()) {
        let clamped = match t.as_f64() {
            Some(n) if n > 1.0 => json!(1),
            Some(n) if n < 0.0 => json!(0),
            _ => t.clone(),
        };
        out.insert("temperature".into(), clamped);
    }
    if let Some(v) = body.get("top_p").filter(|v| !v.is_null()) {
        out.insert("top_p".into(), v.clone());
    }
    if let Some(v) = body.get("stop") {
        if v.is_array() {
            out.insert("stop_sequences".into(), v.clone());
        } else if v.is_string() {
            out.insert("stop_sequences".into(), json!([v]));
        }
    }
    if let Some(effort) = body.get("reasoning_effort").filter(|v| !v.is_null()) {
        out.insert("reasoning_effort".into(), effort.clone());
    } else if let Some(effort) = body
        .get("reasoning")
        .and_then(|v| v.get("effort"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        out.insert("reasoning_effort".into(), json!(effort));
    }
    if let Some(thinking) = body.get("thinking").filter(|v| v.is_object()) {
        out.insert("thinking".into(), thinking.clone());
    } else if let Some(enabled) = body.get("enable_thinking").and_then(Value::as_bool) {
        out.insert(
            "thinking".into(),
            json!({"type":if enabled {"enabled"} else {"disabled"}}),
        );
    }
    if let Some(rf) = body.get("response_format").filter(|v| v.is_object()) {
        let schema = match string(rf.get("type")) {
            "json_schema" => rf
                .get("json_schema")
                .filter(|v| v.is_object())
                .and_then(|v| v.get("schema"))
                .cloned(),
            "json_object" => Some(json!({"type":"object"})),
            _ => None,
        };
        if let Some(schema) = schema {
            out.insert(
                "output_config".into(),
                json!({"format":{"type":"json_schema", "schema":schema}}),
            );
        }
    }
    if let Some(raw_tools) = body.get("tools").and_then(Value::as_array) {
        let mut tools = Vec::new();
        for tool in raw_tools.iter().filter(|v| v.is_object()) {
            let function = if tool.get("type").and_then(Value::as_str) == Some("function") {
                tool.get("function")
                    .filter(|v| v.is_object())
                    .unwrap_or(tool)
            } else {
                tool
            };
            let name = string(function.get("name"));
            if name.is_empty() {
                continue;
            }
            let schema = ["parameters", "input_schema", "schema"]
                .iter()
                .find_map(|k| function.get(*k).filter(|v| v.is_object()))
                .cloned()
                .unwrap_or(json!({"type":"object", "properties":{}}));
            tools.push(json!({"name":name, "description":string(function.get("description")), "input_schema":schema}));
        }
        if !tools.is_empty() {
            out.insert("tools".into(), json!(tools));
        }
    }
    if let Some(choice) = body.get("tool_choice") {
        match choice.as_str() {
            Some("none") => {
                out.remove("tools");
            }
            Some("auto") => {
                out.insert("tool_choice".into(), json!({"type":"auto"}));
            }
            Some("required") => {
                out.insert("tool_choice".into(), json!({"type":"any"}));
            }
            _ if choice.is_object() => {
                let mut name = string(
                    choice
                        .get("function")
                        .filter(|v| v.is_object())
                        .and_then(|v| v.get("name")),
                );
                if name.is_empty() && choice.get("type").and_then(Value::as_str) == Some("function")
                {
                    name = string(choice.get("name"));
                }
                if !name.is_empty() {
                    out.insert("tool_choice".into(), json!({"type":"tool", "name":name}));
                }
            }
            _ => {}
        }
    }
    Ok(Value::Object(out))
}

/// Convert an Anthropic message response to an OpenAI chat completion.
pub fn anthropic_to_chat(body: &Value, client_model: &str, created: i64) -> Result<Value, String> {
    let id = format!("chatcmpl-{}", random_hex(6));
    let mut text = String::new();
    let mut thinking = String::new();
    let mut calls = Vec::new();
    if let Some(content) = body.get("content").and_then(Value::as_array) {
        for block in content {
            match string(block.get("type")) {
                "text" => text.push_str(string(block.get("text"))),
                "thinking" => thinking.push_str(string(block.get("thinking"))),
                "tool_use" => {
                    let call_id = string(block.get("id"));
                    let call_id = if call_id.is_empty() {
                        format!("call_{}", random_hex(4))
                    } else {
                        call_id.to_owned()
                    };
                    let input = block
                        .get("input")
                        .filter(|v| v.is_object())
                        .cloned()
                        .unwrap_or(json!({}));
                    let arguments = serde_json::to_string(&input).map_err(|e| e.to_string())?;
                    calls.push(json!({"id":call_id, "type":"function", "function":{"name":string(block.get("name")), "arguments":arguments}}));
                }
                _ => {}
            }
        }
    }
    let mut message = Map::new();
    message.insert("role".into(), json!("assistant"));
    message.insert(
        "content".into(),
        if text.is_empty() && !calls.is_empty() {
            Value::Null
        } else {
            json!(text)
        },
    );
    if !thinking.is_empty() {
        message.insert("reasoning_content".into(), json!(thinking));
    }
    let has_tools = !calls.is_empty();
    if has_tools {
        message.insert("tool_calls".into(), json!(calls));
    }
    let reason = match string(body.get("stop_reason")) {
        "max_tokens" => "length",
        "refusal" => "content_filter",
        "tool_use" => "tool_calls",
        _ if has_tools => "tool_calls",
        _ => "stop",
    };
    let usage = body.get("usage");
    let tokens = |key: &str| {
        usage
            .and_then(|v| v.get(key))
            .and_then(Value::as_i64)
            .unwrap_or(0)
    };
    let input = tokens("input_tokens");
    let output = tokens("output_tokens");
    let mut usage_out =
        json!({"prompt_tokens":input, "completion_tokens":output, "total_tokens":input + output});
    let cache = tokens("cache_read_input_tokens");
    if cache > 0 {
        usage_out["prompt_tokens_details"] = json!({"cached_tokens":cache});
    }
    Ok(
        json!({"id":id, "object":"chat.completion", "created":created, "model":client_model,
        "choices":[{"index":0, "message":message, "finish_reason":reason}], "usage":usage_out}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_tools_images_and_merging() {
        let request = json!({"messages":[
            {"role":"system", "content":"sys"},
            {"role":"developer", "content":[{"type":"text","text":"dev"}]},
            {"role":"user", "content":[{"type":"text","text":"hi"},{"type":"image_url","image_url":{"url":"data:image/jpeg;base64,YWJj"}}]},
            {"role":"user", "content":"next"},
            {"role":"assistant", "content":"", "tool_calls":[{"id":"call_a","function":{"name":"lookup","arguments":"{\"q\":1}"}}]},
            {"role":"tool","tool_call_id":"call_a","content":"found"},
            {"role":"tool","tool_call_id":"call_b","content":[{"type":"text","text":"ok"}]}
        ]});
        let out = chat_to_anthropic(&request).unwrap();
        assert_eq!(out["system"], "sys\n\ndev");
        assert_eq!(out["model"], "GLM-5.3");
        assert_eq!(
            out["messages"],
            json!([
                {"role":"user","content":[{"type":"text","text":"hi"},{"type":"image","source":{"type":"base64","media_type":"image/jpeg","data":"YWJj"}},{"type":"text","text":"next"}]},
                {"role":"assistant","content":[{"type":"tool_use","id":"call_a","name":"lookup","input":{"q":1}}]},
                {"role":"user","content":[{"type":"tool_result","tool_use_id":"call_a","content":"found"},{"type":"tool_result","tool_use_id":"call_b","content":[{"type":"text","text":"ok"}]}]}
            ])
        );
    }

    #[test]
    fn rejects_external_and_unsupported_parts() {
        for image in [
            json!({"url":"https://example.com/a"}),
            json!("data:image/png;base64,a"),
            Value::Null,
        ] {
            let req = json!({"messages":[{"role":"user","content":[{"type":"image_url","image_url":image}]}]});
            assert!(chat_to_anthropic(&req)
                .unwrap_err()
                .starts_with("image_url must be an object"));
        }
        let req = json!({"messages":[{"role":"user","content":[{"type":"audio"}]}]});
        assert!(chat_to_anthropic(&req)
            .unwrap_err()
            .contains("unsupported content part type: audio"));
        let req = json!({"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:;base64,abc"}}]}]});
        assert_eq!(
            chat_to_anthropic(&req).unwrap()["messages"][0]["content"][0]["source"]["media_type"],
            "image/png"
        );
    }

    #[test]
    fn options_and_tool_choices() {
        let base = json!({"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object"}}}],
            "max_tokens":10,"max_completion_tokens":20,"temperature":1.9,"stop":"end",
            "reasoning_effort":"high","reasoning":{"effort":"low"},"enable_thinking":false,
            "response_format":{"type":"json_schema","json_schema":{"schema":{"type":"object"}}}});
        let out = chat_to_anthropic(&base).unwrap();
        assert_eq!(out["max_tokens"], 20);
        assert_eq!(out["temperature"], 1);
        assert_eq!(out["stop_sequences"], json!(["end"]));
        assert_eq!(out["reasoning_effort"], "high");
        assert_eq!(out["thinking"], json!({"type":"disabled"}));
        assert_eq!(
            out["output_config"]["format"],
            json!({"type":"json_schema","schema":{"type":"object"}})
        );
        assert_eq!(out["tools"][0]["name"], "f");
        for (choice, expected) in [
            (json!("auto"), json!({"type":"auto"})),
            (json!("required"), json!({"type":"any"})),
            (
                json!({"type":"function","function":{"name":"f"}}),
                json!({"type":"tool","name":"f"}),
            ),
            (
                json!({"type":"function","name":"f"}),
                json!({"type":"tool","name":"f"}),
            ),
        ] {
            let mut req = base.clone();
            req["tool_choice"] = choice;
            assert_eq!(chat_to_anthropic(&req).unwrap()["tool_choice"], expected);
        }
        let mut req = base.clone();
        req["tool_choice"] = json!("none");
        let out = chat_to_anthropic(&req).unwrap();
        assert!(out.get("tools").is_none());
        assert!(out.get("tool_choice").is_none());
        let out = chat_to_anthropic(&json!({"response_format":{"type":"json_object"},"temperature":-2,"reasoning":{"effort":"max"}})).unwrap();
        assert_eq!(out["temperature"], 0);
        assert_eq!(out["reasoning_effort"], "max");
        assert_eq!(
            out["output_config"]["format"]["schema"],
            json!({"type":"object"})
        );
    }

    #[test]
    fn response_tools_usage_and_finish() {
        let body = json!({"id":"msg_orig", "content":[{"type":"thinking","thinking":"why","signature":"private"},
            {"type":"tool_use","id":"call_a","name":"f","input":{"q":1}}],
            "stop_reason":"tool_use", "usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":7}});
        let out = anthropic_to_chat(&body, "client-model", 42).unwrap();
        let id = out["id"].as_str().unwrap();
        assert!(id.starts_with("chatcmpl-") && id.len() == 21);
        assert_eq!(out["created"], 42);
        assert_eq!(out["model"], "client-model");
        assert_eq!(
            out["choices"][0]["message"],
            json!({"role":"assistant","content":null,"reasoning_content":"why",
            "tool_calls":[{"id":"call_a","type":"function","function":{"name":"f","arguments":"{\"q\":1}"}}]})
        );
        assert_eq!(out["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(
            out["usage"],
            json!({"prompt_tokens":10,"completion_tokens":5,"total_tokens":15,"prompt_tokens_details":{"cached_tokens":7}})
        );
        for (stop, expected) in [
            ("max_tokens", "length"),
            ("refusal", "content_filter"),
            ("end_turn", "stop"),
        ] {
            let out = anthropic_to_chat(
                &json!({"content":[{"type":"text","text":"ok"}],"stop_reason":stop}),
                "m",
                0,
            )
            .unwrap();
            assert_eq!(out["choices"][0]["finish_reason"], expected);
            assert!(out["usage"].get("prompt_tokens_details").is_none());
        }
    }

    #[test]
    fn missing_tool_ids_are_generated_and_arguments_preserved() {
        let req = json!({"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"f","arguments":"bad"}}]}]});
        let out = chat_to_anthropic(&req).unwrap();
        let block = &out["messages"][0]["content"][0];
        let id = block["id"].as_str().unwrap();
        assert!(id.starts_with("call_") && id.len() == 13);
        assert_eq!(block["input"], json!({"_raw_arguments":"bad"}));
        let out = anthropic_to_chat(&json!({"content":[{"type":"tool_use","name":"f"}]}), "m", 0)
            .unwrap();
        let id = out["choices"][0]["message"]["tool_calls"][0]["id"]
            .as_str()
            .unwrap();
        assert!(id.starts_with("call_") && id.len() == 13);
        assert_eq!(out["choices"][0]["finish_reason"], "tool_calls");
    }
}

/// Go completionsPrompt: string as-is; array of strings joined with blank
/// lines (multi-sample upstream is unsupported); anything else errors.
pub fn completions_prompt(v: Option<&Value>) -> Result<String, String> {
    match v {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Array(items)) => {
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                match item.as_str() {
                    Some(s) => parts.push(s.to_string()),
                    None => return Err("prompt array elements must be strings".into()),
                }
            }
            Ok(parts.join("\n\n"))
        }
        Some(_) => Err("prompt must be a string or array of strings".into()),
    }
}

/// Go completionsFinish: legacy text_completion has no tool semantics.
pub fn completions_finish(stop_reason: &str) -> &'static str {
    if stop_reason == "max_tokens" {
        "length"
    } else {
        "stop"
    }
}

/// Go completionsResponse: non-stream text_completion shape; echo=true
/// prefixes the original prompt.
pub fn completions_response(
    model: &str,
    text: &str,
    usage: Option<&crate::StreamUsage>,
    echo: bool,
    prompt: &str,
    created: i64,
) -> Value {
    let text = if echo { format!("{prompt}{text}") } else { text.to_string() };
    let (input, output, stop) = usage
        .map(|u| (u.input_tokens, u.output_tokens, u.stop_reason.clone()))
        .unwrap_or_default();
    json!({
        "id": format!("cmpl-{}", random_hex(12)),
        "object": "text_completion",
        "created": created,
        "model": model,
        "choices": [{
            "index": 0, "text": text, "logprobs": Value::Null,
            "finish_reason": completions_finish(&stop),
        }],
        "usage": {
            "prompt_tokens": input, "completion_tokens": output,
            "total_tokens": input + output,
        },
    })
}

/// Build the /v1/responses output object from an aggregated Anthropic
/// message (Go responsesResponseWithItems, synthesis path): thinking blocks
/// become reasoning items, tool_use blocks become function_call items, text
/// becomes the message item; max_tokens truncation reports incomplete.
pub fn anthropic_to_responses(body: &Value, response_id: &str, created: i64) -> Value {
    let model = string(body.get("model"));
    let mut output: Vec<Value> = Vec::new();
    let mut text = String::new();
    let mut thinking = String::new();
    if let Some(blocks) = body.get("content").and_then(Value::as_array) {
        for block in blocks {
            match string(block.get("type")) {
                "text" => text.push_str(string(block.get("text"))),
                "thinking" => thinking.push_str(string(block.get("thinking"))),
                "tool_use" => {
                    let args = match block.get("input") {
                        Some(v) => serde_json::to_string(v).unwrap_or_else(|_| "{}".into()),
                        None => "{}".into(),
                    };
                    let call_id = string(block.get("id"));
                    let call_id = if call_id.is_empty() {
                        format!("call_{}", random_hex(4))
                    } else {
                        call_id.to_owned()
                    };
                    output.push(json!({
                        "id": format!("fc_{}", random_hex(8)), "type": "function_call",
                        "call_id": call_id, "name": string(block.get("name")),
                        "arguments": args,
                    }));
                }
                _ => {}
            }
        }
    }
    if !thinking.is_empty() {
        output.push(json!({
            "id": format!("rs_{}", random_hex(8)), "type": "reasoning",
            "summary": [{"type": "summary_text", "text": thinking}],
        }));
    }
    if !text.is_empty() || output.is_empty() {
        output.push(json!({
            "id": format!("msg_{}", random_hex(8)), "type": "message",
            "status": "completed", "role": "assistant",
            "content": [{"type": "output_text", "text": text, "annotations": []}],
        }));
    }
    let in_tokens = body
        .get("usage")
        .and_then(|u| u.get("input_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let out_tokens = body
        .get("usage")
        .and_then(|u| u.get("output_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let cache_read = body
        .get("usage")
        .and_then(|u| u.get("cache_read_input_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let truncated = string(body.get("stop_reason")) == "max_tokens";
    let mut usage = json!({
        "input_tokens": in_tokens, "output_tokens": out_tokens,
        "total_tokens": in_tokens + out_tokens,
    });
    if cache_read > 0 {
        usage["input_tokens_details"] = json!({"cached_tokens": cache_read});
    }
    let mut out = json!({
        "id": response_id, "object": "response", "created_at": created,
        "status": if truncated {"incomplete"} else {"completed"},
        "model": model, "output": output, "output_text": text,
        "usage": usage,
    });
    if truncated {
        out["incomplete_details"] = json!({"reason": "max_output_tokens"});
    }
    out
}

/// Go /v1/responses input flattening: message/input_text items → chat-like
/// messages; function_call/output items → assistant tool interactions.
/// Other item types are skipped; `input_image` errors (Go fails closed).
pub fn flatten_responses_input(input: &Value) -> Result<Vec<Value>, String> {
    let items = match input {
        Value::String(s) => {
            return Ok(vec![json!({"role": "user", "content": [{"type": "input_text", "text": s}]})]);
        }
        Value::Array(a) => a.clone(),
        _ => return Err("input must be a string or array".into()),
    };
    let mut out = Vec::new();
    for item in items {
        let it = match item.as_object() {
            Some(o) => o,
            None => continue,
        };
        match it.get("type").and_then(Value::as_str) {
            Some("message") => {
                let role = it.get("role").and_then(Value::as_str).unwrap_or("user");
                let mut parts = Vec::new();
                match it.get("content") {
                    Some(Value::String(s)) => {
                        parts.push(json!({"type": if role == "assistant" {"output_text"} else {"input_text"}, "text": s}));
                    }
                    Some(Value::Array(arr)) => {
                        for part in arr {
                            if let Some(pt) = part.as_object() {
                                match pt.get("type").and_then(Value::as_str) {
                                    Some("input_text") | Some("output_text") | Some("text") => {
                                        parts.push(json!({
                                            "type": if role == "assistant" {"output_text"} else {"input_text"},
                                            "text": pt.get("text").cloned().unwrap_or(Value::Null),
                                        }));
                                    }
                                    Some("input_image") => {
                                        return Err("input_image is not supported by the upstream".into());
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {}
                }
                if !parts.is_empty() {
                    out.push(json!({"role": role, "content": parts}));
                } else if it.get("content").is_some() {
                    out.push(json!({"role": role, "content": ""}));
                }
            }
            Some("function_call") => {
                let name = it.get("name").and_then(Value::as_str).unwrap_or("");
                if !name.is_empty() {
                    let args = match it.get("arguments") {
                        Some(Value::String(s)) => s.clone(),
                        Some(v) => serde_json::to_string(v).unwrap_or_else(|_| "{}".into()),
                        None => "{}".into(),
                    };
                    out.push(json!({
                        "role": "assistant",
                        "content": [],
                        "tool_calls": [{"id": it.get("call_id").cloned().unwrap_or(json!(format!("call_{}", random_hex(4)))),
                            "type": "function",
                            "function": {"name": name, "arguments": args}}],
                    }));
                }
            }
            Some("function_call_output") => {
                if let Some(call_id) = it.get("call_id").and_then(Value::as_str) {
                    let output = match it.get("output") {
                        Some(Value::String(s)) => json!(s),
                        Some(v @ Value::Array(_)) => v.clone(),
                        _ => json!(""),
                    };
                    out.push(json!({
                        "role": "user",
                        "content": [{"type": "tool_result", "tool_use_id": call_id, "content": output}],
                    }));
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Go responsesResponse usage of stop_reason for truncation semantics on
/// flattened input bodies.
pub fn flatten_responses_body(body: &Value) -> Result<Vec<Value>, String> {
    match body.get("input") {
        Some(v) => flatten_responses_input(v),
        None => Err("input is required".into()),
    }
}
