//! Port of zcode_api.go's count_tokens estimator + image dimension sniffing.
//!
//! Contract: conservative ("rather over than under"), +5% overall margin,
//! CJK counted per char where ASCII counts per 4. Images cost real pixels
//! (Anthropic long-edge-1568 pricing) when the header can be sniffed from a
//! base64 payload; URL references and unknown formats keep the flat floor.

use serde_json::Value;

pub const EST_IMAGE_TOKENS: i64 = 1500;
const EST_MESSAGE_OVERHEAD: i64 = 4;
pub const EST_BASE_TOKENS: i64 = 8;

fn is_cjk(r: char) -> bool {
    let c = r as u32;
    // Han (main ranges incl. radicals + extensions), Hiragana, Katakana,
    // Hangul syllables + jamo. Go's unicode.Is per-script coverage for the
    // scripts this estimator actually sees.
    (0x2E80..=0x2FDF).contains(&c)
        || (0x3005..=0x3007).contains(&c)
        || (0x3400..=0x4DBF).contains(&c)
        || (0x4E00..=0x9FFF).contains(&c)
        || (0xF900..=0xFAFF).contains(&c)
        || (0x20000..=0x2FA1F).contains(&c)
        || (0x3041..=0x309F).contains(&c)
        || (0x30A0..=0x30FF).contains(&c)
        || (0x31F0..=0x31FF).contains(&c)
        || (0xFF66..=0xFF9F).contains(&c)
        || (0xAC00..=0xD7AF).contains(&c)
        || (0x1100..=0x11FF).contains(&c)
        || (0x3130..=0x318F).contains(&c)
}

pub fn estimate_text_tokens(s: &str) -> i64 {
    let (mut ascii, mut cjk, mut other) = (0i64, 0i64, 0i64);
    for r in s.chars() {
        if r.is_ascii() {
            ascii += 1;
        } else if is_cjk(r) {
            cjk += 1;
        } else {
            other += 1;
        }
    }
    let n = ascii / 4 + cjk + other / 2;
    n * 21 / 20
}

/// content/system field: JSON string (decoded), block array, or raw fallback.
pub fn estimate_content_tokens(raw: Option<&Value>) -> i64 {
    let raw = match raw {
        None | Some(Value::Null) => return 0,
        Some(v) => v,
    };
    match raw {
        Value::String(s) => estimate_text_tokens(s),
        Value::Array(blocks) => {
            let mut total = 0;
            for b in blocks {
                total += estimate_block_tokens(b);
            }
            total
        }
        other => estimate_text_tokens(&other.to_string()) / 2,
    }
}

fn estimate_block_tokens(b: &Value) -> i64 {
    let ty = b.get("type").and_then(Value::as_str).unwrap_or("");
    match ty {
        "text" => estimate_content_tokens(b.get("text")),
        "thinking" => estimate_content_tokens(b.get("thinking")),
        "tool_use" => {
            // Raw JSON text of the input (Go estimates the raw bytes).
            match b.get("input") {
                Some(v) => estimate_text_tokens(&v.to_string()),
                None => 0,
            }
        }
        "tool_result" => estimate_content_tokens(b.get("content")),
        "image" => estimate_image_block_tokens(b).unwrap_or(EST_IMAGE_TOKENS),
        "document" => EST_IMAGE_TOKENS,
        _ => {
            // Unknown block: half the raw-text estimate as the floor.
            estimate_text_tokens(&b.to_string()) / 2
        }
    }
}

pub fn estimate_messages_tokens(raw: Option<&Value>) -> i64 {
    let msgs = match raw {
        None | Some(Value::Null) => return 0,
        Some(Value::Array(a)) => a,
        Some(other) => return estimate_text_tokens(&other.to_string()) / 2,
    };
    let mut total = 0;
    for m in msgs {
        total += EST_MESSAGE_OVERHEAD + estimate_content_tokens(m.get("content"));
    }
    total
}

/// Base64 image block: sniff pixel dimensions from the header and price by
/// the Anthropic formula. Returns None for URL references / unknown formats.
pub fn estimate_image_block_tokens(b: &Value) -> Option<i64> {
    let src = b.get("source")?;
    if src.get("type").and_then(Value::as_str) != Some("base64") {
        return None;
    }
    let data = src.get("data").and_then(Value::as_str)?;
    if data.is_empty() {
        return None;
    }
    // Header-only decode: PNG needs 24 bytes; JPEG SOF lives within ~64KB.
    let enc = if data.len() > 90_000 {
        &data[..90_000]
    } else {
        data
    };
    let head = decode_base64_lenient(enc)?;
    let (w, h) = image_pixel_dimensions(&head);
    if w <= 0 || h <= 0 {
        return None;
    }
    Some(image_tokens_from_dimensions(w, h))
}

/// Lenient base64: decode the largest valid prefix (Go base64.StdEncoding
/// on a possibly-truncated payload yields the decoded prefix + error).
fn decode_base64_lenient(enc: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let trimmed: String = enc.chars().filter(|c| !c.is_whitespace()).collect();
    for end in (0..=trimmed.len()).rev() {
        // Only cut on 4-char boundaries; strip '=' padding as needed.
        if end % 4 != 0 {
            continue;
        }
        let slice = &trimmed[..end];
        match engine.decode(slice) {
            Ok(v) if !v.is_empty() => return Some(v),
            _ => continue,
        }
    }
    None
}

/// Anthropic preprocessing equivalent: long edge clamped to 1568, then
/// (w*h)/750 rounded up.
pub fn image_tokens_from_dimensions(w: i64, h: i64) -> i64 {
    const LONG_EDGE: i64 = 1568;
    let (w, h) = if w > LONG_EDGE || h > LONG_EDGE {
        if w >= h {
            (LONG_EDGE, (h * LONG_EDGE / w).max(1))
        } else {
            ((w * LONG_EDGE / h).max(1), LONG_EDGE)
        }
    } else {
        (w, h)
    };
    let w = w.max(1);
    let h = h.max(1);
    (w * h + 749) / 750
}

/// PNG IHDR (fixed offsets after the 8-byte signature) or JPEG SOF walk.
/// Returns (0, 0) for unknown formats or truncated headers.
pub fn image_pixel_dimensions(d: &[u8]) -> (i64, i64) {
    const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if d.len() >= 24 && d[..8] == PNG_MAGIC {
        let be32 = |b: &[u8]| i64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
        return (be32(&d[16..20]), be32(&d[20..24]));
    }
    if d.len() >= 4 && d[0] == 0xFF && d[1] == 0xD8 {
        let mut i = 2usize;
        while i + 9 < d.len() {
            if d[i] != 0xFF {
                i += 1;
                continue;
            }
            let m = d[i + 1];
            if m == 0x01 || m == 0xD8 || (0xD0..=0xD7).contains(&m) {
                i += 2; // standalone markers carry no length
                continue;
            }
            if i + 4 > d.len() {
                break;
            }
            let seg_len = usize::from(d[i + 2]) << 8 | usize::from(d[i + 3]);
            if (0xC0..=0xCF).contains(&m) && m != 0xC4 && m != 0xC8 && m != 0xCC {
                let be16 = |b: &[u8]| i64::from(u16::from_be_bytes([b[0], b[1]]));
                return (be16(&d[i + 7..i + 9]), be16(&d[i + 5..i + 7]));
            }
            if seg_len < 2 {
                break;
            }
            i += 2 + seg_len;
        }
    }
    (0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Vectors ported from count_tokens_test.go.
    #[test]
    fn text_tokens() {
        let cjk100 = "汉".repeat(100);
        let cases = [
            ("empty", "", 0),
            ("ascii 28 chars", "Hello world, this is a test!", 7),
            ("cjk 4 chars", "你好世界", 4),
            ("cjk 100 chars", cjk100.as_str(), 105),
            ("mixed", "abc你好", 2),
        ];
        for (name, input, want) in cases {
            assert_eq!(estimate_text_tokens(input), want, "{name}");
        }
    }

    #[test]
    fn cjk_dominates_ascii() {
        let ascii = estimate_text_tokens(&"a".repeat(100));
        let cjk = estimate_text_tokens(&"汉".repeat(100));
        assert!(cjk > ascii);
    }

    #[test]
    fn content_tokens() {
        let cases: Vec<(&str, Value, i64)> = vec![
            ("plain string", json!("Hello world, this is a test!"), 7),
            (
                "text block",
                json!([{"type": "text", "text": "Hello world, this is a test!"}]),
                7,
            ),
            (
                "thinking block",
                json!([{"type": "thinking", "thinking": "你好世界"}]),
                4,
            ),
            (
                "image block fallback",
                json!([{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}}]),
                EST_IMAGE_TOKENS,
            ),
            (
                "tool_use input",
                json!([{"type": "tool_use", "id": "t1", "name": "bash", "input": {"command": "ls -la"}}]),
                5,
            ),
            (
                "tool_result nested array",
                json!([{"type": "tool_result", "tool_use_id": "t1", "content": [{"type": "text", "text": "output here"}]}]),
                2,
            ),
            (
                "unknown block falls back",
                json!([{"type": "weird_thing", "foo": "bar"}]),
                4,
            ),
        ];
        for (name, v, want) in cases {
            assert_eq!(estimate_content_tokens(Some(&v)), want, "{name}");
        }
    }

    #[test]
    fn malformed_content_falls_back() {
        // Go: unparseable raw -> estimateTextTokens(raw)/2.
        assert_eq!(estimate_content_tokens(None), 0);
        let num = serde_json::from_str::<Value>("{{{not json").unwrap_or(Value::Null);
        assert_eq!(estimate_content_tokens(Some(&num)), 0);
    }

    #[test]
    fn messages_tokens() {
        let v = json!([
            {"role": "user", "content": "Hello world, this is a test!"},
            {"role": "assistant", "content": "你好世界"}
        ]);
        assert_eq!(estimate_messages_tokens(Some(&v)), 2 * 4 + 7 + 4);
        assert_eq!(estimate_messages_tokens(None), 0);
    }

    #[test]
    fn png_dimensions_and_pricing() {
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend_from_slice(&[0, 0, 0, 13]); // IHDR length
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&3840u32.to_be_bytes());
        png.extend_from_slice(&2160u32.to_be_bytes());
        let (w, h) = image_pixel_dimensions(&png);
        assert_eq!((w, h), (3840, 2160));
        let tok = image_tokens_from_dimensions(w, h);
        // (1568*882)/750 = 1844 — far above the 1500 flat floor.
        assert!(tok > 1500, "4K image priced {tok}");
        assert_eq!(image_pixel_dimensions(b"not an image"), (0, 0));
    }
}
