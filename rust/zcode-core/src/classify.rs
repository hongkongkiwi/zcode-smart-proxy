//! Port of relay.go's failure-classification ladder (the forwardOnce >=400
//! branch and the 2xx envelope path), the single most change-sensitive
//! decision in the proxy. Ten audit waves live here.
//!
//! Order contract (never reorder without live data-plane smoke):
//! 3xx redirect -> CF challenge -> HTML block -> captcha (400/401/403 only)
//! -> risk 3012 -> shape-scoped protocol passthrough -> 401/403 credential
//! -> 429/1302/1303 -> exhausted family -> generic upstream error.
//! The 2xx JSON path classifies error envelopes BEFORE empty bodies (the
//! 2026-10-26 L3 fix) and runs the exhaustion ladder inside envelopes (the
//! 2026-11-12 live regression: {"code":1005} must fail over, never terminate).

use crate::bizcode::*;
use crate::cooldown::is_rate_limit_body;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    Plain,
    OffPeak,
    Highspeed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureClass {
    /// 3xx: WAF/login redirect; caller cools the channel.
    Redirect,
    /// Cloudflare/WAF challenge page: egress-IP problem, cool only.
    Challenge,
    /// Non-CF HTML (Aliyun WAF etc.): cool, never kill credentials.
    HtmlBlock,
    /// Captcha rejected: re-solve and retry with fresh params.
    CaptchaRejected,
    /// Risk block (3012 / unusual activity): temporary ban, short cooling.
    RiskBlocked,
    /// Off-peak/highspeed plan-side ticket/card signal: pass through
    /// verbatim, never penalize the account.
    ProtocolPassthrough,
    /// 401/403 without a soft shell: refresh-first, then MarkInvalid.
    CredentialFailure,
    /// 429 or 1302/1303 concurrency cap: backoff-retry once, escalate ladder.
    RateLimited,
    /// 402 or quota family: exhausted path, paid fallback chain.
    Exhausted,
    /// Any other >=400: terminal upstream error.
    UpstreamError,
}

/// Classify a >=400 upstream response. `body` is the response text;
/// `cf_mitigated` is the raw Cf-Mitigated header value (None when absent);
/// `content_type` the Content-Type header.
pub fn classify_failure(
    shape: Shape,
    status: u16,
    cf_mitigated: Option<&str>,
    content_type: Option<&str>,
    body: &str,
) -> FailureClass {
    if (300..400).contains(&status) {
        return FailureClass::Redirect;
    }
    if is_cloudflare_challenge(cf_mitigated, body) {
        return FailureClass::Challenge;
    }
    if content_type
        .map(|c| c.to_lowercase().contains("text/html"))
        .unwrap_or(false)
    {
        return FailureClass::HtmlBlock;
    }
    let low = body.to_lowercase();
    if matches!(status, 400 | 401 | 403) && is_captcha_error(&low) {
        return FailureClass::CaptchaRejected;
    }
    if is_risk_blocked(&low) {
        return FailureClass::RiskBlocked;
    }
    if is_special_protocol_biz_code(shape, status, &low) {
        return FailureClass::ProtocolPassthrough;
    }
    if matches!(status, 401 | 403) {
        return FailureClass::CredentialFailure;
    }
    if is_rate_limit_body(status, &low) {
        return FailureClass::RateLimited;
    }
    if is_exhausted_error(status, &low) {
        return FailureClass::Exhausted;
    }
    FailureClass::UpstreamError
}

/// Shape-scoped passthrough recognition (Go isSpecialProtocolBizCode).
pub fn is_special_protocol_biz_code(shape: Shape, status: u16, lower_text: &str) -> bool {
    match shape {
        Shape::OffPeak => {
            if status == 429 {
                return true;
            }
            ["3101", "3102", "3103", "3104", "3105", "3106", "3001"]
                .iter()
                .any(|code| has_biz_code(lower_text, code))
        }
        Shape::Highspeed => has_provider_code(lower_text, "3402"),
        Shape::Plain => false,
    }
}

/// Classification of a 2xx JSON body (relay.go's envelope path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OkBodyClass {
    /// Inline error envelope whose body is in the exhaustion family: run the
    /// exhaustion ladder and fail over (free -> paid), never terminal.
    ExhaustedEnvelope,
    /// Any other inline error envelope: terminal error to the client.
    ErrorEnvelope,
    /// 2xx message envelope with no content blocks: channel failure.
    EmptyMessage,
    /// A genuine success payload.
    Success,
}

pub fn classify_ok_body(body: &str) -> OkBodyClass {
    if is_error_envelope(body) {
        if is_exhausted_error(200, body) {
            return OkBodyClass::ExhaustedEnvelope;
        }
        return OkBodyClass::ErrorEnvelope;
    }
    if is_empty_message_body(body) {
        return OkBodyClass::EmptyMessage;
    }
    OkBodyClass::Success
}

/// Go isErrorEnvelope: {"type":"error"} (Anthropic shape), or a top-level
/// "error" field, or a non-numeric/!={0,200} "code" (gateway envelopes).
pub fn is_error_envelope(body: &str) -> bool {
    let v: Result<serde_json::Value, _> = serde_json::from_str(body);
    let v = match v {
        Ok(value @ serde_json::Value::Object(_)) => value,
        _ => return false, // non-object (HTML etc.) is not an envelope
    };
    if v.get("type").and_then(serde_json::Value::as_str) == Some("error") {
        return true;
    }
    match v.get("error") {
        Some(e) if !e.is_null() => return true,
        _ => {}
    }
    match v.get("code") {
        Some(serde_json::Value::Number(n)) => {
            let code = n.as_f64().unwrap_or(0.0);
            code != 0.0 && code != 200.0
        }
        Some(_) => true, // string-typed code is an error envelope
        None => false,
    }
}

/// Go isEmptyMessageBody, with the L3 self-defense: error envelopes also lack
/// content and must not classify as empty messages.
pub fn is_empty_message_body(body: &str) -> bool {
    let v: Result<serde_json::Value, _> = serde_json::from_str(body);
    let v = match v {
        Ok(value @ serde_json::Value::Object(_)) => value,
        _ => return false,
    };
    match v.get("type") {
        Some(t) if t.as_str().map(|s| s != "message").unwrap_or(true) => return false,
        _ => {}
    }
    if is_error_envelope(body) {
        return false;
    }
    match v.get("content") {
        None | Some(serde_json::Value::Null) => true,
        Some(serde_json::Value::Array(a)) => a.is_empty(),
        Some(serde_json::Value::String(s)) => s.is_empty(),
        Some(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ladder_order_challenges_before_credentials() {
        // 401 shell with a CF challenge page: Challenge, not CredentialFailure.
        assert_eq!(
            classify_failure(Shape::Plain, 401, Some("challenge"), None, "ignored"),
            FailureClass::Challenge
        );
        // 403 shell with risk 3012 body (documented upstream behavior): Risk.
        assert_eq!(
            classify_failure(
                Shape::Plain,
                403,
                None,
                None,
                r#"{"code":3012,"msg":"unusual activity"}"#
            ),
            FailureClass::RiskBlocked
        );
        // 401 shell with captcha keyword: CaptchaRejected.
        assert_eq!(
            classify_failure(Shape::Plain, 401, None, None, "请完成验证"),
            FailureClass::CaptchaRejected
        );
        // Plain 401 falls through to the credential branch.
        assert_eq!(
            classify_failure(Shape::Plain, 401, None, None, "{}"),
            FailureClass::CredentialFailure
        );
    }

    #[test]
    fn offpeak_bare_429_beats_rate_limit() {
        // A bare 429 on the offpeak shape is the queue signal, not a
        // rate limit — passthrough wins because it precedes the 429 branch.
        assert_eq!(
            classify_failure(Shape::OffPeak, 429, None, None, "{}"),
            FailureClass::ProtocolPassthrough
        );
        // Same 429 on the plain shape is an ordinary rate limit.
        assert_eq!(
            classify_failure(Shape::Plain, 429, None, None, "{}"),
            FailureClass::RateLimited
        );
    }

    #[test]
    fn exhaustion_family() {
        assert_eq!(
            classify_failure(Shape::Plain, 200, None, None, "unreachable"),
            FailureClass::UpstreamError
        );
        assert_eq!(
            classify_failure(Shape::Plain, 402, None, None, "{}"),
            FailureClass::Exhausted
        );
        assert_eq!(
            classify_failure(
                Shape::Plain,
                400,
                None,
                None,
                r#"{"code":1005,"msg":"exceed quota limit"}"#
            ),
            FailureClass::Exhausted
        );
    }

    #[test]
    fn ok_body_envelope_before_empty() {
        // The L3 fix: an error envelope is never an empty message.
        assert_eq!(
            classify_ok_body(r#"{"code":1302,"msg":"rate"}"#),
            OkBodyClass::ErrorEnvelope
        );
        // The wave-6 live regression: 1005 envelope = exhaustion failover.
        assert_eq!(
            classify_ok_body(r#"{"code":1005,"msg":"exceed quota limit","type":"error"}"#),
            OkBodyClass::ExhaustedEnvelope
        );
        // Anthropic-style error envelope.
        assert_eq!(
            classify_ok_body(r#"{"type":"error","error":{"message":"x"}}"#),
            OkBodyClass::ErrorEnvelope
        );
        // Empty message must still classify as empty.
        assert_eq!(
            classify_ok_body(r#"{"type":"message","content":[]}"#),
            OkBodyClass::EmptyMessage
        );
        // Genuine success.
        assert_eq!(
            classify_ok_body(r#"{"type":"message","content":[{"type":"text","text":"hi"}]}"#),
            OkBodyClass::Success
        );
        // Go parity: a code-200 envelope with no type/content also classifies
        // as an empty message body on this path (isEmptyMessageBody only
        // checks type + content). Not a port bug.
        assert_eq!(
            classify_ok_body(r#"{"code":200,"data":{}}"#),
            OkBodyClass::EmptyMessage
        );
    }
}
