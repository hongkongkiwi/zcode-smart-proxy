//! Port of activity.go (promo auto-claim) and auto_reset.go (reset slot
//! spend) at the request-construction level, for the cron service layer.
//!
//! Honest scope: these functions BUILD the control-plane requests the Go
//! crons send (billing/preview detect, billing/claim, coding-plan/reset).
//! Their live behavior is a deploy-time validation item; the decision logic
//! that drives them is already ported and tested in autoreset.rs.

pub const OFFPEAK_ORIGIN: &str = "https://zcode.z.ai";

fn auth_headers(jwt: &str, api_key: &str) -> Vec<(String, String)> {
    let mut h = vec![("Authorization".to_string(), format!("Bearer {jwt}"))];
    if !api_key.is_empty() {
        h.push(("x-coding-plan-api-key".to_string(), api_key.to_string()));
    }
    h
}

/// GET billing/preview?app_version=...&platform=... — the promo detect call
/// (Go activity.go detect via doGetJSON, Bearer JWT auth).
pub fn build_detect_request(
    jwt: &str,
    api_key: &str,
    app_version: &str,
    platform: &str,
) -> (String, Vec<(String, String)>) {
    let url = format!(
        "{OFFPEAK_ORIGIN}/api/v1/zcode-plan/billing/preview?app_version={app_version}&platform={platform}"
    );
    let mut headers = vec![("accept".to_string(), "application/json".to_string())];
    headers.extend(auth_headers(jwt, api_key));
    (url, headers)
}

/// POST billing/claim {"plan_id"} with the captcha verify param header the
/// solve seam would provide (Go ClaimForAccount's claim step). verify_param
/// empty = no captcha solution available this round (the claim fails
/// upstream; the cron records it and moves on — degraded parity).
pub fn build_claim_request(
    jwt: &str,
    api_key: &str,
    plan_id: &str,
    verify_param: &str,
) -> (String, Vec<(String, String)>, String) {
    let url = format!("{OFFPEAK_ORIGIN}/api/v1/zcode-plan/billing/claim");
    let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
    headers.extend(auth_headers(jwt, api_key));
    if !verify_param.is_empty() {
        headers.push((
            "X-Aliyun-Captcha-Verify-Param".to_string(),
            verify_param.to_string(),
        ));
    }
    let body = serde_json::json!({"plan_id": plan_id}).to_string();
    (url, headers, body)
}

/// POST /api/v1/coding-plan/reset — spend a reset opportunity slot.
/// expire_at_ms is the slot's own expiry (ms epoch; the da48fec unit
/// confirmation stays load-bearing).
pub fn build_reset_request(
    jwt: &str,
    api_key: &str,
    slot_expire_ms: i64,
) -> (String, Vec<(String, String)>, String) {
    let url = format!("{OFFPEAK_ORIGIN}/api/v1/coding-plan/reset");
    let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
    headers.extend(auth_headers(jwt, api_key));
    let body = serde_json::json!({"expire_at": slot_expire_ms}).to_string();
    (url, headers, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    const JWT: &str = "jwt-c";
    const KEY: &str = "key-c";

    #[test]
    fn detect_request_shape() {
        let (url, headers) = build_detect_request(JWT, KEY, "3.18.0", "darwin-arm64");
        assert!(url.starts_with(
            "https://zcode.z.ai/api/v1/zcode-plan/billing/preview?app_version=3.18.0&platform=darwin-arm64"
        ));
        assert!(headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer jwt-c"));
        assert!(headers
            .iter()
            .any(|(k, v)| k == "x-coding-plan-api-key" && v == "key-c"));
    }

    #[test]
    fn claim_request_shape() {
        let (url, headers, body) = build_claim_request(JWT, KEY, "plan-7", "captcha-param-1");
        assert_eq!(url, "https://zcode.z.ai/api/v1/zcode-plan/billing/claim");
        assert!(headers
            .iter()
            .any(|(k, v)| k == "X-Aliyun-Captcha-Verify-Param" && v == "captcha-param-1"));
        assert_eq!(body, r#"{"plan_id":"plan-7"}"#);
        // No captcha solution: the verify header is absent (degraded parity).
        let (_, h2, _) = build_claim_request(JWT, KEY, "plan-7", "");
        assert!(!h2.iter().any(|(k, _)| k == "X-Aliyun-Captcha-Verify-Param"));
    }

    #[test]
    fn reset_request_shape() {
        let (url, headers, body) = build_reset_request(JWT, KEY, 1797000000000);
        assert_eq!(url, "https://zcode.z.ai/api/v1/coding-plan/reset");
        assert_eq!(body, r#"{"expire_at":1797000000000}"#);
        assert!(headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer jwt-c"));
    }
}
