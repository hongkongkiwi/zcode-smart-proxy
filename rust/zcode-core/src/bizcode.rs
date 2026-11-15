//! Port of relay.go's error-classification matchers.
//!
//! Semantics contract: exact business-code boundary matching (a Contains
//! match would hit `"code":30071` for target 3007), lowercase-then-match
//! like the Go callers, and the never-globalize rule — these codes mean
//! different things on other bigmodel endpoints, so shape scoping lives in
//! the caller.

/// Exact `"code":` business-code match: optional spaces after the colon,
/// the code must end on a non-digit boundary. Input is matched as-is;
/// callers lowercase first (Go hasBizCode contract).
pub fn has_biz_code(text: &str, code: &str) -> bool {
    const NEEDLE: &str = "\"code\":";
    let mut i = 0usize;
    while let Some(rel) = text[i..].find(NEEDLE) {
        let mut k = i + rel + NEEDLE.len();
        while k < text.len() && text.as_bytes()[k] == b' ' {
            k += 1;
        }
        if text[k..].starts_with(code) {
            let end = k + code.len();
            if end >= text.len() || !text.as_bytes()[end].is_ascii_digit() {
                return true;
            }
        }
        i = k;
        if i >= text.len() {
            break;
        }
    }
    false
}

/// Exact provider_code / providerErrorCode match (both spellings, keys are
/// lowercase like the Go caller's lowered text): spaces AND an opening quote
/// may follow the colon before the code.
pub fn has_provider_code(text: &str, code: &str) -> bool {
    for key in ["\"provider_code\":", "\"providererrorcode\":"] {
        let mut i = 0usize;
        while let Some(rel) = text[i..].find(key) {
            let mut k = i + rel + key.len();
            while k < text.len() && (text.as_bytes()[k] == b' ' || text.as_bytes()[k] == b'"') {
                k += 1;
            }
            if text[k..].starts_with(code) {
                let end = k + code.len();
                if end >= text.len() || !text.as_bytes()[end].is_ascii_digit() {
                    return true;
                }
            }
            i = k;
            if i >= text.len() {
                break;
            }
        }
    }
    false
}

/// 2xx-envelope exhaustion family: HTTP 402 or the quota phrases upstream
/// actually sends ("exceed quota limit" is the real message; "quota exceeded"
/// alone never matched it — the 2026-11-12 live regression).
pub fn is_exhausted_error(status_code: u16, text: &str) -> bool {
    if status_code == 402 {
        return true;
    }
    let low = text.to_lowercase();
    [
        "insufficient balance",
        "insufficient funds",
        "no resource package",
        "resource package exhausted",
        "quota exceeded",
        "exceed quota limit",
        "余额不足",
        "额度已用完",
    ]
    .iter()
    .any(|m| low.contains(m))
}

/// Risk-control block (code 3012 / unusual activity): temporary account ban,
/// cooling — never MarkInvalid material.
pub fn is_risk_blocked(text: &str) -> bool {
    let low = text.to_lowercase();
    low.contains("unusual activity") || has_biz_code(&low, "3012")
}

/// Captcha-rejection family: the keywords plus biz code 3007 (zcode-plan
/// security-check rejection; same family as 3012, never the credential
/// branch).
pub fn is_captcha_error(text: &str) -> bool {
    let low = text.to_lowercase();
    for m in [
        "captcha",
        "verify token",
        "verify failed",
        "verifycode",
        "human verification",
        "人机验证",
        "请完成验证",
        "安全验证",
        "安全校验",
    ] {
        if low.contains(m) {
            return true;
        }
    }
    has_biz_code(&low, "3007")
}

/// Cloudflare/WAF challenge: the Cf-Mitigated header or the challenge-page
/// fingerprint keywords. Egress-IP/risk-tier problem, never a credential or
/// captcha signal.
pub fn is_cloudflare_challenge(cf_mitigated_header: Option<&str>, text: &str) -> bool {
    if cf_mitigated_header == Some("challenge") {
        return true;
    }
    let low = text.to_lowercase();
    [
        "just a moment",
        "attention required",
        "checking your browser",
        "verifying you are human",
        "cf-challenge",
        "challenge-platform",
        "_cf_chl_opt",
        "cf-browser-verification",
        "cf-error-details",
    ]
    .iter()
    .any(|m| low.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Frozen table ported from special_proto_relay_test.go (17 rows, incl.
    // the 3.17.1 wave's 3104/3106 additions and boundary guards).
    #[test]
    fn frozen_classification_table() {
        struct C {
            name: &'static str,
            shape: &'static str,
            status: u16,
            text: &'static str,
            want: bool,
        }
        let cases = vec![
            C { name: "offpeak queued code", shape: "offpeak", status: 429, text: r#"{"code":3105,"msg":"queued"}"#, want: true },
            C { name: "offpeak bare 429 = queue signal", shape: "offpeak", status: 429, text: r#"{"error":{"message":"busy"}}"#, want: true },
            C { name: "offpeak ticket expired", shape: "offpeak", status: 400, text: r#"{"code":3102,"msg":"ticket unavailable"}"#, want: true },
            C { name: "offpeak ticket wrong state (3.17.1)", shape: "offpeak", status: 400, text: r#"{"code":3104,"msg":"invalid off-peak ticket"}"#, want: true },
            C { name: "offpeak window expired (3.17.1)", shape: "offpeak", status: 400, text: r#"{"code":3106,"msg":"off-peak active window expired"}"#, want: true },
            C { name: "offpeak legacy 3001 compat", shape: "offpeak", status: 400, text: r#"{"code": 3001}"#, want: true },
            C { name: "offpeak eligibility", shape: "offpeak", status: 400, text: r#"{"code":3101}"#, want: true },
            C { name: "offpeak idle quota", shape: "offpeak", status: 400, text: r#"{"code":3103}"#, want: true },
            C { name: "offpeak long code boundary", shape: "offpeak", status: 400, text: r#"{"code":31021}"#, want: false },
            C { name: "offpeak unrelated 400", shape: "offpeak", status: 400, text: r#"{"error":{"message":"bad request"}}"#, want: false },
            C { name: "highspeed card expired quoted", shape: "highspeed", status: 400, text: r#"{"error":{"provider_code":"3402"}}"#, want: true },
            C { name: "highspeed card expired numeric", shape: "highspeed", status: 400, text: r#"{"provider_code": 3402}"#, want: true },
            C { name: "highspeed providerErrorCode spelling", shape: "highspeed", status: 400, text: r#"{"providerErrorCode":"3402"}"#, want: true },
            C { name: "highspeed long code boundary", shape: "highspeed", status: 400, text: r#"{"provider_code":"34021"}"#, want: false },
            C { name: "highspeed generic biz code not matched", shape: "highspeed", status: 400, text: r#"{"code":3402}"#, want: false },
            C { name: "plain shape never special", shape: "", status: 429, text: r#"{"code":3105}"#, want: false },
        ];
        for c in cases {
            let got = match c.shape {
                "offpeak" => {
                    c.status == 429
                        || ["3101", "3102", "3103", "3104", "3105", "3106", "3001"]
                            .iter()
                            .any(|code| has_biz_code(&c.text.to_lowercase(), code))
                }
                "highspeed" => has_provider_code(&c.text.to_lowercase(), "3402"),
                _ => false,
            };
            assert_eq!(got, c.want, "{}: shape={} status={} text={}", c.name, c.shape, c.status, c.text);
        }
    }

    // Ported from TestHasProviderCode.
    #[test]
    fn provider_code_boundaries() {
        let cases = [
            (r#"{"provider_code":"3402"}"#, true),
            (r#"{"provider_code":3402}"#, true),
            (r#"{"provider_code": "3402"}"#, true),
            (r#"{"provider_code":"34021"}"#, false),
            (r#"{"provider_code":"13402"}"#, false),
            (r#"{"providerErrorCode":"3402"}"#, true),
            (r#"{"other":"3402"}"#, false),
            (r#"{}"#, false),
        ];
        for (text, want) in cases {
            assert_eq!(has_provider_code(&text.to_lowercase(), "3402"), want, "{text}");
        }
    }

    #[test]
    fn exhaustion_family() {
        assert!(is_exhausted_error(200, r#"{"code":1005,"msg":"exceed quota limit"}"#));
        assert!(is_exhausted_error(402, "anything"));
        assert!(is_exhausted_error(200, "Insufficient Balance"));
        assert!(is_exhausted_error(200, "QUOTA EXCEEDED"));
        assert!(is_exhausted_error(200, "额度已用完"));
        // Go parity: phrase matching is strings.Contains, so suffix digits
        // still match. This is the shipped Go behavior, not a port bug.
        assert!(is_exhausted_error(200, "exceed quota limit2"));
        assert!(!is_exhausted_error(500, "internal error"));
    }

    #[test]
    fn risk_and_captcha_families() {
        assert!(is_risk_blocked(r#"{"code":3012,"msg":"..."}"#));
        assert!(!is_risk_blocked(r#"{"code":30121}"#));
        assert!(is_risk_blocked("Unusual Activity detected"));
        assert!(is_captcha_error("请完成验证"));
        assert!(is_captcha_error(r#"{"code":3007}"#));
        assert!(!is_captcha_error(r#"{"code":30071}"#));
    }

    #[test]
    fn cloudflare_family() {
        assert!(is_cloudflare_challenge(Some("challenge"), ""));
        assert!(is_cloudflare_challenge(None, "Just a moment..."));
        assert!(is_cloudflare_challenge(None, "<html>_cf_chl_opt</html>"));
        assert!(!is_cloudflare_challenge(None, "<html>normal page</html>"));
    }
}
