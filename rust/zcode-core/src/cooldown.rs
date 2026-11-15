//! Port of pool.go cooldown escalation + relay.go rate-limit recognition.
//!
//! Escalation contract: same account eating repeated 429s cools 30s -> 120s
//! -> 300s, keyed on markers the proxy itself wrote into last_error — paid
//! channel limits also land in last_error, so only the exact free-side
//! markers escalate (the 2026-10-10 lesson: paid reasons must not lift the
//! free tier's first rung straight to 120s).

/// Next rate-limit cooldown in seconds from the account's last_error text.
pub fn next_rate_limit_cooldown(last_error: &str) -> u64 {
    if last_error.contains("冷却 120s") || last_error.contains("冷却 300s") {
        300
    } else if last_error.contains("冷却 30s") {
        120
    } else {
        30
    }
}

/// Rate limit: HTTP 429, biz codes 1302/1303 (concurrency caps), or the
/// bare code + "rate limit" phrase combination.
pub fn is_rate_limit_body(status: u16, text: &str) -> bool {
    if status == 429 {
        return true;
    }
    if crate::has_biz_code(text, "1302") || crate::has_biz_code(text, "1303") {
        return true;
    }
    let low = text.to_lowercase();
    (text.contains("1302") || text.contains("1303")) && low.contains("rate limit")
}

/// Risk-strike ladder: Nth block within the 24h window cools for
/// 120s -> 30min -> 24h (index clamped at the last rung). Shared shape by
/// free and paid channels with independent strike counters.
pub const RISK_LADDER_SECS: [u64; 3] = [120, 1800, 86400];
pub const RISK_STRIKE_WINDOW_SECS: i64 = 86_400;

/// Prune expired strikes and append the new one; returns the count of live
/// strikes (Go MarkPaidRiskCooling's in-window accounting).
pub fn record_risk_strike(live_strikes: &mut Vec<i64>, now_unix: i64) -> usize {
    let cutoff = now_unix - RISK_STRIKE_WINDOW_SECS;
    live_strikes.retain(|&ts| ts > cutoff);
    live_strikes.push(now_unix);
    live_strikes.len()
}

/// Cooldown for the current strike index (1-based count from
/// record_risk_strike), clamped to the ladder tail.
pub fn risk_cooldown_secs(strike_count: usize) -> u64 {
    let idx = strike_count
        .saturating_sub(1)
        .min(RISK_LADDER_SECS.len() - 1);
    RISK_LADDER_SECS[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalation_ladder() {
        assert_eq!(next_rate_limit_cooldown(""), 30);
        assert_eq!(
            next_rate_limit_cooldown("上游限流（HTTP 429），冷却 30s"),
            120
        );
        assert_eq!(
            next_rate_limit_cooldown("上游限流（HTTP 429），冷却 120s"),
            300
        );
        assert_eq!(next_rate_limit_cooldown("冷却 300s"), 300);
        // Paid-channel wording must not escalate the free tier's first rung.
        assert_eq!(next_rate_limit_cooldown("付费通道限流，冷却"), 30);
    }

    #[test]
    fn rate_limit_recognition() {
        assert!(is_rate_limit_body(429, "anything"));
        assert!(is_rate_limit_body(200, r#"{"code":1302}"#));
        assert!(is_rate_limit_body(200, r#"{"code": 1303}"#));
        assert!(is_rate_limit_body(200, "code 1302: rate limit hit"));
        assert!(!is_rate_limit_body(200, "1302 alone without the phrase"));
        assert!(!is_rate_limit_body(500, "internal"));
    }

    #[test]
    fn risk_ladder_and_window() {
        let mut strikes = Vec::new();
        assert_eq!(record_risk_strike(&mut strikes, 1000), 1);
        assert_eq!(risk_cooldown_secs(1), 120);
        assert_eq!(record_risk_strike(&mut strikes, 2000), 2);
        assert_eq!(risk_cooldown_secs(2), 1800);
        assert_eq!(record_risk_strike(&mut strikes, 3000), 3);
        assert_eq!(risk_cooldown_secs(3), 86400);
        // Fourth strike inside the window clamps at the ladder tail.
        assert_eq!(record_risk_strike(&mut strikes, 4000), 4);
        assert_eq!(risk_cooldown_secs(4), 86400);
        // Strikes older than 24h prune out.
        assert_eq!(record_risk_strike(&mut strikes, 86_400 * 2 + 5000), 1);
        assert_eq!(risk_cooldown_secs(1), 120);
    }
}
