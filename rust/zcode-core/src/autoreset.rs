//! Port of auto_reset.go's decision logic (pure parts).
//!
//! The reset opportunity store exposes slots with millisecond expire_at
//! timestamps (the da48fec unit confirmation is load-bearing). Two spend
//! triggers: threshold (account actually ran dry) and expiry (slot about to
//! lapse — use-it-or-lose-it). Idempotency keys prevent double-spend of the
//! same slot across concurrent evaluations.

/// Deterministic idempotency key for the expiring path (Go autoResetIdemKey):
/// account + slot expiry uniquely identify a spendable slot. The threshold
/// path has no stable slot identity and must return an empty key (its spend
/// guard rejects empty keys conservatively).
pub fn idem_key(expiring: bool, account_id: i64, expire_at_ms: i64) -> String {
    if !expiring {
        return String::new();
    }
    format!("auto-expiry-{account_id}-{expire_at_ms}")
}

/// Expiry-window decision: spend the slot if it lapses within `window_secs`
/// (window <= 0 disables the trigger). Slots already expired (expire_at <=
/// now) never fire — spending a lapsed slot necessarily fails upstream.
pub fn should_spend_expiring(now_unix: i64, expire_at_ms: i64, window_secs: i64) -> bool {
    if window_secs <= 0 {
        return false;
    }
    if expire_at_ms <= 0 {
        // No expiry given: treat as indefinite, not near-expiry.
        return false;
    }
    let expire_at_secs = expire_at_ms / 1000;
    expire_at_secs > now_unix && expire_at_secs <= now_unix + window_secs
}

/// Threshold decision: the account is exhausted and a slot's remaining
/// lifetime exceeds the minimum-wait (a slot about to lapse anyway is not
/// worth spending on a full refill).
pub fn should_spend_threshold(now_unix: i64, expire_at_ms: i64, min_wait_secs: i64) -> bool {
    if expire_at_ms <= 0 {
        // Indefinite slot: always spendable when the account is exhausted.
        return true;
    }
    let expire_at_secs = expire_at_ms / 1000;
    expire_at_secs > now_unix + min_wait_secs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idem_keys() {
        assert_eq!(idem_key(true, 7, 123456), "auto-expiry-7-123456");
        assert_eq!(
            idem_key(false, 7, 123456),
            "",
            "threshold path has no stable slot key"
        );
    }

    #[test]
    fn expiry_window() {
        let now = 10_000i64;
        assert!(should_spend_expiring(now, (now + 600) * 1000, 900));
        assert!(
            !should_spend_expiring(now, (now + 1200) * 1000, 900),
            "outside window"
        );
        assert!(
            !should_spend_expiring(now, (now - 1) * 1000, 900),
            "already lapsed"
        );
        assert!(!should_spend_expiring(now, 0, 900), "indefinite slot");
        assert!(
            !should_spend_expiring(now, (now + 600) * 1000, 0),
            "window disabled"
        );
    }

    #[test]
    fn threshold_min_wait() {
        let now = 10_000i64;
        assert!(
            should_spend_threshold(now, 0, 3600),
            "indefinite always spendable"
        );
        assert!(should_spend_threshold(now, (now + 7200) * 1000, 3600));
        assert!(
            !should_spend_threshold(now, (now + 1800) * 1000, 3600),
            "lapses before min wait"
        );
    }
}
