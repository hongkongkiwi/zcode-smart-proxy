//! Port of auto_reset.go's decision logic (pure parts).
//!
//! The reset opportunity store exposes slots with millisecond expire_at
//! timestamps (the da48fec unit confirmation is load-bearing). Two spend
//! triggers: threshold (account actually ran dry) and expiry (slot about to
//! lapse — use-it-or-lose-it). Idempotency keys prevent double-spend of the
//! same slot across concurrent evaluations.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const SPEND_GAP_SECS: u64 = 1800;
pub const ATTEMPT_INTERVAL_SECS: u64 = 600;
pub const EXPIRY_WINDOW_DEFAULT_MIN: i64 = 60;
pub const MIN_WAIT_DEFAULT_MIN: i64 = 60;
pub const WEEK_WAIT_DEFAULT_HOURS: i64 = 24;

/// Spend when the natural reset wait is unknown or meets the threshold.
pub fn should_spend(wait_known: bool, wait_secs: i64, threshold_secs: i64) -> bool {
    !wait_known || wait_secs >= threshold_secs
}

/// A reset opportunity with an expiry in Unix seconds; zero means unknown.
pub struct ResetSlot {
    pub expire_at: i64,
}

/// Return the earliest positive future expiry within the enabled window.
pub fn slot_expiring_soon(now_unix: i64, window_secs: i64, slots: &[ResetSlot]) -> Option<i64> {
    if window_secs <= 0 {
        return None;
    }
    let window_end = now_unix.saturating_add(window_secs);
    slots
        .iter()
        .map(|slot| slot.expire_at)
        .filter(|&expiry| expiry > 0 && expiry > now_unix && expiry <= window_end)
        .min()
}

/// Recent confirmed spends by account. This guard does not reserve a spend.
/// The caller must hold per-account automation admission across the decision and remote operation.
#[derive(Default)]
pub struct SpendGuard {
    stamps: Mutex<HashMap<i64, (Instant, i64)>>,
}

impl SpendGuard {
    /// Record only a confirmed used spend; zero identifies an unattributed spend.
    pub fn stamp(&self, account_id: i64, at: Instant, slot: i64) {
        self.stamps.lock().unwrap().insert(account_id, (at, slot));
    }

    pub fn permits(&self, account_id: i64, expire_at: i64, now: Instant) -> bool {
        let stamps = self.stamps.lock().unwrap();
        match stamps.get(&account_id) {
            Some(&(at, slot)) if within_gap(at, now) => slot != 0 && slot != expire_at,
            _ => true,
        }
    }

    pub fn spent_within_gap(&self, account_id: i64, now: Instant) -> bool {
        let stamps = self.stamps.lock().unwrap();
        stamps
            .get(&account_id)
            .is_some_and(|&(at, _)| within_gap(at, now))
    }
}

fn within_gap(at: Instant, now: Instant) -> bool {
    match now.checked_duration_since(at) {
        Some(elapsed) => elapsed < Duration::from_secs(SPEND_GAP_SECS),
        None => true,
    }
}

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

/// Legacy threshold decision based on slot lifetime, deprecated for automatic reset.
/// It does not evaluate the natural reset wait; use `should_spend` for the service.
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
