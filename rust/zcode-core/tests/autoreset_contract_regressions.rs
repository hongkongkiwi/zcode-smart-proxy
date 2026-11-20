use std::time::{Duration, Instant};

use zcode_core::autoreset::{
    should_spend, slot_expiring_soon, ResetSlot, SpendGuard, ATTEMPT_INTERVAL_SECS,
    EXPIRY_WINDOW_DEFAULT_MIN, MIN_WAIT_DEFAULT_MIN, SPEND_GAP_SECS, WEEK_WAIT_DEFAULT_HOURS,
};

fn slot(expire_at: i64) -> ResetSlot {
    ResetSlot { expire_at }
}

#[test]
fn should_spend_unknown_spends_equality_spends_smaller_waits() {
    // Go autoResetShouldSpend: unknown wait means spend; a known wait at or
    // above the threshold (equality included) means spend; below means keep
    // the natural reset.
    assert!(should_spend(false, 0, 3600), "unknown wait must spend");
    assert!(
        should_spend(false, 9_999_999, 3600),
        "unknown wait must spend regardless of the wait value"
    );
    assert!(
        should_spend(true, 3600, 3600),
        "wait equal to threshold spends"
    );
    assert!(
        should_spend(true, 3601, 3600),
        "wait above threshold spends"
    );
    assert!(
        !should_spend(true, 3599, 3600),
        "wait below threshold keeps the natural reset"
    );
    assert!(!should_spend(true, 0, 3600));
    assert!(
        !should_spend(true, -1, 3600),
        "already-elapsed wait stays below threshold"
    );
}

#[test]
fn slot_expiring_soon_returns_earliest_future_expiry_in_whole_seconds() {
    let now = 10_000_i64;
    assert_eq!(
        slot_expiring_soon(
            now,
            900,
            &[slot(now + 500), slot(now + 100), slot(now + 300)]
        ),
        Some(now + 100),
        "earliest in-window expiry wins"
    );
    // Lower boundary is exclusive: a slot already at or before now never fires.
    assert_eq!(
        slot_expiring_soon(now, 900, &[slot(now)]),
        None,
        "expired slot never fires"
    );
    assert_eq!(
        slot_expiring_soon(now, 900, &[slot(now + 1)]),
        Some(now + 1)
    );
    // Upper boundary is inclusive: expire_at == now + window still triggers.
    assert_eq!(
        slot_expiring_soon(now, 900, &[slot(now + 900)]),
        Some(now + 900)
    );
    assert_eq!(
        slot_expiring_soon(now, 900, &[slot(now + 901)]),
        None,
        "expiry past the window does not trigger"
    );
    // Already-lapsed and unknown-expiry (0, treated as indefinite) slots are skipped.
    assert_eq!(
        slot_expiring_soon(now, 900, &[slot(now - 1), slot(0), slot(now + 5000)]),
        None
    );
    assert_eq!(
        slot_expiring_soon(now, 900, &[]),
        None,
        "no slots means no trigger"
    );
}

#[test]
fn slot_expiring_soon_disabled_window_and_overflow_boundaries_do_not_panic() {
    // window <= 0 disables the trigger even when a slot looks in-window.
    assert_eq!(slot_expiring_soon(10_000, 0, &[slot(10_500)]), None);
    assert_eq!(slot_expiring_soon(10_000, -5, &[slot(10_500)]), None);
    // now at i64::MAX makes now + window overflow, and no expiry can be
    // strictly after i64::MAX: the answer is None under checked or
    // saturating math alike, and the addition must not panic.
    assert_eq!(
        slot_expiring_soon(i64::MAX, i64::MAX, &[slot(i64::MAX)]),
        None,
        "overflowing window math must not panic"
    );
    // A genuinely future slot behind an overflowing bound: which of the two
    // math modes wins is implementation-defined, so only pin no-panic here.
    let _ = slot_expiring_soon(i64::MAX - 3, 10, &[slot(i64::MAX - 1)]);
}

#[test]
fn packet_a_constants_match_the_go_reference_values() {
    assert_eq!(SPEND_GAP_SECS, 1800_u64, "30 minute double-spend gap");
    assert_eq!(ATTEMPT_INTERVAL_SECS, 600_u64, "10 minute attempt interval");
    assert_eq!(EXPIRY_WINDOW_DEFAULT_MIN, 60_i64);
    assert_eq!(MIN_WAIT_DEFAULT_MIN, 60_i64);
    assert_eq!(WEEK_WAIT_DEFAULT_HOURS, 24_i64);
}

#[test]
fn spend_guard_default_permits_everything_and_reports_no_recent_spend() {
    let guard = SpendGuard::default();
    assert!(
        guard.permits(1, 500, Instant::now()),
        "unstamped account is unrestricted"
    );
    assert!(guard.permits(1, 0, Instant::now()));
    assert!(
        !guard.spent_within_gap(1, Instant::now()),
        "no stamp means no deferral"
    );
    assert!(!guard.spent_within_gap(2, Instant::now()));
}

#[test]
fn spend_guard_same_slot_blocks_within_gap_and_expires_at_exactly_30_minutes() {
    let guard = SpendGuard::default();
    let at = Instant::now();
    guard.stamp(1, at, 500);
    let within = at + Duration::from_secs(SPEND_GAP_SECS - 1);
    assert!(
        !guard.permits(1, 500, within),
        "same slot within the gap is refused"
    );
    assert!(guard.spent_within_gap(1, within));
    // The Go predicate is strict (< gap): at exactly 30 minutes the stamp
    // has expired and the same slot is spendable again.
    let exact = at + Duration::from_secs(SPEND_GAP_SECS);
    assert!(
        guard.permits(1, 500, exact),
        "exactly-gap stamp no longer blocks"
    );
    assert!(!guard.spent_within_gap(1, exact));
}

#[test]
fn spend_guard_unattributed_stamp_blocks_any_slot_within_gap() {
    // Frozen Go contract (spend_guard_stamps_test.go, review F3): a slot=0
    // stamp left by the manual/threshold path conservatively refuses every
    // expiring slot for the rest of the gap, then releases.
    let guard = SpendGuard::default();
    let at = Instant::now();
    guard.stamp(2, at, 0);
    let within = at + Duration::from_secs(60);
    assert!(!guard.permits(2, 500, within));
    assert!(
        !guard.permits(2, 123_456, within),
        "unattributed stamp blocks all slots"
    );
    assert!(guard.spent_within_gap(2, within));
    let after_gap = at + Duration::from_secs(SPEND_GAP_SECS);
    assert!(
        guard.permits(2, 500, after_gap),
        "unattributed stamp is not a permanent fuse"
    );
}

#[test]
fn spend_guard_allows_different_attributed_slot_within_gap() {
    // Frozen Go TestGuardDifferentSlotStillAllowed: within the gap, a stamp
    // with a known slot only blocks that same slot.
    let guard = SpendGuard::default();
    let at = Instant::now();
    guard.stamp(3, at, 1000);
    let within = at + Duration::from_secs(60);
    assert!(
        guard.permits(3, 2000, within),
        "different attributed slot stays allowed"
    );
    assert!(
        !guard.permits(3, 1000, within),
        "same slot is still blocked"
    );
}

#[test]
fn spend_guard_stamps_are_isolated_per_account() {
    let guard = SpendGuard::default();
    let at = Instant::now();
    guard.stamp(10, at, 700);
    let within = at + Duration::from_secs(60);
    assert!(
        guard.permits(11, 700, within),
        "another account's stamp must not leak"
    );
    assert!(!guard.permits(10, 700, within));
    assert!(!guard.spent_within_gap(11, within));
}

#[test]
fn spend_guard_future_stamp_instant_is_treated_conservatively_without_panic() {
    // A stamp whose Instant is ahead of the supplied now (injected clocks,
    // skew) must read as within-gap and must not panic on subtraction; the
    // frozen slot-identity rule still applies on top of it.
    let guard = SpendGuard::default();
    let now = Instant::now();
    let future = now + Duration::from_secs(600);
    guard.stamp(20, future, 900);
    assert!(
        !guard.permits(20, 900, now),
        "future stamp counts as within gap for its slot"
    );
    assert!(
        guard.permits(20, 1000, now),
        "within-gap reading still honors slot identity"
    );
    assert!(guard.spent_within_gap(20, now));
}
