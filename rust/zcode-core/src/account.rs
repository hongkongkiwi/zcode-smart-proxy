//! Port of pool.go's account state machine (pure logic).
//!
//! Selectability contract (Go accountSelectable): disabled/invalid/exhausted/
//! inactive accounts are never selectable; cooling is time-bounded — an
//! expired cooling_until recovers without an explicit transition.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    Active,
    Cooling,
    Exhausted,
    Invalid,
    Inactive,
    Disabled,
}

/// Can this account serve a request right now (free channel gate)?
pub fn selectable(enabled: bool, status: AccountStatus, cooling_until: i64, now_unix: i64) -> bool {
    if !enabled {
        return false;
    }
    match status {
        AccountStatus::Disabled
        | AccountStatus::Invalid
        | AccountStatus::Exhausted
        | AccountStatus::Inactive => false,
        AccountStatus::Cooling => cooling_until <= 0 || cooling_until <= now_unix,
        AccountStatus::Active => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_enabled_selectable() {
        assert!(selectable(true, AccountStatus::Active, 0, 1000));
    }

    #[test]
    fn hard_states_never_selectable() {
        for st in [
            AccountStatus::Disabled,
            AccountStatus::Invalid,
            AccountStatus::Exhausted,
            AccountStatus::Inactive,
        ] {
            assert!(!selectable(true, st, 0, 1000), "{st:?}");
        }
        // Even a disabled flag overrides an active status.
        assert!(!selectable(false, AccountStatus::Active, 0, 1000));
    }

    #[test]
    fn cooling_is_time_bounded() {
        assert!(!selectable(true, AccountStatus::Cooling, 2000, 1000));
        assert!(selectable(true, AccountStatus::Cooling, 1000, 1000));
        assert!(selectable(true, AccountStatus::Cooling, 500, 1000));
        // cooling_until <= 0 (legacy/hand-written rows) counts as expired.
        assert!(selectable(true, AccountStatus::Cooling, 0, 1000));
    }
}
