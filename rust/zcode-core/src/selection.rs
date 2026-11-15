//! Port of pool.go's account selection: channel gating, strategies, sticky
//! sessions. Pure logic over plain account views; persistence lives behind
//! the store in the service layer.
//!
//! Channel semantics (Go):
//! - free: zcode.z.ai JWT channel (plan quota, no metered cost)
//! - paid: api.z.ai API Key channel (metered, real spend)
//! - paid_only pseudo-channel: accounts whose ONLY channel is the API key —
//!   paid_fallback_mode=never must not strand them.

use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct AccountView {
    pub id: i64,
    pub provider: String,
    pub enabled: bool,
    /// Go Status string; compared against the string constants to stay
    /// byte-faithful with the DB rows ("active"/"cooling"/...).
    pub status: String,
    pub cooling_until: i64,
    pub paid_cooling_until: i64,
    pub paid_fallback: bool,
    pub zcode_jwt: String,
    pub api_key: String,
    pub account_group: String,
    pub remaining: f64,
    pub priority: i64,
}

pub const STRATEGY_RANDOM: &str = "random";
pub const STRATEGY_ROUND_ROBIN: &str = "round_robin";
pub const STRATEGY_BEST_QUOTA: &str = "best_quota";
pub const STRATEGY_PRIORITY: &str = "priority";

pub const CHANNEL_FREE: &str = "free";
pub const CHANNEL_PAID: &str = "paid";
pub const CHANNEL_PAID_ONLY: &str = "paid_only";

pub const STATUS_ACTIVE: &str = "active";
pub const STATUS_COOLING: &str = "cooling";
pub const STATUS_EXHAUSTED: &str = "exhausted";
pub const STATUS_INVALID: &str = "invalid";
pub const STATUS_INACTIVE: &str = "inactive";
pub const STATUS_DISABLED: &str = "disabled";

/// Comma-separated multi-group membership, exact segment match.
pub fn match_account_group(account_group: &str, group: &str) -> bool {
    account_group.split(',').any(|p| p.trim() == group)
}

/// Live status: expired cooling reads as active (dashboard and relay must
/// never disagree).
pub fn effective_status(status: &str, cooling_until: i64, now_unix: i64) -> String {
    if status == STATUS_COOLING && (cooling_until <= 0 || now_unix >= cooling_until) {
        return STATUS_ACTIVE.to_string();
    }
    status.to_string()
}

/// Account-level gate (Go accountSelectable): hard states out, cooling
/// time-bounded (<=0 counts as expired).
pub fn account_selectable(status: &str, cooling_until: i64, now_unix: i64) -> bool {
    effective_status(status, cooling_until, now_unix) == STATUS_ACTIVE
}

pub fn selectable_for_free_phase(a: &AccountView, now_unix: i64) -> bool {
    !a.zcode_jwt.is_empty() && account_selectable(&a.status, a.cooling_until, now_unix)
}

/// Paid-channel availability: enabled, not disabled, has API key, paid
/// fallback on, past paid cooling; JWT-less accounts additionally need
/// account-level selectability (their paid channel IS the account channel).
pub fn paid_channel_available(a: &AccountView, now_unix: i64) -> bool {
    if !a.enabled || a.status == STATUS_DISABLED || a.api_key.is_empty() || !a.paid_fallback {
        return false;
    }
    if now_unix < a.paid_cooling_until {
        return false;
    }
    if a.zcode_jwt.is_empty() {
        return account_selectable(&a.status, a.cooling_until, now_unix);
    }
    true
}

pub fn channel_selectable(a: &AccountView, channel: &str, now_unix: i64) -> bool {
    match channel {
        CHANNEL_FREE => selectable_for_free_phase(a, now_unix),
        CHANNEL_PAID => paid_channel_available(a, now_unix),
        CHANNEL_PAID_ONLY => {
            a.zcode_jwt.is_empty()
                && !a.api_key.is_empty()
                && now_unix >= a.paid_cooling_until
                && account_selectable(&a.status, a.cooling_until, now_unix)
        }
        _ => account_selectable(&a.status, a.cooling_until, now_unix),
    }
}

pub fn channel_has_creds(a: &AccountView, channel: &str) -> bool {
    match channel {
        CHANNEL_FREE => !a.zcode_jwt.is_empty(),
        CHANNEL_PAID | CHANNEL_PAID_ONLY => !a.api_key.is_empty(),
        _ => !a.zcode_jwt.is_empty() || !a.api_key.is_empty(),
    }
}

/// Strategy context: the settings a selection needs, provided by the caller
/// (DB reads stay in the service layer).
pub struct StrategyConfig {
    pub strategy: String,
    /// Sticky sessions enabled (setting sticky_sessions, default on).
    pub sticky_enabled: bool,
}

impl Default for StrategyConfig {
    fn default() -> Self {
        Self {
            strategy: STRATEGY_ROUND_ROBIN.to_string(),
            sticky_enabled: true,
        }
    }
}

const STICKY_TTL_SECS: i64 = 3600;
const STICKY_MAX: usize = 10_000;

#[derive(Clone, Copy)]
struct StickyEntry {
    account_id: i64,
    seen_at: i64,
}

#[derive(Default)]
pub struct Selector {
    config: StrategyConfig,
    sticky: HashMap<String, StickyEntry>,
    rotation: HashMap<String, usize>,
}

/// Selection outcome: the chosen account (None = no candidate) and whether
/// it came from sticky reuse (telemetry parity with the Go logs).
pub struct Selection<'a> {
    pub account: Option<&'a AccountView>,
    pub sticky_hit: bool,
}

/// One request's selection parameters (Go SelectChannel's argument cluster).
pub struct SelectionQuery<'k> {
    pub provider: &'k str,
    pub group: &'k str,
    /// Already-tried account ids for this request (never re-selected, never
    /// sticky-bound).
    pub skip: &'k HashMap<i64, bool>,
    /// Channel gate ("" = any channel, account-level gate).
    pub channel: &'k str,
    pub now_unix: i64,
}

impl Selector {
    pub fn new(config: StrategyConfig) -> Self {
        Self {
            config,
            sticky: HashMap::new(),
            rotation: HashMap::new(),
        }
    }

    /// Filter by provider/group/skip/channel gates, then apply strategy.
    pub fn select_channel<'a>(
        &mut self,
        accounts: &'a [AccountView],
        q: &SelectionQuery,
    ) -> Option<&'a AccountView> {
        let pool: Vec<&AccountView> = accounts
            .iter()
            .filter(|a| {
                a.provider == q.provider
                    && (q.group.is_empty() || match_account_group(&a.account_group, q.group))
                    && !q.skip.get(&a.id).copied().unwrap_or(false)
                    && channel_selectable(a, q.channel, q.now_unix)
                    && channel_has_creds(a, q.channel)
            })
            .collect();
        if pool.is_empty() {
            return None;
        }
        Some(self.pick_by_strategy(&pool, q.group, q.provider))
    }

    fn pick_by_strategy<'a>(
        &mut self,
        pool: &[&'a AccountView],
        group: &str,
        provider: &str,
    ) -> &'a AccountView {
        let mut pool = pool.to_vec();
        if self.config.strategy == STRATEGY_PRIORITY {
            // Cascade: keep only the best (lowest) priority tier.
            let min_pri = pool.iter().map(|a| a.priority).min().unwrap_or(0);
            pool.retain(|a| a.priority == min_pri);
        }
        match self.config.strategy.as_str() {
            STRATEGY_BEST_QUOTA => {
                // Highest remaining first; unknown quota (0) sorts last
                // (stable, Go sort.SliceStable).
                pool.sort_by(|a, b| {
                    b.remaining
                        .partial_cmp(&a.remaining)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                pool[0]
            }
            // round_robin (default) and random both rotate fairly here; the
            // service layer injects real entropy for random via its rotation
            // seed, the sequence itself is not a wire contract.
            _ => {
                let key = format!("{group}|{provider}");
                let idx = self.rotation.entry(key).or_insert(0);
                let a = pool[*idx % pool.len()];
                *idx = (*idx + 1) % pool.len();
                a
            }
        }
    }

    /// Sticky-first selection (channel-aware): a sticky hit must revalidate
    /// fresh against the same gates; failed (skip) accounts never stick.
    pub fn select_sticky_channel<'a>(
        &mut self,
        accounts: &'a [AccountView],
        q: &SelectionQuery,
        session_key: &str,
    ) -> Selection<'a> {
        if !session_key.is_empty() && self.config.sticky_enabled {
            if let Some(e) = self.sticky.get(session_key) {
                if q.now_unix - e.seen_at < STICKY_TTL_SECS
                    && !q.skip.get(&e.account_id).copied().unwrap_or(false)
                {
                    let found = accounts.iter().find(|a| {
                        a.id == e.account_id
                            && a.provider == q.provider
                            && (q.group.is_empty()
                                || match_account_group(&a.account_group, q.group))
                            && channel_selectable(a, q.channel, q.now_unix)
                            && channel_has_creds(a, q.channel)
                    });
                    if let Some(a) = found {
                        self.remember_sticky(session_key, a.id, q.now_unix);
                        return Selection {
                            account: Some(a),
                            sticky_hit: true,
                        };
                    }
                }
            }
        }
        match self.select_channel(accounts, q) {
            Some(a) => {
                if !session_key.is_empty() && self.config.sticky_enabled {
                    self.remember_sticky(session_key, a.id, q.now_unix);
                }
                Selection {
                    account: Some(a),
                    sticky_hit: false,
                }
            }
            None => Selection {
                account: None,
                sticky_hit: false,
            },
        }
    }

    fn remember_sticky(&mut self, session_key: &str, account_id: i64, now_unix: i64) {
        // Capacity backstop: evict the oldest entry at the cap.
        if self.sticky.len() >= STICKY_MAX && !self.sticky.contains_key(session_key) {
            if let Some(oldest) = self
                .sticky
                .iter()
                .min_by_key(|(_, e)| e.seen_at)
                .map(|(k, _)| k.clone())
            {
                self.sticky.remove(&oldest);
            }
        }
        self.sticky.insert(
            session_key.to_string(),
            StickyEntry {
                account_id,
                seen_at: now_unix,
            },
        );
    }

    pub fn forget_sticky(&mut self, session_key: &str) {
        self.sticky.remove(session_key);
    }
}

/// Sticky session key derivation (relay.go sessionKey): metadata.user_id
/// first ("u:" prefix), else sha256(system)[:24] hex ("s:" prefix).
pub fn session_key(metadata_user_id: Option<&str>, system_json: Option<&str>) -> String {
    if let Some(uid) = metadata_user_id.filter(|s| !s.is_empty()) {
        return format!("u:{uid}");
    }
    if let Some(sys) = system_json.filter(|s| !s.is_empty()) {
        let mut h = Sha256::new();
        h.update(sys.as_bytes());
        let hex = format!("{:x}", h.finalize());
        return format!("s:{}", &hex[..24]);
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(id: i64, jwt: &str, key: &str) -> AccountView {
        AccountView {
            id,
            provider: "zai".into(),
            enabled: true,
            status: STATUS_ACTIVE.into(),
            zcode_jwt: jwt.into(),
            api_key: key.into(),
            // Dual-channel fixture parity: DB-created accounts default the
            // paid fallback flag on (the editor writes it per account).
            paid_fallback: !key.is_empty(),
            ..Default::default()
        }
    }

    #[test]
    fn group_matching_multi_membership() {
        assert!(match_account_group("eu,failover", "failover"));
        assert!(match_account_group("eu", "eu"));
        assert!(!match_account_group("eu,failover", "us"));
    }

    #[test]
    fn effective_status_expiry() {
        assert_eq!(effective_status(STATUS_COOLING, 500, 1000), STATUS_ACTIVE);
        assert_eq!(effective_status(STATUS_COOLING, 0, 1000), STATUS_ACTIVE);
        assert_eq!(effective_status(STATUS_COOLING, 2000, 1000), STATUS_COOLING);
        assert_eq!(effective_status(STATUS_ACTIVE, 0, 1000), STATUS_ACTIVE);
    }

    #[test]
    fn channel_gates() {
        let now = 1000i64;
        let dual = acct(1, "jwt", "key");
        assert!(selectable_for_free_phase(&dual, now));
        assert!(paid_channel_available(&dual, now));
        let jwt_only = acct(2, "jwt", "");
        assert!(!paid_channel_available(&jwt_only, now), "no API key");
        let key_only = acct(3, "", "key");
        assert!(
            !selectable_for_free_phase(&key_only, now),
            "no free channel"
        );
        assert!(channel_selectable(&key_only, CHANNEL_PAID_ONLY, now));
        // Disabled gates both paid availability and the paid_only pseudo-channel.
        let mut dis = acct(4, "", "key");
        dis.status = STATUS_DISABLED.into();
        assert!(!paid_channel_available(&dis, now));
        assert!(!channel_selectable(&dis, CHANNEL_PAID_ONLY, now));
    }

    #[test]
    fn selection_strategy_round_robin_and_priority() {
        let accounts = vec![acct(1, "j", "k"), acct(2, "j", "k"), acct(3, "j", "k")];
        let mut sel = Selector::new(StrategyConfig::default());
        let skip = HashMap::new();
        let q = |now: i64| SelectionQuery {
            provider: "zai",
            group: "",
            skip: &skip,
            channel: "",
            now_unix: now,
        };
        let a1 = sel.select_channel(&accounts, &q(1000)).unwrap();
        let a2 = sel.select_channel(&accounts, &q(1000)).unwrap();
        let a3 = sel.select_channel(&accounts, &q(1000)).unwrap();
        assert_eq!((a1.id, a2.id, a3.id), (1, 2, 3), "fair rotation");

        let pri = vec![
            AccountView {
                priority: 5,
                ..acct(10, "j", "k")
            },
            AccountView {
                priority: 1,
                ..acct(11, "j", "k")
            },
            AccountView {
                priority: 1,
                ..acct(12, "j", "k")
            },
        ];
        let mut sel_p = Selector::new(StrategyConfig {
            strategy: STRATEGY_PRIORITY.into(),
            sticky_enabled: false,
        });
        let p1 = sel_p.select_channel(&pri, &q(1000)).unwrap();
        let p2 = sel_p.select_channel(&pri, &q(1000)).unwrap();
        assert_eq!(p1.id, 11);
        assert_eq!(
            p2.id, 12,
            "cascade keeps only the top tier, rotates inside it"
        );
    }

    #[test]
    fn best_quota_prefers_remaining() {
        let accounts = vec![
            AccountView {
                remaining: 10.0,
                ..acct(1, "j", "k")
            },
            AccountView {
                remaining: 90.0,
                ..acct(2, "j", "k")
            },
        ];
        let mut sel = Selector::new(StrategyConfig {
            strategy: STRATEGY_BEST_QUOTA.into(),
            sticky_enabled: false,
        });
        let skip = HashMap::new();
        let q = SelectionQuery {
            provider: "zai",
            group: "",
            skip: &skip,
            channel: "",
            now_unix: 1000,
        };
        assert_eq!(sel.select_channel(&accounts, &q).unwrap().id, 2);
    }

    #[test]
    fn sticky_hit_and_revalidation() {
        let accounts = vec![acct(1, "j", "k"), acct(2, "j", "k")];
        let mut sel = Selector::new(StrategyConfig::default());
        let skip = HashMap::new();
        let sq = |now: i64, chan: &'static str| SelectionQuery {
            provider: "zai",
            group: "",
            skip: &skip,
            channel: chan,
            now_unix: now,
        };
        let s1 = sel.select_sticky_channel(&accounts, &sq(1000, ""), "sess-1");
        assert!(!s1.sticky_hit);
        assert_eq!(s1.account.unwrap().id, 1);
        let s2 = sel.select_sticky_channel(&accounts, &sq(1010, ""), "sess-1");
        assert!(s2.sticky_hit, "second selection reuses the sticky account");
        assert_eq!(s2.account.unwrap().id, 1);
        // TTL expiry (1h) forces a fresh pick.
        let s3 = sel.select_sticky_channel(&accounts, &sq(1000 + 3700, ""), "sess-1");
        assert!(!s3.sticky_hit);
        // Sticky account gone cooling: falls back to strategy, not stuck.
        let half_cool = vec![
            AccountView {
                status: STATUS_COOLING.into(),
                cooling_until: 5000,
                ..acct(1, "j", "k")
            },
            acct(2, "j", "k"),
        ];
        let s4 = sel.select_sticky_channel(&half_cool, &sq(2000, CHANNEL_FREE), "sess-1");
        assert_eq!(
            s4.account.unwrap().id,
            2,
            "cooling sticky account loses the slot"
        );
    }

    #[test]
    fn session_key_shapes() {
        assert_eq!(session_key(Some("dev-1"), None), "u:dev-1");
        let k = session_key(None, Some("system prompt"));
        assert!(k.starts_with("s:") && k.len() == 26, "{k}");
        assert_eq!(session_key(None, None), "");
    }
}
