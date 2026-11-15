//! Port of gateway_keys.go: quota charge, model whitelist, RPM sliding
//! window, and the 168-slot hourly ring (5h/24h/7d rolling windows).
//!
//! Ring contract (reviewer-verified 2026-10-10): counts[i] = hits in the
//! natural hour `anchor - i`; advance is a memmove with clock rollback and
//! full-ring treated as reset (prefer over-admitting to wedging a key);
//! unlock_after walks the oldest side of the window until the count drops
//! below the limit — honest hour-boundary estimate, floor 1s.

use std::collections::HashMap;

/// Billing-口径 charge: input+output full price, cache_creation full,
/// cache_read at 1/10 (Go gatewayKeyQuotaCharge; integer division).
pub fn quota_charge(input: i64, output: i64, cache_read: i64, cache_creation: i64) -> i64 {
    input + output + cache_creation + cache_read / 10
}

/// Comma-separated exact model match; empty whitelist = allow all
/// (Go GatewayKey.modelAllowed; model arrives pre-normalized lowercase).
pub fn model_allowed(models_csv: &str, model: &str) -> bool {
    if models_csv.is_empty() {
        return true;
    }
    models_csv.split(',').any(|m| m.trim() == model)
}

pub const GW_WINDOW_RING_HOURS: usize = 168; // 7 days

#[derive(Debug, Clone)]
pub struct GwHourRing {
    /// Natural hour (unix_secs / 3600) that counts[0] corresponds to.
    pub anchor: i64,
    pub counts: [i64; GW_WINDOW_RING_HOURS],
}

impl Default for GwHourRing {
    fn default() -> Self {
        Self {
            anchor: 0,
            counts: [0; GW_WINDOW_RING_HOURS],
        }
    }
}

impl GwHourRing {
    /// Advance the ring to now_hour. Clock rollback and >full-ring jumps
    /// reset (never under-count, never wedge).
    pub fn advance(&mut self, now_hour: i64) {
        if self.anchor == now_hour {
            return;
        }
        if self.anchor == 0
            || now_hour < self.anchor
            || now_hour - self.anchor >= GW_WINDOW_RING_HOURS as i64
        {
            self.anchor = now_hour;
            self.counts = [0; GW_WINDOW_RING_HOURS];
            return;
        }
        let d = (now_hour - self.anchor) as usize;
        self.counts.copy_within(0..GW_WINDOW_RING_HOURS - d, d);
        for c in self.counts[..d].iter_mut() {
            *c = 0;
        }
        self.anchor = now_hour;
    }

    pub fn sum(&self, hours: usize) -> i64 {
        self.counts
            .iter()
            .take(hours.min(GW_WINDOW_RING_HOURS))
            .sum()
    }

    /// Earliest unlock estimate for a tripped window: walk the oldest side
    /// out of the window until total - removed < limit. Floor 1 second.
    pub fn unlock_after(&self, hours: usize, limit: i64, now_hour: i64, now_unix: i64) -> i64 {
        let hours = hours.min(GW_WINDOW_RING_HOURS);
        let total = self.sum(hours);
        let mut removed = 0i64;
        let mut k = 1usize;
        while k <= hours {
            let idx = hours.checked_sub(k).unwrap_or(usize::MAX);
            if idx != usize::MAX {
                removed += self.counts[idx];
            }
            if total - removed < limit {
                break;
            }
            k += 1;
        }
        if k > hours {
            k = hours;
        }
        let d = (now_hour + k as i64) * 3600 - now_unix;
        d.max(1)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct GwWindowSpec<'a> {
    pub hours: usize,
    pub limit: i64,
    pub label: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GwRejection {
    pub window: String,
    pub retry_after_secs: i64,
}

/// Per-key rolling-window tracker. Hits are counted at admit time (auth
/// moment); rejected requests are NOT recorded (Go admit contract), and
/// once tripped a window freezes until unlock (subsequent admits keep
/// rejecting without recording).
#[derive(Default)]
pub struct GwWindowTracker {
    keys: HashMap<i64, GwHourRing>,
}

impl GwWindowTracker {
    /// Check every window; all clear -> record one hit and return None.
    pub fn admit(&mut self, id: i64, specs: &[GwWindowSpec], now_unix: i64) -> Option<GwRejection> {
        let now_hour = now_unix / 3600;
        // Stale-ring backstop (Go: >=4096 keys with anchor a full ring behind).
        if self.keys.len() >= 4096 {
            self.keys
                .retain(|_, r| now_hour - r.anchor < GW_WINDOW_RING_HOURS as i64);
        }
        let r = self.keys.entry(id).or_default();
        r.advance(now_hour);
        for sp in specs {
            if sp.limit > 0 && r.sum(sp.hours) >= sp.limit {
                return Some(GwRejection {
                    window: sp.label.to_string(),
                    retry_after_secs: r.unlock_after(sp.hours, sp.limit, now_hour, now_unix),
                });
            }
        }
        r.counts[0] += 1;
        None
    }

    /// Drop a key's ring state (Go forget: create->use->delete must not leak).
    pub fn forget(&mut self, id: i64) {
        self.keys.remove(&id);
    }
}

/// Named-key RPM sliding window (60s, per-key timestamp list with a 4096-key
/// prune backstop). Injectable clock for tests.
#[derive(Default)]
pub struct GwRpmTracker {
    hits: HashMap<i64, Vec<i64>>,
    prune_at: i64,
}

pub const GW_RPM_WINDOW_SECS: i64 = 60;

impl GwRpmTracker {
    /// One hit against the sliding window; false = over the limit (the hit
    /// is not recorded, matching Go allow).
    pub fn allow(&mut self, id: i64, limit: i64, now_unix: i64) -> bool {
        // Capacity backstop: prune stale keys when the map balloons.
        if self.hits.len() >= 4096 && now_unix - self.prune_at > GW_RPM_WINDOW_SECS {
            self.hits.retain(|_, ts| {
                ts.last()
                    .is_none_or(|&t| now_unix - t <= GW_RPM_WINDOW_SECS)
            });
            self.prune_at = now_unix;
        }
        let cutoff = now_unix - GW_RPM_WINDOW_SECS;
        let live = self
            .hits
            .entry(id)
            .or_default()
            .iter()
            .copied()
            .filter(|&t| t > cutoff)
            .collect::<Vec<i64>>();
        if live.len() as i64 >= limit {
            self.hits.insert(id, live);
            return false;
        }
        self.hits.insert(id, {
            let mut v = live;
            v.push(now_unix);
            v
        });
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from gateway_window_test.go TestGWWindowRingAdvance.
    #[test]
    fn ring_advance_slide_and_reset() {
        let mut r = GwHourRing::default();
        let now_hour = 2_000_000;
        r.advance(now_hour);
        r.counts[0] = 5;
        assert_eq!(r.sum(5), 5);
        r.advance(now_hour + 1);
        assert_eq!(r.sum(5), 5, "hit slides into history, still in window");
        r.advance(now_hour + 5);
        assert_eq!(r.sum(5), 0, "bucket slid out of the 5h window");
        r.advance(now_hour + 200);
        assert_eq!(r.sum(168), 0, "full-ring jump resets");
        r.counts[0] = 9;
        r.advance(now_hour - 10);
        assert_eq!(r.sum(24), 0, "clock rollback resets");
    }

    // Ported from TestGWWindowUnlockAfter (4 scenarios).
    #[test]
    fn unlock_after_honesty() {
        let now_hour = 2_000_000;
        let now_unix = now_hour * 3600 + 1800; // mid-hour
        let mut r = GwHourRing::default();
        r.advance(now_hour);
        r.counts[0] = 1;
        assert_eq!(
            r.unlock_after(5, 1, now_hour, now_unix),
            (now_hour + 5) * 3600 - now_unix
        );

        let mut r2 = GwHourRing::default();
        r2.advance(now_hour);
        r2.counts[4] = 1;
        assert_eq!(
            r2.unlock_after(5, 1, now_hour, now_unix),
            (now_hour + 1) * 3600 - now_unix
        );

        let mut r3 = GwHourRing::default();
        r3.advance(now_hour);
        r3.counts[4] = 3;
        r3.counts[0] = 3;
        assert_eq!(
            r3.unlock_after(5, 5, now_hour, now_unix),
            (now_hour + 1) * 3600 - now_unix
        );

        assert_eq!(
            r.unlock_after(24, 1, now_hour, now_unix),
            (now_hour + 24) * 3600 - now_unix
        );
    }

    // Ported from TestGWWindowAdmitLimits + TestGWWindowUnlimitedPasses +
    // TestGWWindowIndependentKeys.
    #[test]
    fn admit_windows_and_independence() {
        let mut tr = GwWindowTracker::default();
        let specs = [
            GwWindowSpec {
                hours: 5,
                limit: 3,
                label: "5h",
            },
            GwWindowSpec {
                hours: 24,
                limit: 10,
                label: "24h",
            },
            GwWindowSpec {
                hours: 168,
                limit: 100,
                label: "7d",
            },
        ];
        let now = 1_700_000_000;
        for _ in 0..3 {
            assert_eq!(tr.admit(1, &specs, now), None);
        }
        let rej = tr.admit(1, &specs, now).expect("5h trip");
        assert_eq!(rej.window, "5h");
        assert!(rej.retry_after_secs > 0 && rej.retry_after_secs <= 5 * 3600 + 2);
        for _ in 0..5 {
            let r = tr.admit(1, &specs, now).expect("still tripped");
            assert_eq!(r.window, "5h", "frozen window keeps rejecting");
        }

        let mut tr2 = GwWindowTracker::default();
        let unlimited = [GwWindowSpec {
            hours: 5,
            limit: 0,
            label: "5h",
        }];
        for _ in 0..1000 {
            assert_eq!(tr2.admit(2, &unlimited, now), None);
        }

        let mut tr3 = GwWindowTracker::default();
        let one = [GwWindowSpec {
            hours: 5,
            limit: 1,
            label: "5h",
        }];
        assert_eq!(tr3.admit(10, &one, now), None);
        assert!(tr3.admit(10, &one, now).is_some());
        assert_eq!(tr3.admit(11, &one, now), None, "keys independent");
        tr3.forget(10);
        assert_eq!(tr3.admit(10, &one, now), None, "forget clears the ring");
    }

    #[test]
    fn rpm_sliding_window() {
        let mut t = GwRpmTracker::default();
        assert!(t.allow(1, 2, 1000));
        assert!(t.allow(1, 2, 1030));
        assert!(!t.allow(1, 2, 1050), "third hit inside 60s trips");
        // 60s after the first hit it slides out; second still live.
        assert!(t.allow(1, 2, 1061));
    }

    #[test]
    fn quota_charge_and_whitelist() {
        assert_eq!(quota_charge(100, 50, 1000, 20), 100 + 50 + 20 + 100);
        assert_eq!(quota_charge(0, 0, 0, 0), 0);
        assert!(model_allowed("", "anything"));
        assert!(model_allowed("glm-5.3, glm-5.2", "glm-5.2"));
        assert!(!model_allowed("glm-5.3", "glm-5.2"));
    }
}
