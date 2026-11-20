//! Bounded reset spending with shared manual admission and durable acknowledgement audit.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant as SpendInstant},
};

use futures_util::FutureExt;
use rusqlite::OptionalExtension;
use serde_json::Value;
use tokio::{sync::watch, task::JoinHandle, time::Instant};
use zcode_core::autoreset::{should_spend, slot_expiring_soon, ResetSlot};

use crate::{
    account_billing::{self, Account, Flight},
    state::AppState,
    store,
};

const MAX_PENDING: usize = 256;

pub struct AutoResetConfig {
    pub capacity: usize,
    pub shutdown_wait: Duration,
    pub attempt_interval: Duration,
    pub retry_delay: Duration,
    pub clock: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl Default for AutoResetConfig {
    fn default() -> Self {
        Self {
            capacity: 2,
            shutdown_wait: Duration::from_secs(5),
            attempt_interval: Duration::from_secs(600),
            retry_delay: Duration::from_secs(5),
            clock: Arc::new(crate::auth::now_secs),
        }
    }
}

#[derive(Clone, Copy)]
pub enum ResetTrigger {
    Relay,
    Quota,
    Sweep,
}

pub struct AutoResetShutdownReport {
    pub drained: bool,
    pub abandoned: Vec<i64>,
    pub cancelled: usize,
}

struct Job {
    trigger: ResetTrigger,
    ready: Instant,
    retried: bool,
}

#[derive(Default)]
struct Control {
    stopped: bool,
    pending: BTreeMap<i64, Job>,
    executing: BTreeSet<i64>,
    attempts: BTreeMap<i64, Instant>,
    cancelled: usize,
}

struct Shared {
    state: Arc<AppState>,
    config: AutoResetConfig,
    control: Mutex<Control>,
    changed: watch::Sender<()>,
}

pub struct AutoReset {
    shared: Arc<Shared>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    active: bool,
}

impl AutoReset {
    pub fn new(state: Arc<AppState>) -> Self {
        Self::with_config(state, AutoResetConfig::default())
    }

    pub fn with_config(state: Arc<AppState>, mut config: AutoResetConfig) -> Self {
        config.capacity = config.capacity.clamp(1, 16);
        let (changed, _) = watch::channel(());
        let shared = Arc::new(Shared {
            state,
            config,
            control: Mutex::new(Control::default()),
            changed,
        });
        let runtime = tokio::runtime::Handle::try_current().ok();
        let mut workers = Vec::new();
        if let Some(runtime) = &runtime {
            for _ in 0..shared.config.capacity {
                workers.push(runtime.spawn(work(shared.clone(), shared.changed.subscribe())));
            }
        }
        Self {
            shared,
            workers: Mutex::new(workers),
            active: runtime.is_some(),
        }
    }

    pub fn enqueue(&self, account_id: i64, trigger: ResetTrigger) -> bool {
        if !self.active {
            return false;
        }
        let mut control = self.shared.control.lock().unwrap();
        if control.stopped
            || control.pending.contains_key(&account_id)
            || control.executing.contains(&account_id)
            || control.pending.len() >= MAX_PENDING
            || debounced(&control, account_id, self.shared.config.attempt_interval)
        {
            return false;
        }
        control.pending.insert(
            account_id,
            Job {
                trigger,
                ready: Instant::now(),
                retried: false,
            },
        );
        self.shared.changed.send_replace(());
        true
    }

    pub fn sweep(&self) -> usize {
        let ids: Vec<_> = self
            .shared
            .state
            .accounts
            .lock()
            .unwrap()
            .iter()
            .map(|a| a.id)
            .collect();
        ids.into_iter()
            .filter(|&id| {
                snapshot(&self.shared.state, id, ResetTrigger::Sweep).is_some()
                    && self.enqueue(id, ResetTrigger::Sweep)
            })
            .count()
    }

    pub fn pending(&self) -> Vec<i64> {
        self.shared
            .control
            .lock()
            .unwrap()
            .pending
            .keys()
            .copied()
            .collect()
    }

    pub fn executing(&self) -> Vec<i64> {
        self.shared
            .control
            .lock()
            .unwrap()
            .executing
            .iter()
            .copied()
            .collect()
    }

    pub fn stop(&self) {
        let mut control = self.shared.control.lock().unwrap();
        control.stopped = true;
        control.cancelled += control.pending.len();
        control.pending.clear();
        self.shared.changed.send_replace(());
    }

    pub fn is_stopped(&self) -> bool {
        self.shared.control.lock().unwrap().stopped
    }

    pub async fn wait_idle(&self) {
        loop {
            let (idle, stopped) = {
                let control = self.shared.control.lock().unwrap();
                (
                    control.pending.is_empty() && control.executing.is_empty(),
                    control.stopped,
                )
            };
            let joined = {
                let mut workers = self.workers.lock().unwrap();
                workers.retain_mut(|handle| !join_finished(handle));
                workers.is_empty()
            };
            if idle && (!stopped || joined) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn shutdown(&self) -> AutoResetShutdownReport {
        self.stop();
        let drained = tokio::time::timeout(self.shared.config.shutdown_wait, self.wait_idle())
            .await
            .is_ok();
        let control = self.shared.control.lock().unwrap();
        AutoResetShutdownReport {
            drained,
            abandoned: if drained {
                Vec::new()
            } else {
                control.executing.iter().copied().collect()
            },
            cancelled: control.cancelled,
        }
    }
}

impl Drop for AutoReset {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn recent_spend(state: &AppState, account_id: i64) -> bool {
    state
        .reset_spend_guard
        .spent_within_gap(account_id, SpendInstant::now())
}

fn debounced(control: &Control, id: i64, interval: Duration) -> bool {
    control
        .attempts
        .get(&id)
        .is_some_and(|at| at.elapsed() < interval)
}

struct Snapshot {
    account: Account,
    threshold: bool,
    expiry_window: i64,
    five_wait: i64,
    week_wait: i64,
    next_reset: Option<i64>,
}

fn snapshot(state: &AppState, id: i64, trigger: ResetTrigger) -> Option<Snapshot> {
    let (threshold, expiry_window, five_wait, week_wait, next_reset, expected_jwt, expected_key) = {
        let db = state.db.lock().unwrap();
        let accounts = state.accounts.lock().unwrap();
        let a = accounts.iter().find(|a| a.id == id)?;
        let (enabled, status, jwt, key, quota): (bool, String, String, String, String) = db
            .query_row(
                "SELECT enabled,status,zcode_jwt,api_key,quota_json FROM accounts WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()
            .ok()??;
        if !enabled
            || !a.enabled
            || !matches!(status.as_str(), "active" | "cooling" | "exhausted")
            || status != a.status
            || a.zcode_jwt.is_empty()
            || state.vault.decrypt(&jwt).ok()? != a.zcode_jwt
            || state.vault.decrypt(&key).ok()? != a.api_key
        {
            return None;
        }
        let creds = state.creds.lock().unwrap();
        let creds = creds.get(&id)?;
        if creds.zcode_jwt != a.zcode_jwt || creds.api_key != a.api_key {
            return None;
        }
        let stored = store::load_settings(&db, &state.vault).ok()?;
        let settings = state.settings.lock().unwrap();
        for name in [
            "auto_reset_enabled",
            "auto_reset_expiry_enabled",
            "auto_reset_min_wait_minutes",
            "auto_reset_min_wait_week_hours",
            "auto_reset_expiry_spend_minutes",
        ] {
            if stored.get(name) != settings.get(name) {
                return None;
            }
        }
        let enabled = |name: &str| settings.get(name).is_some_and(|v| v == "1");
        let number = |name: &str, default: i64| {
            settings
                .get(name)
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(default)
                .max(0)
        };
        let threshold = !matches!(trigger, ResetTrigger::Sweep)
            && status == "exhausted"
            && enabled("auto_reset_enabled");
        let expiry_window = if enabled("auto_reset_expiry_enabled") {
            number("auto_reset_expiry_spend_minutes", 60).saturating_mul(60)
        } else {
            0
        };
        if !threshold && expiry_window == 0 {
            return None;
        }
        let next_reset = serde_json::from_str::<Value>(&quota)
            .ok()
            .and_then(|q| q["next_reset"].as_i64())
            .filter(|&n| n > 0);
        (
            threshold,
            expiry_window,
            number("auto_reset_min_wait_minutes", 60).saturating_mul(60),
            number("auto_reset_min_wait_week_hours", 24).saturating_mul(3600),
            next_reset,
            a.zcode_jwt.clone(),
            a.api_key.clone(),
        )
    };
    let account = account_billing::load_account(state, id).ok()?;
    if account.jwt != expected_jwt || account.key != expected_key {
        return None;
    }
    Some(Snapshot {
        account,
        threshold,
        expiry_window,
        five_wait,
        week_wait,
        next_reset,
    })
}

struct Decision {
    kind: &'static str,
    expiry: i64,
}

fn decide(snapshot: &Snapshot, status: &Value, now: i64) -> Option<Decision> {
    let slots = |field: &str| -> Vec<ResetSlot> {
        status[field]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|slot| {
                let expiry = slot["expire_at"].as_i64()?;
                let expiry = if expiry > 100_000_000_000 {
                    expiry / 1000
                } else {
                    expiry
                };
                (expiry > 0 && expiry > now).then_some(ResetSlot { expire_at: expiry })
            })
            .collect()
    };
    let five = slots("available_five_hour_resets");
    let week = slots("available_week_resets");
    let expiry = [("FIVE_HOUR", &five), ("WEEK", &week)]
        .into_iter()
        .filter_map(|(kind, slots)| {
            slot_expiring_soon(now, snapshot.expiry_window, slots)
                .map(|expiry| Decision { kind, expiry })
        })
        .min_by_key(|decision| decision.expiry);
    if expiry.is_some() {
        return expiry;
    }
    if !snapshot.threshold {
        return None;
    }
    let (kind, threshold) = if !five.is_empty() {
        ("FIVE_HOUR", snapshot.five_wait)
    } else if !week.is_empty() {
        ("WEEK", snapshot.week_wait)
    } else {
        return None;
    };
    let wait = snapshot
        .next_reset
        .map(|reset| reset.saturating_sub(now).max(0));
    should_spend(wait.is_some(), wait.unwrap_or(0), threshold)
        .then_some(Decision { kind, expiry: 0 })
}

// Serialize each request's first poll with stop; already-sent requests must finish and audit.
async fn http_step<F: Future>(shared: &Shared, future: F) -> Option<F::Output> {
    tokio::pin!(future);
    let mut first = true;
    std::future::poll_fn(|cx| {
        if first {
            let control = shared.control.lock().unwrap();
            if control.stopped {
                return Poll::Ready(None);
            }
            first = false;
            future.as_mut().poll(cx).map(Some)
        } else {
            future.as_mut().poll(cx).map(Some)
        }
    })
    .await
}

enum Outcome {
    Done,
    QuotaBusy,
}

struct QuotaFlight<'a> {
    state: &'a AppState,
    id: i64,
}

impl Drop for QuotaFlight<'_> {
    fn drop(&mut self) {
        self.state
            .quota_refresh_inflight
            .lock()
            .unwrap()
            .remove(&self.id);
    }
}

async fn attempt(shared: &Shared, id: i64, trigger: ResetTrigger) -> Outcome {
    let state = &shared.state;
    let Some(initial) = snapshot(state, id, trigger) else {
        return Outcome::Done;
    };
    if !state.automation_inflight.lock().unwrap().insert(id) {
        return Outcome::Done;
    }
    let _flight = Flight { state, id };
    if !state.quota_refresh_inflight.lock().unwrap().insert(id) {
        return Outcome::QuotaBusy;
    }
    let quota_flight = QuotaFlight { state, id };
    {
        let mut control = shared.control.lock().unwrap();
        if control.stopped || debounced(&control, id, shared.config.attempt_interval) {
            return Outcome::Done;
        }
        control.attempts.insert(id, Instant::now());
    }
    let Some(Ok(status)) = http_step(shared, async {
        let current = snapshot(state, id, trigger).ok_or(())?;
        if current.account.jwt != initial.account.jwt || current.account.key != initial.account.key
        {
            return Err(());
        }
        account_billing::reset_status(state, &current.account).await
    })
    .await
    else {
        return Outcome::Done;
    };
    let Some((account, decision, result, used_at)) = http_step(shared, async {
        let current = snapshot(state, id, trigger)?;
        if current.account.jwt != initial.account.jwt || current.account.key != initial.account.key
        {
            return None;
        }
        let now = (shared.config.clock)();
        let decision = decide(&current, &status, now)?;
        let cold_recent = match store::recent_reset_spend(&state.db.lock().unwrap(), id, now) {
            Ok(recent) => recent,
            Err(error) => {
                eprintln!("automatic reset ledger guard failed for account {id}: {error}");
                return None;
            }
        };
        let warm = recent_spend(state, id);
        let permitted = if warm {
            decision.expiry > 0
                && state
                    .reset_spend_guard
                    .permits(id, decision.expiry, SpendInstant::now())
        } else {
            !cold_recent
        };
        if !permitted {
            return None;
        }
        let idem = if decision.expiry > 0 {
            format!("auto-expiry-{id}-{}", decision.expiry)
        } else {
            String::new()
        };
        let (result, used_at) = account_billing::use_reset(
            state,
            &current.account,
            decision.kind,
            &idem,
            shared.config.clock.as_ref(),
        )
        .await;
        Some((current.account, decision, result, used_at))
    })
    .await
    .flatten() else {
        return Outcome::Done;
    };
    if result.ok && decision.expiry > 0 {
        state
            .reset_spend_guard
            .stamp(id, SpendInstant::now(), decision.expiry);
    }
    let mut result = result;
    account_billing::auto_reset_plan(&mut result, decision.kind, decision.expiry > 0);
    if let Err(error) =
        account_billing::persist_outcome(state, &account, "reset", &result, used_at, None)
    {
        eprintln!("automatic reset audit failed for account {id}: {error}; remote consumption may already have occurred");
        return Outcome::Done;
    }
    drop(quota_flight);
    if result.ok {
        if let Some(refresh) = state.background_refresh() {
            refresh.refresh_quota_only(id);
        }
    }
    Outcome::Done
}

async fn work(shared: Arc<Shared>, mut changed: watch::Receiver<()>) {
    loop {
        let (job, next) = {
            let mut control = shared.control.lock().unwrap();
            if control.stopped {
                return;
            }
            let next = control
                .pending
                .iter()
                .min_by_key(|(id, job)| (job.ready, **id))
                .map(|(&id, job)| (id, job.ready));
            match next {
                Some((id, ready)) if ready <= Instant::now() => {
                    let job = control.pending.remove(&id).unwrap();
                    control.executing.insert(id);
                    (Some((id, job)), None)
                }
                other => (None, other.map(|(_, ready)| ready)),
            }
        };
        let Some((id, job)) = job else {
            tokio::select! {
                _ = changed.changed() => (),
                _ = async { match next { Some(ready) => tokio::time::sleep_until(ready).await, None => std::future::pending::<()>().await } } => (),
            }
            continue;
        };
        let result = AssertUnwindSafe(attempt(&shared, id, job.trigger))
            .catch_unwind()
            .await;
        let mut control = shared.control.lock().unwrap();
        control.executing.remove(&id);
        match result {
            Ok(Outcome::QuotaBusy)
                if !control.stopped && !job.retried && control.pending.len() < MAX_PENDING =>
            {
                control.pending.insert(
                    id,
                    Job {
                        trigger: job.trigger,
                        ready: Instant::now() + shared.config.retry_delay,
                        retried: true,
                    },
                );
            }
            Err(_) => eprintln!("automatic reset worker panicked for account {id}"),
            _ => (),
        }
        shared.changed.send_replace(());
    }
}

fn join_finished(handle: &mut JoinHandle<()>) -> bool {
    if !handle.is_finished() {
        return false;
    }
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    match std::pin::Pin::new(handle).poll(&mut cx) {
        Poll::Ready(result) => {
            if let Err(error) = result {
                eprintln!("automatic reset worker join failed: {error}");
            }
            true
        }
        Poll::Pending => false,
    }
}
