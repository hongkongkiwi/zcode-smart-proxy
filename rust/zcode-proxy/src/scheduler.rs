//! Durable minute admission, account automation, and bounded scheduler shutdown.

use std::{
    collections::BTreeMap,
    future::Future,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Local};
use futures_util::FutureExt;
use rand::Rng;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::{sync::watch, task::JoinHandle};

use crate::{account_billing as billing, cron::Cron, state::AppState, store};

const ABORT_MESSAGE: &str = "服务停机中断，本次未完成全部账号";
const RESET_MESSAGE: &str = "重置仅支持在账号页面手动执行，不支持计划任务";
const CLAIM_BLOCKED_MESSAGE: &str =
    "scheduled claim blocked: upstream pricing is unknown; use the manual account claim action";

pub struct SchedulerConfig {
    pub tick_interval: Duration,
    pub clock: Arc<dyn Fn() -> DateTime<Local> + Send + Sync>,
    pub tick_stop_wait: Duration,
    pub task_drain_wait: Duration,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_secs(60),
            clock: Arc::new(Local::now),
            tick_stop_wait: Duration::from_secs(5),
            task_drain_wait: Duration::from_secs(15),
        }
    }
}

#[derive(Serialize, Clone)]
pub struct PlanRunState {
    pub plan_id: i64,
    pub plan_name: String,
    pub task_type: String,
    pub total: i64,
    pub done: i64,
    pub success: i64,
    pub fail: i64,
    pub current_account: String,
    pub started_at: String,
}

pub struct RunReceipt {
    pub plan_id: i64,
}

#[derive(Debug)]
pub enum RunNowError {
    NotFound(String),
    Busy(String),
    ShuttingDown(String),
    Storage(String),
}

pub struct ShutdownReport {
    pub tick_stopped: bool,
    pub tasks_drained: bool,
    pub abandoned: Vec<i64>,
}

#[derive(Default)]
struct Control {
    stopped: bool,
    started: bool,
    running: BTreeMap<i64, PlanRunState>,
    tasks: Vec<JoinHandle<()>>,
    tick: Option<JoinHandle<()>>,
}

struct Shared {
    state: Arc<AppState>,
    config: SchedulerConfig,
    control: Mutex<Control>,
    cancel: watch::Sender<bool>,
}

#[derive(Clone)]
pub struct Scheduler {
    shared: Arc<Shared>,
}

impl Scheduler {
    pub fn new(state: Arc<AppState>) -> Self {
        Self::with_config(state, SchedulerConfig::default())
    }

    pub fn with_config(state: Arc<AppState>, config: SchedulerConfig) -> Self {
        let (cancel, _) = watch::channel(false);
        Self {
            shared: Arc::new(Shared {
                state,
                config,
                control: Mutex::new(Control::default()),
                cancel,
            }),
        }
    }

    pub fn reconcile_stale_running(&self) -> Result<usize, store::StoreError> {
        let control = self.shared.control.lock().unwrap();
        if !control.running.is_empty() {
            return Err(store::StoreError::Database);
        }
        self.reconcile_locked()
    }

    fn reconcile_locked(&self) -> Result<usize, store::StoreError> {
        let stamp = (self.shared.config.clock)()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        store::reconcile_plan_runs(&mut self.shared.state.db.lock().unwrap(), &stamp)
    }

    pub fn start(&self) -> Result<usize, store::StoreError> {
        let mut control = self.shared.control.lock().unwrap();
        if control.started || control.stopped {
            return Ok(0);
        }
        if !control.running.is_empty() {
            return Err(store::StoreError::Database);
        }
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| store::StoreError::Database)?;
        let reconciled = self.reconcile_locked()?;
        let weak = Arc::downgrade(&self.shared);
        let mut cancel = self.shared.cancel.subscribe();
        let interval = self
            .shared
            .config
            .tick_interval
            .max(Duration::from_nanos(1));
        control.started = true;
        control.tick = Some(runtime.spawn(async move {
            let mut ticks =
                tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.changed() => break,
                    _ = ticks.tick() => {
                        let Some(shared) = weak.upgrade() else { break };
                        let now = (shared.config.clock)();
                        if let Err(error) = (Scheduler { shared }).run_due_at(now).await {
                            eprintln!("scheduler tick failed: {error}");
                        }
                    }
                }
            }
        }));
        Ok(reconciled)
    }

    pub async fn run_due_at(&self, now: DateTime<Local>) -> Result<Vec<i64>, store::StoreError> {
        let plans = store::list_claim_plans(&self.shared.state.db.lock().unwrap())?;
        let mut claimed = Vec::new();
        for plan in plans {
            if plan.is_active && Cron::parse(&plan.cron_expr).is_ok_and(|cron| cron.matches(now)) {
                match self.admit(plan, now, true) {
                    Ok(Some(id)) => claimed.push(id),
                    Ok(None) => (),
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(claimed)
    }

    pub async fn run_plan_now(&self, plan_id: i64) -> Result<RunReceipt, RunNowError> {
        let plan = store::list_claim_plans(&self.shared.state.db.lock().unwrap())
            .map_err(|e| RunNowError::Storage(e.to_string()))?
            .into_iter()
            .find(|p| p.id == plan_id)
            .ok_or_else(|| RunNowError::NotFound("计划不存在".into()))?;
        let now = (self.shared.config.clock)();
        match self
            .admit(plan, now, false)
            .map_err(|e| RunNowError::Storage(e.to_string()))?
        {
            Some(plan_id) => Ok(RunReceipt { plan_id }),
            None if self.is_stopped() => {
                Err(RunNowError::ShuttingDown("服务停机中，无法执行计划".into()))
            }
            None => Err(RunNowError::Busy("计划正在执行中，请稍后再试".into())),
        }
    }

    fn admit(
        &self,
        plan: store::ClaimPlanRow,
        now: DateTime<Local>,
        minute: bool,
    ) -> Result<Option<i64>, store::StoreError> {
        // Admission and shutdown serialize here; only this lock precedes the database lock.
        let mut control = self.shared.control.lock().unwrap();
        reap_tasks(&mut control);
        if control.stopped || control.running.contains_key(&plan.id) {
            return Ok(None);
        }
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| store::StoreError::Database)?;
        let stamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
        {
            let db = self.shared.state.db.lock().unwrap();
            if minute {
                if !store::claim_plan_minute(&db, plan.id, &stamp)? {
                    return Ok(None);
                }
            } else {
                store::update_claim_plan_run(&db, plan.id, "running", "执行中", &stamp)?;
            }
        }
        let id = plan.id;
        control.running.insert(
            id,
            PlanRunState {
                plan_id: id,
                plan_name: plan.plan_name.clone(),
                task_type: plan.task_type.clone(),
                total: 0,
                done: 0,
                success: 0,
                fail: 0,
                current_account: String::new(),
                started_at: now.format("%H:%M:%S").to_string(),
            },
        );
        let weak = Arc::downgrade(&self.shared);
        let state = self.shared.state.clone();
        let cancel = self.shared.cancel.subscribe();
        control.tasks.push(runtime.spawn(async move {
            let started = Instant::now();
            let outcome = AssertUnwindSafe(run_plan(&state, &weak, &plan, cancel))
                .catch_unwind()
                .await;
            let terminal = match outcome {
                Ok(terminal) => terminal,
                Err(_) => Terminal::failed("计划执行异常"),
            };
            let result = store::finish_plan_run(
                &mut state.db.lock().unwrap(),
                &store::PlanRunRow {
                    plan: &plan,
                    run_at: &stamp,
                    status: terminal.status,
                    message: &terminal.message,
                    total: terminal.total,
                    success: terminal.success,
                    fail: terminal.fail,
                    duration_ms: started.elapsed().as_millis().min(i64::MAX as u128) as i64,
                },
            );
            if let Err(error) = result {
                eprintln!("scheduler terminal persistence failed for plan {id}: {error}");
            }
            if let Some(shared) = weak.upgrade() {
                shared.control.lock().unwrap().running.remove(&id);
            }
        }));
        Ok(Some(id))
    }

    pub fn running(&self) -> Vec<PlanRunState> {
        self.shared
            .control
            .lock()
            .unwrap()
            .running
            .values()
            .cloned()
            .collect()
    }

    pub fn is_stopped(&self) -> bool {
        self.shared.control.lock().unwrap().stopped
    }

    pub async fn wait_idle(&self) {
        loop {
            let idle = {
                let mut control = self.shared.control.lock().unwrap();
                reap_tasks(&mut control);
                control.tasks.is_empty()
            };
            if idle {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn shutdown(&self) -> ShutdownReport {
        {
            let mut control = self.shared.control.lock().unwrap();
            control.stopped = true;
            self.shared.cancel.send_replace(true);
        }
        let tick_stopped = tokio::time::timeout(self.shared.config.tick_stop_wait, async {
            loop {
                let stopped = {
                    let mut control = self.shared.control.lock().unwrap();
                    if control.tick.as_mut().is_some_and(join_finished) {
                        control.tick = None;
                    }
                    control.tick.is_none()
                };
                if stopped {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok();
        let tasks_drained =
            tokio::time::timeout(self.shared.config.task_drain_wait, self.wait_idle())
                .await
                .is_ok();
        let abandoned = if tasks_drained {
            Vec::new()
        } else {
            self.shared
                .control
                .lock()
                .unwrap()
                .running
                .keys()
                .copied()
                .collect()
        };
        ShutdownReport {
            tick_stopped,
            tasks_drained,
            abandoned,
        }
    }
}

// Poll only finished handles in their owning slots. Cancellation of a waiter cannot detach them.
fn join_finished(handle: &mut JoinHandle<()>) -> bool {
    if !handle.is_finished() {
        return false;
    }
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    match std::pin::Pin::new(handle).poll(&mut cx) {
        Poll::Ready(result) => {
            if let Err(error) = result {
                eprintln!("scheduler task join failed: {error}");
            }
            true
        }
        Poll::Pending => false,
    }
}

fn reap_tasks(control: &mut Control) {
    control.tasks.retain_mut(|handle| !join_finished(handle));
}

fn progress(weak: &Weak<Shared>, id: i64, update: impl FnOnce(&mut PlanRunState)) {
    if let Some(shared) = weak.upgrade() {
        let mut control = shared.control.lock().unwrap();
        if let Some(run) = control.running.get_mut(&id) {
            update(run);
        }
    }
}

/// Allow only after a verified free indicator is documented in the upstream preview contract.
pub(crate) fn scheduled_claim_allowed(_evidence: Option<&Value>) -> bool {
    false
}

struct Terminal {
    status: &'static str,
    message: String,
    total: i64,
    success: i64,
    fail: i64,
}

impl Terminal {
    fn failed(message: &str) -> Self {
        Self {
            status: "failed",
            message: message.into(),
            total: 0,
            success: 0,
            fail: 0,
        }
    }
}

fn runnable(a: &zcode_core::AccountView) -> bool {
    a.enabled && !matches!(a.status.as_str(), "invalid" | "disabled") && !a.zcode_jwt.is_empty()
}

fn targets(state: &AppState, plan: &store::ClaimPlanRow) -> Result<Vec<billing::Account>, String> {
    let ids = {
        let accounts = state.accounts.lock().unwrap();
        match plan.target_type.as_str() {
            "single_account" => {
                if !accounts
                    .iter()
                    .any(|a| a.id == plan.account_id && runnable(a))
                {
                    return Err("目标账号不可执行（已禁用/无效或缺少 JWT）".into());
                }
                vec![plan.account_id]
            }
            "group" if plan.account_group.trim().is_empty() => {
                return Err("分组目标缺少组名".into())
            }
            "all_accounts" | "group" => accounts
                .iter()
                .filter(|a| runnable(a))
                .filter(|a| {
                    plan.target_type != "group"
                        || a.account_group
                            .split(',')
                            .any(|g| g.trim() == plan.account_group.trim())
                })
                .map(|a| a.id)
                .collect(),
            _ => return Err("invalid target_type".into()),
        }
    };
    ids.into_iter()
        .map(|id| billing::load_account(state, id).map_err(|e| e.1.to_owned()))
        .collect()
}

async fn run_plan(
    state: &AppState,
    weak: &Weak<Shared>,
    plan: &store::ClaimPlanRow,
    mut cancel: watch::Receiver<bool>,
) -> Terminal {
    if plan.task_type == "reset" {
        return Terminal::failed(RESET_MESSAGE);
    }
    let accounts = match targets(state, plan) {
        Ok(accounts) if !accounts.is_empty() => accounts,
        Ok(_) => return Terminal::failed("没有符合条件的账号"),
        Err(message) => return Terminal::failed(&message),
    };
    let mut terminal = Terminal {
        status: "failed",
        message: String::new(),
        total: accounts.len() as i64,
        success: 0,
        fail: 0,
    };
    progress(weak, plan.id, |p| p.total = terminal.total);
    let blocked = plan.task_type == "claim" && !scheduled_claim_allowed(None);
    let mut messages = Vec::new();
    for (index, account) in accounts.iter().enumerate() {
        if *cancel.borrow() {
            terminal.message = ABORT_MESSAGE.into();
            return terminal;
        }
        if index > 0 && plan.delay_seconds > 0 {
            let delay = plan.delay_seconds as u64;
            let jitter = rand::thread_rng().gen_range(0..=delay / 2);
            tokio::select! {
                biased;
                _ = cancel.changed() => { terminal.message = ABORT_MESSAGE.into(); return terminal; }
                _ = tokio::time::sleep(Duration::from_secs(delay.saturating_add(jitter))) => ()
            }
            if *cancel.borrow() {
                terminal.message = ABORT_MESSAGE.into();
                return terminal;
            }
        }
        progress(weak, plan.id, |p| p.current_account = account.email.clone());
        let admitted = state.automation_inflight.lock().unwrap().insert(account.id);
        let result = if admitted {
            let _flight = billing::Flight {
                state,
                id: account.id,
            };
            match plan.task_type.as_str() {
                "detect" => billing::detect_task(state, account).await,
                "activate" => billing::activate_task(state, account).await,
                "claim" if !blocked => {
                    let result = billing::claim_task(state, account).await;
                    persist_local(state, account, "claim", result)
                }
                "claim" => persist_local(
                    state,
                    account,
                    "claim",
                    billing::ResultBody::failure(CLAIM_BLOCKED_MESSAGE),
                ),
                _ => persist_local(
                    state,
                    account,
                    &plan.task_type,
                    billing::ResultBody::failure("invalid task_type"),
                ),
            }
        } else {
            persist_local(
                state,
                account,
                &plan.task_type,
                billing::ResultBody::failure("account billing action already in progress"),
            )
        };
        if result.ok {
            terminal.success += 1;
        } else {
            terminal.fail += 1;
        }
        messages.push(format!("{}: {}", account.email, result.message));
        progress(weak, plan.id, |p| {
            p.done += 1;
            p.success = terminal.success;
            p.fail = terminal.fail;
        });
    }
    terminal.status = if blocked {
        "blocked"
    } else if terminal.success > 0 {
        "success"
    } else {
        "failed"
    };
    terminal.message = format!(
        "{}/{} 成功: {}",
        terminal.success,
        terminal.total,
        messages.join("; ")
    )
    .chars()
    .take(900)
    .collect();
    terminal
}

fn persist_local(
    state: &AppState,
    account: &billing::Account,
    task: &str,
    mut result: billing::ResultBody,
) -> billing::ResultBody {
    if billing::persist_outcome(state, account, task, &result, 0, None).is_err() {
        result.ok = false;
        result
            .message
            .push_str("; local persistence failed; remote outcome may already have taken effect");
    }
    result
}

fn response(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"message": message}))).into_response()
}

pub async fn handle_run(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Ok(id) = id.parse::<i64>() else {
        return response(StatusCode::BAD_REQUEST, "invalid id");
    };
    let plans = store::list_claim_plans(&state.db.lock().unwrap());
    let plan = match plans {
        Ok(plans) => match plans.into_iter().find(|p| p.id == id) {
            Some(plan) => plan,
            None => return response(StatusCode::NOT_FOUND, "计划不存在"),
        },
        Err(_) => return response(StatusCode::INTERNAL_SERVER_ERROR, "计划查询失败"),
    };
    if plan.task_type == "reset" {
        return response(StatusCode::BAD_REQUEST, RESET_MESSAGE);
    }
    let Some(scheduler) = state.scheduler() else {
        return response(StatusCode::SERVICE_UNAVAILABLE, "scheduler unavailable");
    };
    match scheduler.run_plan_now(id).await {
        Ok(_) => Json(json!({"success":true,"message":"计划已开始执行"})).into_response(),
        Err(RunNowError::NotFound(message)) => response(StatusCode::NOT_FOUND, &message),
        Err(RunNowError::Busy(message)) => response(StatusCode::CONFLICT, &message),
        Err(RunNowError::ShuttingDown(message)) => response(StatusCode::BAD_REQUEST, &message),
        Err(RunNowError::Storage(_)) => response(StatusCode::INTERNAL_SERVER_ERROR, "计划查询失败"),
    }
}

pub async fn handle_running(State(state): State<Arc<AppState>>) -> Response {
    let running = state
        .scheduler()
        .map(|scheduler| scheduler.running())
        .unwrap_or_default();
    Json(json!({"running":running})).into_response()
}
