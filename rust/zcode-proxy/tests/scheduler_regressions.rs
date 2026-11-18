//! Independent scheduler regressions authored against the finalized contract
//! in .agents/state/rust-migration/scheduler-design.md BEFORE the scheduler
//! existed. Until src/scheduler.rs lands this suite does not compile: that
//! gap is the honest red baseline, no stubs are added on the test side.
//!
//! Pins: run/running route gates and the weak scheduler slot, stale-running
//! reconcile with durable atomic records, durable minute claims across
//! restarts, real detect runs against a scripted mock, per-plan manual run
//! serialization (Busy/409, Storage/500, ShuttingDown/400), fail-closed
//! blocked scheduled claims with zero remote calls, running progress, bounded
//! shutdown with abandoned joins retained, and Go-parity terminal records.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    Json, Router,
};
use chrono::{DateTime, Local, TimeZone};
use serde_json::{json, Value};
use tokio::sync::Notify;
use tower::ServiceExt;
use zcode_core::{egress::CaptchaSolver, AccountView};
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    scheduler::{RunNowError, Scheduler, SchedulerConfig},
    state::{AppState, AutomationUrls, ManagementUrls, UpstreamUrls},
    store,
    vault::Vault,
};

const SESSION: &str = "PUBLIC-scheduler-session";
const JWT: &str = "PUBLIC-scheduler-jwt";
const KEY: &str = "PUBLIC-scheduler-api-key";
const VERSION: &str = "PUBLIC-scheduler-version";
const MID: &str = "PUBLIC-scheduler-device";
const USER: &str = "PUBLIC-scheduler-user";
const SCENE: &str = "PUBLIC-scheduler-scene";
const PREFIX: &str = "PUBLIC-scheduler-prefix";
const REGION: &str = "PUBLIC-scheduler-region";
const PREVIEW: &str = "/api/v1/zcode-plan/billing/preview";
const CLAIM: &str = "/api/v1/zcode-plan/billing/claim";
const EVENT: &str = "/api/v1/event/report";
const RESET_STATUS: &str = "/api/v1/coding-plan/reset/status";
const RESET_USE: &str = "/api/v1/coding-plan/reset/use";
const ORIGIN: &str = "http://localhost:8080";
const CROSS_ORIGIN: &str = "https://untrusted.example.invalid";
const STALE_STAMP: &str = "2026-11-18 08:00:00";
const ABORT_MESSAGE: &str = "服务停机中断，本次未完成全部账号";
const HOLD_DEADLINE: Duration = Duration::from_secs(5);

// ---- scripted upstream mock (adapted from billing_automation_regressions) ----

struct Seen {
    method: String,
    path: String,
}

struct Step {
    method: &'static str,
    path: &'static str,
    body: Value,
}

/// Entry/release gate: the handler announces arrival and parks until released.
/// notify_one permit semantics make the handshake race-free.
#[derive(Default)]
struct Gate {
    entered: Notify,
    release: Notify,
}

struct Script {
    steps: Mutex<VecDeque<Step>>,
    seen: Mutex<Vec<Seen>>,
    violations: Mutex<Vec<String>>,
    hold_preview: Mutex<Option<Arc<Gate>>>,
}

struct Mock {
    base: String,
    script: Arc<Script>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Mock {
    async fn start() -> Self {
        async fn serve(
            State(script): State<Arc<Script>>,
            request: Request,
        ) -> (StatusCode, Json<Value>) {
            let (parts, body) = request.into_parts();
            let _ = axum::body::to_bytes(body, 1 << 20).await;
            let method = parts.method.to_string();
            let path = parts.uri.path().to_string();
            script.seen.lock().unwrap().push(Seen {
                method: method.clone(),
                path: path.clone(),
            });
            let authorized = parts
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                == Some(format!("Bearer {JWT}").as_str());
            if !authorized {
                script
                    .violations
                    .lock()
                    .unwrap()
                    .push(format!("{} {} missing JWT bearer", method, path));
                return (StatusCode::UNAUTHORIZED, Json(json!({"code":401})));
            }
            if path == PREVIEW {
                // Clone out of the mutex, then drop the guard before awaiting.
                let gate = script.hold_preview.lock().unwrap().clone();
                if let Some(gate) = gate {
                    gate.entered.notify_one();
                    gate.release.notified().await;
                }
            }
            let step = script.steps.lock().unwrap().pop_front();
            let Some(step) = step else {
                script
                    .violations
                    .lock()
                    .unwrap()
                    .push(format!("unexpected {} {}", method, path));
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code":500})));
            };
            if method != step.method || path != step.path {
                script.violations.lock().unwrap().push(format!(
                    "expected {} {}, got {} {}",
                    step.method, step.path, method, path
                ));
                return (StatusCode::BAD_REQUEST, Json(json!({"code":3001})));
            }
            (StatusCode::OK, Json(step.body))
        }
        let script = Arc::new(Script {
            steps: Mutex::new(VecDeque::new()),
            seen: Mutex::new(Vec::new()),
            violations: Mutex::new(Vec::new()),
            hold_preview: Mutex::new(None),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(serve).with_state(script.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base, script, task }
    }

    fn push(&self, method: &'static str, path: &'static str, body: Value) {
        self.script
            .steps
            .lock()
            .unwrap()
            .push_back(Step { method, path, body });
    }

    fn hold(&self, gate: Arc<Gate>) {
        *self.script.hold_preview.lock().unwrap() = Some(gate);
    }

    /// (method, path) of every upstream request, in arrival order.
    fn seen_requests(&self) -> Vec<(String, String)> {
        self.script
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|s| (s.method.clone(), s.path.clone()))
            .collect()
    }

    fn assert_complete(&self) {
        let violations = self.script.violations.lock().unwrap();
        assert!(
            violations.is_empty(),
            "mock contract violations: {violations:?}"
        );
        assert!(
            self.script.steps.lock().unwrap().is_empty(),
            "unconsumed upstream responses"
        );
    }
}

#[derive(Default)]
struct CountingSolver {
    seen: Mutex<Vec<(String, String)>>,
}

impl CountingSolver {
    fn calls(&self) -> Vec<(String, String)> {
        self.seen.lock().unwrap().clone()
    }
}

impl CaptchaSolver for CountingSolver {
    fn solve(&self, scene: &str, prefix: &str) -> Option<String> {
        self.seen
            .lock()
            .unwrap()
            .push((scene.into(), prefix.into()));
        None
    }
}

// ---- fixture ----

struct Seed {
    email: &'static str,
    jwt: &'static str,
    enabled: bool,
    status: &'static str,
    group: &'static str,
}

impl Seed {
    fn active(email: &'static str) -> Self {
        Self {
            email,
            jwt: JWT,
            enabled: true,
            status: "active",
            group: "",
        }
    }
}

/// Accounts must be seeded before AppState construction: the in-memory
/// account mirror is loaded once from the database.
fn fixture(
    mock: &Mock,
    solver: Option<Arc<CountingSolver>>,
    seeds: &[Seed],
) -> (Arc<AppState>, Vec<i64>) {
    let db = store::open(":memory:");
    let vault = Vault::from_secret("PUBLIC scheduler fixture vault seed").unwrap();
    let mut ids = Vec::new();
    for seed in seeds {
        let id = store::insert_account_encrypted(
            &db,
            &vault,
            &AccountView {
                email: seed.email.into(),
                enabled: seed.enabled,
                status: seed.status.into(),
                account_group: seed.group.into(),
                ..Default::default()
            },
            seed.jwt,
            KEY,
        )
        .unwrap();
        let info = vault.encrypt(&json!({"id":USER}).to_string()).unwrap();
        db.execute(
            "UPDATE accounts SET user_info=?1,device_mid=?2 WHERE id=?3",
            rusqlite::params![info, MID, id],
        )
        .unwrap();
        ids.push(id);
    }
    let mut state = AppState::try_from_db_with_vault(
        String::new(),
        UpstreamUrls {
            zai: format!("{}/forbidden-free-relay", mock.base),
            zai_fallback: format!("{}/forbidden-paid-relay", mock.base),
        },
        db,
        vault,
    )
    .unwrap();
    state.management = ManagementUrls {
        billing_base: format!("{}/api/v1/zcode-plan", mock.base),
        quota_limit: format!("{}/forbidden-monitor", mock.base),
        subscription: format!("{}/forbidden-subscription", mock.base),
        oauth_token: format!("{}/forbidden-oauth", mock.base),
        app_version: VERSION.into(),
    };
    state.automation = AutomationUrls {
        billing_preview: format!("{}{PREVIEW}", mock.base),
        billing_claim: format!("{}{CLAIM}", mock.base),
        event_report: format!("{}{EVENT}", mock.base),
        reset_status: format!("{}{RESET_STATUS}", mock.base),
        reset_use: format!("{}{RESET_USE}", mock.base),
        captcha_scene: SCENE.into(),
        captcha_prefix: PREFIX.into(),
        captcha_region: REGION.into(),
    };
    if let Some(solver) = solver {
        state.automation_solver = solver;
    }
    state
        .sessions
        .lock()
        .unwrap()
        .insert(SESSION.into(), now_secs() + 3600);
    (Arc::new(state), ids)
}

fn plan_body(name: &str) -> Value {
    json!({
        "plan_name": name,
        "cron_expr": "* * * * *",
        "is_active": true,
        "task_type": "detect",
        "target_type": "all_accounts",
        "account_id": 0,
        "account_group": "",
        "auto_pick": true,
        "delay_seconds": 0,
    })
}

fn preview() -> Value {
    json!({"code":0,"data":{"plans":[
        {"plan_id":"offer","name":"PUBLIC scheduler offer","priority":7}
    ]}})
}

async fn call(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<&str>,
    authenticated: bool,
    origin: &str,
) -> (StatusCode, Value) {
    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "localhost:8080")
        .header("origin", origin);
    if authenticated {
        builder = builder.header("cookie", format!("{SESSION_COOKIE}={SESSION}"));
    }
    let request = match body {
        Some(payload) => builder
            .header("content-type", "application/json")
            .body(Body::from(payload.to_owned()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = build_router(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn authed(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<&str>,
) -> (StatusCode, Value) {
    call(state, method, uri, body, true, ORIGIN).await
}

async fn create_plan(state: &Arc<AppState>, body: &Value) -> i64 {
    let (status, response) = authed(state, "POST", "/api/plans", Some(&body.to_string())).await;
    assert_eq!(status, StatusCode::OK, "POST /api/plans: {response}");
    response["id"]
        .as_i64()
        .unwrap_or_else(|| panic!("POST /api/plans must return an id: {response}"))
}

// ---- scheduler configuration ----

fn fixed() -> DateTime<Local> {
    Local.with_ymd_and_hms(2026, 11, 19, 9, 0, 0).unwrap()
}

fn config(task_drain_wait: Duration) -> SchedulerConfig {
    let stamp = fixed();
    SchedulerConfig {
        tick_interval: Duration::from_secs(3600),
        clock: Arc::new(move || stamp),
        tick_stop_wait: Duration::from_secs(2),
        task_drain_wait,
    }
}

/// A clock the test can step forward so successive manual runs land in fresh
/// minutes (minute-claim semantics for manual runs are out of contract).
fn stepping_config(
    start: DateTime<Local>,
    task_drain_wait: Duration,
) -> (Arc<Mutex<DateTime<Local>>>, SchedulerConfig) {
    let cell = Arc::new(Mutex::new(start));
    let reader = cell.clone();
    let config = SchedulerConfig {
        tick_interval: Duration::from_secs(3600),
        clock: Arc::new(move || *reader.lock().unwrap()),
        tick_stop_wait: Duration::from_secs(2),
        task_drain_wait,
    };
    (cell, config)
}

// ---- database readers ----

fn plan_row(state: &AppState, id: i64) -> (String, String, String) {
    state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT last_run_at,last_run_status,last_run_msg FROM claim_plans WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap_or_else(|e| panic!("plan row {id}: {e}"))
}

struct RunRow {
    plan_name: String,
    task_type: String,
    target_type: String,
    run_at: String,
    status: String,
    message: String,
    total: i64,
    success: i64,
    fail: i64,
}

fn run_records(state: &AppState, plan_id: i64) -> Vec<RunRow> {
    let db = state.db.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT plan_name,task_type,target_type,run_at,status,message,total,
                success_count,fail_count FROM plan_run_records WHERE plan_id=?1 ORDER BY id",
        )
        .unwrap();
    let rows = stmt
        .query_map([plan_id], |r| {
            Ok(RunRow {
                plan_name: r.get(0)?,
                task_type: r.get(1)?,
                target_type: r.get(2)?,
                run_at: r.get(3)?,
                status: r.get(4)?,
                message: r.get(5)?,
                total: r.get(6)?,
                success: r.get(7)?,
                fail: r.get(8)?,
            })
        })
        .unwrap();
    rows.collect::<Result<Vec<_>, _>>().unwrap()
}

/// (task_type, success, code, message) for one account's ledger rows.
fn claim_rows(state: &AppState, account_id: i64) -> Vec<(String, bool, i64, String)> {
    let db = state.db.lock().unwrap();
    let mut stmt = db
        .prepare("SELECT task_type,success,code,message FROM claim_records WHERE account_id=?1 ORDER BY id")
        .unwrap();
    let rows = stmt
        .query_map([account_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, bool>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .unwrap();
    rows.collect::<Result<Vec<_>, _>>().unwrap()
}

fn set_running_row(state: &AppState, id: i64, stamp: &str) {
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE claim_plans SET last_run_at=?1,last_run_status='running',
                last_run_msg='执行中' WHERE id=?2",
            rusqlite::params![stamp, id],
        )
        .unwrap();
}

/// The save route rejects reset plans, so the run route's reset refusal is
/// probed on a directly seeded row (defense in depth).
fn seed_reset_plan(state: &AppState) -> i64 {
    let db = state.db.lock().unwrap();
    db.execute(
        "INSERT INTO claim_plans(plan_name,cron_expr,is_active,target_type,account_id,
            account_group,task_type,auto_pick,delay_seconds)
         VALUES('reset-gate','* * * * *',1,'all_accounts',0,'','reset',1,0)",
        [],
    )
    .unwrap();
    db.last_insert_rowid()
}

fn install_trigger(state: &AppState, sql: &str) {
    state.db.lock().unwrap().execute_batch(sql).unwrap();
}

fn drop_trigger(state: &AppState, name: &str) {
    state
        .db
        .lock()
        .unwrap()
        .execute_batch(&format!("DROP TRIGGER IF EXISTS {name};"))
        .unwrap();
}

fn is_clock(stamp: &str) -> bool {
    let bytes = stamp.as_bytes();
    bytes.len() == 8
        && bytes[2] == b':'
        && bytes[5] == b':'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, &c)| matches!(i, 2 | 5) || c.is_ascii_digit())
}

// ---- regressions ----

#[tokio::test]
async fn run_route_and_running_route_gates() {
    let mock = Mock::start().await;
    let (state, _) = fixture(&mock, None, &[]);

    let (status, body) = call(&state, "POST", "/api/plans/1/run", None, false, ORIGIN).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "session gate first: {body}"
    );
    let (status, _) = call(&state, "POST", "/api/plans/1/run", None, true, CROSS_ORIGIN).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "cross-origin write refused");

    let (status, body) = authed(&state, "POST", "/api/plans/not-an-id/run", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["message"], "invalid id");
    let (status, body) = authed(&state, "POST", "/api/plans/999999/run", None).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "plan lookup precedes all: {body}"
    );
    assert_eq!(body["message"], "计划不存在");

    let claim_id = create_plan(&state, &plan_body("gate-claim")).await;
    let reset_id = seed_reset_plan(&state);
    let (status, body) = authed(&state, "POST", &format!("/api/plans/{reset_id}/run"), None).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "reset refusal first: {body}"
    );
    assert_eq!(
        body["message"],
        "重置仅支持在账号页面手动执行，不支持计划任务"
    );
    let (status, body) = authed(&state, "POST", &format!("/api/plans/{claim_id}/run"), None).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "no installed scheduler: {body}"
    );
    assert_eq!(body["message"], "scheduler unavailable");

    let (status, _) = call(&state, "GET", "/api/plans/running", None, false, ORIGIN).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = call(
        &state,
        "GET",
        "/api/plans/running",
        None,
        true,
        CROSS_ORIGIN,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "reads are origin-exempt");
    assert_eq!(body["running"], json!([]), "no scheduler lists []");

    // Weak slot semantics: one live scheduler, no replacement while live,
    // degradation after the scheduler dies, then the dead Weak is replaceable.
    assert!(state.scheduler().is_none());
    let first = Arc::new(Scheduler::with_config(
        state.clone(),
        config(Duration::from_secs(10)),
    ));
    state.set_scheduler(first.clone()).unwrap();
    assert!(
        state
            .set_scheduler(Arc::new(Scheduler::with_config(
                state.clone(),
                config(Duration::from_secs(10))
            )))
            .is_err(),
        "a live scheduler must not be replaced"
    );
    let (status, body) = authed(&state, "GET", "/api/plans/running", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["running"], json!([]), "idle scheduler lists []");

    drop(first);
    let (status, body) = authed(&state, "POST", &format!("/api/plans/{claim_id}/run"), None).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "dead Weak degrades, never wedges: {body}"
    );
    let second = Arc::new(Scheduler::with_config(
        state.clone(),
        config(Duration::from_secs(10)),
    ));
    state.set_scheduler(second.clone()).unwrap();
    assert!(Arc::ptr_eq(
        &state.scheduler().expect("replacement installed"),
        &second
    ));
    mock.assert_complete();
}

#[tokio::test]
async fn stale_running_reconciled_durable() {
    let mock = Mock::start().await;
    let (state, _) = fixture(&mock, None, &[]);
    let id = create_plan(&state, &plan_body("stale-plan")).await;
    set_running_row(&state, id, STALE_STAMP);
    let scheduler = Scheduler::with_config(state.clone(), config(Duration::from_secs(10)));

    let reconciled = scheduler.reconcile_stale_running().unwrap();
    assert_eq!(reconciled, 1);
    assert_eq!(
        plan_row(&state, id),
        (
            STALE_STAMP.to_owned(),
            "failed".to_owned(),
            "进程重启中断".to_owned()
        ),
        "row flips and preserves the stale trigger stamp"
    );
    let records = run_records(&state, id);
    assert_eq!(records.len(), 1, "reconcile writes a durable run record");
    assert_eq!(records[0].status, "failed");
    assert_eq!(records[0].message, "进程重启中断");
    assert_eq!(records[0].run_at, STALE_STAMP, "preserved trigger stamp");
    assert_eq!(
        (records[0].total, records[0].success, records[0].fail),
        (0, 0, 0)
    );

    // Idempotent: nothing stale remains.
    assert_eq!(scheduler.reconcile_stale_running().unwrap(), 0);
    assert_eq!(run_records(&state, id).len(), 1);

    // A failing record insert rolls the whole batch back: Err, the row stays
    // running, and no fabricated records appear.
    install_trigger(
        &state,
        "CREATE TRIGGER sched_regr_fail_run_insert BEFORE INSERT ON plan_run_records
         BEGIN SELECT RAISE(ABORT, 'regression seeded run-record insert failure'); END;",
    );
    set_running_row(&state, id, "2026-11-18 08:05:00");
    let result = scheduler.reconcile_stale_running();
    assert!(result.is_err(), "DB failure must be Err, not fake records");
    assert_eq!(
        plan_row(&state, id),
        (
            "2026-11-18 08:05:00".to_owned(),
            "running".to_owned(),
            "执行中".to_owned()
        ),
        "failed reconcile rolls the batch back"
    );
    assert_eq!(
        run_records(&state, id).len(),
        1,
        "no partial plan_run_records rows"
    );
    drop_trigger(&state, "sched_regr_fail_run_insert");
}

#[tokio::test]
async fn run_due_at_claims_minute_durably_before_work() {
    let mock = Mock::start().await;
    let (state, _) = fixture(
        &mock,
        None,
        &[Seed::active("durable-claim@example.invalid")],
    );
    let id = create_plan(&state, &plan_body("durable-minute")).await;
    let scheduler = Scheduler::with_config(state.clone(), config(Duration::from_secs(10)));
    let t0 = fixed();
    let gate = Arc::new(Gate::default());
    mock.hold(gate.clone());
    mock.push("GET", PREVIEW, preview());

    let claimed = scheduler.run_due_at(t0).await.unwrap();
    assert_eq!(claimed, vec![id]);
    tokio::time::timeout(HOLD_DEADLINE, gate.entered.notified())
        .await
        .expect("plan task reached the held remote call");

    // While the detect is parked upstream, the durable claim is already
    // visible: trigger minute plus running status, before any completion.
    assert_eq!(
        plan_row(&state, id),
        (
            "2026-11-19 09:00:00".to_owned(),
            "running".to_owned(),
            "执行中".to_owned()
        )
    );

    // Same minute: no reclaim, even with the first run still in flight.
    let again = scheduler
        .run_due_at(t0 + chrono::Duration::seconds(30))
        .await
        .unwrap();
    assert!(again.is_empty(), "minute already claimed: {again:?}");

    gate.release.notify_one();
    scheduler.wait_idle().await;
    assert_eq!(plan_row(&state, id).1, "success");
    assert_eq!(run_records(&state, id).len(), 1);
    mock.assert_complete();

    // Restart on the same persisted state: the claimed minute must not
    // repeat; the next minute reclaims.
    let restarted = Scheduler::with_config(state.clone(), config(Duration::from_secs(10)));
    let repeat = restarted
        .run_due_at(t0 + chrono::Duration::seconds(45))
        .await
        .unwrap();
    assert!(
        repeat.is_empty(),
        "restart reran a claimed minute: {repeat:?}"
    );
    mock.push("GET", PREVIEW, preview());
    let next = restarted
        .run_due_at(t0 + chrono::Duration::minutes(1))
        .await
        .unwrap();
    assert_eq!(next, vec![id]);
    // The hold is persistent: handshake the reclaimed run's request before
    // letting it finish, proving the rerun really reached upstream.
    tokio::time::timeout(HOLD_DEADLINE, gate.entered.notified())
        .await
        .expect("reclaimed run reached the held remote call");
    gate.release.notify_one();
    restarted.wait_idle().await;
    let row = plan_row(&state, id);
    assert_eq!(
        row.0, "2026-11-19 09:01:00",
        "next minute claims a fresh stamp"
    );
    assert_eq!(row.1, "success");
    assert_eq!(run_records(&state, id).len(), 2);
    mock.assert_complete();
}

#[tokio::test]
async fn due_plan_spawns_and_records_terminal() {
    let mock = Mock::start().await;
    let (state, ids) = fixture(&mock, None, &[Seed::active("terminal@example.invalid")]);
    let account = ids[0];
    let id = create_plan(&state, &plan_body("detect-terminal")).await;
    mock.push("GET", PREVIEW, preview());
    let scheduler = Scheduler::with_config(state.clone(), config(Duration::from_secs(10)));

    let claimed = scheduler.run_due_at(fixed()).await.unwrap();
    assert_eq!(claimed, vec![id]);
    scheduler.wait_idle().await;

    let row = plan_row(&state, id);
    assert_eq!(
        row.0, "2026-11-19 09:00:00",
        "terminal keeps the trigger stamp"
    );
    assert_eq!(row.1, "success");
    assert!(
        row.2.starts_with("1/1 成功: "),
        "Go summary prefix: {}",
        row.2
    );

    let records = run_records(&state, id);
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.plan_name, "detect-terminal");
    assert_eq!(record.task_type, "detect");
    assert_eq!(record.target_type, "all_accounts");
    assert_eq!(record.run_at, "2026-11-19 09:00:00");
    assert_eq!(record.status, "success");
    assert!(record.message.starts_with("1/1 成功: "));
    assert_eq!((record.total, record.success, record.fail), (1, 1, 0));

    let ledger = claim_rows(&state, account);
    assert_eq!(ledger.len(), 1, "detect persists one per-account record");
    assert_eq!(ledger[0].0, "detect");
    assert!(ledger[0].1, "detect persists a success row");
    assert_eq!(ledger[0].2, 0);

    assert_eq!(
        mock.seen_requests(),
        vec![("GET".to_owned(), PREVIEW.to_owned())],
        "detect makes exactly one preview call per account"
    );
    assert!(
        scheduler.running().is_empty(),
        "no running entry after idle"
    );
    mock.assert_complete();
}

#[tokio::test]
async fn manual_run_serializes_per_plan() {
    let mock = Mock::start().await;
    let (state, _) = fixture(&mock, None, &[Seed::active("manual@example.invalid")]);
    let id = create_plan(&state, &plan_body("manual-serialize")).await;
    let (clock, config) = stepping_config(fixed(), Duration::from_secs(10));
    let scheduler = Arc::new(Scheduler::with_config(state.clone(), config));
    state.set_scheduler(scheduler.clone()).unwrap();
    assert!(!scheduler.is_stopped());

    assert!(matches!(
        scheduler.run_plan_now(999_999).await,
        Err(RunNowError::NotFound(_))
    ));
    let (status, body) = authed(&state, "POST", "/api/plans/not-an-id/run", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["message"], "invalid id");
    let (status, body) = authed(&state, "POST", "/api/plans/999999/run", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["message"], "计划不存在");

    // A held run keeps the per-plan claim: Busy, never queueing.
    let gate = Arc::new(Gate::default());
    mock.hold(gate.clone());
    mock.push("GET", PREVIEW, preview());
    let receipt = scheduler
        .run_plan_now(id)
        .await
        .expect("manual run must start");
    assert_eq!(receipt.plan_id, id);
    tokio::time::timeout(HOLD_DEADLINE, gate.entered.notified())
        .await
        .expect("manual run reached the held remote call");
    assert_eq!(scheduler.running().len(), 1);
    assert!(matches!(
        scheduler.run_plan_now(id).await,
        Err(RunNowError::Busy(_))
    ));
    let (status, body) = authed(&state, "POST", &format!("/api/plans/{id}/run"), None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["message"], "计划正在执行中，请稍后再试");

    gate.release.notify_one();
    scheduler.wait_idle().await;
    assert_eq!(plan_row(&state, id).1, "success");

    // Storage failure surfaces as Storage/500, never a fabricated run.
    *clock.lock().unwrap() = fixed() + chrono::Duration::minutes(1);
    install_trigger(
        &state,
        "CREATE TRIGGER sched_regr_fail_plan_update BEFORE UPDATE ON claim_plans
         BEGIN SELECT RAISE(ABORT, 'regression seeded plan update failure'); END;",
    );
    assert!(matches!(
        scheduler.run_plan_now(id).await,
        Err(RunNowError::Storage(_))
    ));
    let (status, body) = authed(&state, "POST", &format!("/api/plans/{id}/run"), None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["message"], "计划查询失败");
    drop_trigger(&state, "sched_regr_fail_plan_update");

    // Free again: the route starts the plan and reports Go's receipt body.
    *clock.lock().unwrap() = fixed() + chrono::Duration::minutes(2);
    mock.push("GET", PREVIEW, preview());
    let (status, body) = authed(&state, "POST", &format!("/api/plans/{id}/run"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["success"], true);
    assert_eq!(body["message"], "计划已开始执行");
    // The hold is persistent: handshake the freed run's request before
    // letting it finish, proving the rerun really reached upstream.
    tokio::time::timeout(HOLD_DEADLINE, gate.entered.notified())
        .await
        .expect("free manual run reached the held remote call");
    gate.release.notify_one();
    scheduler.wait_idle().await;
    assert_eq!(plan_row(&state, id).1, "success");

    // After shutdown, manual runs are refused everywhere.
    scheduler.shutdown().await;
    assert!(scheduler.is_stopped());
    assert!(matches!(
        scheduler.run_plan_now(id).await,
        Err(RunNowError::ShuttingDown(_))
    ));
    let (status, body) = authed(&state, "POST", &format!("/api/plans/{id}/run"), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["message"], "服务停机中，无法执行计划");
    mock.assert_complete();
}

#[tokio::test]
async fn scheduled_claim_blocked_fail_closed_no_remote() {
    let mock = Mock::start().await;
    let solver = Arc::new(CountingSolver::default());
    let (state, ids) = fixture(
        &mock,
        Some(solver.clone()),
        &[
            Seed::active("blocked-one@example.invalid"),
            Seed::active("blocked-two@example.invalid"),
        ],
    );
    let mut body = plan_body("blocked-claim");
    body["task_type"] = json!("claim");
    let id = create_plan(&state, &body).await;
    let scheduler = Scheduler::with_config(state.clone(), config(Duration::from_secs(10)));

    let claimed = scheduler.run_due_at(fixed()).await.unwrap();
    assert_eq!(claimed, vec![id]);
    scheduler.wait_idle().await;

    assert!(
        mock.seen_requests().is_empty(),
        "scheduled claim must make zero upstream calls"
    );
    mock.assert_complete();
    assert!(
        solver.calls().is_empty(),
        "no CAPTCHA solving without a remote claim"
    );

    for account in &ids {
        let ledger = claim_rows(&state, *account);
        assert_eq!(ledger.len(), 1, "one blocked row per target account");
        assert_eq!(ledger[0].0, "claim");
        assert!(!ledger[0].1, "blocked claim is a failure row");
        assert_eq!(ledger[0].2, -1);
        assert!(
            !ledger[0].3.is_empty(),
            "the blocked reason must be recorded"
        );
    }

    let row = plan_row(&state, id);
    assert_eq!(row.0, "2026-11-19 09:00:00");
    assert_eq!(row.1, "blocked", "blocked is distinct from failed");
    let records = run_records(&state, id);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].status, "blocked");
    assert_eq!(records[0].run_at, "2026-11-19 09:00:00");
}

#[tokio::test]
async fn running_progress_and_shutdown_bounds() {
    let mock = Mock::start().await;
    let (state, _) = fixture(
        &mock,
        None,
        &[
            Seed::active("progress-one@example.invalid"),
            Seed::active("progress-two@example.invalid"),
        ],
    );
    let id = create_plan(&state, &plan_body("progress-plan")).await;
    let scheduler = Arc::new(Scheduler::with_config(
        state.clone(),
        config(Duration::from_secs(10)),
    ));
    state.set_scheduler(scheduler.clone()).unwrap();
    assert_eq!(
        scheduler.start().unwrap(),
        0,
        "reconcile-first finds nothing stale"
    );

    let gate = Arc::new(Gate::default());
    mock.hold(gate.clone());
    mock.push("GET", PREVIEW, preview());
    mock.push("GET", PREVIEW, preview());

    let claimed = scheduler.run_due_at(fixed()).await.unwrap();
    assert_eq!(claimed, vec![id]);

    tokio::time::timeout(HOLD_DEADLINE, gate.entered.notified())
        .await
        .expect("first account reached the held remote call");
    let running = scheduler.running();
    assert_eq!(running.len(), 1, "exactly one running entry");
    let first = &running[0];
    assert_eq!(first.plan_id, id);
    assert_eq!(first.plan_name, "progress-plan");
    assert_eq!(first.task_type, "detect");
    assert_eq!(first.total, 2);
    assert_eq!(first.done, 0);
    assert_eq!(first.success, 0);
    assert_eq!(first.fail, 0);
    assert_eq!(first.current_account, "progress-one@example.invalid");
    assert!(is_clock(&first.started_at), "HH:MM:SS stamp");

    gate.release.notify_one();
    tokio::time::timeout(HOLD_DEADLINE, gate.entered.notified())
        .await
        .expect("second account reached the held remote call");
    let running = scheduler.running();
    assert_eq!(running.len(), 1);
    let second = &running[0];
    assert_eq!(second.done, 1);
    assert_eq!(second.success, 1);
    assert_eq!(second.fail, 0);
    assert_eq!(second.current_account, "progress-two@example.invalid");

    gate.release.notify_one();
    scheduler.wait_idle().await;
    assert!(scheduler.running().is_empty());
    let records = run_records(&state, id);
    assert_eq!(records.len(), 1);
    assert_eq!(
        (records[0].total, records[0].success, records[0].fail),
        (2, 2, 0)
    );

    // Everything idle: bounded shutdown drains fully.
    let report = scheduler.shutdown().await;
    assert!(report.tick_stopped);
    assert!(report.tasks_drained);
    assert!(report.abandoned.is_empty());
    assert!(scheduler.is_stopped());
    mock.assert_complete();
}

#[tokio::test]
async fn shutdown_abandons_never_responding_task_but_retains_join_until_idle() {
    let mock = Mock::start().await;
    let (state, _) = fixture(&mock, None, &[Seed::active("abandoned@example.invalid")]);
    let id = create_plan(&state, &plan_body("abandoned-plan")).await;
    let scheduler = Scheduler::with_config(state.clone(), config(Duration::from_millis(300)));
    let gate = Arc::new(Gate::default());
    mock.hold(gate.clone());
    mock.push("GET", PREVIEW, preview());

    let claimed = scheduler.run_due_at(fixed()).await.unwrap();
    assert_eq!(claimed, vec![id]);
    tokio::time::timeout(HOLD_DEADLINE, gate.entered.notified())
        .await
        .expect("task parked on the never-responding upstream");

    let report = tokio::time::timeout(Duration::from_secs(10), scheduler.shutdown())
        .await
        .expect("shutdown is bounded even with a stuck task");
    assert!(report.tick_stopped);
    assert!(
        !report.tasks_drained,
        "a stuck task is never reported drained"
    );
    assert_eq!(report.abandoned, vec![id]);
    assert!(scheduler.is_stopped());
    assert_eq!(
        plan_row(&state, id).1,
        "running",
        "no terminal while the remote call is stuck"
    );

    // Join ownership is retained: release the upstream, the abandoned task
    // writes its own terminal, then wait_idle joins it.
    gate.release.notify_one();
    tokio::time::timeout(Duration::from_secs(10), scheduler.wait_idle())
        .await
        .expect("retained join completes after the upstream releases");
    assert_eq!(
        plan_row(&state, id).1,
        "success",
        "abandoned task writes its own terminal"
    );
    assert_eq!(run_records(&state, id).len(), 1);
    mock.assert_complete();
}

#[tokio::test]
async fn shutdown_interrupts_between_account_delay_leaving_aborted_terminal_record() {
    let mock = Mock::start().await;
    let (state, _) = fixture(
        &mock,
        None,
        &[
            Seed::active("delay-one@example.invalid"),
            Seed::active("delay-two@example.invalid"),
        ],
    );
    let mut body = plan_body("delay-plan");
    body["delay_seconds"] = json!(30);
    let id = create_plan(&state, &body).await;
    let scheduler = Scheduler::with_config(state.clone(), config(Duration::from_secs(2)));
    mock.push("GET", PREVIEW, preview());

    let claimed = scheduler.run_due_at(fixed()).await.unwrap();
    assert_eq!(claimed, vec![id]);

    // Account one runs immediately; account two waits out the anti-risk delay.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let done = scheduler
            .running()
            .iter()
            .any(|st| st.plan_id == id && st.done == 1 && st.success == 1);
        if done {
            break;
        }
        assert!(Instant::now() < deadline, "first account never completed");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Shutdown during the inter-account sleep: the loop wakes on the signal,
    // writes the aborted terminal, and exits inside the drain bound.
    let report = tokio::time::timeout(Duration::from_secs(10), scheduler.shutdown())
        .await
        .expect("shutdown is bounded");
    assert!(report.tick_stopped);
    assert!(
        report.tasks_drained,
        "an interrupted sleeper must finish inside the drain wait"
    );
    assert!(report.abandoned.is_empty());

    let row = plan_row(&state, id);
    assert_eq!(
        row.0, "2026-11-19 09:00:00",
        "abort keeps the trigger stamp"
    );
    assert_eq!(row.1, "failed");
    assert_eq!(row.2, ABORT_MESSAGE);
    let records = run_records(&state, id);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].status, "failed");
    assert_eq!(records[0].message, ABORT_MESSAGE);
    assert_eq!(
        (records[0].total, records[0].success, records[0].fail),
        (2, 1, 0)
    );
    mock.assert_complete();
}

#[tokio::test]
async fn every_terminal_leaves_run_record() {
    let mock = Mock::start().await;
    let disabled = Seed {
        enabled: false,
        ..Seed::active("unrunnable@example.invalid")
    };
    let (state, ids) = fixture(&mock, None, &[disabled]);
    let account = ids[0];

    let empty_id = create_plan(&state, &plan_body("empty-targets")).await;
    let mut single = plan_body("unrunnable-single");
    single["target_type"] = json!("single_account");
    single["account_id"] = json!(account);
    let single_id = create_plan(&state, &single).await;
    let mut group = plan_body("group-missing-name");
    group["target_type"] = json!("group");
    let group_id = create_plan(&state, &group).await;

    let scheduler = Scheduler::with_config(state.clone(), config(Duration::from_secs(10)));
    let mut claimed = scheduler.run_due_at(fixed()).await.unwrap();
    claimed.sort_unstable();
    let mut expected = vec![empty_id, single_id, group_id];
    expected.sort_unstable();
    assert_eq!(claimed, expected, "all three plans claim their minute");

    scheduler.wait_idle().await;
    assert!(
        mock.seen_requests().is_empty(),
        "no target resolution reaches upstream"
    );

    for (id, message) in [
        (empty_id, "没有符合条件的账号"),
        (single_id, "目标账号不可执行（已禁用/无效或缺少 JWT）"),
        (group_id, "分组目标缺少组名"),
    ] {
        let row = plan_row(&state, id);
        assert_eq!(row.1, "failed", "plan {id}");
        assert_eq!(row.2, message, "plan {id}");
        let records = run_records(&state, id);
        assert_eq!(
            records.len(),
            1,
            "terminal for plan {id} leaves exactly one record"
        );
        assert_eq!(records[0].status, "failed");
        assert_eq!(records[0].message, message);
        assert_eq!(
            (records[0].total, records[0].success, records[0].fail),
            (0, 0, 0)
        );
    }
    mock.assert_complete();
}

#[test]
fn router_build_smoke() {
    let state = Arc::new(AppState::new(
        String::new(),
        UpstreamUrls {
            zai: "http://127.0.0.1:1/unused-relay".into(),
            zai_fallback: "http://127.0.0.1:1/unused-paid-relay".into(),
        },
    ));
    // matchit panics at insertion time if /api/plans/running conflicts with
    // /api/plans/:id, so building the router is the conflict smoke test.
    let _ = build_router(state.clone());
    let _ = build_router(state);

    let defaults = SchedulerConfig::default();
    assert_eq!(defaults.tick_interval, Duration::from_secs(60));
    assert_eq!(defaults.tick_stop_wait, Duration::from_secs(5));
    assert_eq!(defaults.task_drain_wait, Duration::from_secs(15));
    let skew = ((defaults.clock)() - Local::now()).num_seconds().abs();
    assert!(skew < 60, "default clock reads Local::now, skew {skew}s");
}
