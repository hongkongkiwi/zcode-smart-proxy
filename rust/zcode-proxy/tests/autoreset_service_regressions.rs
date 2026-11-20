//! Independent service regressions for the automatic reset manager (design:
//! .agents/state/rust-migration/autoreset-service-design.md, baseline c845067).
//! Authored against the documented public surface BEFORE implementation: a
//! missing `autoreset` module is an honest compile gap, not a behavioral red.
//!
//! Pinned contract, per the finalized design:
//! - both switches absent means OFF: enqueue/sweep cause zero remote HTTP and
//!   no settings are invented; only the exact string "1" enables a switch;
//! - threshold path (Relay/Quota trigger, exhausted accounts only): FIVE_HOUR
//!   preferred over WEEK, natural wait from accounts.quota_json.next_reset,
//!   equality and unknown waits spend, shorter waits keep the slot;
//! - expiry path (own switch, main switch irrelevant): earliest future slot
//!   across both kinds within the window, window 0 or stale/nonpositive slots
//!   never spend, deterministic idem auto-expiry-{account}-{expiry-seconds};
//! - shared spend guard: manual success stamps slot 0 and blocks everything
//!   for the gap, rejected manual spends stamp nothing, distinct attributed
//!   slots stay spendable, recent successful ledger rows block cold starts,
//!   store errors block the spend;
//! - remote used=false and transport ambiguity never stamp and never retry;
//! - account changes (disable, credential rotation, delete) and stop during a
//!   gated status fetch suppress the use request;
//! - the success ledger commits before any optional quota refresh, and no
//!   quota HTTP happens without an installed refresh manager;
//! - manager bounds: dedup, 256 pending ids, bounded shutdown report, drop
//!   cancels queued work, weak state slot;
//! - GET reset-status and POST reset-history/sync stay non-spending even with
//!   both switches enabled.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json, Router,
};
use serde_json::{json, Value};
use tokio::sync::Notify;
use tower::ServiceExt;
use zcode_core::AccountView;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    autoreset::{AutoReset, AutoResetConfig, AutoResetShutdownReport, ResetTrigger},
    background_refresh::BackgroundRefresh,
    build_router,
    state::{AppState, AutomationUrls, Creds, ManagementUrls, UpstreamUrls},
    store,
    vault::Vault,
};

const SESSION: &str = "PUBLIC-autoreset-service-session";
const VAULT_SEED: &str = "PUBLIC autoreset service fixture vault seed";
const VERSION: &str = "PUBLIC-autoreset-service-version";
const JWT_PREFIX: &str = "PUBLIC-autoreset-svc-jwt-";
const KEY_PREFIX: &str = "PUBLIC-autoreset-svc-key-";
const RESET_STATUS: &str = "/api/v1/coding-plan/reset/status";
const RESET_USE: &str = "/api/v1/coding-plan/reset/use";
const BILLING_BALANCE: &str = "/api/v1/zcode-plan/billing/balance";
const BILLING_CURRENT: &str = "/api/v1/zcode-plan/billing/current";
const PLAN_MANUAL_FIVE_HOUR: &str = "配额重置(FIVE_HOUR)";
const PLAN_AUTO_FIVE_HOUR: &str = "配额重置(FIVE_HOUR)[自动]";
const PLAN_AUTO_WEEK: &str = "配额重置(WEEK)[自动]";
const PLAN_AUTO_EXPIRY_FIVE_HOUR: &str = "配额重置(FIVE_HOUR)[自动-临期]";
const PLAN_AUTO_EXPIRY_WEEK: &str = "配额重置(WEEK)[自动-临期]";
// Pinned decision clock: 2026-06-01T00:00:00Z. Every threshold, window, and
// ledger comparison below derives from it, so dates stay deterministic.
const NOW: i64 = 1780272000;
// 2100-01-01T00:00:00Z: future under both the injected clock and the wall
// clock, so cooling eligibility never depends on which clock a check uses.
const COOLING_UNTIL: i64 = 4102444800;
const DEADLINE: Duration = Duration::from_secs(8);
const SPEND_GAP_SECS: i64 = 1800;
const FIVE_HOUR_THRESHOLD_SECS: i64 = 3600;
const WEEK_THRESHOLD_SECS: i64 = 24 * 3600;

// ---- synthetic loopback upstream ----

#[derive(Clone)]
struct Seen {
    path: String,
    bearer: String,
    body: Value,
}

#[derive(Clone, PartialEq)]
enum UseOutcome {
    UsedTrue,
    UsedAbsent,
    UsedFalse,
    Garbage,
}

#[derive(Default)]
struct Script {
    seen: Mutex<Vec<Seen>>,
    violations: Mutex<Vec<String>>,
    status_body: Mutex<Value>,
    use_outcomes: Mutex<VecDeque<UseOutcome>>,
    status_gate: Mutex<Option<Arc<Notify>>>,
    use_gate: Mutex<Option<Arc<Notify>>>,
    balance_gate: Mutex<Option<Arc<Notify>>>,
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

fn billing_body() -> Value {
    json!({"code":0,"success":true,"data":{"result":{
        "plans":[{"plan_id":"start","name":"Start Plan","status":"active"}],
        "balances":[{"plan_id":"start","show_name":"PUBLIC tokens","total_units":100,
            "used_units":0,"remaining_units":100}]
    }}})
}

impl Mock {
    async fn start() -> Self {
        async fn serve(State(script): State<Arc<Script>>, request: Request) -> Response {
            let (parts, body) = request.into_parts();
            let bytes = to_bytes(body, 1 << 20).await.unwrap_or_default();
            let payload: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            let bearer = parts
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let key = parts
                .headers
                .get("x-bigmodel-authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let path = parts.uri.path().to_owned();
            let method = parts.method.as_str().to_owned();
            let reset_path = path == RESET_STATUS || path == RESET_USE;
            let bearer_ok = bearer
                .strip_prefix("Bearer ")
                .is_some_and(|token| token.starts_with(JWT_PREFIX));
            let key_ok = key.starts_with(KEY_PREFIX);
            // Every request is gated on fixture credentials: reset traffic
            // must carry the account's JWT bearer and API key header pair.
            if !bearer_ok || (reset_path && !key_ok) {
                script.violations.lock().unwrap().push(format!(
                    "{method} {path} arrived without fixture credentials"
                ));
                return (StatusCode::UNAUTHORIZED, Json(json!({"code":401}))).into_response();
            }
            script.seen.lock().unwrap().push(Seen {
                path: path.clone(),
                bearer,
                body: payload,
            });
            // Bind the cloned gate before awaiting: a Mutex guard held across
            // an await makes this handler future !Send.
            if path == RESET_STATUS {
                let gate = script.status_gate.lock().unwrap().clone();
                if let Some(gate) = gate {
                    gate.notified().await;
                }
                return (
                    StatusCode::OK,
                    Json(script.status_body.lock().unwrap().clone()),
                )
                    .into_response();
            }
            if path == RESET_USE {
                let gate = script.use_gate.lock().unwrap().clone();
                if let Some(gate) = gate {
                    gate.notified().await;
                }
                let outcome = script
                    .use_outcomes
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(UseOutcome::UsedTrue);
                return match outcome {
                    UseOutcome::UsedTrue => {
                        (StatusCode::OK, Json(json!({"code":0,"data":{"used":true}})))
                            .into_response()
                    }
                    UseOutcome::UsedAbsent => (
                        StatusCode::OK,
                        Json(json!({"code":0,"data":{"plan":{"name":"PUBLIC fixture"}}})),
                    )
                        .into_response(),
                    UseOutcome::UsedFalse => (
                        StatusCode::OK,
                        Json(json!({"code":0,"data":{"used":false}})),
                    )
                        .into_response(),
                    UseOutcome::Garbage => {
                        // Unparseable body: the request was sent but no
                        // acknowledgement can be read (transport ambiguity).
                        (StatusCode::OK, "PUBLIC-autoreset-not-json").into_response()
                    }
                };
            }
            if method == "GET" && (path == BILLING_BALANCE || path == BILLING_CURRENT) {
                if path == BILLING_BALANCE {
                    let gate = script.balance_gate.lock().unwrap().clone();
                    if let Some(gate) = gate {
                        gate.notified().await;
                    }
                }
                return (StatusCode::OK, Json(billing_body())).into_response();
            }
            script
                .violations
                .lock()
                .unwrap()
                .push(format!("unexpected {method} {path}"));
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code":500}))).into_response()
        }
        let script = Arc::new(Script {
            seen: Mutex::new(Vec::new()),
            violations: Mutex::new(Vec::new()),
            status_body: Mutex::new(Value::Null),
            use_outcomes: Mutex::new(VecDeque::new()),
            status_gate: Mutex::new(None),
            use_gate: Mutex::new(None),
            balance_gate: Mutex::new(None),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(serve).with_state(script.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base, script, task }
    }

    fn set_status(&self, body: Value) {
        *self.script.status_body.lock().unwrap() = body;
    }

    fn push_use(&self, outcome: UseOutcome) {
        self.script.use_outcomes.lock().unwrap().push_back(outcome);
    }

    fn set_status_gate(&self, gate: Option<Arc<Notify>>) {
        *self.script.status_gate.lock().unwrap() = gate;
    }

    fn set_use_gate(&self, gate: Option<Arc<Notify>>) {
        *self.script.use_gate.lock().unwrap() = gate;
    }

    fn set_balance_gate(&self, gate: Option<Arc<Notify>>) {
        *self.script.balance_gate.lock().unwrap() = gate;
    }

    fn seen_for(&self, path: &str) -> Vec<Seen> {
        self.script
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.path == path)
            .cloned()
            .collect()
    }

    fn count(&self, path: &str) -> usize {
        self.seen_for(path).len()
    }

    fn total(&self) -> usize {
        self.script.seen.lock().unwrap().len()
    }

    fn use_payloads(&self) -> Vec<Value> {
        self.seen_for(RESET_USE)
            .into_iter()
            .map(|s| s.body)
            .collect()
    }

    fn assert_no_violations(&self) {
        let violations = self.script.violations.lock().unwrap();
        assert!(
            violations.is_empty(),
            "mock contract violations: {violations:?}"
        );
    }
}

// Slot expiries are authored in upstream milliseconds (>1e11) so every spend
// pins the ms-to-seconds normalization the decision must perform.
fn slot_ms(offset_secs: i64) -> i64 {
    (NOW + offset_secs) * 1000
}

fn status_body(five_hour_ms: &[i64], week_ms: &[i64]) -> Value {
    let slots = |values: &[i64]| {
        Value::Array(
            values
                .iter()
                .map(|expire_at| json!({"expire_at": expire_at}))
                .collect(),
        )
    };
    json!({"code":0,"data":{
        "available_five_hour_resets":slots(five_hour_ms),
        "available_week_resets":slots(week_ms),
        "latest_five_hour_reset_history":null,
        "latest_week_reset_history":null,
        "has_unread_history":false
    }})
}

// ---- fixture state ----

struct AccountSpec {
    label: String,
    status: String,
    enabled: bool,
    cooling_until: i64,
}

fn spec(label: &str, status: &str) -> AccountSpec {
    AccountSpec {
        label: label.into(),
        status: status.into(),
        enabled: true,
        cooling_until: 0,
    }
}

fn cooling_spec(label: &str) -> AccountSpec {
    AccountSpec {
        cooling_until: COOLING_UNTIL,
        ..spec(label, "cooling")
    }
}

fn jwt_for(label: &str) -> String {
    format!("{JWT_PREFIX}{label}")
}

fn key_for(label: &str) -> String {
    format!("{KEY_PREFIX}{label}")
}

fn seed_account(db: &rusqlite::Connection, vault: &Vault, spec: &AccountSpec) -> i64 {
    let id = store::insert_account_encrypted(
        db,
        vault,
        &AccountView {
            email: format!("autoreset-{}@example.invalid", spec.label),
            enabled: spec.enabled,
            status: spec.status.clone(),
            cooling_until: spec.cooling_until,
            ..Default::default()
        },
        &jwt_for(&spec.label),
        &key_for(&spec.label),
    )
    .unwrap();
    let info = vault
        .encrypt(&json!({"id":format!("PUBLIC-autoreset-user-{}", spec.label)}).to_string())
        .unwrap();
    db.execute(
        "UPDATE accounts SET user_info=?1,device_mid=?2 WHERE id=?3",
        rusqlite::params![info, format!("PUBLIC-autoreset-mid-{}", spec.label), id],
    )
    .unwrap();
    id
}

fn mounted_state(db: rusqlite::Connection, vault: Vault, mock: &Mock) -> AppState {
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
        billing_preview: format!("{}/forbidden-preview", mock.base),
        billing_claim: format!("{}/forbidden-claim", mock.base),
        event_report: format!("{}/forbidden-event", mock.base),
        reset_status: format!("{}{RESET_STATUS}", mock.base),
        reset_use: format!("{}{RESET_USE}", mock.base),
        captcha_scene: String::new(),
        captcha_prefix: String::new(),
        captcha_region: String::new(),
    };
    state
        .sessions
        .lock()
        .unwrap()
        .insert(SESSION.into(), now_secs() + 3600);
    state
}

struct Fixture {
    state: Arc<AppState>,
    ids: Vec<i64>,
    labels: Vec<String>,
}

impl Fixture {
    fn new(mock: &Mock, specs: &[AccountSpec]) -> Self {
        let db = store::open(":memory:");
        let vault = Vault::from_secret(VAULT_SEED).unwrap();
        let ids = specs
            .iter()
            .map(|spec| seed_account(&db, &vault, spec))
            .collect();
        Self {
            state: Arc::new(mounted_state(db, vault, mock)),
            ids,
            labels: specs.iter().map(|s| s.label.clone()).collect(),
        }
    }

    fn id(&self, index: usize) -> i64 {
        self.ids[index]
    }

    fn jwt(&self, index: usize) -> String {
        jwt_for(&self.labels[index])
    }

    fn email(&self, index: usize) -> String {
        format!("autoreset-{}@example.invalid", self.labels[index])
    }
}

// ---- shared helpers ----

fn fixed_clock() -> Arc<dyn Fn() -> i64 + Send + Sync> {
    Arc::new(|| NOW)
}

fn config(capacity: usize, shutdown_wait: Duration, attempt_interval: Duration) -> AutoResetConfig {
    AutoResetConfig {
        capacity,
        shutdown_wait,
        attempt_interval,
        clock: fixed_clock(),
        ..AutoResetConfig::default()
    }
}

// Manual-route tests anchor the injected manager clock to a captured wall
// second: the manual reset filters live slots with the real clock, so its
// fixtures and the manager decision clock must share one base.
fn wall_config(wall: i64) -> AutoResetConfig {
    AutoResetConfig {
        capacity: 2,
        shutdown_wait: Duration::from_secs(1),
        attempt_interval: Duration::from_secs(600),
        clock: Arc::new(move || wall),
        ..AutoResetConfig::default()
    }
}

fn manager(state: &Arc<AppState>, config: AutoResetConfig) -> Arc<AutoReset> {
    Arc::new(AutoReset::with_config(state.clone(), config))
}

async fn idle(manager: &AutoReset) {
    tokio::time::timeout(DEADLINE, manager.wait_idle())
        .await
        .expect("autoreset wait_idle must respect the bounded test deadline");
}

async fn shutdown(manager: &AutoReset) -> AutoResetShutdownReport {
    tokio::time::timeout(DEADLINE, manager.shutdown())
        .await
        .expect("autoreset shutdown must respect the bounded test deadline")
}

async fn until<F: Fn() -> bool>(label: &str, condition: F) {
    for _ in 0..800 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {label}");
}

async fn call(state: &Arc<AppState>, method: &str, path: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost:8080")
        .header("origin", "http://localhost:8080")
        .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
        .body(Body::empty())
        .unwrap();
    let response = tokio::time::timeout(DEADLINE, build_router(state.clone()).oneshot(request))
        .await
        .expect("admin route call exceeded bounded loopback deadline")
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn set_quota_json(state: &AppState, id: i64, next_reset: Option<i64>) {
    let quota = match next_reset {
        Some(next_reset) => json!({"next_reset": next_reset}).to_string(),
        None => String::new(),
    };
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE accounts SET quota_json=?1 WHERE id=?2",
            rusqlite::params![quota, id],
        )
        .unwrap();
}

fn seed_setting(state: &AppState, key: &str, value: &str) {
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO settings(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value=?2",
            [key, value],
        )
        .unwrap();
    state
        .settings
        .lock()
        .unwrap()
        .insert(key.into(), value.into());
}

fn enable(state: &AppState, values: &[(&str, &str)]) {
    state.persist_settings(values).unwrap();
}

fn autoreset_settings_rows(state: &AppState) -> Vec<(String, String)> {
    let db = state.db.lock().unwrap();
    let mut stmt = db
        .prepare("SELECT key, value FROM settings WHERE key LIKE 'auto_reset_%' ORDER BY key")
        .unwrap();
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

type ResetRow = (String, String, bool, i64, String);

fn reset_rows(state: &AppState, id: i64) -> Vec<ResetRow> {
    let db = state.db.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT task_type,plan_name,success,used_at,message FROM claim_records
             WHERE account_id=?1 ORDER BY id",
        )
        .unwrap();
    stmt.query_map([id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, bool>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, String>(4)?,
        ))
    })
    .unwrap()
    .collect::<rusqlite::Result<_>>()
    .unwrap()
}

fn seed_ledger_row(state: &AppState, id: i64, email: &str, success: bool, used_at: i64) {
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO claim_records
                 (account_id,email,task_type,plan_name,success,code,message,used_at,created_at)
             VALUES(?1,?2,'reset',?3,?4,0,'PUBLIC seeded local reset',?5,'2020-01-01 00:00:00')",
            rusqlite::params![id, email, PLAN_MANUAL_FIVE_HOUR, success, used_at],
        )
        .unwrap();
}

fn disable_account(state: &AppState, id: i64) {
    state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE accounts SET enabled=0 WHERE id=?1", [id])
        .unwrap();
    let mut accounts = state.accounts.lock().unwrap();
    accounts
        .iter_mut()
        .find(|a| a.id == id)
        .expect("fixture account must exist in the mirror")
        .enabled = false;
}

// Reimport shape: DB ciphertext and both mirrors move to fresh credentials,
// so only the attempt's own snapshot comparison can detect the change.
fn rotate_credentials(state: &AppState, id: i64, label_suffix: &str) {
    let jwt = format!("{JWT_PREFIX}rotated-{label_suffix}");
    let key = format!("{KEY_PREFIX}rotated-{label_suffix}");
    let encrypted_jwt = state.vault.encrypt(&jwt).unwrap();
    let encrypted_key = state.vault.encrypt(&key).unwrap();
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE accounts SET zcode_jwt=?1,api_key=?2 WHERE id=?3",
            rusqlite::params![encrypted_jwt, encrypted_key, id],
        )
        .unwrap();
    let mut accounts = state.accounts.lock().unwrap();
    let account = accounts
        .iter_mut()
        .find(|a| a.id == id)
        .expect("fixture account must exist in the mirror");
    account.zcode_jwt = jwt.clone();
    account.api_key = key.clone();
    drop(accounts);
    state.creds.lock().unwrap().insert(
        id,
        Creds {
            zcode_jwt: jwt,
            api_key: key,
        },
    );
}

fn delete_account(state: &AppState, id: i64) {
    state
        .db
        .lock()
        .unwrap()
        .execute("DELETE FROM accounts WHERE id=?1", [id])
        .unwrap();
    state.accounts.lock().unwrap().retain(|a| a.id != id);
    state.creds.lock().unwrap().remove(&id);
}

fn assert_auto_success_row_at(row: &ResetRow, expected_plan: &str, clock: i64) {
    assert_eq!(row.0, "reset", "automatic spends audit task reset: {row:?}");
    assert_eq!(row.1, expected_plan, "plan name: {row:?}");
    assert!(row.2, "expected a successful ledger row: {row:?}");
    assert_eq!(
        row.3, clock,
        "used_at must be the injected clock in seconds: {row:?}"
    );
}

fn assert_auto_success_row(row: &ResetRow, expected_plan: &str) {
    assert_auto_success_row_at(row, expected_plan, NOW);
}

// ---- tests ----

#[test]
fn config_defaults_match_the_documented_contract() {
    let config = AutoResetConfig::default();
    assert_eq!(config.capacity, 2, "documented default capacity");
    assert_eq!(config.shutdown_wait, Duration::from_secs(5));
    assert_eq!(config.attempt_interval, Duration::from_secs(600));
    assert_eq!(config.retry_delay, Duration::from_secs(5));
}

#[tokio::test]
async fn defaults_off_enqueues_and_sweep_cause_zero_remote_activity() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[spec("default-off", "exhausted")]);
    let id = f.id(0);
    // Conditions that would spend on either path if the switches were on.
    set_quota_json(&f.state, id, Some(NOW + FIVE_HOUR_THRESHOLD_SECS));
    mock.set_status(status_body(&[slot_ms(600)], &[slot_ms(600)]));
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(1), Duration::from_secs(600)),
    );
    // The enqueue return value is not pinned while OFF; the observable
    // contract is that every trigger stays inert.
    manager.enqueue(id, ResetTrigger::Relay);
    manager.enqueue(id, ResetTrigger::Quota);
    manager.enqueue(id, ResetTrigger::Sweep);
    let swept = manager.sweep();
    assert_eq!(swept, 0, "sweep must find nothing eligible while OFF");
    idle(&manager).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        mock.total(),
        0,
        "no remote HTTP may leave the process while both switches are absent"
    );
    assert!(
        autoreset_settings_rows(&f.state).is_empty(),
        "no auto_reset_* defaults may be invented by evaluation"
    );
    assert!(
        reset_rows(&f.state, id).is_empty(),
        "no ledger rows while OFF"
    );
    assert!(
        !zcode_proxy::autoreset::recent_spend(&f.state, id),
        "no spend stamp while OFF"
    );
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn only_the_exact_enabled_string_switches_the_threshold_path_on() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[spec("exact-gate", "exhausted")]);
    let id = f.id(0);
    set_quota_json(&f.state, id, Some(NOW + FIVE_HOUR_THRESHOLD_SECS));
    mock.set_status(status_body(&[slot_ms(86_400)], &[]));
    // disabled_manager: naming the first binding away from the helper fn keeps
    // `manager(...)` callable for the fresh phase-two manager below.
    let disabled_manager = manager(
        &f.state,
        config(2, Duration::from_secs(1), Duration::from_secs(600)),
    );
    for bogus in ["0", "true", " 1", "on", "yes"] {
        seed_setting(&f.state, "auto_reset_enabled", bogus);
        disabled_manager.enqueue(id, ResetTrigger::Relay);
        idle(&disabled_manager).await;
        assert_eq!(
            mock.total(),
            0,
            "auto_reset_enabled={bogus:?} must stay OFF: only the exact string 1 enables"
        );
    }
    shutdown(&disabled_manager).await;
    drop(disabled_manager);
    enable(&f.state, &[("auto_reset_enabled", "1")]);
    // A fresh manager keeps the enabled phase independent of whether OFF
    // evaluations consumed an attempt stamp in the phase above.
    let enabled_manager = manager(
        &f.state,
        config(2, Duration::from_secs(1), Duration::from_secs(600)),
    );
    assert!(enabled_manager.enqueue(id, ResetTrigger::Relay));
    until("threshold spend after exact enable", || {
        mock.count(RESET_USE) == 1
    })
    .await;
    idle(&enabled_manager).await;
    assert_eq!(mock.count(RESET_STATUS), 1);
    assert_eq!(
        autoreset_settings_rows(&f.state),
        vec![("auto_reset_enabled".to_owned(), "1".to_owned())],
        "evaluation must not rewrite or seed settings"
    );
    let rows = reset_rows(&f.state, id);
    assert_eq!(rows.len(), 1);
    assert_auto_success_row(&rows[0], PLAN_AUTO_FIVE_HOUR);
    mock.assert_no_violations();
    shutdown(&enabled_manager).await;
}

#[tokio::test]
async fn five_hour_threshold_spends_only_at_or_above_the_configured_wait() {
    let mock = Mock::start().await;
    let f = Fixture::new(
        &mock,
        &[
            spec("five-below", "exhausted"),
            spec("five-equal", "exhausted"),
            spec("five-unknown", "exhausted"),
        ],
    );
    // Slots far outside the expiry window and the expiry switch absent:
    // only the threshold decision can spend.
    mock.set_status(status_body(&[slot_ms(86_400)], &[]));
    enable(&f.state, &[("auto_reset_enabled", "1")]);
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(1), Duration::from_secs(600)),
    );

    set_quota_json(&f.state, f.id(0), Some(NOW + FIVE_HOUR_THRESHOLD_SECS - 1));
    assert!(manager.enqueue(f.id(0), ResetTrigger::Relay));
    until("below-threshold status fetch", || {
        mock.count(RESET_STATUS) == 1
    })
    .await;
    idle(&manager).await;
    assert_eq!(
        mock.count(RESET_USE),
        0,
        "a shorter natural wait must keep the slot"
    );
    assert!(reset_rows(&f.state, f.id(0)).is_empty());

    set_quota_json(&f.state, f.id(1), Some(NOW + FIVE_HOUR_THRESHOLD_SECS));
    assert!(manager.enqueue(f.id(1), ResetTrigger::Relay));
    until("equality spend", || mock.count(RESET_USE) == 1).await;
    idle(&manager).await;

    set_quota_json(&f.state, f.id(2), None);
    assert!(manager.enqueue(f.id(2), ResetTrigger::Relay));
    until("unknown-wait spend", || mock.count(RESET_USE) == 2).await;
    idle(&manager).await;

    assert_eq!(mock.count(RESET_STATUS), 3, "one status fetch per attempt");
    assert_eq!(
        mock.count(BILLING_BALANCE) + mock.count(BILLING_CURRENT),
        0,
        "no confirmation HTTP runs inside the worker"
    );
    let rows = reset_rows(&f.state, f.id(1));
    assert_eq!(rows.len(), 1);
    assert_auto_success_row(&rows[0], PLAN_AUTO_FIVE_HOUR);
    let rows = reset_rows(&f.state, f.id(2));
    assert_eq!(rows.len(), 1);
    assert_auto_success_row(&rows[0], PLAN_AUTO_FIVE_HOUR);
    let payloads = mock.use_payloads();
    let idem_keys: Vec<&str> = payloads
        .iter()
        .filter_map(|body| body["idempotency_key"].as_str())
        .collect();
    assert_eq!(idem_keys.len(), 2);
    for idem in idem_keys {
        assert!(
            !idem.is_empty(),
            "the threshold path must not send an empty key"
        );
        assert!(
            !idem.starts_with("auto-expiry-"),
            "the threshold path has no slot identity and must use a random key: {idem}"
        );
    }
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn week_threshold_spends_only_at_or_above_the_configured_wait() {
    let mock = Mock::start().await;
    let f = Fixture::new(
        &mock,
        &[
            spec("week-below", "exhausted"),
            spec("week-equal", "exhausted"),
            spec("week-unknown", "exhausted"),
        ],
    );
    // No five-hour slots: the WEEK threshold must apply.
    mock.set_status(status_body(&[], &[slot_ms(30 * 86_400)]));
    enable(&f.state, &[("auto_reset_enabled", "1")]);
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(1), Duration::from_secs(600)),
    );

    set_quota_json(&f.state, f.id(0), Some(NOW + WEEK_THRESHOLD_SECS - 1));
    assert!(manager.enqueue(f.id(0), ResetTrigger::Relay));
    until("week below-threshold status fetch", || {
        mock.count(RESET_STATUS) == 1
    })
    .await;
    idle(&manager).await;
    assert_eq!(
        mock.count(RESET_USE),
        0,
        "a wait below 24h must keep the WEEK slot"
    );
    assert!(reset_rows(&f.state, f.id(0)).is_empty());

    set_quota_json(&f.state, f.id(1), Some(NOW + WEEK_THRESHOLD_SECS));
    assert!(manager.enqueue(f.id(1), ResetTrigger::Relay));
    until("week equality spend", || mock.count(RESET_USE) == 1).await;
    idle(&manager).await;

    set_quota_json(&f.state, f.id(2), None);
    assert!(manager.enqueue(f.id(2), ResetTrigger::Relay));
    until("week unknown spend", || mock.count(RESET_USE) == 2).await;
    idle(&manager).await;

    assert_eq!(mock.count(RESET_STATUS), 3);
    let rows = reset_rows(&f.state, f.id(1));
    assert_eq!(rows.len(), 1);
    assert_auto_success_row(&rows[0], PLAN_AUTO_WEEK);
    let rows = reset_rows(&f.state, f.id(2));
    assert_eq!(rows.len(), 1);
    assert_auto_success_row(&rows[0], PLAN_AUTO_WEEK);
    let payloads = mock.use_payloads();
    let reset_types: Vec<&str> = payloads
        .iter()
        .filter_map(|body| body["reset_type"].as_str())
        .collect();
    assert_eq!(
        reset_types,
        vec!["WEEK", "WEEK"],
        "no five-hour slot means WEEK spends"
    );
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn expiry_path_runs_with_main_switch_off_and_spends_the_earliest_slot_across_kinds() {
    let mock = Mock::start().await;
    let f = Fixture::new(
        &mock,
        &[
            spec("expiry-cross", "active"),
            spec("expiry-five", "active"),
        ],
    );
    // Main switch absent; only auto_reset_expiry_enabled is on. A week slot
    // expiring sooner than the five-hour slot must win the earliest-slot race
    // even though the five-hour list is non-empty.
    mock.set_status(status_body(&[slot_ms(3000)], &[slot_ms(600)]));
    let other = status_body(&[slot_ms(600)], &[]);
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(1), Duration::from_secs(600)),
    );

    assert!(manager.enqueue(f.id(0), ResetTrigger::Sweep));
    until("earliest cross-kind spend", || mock.count(RESET_USE) == 1).await;
    idle(&manager).await;
    mock.set_status(other);
    assert!(manager.enqueue(f.id(1), ResetTrigger::Sweep));
    until("five-hour-only expiry spend", || mock.count(RESET_USE) == 2).await;
    idle(&manager).await;

    let cross_id = f.id(0);
    let payloads = mock.use_payloads();
    assert_eq!(
        payloads[0]["reset_type"],
        json!("WEEK"),
        "the sooner WEEK slot overrides the five-hour preference"
    );
    assert_eq!(
        payloads[0]["idempotency_key"],
        json!(format!("auto-expiry-{cross_id}-{}", NOW + 600)),
        "expiry idem keys must be deterministic account + expiry-seconds"
    );
    assert_eq!(payloads[1]["reset_type"], json!("FIVE_HOUR"));
    let rows = reset_rows(&f.state, cross_id);
    assert_eq!(rows.len(), 1);
    assert_auto_success_row(&rows[0], PLAN_AUTO_EXPIRY_WEEK);
    let rows = reset_rows(&f.state, f.id(1));
    assert_eq!(rows.len(), 1);
    assert_auto_success_row(&rows[0], PLAN_AUTO_EXPIRY_FIVE_HOUR);
    assert!(
        zcode_proxy::autoreset::recent_spend(&f.state, cross_id),
        "a confirmed expiry spend must leave a warm stamp"
    );
    assert_eq!(mock.count(RESET_STATUS), 2);
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn expiry_window_zero_and_stale_or_nonpositive_slots_never_spend() {
    let mock = Mock::start().await;
    let f = Fixture::new(
        &mock,
        &[spec("window-zero", "active"), spec("stale-slots", "active")],
    );
    enable(
        &f.state,
        &[
            ("auto_reset_expiry_enabled", "1"),
            ("auto_reset_expiry_spend_minutes", "0"),
        ],
    );
    mock.set_status(status_body(&[slot_ms(60)], &[]));
    // attempt_interval 0 so the phase-two account still evaluates after the
    // phase-one attempt stamped its own account.
    let manager = manager(&f.state, config(2, Duration::from_secs(1), Duration::ZERO));
    assert!(manager.enqueue(f.id(0), ResetTrigger::Sweep));
    idle(&manager).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        mock.count(RESET_USE),
        0,
        "window 0 disables the expiry trigger"
    );
    assert!(reset_rows(&f.state, f.id(0)).is_empty());

    enable(&f.state, &[("auto_reset_expiry_spend_minutes", "60")]);
    mock.set_status(status_body(&[slot_ms(-60), 0, slot_ms(120 * 60)], &[]));
    assert!(manager.enqueue(f.id(1), ResetTrigger::Sweep));
    idle(&manager).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        mock.count(RESET_USE),
        0,
        "expired, zero, and out-of-window slots must all be ignored"
    );
    assert!(reset_rows(&f.state, f.id(1)).is_empty());
    assert!(!zcode_proxy::autoreset::recent_spend(&f.state, f.id(1)));
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn manual_success_stamps_unattributed_and_blocks_any_auto_spend() {
    let mock = Mock::start().await;
    // Both switches stay off for the manual action: the manual path must keep
    // its own ledger and stamp regardless of the automatic settings.
    let f = Fixture::new(&mock, &[spec("manual-block", "active")]);
    let id = f.id(0);
    // The manual route compares normalized slot seconds against the real
    // clock, so its live slot anchors to a captured wall second.
    let wall = now_secs();
    mock.set_status(status_body(&[(wall + 1800) * 1000], &[]));
    mock.push_use(UseOutcome::UsedAbsent);
    let (status, body) = call(&f.state, "POST", &format!("/api/accounts/{id}/reset")).await;
    assert_eq!(status, StatusCode::OK, "manual reset: {body}");
    assert_eq!(body["ok"], true, "absent data.used counts as used: {body}");
    let rows = reset_rows(&f.state, id);
    assert_eq!(rows.len(), 1, "the manual ledger stays unchanged: {rows:?}");
    assert_eq!(rows[0].1, PLAN_MANUAL_FIVE_HOUR);
    assert!(rows[0].2);
    assert!(
        zcode_proxy::autoreset::recent_spend(&f.state, id),
        "a successful manual reset must stamp the shared guard"
    );

    // A different, in-window slot must still be refused: the manual stamp is
    // unattributed (slot 0) and blocks every expiry spend for the gap.
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    mock.set_status(status_body(&[(wall + 600) * 1000], &[]));
    let manager = manager(&f.state, wall_config(wall));
    assert!(manager.enqueue(id, ResetTrigger::Sweep));
    idle(&manager).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        mock.count(RESET_USE),
        1,
        "the manual use is the only spend allowed"
    );
    assert_eq!(
        reset_rows(&f.state, id).len(),
        1,
        "no automatic row may appear"
    );
    assert!(zcode_proxy::autoreset::recent_spend(&f.state, id));
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn manual_rejection_leaves_no_stamp_so_auto_spend_proceeds() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[spec("manual-reject", "active")]);
    let id = f.id(0);
    // The manual route needs a slot live under the real wall clock.
    let wall = now_secs();
    mock.set_status(status_body(&[(wall + 1800) * 1000], &[]));
    mock.push_use(UseOutcome::UsedFalse);
    let (status, body) = call(&f.state, "POST", &format!("/api/accounts/{id}/reset")).await;
    assert_eq!(status, StatusCode::OK, "manual reset: {body}");
    assert_eq!(body["ok"], false, "data.used=false is a rejection: {body}");
    let rows = reset_rows(&f.state, id);
    assert_eq!(rows.len(), 1, "the rejection is audited: {rows:?}");
    assert!(!rows[0].2, "a rejected manual spend is not a success row");
    assert!(
        !zcode_proxy::autoreset::recent_spend(&f.state, id),
        "a rejected manual spend must never stamp"
    );

    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    mock.set_status(status_body(&[(wall + 600) * 1000], &[]));
    let manager = manager(&f.state, wall_config(wall));
    assert!(manager.enqueue(id, ResetTrigger::Sweep));
    until("auto spend after an unstamped rejection", || {
        mock.count(RESET_USE) == 2
    })
    .await;
    idle(&manager).await;
    let rows = reset_rows(&f.state, id);
    assert_eq!(
        rows.len(),
        2,
        "failure row plus automatic success: {rows:?}"
    );
    assert_auto_success_row_at(&rows[1], PLAN_AUTO_EXPIRY_FIVE_HOUR, wall);
    assert!(zcode_proxy::autoreset::recent_spend(&f.state, id));
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn automatic_used_false_or_transport_ambiguity_never_stamps_and_never_retries() {
    let mock = Mock::start().await;
    let f = Fixture::new(
        &mock,
        &[
            spec("auto-used-false", "active"),
            spec("auto-ambiguous", "active"),
        ],
    );
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    // attempt_interval 0 removes the debounce: anything that re-triggers the
    // same account during the assertion window is an automatic retry.
    let manager = manager(&f.state, config(2, Duration::from_secs(1), Duration::ZERO));

    mock.push_use(UseOutcome::UsedFalse);
    assert!(manager.enqueue(f.id(0), ResetTrigger::Sweep));
    until("used=false attempt", || mock.count(RESET_USE) == 1).await;
    idle(&manager).await;
    assert!(
        !zcode_proxy::autoreset::recent_spend(&f.state, f.id(0)),
        "used=false must never stamp"
    );
    let rows = reset_rows(&f.state, f.id(0));
    assert_eq!(rows.len(), 1, "the rejection is audited: {rows:?}");
    assert!(!rows[0].2, "used=false audits a failure row");

    mock.push_use(UseOutcome::Garbage);
    assert!(manager.enqueue(f.id(1), ResetTrigger::Sweep));
    until("transport-ambiguous attempt", || mock.count(RESET_USE) == 2).await;
    idle(&manager).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        mock.count(RESET_USE),
        2,
        "no automatic retry after used=false or ambiguity"
    );
    assert_eq!(mock.count(RESET_STATUS), 2, "one status fetch per episode");
    assert!(
        !zcode_proxy::autoreset::recent_spend(&f.state, f.id(1)),
        "an ambiguous outcome must not stamp a confirmed spend"
    );
    let rows = reset_rows(&f.state, f.id(1));
    assert_eq!(rows.len(), 1, "ambiguity writes a failure audit: {rows:?}");
    assert!(!rows[0].2, "ambiguity is never a success row");
    assert!(
        !rows[0].4.is_empty(),
        "the ambiguity audit must carry an explicit unknown-consumption message"
    );
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn cold_ledger_boundary_blocks_exactly_recent_successful_resets() {
    let mock = Mock::start().await;
    let f = Fixture::new(
        &mock,
        &[
            spec("cold-failure-row", "active"),
            spec("cold-edge", "active"),
            spec("cold-just-past", "active"),
        ],
    );
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    // A failure row is never a spend; the success boundary is inclusive.
    seed_ledger_row(&f.state, f.id(0), &f.email(0), false, NOW - 60);
    seed_ledger_row(&f.state, f.id(1), &f.email(1), true, NOW - SPEND_GAP_SECS);
    seed_ledger_row(
        &f.state,
        f.id(2),
        &f.email(2),
        true,
        NOW - SPEND_GAP_SECS - 1,
    );
    // Capture the seeds immediately: every ledger assertion below compares
    // against them, so the test can never miscount its own fixtures again.
    let failure_seed = reset_rows(&f.state, f.id(0));
    let edge_seed = reset_rows(&f.state, f.id(1));
    let past_seed = reset_rows(&f.state, f.id(2));
    assert_eq!(failure_seed.len(), 1, "seeded failure row captured");
    assert_eq!(edge_seed.len(), 1, "seeded edge row captured");
    assert_eq!(past_seed.len(), 1, "seeded past-gap row captured");
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(1), Duration::from_secs(600)),
    );

    assert!(manager.enqueue(f.id(0), ResetTrigger::Sweep));
    until("failure rows do not block", || mock.count(RESET_USE) == 1).await;
    idle(&manager).await;
    let rows = reset_rows(&f.state, f.id(0));
    assert_eq!(
        rows.len(),
        failure_seed.len() + 1,
        "a failure row never blocks the spend: {rows:?}"
    );
    assert_eq!(
        rows[..failure_seed.len()],
        failure_seed[..],
        "the seed row must stay untouched"
    );
    assert_auto_success_row(&rows[failure_seed.len()], PLAN_AUTO_EXPIRY_FIVE_HOUR);
    assert!(manager.enqueue(f.id(1), ResetTrigger::Sweep));
    idle(&manager).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        mock.count(RESET_USE),
        1,
        "a successful ledger row exactly 1800s old must block (>= boundary)"
    );
    assert_eq!(
        reset_rows(&f.state, f.id(1)),
        edge_seed,
        "the blocked attempt must leave the ledger byte-identical to the seed"
    );
    assert!(manager.enqueue(f.id(2), ResetTrigger::Sweep));
    until("rows older than the gap do not block", || {
        mock.count(RESET_USE) == 2
    })
    .await;
    idle(&manager).await;
    let rows = reset_rows(&f.state, f.id(2));
    assert_eq!(
        rows.len(),
        past_seed.len() + 1,
        "seed plus exactly one new spend row: {rows:?}"
    );
    assert_eq!(
        rows[..past_seed.len()],
        past_seed[..],
        "the seed row must stay untouched"
    );
    assert_auto_success_row(&rows[past_seed.len()], PLAN_AUTO_EXPIRY_FIVE_HOUR);
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn real_spend_replayed_after_state_reload_hits_the_cold_ledger_block() {
    let mock = Mock::start().await;
    let db = store::open(":memory:");
    let vault = Vault::from_secret(VAULT_SEED).unwrap();
    let id = seed_account(&db, &vault, &spec("reload-replay", "active"));
    let state = Arc::new(mounted_state(db, vault, &mock));
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(&state, &[("auto_reset_expiry_enabled", "1")]);
    let first = manager(
        &state,
        config(2, Duration::from_secs(1), Duration::from_secs(600)),
    );
    assert!(first.enqueue(id, ResetTrigger::Sweep));
    until("original spend", || mock.count(RESET_USE) == 1).await;
    idle(&first).await;
    let report = shutdown(&first).await;
    assert!(report.drained, "a clean manager must drain before reload");
    drop(first);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let state = match Arc::try_unwrap(state) {
        Ok(state) => state,
        // AppState carries credentials and has no Debug impl: never format it.
        Err(_) => panic!("workers must release the state Arc after shutdown"),
    };
    let db = state.db.into_inner().unwrap();
    let reloaded = Arc::new(mounted_state(
        db,
        Vault::from_secret(VAULT_SEED).unwrap(),
        &mock,
    ));
    // The upstream still lists the spent slot (status lag): the restarted
    // process has no warm stamp, so only the ledger row can stop the replay.
    assert!(
        !zcode_proxy::autoreset::recent_spend(&reloaded, id),
        "a reloaded state starts cold by design"
    );
    let second = manager(
        &reloaded,
        config(2, Duration::from_secs(1), Duration::from_secs(600)),
    );
    assert!(second.enqueue(id, ResetTrigger::Sweep));
    idle(&second).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        mock.count(RESET_USE),
        1,
        "the replay attempt must be blocked by the cold ledger"
    );
    let rows = reset_rows(&reloaded, id);
    assert_eq!(
        rows.len(),
        1,
        "only the original success row survives: {rows:?}"
    );
    assert_auto_success_row(&rows[0], PLAN_AUTO_EXPIRY_FIVE_HOUR);
    mock.assert_no_violations();
    shutdown(&second).await;
}

#[tokio::test]
async fn distinct_attributed_slots_stay_spendable_within_the_warm_gap() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[spec("two-slots", "active")]);
    let id = f.id(0);
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    // attempt_interval 0 lets the second explicit trigger evaluate while the
    // first stamp is still warm; the guard, not the debounce, decides.
    let manager = manager(&f.state, config(2, Duration::from_secs(1), Duration::ZERO));
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    assert!(manager.enqueue(id, ResetTrigger::Sweep));
    until("first attributed spend", || mock.count(RESET_USE) == 1).await;
    idle(&manager).await;
    assert!(zcode_proxy::autoreset::recent_spend(&f.state, id));

    mock.set_status(status_body(&[slot_ms(1200)], &[]));
    assert!(manager.enqueue(id, ResetTrigger::Sweep));
    until("different attributed slot spends within the gap", || {
        mock.count(RESET_USE) == 2
    })
    .await;
    idle(&manager).await;
    let payloads = mock.use_payloads();
    let idems: Vec<&str> = payloads
        .iter()
        .filter_map(|body| body["idempotency_key"].as_str())
        .collect();
    assert_eq!(idems.len(), 2);
    assert_ne!(
        idems[0], idems[1],
        "each slot spends under its own deterministic key"
    );
    for idem in idems {
        assert!(
            idem.starts_with(&format!("auto-expiry-{id}-")),
            "key {idem}"
        );
    }
    let rows = reset_rows(&f.state, id);
    assert_eq!(rows.len(), 2, "both distinct-slot spends audit: {rows:?}");
    assert_auto_success_row(&rows[0], PLAN_AUTO_EXPIRY_FIVE_HOUR);
    assert_auto_success_row(&rows[1], PLAN_AUTO_EXPIRY_FIVE_HOUR);
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn duplicate_enqueues_dedupe_and_completed_attempts_debounce() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[spec("debounce", "exhausted")]);
    let id = f.id(0);
    set_quota_json(&f.state, id, Some(NOW + FIVE_HOUR_THRESHOLD_SECS));
    mock.set_status(status_body(&[slot_ms(86_400)], &[]));
    enable(&f.state, &[("auto_reset_enabled", "1")]);
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(1), Duration::from_secs(600)),
    );
    let gate = Arc::new(Notify::new());
    mock.set_status_gate(Some(gate.clone()));
    assert!(manager.enqueue(id, ResetTrigger::Relay));
    until("attempt reaches the gated status fetch", || {
        mock.count(RESET_STATUS) == 1
    })
    .await;
    assert!(
        !manager.enqueue(id, ResetTrigger::Relay),
        "an id pending or executing must be deduplicated"
    );
    gate.notify_one();
    mock.set_status_gate(None);
    until("first attempt spends", || mock.count(RESET_USE) == 1).await;
    idle(&manager).await;

    let statuses_before = mock.count(RESET_STATUS);
    manager.enqueue(id, ResetTrigger::Relay);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.count(RESET_STATUS),
        statuses_before,
        "a completed attempt debounces re-enqueues for attempt_interval"
    );
    assert_eq!(mock.count(RESET_USE), 1);
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn busy_manual_action_defers_the_auto_attempt_without_consuming_debounce() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[spec("busy-manual", "exhausted")]);
    let id = f.id(0);
    // Wall anchor: the manual route needs a real-clock-live slot, while the
    // threshold equality below stays exact for the injected clock (wall).
    let wall = now_secs();
    set_quota_json(&f.state, id, Some(wall + FIVE_HOUR_THRESHOLD_SECS));
    mock.set_status(status_body(&[(wall + 1800) * 1000], &[]));
    enable(&f.state, &[("auto_reset_enabled", "1")]);
    // The manual spend ends ambiguous (garbage response): it leaves no stamp,
    // so the later auto attempt is free to spend if its debounce was spared.
    mock.push_use(UseOutcome::Garbage);
    let use_gate = Arc::new(Notify::new());
    mock.set_use_gate(Some(use_gate.clone()));
    let manual_state = f.state.clone();
    let manual_path = format!("/api/accounts/{id}/reset");
    let manual = tokio::spawn(async move { call(&manual_state, "POST", &manual_path).await });
    until("manual reset parks on the gated use", || {
        mock.count(RESET_USE) == 1
    })
    .await;

    let manager = manager(&f.state, wall_config(wall));
    // Return value unpinned: rejecting a busy enqueue and deferring inside the
    // worker are both admissible as long as no attempt is consumed.
    manager.enqueue(id, ResetTrigger::Relay);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.total(),
        2,
        "a busy manual account holds the admission: no auto HTTP at all"
    );
    use_gate.notify_one();
    mock.set_use_gate(None);
    let (status, body) = manual.await.unwrap();
    assert_eq!(status, StatusCode::OK, "manual reset: {body}");
    assert_eq!(
        body["ok"], false,
        "the gated manual spend stays ambiguous: {body}"
    );

    manager.enqueue(id, ResetTrigger::Relay);
    until("the spared debounce lets the next attempt run", || {
        mock.count(RESET_STATUS) == 2
    })
    .await;
    until("auto spend after the manual episode", || {
        mock.count(RESET_USE) == 2
    })
    .await;
    idle(&manager).await;
    let rows = reset_rows(&f.state, id);
    assert_eq!(
        rows.len(),
        2,
        "manual failure row plus auto success: {rows:?}"
    );
    assert!(!rows[0].2);
    assert_auto_success_row_at(&rows[1], PLAN_AUTO_FIVE_HOUR, wall);
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn mid_attempt_disable_rotation_or_delete_suppresses_the_spend() {
    let mock = Mock::start().await;
    let f = Fixture::new(
        &mock,
        &[
            spec("gated-disable", "active"),
            spec("gated-rotate", "active"),
            spec("gated-delete", "active"),
        ],
    );
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(1), Duration::from_secs(600)),
    );
    let mutations: [&str; 3] = ["disable", "rotate", "delete"];
    for (index, mutation) in mutations.iter().enumerate() {
        let id = f.id(index);
        let gate = Arc::new(Notify::new());
        mock.set_status_gate(Some(gate.clone()));
        assert!(manager.enqueue(id, ResetTrigger::Sweep));
        let expected_status = index + 1;
        until("attempt parks on the gated status fetch", || {
            mock.count(RESET_STATUS) == expected_status
        })
        .await;
        match *mutation {
            "disable" => disable_account(&f.state, id),
            "rotate" => rotate_credentials(&f.state, id, &f.labels[index]),
            "delete" => delete_account(&f.state, id),
            other => panic!("unknown mutation {other}"),
        }
        gate.notify_one();
        mock.set_status_gate(None);
        idle(&manager).await;
        assert_eq!(
            mock.count(RESET_USE),
            0,
            "a {mutation} mid-attempt must suppress the use request"
        );
        assert!(
            reset_rows(&f.state, id).is_empty(),
            "suppressed attempts write no ledger rows"
        );
    }
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn stop_suppresses_the_next_http_step_for_an_in_flight_attempt() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[spec("stop-gate", "active")]);
    let id = f.id(0);
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(1), Duration::from_secs(600)),
    );
    let gate = Arc::new(Notify::new());
    mock.set_status_gate(Some(gate.clone()));
    assert!(manager.enqueue(id, ResetTrigger::Sweep));
    until("attempt parks on the gated status fetch", || {
        mock.count(RESET_STATUS) == 1
    })
    .await;
    assert!(!manager.is_stopped());
    manager.stop();
    assert!(manager.is_stopped(), "stop must be observable immediately");
    gate.notify_one();
    mock.set_status_gate(None);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.count(RESET_USE),
        0,
        "stop must suppress the next HTTP step after the in-flight status finishes"
    );
    assert!(manager.pending().is_empty(), "stop cancels pending work");
    assert!(reset_rows(&f.state, id).is_empty());
    assert!(
        !manager.enqueue(id, ResetTrigger::Sweep),
        "a stopped manager accepts no new work"
    );
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn ledger_commit_failure_retains_the_warm_stamp_and_prevents_replay() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[spec("audit-fail", "active")]);
    let id = f.id(0);
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    f.state
        .db
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_autoreset_ledger BEFORE INSERT ON claim_records
             BEGIN SELECT RAISE(ABORT, 'PUBLIC fixture blocks the success ledger'); END;",
        )
        .unwrap();
    // attempt_interval 0: the replay probe below cannot be eaten by debounce.
    let manager = manager(&f.state, config(2, Duration::from_secs(1), Duration::ZERO));
    assert!(manager.enqueue(id, ResetTrigger::Sweep));
    until("remote spend acknowledged", || mock.count(RESET_USE) == 1).await;
    idle(&manager).await;
    assert!(
        zcode_proxy::autoreset::recent_spend(&f.state, id),
        "a failed audit must retain the warm stamp: the remote spend is real"
    );

    mock.set_status(status_body(&[slot_ms(600)], &[]));
    assert!(manager.enqueue(id, ResetTrigger::Sweep));
    idle(&manager).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.count(RESET_USE),
        1,
        "the retained stamp must block a replay of the same slot"
    );
    assert_eq!(mock.count(RESET_STATUS), 2, "the replay probe did evaluate");
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn cold_guard_store_error_blocks_the_spend() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[spec("store-error", "active")]);
    let id = f.id(0);
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    f.state
        .db
        .lock()
        .unwrap()
        .execute_batch("DROP TABLE claim_records")
        .unwrap();
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(1), Duration::from_secs(600)),
    );
    assert!(manager.enqueue(id, ResetTrigger::Sweep));
    idle(&manager).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        mock.count(RESET_USE),
        0,
        "a store error during the cold-ledger guard must block, never spend"
    );
    assert!(!zcode_proxy::autoreset::recent_spend(&f.state, id));
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn success_ledger_is_durable_before_the_optional_quota_refresh() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[spec("audit-first", "active")]);
    let id = f.id(0);
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    let refresh = Arc::new(BackgroundRefresh::new(f.state.clone()));
    f.state
        .set_background_refresh(refresh.clone())
        .expect("installing the refresh manager must succeed");
    let balance_gate = Arc::new(Notify::new());
    mock.set_balance_gate(Some(balance_gate.clone()));
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(1), Duration::from_secs(600)),
    );
    assert!(manager.enqueue(id, ResetTrigger::Sweep));
    until("the refresh manager fetches quota", || {
        mock.count(BILLING_BALANCE) == 1
    })
    .await;
    let rows = reset_rows(&f.state, id);
    assert_eq!(
        rows.len(),
        1,
        "the success ledger must already be committed: {rows:?}"
    );
    assert_auto_success_row(&rows[0], PLAN_AUTO_EXPIRY_FIVE_HOUR);
    let bearers: Vec<String> = mock
        .seen_for(BILLING_BALANCE)
        .iter()
        .map(|seen| seen.bearer.clone())
        .collect();
    assert_eq!(bearers, vec![format!("Bearer {}", f.jwt(0))]);
    balance_gate.notify_one();
    mock.set_balance_gate(None);
    idle(&manager).await;
    tokio::time::timeout(DEADLINE, refresh.shutdown())
        .await
        .expect("refresh manager shutdown must stay bounded");
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn missing_refresh_manager_means_no_quota_http_after_a_spend() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[spec("no-refresh", "active")]);
    let id = f.id(0);
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(1), Duration::from_secs(600)),
    );
    assert!(manager.enqueue(id, ResetTrigger::Sweep));
    until("spend without a refresh manager", || {
        mock.count(RESET_USE) == 1
    })
    .await;
    idle(&manager).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        mock.count(BILLING_BALANCE) + mock.count(BILLING_CURRENT),
        0,
        "no installed manager means no fabricated quota refresh"
    );
    assert_eq!(mock.total(), 2, "exactly one status fetch and one use");
    let rows = reset_rows(&f.state, id);
    assert_eq!(rows.len(), 1);
    assert_auto_success_row(&rows[0], PLAN_AUTO_EXPIRY_FIVE_HOUR);
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn zero_capacity_normalizes_to_one_executor() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[cooling_spec("cap-a"), cooling_spec("cap-b")]);
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    let manager = manager(
        &f.state,
        config(0, Duration::from_secs(1), Duration::from_secs(600)),
    );
    let gate = Arc::new(Notify::new());
    mock.set_status_gate(Some(gate.clone()));
    assert!(manager.enqueue(f.id(0), ResetTrigger::Sweep));
    until("first executor parks", || mock.count(RESET_STATUS) == 1).await;
    let mut max_executing = manager.executing().len();
    assert!(manager.enqueue(f.id(1), ResetTrigger::Sweep));
    max_executing = max_executing.max(manager.executing().len());
    assert_eq!(
        manager.executing(),
        vec![f.id(0)],
        "capacity 0 must normalize to at least one executor, never zero"
    );
    assert_eq!(manager.pending(), vec![f.id(1)]);
    let second_gate = Arc::new(Notify::new());
    mock.set_status_gate(Some(second_gate.clone()));
    gate.notify_one();
    until("serialized second executor runs", || {
        mock.count(RESET_STATUS) == 2
    })
    .await;
    max_executing = max_executing.max(manager.executing().len());
    second_gate.notify_one();
    mock.set_status_gate(None);
    until("both serialized spends complete", || {
        mock.count(RESET_USE) == 2
    })
    .await;
    idle(&manager).await;
    assert!(
        max_executing <= 1,
        "capacity 0 must never run two attempts concurrently (observed {max_executing})"
    );
    assert_eq!(reset_rows(&f.state, f.id(0)).len(), 1);
    assert_eq!(reset_rows(&f.state, f.id(1)).len(), 1);
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn pending_ids_are_bounded_and_shutdown_reports_cancelled_and_abandoned() {
    let mock = Mock::start().await;
    // 2 executing + 256 pending + 1 refused probe.
    let specs: Vec<AccountSpec> = (0..259)
        .map(|index| cooling_spec(&format!("bound-{index:03}")))
        .collect();
    let f = Fixture::new(&mock, &specs);
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    let manager = manager(
        &f.state,
        config(2, Duration::from_millis(150), Duration::from_secs(600)),
    );
    let gate = Arc::new(Notify::new());
    mock.set_status_gate(Some(gate.clone()));
    assert!(manager.enqueue(f.id(0), ResetTrigger::Sweep));
    until("executor one parks", || mock.count(RESET_STATUS) == 1).await;
    assert!(manager.enqueue(f.id(1), ResetTrigger::Sweep));
    until("executor two parks", || mock.count(RESET_STATUS) == 2).await;
    for id in f.ids.iter().take(258).skip(2) {
        assert!(
            manager.enqueue(*id, ResetTrigger::Sweep),
            "pending ids below the bound must be accepted"
        );
    }
    assert_eq!(
        manager.pending().len(),
        256,
        "the pending set holds exactly 256 ids"
    );
    assert!(
        !manager.enqueue(f.id(258), ResetTrigger::Sweep),
        "the 257th distinct pending id must be refused"
    );

    let report = shutdown(&manager).await;
    assert!(
        !report.drained,
        "workers parked on the gate cannot drain in 150ms"
    );
    let mut abandoned = report.abandoned;
    abandoned.sort();
    assert_eq!(
        abandoned,
        vec![f.id(0), f.id(1)],
        "the two in-flight ids are abandoned"
    );
    assert_eq!(
        report.cancelled, 256,
        "every pending id is counted as cancelled"
    );
    gate.notify_waiters();
    mock.set_status_gate(None);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.count(RESET_USE),
        0,
        "stopped workers must not spend after the gate opens"
    );
    assert!(manager.is_stopped());
    mock.assert_no_violations();
}

#[tokio::test]
async fn dropping_the_manager_cancels_queued_work() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[spec("drop-cancel", "active")]);
    let id = f.id(0);
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    let manager = manager(
        &f.state,
        config(2, Duration::from_millis(100), Duration::from_secs(600)),
    );
    let gate = Arc::new(Notify::new());
    mock.set_status_gate(Some(gate.clone()));
    assert!(manager.enqueue(id, ResetTrigger::Sweep));
    until("attempt parks on the gated status fetch", || {
        mock.count(RESET_STATUS) == 1
    })
    .await;
    drop(manager);
    gate.notify_one();
    mock.set_status_gate(None);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.count(RESET_USE),
        0,
        "dropping the handle must cancel the queued episode before its use step"
    );
    assert!(reset_rows(&f.state, id).is_empty());
    mock.assert_no_violations();
}

#[tokio::test]
async fn state_holds_a_weak_autoreset_slot() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[spec("weak-slot", "active")]);
    let first = manager(
        &f.state,
        config(2, Duration::from_secs(1), Duration::from_secs(600)),
    );
    f.state
        .set_auto_reset(first.clone())
        .expect("the first installation must succeed");
    // Arc<AutoReset> has no Debug bound: never expect()/unwrap() the slot.
    match f.state.auto_reset() {
        Some(live) => assert!(
            Arc::ptr_eq(&live, &first),
            "the state slot must return the live manager"
        ),
        None => panic!("the live manager must be readable through the state slot"),
    }
    let second = manager(
        &f.state,
        config(2, Duration::from_secs(1), Duration::from_secs(600)),
    );
    assert_eq!(
        f.state.set_auto_reset(second.clone()).err(),
        Some(()),
        "a live occupant refuses a second installation"
    );
    shutdown(&first).await;
    drop(first);
    assert!(
        f.state.auto_reset().is_none(),
        "the state slot is weak: no strong reference outlives the manager"
    );
    f.state
        .set_auto_reset(second.clone())
        .expect("reinstalling after the occupant dropped must succeed");
    shutdown(&second).await;
    mock.assert_no_violations();
}

#[tokio::test]
async fn readonly_reset_status_and_history_sync_never_spend_with_switches_enabled() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[spec("readonly", "active")]);
    let id = f.id(0);
    let mut readable = status_body(&[slot_ms(600)], &[slot_ms(900)]);
    readable["data"]["latest_five_hour_reset_history"] = json!({"used_at": (NOW - 864_000) * 1000});
    mock.set_status(readable);
    enable(
        &f.state,
        &[
            ("auto_reset_enabled", "1"),
            ("auto_reset_expiry_enabled", "1"),
        ],
    );
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(1), Duration::from_secs(600)),
    );
    let (status, body) = call(&f.state, "GET", &format!("/api/accounts/{id}/reset-status")).await;
    assert_eq!(status, StatusCode::OK, "GET reset-status: {body}");
    assert_eq!(body["ok"], true, "GET reset-status: {body}");
    assert!(
        reset_rows(&f.state, id).is_empty(),
        "reads write no ledger rows"
    );

    let (status, body) = call(
        &f.state,
        "POST",
        &format!("/api/accounts/{id}/reset-history/sync"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "POST history sync: {body}");
    assert_eq!(
        body["upstream_synced"].as_i64(),
        Some(1),
        "history imports: {body}"
    );
    idle(&manager).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        mock.count(RESET_USE),
        0,
        "GET reset-status and POST history sync must stay non-spending with both switches on"
    );
    let rows = reset_rows(&f.state, id);
    assert_eq!(rows.len(), 1, "only the imported history row: {rows:?}");
    assert_eq!(rows[0].1, PLAN_MANUAL_FIVE_HOUR);
    assert!(rows[0].2);
    assert!(!zcode_proxy::autoreset::recent_spend(&f.state, id));
    mock.assert_no_violations();
    shutdown(&manager).await;
}

#[tokio::test]
async fn sweep_enqueues_eligible_expiry_accounts_without_inline_http() {
    let mock = Mock::start().await;
    let f = Fixture::new(
        &mock,
        &[cooling_spec("sweep-one"), cooling_spec("sweep-two")],
    );
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    let manager = manager(
        &f.state,
        config(1, Duration::from_secs(1), Duration::from_secs(600)),
    );
    let gate = Arc::new(Notify::new());
    mock.set_status_gate(Some(gate.clone()));
    assert!(manager.enqueue(f.id(0), ResetTrigger::Sweep));
    until("the only executor parks", || mock.count(RESET_STATUS) == 1).await;
    let swept = manager.sweep();
    assert!(
        swept >= 1,
        "sweep must enqueue the second eligible cooling account (returned {swept})"
    );
    assert_eq!(
        mock.count(RESET_STATUS),
        1,
        "sweep itself must not perform inline HTTP"
    );
    assert!(manager.pending().contains(&f.id(1)));

    let second_gate = Arc::new(Notify::new());
    mock.set_status_gate(Some(second_gate.clone()));
    gate.notify_one();
    until("the swept account evaluates", || {
        mock.count(RESET_STATUS) == 2
    })
    .await;
    second_gate.notify_one();
    mock.set_status_gate(None);
    until("both accounts spend", || mock.count(RESET_USE) == 2).await;
    idle(&manager).await;
    assert_eq!(reset_rows(&f.state, f.id(0)).len(), 1);
    assert_eq!(reset_rows(&f.state, f.id(1)).len(), 1);
    let report = shutdown(&manager).await;
    assert!(report.drained, "an idle manager drains cleanly");
    assert_eq!(report.cancelled, 0);
    assert!(report.abandoned.is_empty());
    mock.assert_no_violations();
}
