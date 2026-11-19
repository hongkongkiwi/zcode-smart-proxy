//! Independent trigger-wiring regressions for the automatic reset service
//! (Packet C; design: .agents/state/rust-migration/autoreset-service.md,
//! baseline 62347d8 where the manager exists but no trigger is wired).
//! Authored against the documented behavior BEFORE implementation using only
//! the existing public surface, so the red baseline is behavioral, never a
//! compile gap.
//!
//! Pins:
//! - free-channel exhaustion (HTTP 402 and the 2xx exhausted envelope)
//!   persists status=exhausted in the database before the mirror publishes
//!   it, then enqueues the Relay trigger when a manager is installed; both
//!   switches absent still persists the status but performs zero reset HTTP;
//!   a missing manager persists without fabricating work; opt-in performs
//!   the real reset status/use round trip and the automatic ledger row;
//! - paid-channel 402 and protocol passthrough (3104/3106/3402) never
//!   persist exhausted and never trigger;
//! - credential rotation, deletion, or disable racing the relay response
//!   suppresses both the status overwrite and the trigger;
//! - a failed exhausted-status database write reports 500 with no mirror
//!   change, no continued ladder, and no spend (no fire-and-forget write);
//! - a quota refresh that confirms exhaustion enqueues the Quota trigger
//!   only after the database commit and in-flight guards are released;
//!   non-exhausted and auth-failed refreshes never trigger; a failed
//!   refresh write triggers nothing;
//! - Scheduler::run_due_at admits plans and then sweeps the installed
//!   manager through the existing expiry switch only (no invented
//!   auto_reset_sweep_enabled setting; default OFF is inert); the configured
//!   tick interval exercises the same sweep; reset plans stay refused.

use std::{
    collections::HashMap,
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
use chrono::{Local, TimeZone};
use serde_json::{json, Value};
use tokio::sync::Notify;
use tower::ServiceExt;
use zcode_core::AccountView;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    autoreset::{recent_spend, AutoReset, AutoResetConfig},
    build_router,
    scheduler::{Scheduler, SchedulerConfig},
    state::{AppState, AutomationUrls, Creds, ManagementUrls, UpstreamUrls},
    store,
    vault::Vault,
};

const SESSION: &str = "PUBLIC-autoreset-trigger-session";
const VAULT_SEED: &str = "PUBLIC autoreset trigger fixture vault seed";
const VERSION: &str = "PUBLIC-autoreset-trigger-version";
const JWT_PREFIX: &str = "PUBLIC-atr-jwt-";
const KEY_PREFIX: &str = "PUBLIC-atr-key-";
const RELAY_FREE: &str = "/relay-free";
const RELAY_PAID: &str = "/relay-paid";
const RESET_STATUS: &str = "/api/v1/coding-plan/reset/status";
const RESET_USE: &str = "/api/v1/coding-plan/reset/use";
const BILLING_BALANCE: &str = "/api/v1/zcode-plan/billing/balance";
const BILLING_CURRENT: &str = "/api/v1/zcode-plan/billing/current";
const PREVIEW: &str = "/api/v1/zcode-plan/billing/preview";
const PLAN_AUTO_FIVE_HOUR: &str = "配额重置(FIVE_HOUR)[自动]";
const PLAN_AUTO_EXPIRY_FIVE_HOUR: &str = "配额重置(FIVE_HOUR)[自动-临期]";
const RESET_REFUSAL: &str = "重置仅支持在账号页面手动执行，不支持计划任务";
// Pinned decision clock: 2026-06-01T00:00:00Z. Threshold waits, slot windows,
// idempotency keys, and ledger stamps all derive from it. Anything the source
// filters through the wall clock (billing period_end freshness) anchors to
// now_secs() instead, so both clocks stay live and aligned per fixture.
const NOW: i64 = 1780272000;
// 2100-01-01T00:00:00Z: cooling stays cooling under the wall and injected clocks alike.
const COOLING_UNTIL: i64 = 4102444800;
const DEADLINE: Duration = Duration::from_secs(8);
const FIVE_HOUR_THRESHOLD_SECS: i64 = 3600;

// ---- synthetic loopback upstream ----

#[derive(Clone)]
struct Seen {
    method: String,
    path: String,
    bearer: String,
    body: Value,
}

#[derive(Clone)]
struct RelayResponse {
    status: StatusCode,
    body: Value,
}

#[derive(Default)]
struct Script {
    seen: Mutex<Vec<Seen>>,
    violations: Mutex<Vec<String>>,
    free: Mutex<HashMap<String, RelayResponse>>,
    free_default: Mutex<Option<RelayResponse>>,
    free_gate: Mutex<Option<Arc<Notify>>>,
    paid: Mutex<Option<RelayResponse>>,
    status_body: Mutex<Value>,
    billing: Mutex<HashMap<String, Value>>,
    billing_default: Mutex<Value>,
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
            let api_key = parts
                .headers
                .get("x-api-key")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let path = parts.uri.path().to_owned();
            let method = parts.method.as_str().to_owned();
            if path == RELAY_FREE || path == RELAY_PAID {
                let missing_credentials = (path == RELAY_FREE && !bearer.starts_with("Bearer "))
                    || (path == RELAY_PAID && api_key.is_empty());
                if missing_credentials {
                    script
                        .violations
                        .lock()
                        .unwrap()
                        .push(format!("{method} {path} arrived without relay credentials"));
                    return (StatusCode::UNAUTHORIZED, Json(json!({"code":401}))).into_response();
                }
                script.seen.lock().unwrap().push(Seen {
                    method: method.clone(),
                    path: path.clone(),
                    bearer: bearer.clone(),
                    body: payload,
                });
                if path == RELAY_FREE {
                    // Bind the cloned gate before awaiting: a guard held across
                    // an await makes this handler future !Send.
                    let gate = script.free_gate.lock().unwrap().clone();
                    if let Some(gate) = gate {
                        gate.notified().await;
                    }
                    let response = script
                        .free
                        .lock()
                        .unwrap()
                        .get(&bearer)
                        .cloned()
                        .or_else(|| script.free_default.lock().unwrap().clone());
                    return match response {
                        Some(response) => (response.status, Json(response.body)).into_response(),
                        None => {
                            script.violations.lock().unwrap().push(format!(
                                "{method} {path} hit an unscripted free relay response"
                            ));
                            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code":500})))
                                .into_response()
                        }
                    };
                }
                let response = script.paid.lock().unwrap().clone();
                return match response {
                    Some(response) => (response.status, Json(response.body)).into_response(),
                    None => {
                        script.violations.lock().unwrap().push(format!(
                            "{method} {path} hit an unscripted paid relay response"
                        ));
                        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code":500})))
                            .into_response()
                    }
                };
            }
            let bearer_ok = bearer
                .strip_prefix("Bearer ")
                .is_some_and(|token| token.starts_with(JWT_PREFIX));
            if !bearer_ok {
                script.violations.lock().unwrap().push(format!(
                    "{method} {path} arrived without the fixture JWT bearer"
                ));
                return (StatusCode::UNAUTHORIZED, Json(json!({"code":401}))).into_response();
            }
            script.seen.lock().unwrap().push(Seen {
                method: method.clone(),
                path: path.clone(),
                bearer: bearer.clone(),
                body: payload,
            });
            match (method.as_str(), path.as_str()) {
                ("GET", RESET_STATUS) => (
                    StatusCode::OK,
                    Json(script.status_body.lock().unwrap().clone()),
                )
                    .into_response(),
                ("POST", RESET_USE) => {
                    (StatusCode::OK, Json(json!({"code":0,"data":{"used":true}}))).into_response()
                }
                ("GET", BILLING_BALANCE) | ("GET", BILLING_CURRENT) => {
                    let body = script
                        .billing
                        .lock()
                        .unwrap()
                        .get(&bearer)
                        .cloned()
                        .unwrap_or_else(|| script.billing_default.lock().unwrap().clone());
                    (StatusCode::OK, Json(body)).into_response()
                }
                ("GET", PREVIEW) => {
                    (StatusCode::OK, Json(json!({"code":0,"data":{"plans":[]}}))).into_response()
                }
                _ => {
                    script
                        .violations
                        .lock()
                        .unwrap()
                        .push(format!("unexpected {method} {path}"));
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code":500}))).into_response()
                }
            }
        }
        let script = Arc::new(Script {
            seen: Mutex::new(Vec::new()),
            violations: Mutex::new(Vec::new()),
            free: Mutex::new(HashMap::new()),
            free_default: Mutex::new(None),
            free_gate: Mutex::new(None),
            paid: Mutex::new(None),
            status_body: Mutex::new(Value::Null),
            billing: Mutex::new(HashMap::new()),
            billing_default: Mutex::new(Value::Null),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(serve).with_state(script.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base, script, task }
    }

    fn set_free(&self, bearer: &str, status: StatusCode, body: Value) {
        self.script
            .free
            .lock()
            .unwrap()
            .insert(bearer.to_owned(), RelayResponse { status, body });
    }

    fn set_free_default(&self, status: StatusCode, body: Value) {
        *self.script.free_default.lock().unwrap() = Some(RelayResponse { status, body });
    }

    fn set_paid(&self, status: StatusCode, body: Value) {
        *self.script.paid.lock().unwrap() = Some(RelayResponse { status, body });
    }

    fn set_free_gate(&self, gate: Option<Arc<Notify>>) {
        *self.script.free_gate.lock().unwrap() = gate;
    }

    fn set_status(&self, body: Value) {
        *self.script.status_body.lock().unwrap() = body;
    }

    fn set_billing(&self, bearer: Option<&str>, body: Value) {
        match bearer {
            Some(bearer) => {
                self.script
                    .billing
                    .lock()
                    .unwrap()
                    .insert(bearer.to_owned(), body);
            }
            None => *self.script.billing_default.lock().unwrap() = body,
        }
    }

    fn seen_for(&self, path: &str) -> Vec<Seen> {
        self.script
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|seen| seen.path == path)
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
            .map(|seen| seen.body)
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

struct Seed {
    label: String,
    status: String,
    enabled: bool,
    cooling_until: i64,
    jwt: String,
    key: String,
    paid_fallback: bool,
}

fn dual(label: &str) -> Seed {
    Seed {
        label: label.into(),
        status: "active".into(),
        enabled: true,
        cooling_until: 0,
        jwt: jwt_for(label),
        key: key_for(label),
        paid_fallback: true,
    }
}

fn jwt_only(label: &str) -> Seed {
    Seed {
        key: String::new(),
        paid_fallback: false,
        ..dual(label)
    }
}

fn cooling(label: &str) -> Seed {
    Seed {
        status: "cooling".into(),
        cooling_until: COOLING_UNTIL,
        ..dual(label)
    }
}

fn jwt_for(label: &str) -> String {
    format!("{JWT_PREFIX}{label}")
}

fn key_for(label: &str) -> String {
    format!("{KEY_PREFIX}{label}")
}

fn seed_account(db: &rusqlite::Connection, vault: &Vault, seed: &Seed) -> i64 {
    let id = store::insert_account_encrypted(
        db,
        vault,
        &AccountView {
            email: format!("trigger-{}@example.invalid", seed.label),
            provider: "zai".into(),
            enabled: seed.enabled,
            status: seed.status.clone(),
            cooling_until: seed.cooling_until,
            paid_fallback: seed.paid_fallback,
            ..Default::default()
        },
        &seed.jwt,
        &seed.key,
    )
    .unwrap();
    let info = vault
        .encrypt(&json!({"id":format!("PUBLIC-atr-user-{}", seed.label)}).to_string())
        .unwrap();
    db.execute(
        "UPDATE accounts SET user_info=?1,device_mid=?2 WHERE id=?3",
        rusqlite::params![info, format!("PUBLIC-atr-mid-{}", seed.label), id],
    )
    .unwrap();
    id
}

fn mounted_state(db: rusqlite::Connection, vault: Vault, mock: &Mock) -> AppState {
    let mut state = AppState::try_from_db_with_vault(
        "root".into(),
        UpstreamUrls {
            zai: format!("{}{RELAY_FREE}", mock.base),
            zai_fallback: format!("{}{RELAY_PAID}", mock.base),
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
    fn new(mock: &Mock, seeds: &[Seed]) -> Self {
        let db = store::open(":memory:");
        let vault = Vault::from_secret(VAULT_SEED).unwrap();
        let ids = seeds
            .iter()
            .map(|seed| seed_account(&db, &vault, seed))
            .collect();
        Self {
            state: Arc::new(mounted_state(db, vault, mock)),
            ids,
            labels: seeds.iter().map(|seed| seed.label.clone()).collect(),
        }
    }

    fn id(&self, index: usize) -> i64 {
        self.ids[index]
    }

    fn jwt(&self, index: usize) -> String {
        jwt_for(&self.labels[index])
    }

    fn bearer(&self, index: usize) -> String {
        format!("Bearer {}", self.jwt(index))
    }
}

// ---- shared helpers ----

fn fixed_clock() -> Arc<dyn Fn() -> i64 + Send + Sync> {
    Arc::new(|| NOW)
}

fn config(capacity: usize, attempt_interval: Duration, retry_delay: Duration) -> AutoResetConfig {
    AutoResetConfig {
        capacity,
        attempt_interval,
        retry_delay,
        shutdown_wait: Duration::from_secs(1),
        clock: fixed_clock(),
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

async fn stop(manager: Arc<AutoReset>) {
    tokio::time::timeout(DEADLINE, manager.shutdown())
        .await
        .expect("autoreset shutdown must respect the bounded test deadline");
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

async fn relay(state: &Arc<AppState>, shape: Option<&str>) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("x-api-key", "root")
        .header("content-type", "application/json");
    if let Some(shape) = shape {
        builder = builder.header("x-zcode-rs-shape", shape);
    }
    let payload = json!({"model":"GLM-5.3","stream":false,
        "messages":[{"role":"user","content":"trigger wiring fixture"}]});
    let request = builder.body(Body::from(payload.to_string())).unwrap();
    let response = tokio::time::timeout(DEADLINE, build_router(state.clone()).oneshot(request))
        .await
        .expect("relay call exceeded the bounded loopback deadline")
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn call(
    state: &Arc<AppState>,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    let builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost:8080")
        .header("origin", "http://localhost:8080")
        .header("cookie", format!("{SESSION_COOKIE}={SESSION}"));
    let request = match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = tokio::time::timeout(DEADLINE, build_router(state.clone()).oneshot(request))
        .await
        .expect("admin call exceeded the bounded loopback deadline")
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn refresh(state: &Arc<AppState>, id: i64) -> (StatusCode, Value) {
    call(state, "POST", &format!("/api/accounts/{id}/refresh"), None).await
}

fn db_account(state: &AppState, id: i64) -> Option<(String, bool)> {
    state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT status,enabled FROM accounts WHERE id=?1",
            [id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? != 0)),
        )
        .ok()
}

fn db_status(state: &AppState, id: i64) -> String {
    db_account(state, id)
        .unwrap_or_else(|| panic!("account {id} must still exist in the database"))
        .0
}

fn db_quota_json(state: &AppState, id: i64) -> String {
    state
        .db
        .lock()
        .unwrap()
        .query_row("SELECT quota_json FROM accounts WHERE id=?1", [id], |row| {
            row.get::<_, String>(0)
        })
        .unwrap()
}

fn mirror_account(state: &AppState, id: i64) -> Option<AccountView> {
    state
        .accounts
        .lock()
        .unwrap()
        .iter()
        .find(|account| account.id == id)
        .cloned()
}

fn mirror_status(state: &AppState, id: i64) -> String {
    mirror_account(state, id)
        .unwrap_or_else(|| panic!("account {id} must still exist in the mirror"))
        .status
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
             WHERE account_id=?1 AND task_type='reset' ORDER BY id",
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

fn assert_auto_success_row(row: &ResetRow, expected_plan: &str) {
    assert_eq!(row.0, "reset", "automatic spends audit task reset: {row:?}");
    assert_eq!(row.1, expected_plan, "plan name: {row:?}");
    assert!(row.2, "expected a successful ledger row: {row:?}");
    assert_eq!(
        row.3, NOW,
        "used_at must be the injected clock in seconds: {row:?}"
    );
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
        .find(|account| account.id == id)
        .expect("fixture account must exist in the mirror")
        .enabled = false;
}

// Reimport shape: DB ciphertext and both mirrors move to fresh credentials,
// so only a re-read under the writer locks can detect the change.
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
        .find(|account| account.id == id)
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
    state
        .accounts
        .lock()
        .unwrap()
        .retain(|account| account.id != id);
    state.creds.lock().unwrap().remove(&id);
}

fn fixed() -> chrono::DateTime<Local> {
    Local.with_ymd_and_hms(2026, 11, 19, 9, 0, 0).unwrap()
}

fn sched_config(tick_interval: Duration, task_drain_wait: Duration) -> SchedulerConfig {
    let stamp = fixed();
    SchedulerConfig {
        tick_interval,
        clock: Arc::new(move || stamp),
        tick_stop_wait: Duration::from_secs(2),
        task_drain_wait,
    }
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

async fn create_plan(state: &Arc<AppState>, body: &Value) -> i64 {
    let (status, response) = call(state, "POST", "/api/plans", Some(body)).await;
    assert_eq!(status, StatusCode::OK, "POST /api/plans: {response}");
    response["id"]
        .as_i64()
        .unwrap_or_else(|| panic!("POST /api/plans must return an id: {response}"))
}

fn plan_row(state: &AppState, id: i64) -> (String, String, String) {
    state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT last_run_at,last_run_status,last_run_msg FROM claim_plans WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

/// The save route rejects reset plans, so the due-path refusal is probed on a
/// directly seeded row (defense in depth).
fn seed_reset_plan(state: &AppState) -> i64 {
    let db = state.db.lock().unwrap();
    db.execute(
        "INSERT INTO claim_plans(plan_name,cron_expr,is_active,target_type,account_id,
            account_group,task_type,auto_pick,delay_seconds)
         VALUES('trigger-reset-gate','* * * * *',1,'all_accounts',0,'','reset',1,0)",
        [],
    )
    .unwrap();
    db.last_insert_rowid()
}

fn billing(used: f64, period_end_ms: Option<i64>) -> Value {
    let mut balance = json!({"plan_id":"pro","show_name":"PUBLIC trigger quota",
        "total_units":100.0,"used_units":used,"remaining_units":100.0 - used});
    if let Some(period_end_ms) = period_end_ms {
        balance["period_end"] = json!(period_end_ms);
    }
    json!({"code":0,"success":true,"data":{"result":{
        "plans":[{"plan_id":"pro","name":"Pro","status":"active"}],
        "balances":[balance]
    }}})
}

fn exhausted_billing() -> Value {
    // The natural reset wait stays known-future under the injected decision
    // clock while passing normalize_billing's wall-clock freshness filter.
    billing(100.0, Some((now_secs() + 7200) * 1000))
}

// ---- relay trigger ----

#[tokio::test]
async fn free_channel_exhaustion_persists_status_and_stays_silent_with_switches_off() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[dual("free-402"), dual("free-envelope")]);
    mock.set_free(&f.bearer(0), StatusCode::PAYMENT_REQUIRED, json!({}));
    mock.set_free(
        &f.bearer(1),
        StatusCode::OK,
        json!({"code":1005,"msg":"exceed quota limit","type":"error"}),
    );
    mock.set_paid(
        StatusCode::OK,
        json!({"content":[{"type":"text","text":"ok"}]}),
    );
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(600), Duration::from_secs(5)),
    );
    f.state
        .set_auto_reset(manager.clone())
        .expect("installing the manager must succeed");

    let (status, body) = relay(&f.state, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the paid fallback still serves the request: {body}"
    );
    assert_eq!(
        mock.count(RELAY_FREE),
        2,
        "both accounts attempted the free channel"
    );
    assert_eq!(mock.count(RELAY_PAID), 1);
    for index in 0..2 {
        assert_eq!(
            db_status(&f.state, f.id(index)),
            "exhausted",
            "free-channel exhaustion must persist per account in the database"
        );
        assert_eq!(
            mirror_status(&f.state, f.id(index)),
            "exhausted",
            "the mirror must publish the same exhausted status"
        );
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.count(RESET_STATUS) + mock.count(RESET_USE),
        0,
        "both switches absent means zero reset HTTP even though the status is persisted"
    );
    assert!(
        autoreset_settings_rows(&f.state).is_empty(),
        "the relay path must not invent auto_reset_* settings"
    );
    for index in 0..2 {
        assert!(
            reset_rows(&f.state, f.id(index)).is_empty(),
            "no ledger rows while OFF"
        );
        assert!(
            !recent_spend(&f.state, f.id(index)),
            "no spend stamp while OFF"
        );
    }
    mock.assert_no_violations();
    stop(manager).await;
}

#[tokio::test]
async fn free_channel_exhaustion_without_a_manager_persists_status_without_spending() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[dual("no-manager")]);
    mock.set_free_default(StatusCode::PAYMENT_REQUIRED, json!({}));
    mock.set_paid(
        StatusCode::OK,
        json!({"content":[{"type":"text","text":"ok"}]}),
    );
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(
        &f.state,
        &[
            ("auto_reset_enabled", "1"),
            ("auto_reset_expiry_enabled", "1"),
        ],
    );
    assert!(
        f.state.auto_reset().is_none(),
        "this fixture deliberately installs no manager"
    );

    let (status, body) = relay(&f.state, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        db_status(&f.state, f.id(0)),
        "exhausted",
        "the status write must not depend on an installed manager"
    );
    assert_eq!(mirror_status(&f.state, f.id(0)), "exhausted");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.total(),
        2,
        "only the relay attempts: no manager means no fabricated reset work"
    );
    assert!(reset_rows(&f.state, f.id(0)).is_empty());
    mock.assert_no_violations();
}

#[tokio::test]
async fn relay_exhaustion_enqueues_the_real_threshold_spend_when_opted_in() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[dual("opt-402"), dual("opt-envelope")]);
    mock.set_free(&f.bearer(0), StatusCode::PAYMENT_REQUIRED, json!({}));
    mock.set_free(
        &f.bearer(1),
        StatusCode::OK,
        json!({"code":1005,"msg":"exceed quota limit","type":"error"}),
    );
    mock.set_paid(
        StatusCode::OK,
        json!({"content":[{"type":"text","text":"ok"}]}),
    );
    mock.set_status(status_body(&[slot_ms(86_400)], &[]));
    for index in 0..2 {
        set_quota_json(&f.state, f.id(index), Some(NOW + FIVE_HOUR_THRESHOLD_SECS));
    }
    enable(&f.state, &[("auto_reset_enabled", "1")]);
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(600), Duration::from_secs(5)),
    );
    f.state
        .set_auto_reset(manager.clone())
        .expect("installing the manager must succeed");

    let (status, body) = relay(&f.state, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    until("relay-triggered threshold spends for both accounts", || {
        mock.count(RESET_USE) == 2
    })
    .await;
    idle(&manager).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.count(RESET_STATUS),
        2,
        "one gated status fetch per trigger, no retries"
    );
    assert_eq!(
        mock.count(BILLING_BALANCE) + mock.count(BILLING_CURRENT),
        0,
        "the relay trigger must not fabricate quota refreshes"
    );
    for index in 0..2 {
        let rows = reset_rows(&f.state, f.id(index));
        assert_eq!(rows.len(), 1, "exactly one automatic spend: {rows:?}");
        assert_auto_success_row(&rows[0], PLAN_AUTO_FIVE_HOUR);
        assert_eq!(db_status(&f.state, f.id(index)), "exhausted");
        let quota: Value = serde_json::from_str(&db_quota_json(&f.state, f.id(index))).unwrap();
        assert_eq!(
            quota["next_reset"],
            json!(NOW + FIVE_HOUR_THRESHOLD_SECS),
            "the exhausted write must preserve the persisted quota snapshot"
        );
    }
    assert!(
        recent_spend(&f.state, f.id(0)),
        "a confirmed spend leaves a warm stamp"
    );
    mock.assert_no_violations();
    stop(manager).await;
}

#[tokio::test]
async fn paid_channel_402_never_persists_exhausted_or_triggers() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[dual("paid-402")]);
    mock.set_free_default(StatusCode::UNAUTHORIZED, json!({}));
    mock.set_paid(StatusCode::PAYMENT_REQUIRED, json!({}));
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(
        &f.state,
        &[
            ("auto_reset_enabled", "1"),
            ("auto_reset_expiry_enabled", "1"),
        ],
    );
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(600), Duration::from_secs(5)),
    );
    f.state
        .set_auto_reset(manager.clone())
        .expect("installing the manager must succeed");

    let (status, _body) = relay(&f.state, None).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "both channels fail the ladder"
    );
    assert_eq!(mock.count(RELAY_FREE), 1);
    assert_eq!(mock.count(RELAY_PAID), 1);
    assert_eq!(
        db_status(&f.state, f.id(0)),
        "active",
        "a paid-channel 402 must never mark the free channel exhausted"
    );
    assert_eq!(mirror_status(&f.state, f.id(0)), "active");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.count(RESET_STATUS) + mock.count(RESET_USE),
        0,
        "a paid-channel 402 must never trigger an automatic reset"
    );
    assert!(reset_rows(&f.state, f.id(0)).is_empty());
    assert!(!recent_spend(&f.state, f.id(0)));
    mock.assert_no_violations();
    stop(manager).await;
}

#[tokio::test]
async fn protocol_passthrough_3104_3106_3402_is_verbatim_and_never_triggers() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[dual("passthrough")]);
    mock.set_paid(
        StatusCode::OK,
        json!({"content":[{"type":"text","text":"ok"}]}),
    );
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(
        &f.state,
        &[
            ("auto_reset_enabled", "1"),
            ("auto_reset_expiry_enabled", "1"),
        ],
    );
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(600), Duration::from_secs(5)),
    );
    f.state
        .set_auto_reset(manager.clone())
        .expect("installing the manager must succeed");

    let cases = [
        (
            "off-peak",
            StatusCode::BAD_REQUEST,
            json!({"code":3104,"msg":"invalid off-peak ticket"}),
        ),
        (
            "off-peak",
            StatusCode::TOO_MANY_REQUESTS,
            json!({"code":3106,"msg":"off-peak window closed"}),
        ),
        (
            "highspeed",
            StatusCode::TOO_MANY_REQUESTS,
            json!({"provider_code":3402,"msg":"highspeed card required"}),
        ),
    ];
    for (shape, upstream_status, upstream_body) in cases {
        mock.set_free_default(upstream_status, upstream_body.clone());
        let (status, body) = relay(&f.state, Some(shape)).await;
        assert_eq!(
            status, upstream_status,
            "passthrough keeps the upstream status ({shape})"
        );
        assert_eq!(
            body, upstream_body,
            "passthrough keeps the upstream body verbatim ({shape})"
        );
        assert_eq!(
            db_status(&f.state, f.id(0)),
            "active",
            "a passthrough response must never persist exhaustion ({shape})"
        );
        assert_eq!(mirror_status(&f.state, f.id(0)), "active");
    }
    assert_eq!(
        mock.count(RELAY_PAID),
        0,
        "passthrough is terminal and never cascades to paid"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.count(RESET_STATUS) + mock.count(RESET_USE),
        0,
        "passthrough must never trigger an automatic reset"
    );
    assert!(reset_rows(&f.state, f.id(0)).is_empty());
    mock.assert_no_violations();
    stop(manager).await;
}

#[tokio::test]
async fn mid_request_rotation_deletion_and_disable_suppress_the_exhaustion_write() {
    for mutation in ["rotate", "delete", "disable"] {
        let mock = Mock::start().await;
        let label = format!("mutate-{mutation}");
        let f = Fixture::new(&mock, &[dual(&label)]);
        let id = f.id(0);
        mock.set_free_default(StatusCode::PAYMENT_REQUIRED, json!({}));
        mock.set_paid(
            StatusCode::OK,
            json!({"content":[{"type":"text","text":"ok"}]}),
        );
        mock.set_status(status_body(&[slot_ms(600)], &[]));
        enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
        let manager = manager(
            &f.state,
            config(1, Duration::from_secs(600), Duration::from_secs(5)),
        );
        f.state
            .set_auto_reset(manager.clone())
            .expect("installing the manager must succeed");
        let gate = Arc::new(Notify::new());
        mock.set_free_gate(Some(gate.clone()));
        let relay_state = f.state.clone();
        let request = tokio::spawn(async move { relay(&relay_state, None).await });
        until("the free attempt parks on the gated relay response", || {
            mock.count(RELAY_FREE) == 1
        })
        .await;
        match mutation {
            "rotate" => rotate_credentials(&f.state, id, &label),
            "delete" => delete_account(&f.state, id),
            "disable" => disable_account(&f.state, id),
            other => panic!("unknown mutation {other}"),
        }
        gate.notify_one();
        mock.set_free_gate(None);
        let (status, body) = request.await.expect("the relay task must not panic");
        assert_eq!(
            status,
            StatusCode::OK,
            "the paid fallback still serves the request: {body}"
        );
        match mutation {
            "rotate" => {
                assert_eq!(
                    db_status(&f.state, id),
                    "active",
                    "a rotated account must not be overwritten with exhausted"
                );
                let rotated = format!("{JWT_PREFIX}rotated-{label}");
                let mirror =
                    mirror_account(&f.state, id).expect("the rotated account stays mirrored");
                assert_eq!(mirror.status, "active");
                assert_eq!(mirror.zcode_jwt, rotated);
            }
            "delete" => {
                assert!(
                    db_account(&f.state, id).is_none(),
                    "a deleted account must not be resurrected by the status write"
                );
                assert!(
                    mirror_account(&f.state, id).is_none(),
                    "the mirror must not resurrect a deleted account"
                );
            }
            "disable" => {
                let (status_row, enabled) =
                    db_account(&f.state, id).expect("the disabled account keeps its row");
                assert_eq!(
                    status_row, "active",
                    "an exhausted write must not land on a disabled account"
                );
                assert!(!enabled, "the account stays disabled");
                let mirror =
                    mirror_account(&f.state, id).expect("the disabled account stays mirrored");
                assert_eq!(mirror.status, "active");
                assert!(!mirror.enabled);
            }
            _ => unreachable!("the mutation loop only feeds the three cases above"),
        }
        idle(&manager).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            mock.count(RESET_STATUS) + mock.count(RESET_USE),
            0,
            "a mutated account must never be enqueued by the relay trigger ({mutation})"
        );
        if mutation != "delete" {
            assert!(reset_rows(&f.state, id).is_empty());
        }
        mock.assert_no_violations();
        stop(manager).await;
    }
}

#[tokio::test]
async fn exhausted_status_db_failure_reports_500_without_mirror_change_or_spend() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[dual("persist-500")]);
    mock.set_free_default(StatusCode::PAYMENT_REQUIRED, json!({}));
    mock.set_paid(
        StatusCode::OK,
        json!({"content":[{"type":"text","text":"ok"}]}),
    );
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    f.state
        .db
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_exhausted_status_write BEFORE UPDATE ON accounts
             BEGIN SELECT RAISE(ABORT, 'PUBLIC fixture blocks the exhausted status write'); END;",
        )
        .unwrap();
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(600), Duration::from_secs(5)),
    );
    f.state
        .set_auto_reset(manager.clone())
        .expect("installing the manager must succeed");

    let (status, body) = relay(&f.state, None).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a failed exhausted-status write must fail the request, not fire-and-forget: {body}"
    );
    assert_eq!(
        mock.count(RELAY_PAID),
        0,
        "the ladder must not continue after the durable status write fails"
    );
    assert_eq!(db_status(&f.state, f.id(0)), "active");
    assert_eq!(
        mirror_status(&f.state, f.id(0)),
        "active",
        "no mirror publication without the database commit"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.count(RESET_STATUS) + mock.count(RESET_USE),
        0,
        "a failed status write must never enqueue a spend"
    );
    assert!(reset_rows(&f.state, f.id(0)).is_empty());
    assert!(!recent_spend(&f.state, f.id(0)));
    mock.assert_no_violations();
    stop(manager).await;
}

// ---- quota trigger ----

#[tokio::test]
async fn quota_refresh_confirmed_exhausted_enqueues_the_quota_trigger_after_commit() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[jwt_only("quota-exhausted")]);
    let id = f.id(0);
    mock.set_billing(None, exhausted_billing());
    mock.set_status(status_body(&[slot_ms(86_400)], &[]));
    enable(&f.state, &[("auto_reset_enabled", "1")]);
    // A long retry_delay turns a quota-refresh flight collision into a visible
    // stall: only an enqueue released after the refresh's commit and in-flight
    // guard can spend inside the bounded window.
    let manager = manager(
        &f.state,
        config(1, Duration::from_secs(600), Duration::from_secs(600)),
    );
    f.state
        .set_auto_reset(manager.clone())
        .expect("installing the manager must succeed");

    let (status, body) = refresh(&f.state, id).await;
    assert_eq!(status, StatusCode::OK, "refresh must succeed: {body}");
    assert_eq!(body["account"]["status"], "exhausted", "{body}");
    assert_eq!(db_status(&f.state, id), "exhausted");
    assert_eq!(mirror_status(&f.state, id), "exhausted");
    until("the quota trigger reaches the reset status fetch", || {
        mock.count(RESET_STATUS) == 1
    })
    .await;
    until("the quota trigger spends the threshold slot", || {
        mock.count(RESET_USE) == 1
    })
    .await;
    idle(&manager).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.count(RESET_STATUS),
        1,
        "no busy retry: the trigger must fire after the flight is released"
    );
    assert_eq!(
        mock.count(BILLING_BALANCE),
        1,
        "only the refresh's own billing fetch"
    );
    assert_eq!(mock.count(BILLING_CURRENT), 0);
    let rows = reset_rows(&f.state, id);
    assert_eq!(rows.len(), 1, "exactly one automatic spend: {rows:?}");
    assert_auto_success_row(&rows[0], PLAN_AUTO_FIVE_HOUR);
    mock.assert_no_violations();
    stop(manager).await;
}

#[tokio::test]
async fn quota_refresh_with_switches_off_persists_exhausted_with_zero_reset_http() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[jwt_only("quota-off")]);
    let id = f.id(0);
    mock.set_billing(None, exhausted_billing());
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(600), Duration::from_secs(5)),
    );
    f.state
        .set_auto_reset(manager.clone())
        .expect("installing the manager must succeed");

    let (status, body) = refresh(&f.state, id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["account"]["status"], "exhausted", "{body}");
    assert_eq!(db_status(&f.state, id), "exhausted");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.count(RESET_STATUS) + mock.count(RESET_USE),
        0,
        "the quota trigger stays silent while both switches are absent"
    );
    assert!(
        autoreset_settings_rows(&f.state).is_empty(),
        "the refresh path must not invent auto_reset_* settings"
    );
    assert!(reset_rows(&f.state, id).is_empty());
    assert!(!recent_spend(&f.state, id));
    mock.assert_no_violations();
    stop(manager).await;
}

#[tokio::test]
async fn non_exhausted_or_auth_failed_refresh_never_enqueues() {
    let mock = Mock::start().await;
    let f = Fixture::new(
        &mock,
        &[jwt_only("quota-active"), jwt_only("quota-auth-fail")],
    );
    mock.set_billing(Some(f.bearer(0).as_str()), billing(25.0, None));
    // Business code 401 on HTTP 200 is the auth-failure family the client maps
    // to FetchError::Auth before any monitor fallback.
    mock.set_billing(
        Some(f.bearer(1).as_str()),
        json!({"code":401,"msg":"PUBLIC trigger auth failure"}),
    );
    mock.set_billing(None, billing(25.0, None));
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(
        &f.state,
        &[
            ("auto_reset_enabled", "1"),
            ("auto_reset_expiry_enabled", "1"),
        ],
    );
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(600), Duration::from_secs(5)),
    );
    f.state
        .set_auto_reset(manager.clone())
        .expect("installing the manager must succeed");

    let (status, body) = refresh(&f.state, f.id(0)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["account"]["status"], "active",
        "a healthy quota keeps the account active: {body}"
    );
    let (status, body) = refresh(&f.state, f.id(1)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["account"]["status"], "invalid",
        "an auth failure marks the account invalid: {body}"
    );
    assert_eq!(db_status(&f.state, f.id(1)), "invalid");

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.count(RESET_STATUS) + mock.count(RESET_USE),
        0,
        "non-exhausted and auth-failed refreshes must never enqueue the quota trigger"
    );
    assert!(reset_rows(&f.state, f.id(0)).is_empty());
    assert!(reset_rows(&f.state, f.id(1)).is_empty());
    assert_eq!(mock.count(BILLING_BALANCE), 2);
    assert_eq!(mock.count(BILLING_CURRENT), 0);
    mock.assert_no_violations();
    stop(manager).await;
}

#[tokio::test]
async fn quota_trigger_db_failure_reports_500_and_never_enqueues() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[jwt_only("quota-500")]);
    let id = f.id(0);
    mock.set_billing(None, exhausted_billing());
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(
        &f.state,
        &[
            ("auto_reset_enabled", "1"),
            ("auto_reset_expiry_enabled", "1"),
        ],
    );
    f.state
        .db
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_refresh_status_write BEFORE UPDATE ON accounts
             BEGIN SELECT RAISE(ABORT, 'PUBLIC fixture blocks the refresh status write'); END;",
        )
        .unwrap();
    let manager = manager(
        &f.state,
        config(2, Duration::from_secs(600), Duration::from_secs(5)),
    );
    f.state
        .set_auto_reset(manager.clone())
        .expect("installing the manager must succeed");

    let (status, body) = refresh(&f.state, id).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "the refresh commit fails closed: {body}"
    );
    assert_eq!(
        body["error"]["message"], "storage operation failed",
        "{body}"
    );
    assert_eq!(db_status(&f.state, id), "active");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.count(RESET_STATUS) + mock.count(RESET_USE),
        0,
        "a failed refresh commit must never enqueue the quota trigger"
    );
    assert!(reset_rows(&f.state, id).is_empty());
    mock.assert_no_violations();
    stop(manager).await;
}

// ---- scheduler sweep trigger ----

// The plan target must stay disjoint from the swept account: the plan task and
// an automatic attempt share the per-account automation_inflight admission,
// so a collision would consume the attempt without a retry. Removing the
// plan target from the creds map is the documented sweep-ineligibility gate.
fn single_account_plan(name: &str, account_id: i64) -> Value {
    let mut body = plan_body(name);
    body["target_type"] = json!("single_account");
    body["account_id"] = json!(account_id);
    body
}

#[tokio::test]
async fn run_due_at_sweeps_eligible_expiry_accounts_after_plan_admission() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[dual("sweep-plan-target"), cooling("sweep-expiry")]);
    let plan_target = f.id(0);
    let swept = f.id(1);
    f.state.creds.lock().unwrap().remove(&plan_target);
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    let manager = manager(
        &f.state,
        config(1, Duration::from_secs(600), Duration::from_secs(5)),
    );
    f.state
        .set_auto_reset(manager.clone())
        .expect("installing the manager must succeed");
    let plan = create_plan(&f.state, &single_account_plan("sweep-detect", plan_target)).await;
    let scheduler = Scheduler::with_config(
        f.state.clone(),
        sched_config(Duration::from_secs(3600), Duration::from_secs(10)),
    );

    let claimed = scheduler.run_due_at(fixed()).await.unwrap();
    assert_eq!(claimed, vec![plan], "the due plan is admitted first");
    until("the swept account spends its expiring slot", || {
        mock.count(RESET_USE) == 1
    })
    .await;
    tokio::time::timeout(DEADLINE, scheduler.wait_idle())
        .await
        .expect("the admitted plan must finish inside the bounded deadline");
    idle(&manager).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.count(RESET_STATUS),
        1,
        "one sweep attempt for the one eligible account"
    );
    let preview = mock.seen_for(PREVIEW);
    assert_eq!(preview.len(), 1, "the admitted plan ran its detect task");
    assert_eq!(preview[0].method, "GET");
    assert_eq!(preview[0].bearer, format!("Bearer {}", f.jwt(0)));
    let payloads = mock.use_payloads();
    assert_eq!(
        payloads[0]["idempotency_key"],
        json!(format!("auto-expiry-{swept}-{}", NOW + 600)),
        "the sweep spends under the deterministic expiry idem"
    );
    let rows = reset_rows(&f.state, swept);
    assert_eq!(rows.len(), 1);
    assert_auto_success_row(&rows[0], PLAN_AUTO_EXPIRY_FIVE_HOUR);
    assert!(reset_rows(&f.state, plan_target).is_empty());
    assert_eq!(
        plan_row(&f.state, plan).1,
        "success",
        "the detect plan still completes normally"
    );
    assert_eq!(
        autoreset_settings_rows(&f.state),
        vec![("auto_reset_expiry_enabled".to_owned(), "1".to_owned())],
        "the sweep must reuse the existing expiry flag without inventing settings"
    );
    mock.assert_no_violations();
    stop(manager).await;
}

#[tokio::test]
async fn scheduler_sweep_with_switches_off_is_inert_and_invents_no_settings() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[cooling("sweep-off")]);
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    let manager = manager(
        &f.state,
        config(1, Duration::from_secs(600), Duration::from_secs(5)),
    );
    f.state
        .set_auto_reset(manager.clone())
        .expect("installing the manager must succeed");
    let plan = create_plan(&f.state, &plan_body("sweep-off-detect")).await;
    let scheduler = Scheduler::with_config(
        f.state.clone(),
        sched_config(Duration::from_secs(3600), Duration::from_secs(10)),
    );

    let claimed = scheduler.run_due_at(fixed()).await.unwrap();
    assert_eq!(claimed, vec![plan], "the plan machinery runs as usual");
    tokio::time::timeout(DEADLINE, scheduler.wait_idle())
        .await
        .expect("the detect plan must finish inside the bounded deadline");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.count(PREVIEW),
        1,
        "the detect plan did its one upstream call"
    );
    assert_eq!(
        mock.count(RESET_STATUS) + mock.count(RESET_USE),
        0,
        "default OFF means zero reset HTTP even after admission"
    );
    assert!(
        mock.total() <= 1,
        "no other remote HTTP may leave the process while OFF"
    );
    assert!(
        autoreset_settings_rows(&f.state).is_empty(),
        "no auto_reset_* setting (in particular no auto_reset_sweep_enabled) may be invented"
    );
    assert!(manager.pending().is_empty());
    assert!(reset_rows(&f.state, f.id(0)).is_empty());
    mock.assert_no_violations();
    stop(manager).await;
}

#[tokio::test]
async fn scheduler_tick_interval_exercises_the_sweep() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[dual("tick-plan-target"), cooling("tick-expiry")]);
    let plan_target = f.id(0);
    let swept = f.id(1);
    f.state.creds.lock().unwrap().remove(&plan_target);
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    let manager = manager(
        &f.state,
        config(1, Duration::from_secs(600), Duration::from_secs(5)),
    );
    f.state
        .set_auto_reset(manager.clone())
        .expect("installing the manager must succeed");
    let plan = create_plan(&f.state, &single_account_plan("tick-detect", plan_target)).await;
    let scheduler = Scheduler::with_config(
        f.state.clone(),
        sched_config(Duration::from_millis(100), Duration::from_secs(5)),
    );
    assert_eq!(
        scheduler.start().unwrap(),
        0,
        "reconcile-first finds nothing stale"
    );

    until("the tick's run_due_at sweeps the expiring account", || {
        mock.count(RESET_USE) == 1
    })
    .await;
    tokio::time::timeout(DEADLINE, scheduler.wait_idle())
        .await
        .expect("the ticked plan must finish inside the bounded deadline");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.count(RESET_STATUS),
        1,
        "repeated ticks in the same minute debounce to one attempt"
    );
    let rows = reset_rows(&f.state, swept);
    assert_eq!(rows.len(), 1);
    assert_auto_success_row(&rows[0], PLAN_AUTO_EXPIRY_FIVE_HOUR);
    assert_eq!(
        plan_row(&f.state, plan).1,
        "success",
        "the ticked plan ran to a terminal record"
    );
    let report = scheduler.shutdown().await;
    assert!(report.tick_stopped, "the configured tick must stop cleanly");
    mock.assert_no_violations();
    stop(manager).await;
}

#[tokio::test]
async fn reset_plans_stay_refused_while_the_sweep_is_installed() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, &[cooling("sweep-reset-gate")]);
    let swept = f.id(0);
    mock.set_status(status_body(&[slot_ms(600)], &[]));
    enable(&f.state, &[("auto_reset_expiry_enabled", "1")]);
    let manager = manager(
        &f.state,
        config(1, Duration::from_secs(600), Duration::from_secs(5)),
    );
    f.state
        .set_auto_reset(manager.clone())
        .expect("installing the manager must succeed");
    let plan = seed_reset_plan(&f.state);
    let scheduler = Scheduler::with_config(
        f.state.clone(),
        sched_config(Duration::from_secs(3600), Duration::from_secs(10)),
    );

    let claimed = scheduler.run_due_at(fixed()).await.unwrap();
    assert_eq!(
        claimed,
        vec![plan],
        "the reset plan is admitted and then refused inside the task"
    );
    tokio::time::timeout(DEADLINE, scheduler.wait_idle())
        .await
        .expect("the refused reset plan must finish immediately");
    let row = plan_row(&f.state, plan);
    assert_eq!(row.1, "failed");
    assert_eq!(row.2, RESET_REFUSAL, "reset stays manual-only");
    assert_eq!(
        mock.count(PREVIEW),
        0,
        "a refused reset plan touches no accounts"
    );
    until("the sweep still runs after the reset refusal", || {
        mock.count(RESET_USE) == 1
    })
    .await;
    idle(&manager).await;
    let rows = reset_rows(&f.state, swept);
    assert_eq!(rows.len(), 1);
    assert_auto_success_row(&rows[0], PLAN_AUTO_EXPIRY_FIVE_HOUR);
    mock.assert_no_violations();
    stop(manager).await;
}
