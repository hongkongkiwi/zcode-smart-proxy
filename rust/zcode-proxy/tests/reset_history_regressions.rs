//! Reset-history sync regressions for POST /api/accounts/:id/reset-history/sync.
//!
//! Ported from the Go upstream-history sync (reset.go SyncResetHistoryFromUpstream,
//! database_ops.go HasResetRecordNear) with the Rust-specific contract from the
//! route brief:
//! - session + same-origin gate, nested error envelope for failures;
//! - upstream latest_*_reset_history entries: >1e11 treated as milliseconds,
//!   epoch-scale values treated as seconds, invalid/nonpositive entries skipped,
//!   record used_at is the upstream value (never an invented "now");
//! - per-kind ledger rows (task reset, success, plan_name quota reset(KIND)) with
//!   kind-scoped dedup (exact, +-900s, legacy used_at=0 via localtime created_at
//!   +-5400s) and settings anchors reset_history_seen:{id} compared at second
//!   precision;
//! - dedup + insert + anchor commit atomically before the settings mirror; a
//!   failure keeps the anchor unadvanced and leaves no partial history, and a
//!   retry is immediate (no 10-minute throttle on failure);
//! - a successful sync throttles the account for 10 minutes without a second
//!   upstream call; a manual billing action in flight reports busy without any
//!   upstream call; an account deleted mid-fetch gets no stale commit;
//! - GET reset-status stays read-only: no ledger writes, no anchors, no reset/use.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    Json, Router,
};
use serde_json::{json, Value};
use tokio::sync::Notify;
use tower::ServiceExt;
use zcode_core::AccountView;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, AutomationUrls, ManagementUrls, UpstreamUrls},
    store,
    vault::Vault,
};

const SESSION: &str = "PUBLIC-reset-history-session";
const VAULT_SEED: &str = "PUBLIC reset-history fixture vault seed";
const VERSION: &str = "PUBLIC-reset-history-version";
const JWT: [&str; 2] = ["PUBLIC-reset-history-jwt-a", "PUBLIC-reset-history-jwt-b"];
const KEY: [&str; 2] = ["PUBLIC-reset-history-key-a", "PUBLIC-reset-history-key-b"];
const USER: [&str; 2] = ["PUBLIC-reset-history-user-a", "PUBLIC-reset-history-user-b"];
const MID: [&str; 2] = [
    "PUBLIC-reset-history-device-a",
    "PUBLIC-reset-history-device-b",
];
const EMAIL: [&str; 2] = [
    "reset-history-a@example.invalid",
    "reset-history-b@example.invalid",
];
const RESET_STATUS: &str = "/api/v1/coding-plan/reset/status";
const RESET_USE: &str = "/api/v1/coding-plan/reset/use";
const PLAN_FIVE_HOUR: &str = "配额重置(FIVE_HOUR)";
const PLAN_WEEK: &str = "配额重置(WEEK)";
const MS_CEILING: i64 = 100_000_000_000;
// 2100-01-01T00:00:00Z: far enough in the future to stay a valid slot expiry
// and never collide with a wall-clock "now" invented by the implementation.
const FIVE_HOUR_MS: i64 = 4102444800000;
const FIVE_HOUR_SECONDS: i64 = 4102444800;
const WEEK_MS: i64 = 4102445100000;
const WEEK_SECONDS: i64 = 4102445100;

#[derive(Clone)]
struct Seen {
    method: String,
    path: String,
    bearer: Option<String>,
    bigmodel_key: Option<String>,
}

struct Script {
    seen: Mutex<Vec<Seen>>,
    violations: Mutex<Vec<String>>,
    status_body: Mutex<Value>,
    fail_status: Mutex<bool>,
    status_gate: Mutex<Option<Arc<Notify>>>,
    use_gate: Mutex<Option<Arc<Notify>>>,
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
            let _ = axum::body::to_bytes(body, 1 << 20).await.unwrap();
            let bearer = parts
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let bigmodel_key = parts
                .headers
                .get("x-bigmodel-authorization")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            if !bearer
                .as_deref()
                .is_some_and(|b| JWT.iter().any(|j| b == format!("Bearer {j}")))
            {
                script
                    .violations
                    .lock()
                    .unwrap()
                    .push(format!("{} without a fixture bearer", parts.uri.path()));
                return (StatusCode::UNAUTHORIZED, Json(json!({"code":401})));
            }
            script.seen.lock().unwrap().push(Seen {
                method: parts.method.to_string(),
                path: parts.uri.path().into(),
                bearer,
                bigmodel_key,
            });
            // Bind the cloned gate first: a guard held in the if-let scrutinee
            // would live across the await and make the handler future !Send.
            let status_gate = script.status_gate.lock().unwrap().clone();
            if let Some(gate) = status_gate {
                gate.notified().await;
            }
            let path = parts.uri.path();
            if parts.method == "GET" && path == RESET_STATUS {
                if *script.fail_status.lock().unwrap() {
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(json!({"code":502,"msg":"PUBLIC reset status unavailable"})),
                    );
                }
                return (
                    StatusCode::OK,
                    Json(script.status_body.lock().unwrap().clone()),
                );
            }
            if parts.method == "POST" && path == RESET_USE {
                let use_gate = script.use_gate.lock().unwrap().clone();
                if let Some(gate) = use_gate {
                    gate.notified().await;
                }
                return (StatusCode::OK, Json(json!({"code":0,"data":{"used":true}})));
            }
            if parts.method == "GET"
                && matches!(
                    path,
                    "/api/v1/zcode-plan/billing/balance" | "/api/v1/zcode-plan/billing/current"
                )
            {
                return (
                    StatusCode::OK,
                    Json(json!({"code":0,"data":{"result":{
                        "plans":[{"plan_id":"start","name":"Start Plan","status":"active"}],
                        "balances":[{"plan_id":"start","show_name":"PUBLIC tokens",
                            "total_units":100,"used_units":0,"remaining_units":100}]
                    }}})),
                );
            }
            script
                .violations
                .lock()
                .unwrap()
                .push(format!("unexpected {} {}", parts.method, path));
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code":500})))
        }
        let script = Arc::new(Script {
            seen: Mutex::new(Vec::new()),
            violations: Mutex::new(Vec::new()),
            status_body: Mutex::new(history_status(Value::Null, Value::Null)),
            fail_status: Mutex::new(false),
            status_gate: Mutex::new(None),
            use_gate: Mutex::new(None),
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

    fn set_status_failure(&self, failing: bool) {
        *self.script.fail_status.lock().unwrap() = failing;
    }

    fn set_status_gate(&self, gate: Option<Arc<Notify>>) {
        *self.script.status_gate.lock().unwrap() = gate;
    }

    fn set_use_gate(&self, gate: Option<Arc<Notify>>) {
        *self.script.use_gate.lock().unwrap() = gate;
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

    fn assert_no_violations(&self) {
        let violations = self.script.violations.lock().unwrap();
        assert!(
            violations.is_empty(),
            "mock contract violations: {violations:?}"
        );
    }
}

fn history_status(five: Value, week: Value) -> Value {
    json!({"code":0,"data":{
        "available_five_hour_resets":[],
        "available_week_resets":[],
        "latest_five_hour_reset_history":five,
        "latest_week_reset_history":week,
        "has_unread_history":true
    }})
}

fn slots_status() -> Value {
    json!({"code":0,"data":{
        "available_five_hour_resets":[{"expire_at":FIVE_HOUR_MS}],
        "available_week_resets":[{"expire_at":WEEK_MS}],
        "latest_five_hour_reset_history":null,
        "latest_week_reset_history":null,
        "has_unread_history":false
    }})
}

fn anchor_key(id: i64) -> String {
    format!("reset_history_seen:{id}")
}

fn anchor_in_db(state: &AppState, id: i64) -> Option<Value> {
    let db = state.db.lock().unwrap();
    store::get_setting(&db, &anchor_key(id)).and_then(|raw| serde_json::from_str(&raw).ok())
}

fn anchor_in_mirror(state: &AppState, id: i64) -> Option<Value> {
    state
        .setting(&anchor_key(id))
        .and_then(|raw| serde_json::from_str(&raw).ok())
}

fn anchor_seconds(value: i64) -> i64 {
    if value > MS_CEILING {
        value / 1000
    } else {
        value
    }
}

fn sync_path(id: i64) -> String {
    format!("/api/accounts/{id}/reset-history/sync")
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
    let response = tokio::time::timeout(
        Duration::from_secs(8),
        build_router(state.clone()).oneshot(request),
    )
    .await
    .expect("reset-history request exceeded bounded loopback deadline")
    .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn assert_envelope(body: &Value, synced: i64, throttled: bool, busy: bool) {
    assert_eq!(body["ok"], true, "sync envelope: {body}");
    assert_eq!(
        body["upstream_synced"].as_i64(),
        Some(synced),
        "sync envelope upstream_synced: {body}"
    );
    assert_eq!(
        body["throttled"], throttled,
        "sync envelope throttled: {body}"
    );
    assert_eq!(body["busy"], busy, "sync envelope busy: {body}");
}

fn assert_no_credentials(body: &Value) {
    let text = body.to_string();
    for private in [JWT[0], JWT[1], KEY[0], KEY[1], "vault1:"] {
        assert!(
            !text.contains(private),
            "reset-history response exposed credential material: {body}"
        );
    }
}

fn sorted_rows(mut rows: Vec<Value>) -> Vec<Value> {
    rows.sort_by(|a, b| {
        a["used_at"]
            .as_i64()
            .cmp(&b["used_at"].as_i64())
            .then_with(|| a["plan_name"].as_str().cmp(&b["plan_name"].as_str()))
    });
    rows
}

fn history_rows(state: &AppState, id: i64) -> Vec<Value> {
    let db = state.db.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT task_type,plan_name,success,used_at FROM claim_records
             WHERE account_id=?1 ORDER BY id",
        )
        .unwrap();
    let rows = stmt
        .query_map([id], |r| {
            Ok(json!({
                "task_type":r.get::<_,String>(0)?,
                "plan_name":r.get::<_,String>(1)?,
                "success":r.get::<_,bool>(2)?,
                "used_at":r.get::<_,i64>(3)?,
            }))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    sorted_rows(rows)
}

fn seed_reset_record(
    state: &AppState,
    id: i64,
    email: &str,
    kind: &str,
    used_at: i64,
    created_at: &str,
) {
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO claim_records
                 (account_id,email,task_type,plan_name,success,code,message,used_at,created_at)
             VALUES(?1,?2,'reset',?3,1,0,'PUBLIC seeded local reset',?4,?5)",
            rusqlite::params![id, email, format!("配额重置({kind})"), used_at, created_at],
        )
        .unwrap();
}

fn local_stamp(state: &AppState, modifier: &str) -> String {
    state
        .db
        .lock()
        .unwrap()
        .query_row(
            &format!("SELECT datetime('now','localtime','{modifier}')"),
            [],
            |r| r.get(0),
        )
        .unwrap()
}

async fn until<F: Fn() -> bool>(label: &str, condition: F) {
    for _ in 0..600 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {label}");
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

fn seed_account(db: &rusqlite::Connection, vault: &Vault, index: usize) -> i64 {
    let id = store::insert_account_encrypted(
        db,
        vault,
        &AccountView {
            email: EMAIL[index].into(),
            enabled: true,
            status: "active".into(),
            paid_fallback: false,
            ..Default::default()
        },
        JWT[index],
        KEY[index],
    )
    .unwrap();
    let info = vault
        .encrypt(&json!({"id":USER[index]}).to_string())
        .unwrap();
    db.execute(
        "UPDATE accounts SET user_info=?1,device_mid=?2 WHERE id=?3",
        rusqlite::params![info, MID[index], id],
    )
    .unwrap();
    id
}

struct Fixture {
    state: Arc<AppState>,
    ids: Vec<i64>,
}

impl Fixture {
    fn new(mock: &Mock, accounts: usize) -> Self {
        let db = store::open(":memory:");
        let vault = Vault::from_secret(VAULT_SEED).unwrap();
        let ids = (0..accounts)
            .map(|i| seed_account(&db, &vault, i))
            .collect();
        Self {
            state: Arc::new(mounted_state(db, vault, mock)),
            ids,
        }
    }

    fn id(&self, index: usize) -> i64 {
        self.ids[index]
    }

    async fn sync(&self, index: usize) -> (StatusCode, Value) {
        call(&self.state, "POST", &sync_path(self.id(index))).await
    }
}

#[tokio::test]
async fn reset_history_sync_route_requires_session_same_origin_and_valid_account_ids() {
    let state = Arc::new(AppState::new(
        String::new(),
        UpstreamUrls {
            zai: "http://127.0.0.1:1/unused-relay".into(),
            zai_fallback: "http://127.0.0.1:1/unused-paid-relay".into(),
        },
    ));
    state
        .sessions
        .lock()
        .unwrap()
        .insert(SESSION.into(), now_secs() + 3600);
    let probe = |authenticated: bool, origin: &'static str, id: &'static str| {
        let state = state.clone();
        async move {
            let mut request = Request::builder()
                .method("POST")
                .uri(format!("/api/accounts/{id}/reset-history/sync"))
                .header("host", "localhost:8080")
                .header("origin", origin);
            if authenticated {
                request = request.header("cookie", format!("{SESSION_COOKIE}={SESSION}"));
            }
            let response = build_router(state)
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null),
            )
        }
    };
    let (status, _) = probe(false, "http://localhost:8080", "999999").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "no session must be rejected"
    );
    let (status, _) = probe(true, "https://untrusted.example.invalid", "999999").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "cross-origin POST must be rejected"
    );
    for (id, expected) in [
        ("not-an-id", StatusCode::BAD_REQUEST),
        ("999999", StatusCode::NOT_FOUND),
    ] {
        let (status, body) = probe(true, "http://localhost:8080", id).await;
        assert_eq!(
            status, expected,
            "/api/accounts/{id}/reset-history/sync returned {body}"
        );
        assert!(
            body["error"]["message"].is_string(),
            "sync errors must use the nested error envelope: {body}"
        );
    }
    assert!(state.accounts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn reset_history_sync_imports_both_kinds_with_second_precision_records_then_throttles() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, 1);
    let id = f.id(0);
    mock.set_status(history_status(
        json!({"used_at":FIVE_HOUR_MS}),
        json!({"used_at":WEEK_MS}),
    ));
    let (status, body) = f.sync(0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_envelope(&body, 2, false, false);
    assert_no_credentials(&body);
    assert_eq!(
        history_rows(&f.state, id),
        vec![
            json!({"task_type":"reset","plan_name":PLAN_FIVE_HOUR,"success":true,
                "used_at":FIVE_HOUR_SECONDS}),
            json!({"task_type":"reset","plan_name":PLAN_WEEK,"success":true,
                "used_at":WEEK_SECONDS}),
        ],
        "imported rows must carry upstream seconds, not invented wall-clock stamps"
    );
    let message: String = f
        .state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT message FROM claim_records WHERE account_id=?1 AND plan_name=?2",
            rusqlite::params![id, PLAN_FIVE_HOUR],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!message.is_empty(), "imported rows need an audit message");
    let expected_anchor = json!({"FIVE_HOUR":FIVE_HOUR_MS,"WEEK":WEEK_MS});
    assert_eq!(
        anchor_in_db(&f.state, id),
        Some(expected_anchor.clone()),
        "anchors store millisecond values per kind"
    );
    assert_eq!(anchor_in_mirror(&f.state, id), Some(expected_anchor));
    let status_calls = mock.seen_for(RESET_STATUS);
    assert_eq!(status_calls.len(), 1, "one upstream status call expected");
    assert_eq!(status_calls[0].method, "GET");
    assert_eq!(
        status_calls[0].bearer.as_deref(),
        Some(format!("Bearer {}", JWT[0]).as_str())
    );
    assert_eq!(status_calls[0].bigmodel_key.as_deref(), Some(KEY[0]));
    assert_eq!(
        mock.count(RESET_USE),
        0,
        "sync must never spend a reset slot"
    );
    let (status, body) = f.sync(0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_envelope(&body, 0, true, false);
    assert_eq!(
        mock.count(RESET_STATUS),
        1,
        "the success throttle must avoid a second upstream call"
    );
    assert_eq!(history_rows(&f.state, id).len(), 2);
    mock.assert_no_violations();
}

#[tokio::test]
async fn reset_history_sync_treats_epoch_scale_values_as_seconds_and_skips_invalid_entries() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, 2);
    let invalid_id = f.id(0);
    mock.set_status(history_status(
        json!({"used_at":0}),
        json!({"used_at":"not-a-timestamp"}),
    ));
    let (status, body) = f.sync(0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_envelope(&body, 0, false, false);
    assert!(
        history_rows(&f.state, invalid_id).is_empty(),
        "nonpositive or non-numeric used_at entries must be skipped"
    );
    if let Some(anchor) = anchor_in_db(&f.state, invalid_id) {
        assert!(
            anchor.get("FIVE_HOUR").is_none() && anchor.get("WEEK").is_none(),
            "invalid entries must not advance anchors: {anchor}"
        );
    }
    let seconds_id = f.id(1);
    mock.set_status(history_status(
        json!({"used_at":-5000}),
        json!({"used_at":FIVE_HOUR_SECONDS}),
    ));
    let (status, body) = f.sync(1).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_envelope(&body, 1, false, false);
    assert_eq!(
        history_rows(&f.state, seconds_id),
        vec![
            json!({"task_type":"reset","plan_name":PLAN_WEEK,"success":true,
            "used_at":FIVE_HOUR_SECONDS})
        ],
        "epoch-scale used_at must be stored verbatim as seconds"
    );
    assert_ne!(
        FIVE_HOUR_SECONDS,
        now_secs(),
        "fixture sanity: the pinned upstream stamp must never look like a fresh local timestamp"
    );
    let anchor = anchor_in_db(&f.state, seconds_id).expect("valid entry advances the anchor");
    let stored_week = anchor["WEEK"].as_i64().expect("week anchor is numeric");
    assert_eq!(anchor_seconds(stored_week), FIVE_HOUR_SECONDS);
    assert!(
        anchor.get("FIVE_HOUR").is_none(),
        "skipped entries must not advance their kind anchor: {anchor}"
    );
    mock.assert_no_violations();
}

#[tokio::test]
async fn reset_history_sync_dedup_is_kind_scoped_and_tolerant_but_anchored_per_kind() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, 2);
    let now = now_secs();
    let now_ms = now * 1000;
    let tolerant_id = f.id(0);
    seed_reset_record(
        &f.state,
        tolerant_id,
        EMAIL[0],
        "FIVE_HOUR",
        now - 600,
        &local_stamp(&f.state, "0 seconds"),
    );
    let seeded = json!({"WEEK":now_ms}).to_string();
    f.state
        .persist_settings(&[(&anchor_key(tolerant_id), seeded.as_str())])
        .unwrap();
    mock.set_status(history_status(
        json!({"used_at":now_ms}),
        json!({"used_at":now_ms}),
    ));
    let (status, body) = f.sync(0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_envelope(&body, 0, false, false);
    assert_eq!(
        history_rows(&f.state, tolerant_id),
        vec![json!({"task_type":"reset","plan_name":PLAN_FIVE_HOUR,"success":true,
            "used_at":now - 600})],
        "a local record within 900s suppresses the same kind, and an equal-second anchor suppresses its own kind"
    );
    assert_eq!(
        anchor_in_db(&f.state, tolerant_id),
        Some(json!({"FIVE_HOUR":now_ms,"WEEK":now_ms})),
        "a duplicate match still advances its kind anchor at millisecond precision"
    );
    let fresh_id = f.id(1);
    seed_reset_record(
        &f.state,
        fresh_id,
        EMAIL[1],
        "FIVE_HOUR",
        now - 1200,
        &local_stamp(&f.state, "0 seconds"),
    );
    mock.set_status(history_status(json!({"used_at":now_ms}), Value::Null));
    let (status, body) = f.sync(1).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_envelope(&body, 1, false, false);
    assert_eq!(
        history_rows(&f.state, fresh_id),
        vec![
            json!({"task_type":"reset","plan_name":PLAN_FIVE_HOUR,"success":true,
                "used_at":now - 1200}),
            json!({"task_type":"reset","plan_name":PLAN_FIVE_HOUR,"success":true,"used_at":now}),
        ],
        "a local record 1200s away is not a duplicate"
    );
    assert_eq!(
        anchor_in_db(&f.state, fresh_id),
        Some(json!({"FIVE_HOUR":now_ms})),
        "only the synced kind may appear in the anchor"
    );
    mock.assert_no_violations();
}

#[tokio::test]
async fn reset_history_sync_matches_legacy_rows_through_local_created_at_wall_clock() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, 1);
    let id = f.id(0);
    let now = now_secs();
    let now_ms = now * 1000;
    seed_reset_record(
        &f.state,
        id,
        EMAIL[0],
        "FIVE_HOUR",
        0,
        &local_stamp(&f.state, "0 seconds"),
    );
    seed_reset_record(
        &f.state,
        id,
        EMAIL[0],
        "WEEK",
        0,
        &local_stamp(&f.state, "-7200 seconds"),
    );
    mock.set_status(history_status(
        json!({"used_at":now_ms}),
        json!({"used_at":now_ms}),
    ));
    let (status, body) = f.sync(0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_envelope(&body, 1, false, false);
    assert_eq!(
        history_rows(&f.state, id),
        vec![
            json!({"task_type":"reset","plan_name":PLAN_FIVE_HOUR,"success":true,"used_at":0}),
            json!({"task_type":"reset","plan_name":PLAN_WEEK,"success":true,"used_at":0}),
            json!({"task_type":"reset","plan_name":PLAN_WEEK,"success":true,"used_at":now}),
        ],
        "a legacy row created now is a duplicate; one created two hours ago is not"
    );
    assert_eq!(
        anchor_in_db(&f.state, id),
        Some(json!({"FIVE_HOUR":now_ms,"WEEK":now_ms})),
        "both kinds advance: the duplicate by legacy match, the fresh one by insert"
    );
    mock.assert_no_violations();
}

#[tokio::test]
async fn reset_history_sync_upstream_failure_is_a_500_without_side_effects_and_retry_is_immediate()
{
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, 1);
    let id = f.id(0);
    mock.set_status(history_status(
        json!({"used_at":FIVE_HOUR_MS}),
        json!({"used_at":WEEK_MS}),
    ));
    mock.set_status_failure(true);
    let (status, body) = f.sync(0).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a failed sync must fail closed: {body}"
    );
    assert!(
        body["error"]["message"].is_string(),
        "sync failures use the nested error envelope: {body}"
    );
    assert!(
        history_rows(&f.state, id).is_empty(),
        "no history may be recorded when the upstream fetch failed"
    );
    assert_eq!(anchor_in_db(&f.state, id), None, "anchors stay unadvanced");
    assert_eq!(anchor_in_mirror(&f.state, id), None);
    assert_eq!(mock.count(RESET_USE), 0);
    assert_eq!(mock.count(RESET_STATUS), 1);
    mock.set_status_failure(false);
    let (status, body) = f.sync(0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_envelope(&body, 2, false, false);
    assert_eq!(
        mock.count(RESET_STATUS),
        2,
        "a failed sync must not consume the 10-minute throttle"
    );
    assert_eq!(history_rows(&f.state, id).len(), 2);
    assert_eq!(
        anchor_in_db(&f.state, id),
        Some(json!({"FIVE_HOUR":FIVE_HOUR_MS,"WEEK":WEEK_MS}))
    );
    mock.assert_no_violations();
}

#[tokio::test]
async fn reset_history_sync_rolls_back_history_when_anchor_persistence_fails() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, 1);
    let id = f.id(0);
    mock.set_status(history_status(
        json!({"used_at":FIVE_HOUR_MS}),
        json!({"used_at":WEEK_MS}),
    ));
    f.state
        .db
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_anchor_insert BEFORE INSERT ON settings
                 WHEN NEW.key LIKE 'reset_history_seen%'
             BEGIN SELECT RAISE(ABORT, 'PUBLIC fixture blocks anchor insert'); END;
             CREATE TRIGGER reject_anchor_update BEFORE UPDATE ON settings
                 WHEN NEW.key LIKE 'reset_history_seen%'
             BEGIN SELECT RAISE(ABORT, 'PUBLIC fixture blocks anchor update'); END;",
        )
        .unwrap();
    let (status, body) = f.sync(0).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "anchor persistence failure must fail the whole sync: {body}"
    );
    assert!(
        body["error"]["message"].is_string(),
        "sync failures use the nested error envelope: {body}"
    );
    assert!(
        history_rows(&f.state, id).is_empty(),
        "ledger inserts must roll back with the anchor write; partial history is forbidden"
    );
    assert_eq!(anchor_in_db(&f.state, id), None);
    assert_eq!(anchor_in_mirror(&f.state, id), None);
    assert_eq!(mock.count(RESET_STATUS), 1);
    f.state
        .db
        .lock()
        .unwrap()
        .execute_batch(
            "DROP TRIGGER reject_anchor_insert;
             DROP TRIGGER reject_anchor_update;",
        )
        .unwrap();
    let (status, body) = f.sync(0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_envelope(&body, 2, false, false);
    assert_eq!(
        mock.count(RESET_STATUS),
        2,
        "retry after the failed commit must be immediate"
    );
    assert_eq!(history_rows(&f.state, id).len(), 2);
    assert_eq!(
        anchor_in_db(&f.state, id),
        Some(json!({"FIVE_HOUR":FIVE_HOUR_MS,"WEEK":WEEK_MS}))
    );
    mock.assert_no_violations();
}

#[tokio::test]
async fn reset_history_sync_skips_http_while_a_manual_reset_holds_the_account() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, 1);
    let id = f.id(0);
    let mut busy_status = slots_status();
    busy_status["data"]["latest_five_hour_reset_history"] = json!({"used_at":FIVE_HOUR_MS});
    mock.set_status(busy_status);
    let gate = Arc::new(Notify::new());
    mock.set_use_gate(Some(gate.clone()));
    let reset_state = f.state.clone();
    let reset_task = tokio::spawn(async move {
        call(&reset_state, "POST", &format!("/api/accounts/{id}/reset")).await
    });
    until("manual reset status fetch", || {
        mock.count(RESET_STATUS) == 1
    })
    .await;
    let (status, body) = f.sync(0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_envelope(&body, 0, false, true);
    assert_eq!(
        mock.count(RESET_STATUS),
        1,
        "a busy account must skip the upstream call entirely"
    );
    gate.notify_one();
    let (reset_status, reset_body) = reset_task.await.unwrap();
    assert_eq!(reset_status, StatusCode::OK, "manual reset: {reset_body}");
    assert_eq!(reset_body["ok"], true, "manual reset: {reset_body}");
    assert_eq!(
        mock.count(RESET_USE),
        1,
        "only the manual reset may spend a slot"
    );
    let rows = history_rows(&f.state, id);
    assert_eq!(rows.len(), 1, "only the manual reset's own row: {rows:?}");
    assert_eq!(rows[0]["task_type"], "reset");
    assert_eq!(rows[0]["plan_name"], PLAN_FIVE_HOUR);
    assert_eq!(rows[0]["success"], true);
    assert!(
        rows[0]["used_at"].as_i64().is_some_and(|n| n > 0),
        "the manual row stamps its own execution time: {rows:?}"
    );
    assert_eq!(
        anchor_in_db(&f.state, id),
        None,
        "the manual path must not write upstream-history anchors"
    );
    mock.assert_no_violations();
}

#[tokio::test]
async fn reset_history_sync_discards_history_when_the_account_is_deleted_mid_fetch() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, 1);
    let id = f.id(0);
    mock.set_status(history_status(json!({"used_at":FIVE_HOUR_MS}), Value::Null));
    let gate = Arc::new(Notify::new());
    mock.set_status_gate(Some(gate.clone()));
    let sync_state = f.state.clone();
    let sync_task = tokio::spawn(async move { call(&sync_state, "POST", &sync_path(id)).await });
    until("in-flight status fetch", || mock.count(RESET_STATUS) == 1).await;
    let (delete_status, delete_body) =
        call(&f.state, "DELETE", &format!("/api/accounts/{id}")).await;
    assert_eq!(delete_status, StatusCode::OK, "{delete_body}");
    assert_eq!(delete_body["ok"], true, "{delete_body}");
    gate.notify_one();
    let _ = sync_task.await.unwrap();
    assert!(
        history_rows(&f.state, id).is_empty(),
        "a deleted account must not receive stale history"
    );
    let stale_anchors: i64 = f
        .state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(1) FROM settings WHERE key LIKE 'reset_history_seen%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        stale_anchors, 0,
        "no anchor may outlive the deleted account"
    );
    assert_eq!(anchor_in_mirror(&f.state, id), None);
    assert!(f.state.accounts.lock().unwrap().iter().all(|a| a.id != id));
    mock.assert_no_violations();
}

#[tokio::test]
async fn reset_history_sync_anchor_persists_across_state_reload_from_the_same_vault() {
    let mock = Mock::start().await;
    let db = store::open(":memory:");
    let vault = Vault::from_secret(VAULT_SEED).unwrap();
    let id = seed_account(&db, &vault, 0);
    let state = mounted_state(db, vault, &mock);
    let state = Arc::new(state);
    mock.set_status(history_status(json!({"used_at":FIVE_HOUR_MS}), Value::Null));
    let (status, body) = call(&state, "POST", &sync_path(id)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_envelope(&body, 1, false, false);
    assert_eq!(history_rows(&state, id).len(), 1);
    let state = match Arc::try_unwrap(state) {
        Ok(state) => state,
        // AppState intentionally has no Debug impl (it carries credential
        // material), so the residual Arc is never formatted.
        Err(_) => panic!("router requests must all complete before unwrapping the fixture state"),
    };
    let db = state.db.into_inner().unwrap();
    let reloaded = Arc::new(mounted_state(
        db,
        Vault::from_secret(VAULT_SEED).unwrap(),
        &mock,
    ));
    let (status, body) = call(&reloaded, "POST", &sync_path(id)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["ok"], true,
        "reloaded state must serve the sync route: {body}"
    );
    assert_eq!(
        body["upstream_synced"].as_i64(),
        Some(0),
        "a reloaded anchor must suppress a duplicate insert: {body}"
    );
    assert_eq!(
        history_rows(&reloaded, id).len(),
        1,
        "the reloaded ledger must keep exactly the original row"
    );
    let expected = json!({"FIVE_HOUR":FIVE_HOUR_MS});
    assert_eq!(anchor_in_db(&reloaded, id), Some(expected.clone()));
    assert_eq!(anchor_in_mirror(&reloaded, id), Some(expected));
    mock.assert_no_violations();
}

#[tokio::test]
async fn reset_history_sync_keeps_accounts_isolated_for_identical_upstream_history() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, 2);
    mock.set_status(history_status(json!({"used_at":FIVE_HOUR_MS}), Value::Null));
    let (status, body) = f.sync(0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_envelope(&body, 1, false, false);
    let (status, body) = f.sync(1).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_envelope(&body, 1, false, false);
    let expected_row = vec![json!({"task_type":"reset","plan_name":PLAN_FIVE_HOUR,
        "success":true,"used_at":FIVE_HOUR_SECONDS})];
    assert_eq!(history_rows(&f.state, f.id(0)), expected_row.clone());
    assert_eq!(
        history_rows(&f.state, f.id(1)),
        expected_row,
        "one account's ledger row must never dedup another account's identical history"
    );
    let expected_anchor = Some(json!({"FIVE_HOUR":FIVE_HOUR_MS}));
    assert_eq!(anchor_in_db(&f.state, f.id(0)), expected_anchor.clone());
    assert_eq!(anchor_in_db(&f.state, f.id(1)), expected_anchor);
    let bearers: Vec<_> = mock
        .seen_for(RESET_STATUS)
        .iter()
        .map(|s| s.bearer.clone())
        .collect();
    assert_eq!(
        bearers,
        vec![
            Some(format!("Bearer {}", JWT[0])),
            Some(format!("Bearer {}", JWT[1])),
        ],
        "each account's sync must use its own credentials in order"
    );
    mock.assert_no_violations();
}

#[tokio::test]
async fn reset_status_get_stays_read_only_with_no_history_sync_or_slot_spend() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, 1);
    let id = f.id(0);
    let mut readable = slots_status();
    readable["data"]["latest_five_hour_reset_history"] = json!({"used_at":FIVE_HOUR_MS});
    readable["data"]["latest_week_reset_history"] = json!({"used_at":WEEK_MS});
    mock.set_status(readable);
    let (status, body) = call(&f.state, "GET", &format!("/api/accounts/{id}/reset-status")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["ok"], true, "{body}");
    assert_eq!(
        body["upstream_synced"].as_i64(),
        Some(0),
        "the read-only route must never report imported history: {body}"
    );
    assert_eq!(
        body["status"]["available_five_hour_resets"][0]["expire_at"], FIVE_HOUR_SECONDS,
        "slot expiries stay millisecond-normalized on read: {body}"
    );
    assert_eq!(
        mock.count(RESET_USE),
        0,
        "available slots must never be spent by a read"
    );
    assert!(history_rows(&f.state, id).is_empty());
    assert_eq!(anchor_in_db(&f.state, id), None);
    assert_eq!(anchor_in_mirror(&f.state, id), None);
    mock.assert_no_violations();
}
