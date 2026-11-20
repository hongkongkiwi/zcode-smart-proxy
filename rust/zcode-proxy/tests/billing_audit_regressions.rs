//! Manual billing audit regressions.
//!
//! Contracts pinned here:
//! - A remote-acknowledged manual claim keeps its claim_records audit row even
//!   when the account is deleted through the canonical DELETE session route
//!   while the upstream HTTP flight is still pending; the deleted account is
//!   not resurrected, and the response reports the acknowledged remote result
//!   instead of a false local persistence failure.
//! - Activation confirmed with positive quota recovers inactive/exhausted
//!   routing state (live and durable) while an administrator disable sticks
//!   (Go reference: activity.go ActivateForAccount, zcode_api.go
//!   applyQuotaResult, database_accounts.go tryRecoverActive).
//! - A genuine ledger INSERT failure still fails closed with the explicit
//!   local-persistence error and leaves the account summary, quota snapshot,
//!   and live state untouched.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    Json, Router,
};
use serde_json::{json, Value};
use tokio::sync::Notify;
use tower::ServiceExt;
use zcode_core::{egress::CaptchaSolver, AccountView};
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, AutomationUrls, ManagementUrls, UpstreamUrls},
    store,
    vault::Vault,
};

const SESSION: &str = "PUBLIC-billing-audit-session";
const JWT: &str = "PUBLIC-billing-audit-jwt";
const KEY: &str = "PUBLIC-billing-audit-api-key";
const VERSION: &str = "PUBLIC-billing-audit-version";
const MID: &str = "PUBLIC-billing-audit-device";
const USER: &str = "PUBLIC-billing-audit-user";
const SCENE: &str = "PUBLIC-billing-audit-scene";
const PREFIX: &str = "PUBLIC-billing-audit-prefix";
const REGION: &str = "PUBLIC-billing-audit-region";
const PREVIEW: &str = "/api/v1/zcode-plan/billing/preview";
const CLAIM: &str = "/api/v1/zcode-plan/billing/claim";
const EVENT: &str = "/api/v1/event/report";
const BALANCE: &str = "/api/v1/zcode-plan/billing/balance";
const SENTINEL_QUOTA: &str = r#"{"PUBLIC":"audit-sentinel"}"#;

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    headers: HeaderMap,
    body: Value,
}

struct Step {
    method: &'static str,
    path: &'static str,
    body: Value,
    gate: Option<Arc<Gate>>,
}

/// Parks a mocked upstream response until the test releases it.
#[derive(Default)]
struct Gate {
    entered: Notify,
    release: Notify,
}

#[derive(Default)]
struct Script {
    steps: Mutex<VecDeque<Step>>,
    seen: Mutex<Vec<Seen>>,
    violations: Mutex<Vec<String>>,
    balance: Mutex<Value>,
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
            let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap();
            let seen = Seen {
                method: parts.method.to_string(),
                path: parts.uri.path().into(),
                headers: parts.headers.clone(),
                body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            };
            script.seen.lock().unwrap().push(seen.clone());
            let authorized = seen
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                == Some(format!("Bearer {JWT}").as_str());
            if !authorized {
                script
                    .violations
                    .lock()
                    .unwrap()
                    .push(format!("{} {} missing JWT bearer", seen.method, seen.path));
                return (StatusCode::UNAUTHORIZED, Json(json!({"code":401})));
            }
            if seen.path == BALANCE && seen.method == "GET" {
                return (StatusCode::OK, Json(script.balance.lock().unwrap().clone()));
            }
            let step = script.steps.lock().unwrap().pop_front();
            let Some(step) = step else {
                script
                    .violations
                    .lock()
                    .unwrap()
                    .push(format!("unexpected {} {}", seen.method, seen.path));
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code":500})));
            };
            if seen.method != step.method || seen.path != step.path {
                script.violations.lock().unwrap().push(format!(
                    "expected {} {}, got {} {}",
                    step.method, step.path, seen.method, seen.path
                ));
                return (StatusCode::BAD_REQUEST, Json(json!({"code":3001})));
            }
            if seen.path == CLAIM {
                let solved = seen
                    .headers
                    .get("x-aliyun-captcha-verify-param")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.starts_with("PUBLIC-solved-"));
                let region = seen
                    .headers
                    .get("x-aliyun-captcha-verify-region")
                    .and_then(|v| v.to_str().ok())
                    == Some(REGION);
                if !solved || !region {
                    script
                        .violations
                        .lock()
                        .unwrap()
                        .push("claim without explicit solver fixture headers".into());
                    return (
                        StatusCode::OK,
                        Json(json!({"code":3007,"msg":"PUBLIC captcha required"})),
                    );
                }
            }
            if let Some(gate) = step.gate {
                gate.entered.notify_one();
                gate.release.notified().await;
            }
            (StatusCode::OK, Json(step.body))
        }
        let script = Arc::new(Script::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(serve).with_state(script.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base, script, task }
    }

    fn push(&self, method: &'static str, path: &'static str, body: Value) {
        self.script.steps.lock().unwrap().push_back(Step {
            method,
            path,
            body,
            gate: None,
        });
    }

    fn push_gated(&self, method: &'static str, path: &'static str, body: Value) -> Arc<Gate> {
        let gate = Arc::new(Gate::default());
        self.script.steps.lock().unwrap().push_back(Step {
            method,
            path,
            body,
            gate: Some(gate.clone()),
        });
        gate
    }

    fn seen(&self, path: &str) -> Vec<Seen> {
        self.script
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.path == path)
            .cloned()
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

struct Solver {
    answers: Mutex<VecDeque<String>>,
    calls: Mutex<Vec<(String, String)>>,
}

impl Solver {
    fn with(answers: &[&str]) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.iter().map(|s| (*s).to_owned()).collect()),
            calls: Mutex::new(Vec::new()),
        })
    }
}

impl CaptchaSolver for Solver {
    fn solve(&self, scene: &str, prefix: &str) -> Option<String> {
        self.calls
            .lock()
            .unwrap()
            .push((scene.into(), prefix.into()));
        self.answers.lock().unwrap().pop_front()
    }
}

struct Fixture {
    state: Arc<AppState>,
    id: i64,
}

impl Fixture {
    fn new(mock: &Mock, solver: Option<Arc<Solver>>, status: &str, enabled: bool) -> Self {
        let db = store::open(":memory:");
        let vault = Vault::from_secret("PUBLIC billing audit fixture vault seed").unwrap();
        let id = store::insert_account_encrypted(
            &db,
            &vault,
            &AccountView {
                email: "billing-audit@example.invalid".into(),
                enabled,
                status: status.into(),
                paid_fallback: false,
                ..Default::default()
            },
            JWT,
            KEY,
        )
        .unwrap();
        let info = vault.encrypt(&json!({"id":USER}).to_string()).unwrap();
        db.execute(
            "UPDATE accounts SET user_info=?1,device_mid=?2 WHERE id=?3",
            rusqlite::params![info, MID, id],
        )
        .unwrap();
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
            reset_status: format!("{}/forbidden-reset-status", mock.base),
            reset_use: format!("{}/forbidden-reset-use", mock.base),
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
        Self {
            state: Arc::new(state),
            id,
        }
    }
}

async fn admin_call(state: &Arc<AppState>, method: &str, uri: String) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
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
    .expect("admin route exceeded bounded loopback deadline")
    .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

fn assert_no_credentials(body: &Value) {
    let text = body.to_string();
    for private in [JWT, KEY, "vault1:"] {
        assert!(
            !text.contains(private),
            "billing response exposed credential material"
        );
    }
}

fn ledger_rows(state: &Arc<AppState>, id: i64) -> Vec<Value> {
    let db = state.db.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT task_type,plan_id,plan_name,success,code,message,next_at,used_at,email
             FROM claim_records WHERE account_id=?1 ORDER BY id",
        )
        .unwrap();
    let rows = stmt
        .query_map([id], |r| {
            Ok(json!({
                "task_type": r.get::<_, String>(0)?,
                "plan_id": r.get::<_, String>(1)?,
                "plan_name": r.get::<_, String>(2)?,
                "success": r.get::<_, bool>(3)?,
                "code": r.get::<_, i64>(4)?,
                "message": r.get::<_, String>(5)?,
                "next_at": r.get::<_, i64>(6)?,
                "used_at": r.get::<_, i64>(7)?,
                "email": r.get::<_, String>(8)?,
            }))
        })
        .unwrap();
    rows.collect::<Result<Vec<_>, _>>().unwrap()
}

fn account_row(state: &Arc<AppState>, id: i64) -> Option<Value> {
    let db = state.db.lock().unwrap();
    db.query_row(
        "SELECT status,enabled,remaining,cooling_until,quota_json,plan_tier,plan_expire,
            last_claim_plan,last_claim_msg
         FROM accounts WHERE id=?1",
        [id],
        |r| {
            Ok(json!({
                "status": r.get::<_, String>(0)?,
                "enabled": r.get::<_, i64>(1)?,
                "remaining": r.get::<_, f64>(2)?,
                "cooling_until": r.get::<_, i64>(3)?,
                "quota_json": r.get::<_, String>(4)?,
                "plan_tier": r.get::<_, String>(5)?,
                "plan_expire": r.get::<_, String>(6)?,
                "last_claim_plan": r.get::<_, String>(7)?,
                "last_claim_msg": r.get::<_, String>(8)?,
            }))
        },
    )
    .ok()
}

fn live_account(state: &Arc<AppState>, id: i64) -> Option<AccountView> {
    state
        .accounts
        .lock()
        .unwrap()
        .iter()
        .find(|a| a.id == id)
        .cloned()
}

fn preview() -> Value {
    json!({"code":0,"data":{"plans":[
        {"plan_id":"low","name":"PUBLIC lower priority","priority":1},
        {"plan_id":"offer","name":"PUBLIC manual offer","priority":7,"entitlements":[
            {"meter":"model_usage","unit_type":"token","show_name":"PUBLIC daily tokens","grant_units":20000,"period":"daily","priority":3,"capabilities":["chat"],"effective_at":2000000000}
        ]}
    ]}})
}

fn claim_success() -> Value {
    json!({"code":0,"data":{"server_time":2000000000,"plan":{
        "user_plan_id":"PUBLIC-user-plan","plan_id":"offer","name":"PUBLIC manual offer","status":"active","starts_at":2000000000,"ends_at":2000086400
    }}})
}

fn balance_with_remaining(remaining: f64) -> Value {
    json!({"code":0,"data":{"result":{
        "plans":[{"plan_id":"start","name":"Start Plan","status":"active"}],
        "balances":[{"plan_id":"start","show_name":"PUBLIC audit tokens",
            "total_units":remaining + 1.0,"used_units":1.0,"remaining_units":remaining}]
    }}})
}

#[tokio::test]
async fn remote_acknowledged_claim_retains_ledger_when_account_deleted_midflight() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mock = Mock::start().await;
        let solver = Solver::with(&["PUBLIC-solved-claim"]);
        let f = Fixture::new(&mock, Some(solver.clone()), "active", true);
        mock.push("GET", PREVIEW, preview());
        let gate = mock.push_gated("POST", CLAIM, claim_success());
        let claim_state = f.state.clone();
        let claim_id = f.id;
        let claim = tokio::spawn(async move {
            admin_call(
                &claim_state,
                "POST",
                format!("/api/accounts/{claim_id}/claim"),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
            .await
            .expect("claim POST never reached the gated upstream");
        let (del_status, del_body) =
            admin_call(&f.state, "DELETE", format!("/api/accounts/{}", f.id)).await;
        assert_eq!(del_status, StatusCode::OK, "canonical delete: {del_body}");
        assert_eq!(del_body["ok"], true);
        assert!(
            account_row(&f.state, f.id).is_none(),
            "fixture precondition: account row removed before the upstream answered"
        );
        assert!(
            live_account(&f.state, f.id).is_none(),
            "fixture precondition: live routing entry removed before the upstream answered"
        );
        gate.release.notify_one();
        let (status, body) = claim.await.unwrap();
        assert_no_credentials(&body);
        assert_eq!(
            status,
            StatusCode::OK,
            "a remote-acknowledged claim must surface the acknowledged result, not a local persistence failure: {body}"
        );
        assert_eq!(body["ok"], true);
        assert_eq!(body["code"], 0);
        assert_eq!(body["plan"]["user_plan_id"], "PUBLIC-user-plan");
        let rows = ledger_rows(&f.state, f.id);
        assert_eq!(
            rows.len(),
            1,
            "remote-acknowledged claim must retain its audit ledger row after mid-flight deletion: {rows:?}"
        );
        assert_eq!(rows[0]["task_type"], "claim");
        assert_eq!(rows[0]["success"], true);
        assert_eq!(rows[0]["code"], 0);
        assert_eq!(rows[0]["plan_id"], "offer");
        assert_eq!(rows[0]["plan_name"], "PUBLIC manual offer");
        assert_eq!(rows[0]["email"], "billing-audit@example.invalid");
        assert!(
            account_row(&f.state, f.id).is_none(),
            "the audit path must not resurrect a deleted account row"
        );
        assert!(
            live_account(&f.state, f.id).is_none(),
            "the audit path must not resurrect a deleted live routing entry"
        );
        let claims = mock.seen(CLAIM);
        assert_eq!(claims.len(), 1);
        assert_eq!(
            claims[0].body,
            json!({"plan_id":"offer"}),
            "claim wire payload must target the detected offer plan"
        );
        assert_eq!(solver.calls.lock().unwrap().len(), 1);
        mock.assert_complete();
    })
    .await
    .expect("deletion-race orchestration exceeded bounded deadline");
}

#[tokio::test]
async fn activation_quota_confirm_recovers_inactive_or_exhausted_but_not_admin_disabled() {
    for (initial, enabled, expect_active) in [
        ("inactive", true, true),
        ("exhausted", true, true),
        ("disabled", false, false),
    ] {
        let mock = Mock::start().await;
        let f = Fixture::new(&mock, None, initial, enabled);
        mock.push("POST", EVENT, json!({"code":0}));
        mock.push("POST", EVENT, json!({"code":0}));
        *mock.script.balance.lock().unwrap() = balance_with_remaining(100.0);
        let (status, body) =
            admin_call(&f.state, "POST", format!("/api/accounts/{}/activate", f.id)).await;
        assert_no_credentials(&body);
        assert_eq!(
            status,
            StatusCode::OK,
            "activation for initial status {initial}: {body}"
        );
        assert_eq!(body["ok"], true);
        assert_eq!(body["plan_name"], "Start Plan");
        let expected_status = if expect_active { "active" } else { "disabled" };
        let live = live_account(&f.state, f.id)
            .expect("activation recovery must operate on the existing account");
        assert_eq!(
            live.status, expected_status,
            "live routing status after confirmed positive quota, initial={initial}"
        );
        assert_eq!(
            live.enabled, enabled,
            "activation must not flip the administrator enabled flag, initial={initial}"
        );
        let row = account_row(&f.state, f.id)
            .expect("activation recovery must keep the durable account row");
        assert_eq!(
            row["status"], expected_status,
            "durable DB status after confirmed positive quota, initial={initial}"
        );
        assert_eq!(row["enabled"], if enabled { 1 } else { 0 });
        if expect_active {
            assert_eq!(live.cooling_until, 0, "initial={initial}");
            assert_eq!(
                live.remaining, 100.0,
                "confirmed quota must publish to live routing state, initial={initial}"
            );
            assert!(
                zcode_core::selectable_for_free_phase(&live, now_secs()),
                "recovered account must be selectable on the free channel, initial={initial}"
            );
        } else {
            assert!(
                !zcode_core::selectable_for_free_phase(&live, now_secs()),
                "administrator-disabled account must stay unselectable after activation quota confirm"
            );
        }
        let rows = ledger_rows(&f.state, f.id);
        assert_eq!(rows.len(), 1, "initial={initial}: {rows:?}");
        assert_eq!(rows[0]["task_type"], "activate");
        assert_eq!(rows[0]["success"], true);
        mock.assert_complete();
    }
}

#[tokio::test]
async fn genuine_ledger_insert_failure_fails_closed_and_changes_no_state() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, None, "active", true);
    f.state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE accounts SET remaining=?1,quota_json=?2,plan_tier=?3,plan_expire=?4,
                last_claim_plan=?5,last_claim_msg=?6 WHERE id=?7",
            rusqlite::params![
                7.0,
                SENTINEL_QUOTA,
                "PUBLIC-prior-tier",
                "PUBLIC-prior-expire",
                "PUBLIC-prior-plan",
                "PUBLIC-prior-msg",
                f.id
            ],
        )
        .unwrap();
    f.state
        .accounts
        .lock()
        .unwrap()
        .iter_mut()
        .find(|a| a.id == f.id)
        .unwrap()
        .remaining = 7.0;
    f.state
        .db
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_claim_ledger_insert BEFORE INSERT ON claim_records
             BEGIN SELECT RAISE(ABORT, 'PUBLIC fixture rejects claim ledger insert'); END;",
        )
        .unwrap();
    mock.push("POST", EVENT, json!({"code":0}));
    mock.push("POST", EVENT, json!({"code":0}));
    *mock.script.balance.lock().unwrap() = balance_with_remaining(100.0);
    let (status, body) =
        admin_call(&f.state, "POST", format!("/api/accounts/{}/activate", f.id)).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "genuine ledger persistence failure must stay an explicit local error: {body}"
    );
    let message = body["error"]["message"].as_str().unwrap_or("");
    assert!(
        message.contains("local billing persistence failed"),
        "unexpected error body: {body}"
    );
    assert!(
        ledger_rows(&f.state, f.id).is_empty(),
        "no audit row may be claimed when the ledger insert failed"
    );
    let row = account_row(&f.state, f.id)
        .expect("rolled-back activation must leave the account row in place");
    assert_eq!(
        row["remaining"], 7.0,
        "quota snapshot must be unchanged: {row}"
    );
    assert_eq!(row["quota_json"], SENTINEL_QUOTA);
    assert_eq!(row["plan_tier"], "PUBLIC-prior-tier");
    assert_eq!(row["plan_expire"], "PUBLIC-prior-expire");
    assert_eq!(row["last_claim_plan"], "PUBLIC-prior-plan");
    assert_eq!(row["last_claim_msg"], "PUBLIC-prior-msg");
    let live = live_account(&f.state, f.id).unwrap();
    assert_eq!(live.remaining, 7.0, "live state must be unchanged");
    assert_eq!(live.status, "active");
    mock.assert_complete();
}
