//! Manual billing review regressions.
//!
//! Contracts pinned here:
//! - Go oauth.go:333 fabricates `oauth-<8hex>` fallback identities (first 8
//!   chars of a UUID string) that go_import copies verbatim into
//!   accounts.user_id. The activation identity fallback must reject that
//!   synthetic format exactly like `rust:<32hex>`, `<provider>-<16hex>`,
//!   and `oauth-<64hex>`: no activation events, no quota confirmation, and
//!   a failure audit row.
//! - An acknowledged manual claim or reset must be durably audited (exactly
//!   one claim_records row plus the accounts.last_claim_* summary) BEFORE
//!   the optional billing quota confirmation is awaited. Cancelling or
//!   crashing the task while the confirmation read is parked must retain
//!   that audit truthfully: the reset's used_at and the summary survive,
//!   the row is never recreated or duplicated, and no unconfirmed quota is
//!   published. Reproduced with a gated mocked balance read reached only
//!   after the remote acknowledgement, direct spawned build_router
//!   oneshot tasks, and loopback-only mocked HTTP.

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

const SESSION: &str = "PUBLIC-billing-review-session";
const JWT: &str = "PUBLIC-billing-review-jwt";
const KEY: &str = "PUBLIC-billing-review-api-key";
const VERSION: &str = "PUBLIC-billing-review-version";
const MID: &str = "PUBLIC-billing-review-device";
const SCENE: &str = "PUBLIC-billing-review-scene";
const PREFIX: &str = "PUBLIC-billing-review-prefix";
const REGION: &str = "PUBLIC-billing-review-region";
const PREVIEW: &str = "/api/v1/zcode-plan/billing/preview";
const CLAIM: &str = "/api/v1/zcode-plan/billing/claim";
const EVENT: &str = "/api/v1/event/report";
const RESET_STATUS: &str = "/api/v1/coding-plan/reset/status";
const RESET_USE: &str = "/api/v1/coding-plan/reset/use";
const BALANCE: &str = "/api/v1/zcode-plan/billing/balance";
const CURRENT: &str = "/api/v1/zcode-plan/billing/current";
const SENTINEL_QUOTA: &str = r#"{"PUBLIC":"review-sentinel"}"#;

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
}

/// Parks a mocked balance response until the test releases it.
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
    reset_status: Mutex<Value>,
    balance: Mutex<Value>,
    balance_gate: Mutex<Option<Arc<Gate>>>,
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
                headers: parts.headers,
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
            if seen.method == "GET" && matches!(seen.path.as_str(), BALANCE | CURRENT) {
                // Drop the mutex guard before parking on the gate so the
                // handler future stays Send.
                let gate = script.balance_gate.lock().unwrap().clone();
                if let Some(gate) = gate {
                    gate.entered.notify_one();
                    gate.release.notified().await;
                }
                return (StatusCode::OK, Json(script.balance.lock().unwrap().clone()));
            }
            if seen.path == RESET_STATUS && seen.method == "GET" {
                return (
                    StatusCode::OK,
                    Json(script.reset_status.lock().unwrap().clone()),
                );
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
            (StatusCode::OK, Json(step.body))
        }
        let script = Arc::new(Script {
            reset_status: Mutex::new(reset_status(&[], &[])),
            ..Script::default()
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

    fn set_balance(&self, body: Value) {
        *self.script.balance.lock().unwrap() = body;
    }

    fn set_reset_status(&self, body: Value) {
        *self.script.reset_status.lock().unwrap() = body;
    }

    fn gate_balance(&self) -> Arc<Gate> {
        let gate = Arc::new(Gate::default());
        *self.script.balance_gate.lock().unwrap() = Some(gate.clone());
        gate
    }

    fn steps_pending(&self) -> usize {
        self.script.steps.lock().unwrap().len()
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
}

impl Solver {
    fn with(answers: &[&str]) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.iter().map(|s| (*s).to_owned()).collect()),
        })
    }
}

impl CaptchaSolver for Solver {
    fn solve(&self, _scene: &str, _prefix: &str) -> Option<String> {
        self.answers.lock().unwrap().pop_front()
    }
}

/// The identity surfaces consulted by manual activation.
struct Identity {
    user_info: Value,
    stored: String,
    access: String,
}

impl Identity {
    fn profile() -> Self {
        Self {
            user_info: json!({"id": "PUBLIC-billing-review-profile-user"}),
            stored: String::new(),
            access: String::new(),
        }
    }

    fn stored_only(stored: &str) -> Self {
        Self {
            user_info: json!({}),
            stored: stored.into(),
            access: String::new(),
        }
    }
}

struct Fixture {
    state: Arc<AppState>,
    id: i64,
}

impl Fixture {
    fn new(mock: &Mock, solver: Option<Arc<Solver>>, status: &str, identity: &Identity) -> Self {
        let db = store::open(":memory:");
        let vault = Vault::from_secret("PUBLIC billing review fixture vault seed").unwrap();
        let id = store::insert_account_encrypted(
            &db,
            &vault,
            &AccountView {
                email: "billing-review@example.invalid".into(),
                enabled: true,
                status: status.into(),
                paid_fallback: false,
                ..Default::default()
            },
            JWT,
            KEY,
        )
        .unwrap();
        let info = vault.encrypt(&identity.user_info.to_string()).unwrap();
        db.execute(
            "UPDATE accounts SET user_info=?1,device_mid=?2 WHERE id=?3",
            rusqlite::params![info, MID, id],
        )
        .unwrap();
        if !identity.stored.is_empty() {
            db.execute(
                "UPDATE accounts SET user_id=?1 WHERE id=?2",
                rusqlite::params![identity.stored, id],
            )
            .unwrap();
        }
        if !identity.access.is_empty() {
            let access = vault.encrypt(&identity.access).unwrap();
            db.execute(
                "UPDATE accounts SET access_token=?1 WHERE id=?2",
                rusqlite::params![access, id],
            )
            .unwrap();
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
        Self {
            state: Arc::new(state),
            id,
        }
    }

    fn set_quota_sentinel(&self) {
        self.state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE accounts SET quota_json=?1,plan_tier=?2,last_checked_at=?3 WHERE id=?4",
                rusqlite::params![SENTINEL_QUOTA, "PUBLIC-prior-tier", 111, self.id],
            )
            .unwrap();
    }

    async fn action(&self, action: &str) -> Value {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/api/accounts/{}/{}", self.id, action))
            .header("host", "localhost:8080")
            .header("origin", "http://localhost:8080")
            .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
            .body(Body::empty())
            .unwrap();
        let response = tokio::time::timeout(
            Duration::from_secs(8),
            build_router(self.state.clone()).oneshot(request),
        )
        .await
        .expect("manual billing action exceeded bounded loopback deadline")
        .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert_eq!(status, StatusCode::OK, "{action} returned {body}");
        let text = body.to_string();
        for private in [JWT, KEY, "vault1:"] {
            assert!(
                !text.contains(private),
                "{action} response exposed credential material"
            );
        }
        body
    }

    /// Spawns the manual action as an abortable task driving the real
    /// router directly, with no admin-side network beyond loopback.
    fn spawn_action(self: &Arc<Self>, action: &'static str) -> tokio::task::JoinHandle<Value> {
        let state = self.state.clone();
        let id = self.id;
        tokio::spawn(async move {
            let request = axum::http::Request::builder()
                .method("POST")
                .uri(format!("/api/accounts/{id}/{action}"))
                .header("host", "localhost:8080")
                .header("origin", "http://localhost:8080")
                .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
                .body(Body::empty())
                .unwrap();
            let response = tokio::time::timeout(
                Duration::from_secs(15),
                build_router(state.clone()).oneshot(request),
            )
            .await
            .expect("manual billing action exceeded bounded loopback deadline")
            .unwrap();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        })
    }
}

fn ledger_rows(state: &Arc<AppState>, id: i64) -> Vec<Value> {
    let db = state.db.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT task_type,plan_id,plan_name,success,code,message,next_at,used_at
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
            }))
        })
        .unwrap();
    rows.collect::<Result<Vec<_>, _>>().unwrap()
}

fn account_row(state: &Arc<AppState>, id: i64) -> Option<Value> {
    let db = state.db.lock().unwrap();
    db.query_row(
        "SELECT status,remaining,quota_json,plan_tier,last_checked_at,
            last_claim_at,last_claim_plan,last_claim_msg
         FROM accounts WHERE id=?1",
        [id],
        |r| {
            Ok(json!({
                "status": r.get::<_, String>(0)?,
                "remaining": r.get::<_, f64>(1)?,
                "quota_json": r.get::<_, String>(2)?,
                "plan_tier": r.get::<_, String>(3)?,
                "last_checked_at": r.get::<_, i64>(4)?,
                "last_claim_at": r.get::<_, String>(5)?,
                "last_claim_plan": r.get::<_, String>(6)?,
                "last_claim_msg": r.get::<_, String>(7)?,
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
        {"plan_id":"offer","name":"PUBLIC manual offer","priority":7,"entitlements":[
            {"meter":"model_usage","unit_type":"token","show_name":"PUBLIC daily tokens",
             "grant_units":20000,"period":"daily","priority":3,"capabilities":["chat"],
             "effective_at":2000000000}
        ]}
    ]}})
}

fn claim_success() -> Value {
    json!({"code":0,"data":{"server_time":2000000000,"plan":{
        "user_plan_id":"PUBLIC-user-plan","plan_id":"offer","name":"PUBLIC manual offer",
        "status":"active","starts_at":2000000000,"ends_at":2000086400
    }}})
}

fn reset_status(five: &[i64], week: &[i64]) -> Value {
    json!({"code":0,"data":{
        "available_five_hour_resets":five.iter().map(|n| json!({"expire_at":n})).collect::<Vec<_>>(),
        "available_week_resets":week.iter().map(|n| json!({"expire_at":n})).collect::<Vec<_>>(),
        "latest_five_hour_reset_history":null,"latest_week_reset_history":null,
        "has_unread_history":false
    }})
}

fn balance_with_remaining(remaining: f64) -> Value {
    json!({"code":0,"data":{"result":{
        "plans":[{"plan_id":"start","name":"Start Plan","status":"active"}],
        "balances":[{"plan_id":"start","show_name":"PUBLIC review tokens",
            "total_units":remaining + 1.0,"used_units":1.0,"remaining_units":remaining}]
    }}})
}

fn assert_no_quota_confirmation(mock: &Mock, context: &str) {
    assert!(
        mock.seen(BALANCE).is_empty() && mock.seen(CURRENT).is_empty(),
        "{context} must not read the billing quota"
    );
}

async fn assert_cancelled(task: tokio::task::JoinHandle<Value>, context: &str) {
    match tokio::time::timeout(Duration::from_secs(2), task).await {
        Ok(Err(error)) => assert!(
            error.is_cancelled(),
            "{context} must end as a cancelled task"
        ),
        Ok(Ok(value)) => panic!("{context} must not complete a response: {value}"),
        Err(_) => panic!("{context} must terminate promptly after abort"),
    }
}

#[tokio::test]
async fn activation_rejects_go_imported_oauth_eight_hex_identity_without_reporting_events() {
    tokio::time::timeout(Duration::from_secs(15), async {
        // oauth.go:333 fabricates "oauth-" + uuid.NewString()[:8] when no
        // real identity was available; go_import copies it verbatim.
        let mock = Mock::start().await;
        let f = Fixture::new(
            &mock,
            None,
            "active",
            &Identity::stored_only("oauth-9f8e7d6c"),
        );
        f.set_quota_sentinel();
        mock.set_balance(balance_with_remaining(100.0));

        let result = f.action("activate").await;
        assert_eq!(
            result["ok"], false,
            "the Go-fabricated oauth-8hex identity is synthetic and must not activate: {result}"
        );
        assert!(
            !result["message"].as_str().unwrap_or("").is_empty(),
            "rejection must explain itself: {result}"
        );
        assert!(
            mock.seen(EVENT).is_empty(),
            "no activation events for the oauth-8hex synthetic identity"
        );
        assert_no_quota_confirmation(&mock, "a synthetic oauth-8hex identity");
        let row = account_row(&f.state, f.id).unwrap();
        assert_eq!(row["quota_json"], SENTINEL_QUOTA, "{row}");
        assert_eq!(row["status"], "active");
        let rows = ledger_rows(&f.state, f.id);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["task_type"], "activate");
        assert_eq!(rows[0]["success"], false);
        mock.assert_complete();
    })
    .await
    .expect("oauth-8hex rejection exceeded bounded deadline");
}

#[tokio::test]
async fn acknowledged_claim_audits_before_the_optional_quota_confirmation_survives_cancellation() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mock = Mock::start().await;
        let solver = Solver::with(&["PUBLIC-solved-review"]);
        let f = Arc::new(Fixture::new(
            &mock,
            Some(solver),
            "exhausted",
            &Identity::profile(),
        ));
        f.set_quota_sentinel();
        mock.set_balance(balance_with_remaining(100.0));
        mock.push("GET", PREVIEW, preview());
        mock.push("POST", CLAIM, claim_success());
        let gate = mock.gate_balance();

        let task = f.spawn_action("claim");
        tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
            .await
            .expect("claim never reached the gated balance confirmation");
        assert_eq!(
            mock.steps_pending(),
            0,
            "the balance read is only reached after the remote claim acknowledgement"
        );
        let claims = mock.seen(CLAIM);
        assert_eq!(claims.len(), 1);
        assert_eq!(
            claims[0].body,
            json!({"plan_id": "offer"}),
            "claim wire payload must target the detected offer plan"
        );

        let rows = ledger_rows(&f.state, f.id);
        assert_eq!(
            rows.len(),
            1,
            "the acknowledged claim must already be audited before the optional confirmation is awaited: {rows:?}"
        );
        assert_eq!(rows[0]["task_type"], "claim");
        assert_eq!(rows[0]["success"], true);
        assert_eq!(rows[0]["code"], 0);
        assert_eq!(rows[0]["plan_id"], "offer");
        assert_eq!(rows[0]["plan_name"], "PUBLIC manual offer");
        let audited = account_row(&f.state, f.id).unwrap();
        assert_eq!(audited["last_claim_plan"], "PUBLIC manual offer");
        assert!(
            !audited["last_claim_at"].as_str().unwrap_or("").is_empty(),
            "the summary must be durable before the confirmation is awaited: {audited}"
        );
        assert!(
            !audited["last_claim_msg"].as_str().unwrap_or("").is_empty(),
            "{audited}"
        );

        // Cancel the task while the confirmation read is parked.
        task.abort();
        assert_cancelled(task, "the cancelled claim").await;
        gate.release.notify_one();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let after = ledger_rows(&f.state, f.id);
        assert_eq!(
            after,
            rows,
            "cancellation during confirmation must retain the audit without recreating it"
        );
        let row = account_row(&f.state, f.id).unwrap();
        assert_eq!(row["last_claim_at"], audited["last_claim_at"]);
        assert_eq!(row["last_claim_plan"], "PUBLIC manual offer");
        assert_eq!(row["last_claim_msg"], audited["last_claim_msg"]);
        assert_eq!(
            row["quota_json"], SENTINEL_QUOTA,
            "an aborted confirmation must not publish unconfirmed quota: {row}"
        );
        assert_eq!(row["plan_tier"], "PUBLIC-prior-tier");
        assert_eq!(row["last_checked_at"], 111);
        assert_eq!(row["status"], "exhausted");
        let live = live_account(&f.state, f.id)
            .expect("the aborted confirmation must leave the live account in place");
        assert_eq!(live.status, "exhausted");
        assert_eq!(live.remaining, 0.0);
        mock.assert_complete();
    })
    .await
    .expect("claim audit-ordering orchestration exceeded bounded deadline");
}

#[tokio::test]
async fn acknowledged_reset_audits_before_the_optional_quota_confirmation_survives_cancellation() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mock = Mock::start().await;
        let f = Arc::new(Fixture::new(&mock, None, "exhausted", &Identity::profile()));
        f.set_quota_sentinel();
        mock.set_balance(balance_with_remaining(100.0));
        mock.set_reset_status(reset_status(&[4000000000000_i64], &[]));
        mock.push("POST", RESET_USE, json!({"code":0,"data":{"used":true}}));
        let gate = mock.gate_balance();

        let task = f.spawn_action("reset");
        tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
            .await
            .expect("reset never reached the gated balance confirmation");
        assert_eq!(
            mock.steps_pending(),
            0,
            "the balance read is only reached after the reset slot was consumed"
        );
        let uses = mock.seen(RESET_USE);
        assert_eq!(uses.len(), 1);
        assert_eq!(
            uses[0].body["reset_type"], "FIVE_HOUR",
            "reset wire payload must consume the detected five-hour slot"
        );
        assert!(
            uses[0].body["idempotency_key"]
                .as_str()
                .is_some_and(|key| !key.is_empty()),
            "reset use must carry a manual idempotency key: {}",
            uses[0].body
        );

        let rows = ledger_rows(&f.state, f.id);
        assert_eq!(
            rows.len(),
            1,
            "the acknowledged reset must already be audited before the optional confirmation is awaited: {rows:?}"
        );
        assert_eq!(rows[0]["task_type"], "reset");
        assert_eq!(rows[0]["success"], true);
        let used_at = rows[0]["used_at"].as_i64().unwrap_or(0);
        assert!(
            used_at > 0,
            "the consumed reset slot must stamp used_at before the confirmation is awaited: {rows:?}"
        );
        assert_eq!(rows[0]["plan_name"], "配额重置(FIVE_HOUR)");
        let audited = account_row(&f.state, f.id).unwrap();
        assert_eq!(audited["last_claim_plan"], "配额重置(FIVE_HOUR)");
        assert!(
            !audited["last_claim_at"].as_str().unwrap_or("").is_empty(),
            "the summary must be durable before the confirmation is awaited: {audited}"
        );

        // Cancel the task while the confirmation read is parked.
        task.abort();
        assert_cancelled(task, "the cancelled reset").await;
        gate.release.notify_one();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let after = ledger_rows(&f.state, f.id);
        assert_eq!(
            after, rows,
            "cancellation during confirmation must retain the audit without recreating it"
        );
        assert_eq!(
            after[0]["used_at"].as_i64(),
            Some(used_at),
            "the remote slot consumption timestamp must survive the cancellation"
        );
        let row = account_row(&f.state, f.id).unwrap();
        assert_eq!(row["last_claim_at"], audited["last_claim_at"]);
        assert_eq!(row["last_claim_plan"], "配额重置(FIVE_HOUR)");
        assert_eq!(row["last_claim_msg"], audited["last_claim_msg"]);
        assert_eq!(
            row["quota_json"], SENTINEL_QUOTA,
            "an aborted confirmation must not publish unconfirmed quota: {row}"
        );
        assert_eq!(row["last_checked_at"], 111);
        assert_eq!(row["status"], "exhausted");
        mock.assert_complete();
    })
    .await
    .expect("reset audit-ordering orchestration exceeded bounded deadline");
}
