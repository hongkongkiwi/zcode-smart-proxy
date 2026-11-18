//! Manual billing lifecycle regressions.
//!
//! Contracts pinned here (Go reference: activity.go DetectForAccount,
//! ClaimForAccount, ActivateForAccount; reset.go ResetForAccount):
//! - Detect writes only the claim_records ledger for its found / empty /
//!   preview-error branches and never touches the accounts.last_claim_*
//!   summary sentinel; claim and reset still update that summary.
//! - Activation falls back to the real imported accounts.user_id only when
//!   profile and JWT identities are absent. Internal synthetic identities
//!   (store.rs `rust:<hex>`, account_paste.rs `<provider>-<16hex>`,
//!   account_oauth.rs `oauth-<64hex>`) are rejected without reporting
//!   events or confirming quota, and profile / JWT identities keep
//!   precedence over the stored fallback.
//! - A remote-acknowledged claim or reset reads the billing quota and then
//!   atomically publishes the confirmed recovery (live and durable). A
//!   confirmation failure retains the remote success and audits it without
//!   inventing quota, and failed or no-slot actions never attempt
//!   confirmation.

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

const SESSION: &str = "PUBLIC-billing-lifecycle-session";
const JWT: &str = "PUBLIC-billing-lifecycle-jwt";
const KEY: &str = "PUBLIC-billing-lifecycle-api-key";
const VERSION: &str = "PUBLIC-billing-lifecycle-version";
const MID: &str = "PUBLIC-billing-lifecycle-device";
const SCENE: &str = "PUBLIC-billing-lifecycle-scene";
const PREFIX: &str = "PUBLIC-billing-lifecycle-prefix";
const REGION: &str = "PUBLIC-billing-lifecycle-region";
const IMPORTED: &str = "PUBLIC-billing-lifecycle-imported-user";
const PROFILE_USER: &str = "PUBLIC-billing-lifecycle-profile-user";
const JWT_CLAIMS_USER: &str = "PUBLIC-billing-lifecycle-jwt-user";
const PREVIEW: &str = "/api/v1/zcode-plan/billing/preview";
const CLAIM: &str = "/api/v1/zcode-plan/billing/claim";
const EVENT: &str = "/api/v1/event/report";
const RESET_STATUS: &str = "/api/v1/coding-plan/reset/status";
const RESET_USE: &str = "/api/v1/coding-plan/reset/use";
const BALANCE: &str = "/api/v1/zcode-plan/billing/balance";
const CURRENT: &str = "/api/v1/zcode-plan/billing/current";
const SENTINEL_QUOTA: &str = r#"{"PUBLIC":"lifecycle-sentinel"}"#;

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

#[derive(Default)]
struct Script {
    steps: Mutex<VecDeque<Step>>,
    seen: Mutex<Vec<Seen>>,
    violations: Mutex<Vec<String>>,
    reset_status: Mutex<Value>,
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
            user_info: json!({"id": PROFILE_USER}),
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

    fn profile_over_stored() -> Self {
        Self {
            user_info: json!({"id": PROFILE_USER}),
            stored: IMPORTED.into(),
            access: String::new(),
        }
    }

    fn jwt_claims_over_stored() -> Self {
        Self {
            user_info: json!({}),
            stored: IMPORTED.into(),
            access: claims_jwt(JWT_CLAIMS_USER),
        }
    }
}

fn claims_jwt(user: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let payload = URL_SAFE_NO_PAD.encode(json!({"user_id": user}).to_string());
    format!("PUBLIC-lifecycle-header.{payload}.PUBLIC-lifecycle-signature")
}

struct Fixture {
    state: Arc<AppState>,
    id: i64,
}

impl Fixture {
    fn new(mock: &Mock, solver: Option<Arc<Solver>>, status: &str, identity: &Identity) -> Self {
        let db = store::open(":memory:");
        let vault = Vault::from_secret("PUBLIC billing lifecycle fixture vault seed").unwrap();
        let id = store::insert_account_encrypted(
            &db,
            &vault,
            &AccountView {
                email: "billing-lifecycle@example.invalid".into(),
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

    async fn call(&self, method: &str, action: &str) -> (StatusCode, Value) {
        let request = axum::http::Request::builder()
            .method(method)
            .uri(format!("/api/accounts/{}/{action}", self.id))
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
        (status, body)
    }

    async fn action(&self, method: &str, action: &str) -> Value {
        let (status, body) = self.call(method, action).await;
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

    fn set_summary_sentinel(&self) {
        self.state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE accounts SET last_claim_at=?1,last_claim_plan=?2,last_claim_msg=?3
                 WHERE id=?4",
                rusqlite::params![
                    "PUBLIC-prior-at",
                    "PUBLIC-prior-plan",
                    "PUBLIC-prior-msg",
                    self.id
                ],
            )
            .unwrap();
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
        {"plan_id":"low","name":"PUBLIC lower priority","priority":1},
        {"plan_id":"offer","name":"PUBLIC manual offer","priority":7,"entitlements":[
            {"meter":"model_usage","unit_type":"token","show_name":"PUBLIC daily tokens",
             "grant_units":20000,"period":"daily","priority":3,"capabilities":["chat"],
             "effective_at":2000000000}
        ]}
    ]}})
}

fn preview_empty() -> Value {
    json!({"code":0,"data":{"plans":[]}})
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
        "balances":[{"plan_id":"start","show_name":"PUBLIC lifecycle tokens",
            "total_units":remaining + 1.0,"used_units":1.0,"remaining_units":remaining}]
    }}})
}

fn confirmation_unavailable() -> Value {
    json!({"code":500,"msg":"PUBLIC confirmation unavailable"})
}

fn assert_no_quota_confirmation(mock: &Mock, context: &str) {
    assert!(
        mock.seen(BALANCE).is_empty() && mock.seen(CURRENT).is_empty(),
        "{context} must not read the billing quota"
    );
}

#[tokio::test]
async fn detect_writes_ledger_branches_but_never_the_last_claim_summary_sentinel() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, None, "active", &Identity::profile());
    f.set_summary_sentinel();

    mock.push("GET", PREVIEW, preview());
    let found = f.action("POST", "detect").await;
    assert_eq!(found["total"], 2);
    assert_eq!(found["plans"][0]["plan_id"], "offer");

    mock.push("GET", PREVIEW, preview_empty());
    assert_eq!(f.action("POST", "detect").await["total"], 0);

    mock.push(
        "GET",
        PREVIEW,
        json!({"code":500,"msg":"PUBLIC preview unavailable"}),
    );
    let (status, body) = f.call("POST", "detect").await;
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "detect preview error keeps the explicit gateway failure: {body}"
    );

    let rows = ledger_rows(&f.state, f.id);
    assert_eq!(
        rows.len(),
        3,
        "detect must ledger its found, empty, and preview-error branches: {rows:?}"
    );
    assert_eq!(rows[0]["task_type"], "detect");
    assert_eq!(rows[0]["success"], true);
    assert_eq!(rows[0]["plan_id"], "offer");
    let name = rows[0]["plan_name"].as_str().unwrap_or("");
    assert!(
        name.contains("PUBLIC manual offer") && name.contains("PUBLIC lower priority"),
        "found-branch ledger row must name the detected plans: {rows:?}"
    );
    assert!(
        rows[0]["message"].as_str().is_some_and(|m| m.contains('2')),
        "found-branch ledger row must report the detected plan count: {rows:?}"
    );
    assert_eq!(rows[1]["task_type"], "detect");
    assert_eq!(
        rows[1]["success"], true,
        "an empty detect is a successful no-op run"
    );
    assert_eq!(
        rows[1]["plan_id"], "",
        "an empty detect has no plan to name"
    );
    assert!(
        !rows[1]["message"].as_str().unwrap_or("").is_empty(),
        "empty-branch ledger row must carry a message: {rows:?}"
    );
    assert_eq!(rows[2]["task_type"], "detect");
    assert_eq!(rows[2]["success"], false);
    assert!(
        !rows[2]["message"].as_str().unwrap_or("").is_empty(),
        "preview-error ledger row must carry the failure: {rows:?}"
    );

    let row =
        account_row(&f.state, f.id).expect("detect must leave the durable account row in place");
    assert_eq!(
        row["last_claim_at"], "PUBLIC-prior-at",
        "detect writes only the ledger, never the last_claim_* summary (activity.go:494)"
    );
    assert_eq!(row["last_claim_plan"], "PUBLIC-prior-plan");
    assert_eq!(row["last_claim_msg"], "PUBLIC-prior-msg");
    mock.assert_complete();
}

#[tokio::test]
async fn claim_success_reads_billing_quota_and_publishes_confirmed_recovery() {
    let mock = Mock::start().await;
    let solver = Solver::with(&["PUBLIC-solved-claim"]);
    let f = Fixture::new(&mock, Some(solver), "exhausted", &Identity::profile());
    f.set_quota_sentinel();
    mock.set_balance(balance_with_remaining(100.0));
    mock.push("GET", PREVIEW, preview());
    mock.push("POST", CLAIM, claim_success());

    let result = f.action("POST", "claim").await;
    assert_eq!(result["ok"], true);
    assert_eq!(result["code"], 0);
    assert_eq!(result["plan"]["user_plan_id"], "PUBLIC-user-plan");
    assert!(
        !mock.seen(BALANCE).is_empty(),
        "a remote-acknowledged claim must read the billing quota before publishing"
    );
    assert!(
        mock.seen(CURRENT).is_empty(),
        "a healthy balance answer must not need the current fallback"
    );

    let live =
        live_account(&f.state, f.id).expect("claim recovery must operate on the existing account");
    assert_eq!(
        live.status, "active",
        "confirmed quota must recover exhausted routing state"
    );
    assert_eq!(live.cooling_until, 0);
    assert_eq!(
        live.remaining, 100.0,
        "live remaining must be the confirmed quota, not an invented number"
    );
    assert!(
        zcode_core::selectable_for_free_phase(&live, now_secs()),
        "recovered account must be selectable on the free channel"
    );

    let row = account_row(&f.state, f.id).expect("durable row must survive the claim");
    assert_eq!(row["status"], "active");
    assert_eq!(row["remaining"], 100.0);
    assert_eq!(row["plan_tier"], "Start Plan");
    assert_ne!(row["quota_json"], SENTINEL_QUOTA);
    assert!(row["quota_json"]
        .as_str()
        .is_some_and(|q| q.contains("Start Plan")));
    assert!(row["last_checked_at"].as_i64().is_some_and(|n| n > 111));
    assert_eq!(row["last_claim_plan"], "PUBLIC manual offer");
    assert!(
        !row["last_claim_at"].as_str().unwrap_or("").is_empty(),
        "claim, unlike detect, updates the summary sentinel"
    );

    let rows = ledger_rows(&f.state, f.id);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["task_type"], "claim");
    assert_eq!(rows[0]["success"], true);
    assert_eq!(rows[0]["code"], 0);
    assert_eq!(rows[0]["plan_id"], "offer");
    assert_eq!(rows[0]["plan_name"], "PUBLIC manual offer");
    mock.assert_complete();
}

#[tokio::test]
async fn claim_quota_confirmation_failure_retains_remote_success_without_inventing_quota() {
    let mock = Mock::start().await;
    let solver = Solver::with(&["PUBLIC-solved-claim"]);
    let f = Fixture::new(&mock, Some(solver), "exhausted", &Identity::profile());
    f.set_quota_sentinel();
    mock.set_balance(confirmation_unavailable());
    mock.push("GET", PREVIEW, preview());
    mock.push("POST", CLAIM, claim_success());

    let result = f.action("POST", "claim").await;
    assert_eq!(
        result["ok"], true,
        "the remote acknowledgement must survive a local confirmation failure: {result}"
    );
    assert_eq!(result["code"], 0);
    assert_eq!(result["plan"]["user_plan_id"], "PUBLIC-user-plan");
    assert!(
        !mock.seen(BALANCE).is_empty(),
        "confirmation must have been attempted before being reported failed"
    );

    let live = live_account(&f.state, f.id).unwrap();
    assert_eq!(
        live.status, "exhausted",
        "unconfirmed quota must not recover routing state"
    );
    assert_eq!(live.remaining, 0.0);
    assert!(!zcode_core::selectable_for_free_phase(&live, now_secs()));

    let row = account_row(&f.state, f.id).unwrap();
    assert_eq!(
        row["quota_json"], SENTINEL_QUOTA,
        "audit must not invent quota: {row}"
    );
    assert_eq!(row["plan_tier"], "PUBLIC-prior-tier");
    assert_eq!(row["remaining"], 0.0);
    assert_eq!(row["last_checked_at"], 111);

    let rows = ledger_rows(&f.state, f.id);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["task_type"], "claim");
    assert_eq!(
        rows[0]["success"], true,
        "the ledger keeps the remote success instead of turning it into a local failure"
    );
    assert_eq!(rows[0]["code"], 0);
    mock.assert_complete();
}

#[tokio::test]
async fn reset_success_reads_billing_quota_and_publishes_confirmed_recovery() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, None, "exhausted", &Identity::profile());
    f.set_quota_sentinel();
    mock.set_balance(balance_with_remaining(100.0));
    mock.set_reset_status(reset_status(&[4000000000000_i64], &[]));
    mock.push("POST", RESET_USE, json!({"code":0,"data":{"used":true}}));

    let result = f.action("POST", "reset").await;
    assert_eq!(result["ok"], true);
    assert!(
        !mock.seen(BALANCE).is_empty(),
        "a remote-acknowledged reset must read the billing quota before publishing"
    );

    let live =
        live_account(&f.state, f.id).expect("reset recovery must operate on the existing account");
    assert_eq!(live.status, "active");
    assert_eq!(live.remaining, 100.0);
    assert!(zcode_core::selectable_for_free_phase(&live, now_secs()));

    let row = account_row(&f.state, f.id).unwrap();
    assert_eq!(row["status"], "active");
    assert_eq!(row["remaining"], 100.0);
    assert_eq!(row["plan_tier"], "Start Plan");
    assert_ne!(row["quota_json"], SENTINEL_QUOTA);
    assert_eq!(row["last_claim_plan"], "配额重置(FIVE_HOUR)");

    let rows = ledger_rows(&f.state, f.id);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["task_type"], "reset");
    assert_eq!(rows[0]["success"], true);
    assert_eq!(rows[0]["plan_name"], "配额重置(FIVE_HOUR)");
    assert!(
        rows[0]["used_at"].as_i64().is_some_and(|n| n > 0),
        "a consumed reset slot must stamp used_at: {rows:?}"
    );
    mock.assert_complete();
}

#[tokio::test]
async fn reset_quota_confirmation_failure_retains_remote_success_without_inventing_quota() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, None, "exhausted", &Identity::profile());
    f.set_quota_sentinel();
    mock.set_balance(confirmation_unavailable());
    mock.set_reset_status(reset_status(&[4000000000000_i64], &[]));
    mock.push("POST", RESET_USE, json!({"code":0,"data":{"used":true}}));

    let result = f.action("POST", "reset").await;
    assert_eq!(
        result["ok"], true,
        "the consumed reset slot must survive a local confirmation failure: {result}"
    );
    assert!(
        !mock.seen(BALANCE).is_empty(),
        "confirmation must have been attempted before being reported failed"
    );

    let live = live_account(&f.state, f.id).unwrap();
    assert_eq!(live.status, "exhausted");
    assert_eq!(live.remaining, 0.0);

    let row = account_row(&f.state, f.id).unwrap();
    assert_eq!(
        row["quota_json"], SENTINEL_QUOTA,
        "audit must not invent quota: {row}"
    );
    assert_eq!(row["plan_tier"], "PUBLIC-prior-tier");
    assert_eq!(row["remaining"], 0.0);
    assert_eq!(row["last_checked_at"], 111);

    let rows = ledger_rows(&f.state, f.id);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["task_type"], "reset");
    assert_eq!(rows[0]["success"], true);
    assert!(
        rows[0]["used_at"].as_i64().is_some_and(|n| n > 0),
        "the remote slot consumption stays audited: {rows:?}"
    );
    mock.assert_complete();
}

#[tokio::test]
async fn failed_claim_and_no_slot_reset_never_attempt_quota_confirmation() {
    let mock = Mock::start().await;
    let solver = Solver::with(&["PUBLIC-solved-once"]);
    let f = Fixture::new(&mock, Some(solver), "active", &Identity::profile());
    f.set_quota_sentinel();
    mock.set_balance(balance_with_remaining(100.0));
    mock.push("GET", PREVIEW, preview());
    mock.push(
        "POST",
        CLAIM,
        json!({"code":1005,"msg":"PUBLIC daily quota spent","data":{
            "server_time":2000000000,"plan":{"ends_at":2000086400}
        }}),
    );
    let result = f.action("POST", "claim").await;
    assert_eq!(result["ok"], false);
    assert_eq!(result["code"], 1005);
    assert_no_quota_confirmation(&mock, "a rejected claim");
    let row = account_row(&f.state, f.id).unwrap();
    assert_eq!(row["quota_json"], SENTINEL_QUOTA);
    assert_eq!(row["plan_tier"], "PUBLIC-prior-tier");
    assert_eq!(row["last_checked_at"], 111);
    assert_eq!(ledger_rows(&f.state, f.id)[0]["success"], false);
    mock.assert_complete();

    let mock = Mock::start().await;
    let f = Fixture::new(&mock, None, "active", &Identity::profile());
    f.set_quota_sentinel();
    mock.set_balance(balance_with_remaining(100.0));
    mock.set_reset_status(reset_status(&[], &[]));
    let result = f.action("POST", "reset").await;
    assert_eq!(
        result["ok"], true,
        "no available slot is a successful no-op run: {result}"
    );
    assert!(
        mock.seen(RESET_USE).is_empty(),
        "a no-slot reset must not consume a reset chance"
    );
    assert_no_quota_confirmation(&mock, "a no-slot reset");
    let row = account_row(&f.state, f.id).unwrap();
    assert_eq!(row["quota_json"], SENTINEL_QUOTA);
    assert_eq!(row["last_checked_at"], 111);
    let rows = ledger_rows(&f.state, f.id);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["task_type"], "reset");
    assert_eq!(rows[0]["success"], true);
    mock.assert_complete();
}

#[tokio::test]
async fn activation_falls_back_to_real_imported_user_id_when_profile_and_jwt_ids_absent() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, None, "active", &Identity::stored_only(IMPORTED));
    mock.push("POST", EVENT, json!({"code":0}));
    mock.push("POST", EVENT, json!({"code":0}));
    mock.set_balance(balance_with_remaining(100.0));

    let result = f.action("POST", "activate").await;
    assert_eq!(
        result["ok"], true,
        "the real imported stored identity must activate the account: {result}"
    );
    let events = mock.seen(EVENT);
    assert_eq!(events.len(), 2);
    for (seen, element) in events.iter().zip(["app_launch", "app_daily_active"]) {
        assert_eq!(seen.body["element_name"], element);
        assert_eq!(
            seen.body["user_id"], IMPORTED,
            "activation events must carry the real imported identity"
        );
        assert_eq!(seen.body["device_mid"], MID);
    }
    let live = live_account(&f.state, f.id).unwrap();
    assert_eq!(
        live.remaining, 100.0,
        "activation with the stored identity must still confirm and publish quota"
    );
    let rows = ledger_rows(&f.state, f.id);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["task_type"], "activate");
    assert_eq!(rows[0]["success"], true);
    mock.assert_complete();
}

#[tokio::test]
async fn activation_rejects_synthetic_stored_identities_without_reporting_events() {
    let synthetic = [
        format!("rust:{}", "0123456789abcdef0123456789abcdef"),
        format!("zai-{}", "0123456789abcdef"),
        format!(
            "oauth-{}",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ),
    ];
    for stored in &synthetic {
        let mock = Mock::start().await;
        let f = Fixture::new(&mock, None, "active", &Identity::stored_only(stored));
        f.set_quota_sentinel();
        mock.set_balance(balance_with_remaining(100.0));

        let result = f.action("POST", "activate").await;
        assert_eq!(
            result["ok"], false,
            "synthetic identity {stored} must not activate the account"
        );
        assert!(
            !result["message"].as_str().unwrap_or("").is_empty(),
            "rejection must explain itself: {result}"
        );
        assert!(
            mock.seen(EVENT).is_empty(),
            "no activation events for synthetic identity {stored}"
        );
        assert_no_quota_confirmation(&mock, &format!("synthetic identity {stored}"));
        let row = account_row(&f.state, f.id).unwrap();
        assert_eq!(row["quota_json"], SENTINEL_QUOTA);
        assert_eq!(row["status"], "active");
        let rows = ledger_rows(&f.state, f.id);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["task_type"], "activate");
        assert_eq!(rows[0]["success"], false);
        mock.assert_complete();
    }
}

#[tokio::test]
async fn profile_and_jwt_identities_outrank_the_stored_fallback() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, None, "active", &Identity::profile_over_stored());
    mock.push("POST", EVENT, json!({"code":0}));
    mock.push("POST", EVENT, json!({"code":0}));
    mock.set_balance(balance_with_remaining(100.0));
    f.action("POST", "activate").await;
    let events = mock.seen(EVENT);
    assert_eq!(events.len(), 2);
    for seen in &events {
        assert_eq!(
            seen.body["user_id"], PROFILE_USER,
            "a valid profile identity keeps precedence over the stored fallback"
        );
    }
    mock.assert_complete();

    let mock = Mock::start().await;
    let f = Fixture::new(&mock, None, "active", &Identity::jwt_claims_over_stored());
    mock.push("POST", EVENT, json!({"code":0}));
    mock.push("POST", EVENT, json!({"code":0}));
    mock.set_balance(balance_with_remaining(100.0));
    f.action("POST", "activate").await;
    let events = mock.seen(EVENT);
    assert_eq!(events.len(), 2);
    for seen in &events {
        assert_eq!(
            seen.body["user_id"], JWT_CLAIMS_USER,
            "a valid access-token JWT identity keeps precedence over the stored fallback"
        );
    }
    mock.assert_complete();
}
