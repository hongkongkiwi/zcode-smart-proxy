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

const SESSION: &str = "PUBLIC-billing-wire-session";
const JWT: &str = "PUBLIC-billing-wire-jwt";
const KEY: &str = "PUBLIC-billing-wire-api-key";
const VERSION: &str = "PUBLIC-billing-wire-version";
const MID: &str = "PUBLIC-billing-wire-device";
const USER: &str = "PUBLIC-billing-wire-user";
const SCENE: &str = "PUBLIC-billing-wire-scene";
const PREFIX: &str = "PUBLIC-billing-wire-prefix";
const REGION: &str = "PUBLIC-billing-wire-region";
const PREVIEW: &str = "/api/v1/zcode-plan/billing/preview";
const CLAIM: &str = "/api/v1/zcode-plan/billing/claim";
const EVENT: &str = "/api/v1/event/report";
const RESET_STATUS: &str = "/api/v1/coding-plan/reset/status";
const RESET_USE: &str = "/api/v1/coding-plan/reset/use";

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    query: String,
    headers: HeaderMap,
    body: Value,
}

struct Step {
    method: &'static str,
    path: &'static str,
    body: Value,
}

struct Script {
    steps: Mutex<VecDeque<Step>>,
    seen: Mutex<Vec<Seen>>,
    violations: Mutex<Vec<String>>,
    reset_status: Mutex<Value>,
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
                query: parts.uri.query().unwrap_or("").into(),
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
            if matches!(
                seen.path.as_str(),
                "/api/v1/zcode-plan/billing/balance" | "/api/v1/zcode-plan/billing/current"
            ) && seen.method == "GET"
            {
                return (
                    StatusCode::OK,
                    Json(json!({"code":0,"data":{"result":{
                        "plans":[{"plan_id":"start","name":"Start Plan","status":"active"}],
                        "balances":[{"plan_id":"start","show_name":"PUBLIC tokens","total_units":100,"used_units":0,"remaining_units":100}]
                    }}})),
                );
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
            steps: Mutex::new(VecDeque::new()),
            seen: Mutex::new(Vec::new()),
            violations: Mutex::new(Vec::new()),
            reset_status: Mutex::new(reset_status(&[], &[])),
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
struct Solver {
    answers: Mutex<VecDeque<String>>,
    seen: Mutex<Vec<(String, String)>>,
}

impl Solver {
    fn with(answers: &[&str]) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.iter().map(|s| (*s).to_owned()).collect()),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn assert_calls(&self, count: usize) {
        assert_eq!(
            *self.seen.lock().unwrap(),
            vec![(SCENE.into(), PREFIX.into()); count]
        );
    }
}

impl CaptchaSolver for Solver {
    fn solve(&self, scene: &str, prefix: &str) -> Option<String> {
        self.seen
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
    fn new(mock: &Mock, solver: Option<Arc<Solver>>) -> Self {
        let db = store::open(":memory:");
        let vault = Vault::from_secret("PUBLIC billing wire fixture vault seed").unwrap();
        let id = store::insert_account_encrypted(
            &db,
            &vault,
            &AccountView {
                email: "billing@example.invalid".into(),
                enabled: true,
                status: "active".into(),
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
            .persist_settings(&[
                ("highspeed_lane_enabled", "0"),
                ("paid_fallback_mode", "never"),
            ])
            .unwrap();
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

    async fn action(&self, method: &str, action: &str) -> Value {
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
        assert_eq!(status, StatusCode::OK, "{action} returned {body}");
        let text = body.to_string();
        for private in [JWT, KEY, "vault1:"] {
            assert!(
                !text.contains(private),
                "manual billing response exposed credential material"
            );
        }
        body
    }

    fn last_record(&self) -> Value {
        self.state.db.lock().unwrap().query_row(
            "SELECT task_type,plan_id,success,code,next_at,used_at FROM claim_records WHERE account_id=?1 ORDER BY id DESC LIMIT 1",
            [self.id], |r| Ok(json!({
                "task_type":r.get::<_,String>(0)?, "plan_id":r.get::<_,String>(1)?,
                "success":r.get::<_,bool>(2)?, "code":r.get::<_,i64>(3)?,
                "next_at":r.get::<_,i64>(4)?, "used_at":r.get::<_,i64>(5)?
            }))
        ).unwrap()
    }

    fn assert_no_implicit_opt_in(&self) {
        let paid: bool = self
            .state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT paid_fallback FROM accounts WHERE id=?1",
                [self.id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!paid);
        assert!(
            !self
                .state
                .accounts
                .lock()
                .unwrap()
                .iter()
                .find(|a| a.id == self.id)
                .unwrap()
                .paid_fallback
        );
        assert_eq!(
            self.state.setting("highspeed_lane_enabled").as_deref(),
            Some("0")
        );
        assert_eq!(
            self.state.setting("paid_fallback_mode").as_deref(),
            Some("never")
        );
        for (key, expected) in [
            ("highspeed_lane_enabled", "0"),
            ("paid_fallback_mode", "never"),
        ] {
            let stored: String = self
                .state
                .db
                .lock()
                .unwrap()
                .query_row("SELECT value FROM settings WHERE key=?1", [key], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(stored, expected);
        }
    }
}

fn preview() -> Value {
    json!({"code":0,"data":{"plans":[
        {"plan_id":"low","name":"PUBLIC lower priority","priority":1},
        {"plan_id":"offer","name":"PUBLIC manual offer","priority":7,"entitlements":[
            {"meter":"model_usage","unit_type":"token","show_name":"PUBLIC daily tokens","grant_units":20000,"period":"daily","priority":3,"capabilities":["chat"],"effective_at":2000000000},
            {"meter":"storage","unit_type":"byte","show_name":"not token quota","grant_units":10}
        ]}
    ]}})
}

fn claim_success() -> Value {
    json!({"code":0,"data":{"server_time":2000000000,"plan":{
        "user_plan_id":"PUBLIC-user-plan","plan_id":"offer","name":"PUBLIC manual offer","status":"active","starts_at":2000000000,"ends_at":2000086400
    }}})
}

fn reset_status(five: &[i64], week: &[i64]) -> Value {
    json!({"code":0,"data":{
        "available_five_hour_resets":five.iter().map(|n| json!({"expire_at":n})).collect::<Vec<_>>(),
        "available_week_resets":week.iter().map(|n| json!({"expire_at":n})).collect::<Vec<_>>(),
        "latest_five_hour_reset_history":null,"latest_week_reset_history":null,"has_unread_history":false
    }})
}

#[tokio::test]
async fn manual_detect_and_claim_preserve_offer_order_business_codes_and_retry_deadlines() {
    let mock = Mock::start().await;
    let solver = Solver::with(&["PUBLIC-solved-first", "PUBLIC-solved-second"]);
    let f = Fixture::new(&mock, Some(solver.clone()));
    mock.push("GET", PREVIEW, preview());
    let detected = f.action("POST", "detect").await;
    assert_eq!(detected["total"], 2);
    assert_eq!(detected["plans"][0]["plan_id"], "offer");
    assert_eq!(detected["plans"][1]["plan_id"], "low");
    let grants = detected["plans"][0]["grant_items"].as_array().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0]["units"], 20000.0);
    assert_eq!(grants[0]["capabilities"], json!(["chat"]));
    assert_eq!(grants[0]["effective_at"], 2000000000_i64);
    solver.assert_calls(0);
    assert!(mock.seen(CLAIM).is_empty());
    for (code, ok, next_at) in [(1003, true, 0_i64), (1005, false, 2000086400000_i64)] {
        mock.push("GET", PREVIEW, preview());
        mock.push(
            "POST",
            CLAIM,
            json!({"code":code,"msg":"PUBLIC business result","data":{
                "server_time":2000000000,"plan":{"ends_at":2000086400}
            }}),
        );
        let result = f.action("POST", "claim").await;
        assert_eq!(result["ok"], ok);
        assert_eq!(result["code"], code);
        assert_eq!(result["next_at"], next_at);
        assert_eq!(result["server_time"], 2000000000000_i64);
        assert_eq!(
            f.last_record(),
            json!({"task_type":"claim","plan_id":"offer","success":ok,"code":code,"next_at":next_at,"used_at":0})
        );
    }
    let platform = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "darwin-arm64".to_owned(),
        (os, arch) => format!(
            "{}-{}",
            if os == "windows" { "win32" } else { os },
            if arch == "x86_64" {
                "x64"
            } else if arch == "aarch64" {
                "arm64"
            } else {
                arch
            }
        ),
    };
    for seen in mock.seen(PREVIEW) {
        let url = reqwest::Url::parse(&format!("http://localhost/?{}", seen.query)).unwrap();
        let pairs: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(pairs.get("app_version").map(String::as_str), Some(VERSION));
        assert_eq!(pairs.get("platform"), Some(&platform));
    }
    for seen in mock.seen(CLAIM) {
        assert_eq!(seen.method, "POST");
        assert_eq!(seen.body, json!({"plan_id":"offer"}));
    }
    solver.assert_calls(2);
    f.assert_no_implicit_opt_in();
    mock.assert_complete();
}

#[tokio::test]
async fn captcha_rejection_resolves_once_again_and_default_noop_never_fakes_a_claim() {
    for code in [3001, 3007] {
        let mock = Mock::start().await;
        let solver = Solver::with(&["PUBLIC-solved-stale", "PUBLIC-solved-fresh"]);
        let f = Fixture::new(&mock, Some(solver.clone()));
        mock.push("GET", PREVIEW, preview());
        mock.push(
            "POST",
            CLAIM,
            json!({"code":code,"msg":"PUBLIC stale verification"}),
        );
        mock.push("POST", CLAIM, claim_success());
        let result = f.action("POST", "claim").await;
        assert_eq!(result["ok"], true);
        assert_eq!(result["code"], 0);
        assert_eq!(result["plan"]["user_plan_id"], "PUBLIC-user-plan");
        assert_eq!(result["plan"]["ends_at"], 2000086400_i64);
        let attempts = mock.seen(CLAIM);
        assert_eq!(attempts.len(), 2);
        assert_eq!(
            attempts[0].headers["x-aliyun-captcha-verify-param"],
            "PUBLIC-solved-stale"
        );
        assert_eq!(
            attempts[1].headers["x-aliyun-captcha-verify-param"],
            "PUBLIC-solved-fresh"
        );
        solver.assert_calls(2);
        assert_eq!(f.last_record()["success"], true);
        f.assert_no_implicit_opt_in();
        mock.assert_complete();
    }
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, None);
    mock.push("GET", PREVIEW, preview());
    let result = f.action("POST", "claim").await;
    assert_eq!(
        result["ok"], false,
        "NoopSolver has supplied no verification result"
    );
    assert!(
        mock.seen(CLAIM).is_empty(),
        "no verification result must not be sent as a solved CAPTCHA"
    );
    assert_eq!(f.last_record()["success"], false);
    f.assert_no_implicit_opt_in();
    mock.assert_complete();
}

#[tokio::test]
async fn start_plan_activation_reports_both_events_with_account_identity_and_confirms_quota() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, None);
    mock.push("POST", EVENT, json!({"code":0}));
    mock.push("POST", EVENT, json!({"code":0}));
    let result = f.action("POST", "activate").await;
    assert_eq!(result["ok"], true);
    assert_eq!(result["plan_name"], "Start Plan");
    let events = mock.seen(EVENT);
    assert_eq!(events.len(), 2);
    for (seen, element) in events.iter().zip(["app_launch", "app_daily_active"]) {
        assert_eq!(seen.method, "POST");
        for (key, value) in [
            ("element_name", element),
            ("event_region", "app"),
            ("event_type", "view"),
            ("user_id", USER),
            ("device_mid", MID),
            ("app_version", VERSION),
        ] {
            assert_eq!(seen.body[key], value, "activation field {key}");
        }
        assert!(seen.body["event_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()));
        assert_eq!(seen.headers["x-device-mid"], MID);
    }
    assert_ne!(events[0].body["event_id"], events[1].body["event_id"]);
    assert!(
        !mock.seen("/api/v1/zcode-plan/billing/balance").is_empty(),
        "activation must confirm the grant rather than report event submission as quota success"
    );
    assert_eq!(f.last_record()["task_type"], "activate");
    assert_eq!(f.last_record()["success"], true);
    f.assert_no_implicit_opt_in();
    mock.assert_complete();
}

#[tokio::test]
async fn manual_reset_uses_status_then_use_dual_auth_and_distinct_manual_idempotency_keys() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, None);
    *mock.script.reset_status.lock().unwrap() =
        reset_status(&[4000000000000_i64], &[4000003600000_i64]);
    let status = f.action("GET", "reset-status").await;
    assert_eq!(status["ok"], true);
    assert_eq!(
        status["status"]["available_five_hour_resets"][0]["expire_at"],
        4000000000_i64
    );
    mock.push("POST", RESET_USE, json!({"code":0,"data":{"used":true}}));
    let first = f.action("POST", "reset").await;
    assert_eq!(first["ok"], true);
    assert_eq!(f.last_record()["task_type"], "reset");
    assert_eq!(f.last_record()["success"], true);
    assert!(f.last_record()["used_at"].as_i64().is_some_and(|n| n > 0));
    *mock.script.reset_status.lock().unwrap() = reset_status(&[], &[4000003600000_i64]);
    mock.push("POST", RESET_USE, json!({"code":0,"data":{"used":true}}));
    assert_eq!(f.action("POST", "reset").await["ok"], true);
    let uses = mock.seen(RESET_USE);
    assert_eq!(uses.len(), 2);
    let mut keys = Vec::new();
    for (seen, reset_type) in uses.iter().zip(["FIVE_HOUR", "WEEK"]) {
        assert_eq!(seen.body["reset_type"], reset_type);
        let key = seen.body["idempotency_key"].as_str().unwrap();
        assert!(!key.is_empty());
        assert_eq!(
            seen.body.as_object().unwrap().len(),
            2,
            "reset/use does not accept the legacy helper's expire_at payload"
        );
        keys.push(key.to_owned());
    }
    assert_ne!(
        keys[0], keys[1],
        "separate explicit manual resets must not share an account-constant idempotency key"
    );
    for seen in mock.seen(RESET_STATUS).into_iter().chain(uses) {
        assert_eq!(seen.headers["x-bigmodel-authorization"], KEY);
        assert_eq!(seen.headers["bigmodel-target-type"], "PERSONAL");
    }
    f.assert_no_implicit_opt_in();
    mock.assert_complete();
}
