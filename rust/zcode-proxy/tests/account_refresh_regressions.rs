use std::{
    collections::VecDeque,
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
    state::{AppState, ManagementUrls, UpstreamUrls},
    store,
    vault::Vault,
};

const SESSION: &str = "PUBLIC-account-refresh-session";
const JWT: &str = "PUBLIC-account-refresh-jwt";
const KEY: &str = "PUBLIC-account-refresh-api-key";
const VERSION: &str = "PUBLIC-refresh-test-version";
const BILLING: &str = "/api/v1/zcode-plan/billing/balance";
const CURRENT: &str = "/api/v1/zcode-plan/billing/current";
const LIMIT: &str = "/api/monitor/usage/quota/limit";
const SUBSCRIPTION: &str = "/api/biz/subscription/list";

#[derive(Clone, Debug, PartialEq)]
struct Seen {
    method: String,
    path: String,
    query: Option<String>,
    authorization: String,
}

struct Step {
    status: StatusCode,
    body: Value,
    gate: Option<Arc<Gate>>,
}

#[derive(Default)]
struct Gate {
    entered: Notify,
    release: Notify,
}

#[derive(Default)]
struct Script {
    steps: Mutex<VecDeque<Step>>,
    seen: Mutex<Vec<Seen>>,
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
            script.seen.lock().unwrap().push(Seen {
                method: request.method().to_string(),
                path: request.uri().path().into(),
                query: request.uri().query().map(str::to_owned),
                authorization: request
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .into(),
            });
            let step = script.steps.lock().unwrap().pop_front();
            let Some(step) = step else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"code":500,"msg":"unexpected mock request"})),
                );
            };
            if let Some(gate) = step.gate {
                gate.entered.notify_one();
                gate.release.notified().await;
            }
            (step.status, Json(step.body))
        }
        let script = Arc::new(Script::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(serve).with_state(script.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base, script, task }
    }

    fn push(&self, status: StatusCode, body: Value) {
        self.script.steps.lock().unwrap().push_back(Step {
            status,
            body,
            gate: None,
        });
    }

    fn assert_seen(&self, expected: &[(&str, &str)]) {
        let actual = self.script.seen.lock().unwrap().clone();
        let expected: Vec<_> = expected
            .iter()
            .map(|&(path, authorization)| Seen {
                method: "GET".into(),
                path: path.into(),
                query: matches!(path, BILLING | CURRENT).then(|| format!("app_version={VERSION}")),
                authorization: authorization.into(),
            })
            .collect();
        assert_eq!(
            actual, expected,
            "management endpoint, method, version, and credential contract"
        );
        assert!(
            self.script.steps.lock().unwrap().is_empty(),
            "not all expected upstream responses were consumed"
        );
    }
}

struct Fixture {
    state: Arc<AppState>,
    id: i64,
}

impl Fixture {
    fn new(mock: &Mock, jwt: &str, key: &str) -> Self {
        let db = store::open(":memory:");
        let vault = Vault::from_secret("PUBLIC account refresh fixture seed").unwrap();
        let id = store::insert_account_encrypted(
            &db,
            &vault,
            &AccountView {
                email: "refresh@example.invalid".into(),
                provider: "zai".into(),
                enabled: true,
                status: "exhausted".into(),
                remaining: 7.0,
                priority: 37,
                paid_fallback: true,
                ..Default::default()
            },
            jwt,
            key,
        )
        .unwrap();
        let mut state = AppState::try_from_db_with_vault(
            String::new(),
            UpstreamUrls {
                zai: format!("{}/unused-relay", mock.base),
                zai_fallback: format!("{}/unused-relay-fallback", mock.base),
            },
            db,
            vault,
        )
        .unwrap();
        state.management = ManagementUrls {
            billing_base: format!("{}/api/v1/zcode-plan", mock.base),
            quota_limit: format!("{}{LIMIT}", mock.base),
            subscription: format!("{}{SUBSCRIPTION}", mock.base),
            oauth_token: format!("{}/api/v1/oauth/token", mock.base),
            app_version: VERSION.into(),
        };
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

    async fn request(&self, authenticated: bool, origin: &str) -> (StatusCode, Value) {
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/api/accounts/{}/refresh", self.id))
            .header("host", "localhost:8080")
            .header("origin", origin);
        if authenticated {
            request = request.header("cookie", format!("{SESSION_COOKIE}={SESSION}"));
        }
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            build_router(self.state.clone()).oneshot(request.body(Body::empty()).unwrap()),
        )
        .await
        .expect("refresh must complete within the loopback test deadline")
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

    async fn refresh(&self) -> Value {
        let (status, body) = self.request(true, "http://localhost:8080").await;
        assert_eq!(status, StatusCode::OK, "refresh must succeed: {body}");
        assert_eq!(body["success"], true);
        assert_eq!(body["account"]["id"], self.id);
        self.assert_redacted(&body);
        body["account"].clone()
    }

    fn assert_redacted(&self, body: &Value) {
        let text = body.to_string();
        assert!(!text.contains(JWT), "response leaked the full JWT");
        assert!(!text.contains(KEY), "response leaked the full API key");
        assert!(
            !text.contains("vault1:"),
            "response leaked encrypted credentials"
        );
        for field in ["zcode_jwt", "api_key", "access_token", "refresh_token"] {
            assert!(
                body["account"].get(field).is_none(),
                "response exposed {field}"
            );
        }
    }

    fn stored(&self) -> Value {
        self.state.db.lock().unwrap().query_row(
            "SELECT status,cooling_until,quota_json,plan_tier,plan_expire,total_units,used_units,remaining,last_checked_at FROM accounts WHERE id=?1",
            [self.id], |r| Ok(json!({
                "status":r.get::<_,String>(0)?, "cooling_until":r.get::<_,i64>(1)?,
                "quota":serde_json::from_str::<Value>(&r.get::<_,String>(2)?).unwrap(),
                "plan_tier":r.get::<_,String>(3)?, "plan_expire":r.get::<_,String>(4)?,
                "total_units":r.get::<_,f64>(5)?, "used_units":r.get::<_,f64>(6)?,
                "remaining":r.get::<_,f64>(7)?, "last_checked_at":r.get::<_,i64>(8)?,
            }))
        ).unwrap()
    }

    fn live(&self) -> (String, i64, f64, String, String) {
        let accounts = self.state.accounts.lock().unwrap();
        let account = accounts.iter().find(|a| a.id == self.id).unwrap();
        (
            account.status.clone(),
            account.cooling_until,
            account.remaining,
            account.zcode_jwt.clone(),
            account.api_key.clone(),
        )
    }

    fn assert_quota(
        &self,
        account: &Value,
        source: &str,
        status: &str,
        total: f64,
        used: f64,
        remaining: f64,
    ) {
        let stored = self.stored();
        for key in [
            "status",
            "cooling_until",
            "plan_tier",
            "plan_expire",
            "total_units",
            "used_units",
            "remaining",
            "quota",
            "last_checked_at",
        ] {
            assert_eq!(
                account[key], stored[key],
                "public and durable {key} must agree"
            );
        }
        assert_eq!(account["status"], status);
        assert_eq!(account["plan_tier"], "Pro");
        assert_eq!(account["plan_expire"], "2096-01-02 03:04");
        assert_eq!(account["total_units"], total);
        assert_eq!(account["used_units"], used);
        assert_eq!(account["remaining"], remaining);
        assert_eq!(account["quota"]["source"], source);
        assert_eq!(account["quota"]["remaining"], remaining);
        assert!(account["last_checked_at"].as_i64().is_some_and(|n| n > 0));
        assert!(account["quota"]["refreshed_at"]
            .as_i64()
            .is_some_and(|n| n > 0));
        let live = self.live();
        assert_eq!((live.0.as_str(), live.1, live.2), (status, 0, remaining));
        let db = self.state.db.lock().unwrap();
        let loaded = store::load_accounts(&db, &self.state.vault).unwrap();
        let (reloaded, jwt, key) = loaded.iter().find(|(a, _, _)| a.id == self.id).unwrap();
        assert_eq!((&reloaded.status, reloaded.remaining), (&live.0, remaining));
        let creds = self.state.creds.lock().unwrap();
        let creds = creds.get(&self.id).unwrap();
        assert_eq!((&creds.zcode_jwt, &creds.api_key), (jwt, key));
        assert_eq!((&live.3, &live.4), (jwt, key));
    }
}

fn billing(used: f64) -> Value {
    json!({"code":0,"success":true,"data":{"result":{
        "plans":[{"plan_id":"pro","name":"Pro","status":"active","expire_time":"2096-01-02 03:04"}],
        "balances":[{"plan_id":"pro","show_name":"PUBLIC quota","total_units":100.0,"used_units":used,"remaining_units":100.0-used}]
    }}})
}

fn monitor() -> Value {
    json!({"code":200,"success":true,"data":{"level":"lite","limits":[{
        "type":"TIME_LIMIT","unit":3,"number":5,"usage":200.0,"currentValue":25.0,
        "remaining":175.0,"nextResetTime":4_000_000_000_000_i64
    }]}})
}

#[tokio::test]
async fn refresh_requires_session_and_same_origin_without_upstream_requests() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, JWT, KEY);
    let before = f.live();
    for (authenticated, origin, expected) in [
        (false, "http://localhost:8080", StatusCode::UNAUTHORIZED),
        (
            true,
            "https://foreign.example.invalid",
            StatusCode::FORBIDDEN,
        ),
    ] {
        let (status, _) = f.request(authenticated, origin).await;
        assert_eq!(status, expected);
        assert_eq!(f.live(), before);
    }
    mock.assert_seen(&[]);
}

#[tokio::test]
async fn jwt_billing_uses_bearer_current_fallback_and_persists_live_quota_transitions() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, JWT, "");
    mock.push(
        StatusCode::NOT_FOUND,
        json!({"code":404,"msg":"balance unavailable"}),
    );
    mock.push(StatusCode::OK, billing(25.0));
    let account = f.refresh().await;
    f.assert_quota(&account, "zcode.z.ai/billing", "active", 100.0, 25.0, 75.0);
    mock.push(StatusCode::OK, billing(100.0));
    let account = f.refresh().await;
    f.assert_quota(
        &account,
        "zcode.z.ai/billing",
        "exhausted",
        100.0,
        100.0,
        0.0,
    );
    mock.push(StatusCode::OK, billing(10.0));
    let account = f.refresh().await;
    f.assert_quota(&account, "zcode.z.ai/billing", "active", 100.0, 10.0, 90.0);
    let bearer = format!("Bearer {JWT}");
    mock.assert_seen(&[
        (BILLING, &bearer),
        (CURRENT, &bearer),
        (BILLING, &bearer),
        (BILLING, &bearer),
    ]);
}

#[tokio::test]
async fn api_key_monitor_is_raw_for_key_only_auth_fallback_and_exhausted_crosscheck() {
    for mode in ["key_only", "http_401", "business_401", "exhausted"] {
        let mock = Mock::start().await;
        let jwt = if mode == "key_only" { "" } else { JWT };
        let f = Fixture::new(&mock, jwt, KEY);
        match mode {
            "http_401" => mock.push(StatusCode::UNAUTHORIZED, json!({"code":401})),
            "business_401" => mock.push(StatusCode::OK, json!({"code":401,"msg":"expired"})),
            "exhausted" => mock.push(StatusCode::OK, billing(100.0)),
            _ => {}
        }
        mock.push(StatusCode::OK, monitor());
        mock.push(StatusCode::OK, json!({"code":200,"data":[{
            "status":"VALID","inCurrentPeriod":true,"productName":"Pro","expireTime":"2096-01-02 03:04"
        }]}));
        let account = f.refresh().await;
        f.assert_quota(&account, "api.z.ai/monitor", "active", 200.0, 25.0, 175.0);
        assert_eq!(account["quota"]["next_reset"], 4_000_000_000_i64);
        if mode == "exhausted" {
            let channels = account["quota"]["channels"].as_array().unwrap();
            assert_eq!(channels.len(), 2);
            assert_eq!(channels[0]["source"], "zcode.z.ai/billing");
            assert_eq!(channels[0]["exhausted"], true);
            assert_eq!(channels[1]["source"], "api.z.ai/monitor");
            assert_eq!(channels[1]["exhausted"], false);
        }
        let bearer = format!("Bearer {JWT}");
        let mut expected = Vec::new();
        if mode != "key_only" {
            expected.push((BILLING, bearer.as_str()));
        }
        expected.extend([(LIMIT, KEY), (SUBSCRIPTION, KEY)]);
        mock.assert_seen(&expected);
    }
}

#[tokio::test]
async fn operational_failure_preserves_prior_quota_status_and_credentials_without_monitor_fallback()
{
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, JWT, KEY);
    mock.push(StatusCode::OK, billing(25.0));
    f.refresh().await;
    let before_stored = f.stored();
    let before_live = f.live();
    for failure in [
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"code":503,"msg":"PUBLIC temporary outage"}),
        ),
        (
            StatusCode::OK,
            json!({"code":500,"success":false,"msg":"PUBLIC business failure"}),
        ),
    ] {
        mock.push(failure.0, failure.1.clone());
        mock.push(failure.0, failure.1);
        let (status, body) = f.request(true, "http://localhost:8080").await;
        assert_eq!(
            status,
            StatusCode::BAD_GATEWAY,
            "operational failure: {body}"
        );
        assert_eq!(body["error"]["type"], "api_error");
        assert_eq!(
            f.stored(),
            before_stored,
            "failed retrieval must preserve the last quota snapshot"
        );
        assert_eq!(
            f.live(),
            before_live,
            "failed retrieval must not invalidate or replace credentials"
        );
        f.assert_redacted(&body);
    }
    let bearer = format!("Bearer {JWT}");
    mock.assert_seen(&[
        (BILLING, &bearer),
        (BILLING, &bearer),
        (CURRENT, &bearer),
        (BILLING, &bearer),
        (CURRENT, &bearer),
    ]);
}

#[tokio::test]
async fn concurrent_refresh_returns_current_snapshot_without_duplicate_upstream_fetch() {
    let mock = Mock::start().await;
    let f = Arc::new(Fixture::new(&mock, JWT, ""));
    let before_live = f.live();
    let gate = Arc::new(Gate::default());
    mock.script.steps.lock().unwrap().push_back(Step {
        status: StatusCode::OK,
        body: billing(25.0),
        gate: Some(gate.clone()),
    });
    let first = tokio::spawn({
        let f = f.clone();
        async move { f.refresh().await }
    });
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .expect("first refresh must reach the loopback billing endpoint");
    let (status, body) = f.request(true, "http://localhost:8080").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "concurrent refresh must return the current snapshot: {body}"
    );
    assert_eq!(body["success"], true);
    assert_eq!(body["account"]["status"], before_live.0);
    assert_eq!(body["account"]["remaining"], before_live.2);
    assert_eq!(
        f.live(),
        before_live,
        "the blocked fetch must not publish partial state"
    );
    f.assert_redacted(&body);
    gate.release.notify_one();
    let account = first.await.unwrap();
    f.assert_quota(&account, "zcode.z.ai/billing", "active", 100.0, 25.0, 75.0);
    let bearer = format!("Bearer {JWT}");
    mock.assert_seen(&[(BILLING, &bearer)]);
    mock.push(StatusCode::OK, billing(10.0));
    let account = f.refresh().await;
    f.assert_quota(&account, "zcode.z.ai/billing", "active", 100.0, 10.0, 90.0);
    mock.assert_seen(&[(BILLING, &bearer), (BILLING, &bearer)]);
}
