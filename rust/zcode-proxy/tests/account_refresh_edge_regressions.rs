use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Body,
    extract::{Request as IncomingRequest, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_core::{AccountView, SelectionQuery, CHANNEL_FREE};
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
    store,
    vault::Vault,
};

const SESSION: &str = "PUBLIC-refresh-edge-session";
const JWT: &str = "PUBLIC-refresh-edge-jwt";
const KEY: &str = "PUBLIC-refresh-edge-key";
const BALANCE: &str = "/api/v1/zcode-plan/billing/balance";
const CURRENT: &str = "/api/v1/zcode-plan/billing/current";

struct Fixture {
    state: Arc<AppState>,
    id: i64,
}

impl Fixture {
    fn new(base: &str, status: &str, cooling_until: i64) -> Self {
        let db = store::open(":memory:");
        let vault = Vault::from_secret("PUBLIC refresh edge seed").unwrap();
        let id = store::insert_account_encrypted(
            &db,
            &vault,
            &AccountView {
                email: "edge@example.invalid".into(),
                provider: "zai".into(),
                enabled: true,
                status: status.into(),
                cooling_until,
                paid_fallback: true,
                remaining: 7.0,
                ..Default::default()
            },
            JWT,
            KEY,
        )
        .unwrap();
        let mut state = AppState::try_from_db_with_vault(
            String::new(),
            UpstreamUrls {
                zai: format!("{base}/unused-relay"),
                zai_fallback: format!("{base}/unused-fallback"),
            },
            db,
            vault,
        )
        .unwrap();
        state.management.billing_base = format!("{base}/api/v1/zcode-plan");
        state.management.quota_limit = format!("{base}/unused-monitor");
        state.management.subscription = format!("{base}/unused-subscription");
        state.management.oauth_token = format!("{base}/unused-oauth");
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

    async fn request(&self, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost:8080")
            .header("origin", "http://localhost:8080")
            .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            build_router(self.state.clone()).oneshot(request),
        )
        .await
        .expect("loopback request deadline")
        .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn assert_runtime(&self, enabled: bool, status: &str, selected: bool) {
        let stored: (bool, String) = self
            .state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT enabled,status FROM accounts WHERE id=?1",
                [self.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(stored, (enabled, status.into()), "durable account state");
        let accounts = self.state.accounts.lock().unwrap();
        let account = accounts.iter().find(|a| a.id == self.id).unwrap();
        assert_eq!(
            (account.enabled, account.status.as_str()),
            (enabled, status),
            "live account state"
        );
        let skip = Default::default();
        let chosen = self.state.selector.lock().unwrap().select_sticky_channel(
            &accounts,
            &SelectionQuery {
                provider: "zai",
                group: "",
                skip: &skip,
                channel: CHANNEL_FREE,
                now_unix: now_secs(),
            },
            "PUBLIC-refresh-edge-sticky",
        );
        assert_eq!(
            chosen.account.map(|a| a.id),
            selected.then_some(self.id),
            "free-channel eligibility"
        );
    }
}

#[derive(Default)]
struct Script {
    steps: Mutex<VecDeque<(StatusCode, &'static str, Option<&'static str>)>>,
    paths: Mutex<Vec<String>>,
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
        async fn serve(State(script): State<Arc<Script>>, request: IncomingRequest) -> Response {
            script
                .paths
                .lock()
                .unwrap()
                .push(request.uri().path().into());
            let (status, body, location) = script.steps.lock().unwrap().pop_front().unwrap_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "unexpected mock request",
                None,
            ));
            let mut response = (status, body).into_response();
            if let Some(location) = location {
                response
                    .headers_mut()
                    .insert("location", location.parse().unwrap());
            }
            response
        }
        let script = Arc::new(Script::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(serve).with_state(script.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base, script, task }
    }
}

#[tokio::test]
async fn enabled_route_revives_account_disabled_through_metadata_update() {
    let f = Fixture::new("http://127.0.0.1:1", "active", 0);
    f.assert_runtime(true, "active", true);
    let (status, _) = f
        .request(
            "PUT",
            &format!("/api/accounts/{}", f.id),
            json!({"enabled":false}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    f.assert_runtime(false, "disabled", false);
    let (status, _) = f
        .request(
            "PUT",
            &format!("/api/accounts/{}/enabled", f.id),
            json!({"enabled":true}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    f.assert_runtime(true, "active", true);
}

#[tokio::test]
async fn account_list_exposes_effective_status_without_rewriting_expired_cooling() {
    let now = now_secs();
    for (raw, deadline, effective) in [
        ("cooling", now - 1, "active"),
        ("cooling", 0, "active"),
        ("cooling", now + 3600, "cooling"),
        ("active", 0, "active"),
        ("disabled", 0, "disabled"),
    ] {
        let f = Fixture::new("http://127.0.0.1:1", raw, deadline);
        let (status, body) = f.request("GET", "/api/accounts", Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        let accounts = body["accounts"].as_array().unwrap();
        assert_eq!(accounts.len(), 1);
        let account = &accounts[0];
        assert_eq!(
            account["status"], effective,
            "raw={raw}, deadline={deadline}"
        );
        assert_eq!(account["raw_status"], raw);
        assert_eq!(account["cooling_until"], deadline);
        let stored: (String, i64) = f
            .state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT status,cooling_until FROM accounts WHERE id=?1",
                [f.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            stored,
            (raw.into(), deadline),
            "listing must not mutate persisted state"
        );
        let live = f.state.accounts.lock().unwrap();
        let live = live.iter().find(|a| a.id == f.id).unwrap();
        assert_eq!((live.status.as_str(), live.cooling_until), (raw, deadline));
    }
}

#[tokio::test]
async fn non_json_billing_response_tries_current_without_monitor_or_redirect_following() {
    const QUOTA: &str = r#"{"code":0,"data":{"balances":[{"total_units":100,"used_units":25,"remaining_units":75}]}}"#;
    // HTTP authentication failure remains authoritative even with an HTML body.
    let auth = Mock::start().await;
    auth.script.steps.lock().unwrap().extend([
        (StatusCode::FORBIDDEN, "<html>denied</html>", None),
        (StatusCode::UNAUTHORIZED, "<html>denied</html>", None),
    ]);
    let f = Fixture::new(&auth.base, "active", 0);
    let (status, body) = f
        .request(
            "POST",
            &format!("/api/accounts/{}/refresh", f.id),
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["account"]["status"], "invalid");
    // API-key auth fallback is allowed, but billing/current is not retried on 403.
    assert!(!auth
        .script
        .paths
        .lock()
        .unwrap()
        .iter()
        .any(|p| p == CURRENT));

    for first in [
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "<html>temporary outage</html>",
            None,
        ),
        (
            StatusCode::FOUND,
            "<html>redirect</html>",
            Some("/must-not-follow"),
        ),
        (StatusCode::OK, "PUBLIC invalid JSON", None),
    ] {
        let mock = Mock::start().await;
        mock.script
            .steps
            .lock()
            .unwrap()
            .extend([first, (StatusCode::OK, QUOTA, None)]);
        let f = Fixture::new(&mock.base, "exhausted", 0);
        let (status, body) = f
            .request(
                "POST",
                &format!("/api/accounts/{}/refresh", f.id),
                Value::Null,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "billing/current must recover {first:?}: {body}"
        );
        assert_eq!(body["success"], true);
        assert_eq!(body["account"]["quota"]["source"], "zcode.z.ai/billing");
        assert_eq!(body["account"]["remaining"], 75.0);
        f.assert_runtime(true, "active", true);
        assert_eq!(
            *mock.script.paths.lock().unwrap(),
            [BALANCE, CURRENT],
            "no monitor fallback or redirect follow"
        );
        assert!(mock.script.steps.lock().unwrap().is_empty());
        let stored: String = f
            .state
            .db
            .lock()
            .unwrap()
            .query_row("SELECT quota_json FROM accounts WHERE id=?1", [f.id], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&stored).unwrap(),
            body["account"]["quota"]
        );
    }
}
