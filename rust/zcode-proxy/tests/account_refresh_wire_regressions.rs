use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Body,
    extract::{Request as IncomingRequest, State},
    http::{HeaderMap, Request, StatusCode},
    Json, Router,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_core::AccountView;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
    store,
    vault::Vault,
};

const VERSION: &str = "PUBLIC-wire-version";
const DEVICE: &str = "PUBLIC-wire-device-mid";
const JWT: &str = "PUBLIC-wire-jwt";
const KEY: &str = "PUBLIC-wire-api-key";
const SESSION: &str = "PUBLIC-wire-session";
const BILLING: &str = "/api/v1/zcode-plan/billing/balance";
const CURRENT: &str = "/api/v1/zcode-plan/billing/current";
const LIMIT: &str = "/api/monitor/usage/quota/limit";
const SUBSCRIPTION: &str = "/api/biz/subscription/list";

#[derive(Default)]
struct Script {
    steps: Mutex<VecDeque<(StatusCode, Value)>>,
    seen: Mutex<Vec<(String, HeaderMap)>>,
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
            request: IncomingRequest,
        ) -> (StatusCode, Json<Value>) {
            script
                .seen
                .lock()
                .unwrap()
                .push((request.uri().to_string(), request.headers().clone()));
            let (status, body) = script
                .steps
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or((StatusCode::INTERNAL_SERVER_ERROR, json!({"code":500})));
            (status, Json(body))
        }
        let script = Arc::new(Script::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(serve).with_state(script.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base, script, task }
    }

    fn push(&self, status: StatusCode, body: Value) {
        self.script.steps.lock().unwrap().push_back((status, body));
    }

    fn fixture(&self, jwt: &str, key: &str) -> (Arc<AppState>, i64) {
        let db = store::open(":memory:");
        let vault = Vault::from_secret("PUBLIC wire fixture seed").unwrap();
        let id = store::insert_account_encrypted(
            &db,
            &vault,
            &AccountView {
                email: "wire@example.invalid".into(),
                provider: "zai".into(),
                enabled: true,
                status: "active".into(),
                ..Default::default()
            },
            jwt,
            key,
        )
        .unwrap();
        db.execute(
            "UPDATE accounts SET device_mid=?1 WHERE id=?2",
            rusqlite::params![DEVICE, id],
        )
        .unwrap();
        let mut state = AppState::try_from_db_with_vault(
            String::new(),
            UpstreamUrls {
                zai: format!("{}/unused-relay", self.base),
                zai_fallback: format!("{}/unused-fallback", self.base),
            },
            db,
            vault,
        )
        .unwrap();
        state.management.billing_base = format!("{}/api/v1/zcode-plan", self.base);
        state.management.quota_limit = format!("{}{LIMIT}", self.base);
        state.management.subscription = format!("{}{SUBSCRIPTION}", self.base);
        state.management.oauth_token = format!("{}/unused-oauth", self.base);
        state.management.app_version = VERSION.into();
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        (Arc::new(state), id)
    }
}

async fn refresh(state: &Arc<AppState>, id: i64) -> Value {
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/accounts/{id}/refresh"))
        .header("host", "localhost:8080")
        .header("origin", "http://localhost:8080")
        .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
        .body(Body::empty())
        .unwrap();
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        build_router(state.clone()).oneshot(request),
    )
    .await
    .expect("loopback refresh deadline")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["success"], true);
    let (stored, expiration): (String, String) = state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT quota_json,plan_expire FROM accounts WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        body["account"]["quota"],
        serde_json::from_str::<Value>(&stored).unwrap(),
        "published quota must be durable"
    );
    assert_eq!(
        body["account"]["plan_expire"], expiration,
        "published expiration must be durable"
    );
    body["account"].clone()
}

fn billing(reset: Value, remaining: i64) -> Value {
    json!({"code":0,"data":{"plans":[{"plan_id":"pro","status":"active",
        "expireTime":"2096-12-31 23:59"}],"balances":[{"plan_id":"pro",
        "total_units":100,"remaining_units":remaining,"period_end":reset}]}})
}

fn monitor() -> Value {
    json!({"code":200,"data":{"limits":[{"type":"TIME_LIMIT","usage":100,"remaining":75}]}})
}

#[tokio::test]
async fn management_requests_carry_go_client_identity_across_billing_and_monitor() {
    let mock = Mock::start().await;
    let (state, id) = mock.fixture(JWT, KEY);
    mock.push(StatusCode::NOT_FOUND, json!({"code":404}));
    mock.push(StatusCode::OK, billing(Value::Null, 0));
    mock.push(StatusCode::OK, monitor());
    mock.push(StatusCode::OK, json!({"code":200,"data":[]}));
    let account = refresh(&state, id).await;
    assert_eq!(account["quota"]["source"], "api.z.ai/monitor");
    let seen = mock.script.seen.lock().unwrap();
    assert_eq!(seen.len(), 4);
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let platform_os = if os == "windows" { "win32" } else { os };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    };
    let mut request_ids = Vec::new();
    for ((uri, headers), (path, authorization)) in seen.iter().zip([
        (BILLING, format!("Bearer {JWT}")),
        (CURRENT, format!("Bearer {JWT}")),
        (LIMIT, KEY.into()),
        (SUBSCRIPTION, KEY.into()),
    ]) {
        let expected_uri = if matches!(path, BILLING | CURRENT) {
            format!("{path}?app_version={VERSION}")
        } else {
            path.into()
        };
        assert_eq!(uri, &expected_uri);
        for (name, expected) in [
            ("authorization", authorization),
            ("user-agent", format!("ZCode/{VERSION}")),
            ("http-referer", "https://zcode.z.ai".into()),
            ("x-title", "Z Code@electron".into()),
            ("x-zcode-app-version", VERSION.into()),
            ("x-device-mid", DEVICE.into()),
            ("x-release-channel", "stable".into()),
            ("x-client-language", "zh-CN".into()),
            ("content-type", "application/json".into()),
            ("x-os-category", os.into()),
            ("x-platform", format!("{platform_os}-{arch}")),
        ] {
            assert_eq!(
                headers.get(name).and_then(|v| v.to_str().ok()),
                Some(expected.as_str()),
                "{path}: {name}"
            );
        }
        assert!(
            headers
                .get("x-client-timezone")
                .is_some_and(|v| !v.is_empty()),
            "{path}: missing client timezone"
        );
        let request_id = headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .expect("Go request identity header");
        assert_eq!(request_id.len(), 36);
        assert!(request_id
            .bytes()
            .enumerate()
            .all(|(i, b)| if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }));
        assert!(
            !request_ids.contains(&request_id),
            "each request needs a fresh identity"
        );
        request_ids.push(request_id);
    }
    assert!(mock.script.steps.lock().unwrap().is_empty());
}

#[tokio::test]
async fn subscription_expiration_formats_equivalent_instants_consistently() {
    let mock = Mock::start().await;
    let (state, id) = mock.fixture("", KEY);
    let mut formatted = Vec::new();
    for expiration in [
        json!(3_976_283_040_i64),
        json!("3976283040000"),
        json!("2096-01-01T19:04:00Z"),
        json!("2096-01-02T03:04:00+08:00"),
    ] {
        mock.push(StatusCode::OK, monitor());
        mock.push(
            StatusCode::OK,
            json!({"code":200,"data":[{
                "status":"VALID","inCurrentPeriod":true,"productName":"Pro","expireTime":expiration
            }]}),
        );
        let account = refresh(&state, id).await;
        assert_eq!(account["quota"]["source"], "api.z.ai/monitor");
        assert_eq!(account["plan_tier"], "Pro");
        let display = account["plan_expire"].as_str().unwrap().to_owned();
        assert_eq!(display.len(), 16, "expiration display is YYYY-MM-DD HH:MM");
        assert_eq!(account["quota"]["plan_expire"], display);
        formatted.push((expiration, display));
    }
    // Equal instants must format alike in any local timezone, without mutating TZ.
    assert!(
        formatted
            .iter()
            .all(|(_, display)| display == &formatted[0].1),
        "equivalent expiration instants diverged: {formatted:?}"
    );
    for naive in ["2096-01-02 03:04", "2096-01-02"] {
        mock.push(StatusCode::OK, monitor());
        mock.push(
            StatusCode::OK,
            json!({"code":200,"data":[{
                "status":"VALID","inCurrentPeriod":true,"productName":"Pro","expireTime":naive
            }]}),
        );
        let account = refresh(&state, id).await;
        assert_eq!(
            account["plan_expire"], naive,
            "timezone-free expiration must keep its wall time"
        );
    }
    assert!(mock.script.steps.lock().unwrap().is_empty());
}

#[tokio::test]
async fn billing_reset_strings_normalize_to_seconds_without_using_plan_expiration() {
    let mock = Mock::start().await;
    let (state, id) = mock.fixture(JWT, "");
    // 2096-01-02 03:04 in the upstream's fixed UTC+8 timezone.
    for reset in [
        json!(3_976_283_040_i64),
        json!(3_976_283_040_000_i64),
        json!(" 3976283040 "),
        json!("3976283040000"),
        json!("2096-01-01T19:04:00Z"),
        json!("2096-01-02T03:04:00+08:00"),
        json!("2096-01-02 03:04"),
    ] {
        mock.push(StatusCode::OK, billing(reset.clone(), 75));
        let account = refresh(&state, id).await;
        assert_eq!(
            account["quota"]["next_reset"], 3_976_283_040_i64,
            "reset input: {reset}"
        );
        assert_eq!(account["plan_expire"], "2096-12-31 23:59");
    }
    assert!(mock.script.steps.lock().unwrap().is_empty());
}
