use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    extract::{Request as IncomingRequest, State},
    http::{HeaderMap, Request, StatusCode},
    response::Response,
    Router,
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
};

const AVAILABILITY: &str = "/api/offpeak/availability";
const CONTROL_PATH: &str = "/api/v1/off-peak/ticket/availability";
const SESSION: &str = "PUBLIC-offpeak-session";
const ROOT: &str = "PUBLIC-offpeak-root-key";
const FIRST_JWT: &str = "PUBLIC-offpeak-first-jwt";
const SECOND_JWT: &str = "PUBLIC-offpeak-second-jwt";
const FIRST_KEY: &str = "PUBLIC-offpeak-first-api-key";
const SECOND_KEY: &str = "PUBLIC-offpeak-second-api-key";
const VERSION: &str = "PUBLIC-offpeak-version";
const DEADLINE: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    uri: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

struct Step {
    status: StatusCode,
    body: Value,
}

impl Step {
    fn json(body: Value) -> Self {
        Self {
            status: StatusCode::OK,
            body,
        }
    }

    fn error(status: StatusCode, body: Value) -> Self {
        Self { status, body }
    }
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
    async fn start(steps: Vec<Step>) -> Self {
        async fn serve(State(script): State<Arc<Script>>, request: IncomingRequest) -> Response {
            let (parts, body) = request.into_parts();
            let bytes = to_bytes(body, 1 << 20).await.unwrap();
            script.seen.lock().unwrap().push(Seen {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                headers: parts.headers,
                body: bytes.to_vec(),
            });
            let step = script.steps.lock().unwrap().pop_front().unwrap_or_else(|| {
                Step::error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error": "unexpected loopback request"}),
                )
            });
            Response::builder()
                .status(step.status)
                .header("content-type", "application/json")
                .body(Body::from(step.body.to_string()))
                .unwrap()
        }

        let script = Arc::new(Script {
            steps: Mutex::new(steps.into()),
            ..Script::default()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(serve).with_state(script.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base, script, task }
    }

    fn control_base(&self) -> String {
        format!("{}/api/v1/off-peak", self.base)
    }

    fn seen(&self) -> Vec<Seen> {
        self.script.seen.lock().unwrap().clone()
    }
}

struct Reply {
    status: StatusCode,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).expect("response must be JSON")
    }

    fn expect_json(&self, status: StatusCode, body: Value) {
        assert_eq!(self.status, status, "body={}", self.body);
        assert_eq!(self.json(), body);
        self.assert_no_credentials();
    }

    fn assert_no_credentials(&self) {
        for secret in [ROOT, SESSION, FIRST_JWT, SECOND_JWT, FIRST_KEY, SECOND_KEY] {
            assert!(
                !self.body.contains(secret),
                "availability response exposed a fixture credential"
            );
        }
    }
}

struct Fixture {
    state: Arc<AppState>,
    app: Router,
}

impl Fixture {
    fn new(base: String, accounts: &[AccountView]) -> Self {
        let db = store::open(":memory:");
        for account in accounts {
            store::upsert_account(&db, account, &account.zcode_jwt, &account.api_key);
        }
        let mut state = AppState::from_db(
            ROOT.into(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
            db,
        );
        state.offpeak_control_base = base;
        state.management.app_version = VERSION.into();
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        let state = Arc::new(state);
        Self {
            app: build_router(state.clone()),
            state,
        }
    }

    async fn availability(&self, session: Option<&str>) -> Reply {
        let mut request = Request::builder()
            .method("GET")
            .uri(AVAILABILITY)
            .header("host", "localhost:8787")
            .header("authorization", format!("Bearer {ROOT}"))
            .header("x-api-key", ROOT);
        if let Some(session) = session {
            request = request.header("cookie", format!("{SESSION_COOKIE}={session}"));
        }
        tokio::time::timeout(DEADLINE, async {
            let response = self
                .app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
            Reply {
                status,
                body: String::from_utf8(bytes.to_vec()).unwrap(),
            }
        })
        .await
        .expect("availability request exceeded the test deadline")
    }
}

fn account(email: &str, jwt: &str, key: &str) -> AccountView {
    AccountView {
        email: email.into(),
        provider: "zai".into(),
        enabled: true,
        status: "active".into(),
        zcode_jwt: jwt.into(),
        api_key: key.into(),
        ..AccountView::default()
    }
}

fn envelope(can_take: bool, next_take_at: i64) -> Value {
    json!({"code": 0, "data": {
        "can_take_number": can_take, "next_take_at": next_take_at
    }})
}

fn success(email: &str, can_take: bool, next_take_at: i64) -> Value {
    json!({
        "ok": true, "can_take": can_take, "next_take_at": next_take_at, "account": email
    })
}

fn ineligible_accounts() -> Vec<AccountView> {
    let mut disabled = account("disabled@example.test", FIRST_JWT, FIRST_KEY);
    disabled.enabled = false;
    let mut other = account("other@example.test", FIRST_JWT, FIRST_KEY);
    other.provider = "other".into();
    vec![
        disabled,
        other,
        account("jwtless@example.test", "", FIRST_KEY),
    ]
}

fn assert_wire(seen: &Seen, jwt: &str, key: &str) {
    assert_eq!(seen.method, "GET");
    assert!(seen.body.is_empty());
    let url = if seen.uri.starts_with("http://") {
        reqwest::Url::parse(&seen.uri).unwrap()
    } else {
        reqwest::Url::parse(&format!("http://localhost{}", seen.uri)).unwrap()
    };
    assert_eq!(url.path(), CONTROL_PATH);
    assert!(url.query().is_none());
    assert_eq!(seen.headers["authorization"], format!("Bearer {jwt}"));
    if key.is_empty() {
        assert!(!seen.headers.contains_key("x-coding-plan-api-key"));
    } else {
        assert_eq!(seen.headers["x-coding-plan-api-key"], key);
    }
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    };
    for (name, expected) in [
        ("user-agent", format!("ZCode/{VERSION}")),
        ("http-referer", "https://zcode.z.ai".into()),
        ("x-title", "Z Code@electron".into()),
        ("x-zcode-app-version", VERSION.into()),
        ("x-platform", format!("{os}-{arch}")),
        ("x-release-channel", "stable".into()),
        ("x-client-language", "zh-CN".into()),
        (
            "x-os-category",
            if os == "win32" { "windows" } else { os }.into(),
        ),
    ] {
        assert_eq!(
            seen.headers.get(name).unwrap().to_str().unwrap(),
            expected,
            "{name}"
        );
    }
    assert!(!seen.headers["x-client-timezone"]
        .to_str()
        .unwrap()
        .is_empty());
    assert_eq!(seen.headers["x-request-id"].to_str().unwrap().len(), 36);
    for name in ["cookie", "x-api-key", "api-key"] {
        assert!(
            !seen.headers.contains_key(name),
            "outbound {name} must be absent"
        );
    }
    for value in seen.headers.values() {
        let value = value.to_str().unwrap();
        for secret in [ROOT, SESSION] {
            assert!(
                !value.contains(secret),
                "outbound header leaked an admin credential"
            );
        }
    }
}

#[tokio::test]
async fn no_eligible_account_returns_exact_error_without_contacting_upstream() {
    let skipped = ineligible_accounts();
    for accounts in [
        vec![],
        vec![skipped[0].clone()],
        vec![skipped[1].clone()],
        vec![skipped[2].clone()],
        skipped,
    ] {
        let mock = Mock::start(vec![]).await;
        let f = Fixture::new(mock.control_base(), &accounts);
        f.availability(Some(SESSION)).await.expect_json(
            StatusCode::OK,
            json!({"ok": false, "error": "无可用 JWT 账号"}),
        );
        assert!(mock.seen().is_empty());
    }
}

#[tokio::test]
async fn first_stored_eligible_account_wins_and_sends_only_one_authenticated_get() {
    let mock = Mock::start(vec![Step::json(envelope(true, 1700000000))]).await;
    let first = account("z-first@example.test", FIRST_JWT, FIRST_KEY);
    let second = account("a-second@example.test", SECOND_JWT, SECOND_KEY);
    let mut accounts = ineligible_accounts();
    accounts.extend([first.clone(), second]);
    let f = Fixture::new(mock.control_base(), &accounts);
    f.availability(Some(SESSION))
        .await
        .expect_json(StatusCode::OK, success(&first.email, true, 1700000000));
    let seen = mock.seen();
    assert_eq!(seen.len(), 1);
    assert_wire(&seen[0], FIRST_JWT, FIRST_KEY);
}

#[tokio::test]
async fn unavailable_defaults_next_take_at_to_zero_and_omits_an_empty_api_key() {
    let mock = Mock::start(vec![Step::json(json!({
        "code": 0, "data": {"can_take_number": false}
    }))])
    .await;
    let account = account("no-key@example.test", FIRST_JWT, "");
    let f = Fixture::new(mock.control_base(), std::slice::from_ref(&account));
    f.availability(Some(SESSION))
        .await
        .expect_json(StatusCode::OK, success(&account.email, false, 0));
    let seen = mock.seen();
    assert_eq!(seen.len(), 1);
    assert_wire(&seen[0], FIRST_JWT, "");
}

#[tokio::test]
async fn bodies_without_code_are_read_as_is_and_do_not_unwrap_data() {
    let mock = Mock::start(vec![
        Step::json(json!({"can_take_number": true})),
        Step::json(json!({"data": {"can_take_number": true, "next_take_at": 1700000000}})),
    ])
    .await;
    let account = account("bare@example.test", FIRST_JWT, FIRST_KEY);
    let f = Fixture::new(mock.control_base(), std::slice::from_ref(&account));
    for can_take in [true, false] {
        f.availability(Some(SESSION))
            .await
            .expect_json(StatusCode::OK, success(&account.email, can_take, 0));
    }
    let seen = mock.seen();
    assert_eq!(seen.len(), 2);
    for request in &seen {
        assert_wire(request, FIRST_JWT, FIRST_KEY);
    }
}

#[tokio::test]
async fn http_failure_continues_to_second_account_without_exposing_credentials() {
    let mock = Mock::start(vec![
        Step::error(
            StatusCode::UNAUTHORIZED,
            json!({"message": format!("rejected {FIRST_JWT} {FIRST_KEY}")}),
        ),
        Step::json(envelope(true, 1700000000)),
    ])
    .await;
    let first = account("first@example.test", FIRST_JWT, FIRST_KEY);
    let second = account("second@example.test", SECOND_JWT, SECOND_KEY);
    let f = Fixture::new(mock.control_base(), &[first, second.clone()]);
    f.availability(Some(SESSION))
        .await
        .expect_json(StatusCode::OK, success(&second.email, true, 1700000000));
    let seen = mock.seen();
    assert_eq!(seen.len(), 2);
    assert_wire(&seen[0], FIRST_JWT, FIRST_KEY);
    assert_wire(&seen[1], SECOND_JWT, SECOND_KEY);
}

#[tokio::test]
async fn all_failures_report_only_the_last_account_error_and_redact_echoed_credentials() {
    let mock = Mock::start(vec![
        Step::error(
            StatusCode::UNAUTHORIZED,
            json!({"message": format!("rejected {FIRST_JWT} {FIRST_KEY}")}),
        ),
        Step::error(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"message": format!("rejected {SECOND_JWT} {SECOND_KEY}")}),
        ),
    ])
    .await;
    let first = account("first@example.test", FIRST_JWT, FIRST_KEY);
    let second = account("last@example.test", SECOND_JWT, SECOND_KEY);
    let f = Fixture::new(mock.control_base(), &[first.clone(), second.clone()]);
    let reply = f.availability(Some(SESSION)).await;
    assert_eq!(reply.status, StatusCode::OK, "body={}", reply.body);
    reply.assert_no_credentials();
    let body = reply.json();
    let error = body["error"].as_str().expect("error must be a string");
    reply.expect_json(StatusCode::OK, json!({"ok": false, "error": error}));
    assert!(error.starts_with("所有账号探测失败（"), "error={error}");
    assert!(error.ends_with('）'), "error={error}");
    assert!(error.contains(&second.email), "error={error}");
    assert!(error.contains("503"), "error={error}");
    assert!(!error.contains(&first.email), "error={error}");
    let seen = mock.seen();
    assert_eq!(seen.len(), 2);
    assert_wire(&seen[0], FIRST_JWT, FIRST_KEY);
    assert_wire(&seen[1], SECOND_JWT, SECOND_KEY);
}

#[tokio::test]
async fn nonzero_business_code_is_a_failure_even_with_success_shaped_data() {
    let mock = Mock::start(vec![
        Step::json(json!({
            "code": 7301,
            "message": format!("rejected {FIRST_JWT} {FIRST_KEY}"),
            "data": {"can_take_number": true, "next_take_at": 1700000000}
        })),
        Step::json(envelope(false, 0)),
    ])
    .await;
    let first = account("first@example.test", FIRST_JWT, FIRST_KEY);
    let second = account("second@example.test", SECOND_JWT, SECOND_KEY);
    let f = Fixture::new(mock.control_base(), &[first, second.clone()]);
    f.availability(Some(SESSION))
        .await
        .expect_json(StatusCode::OK, success(&second.email, false, 0));
    let seen = mock.seen();
    assert_eq!(seen.len(), 2);
    assert_wire(&seen[0], FIRST_JWT, FIRST_KEY);
    assert_wire(&seen[1], SECOND_JWT, SECOND_KEY);
}

#[tokio::test]
async fn account_group_egress_takes_precedence_over_default_and_global_proxies() {
    let origin = Mock::start(vec![]).await;
    let global = Mock::start(vec![]).await;
    let default = Mock::start(vec![]).await;
    let group = Mock::start(vec![Step::json(envelope(true, 1700000000))]).await;
    let mut account = account("group@example.test", FIRST_JWT, FIRST_KEY);
    account.account_group = "offpeak-test-group".into();
    let f = Fixture::new(origin.control_base(), &[account.clone()]);
    f.state
        .persist_settings(&[("upstream_proxy", &global.base)])
        .unwrap();
    for (mock, is_default, group_name) in
        [(&default, 1_i64, ""), (&group, 0_i64, "offpeak-test-group")]
    {
        let port = reqwest::Url::parse(&mock.base).unwrap().port().unwrap();
        f.state
            .db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO proxy_nodes(name, type, host, port, is_default, group_name, enabled)
                 VALUES('PUBLIC offpeak proxy', 'http', '127.0.0.1', ?1, ?2, ?3, 1)",
                rusqlite::params![i64::from(port), is_default, group_name],
            )
            .unwrap();
    }
    f.availability(Some(SESSION))
        .await
        .expect_json(StatusCode::OK, success(&account.email, true, 1700000000));
    assert!(origin.seen().is_empty(), "probe bypassed the account proxy");
    assert!(global.seen().is_empty(), "probe used the global proxy");
    assert!(default.seen().is_empty(), "probe used the default proxy");
    let seen = group.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].uri, format!("{}{CONTROL_PATH}", origin.base));
    assert_wire(&seen[0], FIRST_JWT, FIRST_KEY);
}

#[tokio::test]
async fn missing_session_returns_exact_unauthorized_json_without_contacting_upstream() {
    let mock = Mock::start(vec![Step::json(envelope(true, 1700000000))]).await;
    let f = Fixture::new(
        mock.control_base(),
        &[account("first@example.test", FIRST_JWT, FIRST_KEY)],
    );
    f.availability(None).await.expect_json(
        StatusCode::UNAUTHORIZED,
        json!({"error": {"message": "unauthorized", "type": "api_error"}}),
    );
    assert!(mock.seen().is_empty());
}
