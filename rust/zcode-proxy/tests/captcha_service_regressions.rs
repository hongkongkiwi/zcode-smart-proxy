use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
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
use zcode_core::{egress::CaptchaSolver, AccountView};
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
    store,
};

const STATUS: &str = "/api/captcha/status";
const INVALIDATE: &str = "/api/captcha/invalidate";
const SOLVE: &str = "/api/captcha/solve";
const CONFIGS: &str = "/api/v1/client/configs";
const HOST: &str = "localhost:8787";
const SESSION: &str = "PUBLIC-captcha-session";
const ROOT: &str = "PUBLIC-captcha-root-key";
const JWT: &str = "PUBLIC-captcha-account-jwt";
const ACCOUNT_KEY: &str = "PUBLIC-captcha-account-api-key";
const VERSION: &str = "PUBLIC-captcha-version+build &1";
const PARAM: &str = "PUBLIC-param";
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
    bytes: Vec<u8>,
    arrived: Option<tokio::sync::oneshot::Sender<()>>,
    release: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl Step {
    fn json(body: Value) -> Self {
        Self::raw(StatusCode::OK, body.to_string().into_bytes())
    }

    fn raw(status: StatusCode, bytes: Vec<u8>) -> Self {
        Self {
            status,
            bytes,
            arrived: None,
            release: None,
        }
    }

    fn held(
        mut self,
        arrived: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) -> Self {
        self.arrived = Some(arrived);
        self.release = Some(release);
        self
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
                Step::raw(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    b"unexpected loopback request".to_vec(),
                )
            });
            if let Some(arrived) = step.arrived {
                arrived.send(()).expect("config arrival receiver dropped");
            }
            if let Some(release) = step.release {
                release.await.expect("config release sender dropped");
            }
            Response::builder()
                .status(step.status)
                .header("content-type", "application/json")
                .body(Body::from(step.bytes))
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

    fn configs(&self) -> String {
        format!("{}{CONFIGS}", self.base)
    }

    fn seen(&self) -> Vec<Seen> {
        self.script.seen.lock().unwrap().clone()
    }
}

struct Solver {
    calls: AtomicUsize,
    param: Option<&'static str>,
}

impl Solver {
    fn new(param: Option<&'static str>) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            param,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl CaptchaSolver for Solver {
    fn solve(&self, _scene: &str, _prefix: &str) -> Option<String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.param.map(str::to_owned)
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
    }

    fn expect_gateway_error(&self) {
        assert_eq!(self.status, StatusCode::BAD_GATEWAY, "body={}", self.body);
        let body = self.json();
        assert!(body.is_object(), "body={body}");
        assert_ne!(body["success"], json!(true), "body={body}");
        let message = body["message"]
            .as_str()
            .or_else(|| body["error"]["message"].as_str());
        assert!(
            message.is_some_and(|message| !message.is_empty()),
            "body={body}"
        );
    }
}

struct Fixture {
    state: Arc<AppState>,
    app: Router,
}

impl Fixture {
    fn new(configs: String, solver: Option<Arc<dyn CaptchaSolver>>) -> Self {
        let db = store::open(":memory:");
        let account = AccountView {
            id: 1,
            email: "captcha@example.test".into(),
            provider: "zai".into(),
            enabled: true,
            status: "active".into(),
            zcode_jwt: JWT.into(),
            api_key: ACCOUNT_KEY.into(),
            ..AccountView::default()
        };
        store::upsert_account(&db, &account, JWT, ACCOUNT_KEY);
        let mut state = AppState::from_db(
            ROOT.into(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
            db,
        );
        state.install_urls.client_configs = configs;
        state.management.app_version = VERSION.into();
        if let Some(solver) = solver {
            state.captcha.solver = solver;
        }
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

    async fn send(&self, method: &str, path: &str, session: Option<&str>, body: &str) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", HOST)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {ROOT}"))
            .header("x-api-key", ROOT);
        if let Some(session) = session {
            request = request.header("cookie", format!("{SESSION_COOKIE}={session}"));
        }
        if method == "POST" {
            request = request.header("origin", "http://localhost:8787");
        }
        let reply = tokio::time::timeout(DEADLINE, async {
            let response = self
                .app
                .clone()
                .oneshot(request.body(Body::from(body.to_owned())).unwrap())
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
        .expect("captcha request exceeded the test deadline");
        if path == SOLVE {
            assert!(
                !reply.body.contains(PARAM),
                "solve response exposed the parameter"
            );
        }
        reply
    }

    async fn status(&self) -> Reply {
        self.send("GET", STATUS, Some(SESSION), "").await
    }

    async fn solve(&self, body: &str) -> Reply {
        self.send("POST", SOLVE, Some(SESSION), body).await
    }

    async fn invalidate(&self) {
        self.send("POST", INVALIDATE, Some(SESSION), "")
            .await
            .expect_json(StatusCode::OK, json!({"success": true}));
    }
}

fn envelope(enabled: bool) -> Value {
    json!({"code": 0, "data": {"configs": {"captcha": {
        "enabled": enabled, "region": "cn", "prefix": "p", "sceneId": "s"
    }}}})
}

fn config(enabled: bool) -> Value {
    json!({"enabled": enabled, "region": "cn", "prefix": "p", "scene_id": "s"})
}

fn empty_status(config: Value) -> Value {
    json!({
        "has_param": false, "param_age_s": 0, "fresh": false,
        "manual_mode": false, "cache_keys": 0, "config": config
    })
}

fn empty_solve() -> Value {
    json!({"success": true, "param_len": 0, "region": ""})
}

fn solved() -> Value {
    json!({"success": true, "param_len": 12, "region": "cn"})
}

fn assert_wire(seen: &Seen) {
    assert_eq!(seen.method, "GET");
    assert!(seen.body.is_empty());
    let url = if seen.uri.starts_with("http://") {
        reqwest::Url::parse(&seen.uri).unwrap()
    } else {
        reqwest::Url::parse(&format!("http://localhost{}", seen.uri)).unwrap()
    };
    assert_eq!(url.path(), CONFIGS);
    let pairs: Vec<_> = url.query_pairs().into_owned().collect();
    assert_eq!(pairs.len(), 2, "query={pairs:?}");
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    };
    assert_eq!(
        pairs.into_iter().collect::<BTreeMap<_, _>>(),
        BTreeMap::from([("version".into(), VERSION.into()), ("os".into(), os.into())])
    );
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
        ("content-type", "application/json".into()),
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
    for name in ["authorization", "x-api-key", "api-key", "cookie"] {
        assert!(
            !seen.headers.contains_key(name),
            "outbound {name} must be absent"
        );
    }
    for value in seen.headers.values() {
        let value = value.to_str().unwrap();
        for secret in [ROOT, SESSION, JWT, ACCOUNT_KEY] {
            assert!(
                !value.contains(secret),
                "outbound header leaked a fixture credential"
            );
        }
    }
}

#[tokio::test]
async fn empty_status_matches_contract_and_all_captcha_routes_require_a_session() {
    let mock = Mock::start(vec![]).await;
    let f = Fixture::new(mock.configs(), None);
    f.status()
        .await
        .expect_json(StatusCode::OK, empty_status(Value::Null));
    for (method, path, body) in [
        ("GET", STATUS, ""),
        ("POST", INVALIDATE, ""),
        ("POST", SOLVE, "{}"),
    ] {
        let reply = f.send(method, path, None, body).await;
        assert_eq!(
            reply.status,
            StatusCode::UNAUTHORIZED,
            "path={path}, body={}",
            reply.body
        );
    }
    assert!(mock.seen().is_empty());
}

#[tokio::test]
async fn solve_rejects_malformed_json_and_unknown_account_before_fetching() {
    let mock = Mock::start(vec![]).await;
    let f = Fixture::new(mock.configs(), None);
    let malformed = f.solve("{not-json").await;
    assert_eq!(
        malformed.status,
        StatusCode::BAD_REQUEST,
        "body={}",
        malformed.body
    );
    let missing = f.solve(r#"{"account_id":99999}"#).await;
    assert_eq!(
        missing.status,
        StatusCode::NOT_FOUND,
        "body={}",
        missing.body
    );
    assert!(mock.seen().is_empty());
    f.status()
        .await
        .expect_json(StatusCode::OK, empty_status(Value::Null));
}

#[tokio::test]
async fn enabled_config_without_a_configured_solver_returns_502_with_a_message() {
    let mock = Mock::start(vec![Step::json(envelope(true))]).await;
    let f = Fixture::new(mock.configs(), None);
    f.solve("{}").await.expect_gateway_error();
    f.status()
        .await
        .expect_json(StatusCode::OK, empty_status(config(true)));
    let seen = mock.seen();
    assert_eq!(seen.len(), 1);
    assert_wire(&seen[0]);
}

#[tokio::test]
async fn disabled_config_returns_empty_success_and_is_cached_without_running_the_solver() {
    let mock = Mock::start(vec![Step::json(envelope(false))]).await;
    let solver = Arc::new(Solver::new(Some(PARAM)));
    let f = Fixture::new(mock.configs(), Some(solver.clone()));
    f.solve("{}")
        .await
        .expect_json(StatusCode::OK, empty_solve());
    f.solve("").await.expect_json(StatusCode::OK, empty_solve());
    f.invalidate().await;
    f.status()
        .await
        .expect_json(StatusCode::OK, empty_status(config(false)));
    assert_eq!(solver.calls(), 0);
    let seen = mock.seen();
    assert_eq!(seen.len(), 1);
    assert_wire(&seen[0]);
}

#[tokio::test]
async fn invalid_config_responses_return_502_and_are_not_cached() {
    for bad in [
        Step::json(json!({"code": 7, "data": envelope(false)["data"]})),
        Step::raw(StatusCode::OK, b"{not-json".to_vec()),
        Step::raw(
            StatusCode::SERVICE_UNAVAILABLE,
            envelope(false).to_string().into_bytes(),
        ),
    ] {
        let origin = Mock::start(vec![bad]).await;
        let recovery = Mock::start(vec![Step::json(envelope(false))]).await;
        let solver = Arc::new(Solver::new(Some(PARAM)));
        let f = Fixture::new(origin.configs(), Some(solver.clone()));
        f.solve("{}").await.expect_gateway_error();
        f.status()
            .await
            .expect_json(StatusCode::OK, empty_status(Value::Null));
        assert_eq!(origin.seen().len(), 1);
        f.state
            .persist_settings(&[("upstream_proxy", &recovery.base)])
            .unwrap();
        f.solve("{}")
            .await
            .expect_json(StatusCode::OK, empty_solve());
        f.status()
            .await
            .expect_json(StatusCode::OK, empty_status(config(false)));
        assert_eq!(solver.calls(), 0);
        assert_eq!(origin.seen().len(), 1);
        let seen = recovery.seen();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].uri.starts_with(&origin.base));
        assert_wire(&seen[0]);
    }
}

#[tokio::test]
async fn fresh_parameter_is_reused_for_shared_egress_and_invalidation_forces_a_new_solve() {
    let mock = Mock::start(vec![Step::json(envelope(true))]).await;
    let solver = Arc::new(Solver::new(Some(PARAM)));
    let f = Fixture::new(mock.configs(), Some(solver.clone()));
    f.solve(r#"{"account_id":1}"#)
        .await
        .expect_json(StatusCode::OK, solved());
    assert_eq!(solver.calls(), 1);
    f.solve("{}").await.expect_json(StatusCode::OK, solved());
    assert_eq!(solver.calls(), 1);
    let reply = f.status().await;
    assert_eq!(reply.status, StatusCode::OK, "body={}", reply.body);
    let status = reply.json();
    assert!(status["param_age_s"].as_u64().is_some_and(|age| age < 45));
    assert_eq!(
        status,
        json!({
            "has_param": true, "param_age_s": status["param_age_s"], "fresh": true,
            "manual_mode": false, "cache_keys": 1, "config": config(true)
        })
    );
    f.invalidate().await;
    f.status()
        .await
        .expect_json(StatusCode::OK, empty_status(config(true)));
    f.solve("{}").await.expect_json(StatusCode::OK, solved());
    assert_eq!(solver.calls(), 2);
    assert_eq!(mock.seen().len(), 1);
}

#[tokio::test]
async fn captcha_mode_off_bypasses_config_fetch_and_solver() {
    let mock = Mock::start(vec![Step::json(envelope(true))]).await;
    let solver = Arc::new(Solver::new(Some(PARAM)));
    let f = Fixture::new(mock.configs(), Some(solver.clone()));
    f.state
        .persist_settings(&[("captcha_mode", "off")])
        .unwrap();
    f.solve("{}")
        .await
        .expect_json(StatusCode::OK, empty_solve());
    f.status()
        .await
        .expect_json(StatusCode::OK, empty_status(Value::Null));
    assert!(mock.seen().is_empty());
    assert_eq!(solver.calls(), 0);
}

#[tokio::test]
async fn solver_failure_is_cooled_down_and_invalidation_does_not_clear_the_cooldown() {
    let mock = Mock::start(vec![Step::json(envelope(true))]).await;
    let solver = Arc::new(Solver::new(None));
    let f = Fixture::new(mock.configs(), Some(solver.clone()));
    f.solve("{}").await.expect_gateway_error();
    assert_eq!(solver.calls(), 1);
    f.solve("{}").await.expect_gateway_error();
    assert_eq!(solver.calls(), 1);
    f.invalidate().await;
    f.solve("{}").await.expect_gateway_error();
    assert_eq!(solver.calls(), 1);
    f.status()
        .await
        .expect_json(StatusCode::OK, empty_status(config(true)));
    assert_eq!(mock.seen().len(), 1);
}

#[tokio::test]
async fn accountless_solve_shares_the_resolved_egress_cooldown() {
    let origin = Mock::start(vec![]).await;
    let global = Mock::start(vec![Step::json(envelope(true))]).await;
    let solver = Arc::new(Solver::new(None));
    let f = Fixture::new(origin.configs(), Some(solver.clone()));
    f.state
        .persist_settings(&[("upstream_proxy", &global.base)])
        .unwrap();
    f.solve(r#"{"account_id":1}"#).await.expect_gateway_error();
    assert_eq!(solver.calls(), 1);
    f.solve("{}").await.expect_gateway_error();
    assert_eq!(solver.calls(), 1);
    assert!(origin.seen().is_empty());
    let seen = global.seen();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].uri.starts_with(&origin.base));
    assert_wire(&seen[0]);
}

#[tokio::test]
async fn cooldown_is_checked_again_after_the_config_fetch() {
    let (first_arrived_tx, first_arrived_rx) = tokio::sync::oneshot::channel();
    let (second_arrived_tx, second_arrived_rx) = tokio::sync::oneshot::channel();
    let (release_first_tx, release_first_rx) = tokio::sync::oneshot::channel();
    let (release_second_tx, release_second_rx) = tokio::sync::oneshot::channel();
    let (first_finished_tx, first_finished_rx) = tokio::sync::oneshot::channel();
    let mock = Mock::start(vec![
        Step::json(envelope(true)).held(first_arrived_tx, release_first_rx),
        Step::json(envelope(true)).held(second_arrived_tx, release_second_rx),
    ])
    .await;
    let solver = Arc::new(Solver::new(None));
    let f = Fixture::new(mock.configs(), Some(solver.clone()));
    let (first, second, ()) = tokio::time::timeout(DEADLINE, async {
        tokio::join!(
            async {
                let reply = f.solve("{}").await;
                first_finished_tx.send(()).unwrap();
                reply
            },
            async {
                first_arrived_rx.await.unwrap();
                f.solve("{}").await
            },
            async {
                second_arrived_rx.await.unwrap();
                assert_eq!(solver.calls(), 0);
                release_first_tx.send(()).unwrap();
                first_finished_rx.await.unwrap();
                release_second_tx.send(()).unwrap();
            }
        )
    })
    .await
    .expect("both cold config requests must connect before the first response is released");
    first.expect_gateway_error();
    second.expect_gateway_error();
    assert_eq!(solver.calls(), 1);
    let seen = mock.seen();
    assert_eq!(seen.len(), 2);
    assert_wire(&seen[0]);
    assert_wire(&seen[1]);
}

#[tokio::test]
async fn config_fetch_uses_global_egress_and_an_enabled_default_node_takes_precedence() {
    for default_node in [false, true] {
        let origin = Mock::start(vec![]).await;
        let global = Mock::start(vec![Step::json(envelope(false))]).await;
        let default = Mock::start(vec![Step::json(envelope(false))]).await;
        let f = Fixture::new(origin.configs(), None);
        f.state
            .persist_settings(&[("upstream_proxy", &global.base)])
            .unwrap();
        if default_node {
            let port = reqwest::Url::parse(&default.base).unwrap().port().unwrap();
            f.state
                .db
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO proxy_nodes(name, type, host, port, is_default, enabled)
                     VALUES('PUBLIC captcha default', 'http', '127.0.0.1', ?1, 1, 1)",
                    [i64::from(port)],
                )
                .unwrap();
        }
        f.solve("{}")
            .await
            .expect_json(StatusCode::OK, empty_solve());
        assert!(
            origin.seen().is_empty(),
            "config fetch bypassed the selected proxy"
        );
        let (selected, unused) = if default_node {
            (&default, &global)
        } else {
            (&global, &default)
        };
        assert!(
            unused.seen().is_empty(),
            "unselected proxy received a request"
        );
        let seen = selected.seen();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].uri.starts_with(&origin.base));
        assert_wire(&seen[0]);
    }
}
