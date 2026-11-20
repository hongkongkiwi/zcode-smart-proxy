use std::{
    collections::{BTreeMap, VecDeque},
    convert::Infallible,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{Request as IncomingRequest, State},
    http::{HeaderMap, Request, StatusCode},
    response::Response,
    Router,
};
use futures_util::stream;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tower::ServiceExt;
use zcode_core::AccountView;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::{key_hash, now_secs},
    build_router,
    highspeed::HighspeedConfig,
    state::{AppState, Creds, NamedKey, UpstreamUrls},
    store,
};

const ROUTE: &str = "/api/v1/highspeed/anthropic/v1/messages";
const DRAW: &str = "/api/v1/highspeed/draw";
const PLAIN: &str = "/plain/messages";
const PAID: &str = "/paid/messages";
const STATUS: &str = "/api/highspeed/status";
const ROOT: &str = "PUBLIC-highspeed-lane-root";
const SESSION: &str = "PUBLIC-highspeed-lane-session";
const JWT: &str = "PUBLIC-highspeed-lane-jwt";
const KEY: &str = "PUBLIC-highspeed-lane-api-key";
const ACCESS: &str = "PUBLIC-highspeed-lane-oauth-access";
const REFRESH: &str = "PUBLIC-highspeed-lane-oauth-refresh";
const DEVICE: &str = "PUBLIC-highspeed-lane-device";
const CLIENT_CARD: &str = "PUBLIC-untrusted-client-card";
const MODEL: &str = "GLM-5.1-Highspeed";
const CARD_MODEL: &str = "PUBLIC-issued-card-model";
const NOW: i64 = 1_800_000_000_000;
const LIMIT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    uri: String,
    path: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

struct Step {
    status: StatusCode,
    headers: Vec<(&'static str, String)>,
    body: Body,
}

impl Step {
    fn raw(status: StatusCode, content_type: &str, body: impl Into<Body>) -> Self {
        Self {
            status,
            headers: vec![("content-type", content_type.into())],
            body: body.into(),
        }
    }

    fn json(status: StatusCode, body: Value) -> Self {
        Self::raw(status, "application/json", body.to_string())
    }

    fn card(id: &str, model: &str, expires: i64) -> Self {
        Self::json(StatusCode::OK, card_body(id, model, expires))
    }

    fn sized_card(bytes: usize) -> Self {
        let mut body = card_body("C1", CARD_MODEL, NOW + 300_000);
        body["padding"] = json!("");
        let overhead = body.to_string().len();
        body["padding"] = json!("x".repeat(bytes - overhead));
        let body = body.to_string();
        assert_eq!(body.len(), bytes);
        Self::raw(StatusCode::OK, "application/json", body)
    }

    fn sse() -> Self {
        Self::raw(StatusCode::OK, "text/event-stream", valid_sse())
            .header("x-request-id", "PUBLIC-highspeed-upstream-request")
    }

    fn plain() -> Self {
        Self::json(StatusCode::OK, plain_body())
    }

    fn header(mut self, name: &'static str, value: &str) -> Self {
        self.headers.push((name, value.into()));
        self
    }
}

#[derive(Default)]
struct Script {
    steps: Mutex<BTreeMap<String, VecDeque<Step>>>,
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
    async fn start(steps: Vec<(&str, Step)>) -> Self {
        async fn serve(State(script): State<Arc<Script>>, request: IncomingRequest) -> Response {
            let (parts, body) = request.into_parts();
            let bytes = to_bytes(body, 2 << 20).await.unwrap();
            let path = parts.uri.path().to_owned();
            script.seen.lock().unwrap().push(Seen {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                path: path.clone(),
                headers: parts.headers,
                body: bytes.to_vec(),
            });
            let step = script
                .steps
                .lock()
                .unwrap()
                .get_mut(&path)
                .and_then(VecDeque::pop_front)
                .unwrap_or_else(|| {
                    Step::json(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({"error": "unexpected loopback request"}),
                    )
                });
            let mut response = Response::builder().status(step.status);
            for (name, value) in step.headers {
                response = response.header(name, value);
            }
            response.body(step.body).unwrap()
        }

        let script = Arc::new(Script::default());
        for (path, step) in steps {
            script
                .steps
                .lock()
                .unwrap()
                .entry(path.into())
                .or_default()
                .push_back(step);
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(serve).with_state(script.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base, script, task }
    }

    fn seen(&self, path: &str) -> Vec<Seen> {
        self.script
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.path == path)
            .cloned()
            .collect()
    }

    fn assert_paths(&self, expected: &[&str]) {
        let paths: Vec<_> = self
            .script
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.path.clone())
            .collect();
        assert_eq!(
            paths, expected,
            "unexpected upstream call, including healthy polling"
        );
    }

    fn assert_consumed(&self) {
        for (path, steps) in self.script.steps.lock().unwrap().iter() {
            assert!(steps.is_empty(), "unconsumed loopback responses at {path}");
        }
    }

    async fn wait_for(&self, path: &str, count: usize) {
        tokio::time::timeout(LIMIT, async {
            while self.seen(path).len() < count {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("expected loopback request did not arrive");
    }
}

#[derive(Debug)]
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).expect("response must be JSON")
    }

    fn expect_plain(&self) {
        assert_eq!(self.status, StatusCode::OK, "body={}", self.body);
        assert_eq!(self.json(), plain_body());
    }

    fn expect_message(&self) {
        assert_eq!(self.status, StatusCode::OK, "body={}", self.body);
        let body = self.json();
        assert_eq!(body["id"], "msg_highspeed");
        assert_eq!(body["type"], "message");
        assert_eq!(body["role"], "assistant");
        assert_eq!(
            body["content"],
            json!([{"type": "text", "text": "HIGHSPEED-OK"}])
        );
        assert_eq!(body["stop_reason"], "end_turn");
        assert_eq!(body["usage"]["input_tokens"], 11);
        assert_eq!(body["usage"]["output_tokens"], 4);
    }
}

#[derive(Clone)]
struct Fixture {
    state: Arc<AppState>,
    app: Router,
    id: i64,
    clock: Arc<AtomicI64>,
}

impl Fixture {
    fn new(mock: &Mock, access: &str) -> Self {
        Self::configured(mock, access, |_, _| {})
    }

    fn configured(mock: &Mock, access: &str, configure: impl FnOnce(&mut AppState, i64)) -> Self {
        let mut state = AppState::new(
            ROOT.into(),
            UpstreamUrls {
                zai: format!("{}{PLAIN}", mock.base),
                zai_fallback: format!("{}{PAID}", mock.base),
            },
        );
        let id = {
            let db = state.db.lock().unwrap();
            let id = store::insert_account_encrypted(
                &db,
                &state.vault,
                &AccountView {
                    email: "highspeed@example.test".into(),
                    provider: "zai".into(),
                    enabled: true,
                    status: "active".into(),
                    account_group: "lane-group".into(),
                    ..AccountView::default()
                },
                JWT,
                KEY,
            )
            .unwrap();
            db.execute(
                "UPDATE accounts SET access_token=?1,refresh_token=?2,device_mid=?3 WHERE id=?4",
                rusqlite::params![
                    state.vault.encrypt(access).unwrap(),
                    state.vault.encrypt(REFRESH).unwrap(),
                    DEVICE,
                    id
                ],
            )
            .unwrap();
            id
        };
        publish_accounts(&state);
        let clock = Arc::new(AtomicI64::new(NOW));
        let read_clock = clock.clone();
        state.highspeed = HighspeedConfig {
            draw_url: format!("{}{DRAW}", mock.base),
            messages_url: format!("{}{ROUTE}", mock.base),
            clock: Arc::new(move || read_clock.load(Ordering::SeqCst)),
        };
        // Recovery and all auxiliary configurable HTTP endpoints stay on loopback too.
        let local = |path: &str| format!("{}{path}", mock.base);
        state.management.billing_base = local("/management/billing");
        state.management.quota_limit = local("/management/quota");
        state.management.subscription = local("/management/subscription");
        state.management.oauth_token = local("/management/token");
        state.offpeak_control_base = local("/offpeak");
        state.offpeak_origin = mock.base.clone();
        state.install_urls.client_configs = local("/client/configs");
        state.install_urls.event_report = local("/install/event");
        state.automation.billing_preview = local("/automation/preview");
        state.automation.billing_claim = local("/automation/claim");
        state.automation.event_report = local("/automation/event");
        state.automation.reset_status = local("/automation/reset/status");
        state.automation.reset_use = local("/automation/reset/use");
        state.oauth.authorize = local("/oauth/authorize");
        state.oauth.userinfo = local("/oauth/userinfo");
        state.oauth.business_login = local("/oauth/login");
        state.oauth.customer_info = local("/oauth/customer");
        state.oauth.project_keys_base = local("/oauth/keys");
        state.oauth.manual_redirect = local("/oauth/manual");
        state.oauth.callback_url = local("/oauth/callback");
        state.oauth_poll.init = local("/oauth/init");
        state.oauth_poll.poll_base = local("/oauth/poll");
        state.proxy_diagnostics.exit_ip_urls = vec![local("/diagnostics/ip")];
        state
            .persist_settings(&[("paid_fallback_mode", "never"), ("captcha_mode", "off")])
            .unwrap();
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        configure(&mut state, id);
        let state = Arc::new(state);
        Self {
            app: build_router(state.clone()),
            state,
            id,
            clock,
        }
    }

    fn enable(&self) {
        self.state
            .persist_settings(&[("highspeed_lane_enabled", "1")])
            .unwrap();
    }

    fn at(&self, millis: i64) {
        self.clock.store(millis, Ordering::SeqCst);
    }

    fn request(&self, body: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(ROUTE)
            .header("x-api-key", ROOT)
            .header("authorization", format!("Bearer {ROOT}"))
            .header("content-type", "application/json")
            .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
            .header("x-highspeed-card-id", CLIENT_CARD)
            .header("x-off-peak-ticket-id", "PUBLIC-client-ticket")
            .header("x-coding-plan-api-key", "PUBLIC-client-plan-key")
            .header("x-bigmodel-authorization", "Bearer PUBLIC-client-oauth")
            .header("x-device-mid", "PUBLIC-client-device")
            .header("anthropic-beta", "PUBLIC-compatible-beta")
            .header("x-stainless-lang", "PUBLIC-compatible-language")
            .header("x-private-client-header", "PUBLIC-not-allowlisted")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn send(&self, streaming: bool) -> Reply {
        self.send_request(self.request(request_body(streaming)))
            .await
    }

    async fn send_request(&self, request: Request<Body>) -> Reply {
        tokio::time::timeout(LIMIT, async {
            let response = self.app.clone().oneshot(request).await.unwrap();
            let (parts, body) = response.into_parts();
            let bytes = to_bytes(body, 2 << 20).await.unwrap();
            Reply {
                status: parts.status,
                headers: parts.headers,
                body: String::from_utf8(bytes.to_vec()).unwrap(),
            }
        })
        .await
        .expect("highspeed request/body exceeded the test deadline")
    }

    async fn status(&self, session: bool) -> Reply {
        let mut request = Request::builder()
            .method("GET")
            .uri(STATUS)
            .header("host", "localhost:8787")
            .header("x-api-key", ROOT);
        if session {
            request = request.header("cookie", format!("{SESSION_COOKIE}={SESSION}"));
        }
        self.send_request(request.body(Body::empty()).unwrap())
            .await
    }

    async fn assert_usage(&self, expected: &[(u16, i64)]) {
        tokio::time::timeout(LIMIT, async {
            while self.state.usage.lock().unwrap().len() < expected.len() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("terminal response must record usage");
        let memory: Vec<_> = self
            .state
            .usage
            .lock()
            .unwrap()
            .iter()
            .map(|record| (record.status, record.quota_charge))
            .collect();
        let persisted: Vec<_> = store::list_usage(&self.state.db.lock().unwrap(), 100)
            .into_iter()
            .rev()
            .map(|record| (record.2, record.4))
            .collect();
        assert_eq!(
            memory, expected,
            "each client request needs exactly one terminal record"
        );
        assert_eq!(
            persisted, expected,
            "durable accounting must agree with memory"
        );
    }
}

fn publish_accounts(state: &AppState) {
    let rows = store::load_accounts(&state.db.lock().unwrap(), &state.vault).unwrap();
    *state.accounts.lock().unwrap() = rows.iter().map(|(account, _, _)| account.clone()).collect();
    *state.creds.lock().unwrap() = rows
        .into_iter()
        .map(|(account, jwt, key)| {
            (
                account.id,
                Creds {
                    zcode_jwt: jwt,
                    api_key: key,
                },
            )
        })
        .collect();
}

fn request_body(streaming: bool) -> Value {
    json!({"model": "zai/ gLm-5.1-hIgHsPeEd ", "stream": streaming,
        "messages": [{"role": "user", "content": "hi"}]})
}

fn plain_body() -> Value {
    json!({"id": "msg_plain", "type": "message", "role": "assistant", "model": MODEL,
        "content": [{"type": "text", "text": "PLAIN-OK"}], "stop_reason": "end_turn",
        "usage": {"input_tokens": 2, "output_tokens": 3}})
}

fn card_body(id: &str, model: &str, expires: i64) -> Value {
    json!({"code": 0, "data": {"card": {"card_id": id, "model": model, "expires_at": expires}}})
}

fn event(kind: &str, data: Value) -> String {
    format!("event: {kind}\ndata: {data}\n\n")
}

fn sse_start() -> String {
    event(
        "message_start",
        json!({"type": "message_start", "message": {
            "id": "msg_highspeed", "type": "message", "role": "assistant", "model": CARD_MODEL,
            "usage": {"input_tokens": 11, "output_tokens": 0}
        }}),
    )
}

fn sse_prefix() -> String {
    sse_start()
        + &event(
            "content_block_start",
            json!({"type": "content_block_start", "index": 0,
            "content_block": {"type": "text", "text": ""}}),
        )
        + &event(
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": "HIGHSPEED-OK"}}),
        )
}

fn valid_sse() -> String {
    sse_prefix()
        + &event(
            "content_block_stop",
            json!({"type": "content_block_stop", "index": 0}),
        )
        + &event(
            "message_delta",
            json!({"type": "message_delta",
            "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 4}}),
        )
        + &event("message_stop", json!({"type": "message_stop"}))
}

fn held_body() -> (mpsc::Sender<Vec<u8>>, Body) {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(2);
    let body = Body::from_stream(stream::unfold(rx, |mut rx| async {
        rx.recv()
            .await
            .map(|bytes| (Ok::<_, Infallible>(Bytes::from(bytes)), rx))
    }));
    (tx, body)
}

fn assert_auth(request: &Seen, plan: &str) {
    assert_eq!(request.method, "POST");
    assert_eq!(request.headers["authorization"], format!("Bearer {JWT}"));
    assert_eq!(
        request.headers["x-bigmodel-authorization"],
        format!("Bearer {plan}")
    );
    assert_eq!(request.headers["bigmodel-target-type"], "PERSONAL");
    assert_eq!(request.headers["x-device-mid"], DEVICE);
    for header in ["x-zcode-app-version", "x-platform", "x-client-timezone"] {
        assert!(
            !request.headers[header].to_str().unwrap().is_empty(),
            "identity header {header}"
        );
    }
    for header in [
        "x-coding-plan-api-key",
        "x-api-key",
        "cookie",
        "x-off-peak-ticket-id",
        "x-private-client-header",
    ] {
        assert!(
            !request.headers.contains_key(header),
            "unexpected upstream credential/header {header}"
        );
    }
}

fn assert_draw(request: &Seen) -> String {
    assert_eq!(request.path, DRAW);
    let body: Value = serde_json::from_slice(&request.body).unwrap();
    let task = body["task_id"].as_str().expect("draw task_id string");
    assert_eq!(task.len(), 36, "task_id must be a UUID");
    for (index, byte) in task.bytes().enumerate() {
        if [8, 13, 18, 23].contains(&index) {
            assert_eq!(byte, b'-');
        } else {
            assert!(byte.is_ascii_hexdigit(), "task_id must be a UUID");
        }
    }
    assert_eq!(
        body,
        json!({"task_id": task, "provider": "builtin:zai-coding-plan", "model": MODEL})
    );
    task.to_owned()
}

#[test]
fn default_highspeed_urls_match_the_go_wire_contract() {
    let config = HighspeedConfig::default();
    assert_eq!(config.draw_url, "https://zcode.z.ai/api/v1/highspeed/draw");
    assert_eq!(
        config.messages_url,
        "https://zcode.z.ai/api/v1/highspeed/anthropic/v1/messages"
    );
}

#[tokio::test]
async fn off_uncovered_and_spoofed_plain_route_use_plain_without_drawing() {
    let mock = Mock::start(vec![
        (PLAIN, Step::plain()),
        (PLAIN, Step::plain()),
        (PLAIN, Step::plain()),
    ])
    .await;
    let f = Fixture::new(&mock, ACCESS);
    f.send(false).await.expect_plain();
    f.enable();
    let mut body = request_body(false);
    body["model"] = json!("zai/glm-5.3");
    f.send_request(f.request(body)).await.expect_plain();
    let mut spoof = f.request(request_body(false));
    *spoof.uri_mut() = "/v1/messages".parse().unwrap();
    spoof
        .headers_mut()
        .insert("x-zcode-rs-shape", "highspeed".parse().unwrap());
    f.send_request(spoof).await.expect_plain();
    mock.assert_paths(&[PLAIN, PLAIN, PLAIN]);
    mock.assert_consumed();
}

#[tokio::test]
async fn auth_pause_body_and_named_key_gates_run_before_draw() {
    const NAMED: &str = "PUBLIC-highspeed-restricted-key";
    let mock = Mock::start(vec![]).await;
    let f = Fixture::new(&mock, ACCESS);
    f.enable();
    let mut request = f.request(request_body(false));
    request.headers_mut().remove("x-api-key");
    request.headers_mut().remove("authorization");
    assert_eq!(
        f.send_request(request).await.status,
        StatusCode::UNAUTHORIZED
    );
    f.state
        .persist_settings(&[("gateway_paused", "1")])
        .unwrap();
    assert_eq!(f.send(false).await.status, StatusCode::SERVICE_UNAVAILABLE);
    f.state
        .persist_settings(&[("gateway_paused", "0")])
        .unwrap();
    for body in ["{bad-json", "[]"] {
        let mut request = f.request(request_body(false));
        *request.body_mut() = Body::from(body);
        assert_eq!(
            f.send_request(request).await.status,
            StatusCode::BAD_REQUEST
        );
    }
    let mut key = NamedKey {
        id: 91,
        name: "PUBLIC restricted".into(),
        key_hash: key_hash(NAMED),
        enabled: true,
        models: "glm-5.3".into(),
        rpm_limit: 0,
        rate_5h: 0,
        rate_1d: 0,
        rate_7d: 0,
        quota_total: 0,
        quota_used: 0,
    };
    for (models, total, used, expected) in [
        ("glm-5.3", 0, 0, StatusCode::FORBIDDEN),
        ("glm-5.1-highspeed", 10, 10, StatusCode::TOO_MANY_REQUESTS),
    ] {
        key.models = models.into();
        key.quota_total = total;
        key.quota_used = used;
        store::upsert_gateway_key(&f.state.db.lock().unwrap(), &key);
        *f.state.named_keys.lock().unwrap() = vec![key.clone()];
        let mut request = f.request(request_body(false));
        request
            .headers_mut()
            .insert("x-api-key", NAMED.parse().unwrap());
        request.headers_mut().remove("authorization");
        let reply = f.send_request(request).await;
        assert_eq!(reply.status, expected, "body={}", reply.body);
    }
    mock.assert_paths(&[]);
}

#[tokio::test]
async fn draw_and_messages_use_exact_plan_auth_card_and_normalized_payload() {
    for (access, plan, streaming) in [(ACCESS, ACCESS, false), ("", KEY, true)] {
        let mock = Mock::start(vec![
            (DRAW, Step::sized_card(1 << 20)),
            (ROUTE, Step::sse()),
        ])
        .await;
        let f = Fixture::new(&mock, access);
        f.enable();
        let reply = f.send(streaming).await;
        if streaming {
            assert_eq!(reply.status, StatusCode::OK, "body={}", reply.body);
            assert!(reply.headers["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/event-stream"));
            assert!(reply.body.contains(&valid_sse()));
        } else {
            reply.expect_message();
        }
        assert_eq!(
            reply.headers["x-request-id"],
            "PUBLIC-highspeed-upstream-request"
        );
        let draws = mock.seen(DRAW);
        assert_eq!(draws.len(), 1);
        assert_draw(&draws[0]);
        assert!(!draws[0].headers.contains_key("x-highspeed-card-id"));
        let messages = mock.seen(ROUTE);
        assert_eq!(messages.len(), 1);
        for request in [&draws[0], &messages[0]] {
            assert_auth(request, plan);
        }
        let sent = &messages[0];
        assert_eq!(sent.headers["x-highspeed-card-id"], "C1");
        assert_ne!(sent.headers["x-highspeed-card-id"], CLIENT_CARD);
        assert_eq!(sent.headers["accept"], "text/event-stream");
        assert_eq!(sent.headers["anthropic-version"], "2023-06-01");
        assert_eq!(sent.headers["anthropic-beta"], "PUBLIC-compatible-beta");
        assert_eq!(
            sent.headers["x-stainless-lang"],
            "PUBLIC-compatible-language"
        );
        let body: Value = serde_json::from_slice(&sent.body).unwrap();
        assert_eq!(body["stream"], true);
        assert_eq!(body["model"], CARD_MODEL);
        assert_eq!(body["messages"], request_body(false)["messages"]);
        let user: Value =
            serde_json::from_str(body["metadata"]["user_id"].as_str().unwrap()).unwrap();
        assert_eq!(
            user,
            json!({"device_id": DEVICE, "account_uuid": "", "session_id": ""})
        );
        f.assert_usage(&[(200, 15)]).await;
        mock.assert_paths(&[DRAW, ROUTE]);
        mock.assert_consumed();
    }
}

#[tokio::test]
async fn present_metadata_is_never_replaced_and_empty_card_model_uses_normalized_original() {
    let metadata = [
        json!({"custom": "PUBLIC value"}),
        Value::Null,
        json!("PUBLIC metadata"),
        json!({"user_id": "PUBLIC-user"}),
    ];
    let mut steps = vec![(DRAW, Step::card("C1", "", 0))];
    steps.extend(metadata.iter().map(|_| (ROUTE, Step::sse())));
    let mock = Mock::start(steps).await;
    let f = Fixture::new(&mock, ACCESS);
    f.enable();
    for value in &metadata {
        let mut body = request_body(false);
        body["metadata"] = value.clone();
        f.send_request(f.request(body)).await.expect_message();
    }
    assert_eq!(mock.seen(DRAW).len(), 1);
    for (request, metadata) in mock.seen(ROUTE).iter().zip(metadata) {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(
            body["metadata"], metadata,
            "only an entirely absent metadata key is synthesized"
        );
        assert_eq!(body["model"], MODEL);
        assert_eq!(body["stream"], true);
    }
    mock.assert_consumed();
}

#[tokio::test]
async fn account_card_cache_reuses_across_models_but_redraws_after_four_minutes() {
    let mock = Mock::start(vec![
        (DRAW, Step::card("C1", CARD_MODEL, 0)),
        (DRAW, Step::card("C2", CARD_MODEL, 0)),
        (ROUTE, Step::sse()),
        (ROUTE, Step::sse()),
        (ROUTE, Step::sse()),
    ])
    .await;
    let f = Fixture::new(&mock, ACCESS);
    f.enable();
    f.send(false).await.expect_message();
    f.at(NOW + 239_999);
    let mut different = request_body(false);
    different["model"] = json!("PUBLIC-other-highspeed");
    f.send_request(f.request(different)).await.expect_message();
    assert_eq!(
        mock.seen(DRAW).len(),
        1,
        "cache is per account, not per requested model"
    );
    f.at(NOW + 240_001);
    f.send(false).await.expect_message();
    assert_eq!(mock.seen(DRAW).len(), 2);
    let cards: Vec<_> = mock
        .seen(ROUTE)
        .iter()
        .map(|request| {
            request.headers["x-highspeed-card-id"]
                .to_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(cards, ["C1", "C1", "C2"]);
    mock.assert_consumed();
}

#[tokio::test]
async fn status_is_session_gated_read_only_and_reports_millisecond_card_expiry_without_secrets() {
    let mock = Mock::start(vec![
        (DRAW, Step::card("C1", CARD_MODEL, NOW + 90_500)),
        (DRAW, Step::card("C2", CARD_MODEL, NOW + 300_000)),
        (ROUTE, Step::sse()),
        (ROUTE, Step::sse()),
    ])
    .await;
    let f = Fixture::new(&mock, ACCESS);
    f.enable();
    assert_eq!(f.status(false).await.status, StatusCode::UNAUTHORIZED);
    let empty = f.status(true).await;
    assert_eq!(empty.status, StatusCode::OK);
    assert!(empty.json()["accounts"][0].get("card_id").is_none());
    mock.assert_paths(&[]);
    f.send(false).await.expect_message();
    f.at(NOW + 1_000);
    let reply = f.status(true).await;
    assert_eq!(reply.status, StatusCode::OK);
    let body = reply.json();
    assert_eq!(body["enabled"], true);
    let account = &body["accounts"][0];
    assert_eq!(account["id"], f.id);
    assert_eq!(account["card_id"], "C1");
    assert_eq!(account["card_model"], CARD_MODEL);
    assert_eq!(account["card_valid"], true);
    assert_eq!(account["card_expires_in_sec"], 89);
    for secret in [JWT, KEY, ACCESS, REFRESH, ROOT, SESSION] {
        assert!(!reply.body.contains(secret), "status leaked a credential");
    }
    f.at(NOW + 90_500);
    let expired = f.status(true).await.json();
    let account = &expired["accounts"][0];
    // An expired entry may be pruned, but it must never be reported as valid.
    if account.get("card_id").is_some() {
        assert_eq!(account["card_valid"], false);
        assert_eq!(account["card_expires_in_sec"], 0);
    }
    assert_eq!(
        mock.seen(DRAW).len(),
        1,
        "GET status must not refresh an expired card"
    );
    assert_eq!(mock.seen(ROUTE).len(), 1);
    f.send(false).await.expect_message();
    assert_eq!(
        mock.seen(DRAW).len(),
        2,
        "positive expiry takes precedence over four-minute cache TTL"
    );
    assert_eq!(mock.seen(ROUTE)[1].headers["x-highspeed-card-id"], "C2");
    mock.assert_consumed();
}

#[tokio::test]
async fn invalid_draw_responses_fall_back_and_block_only_the_lane_for_ten_minutes() {
    for failure in [
        Step::json(StatusCode::OK, json!({"code": 3103, "data": {}})),
        Step::json(StatusCode::OK, json!({"code": 0, "data": {}})),
        Step::json(StatusCode::OK, json!({"data": {"card": {"card_id": ""}}})),
        Step::raw(StatusCode::OK, "application/json", "{not-json"),
        Step::sized_card((1 << 20) + 1),
        Step::json(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"message": "PUBLIC draw unavailable"}),
        ),
    ] {
        let mock = Mock::start(vec![
            (DRAW, failure),
            (DRAW, Step::card("C2", CARD_MODEL, 0)),
            (PLAIN, Step::plain()),
            (PLAIN, Step::plain()),
            (ROUTE, Step::sse()),
        ])
        .await;
        let f = Fixture::new(&mock, ACCESS);
        f.enable();
        f.send(false).await.expect_plain();
        let blocked = f.status(true).await.json();
        assert_eq!(blocked["accounts"][0]["draw_blocked_for_sec"], 600);
        f.at(NOW + 599_999);
        f.send(false).await.expect_plain();
        assert_eq!(mock.seen(DRAW).len(), 1);
        assert_eq!(f.state.accounts.lock().unwrap()[0].status, "active");
        f.at(NOW + 600_001);
        f.send(false).await.expect_message();
        assert_eq!(mock.seen(DRAW).len(), 2);
        f.assert_usage(&[(200, 5), (200, 5), (200, 15)]).await;
        mock.assert_consumed();
    }
}

#[tokio::test]
async fn future_next_draw_advice_is_in_milliseconds_and_clamped_to_one_minute_through_one_hour() {
    for (advice_ms, block_ms, code) in [
        (1_000, 60_000, 3103),
        (125_000, 125_000, 0),
        (7_200_000, 3_600_000, 3103),
    ] {
        let mock = Mock::start(vec![
            (
                DRAW,
                Step::json(
                    StatusCode::OK,
                    json!({"code": code, "data": {"next_draw_at": NOW + advice_ms}}),
                ),
            ),
            (DRAW, Step::card("C2", CARD_MODEL, 0)),
            (PLAIN, Step::plain()),
            (PLAIN, Step::plain()),
            (ROUTE, Step::sse()),
        ])
        .await;
        let f = Fixture::new(&mock, ACCESS);
        f.enable();
        f.send(false).await.expect_plain();
        f.at(NOW + 999);
        assert_eq!(
            f.status(true).await.json()["accounts"][0]["draw_blocked_for_sec"],
            (block_ms - 999) / 1000
        );
        f.at(NOW + block_ms - 1);
        f.send(false).await.expect_plain();
        assert_eq!(mock.seen(DRAW).len(), 1);
        f.at(NOW + block_ms + 1);
        f.send(false).await.expect_message();
        assert_eq!(mock.seen(DRAW).len(), 2);
        mock.assert_consumed();
    }
}

#[tokio::test]
async fn pending_same_account_draw_does_not_hold_other_requests_or_duplicate_spend() {
    let (tx, held) = held_body();
    let mock = Mock::start(vec![
        (DRAW, Step::raw(StatusCode::OK, "application/json", held)),
        (PLAIN, Step::plain()),
        (ROUTE, Step::sse()),
    ])
    .await;
    let f = Fixture::new(&mock, ACCESS);
    f.enable();
    let first_fixture = f.clone();
    let first = tokio::spawn(async move { first_fixture.send(false).await });
    mock.wait_for(DRAW, 1).await;
    let second = tokio::time::timeout(Duration::from_secs(1), f.send(false))
        .await
        .expect("a second request must fall back before the held draw is released");
    second.expect_plain();
    assert_eq!(mock.seen(DRAW).len(), 1);
    assert!(mock.seen(ROUTE).is_empty());
    tx.send(card_body("C1", CARD_MODEL, 0).to_string().into_bytes())
        .await
        .unwrap();
    drop(tx);
    first.await.unwrap().expect_message();
    mock.assert_paths(&[DRAW, PLAIN, ROUTE]);
    f.assert_usage(&[(200, 5), (200, 15)]).await;
    mock.assert_consumed();
}

#[tokio::test]
async fn cancelling_a_pending_draw_clears_the_drawing_slot_without_a_failure_block() {
    let (tx, held) = held_body();
    let mock = Mock::start(vec![
        (DRAW, Step::raw(StatusCode::OK, "application/json", held)),
        (DRAW, Step::card("C2", CARD_MODEL, 0)),
        (ROUTE, Step::sse()),
    ])
    .await;
    let f = Fixture::new(&mock, ACCESS);
    f.enable();
    let pending_fixture = f.clone();
    let pending = tokio::spawn(async move { pending_fixture.send(false).await });
    mock.wait_for(DRAW, 1).await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    drop(tx);
    let status = f.status(true).await.json();
    assert!(status["accounts"][0].get("draw_blocked_for_sec").is_none());
    f.send(false).await.expect_message();
    assert_eq!(mock.seen(DRAW).len(), 2);
    assert_eq!(mock.seen(ROUTE)[0].headers["x-highspeed-card-id"], "C2");
    mock.assert_paths(&[DRAW, DRAW, ROUTE]);
    f.assert_usage(&[(200, 15)]).await;
    mock.assert_consumed();
}

#[tokio::test]
async fn exact_provider_card_expiry_redraws_once_with_the_original_canonical_model() {
    for (field, second_expires) in [("provider_code", false), ("providerErrorCode", true)] {
        let mut expired = json!({"error": {"message": "PUBLIC expired"}});
        expired["error"][field] = json!(3402);
        let mock = Mock::start(
            vec![
                (DRAW, Step::card("C1", CARD_MODEL, 0)),
                (DRAW, Step::card("C2", CARD_MODEL, 0)),
                (ROUTE, Step::json(StatusCode::BAD_REQUEST, expired.clone())),
                (
                    ROUTE,
                    if second_expires {
                        Step::json(StatusCode::BAD_REQUEST, expired)
                    } else {
                        Step::sse()
                    },
                ),
                (PLAIN, Step::plain()),
            ]
            .into_iter()
            .filter(|(path, _)| *path != PLAIN || second_expires)
            .collect(),
        )
        .await;
        let f = Fixture::new(&mock, ACCESS);
        f.enable();
        let reply = f.send(false).await;
        if second_expires {
            reply.expect_plain();
        } else {
            reply.expect_message();
        }
        let draws = mock.seen(DRAW);
        assert_eq!(draws.len(), 2, "at most one redraw per request");
        for request in &draws {
            assert_draw(request);
        }
        let forwards = mock.seen(ROUTE);
        assert_eq!(forwards.len(), 2);
        assert_eq!(forwards[0].headers["x-highspeed-card-id"], "C1");
        assert_eq!(forwards[1].headers["x-highspeed-card-id"], "C2");
        f.assert_usage(&[(200, if second_expires { 5 } else { 15 })])
            .await;
        mock.assert_consumed();
    }
}

#[tokio::test]
async fn generic_code_3402_is_not_card_expiry_and_does_not_invalidate_the_cached_card() {
    let mock = Mock::start(vec![
        (DRAW, Step::card("C1", CARD_MODEL, 0)),
        (
            ROUTE,
            Step::json(StatusCode::BAD_REQUEST, json!({"code": 3402})),
        ),
        (ROUTE, Step::sse()),
        (PLAIN, Step::plain()),
    ])
    .await;
    let f = Fixture::new(&mock, ACCESS);
    f.enable();
    f.send(false).await.expect_plain();
    assert_eq!(mock.seen(DRAW).len(), 1);
    f.send(false).await.expect_message();
    assert_eq!(mock.seen(DRAW).len(), 1);
    assert_eq!(mock.seen(ROUTE)[1].headers["x-highspeed-card-id"], "C1");
    f.assert_usage(&[(200, 5), (200, 15)]).await;
    mock.assert_consumed();
}

#[tokio::test]
async fn pre_consumption_status_non_sse_redirect_and_connect_failures_fall_back_once() {
    for failure in [
        Step::json(
            StatusCode::TOO_MANY_REQUESTS,
            json!({"message": "PUBLIC saturated"}),
        ),
        Step::json(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"message": "PUBLIC unavailable"}),
        ),
        Step::json(StatusCode::OK, json!({"message": "PUBLIC not SSE"})),
        Step::raw(StatusCode::TEMPORARY_REDIRECT, "application/json", "")
            .header("location", "/must-not-follow"),
    ] {
        let mock = Mock::start(vec![
            (DRAW, Step::card("C1", CARD_MODEL, 0)),
            (ROUTE, failure),
            (PLAIN, Step::plain()),
        ])
        .await;
        let f = Fixture::new(&mock, ACCESS);
        f.enable();
        f.send(false).await.expect_plain();
        mock.assert_paths(&[DRAW, ROUTE, PLAIN]);
        assert_eq!(
            f.state.accounts.lock().unwrap()[0].status,
            "active",
            "lane saturation is not account illness"
        );
        let status: String = f
            .state
            .db
            .lock()
            .unwrap()
            .query_row("SELECT status FROM accounts WHERE id=?1", [f.id], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(status, "active");
        f.assert_usage(&[(200, 5)]).await;
        mock.assert_consumed();
    }
    let mock = Mock::start(vec![
        (DRAW, Step::card("C1", CARD_MODEL, 0)),
        (PLAIN, Step::plain()),
    ])
    .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed = format!("http://{}/closed", listener.local_addr().unwrap());
    drop(listener);
    let f = Fixture::configured(&mock, ACCESS, |state, _| {
        state.highspeed.messages_url = closed
    });
    f.enable();
    f.send(false).await.expect_plain();
    mock.assert_paths(&[DRAW, PLAIN]);
    f.assert_usage(&[(200, 5)]).await;
    mock.assert_consumed();
}

#[tokio::test]
async fn accepted_empty_inline_error_and_incomplete_sse_are_terminal_without_replay_and_charge_once(
) {
    for streaming in [false, true] {
        for (upstream, charge) in [
            (String::new(), 0),
            (
                sse_prefix()
                    + &event(
                        "error",
                        json!({"type": "error", "error": {"type": "overloaded_error", "message": "PUBLIC failed"}}),
                    ),
                11,
            ),
            (sse_prefix(), 11),
        ] {
            let mock = Mock::start(vec![
                (DRAW, Step::card("C1", CARD_MODEL, 0)),
                (
                    ROUTE,
                    Step::raw(StatusCode::OK, "text/event-stream", upstream.clone()),
                ),
            ])
            .await;
            let f = Fixture::new(&mock, ACCESS);
            f.enable();
            let reply = f.send(streaming).await;
            if streaming {
                assert_eq!(reply.status, StatusCode::OK, "body={}", reply.body);
                assert!(
                    reply.body.contains(&upstream),
                    "accepted upstream bytes must be preserved"
                );
                let errors: Vec<Value> = reply
                    .body
                    .split("\n\n")
                    .filter(|frame| frame.lines().any(|line| line == "event: error"))
                    .filter_map(|frame| frame.lines().find_map(|line| line.strip_prefix("data: ")))
                    .map(|data| serde_json::from_str(data).unwrap())
                    .collect();
                assert_eq!(
                    errors.len(),
                    if upstream.contains("event: error") {
                        2
                    } else {
                        1
                    }
                );
                assert_eq!(errors.last().unwrap()["error"]["type"], "api_error");
            } else {
                assert_eq!(reply.status, StatusCode::BAD_GATEWAY, "body={}", reply.body);
                assert_eq!(reply.json()["type"], "error");
                assert_eq!(reply.json()["error"]["type"], "api_error");
            }
            mock.assert_paths(&[DRAW, ROUTE]);
            f.assert_usage(&[(502, charge)]).await;
            mock.assert_consumed();
        }
    }
}

#[tokio::test]
async fn healthy_billing_after_messages_401_preserves_credentials_and_falls_back_without_double_usage(
) {
    let mock = Mock::start(vec![
        (DRAW, Step::card("C1", CARD_MODEL, 0)),
        (ROUTE, Step::json(StatusCode::UNAUTHORIZED, json!({"message": "PUBLIC lane auth rejected"}))),
        ("/management/billing/billing/balance", Step::json(StatusCode::OK, json!({"code": 0, "success": true, "data": {"result": {
            "plans": [{"plan_id": "pro", "name": "Pro", "status": "active"}],
            "balances": [{"plan_id": "pro", "total_units": 100, "used_units": 10, "remaining_units": 90}]
        }}}))),
        (PLAIN, Step::plain()),
    ]).await;
    let f = Fixture::new(&mock, ACCESS);
    f.enable();
    f.send(false).await.expect_plain();
    assert_eq!(
        mock.seen("/management/billing/billing/balance").len(),
        1,
        "real 401 must try refresh-first recovery"
    );
    assert_ne!(f.state.accounts.lock().unwrap()[0].status, "invalid");
    let status: String = f
        .state
        .db
        .lock()
        .unwrap()
        .query_row("SELECT status FROM accounts WHERE id=?1", [f.id], |row| {
            row.get(0)
        })
        .unwrap();
    assert_ne!(
        status, "invalid",
        "billing-valid credentials must survive reload"
    );
    f.assert_usage(&[(200, 5)]).await;
    mock.assert_consumed();
}

#[tokio::test]
async fn account_changes_during_held_draw_prevent_stale_card_publication_or_reuse() {
    for change in ["access", "jwt", "disabled", "deleted"] {
        let (tx, held) = held_body();
        let rotating = change == "access" || change == "jwt";
        let mut steps = vec![(DRAW, Step::raw(StatusCode::OK, "application/json", held))];
        if rotating {
            steps.extend([
                (PLAIN, Step::plain()),
                (DRAW, Step::card("FRESH", CARD_MODEL, 0)),
                (ROUTE, Step::sse()),
            ]);
        }
        let mock = Mock::start(steps).await;
        let f = Fixture::new(&mock, ACCESS);
        f.enable();
        let held_fixture = f.clone();
        let pending = tokio::spawn(async move { held_fixture.send(false).await });
        mock.wait_for(DRAW, 1).await;
        {
            let db = f.state.db.lock().unwrap();
            match change {
                "access" => {
                    db.execute(
                        "UPDATE accounts SET access_token=?1 WHERE id=?2",
                        rusqlite::params![
                            f.state.vault.encrypt("PUBLIC-rotated-access").unwrap(),
                            f.id
                        ],
                    )
                    .unwrap();
                }
                "jwt" => {
                    db.execute(
                        "UPDATE accounts SET zcode_jwt=?1 WHERE id=?2",
                        rusqlite::params![
                            f.state.vault.encrypt("PUBLIC-rotated-jwt").unwrap(),
                            f.id
                        ],
                    )
                    .unwrap();
                }
                "disabled" => store::set_account_enabled(&db, f.id, false),
                "deleted" => store::delete_account(&db, f.id),
                _ => unreachable!(),
            }
        }
        if !rotating {
            publish_accounts(&f.state);
        }
        tx.send(card_body("STALE", CARD_MODEL, 0).to_string().into_bytes())
            .await
            .unwrap();
        drop(tx);
        let reply = pending.await.unwrap();
        if rotating {
            reply.expect_plain();
        }
        assert!(
            mock.seen(ROUTE).is_empty(),
            "stale draw must not be forwarded for {change}"
        );
        let status = f.status(true).await;
        assert!(
            !status.body.contains("STALE"),
            "stale card leaked into status cache for {change}"
        );
        publish_accounts(&f.state);
        if rotating {
            f.send(false).await.expect_message();
            assert_eq!(
                mock.seen(DRAW).len(),
                2,
                "rotated account must draw instead of reusing stale card"
            );
            assert_eq!(mock.seen(ROUTE)[0].headers["x-highspeed-card-id"], "FRESH");
            let redraw = &mock.seen(DRAW)[1];
            if change == "access" {
                assert_eq!(
                    redraw.headers["x-bigmodel-authorization"],
                    "Bearer PUBLIC-rotated-access"
                );
            } else {
                assert_eq!(redraw.headers["authorization"], "Bearer PUBLIC-rotated-jwt");
            }
        } else {
            let reply = f.send(false).await;
            assert_eq!(
                reply.status,
                StatusCode::SERVICE_UNAVAILABLE,
                "body={}",
                reply.body
            );
            assert_eq!(
                mock.seen(DRAW).len(),
                1,
                "deleted or disabled accounts cannot spend another draw"
            );
        }
        mock.assert_consumed();
    }
}

#[tokio::test]
async fn independent_exhausted_lane_honors_account_group_and_group_proxy_before_default_and_global()
{
    let target = Mock::start(vec![]).await;
    let proxy = Mock::start(vec![
        (DRAW, Step::card("GROUP", CARD_MODEL, 0)),
        (ROUTE, Step::sse()),
    ])
    .await;
    let unused = Mock::start(vec![]).await;
    let port = reqwest::Url::parse(&proxy.base).unwrap().port().unwrap();
    let default_port = reqwest::Url::parse(&unused.base).unwrap().port().unwrap();
    let f = Fixture::configured(&target, ACCESS, |state, id| {
        let db = state.db.lock().unwrap();
        db.execute("UPDATE accounts SET status='exhausted' WHERE id=?1", [id])
            .unwrap();
        store::insert_account_encrypted(
            &db,
            &state.vault,
            &AccountView {
                email: "unmatched@example.test".into(),
                provider: "zai".into(),
                enabled: true,
                status: "active".into(),
                account_group: "other-group".into(),
                ..AccountView::default()
            },
            "PUBLIC-wrong-group-jwt",
            "PUBLIC-wrong-group-key",
        )
        .unwrap();
        db.execute("INSERT INTO proxy_nodes(name,type,host,port,group_name,enabled) VALUES('PUBLIC group','http','127.0.0.1',?1,'lane-group',1)", [port]).unwrap();
        db.execute("INSERT INTO proxy_nodes(name,type,host,port,is_default,enabled) VALUES('PUBLIC default','http','127.0.0.1',?1,1,1)", [default_port]).unwrap();
        drop(db);
        publish_accounts(state);
        state
            .persist_settings(&[("upstream_proxy", &unused.base)])
            .unwrap();
    });
    f.enable();
    let mut request = f.request(request_body(false));
    request
        .headers_mut()
        .insert("x-zcode-group", "lane-group".parse().unwrap());
    f.send_request(request).await.expect_message();
    target.assert_paths(&[]);
    unused.assert_paths(&[]);
    proxy.assert_paths(&[DRAW, ROUTE]);
    for request in proxy.script.seen.lock().unwrap().iter() {
        assert!(
            request.uri.starts_with(&target.base),
            "configured HTTP proxy must receive absolute-form target URI"
        );
        assert_auth(request, ACCESS);
    }
    assert_eq!(
        f.state
            .accounts
            .lock()
            .unwrap()
            .iter()
            .find(|account| account.id == f.id)
            .unwrap()
            .status,
        "exhausted"
    );
    f.assert_usage(&[(200, 15)]).await;
    proxy.assert_consumed();
}
