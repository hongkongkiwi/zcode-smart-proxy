use std::{
    collections::{BTreeMap, VecDeque},
    convert::Infallible,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{Request as IncomingRequest, State},
    http::{HeaderMap, Request, StatusCode},
    response::Response,
    Router,
};
use futures_util::{stream, StreamExt};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tower::ServiceExt;
use zcode_core::AccountView;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
    store,
};

const ROUTE: &str = "/async/v1/messages";
const TAKE: &str = "/api/v1/off-peak/ticket";
const POLL: &str = "/api/v1/off-peak/ticket/status";
const FORWARD: &str = "/api/v1/off-peak/anthropic/v1/messages";
const ROOT: &str = "PUBLIC-queue-root-key";
const SESSION: &str = "PUBLIC-queue-admin-session";
const JWT: &str = "PUBLIC-queue-first-jwt";
const KEY: &str = "PUBLIC-queue-first-coding-key";
const OTHER_JWT: &str = "PUBLIC-queue-second-jwt";
const OTHER_KEY: &str = "PUBLIC-queue-second-coding-key";
const CLIENT_TICKET: &str = "PUBLIC-untrusted-client-ticket";
const LIMIT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    headers: HeaderMap,
    body: Vec<u8>,
    at: Instant,
}

struct Step {
    status: StatusCode,
    headers: Vec<(&'static str, String)>,
    body: Body,
}

impl Step {
    fn json(status: StatusCode, body: Value) -> Self {
        Self::raw(status, "application/json", Body::from(body.to_string()))
    }

    fn raw(status: StatusCode, content_type: &str, body: Body) -> Self {
        Self {
            status,
            headers: vec![("content-type", content_type.into())],
            body,
        }
    }

    fn sse() -> Self {
        Self::raw(StatusCode::OK, "text/event-stream", Body::from(valid_sse()))
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
    queued_until_ready: AtomicBool,
    ready: AtomicBool,
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
            let bytes = to_bytes(body, 1 << 20).await.unwrap();
            let path = parts.uri.path().to_owned();
            script.seen.lock().unwrap().push(Seen {
                method: parts.method.to_string(),
                path: path.clone(),
                headers: parts.headers,
                body: bytes.to_vec(),
                at: Instant::now(),
            });
            let step = script
                .steps
                .lock()
                .unwrap()
                .get_mut(&path)
                .and_then(VecDeque::pop_front);
            let step = step.unwrap_or_else(|| {
                if path == POLL && script.queued_until_ready.load(Ordering::SeqCst) {
                    poll_step(if script.ready.load(Ordering::SeqCst) {
                        "ready"
                    } else {
                        "queued"
                    })
                } else {
                    Step::json(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({"error": "unexpected loopback request"}),
                    )
                }
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

    fn assert_idle(&self) {
        assert!(self.script.seen.lock().unwrap().is_empty());
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

    fn assert_consumed(&self) {
        for (path, steps) in self.script.steps.lock().unwrap().iter() {
            assert!(steps.is_empty(), "unconsumed mock responses at {path}");
        }
    }
}

// Redirecting a settle to this listener produces a transport failure, not an HTTP failure.
struct Disconnect {
    url: String,
    connections: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Disconnect {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/disconnect", listener.local_addr().unwrap());
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = connections.clone();
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(socket);
            }
        });
        Self {
            url,
            connections,
            task,
        }
    }
}

impl Drop for Disconnect {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    async fn read(response: Response) -> Self {
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, 1 << 20).await.unwrap();
        Self {
            status: parts.status,
            headers: parts.headers,
            body: String::from_utf8(bytes.to_vec()).unwrap(),
        }
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).expect("response must be JSON")
    }

    fn expect_json(&self, status: StatusCode, body: Value) {
        assert_eq!(self.status, status, "body={}", self.body);
        assert_eq!(self.json(), body);
    }

    fn expect_message(&self) {
        assert_eq!(self.status, StatusCode::OK, "body={}", self.body);
        assert!(self.headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("application/json"));
        let body = self.json();
        assert_eq!(body["id"], "msg_queue");
        assert_eq!(body["type"], "message");
        assert_eq!(body["role"], "assistant");
        assert_eq!(body["model"], "glm-5.3");
        assert_eq!(
            body["content"],
            json!([{"type": "text", "text": "QUEUE-OK"}])
        );
        assert_eq!(body["stop_reason"], "end_turn");
        assert_eq!(body["usage"]["input_tokens"], 11);
        assert_eq!(body["usage"]["output_tokens"], 4);
    }
}

struct Fixture {
    state: Arc<AppState>,
    app: Router,
}

impl Fixture {
    fn new(control: &Mock, origin: &Mock, accounts: usize) -> Self {
        let db = store::open(":memory:");
        for (email, jwt, key) in [
            ("first@example.test", JWT, KEY),
            ("second@example.test", OTHER_JWT, OTHER_KEY),
        ]
        .into_iter()
        .take(accounts)
        {
            let account = AccountView {
                email: email.into(),
                provider: "zai".into(),
                enabled: true,
                status: "active".into(),
                zcode_jwt: jwt.into(),
                api_key: key.into(),
                ..AccountView::default()
            };
            store::upsert_account(&db, &account, jwt, key);
        }
        let mut state = AppState::from_db(
            ROOT.into(),
            UpstreamUrls {
                zai: format!("{}/unused-plain-lane", origin.base),
                zai_fallback: format!("{}/unused-paid-lane", origin.base),
            },
            db,
        );
        state.offpeak_control_base = format!("{}/api/v1/off-peak", control.base);
        // Required test seam: an origin, not a full inference URL or the plain-lane URL.
        state.offpeak_origin = origin.base.clone();
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        state
            .persist_settings(&[
                ("async_poll_interval_ms", "500"),
                ("async_keepalive_ms", "300"),
                ("async_max_retries", "3"),
                ("async_max_wait_sec", "2"),
            ])
            .unwrap();
        let state = Arc::new(state);
        Self {
            app: build_router(state.clone()),
            state,
        }
    }

    fn enable(&self) {
        self.set(&[("async_enabled", "1")]);
    }

    fn set(&self, settings: &[(&str, &str)]) {
        self.state.persist_settings(settings).unwrap();
    }

    fn request(&self, streaming: bool) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(ROUTE)
            .header("x-api-key", ROOT)
            .header("content-type", "application/json")
            .header("x-off-peak-ticket-id", CLIENT_TICKET)
            .body(Body::from(request_body(streaming).to_string()))
            .unwrap()
    }

    async fn send(&self, streaming: bool) -> Reply {
        self.send_request(self.request(streaming)).await
    }

    async fn send_request(&self, request: Request<Body>) -> Reply {
        tokio::time::timeout(LIMIT, async {
            Reply::read(self.app.clone().oneshot(request).await.unwrap()).await
        })
        .await
        .expect("queue request/body exceeded the test deadline")
    }

    async fn admin(&self, method: &str, path: &str, session: bool, body: Value) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost:8787")
            .header("origin", "http://localhost:8787")
            .header("content-type", "application/json")
            .header("x-api-key", ROOT);
        if session {
            request = request.header("cookie", format!("{SESSION_COOKIE}={SESSION}"));
        }
        self.send_request(request.body(Body::from(body.to_string())).unwrap())
            .await
    }

    async fn assert_usage(&self, status: u16) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.state.usage.lock().unwrap().is_empty() {
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
            .map(|r| r.status)
            .collect();
        let persisted: Vec<_> = store::list_usage(&self.state.db.lock().unwrap(), 10)
            .iter()
            .map(|r| r.2)
            .collect();
        assert_eq!(memory, vec![status]);
        assert_eq!(persisted, vec![status]);
    }

    async fn assert_cooling(&self, email: &str, seconds: i64, before: i64) {
        let reply = self.admin("GET", "/api/accounts", true, Value::Null).await;
        assert_eq!(reply.status, StatusCode::OK, "body={}", reply.body);
        let body = reply.json();
        let account = body["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|account| account["email"] == email)
            .expect("account in admin view");
        assert_eq!(account["status"], "cooling");
        let until = account["cooling_until"].as_i64().unwrap();
        assert!(until >= before + seconds - 2, "cooling_until={until}");
        assert!(until <= now_secs() + seconds + 2, "cooling_until={until}");
    }
}

fn request_body(streaming: bool) -> Value {
    json!({"model": "zai/GLM-5.3", "stream": streaming,
        "messages": [{"role": "user", "content": "hi"}]})
}

fn api_error(message: &str) -> Value {
    json!({"type": "error", "error": {"type": "api_error", "message": message}})
}

fn async_error(message: &str) -> Value {
    json!({"type": "error", "error": {"type": "async_error", "message": message}})
}

fn ticket(id: &str, state: &str) -> Value {
    json!({"ticket_id": id, "state": state, "position": 2})
}

fn take_step(id: &str, state: &str) -> Step {
    Step::json(
        StatusCode::OK,
        json!({"code": 0, "data": ticket(id, state)}),
    )
}

fn poll_step(state: &str) -> Step {
    // The requested ticket need not be the first element of the response.
    Step::json(
        StatusCode::OK,
        json!({"code": 0, "data": {"tickets": [
            ticket("unrelated-ticket", "expired"), ticket("T1", state)
        ]}}),
    )
}

fn settle_path(ticket: &str) -> String {
    format!("{TAKE}/{ticket}/settle")
}

fn settled() -> Step {
    Step::json(StatusCode::OK, json!({"code": 0, "data": {}}))
}

async fn assert_settles(control: &Mock, ids: &[&str]) {
    for id in ids {
        control.wait_for(&settle_path(id), 1).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let seen: Vec<_> = control
        .script
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|request| request.path.ends_with("/settle"))
        .cloned()
        .collect();
    assert_eq!(
        seen.len(),
        ids.len(),
        "settle must be deduplicated per ticket"
    );
    for id in ids {
        let requests = control.seen(&settle_path(id));
        assert_eq!(requests.len(), 1, "ticket {id}");
        assert_eq!(requests[0].method, "POST");
        assert!(requests[0].body.is_empty());
    }
    control.assert_consumed();
}

fn task_ids(control: &Mock) -> Vec<String> {
    control
        .seen(TAKE)
        .iter()
        .map(|request| {
            assert_eq!(request.method, "POST");
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            let id = body["task_id"].as_str().expect("task_id string").to_owned();
            assert_eq!(body, json!({"task_id": id}));
            assert_eq!(id.len(), 36, "task_id must be a UUID");
            for (index, byte) in id.bytes().enumerate() {
                if [8, 13, 18, 23].contains(&index) {
                    assert_eq!(byte, b'-');
                } else {
                    assert!(byte.is_ascii_hexdigit(), "task_id must be a UUID");
                }
            }
            id
        })
        .collect()
}

fn assert_same_task(control: &Mock, takes: usize) {
    let ids = task_ids(control);
    assert_eq!(ids.len(), takes);
    assert!(
        ids.iter().all(|id| id == &ids[0]),
        "same-account retake changed task_id"
    );
}

fn assert_forward(request: &Seen, ticket: &str) {
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, FORWARD);
    assert_eq!(request.headers["x-off-peak-ticket-id"], ticket);
    assert_ne!(request.headers["x-off-peak-ticket-id"], CLIENT_TICKET);
    assert_eq!(request.headers["accept"], "text/event-stream");
    assert_eq!(request.headers["content-type"], "application/json");
    assert_eq!(request.headers["anthropic-version"], "2023-06-01");
    assert_eq!(request.headers["x-zcode-agent"], "glm");
    assert!(!request.headers.contains_key("x-api-key"));
    assert!(!request.headers.contains_key("cookie"));
    let body: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["stream"], true);
    assert_eq!(body["model"], "glm-5.3");
    assert_eq!(body["max_tokens"], 4096);
    let user: Value = serde_json::from_str(body["metadata"]["user_id"].as_str().unwrap()).unwrap();
    assert!(user["device_id"].is_string());
    assert_eq!(user["account_uuid"], "");
    assert_eq!(user["session_id"], "");
}

fn event(kind: &str, data: Value) -> String {
    format!("event: {kind}\ndata: {data}\n\n")
}

fn sse_start() -> String {
    event(
        "message_start",
        json!({"type": "message_start", "message": {
            "id": "msg_queue", "type": "message", "role": "assistant", "model": "glm-5.3",
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
            "delta": {"type": "text_delta", "text": "QUEUE-OK"}}),
        )
}

fn sse_suffix() -> String {
    event(
        "content_block_stop",
        json!({"type": "content_block_stop", "index": 0}),
    ) + &event(
        "message_delta",
        json!({"type": "message_delta",
            "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 4}}),
    ) + &event("message_stop", json!({"type": "message_stop"}))
}

fn valid_sse() -> String {
    sse_prefix() + &sse_suffix()
}

#[tokio::test]
async fn gates_require_a_data_plane_key_but_no_admin_session_and_never_contact_upstream() {
    let control = Mock::start(vec![]).await;
    let origin = Mock::start(vec![]).await;
    let f = Fixture::new(&control, &origin, 1);
    let mut no_key = f.request(false);
    no_key.headers_mut().remove("x-api-key");
    f.send_request(no_key).await.expect_json(
        StatusCode::UNAUTHORIZED,
        json!({
            "type": "error", "error": {"type": "authentication_error",
            "message": "API key required. Use 'Authorization: Bearer <key>' or 'x-api-key: <key>'"}
        }),
    );
    f.send(false).await.expect_json(
        StatusCode::SERVICE_UNAVAILABLE,
        api_error("async (off-peak) channel is disabled; enable async_enabled in settings"),
    );
    f.enable();
    let mut get = f.request(false);
    *get.method_mut() = axum::http::Method::GET;
    f.send_request(get).await.expect_json(
        StatusCode::METHOD_NOT_ALLOWED,
        api_error("method not allowed"),
    );
    f.set(&[("gateway_paused", "1")]);
    f.send(false).await.expect_json(
        StatusCode::SERVICE_UNAVAILABLE,
        api_error("网关已全局暂停（panic stop），请在管理面板恢复"),
    );
    control.assert_idle();
    origin.assert_idle();
}

#[tokio::test]
async fn malformed_body_and_both_bigmodel_selectors_are_rejected_before_taking_a_ticket() {
    let control = Mock::start(vec![]).await;
    let origin = Mock::start(vec![]).await;
    let f = Fixture::new(&control, &origin, 1);
    f.enable();
    let mut malformed = f.request(false);
    *malformed.body_mut() = Body::from("{not-json");
    f.send_request(malformed).await.expect_json(StatusCode::BAD_REQUEST, json!({
        "type": "error", "error": {"type": "invalid_request_error", "message": "body is not valid JSON"}
    }));
    for by_header in [false, true] {
        let mut request = f.request(false);
        if by_header {
            request
                .headers_mut()
                .insert("x-provider", "bigmodel".parse().unwrap());
        } else {
            let mut body = request_body(false);
            body["model"] = json!("bigmodel/x");
            *request.body_mut() = Body::from(body.to_string());
        }
        f.send_request(request).await.expect_json(
            StatusCode::BAD_REQUEST,
            api_error("async channel only supports zai accounts"),
        );
    }
    control.assert_idle();
    origin.assert_idle();
}

#[tokio::test]
async fn queue_settings_are_session_gated_whitelisted_visible_and_durable() {
    let control = Mock::start(vec![]).await;
    let origin = Mock::start(vec![]).await;
    let f = Fixture::new(&control, &origin, 0);
    let settings = json!({"async_enabled": "1", "async_poll_interval_ms": "500",
        "async_keepalive_ms": "300", "async_max_retries": "4", "async_max_wait_sec": "2",
        "highspeed_lane_enabled": "1"});
    let unauthorized = f
        .admin("PUT", "/api/settings", false, settings.clone())
        .await;
    assert_eq!(unauthorized.status, StatusCode::UNAUTHORIZED);
    let mut with_unknown = settings.clone();
    with_unknown["PUBLIC_unknown_setting"] = json!("ignored");
    let put = f.admin("PUT", "/api/settings", true, with_unknown).await;
    assert_eq!(put.status, StatusCode::OK, "body={}", put.body);
    let mut updated: Vec<_> = put.json()["updated"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key.as_str().unwrap().to_owned())
        .collect();
    updated.sort();
    let mut expected: Vec<_> = settings.as_object().unwrap().keys().cloned().collect();
    expected.sort();
    assert_eq!(updated, expected);
    let get = f.admin("GET", "/api/settings", true, Value::Null).await;
    assert_eq!(get.status, StatusCode::OK);
    let visible = get.json();
    let persisted = store::load_settings(&f.state.db.lock().unwrap(), &f.state.vault).unwrap();
    for (key, value) in settings.as_object().unwrap() {
        assert_eq!(&visible[key], value, "visible setting {key}");
        assert_eq!(
            persisted.get(key).map(String::as_str),
            value.as_str(),
            "durable setting {key}"
        );
    }
    assert!(visible.get("PUBLIC_unknown_setting").is_none());
    assert!(!persisted.contains_key("PUBLIC_unknown_setting"));
    control.assert_idle();
    origin.assert_idle();
}

#[tokio::test]
async fn queued_ticket_polls_then_aggregates_and_settles_only_after_forward_finishes() {
    let settle = settle_path("T1");
    let control = Mock::start(vec![
        (TAKE, take_step("T1", "queued")),
        (POLL, poll_step("ready")),
        (&settle, settled()),
    ])
    .await;
    let (tx, rx) = mpsc::channel::<Vec<u8>>(2);
    tx.send(sse_prefix().into_bytes()).await.unwrap();
    let held = Body::from_stream(stream::unfold(rx, |mut rx| async {
        rx.recv()
            .await
            .map(|bytes| (Ok::<_, Infallible>(Bytes::from(bytes)), rx))
    }));
    let origin = Mock::start(vec![(
        FORWARD,
        Step::raw(StatusCode::OK, "text/event-stream", held)
            .header("x-request-id", "PUBLIC-forward-id"),
    )])
    .await;
    let f = Fixture::new(&control, &origin, 1);
    f.enable();
    let (reply, ()) = tokio::time::timeout(LIMIT, async {
        tokio::join!(f.send(false), async {
            origin.wait_for(FORWARD, 1).await;
            assert!(
                control.seen(&settle).is_empty(),
                "live inference ticket settled early"
            );
            tx.send(sse_suffix().into_bytes()).await.unwrap();
            drop(tx);
        })
    })
    .await
    .expect("held forward must complete after release");
    reply.expect_message();
    assert_eq!(reply.headers["x-request-id"], "PUBLIC-forward-id");
    assert_same_task(&control, 1);
    let polls = control.seen(POLL);
    assert_eq!(polls.len(), 1);
    assert_eq!(polls[0].method, "POST");
    assert_eq!(
        serde_json::from_slice::<Value>(&polls[0].body).unwrap(),
        json!({"ticket_ids": ["T1"]})
    );
    let requests = origin.seen(FORWARD);
    assert_eq!(requests.len(), 1);
    assert_forward(&requests[0], "T1");
    for request in control
        .script
        .seen
        .lock()
        .unwrap()
        .iter()
        .chain(requests.iter())
    {
        assert_eq!(request.headers["authorization"], format!("Bearer {JWT}"));
        assert_eq!(request.headers["x-coding-plan-api-key"], KEY);
        assert!(request.headers.contains_key("x-zcode-app-version"));
        assert!(request.headers.contains_key("x-request-id"));
    }
    assert_settles(&control, &["T1"]).await;
    f.assert_usage(200).await;
    origin.assert_consumed();
}

#[tokio::test]
async fn streaming_headers_and_clamped_keepalive_arrive_before_the_ticket_is_ready() {
    let settle = settle_path("T1");
    let control = Mock::start(vec![
        (TAKE, take_step("T1", "queued")),
        (&settle, settled()),
    ])
    .await;
    control
        .script
        .queued_until_ready
        .store(true, Ordering::SeqCst);
    let (tx, rx) = mpsc::channel::<Vec<u8>>(2);
    tx.send(sse_prefix().into_bytes()).await.unwrap();
    let held = Body::from_stream(stream::unfold(rx, |mut rx| async {
        rx.recv()
            .await
            .map(|bytes| (Ok::<_, Infallible>(Bytes::from(bytes)), rx))
    }));
    let origin = Mock::start(vec![(
        FORWARD,
        Step::raw(StatusCode::OK, "text/event-stream", held),
    )])
    .await;
    let f = Fixture::new(&control, &origin, 1);
    f.enable();
    // 300ms is configured, but the contract clamps keepalive to 3000ms.
    f.set(&[("async_max_wait_sec", "8")]);
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        f.app.clone().oneshot(f.request(true)),
    )
    .await
    .expect("SSE headers must precede queue readiness")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/event-stream"));
    assert_eq!(response.headers()["cache-control"], "no-cache");
    origin.assert_idle();
    let mut stream = response.into_body().into_data_stream();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(6), async {
        while !String::from_utf8_lossy(&bytes).contains(": keepalive\n\n") {
            bytes.extend_from_slice(
                &stream
                    .next()
                    .await
                    .expect("queued SSE remains open")
                    .unwrap(),
            );
        }
    })
    .await
    .expect("queued SSE must emit keepalive despite intervening polls");
    origin.assert_idle();
    assert!(control.seen(&settle).is_empty());
    assert!(!control.seen(POLL).is_empty());
    control.script.ready.store(true, Ordering::SeqCst);
    tokio::time::timeout(LIMIT, async {
        while !String::from_utf8_lossy(&bytes).contains("QUEUE-OK") {
            bytes.extend_from_slice(
                &stream
                    .next()
                    .await
                    .expect("forward stream remains open")
                    .unwrap(),
            );
        }
    })
    .await
    .expect("ready ticket must pass through content before inference completes");
    assert!(
        control.seen(&settle).is_empty(),
        "streaming forward settled before EOF"
    );
    tx.send(sse_suffix().into_bytes()).await.unwrap();
    drop(tx);
    tokio::time::timeout(LIMIT, async {
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
    })
    .await
    .expect("released queue stream must finish");
    assert!(String::from_utf8(bytes).unwrap().contains(&valid_sse()));
    assert_forward(&origin.seen(FORWARD)[0], "T1");
    assert_settles(&control, &["T1"]).await;
    f.assert_usage(200).await;
}

#[tokio::test]
async fn terminal_queue_states_retake_with_the_same_task_and_settle_each_ticket_once() {
    for state in ["expired", "settled", "not_found"] {
        let first = settle_path("T1");
        let second = settle_path("T2");
        let control = Mock::start(vec![
            (TAKE, take_step("T1", "queued")),
            (POLL, poll_step(state)),
            (TAKE, take_step("T2", "ready")),
            (&first, settled()),
            (&second, settled()),
        ])
        .await;
        let origin = Mock::start(vec![(FORWARD, Step::sse())]).await;
        let f = Fixture::new(&control, &origin, 1);
        f.enable();
        f.send(false).await.expect_message();
        assert_same_task(&control, 2);
        assert_eq!(origin.seen(FORWARD).len(), 1);
        assert_forward(&origin.seen(FORWARD)[0], "T2");
        assert_settles(&control, &["T1", "T2"]).await;
    }
}

#[tokio::test]
async fn only_two_consecutive_unknown_poll_states_cause_a_retake() {
    for (states, retake) in [
        (vec!["new_state", "ready"], false),
        (vec!["new_state", "new_state"], true),
        (vec!["new_state", "queued", "new_state", "ready"], false),
    ] {
        let first = settle_path("T1");
        let second = settle_path("T2");
        let mut steps = vec![(TAKE, take_step("T1", "queued")), (&first, settled())];
        for state in states {
            steps.push((POLL, poll_step(state)));
        }
        if retake {
            steps.extend([(TAKE, take_step("T2", "ready")), (&second, settled())]);
        }
        let control = Mock::start(steps).await;
        let origin = Mock::start(vec![(FORWARD, Step::sse())]).await;
        let f = Fixture::new(&control, &origin, 1);
        f.enable();
        f.set(&[("async_max_wait_sec", "5")]);
        f.send(false).await.expect_message();
        assert_same_task(&control, if retake { 2 } else { 1 });
        assert_forward(&origin.seen(FORWARD)[0], if retake { "T2" } else { "T1" });
        assert_settles(&control, if retake { &["T1", "T2"] } else { &["T1"] }).await;
    }
}

#[tokio::test]
async fn active_deadline_is_unix_seconds_and_only_a_positive_elapsed_deadline_retakes() {
    for (deadline, retake) in [
        (now_secs() - 3600, true),
        (0, false),
        (now_secs() + 3600, false),
    ] {
        let first = settle_path("T1");
        let second = settle_path("T2");
        let mut first_ticket = ticket("T1", "active");
        first_ticket["active_deadline"] = json!(deadline);
        let mut steps = vec![
            (
                TAKE,
                Step::json(StatusCode::OK, json!({"code": 0, "data": first_ticket})),
            ),
            (&first, settled()),
        ];
        if retake {
            steps.extend([(TAKE, take_step("T2", "ready")), (&second, settled())]);
        }
        let control = Mock::start(steps).await;
        let origin = Mock::start(vec![(FORWARD, Step::sse())]).await;
        let f = Fixture::new(&control, &origin, 1);
        f.enable();
        f.send(false).await.expect_message();
        assert!(control.seen(POLL).is_empty());
        assert_same_task(&control, if retake { 2 } else { 1 });
        assert_forward(&origin.seen(FORWARD)[0], if retake { "T2" } else { "T1" });
        assert_settles(&control, if retake { &["T1", "T2"] } else { &["T1"] }).await;
    }
}

#[tokio::test]
async fn five_consecutive_poll_request_failures_return_502_and_settle_without_forwarding() {
    let settle = settle_path("T1");
    let mut steps = vec![(TAKE, take_step("T1", "queued")), (&settle, settled())];
    for _ in 0..5 {
        steps.push((
            POLL,
            Step::json(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"message": "poll unavailable"}),
            ),
        ));
    }
    let control = Mock::start(steps).await;
    let origin = Mock::start(vec![]).await;
    let f = Fixture::new(&control, &origin, 1);
    f.enable();
    f.set(&[("async_max_wait_sec", "8")]);
    let reply = f.send(false).await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY, "body={}", reply.body);
    let body = reply.json();
    let message = body["error"]["message"].as_str().unwrap();
    assert!(
        message.starts_with("闲时查票连续失败: "),
        "message={message}"
    );
    assert!(message.contains("503"), "message={message}");
    reply.expect_json(StatusCode::BAD_GATEWAY, async_error(message));
    assert_eq!(control.seen(POLL).len(), 5);
    assert_same_task(&control, 1);
    assert_settles(&control, &["T1"]).await;
    origin.assert_idle();
}

#[tokio::test]
async fn four_poll_failures_then_a_success_reset_the_consecutive_failure_budget() {
    let settle = settle_path("T1");
    let mut steps = vec![(TAKE, take_step("T1", "queued")), (&settle, settled())];
    for terminal in ["queued", "ready"] {
        for _ in 0..4 {
            steps.push((
                POLL,
                Step::json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    json!({"message": "temporary"}),
                ),
            ));
        }
        steps.push((POLL, poll_step(terminal)));
    }
    let control = Mock::start(steps).await;
    let origin = Mock::start(vec![(FORWARD, Step::sse())]).await;
    let f = Fixture::new(&control, &origin, 1);
    f.enable();
    f.set(&[("async_max_wait_sec", "8")]);
    f.send(false).await.expect_message();
    assert_eq!(control.seen(POLL).len(), 10);
    assert_same_task(&control, 1);
    assert_settles(&control, &["T1"]).await;
    f.assert_usage(200).await;
}

#[tokio::test]
async fn hard_deadline_shortens_server_poll_advice_and_returns_exact_queue_timeout() {
    let settle = settle_path("T1");
    let mut data = ticket("T1", "queued");
    data["next_poll_after"] = json!(3600);
    let control = Mock::start(vec![
        (
            TAKE,
            Step::json(StatusCode::OK, json!({"code": 0, "data": data})),
        ),
        (&settle, settled()),
    ])
    .await;
    control
        .script
        .queued_until_ready
        .store(true, Ordering::SeqCst);
    let origin = Mock::start(vec![]).await;
    let f = Fixture::new(&control, &origin, 1);
    f.enable();
    f.set(&[("async_max_wait_sec", "1")]);
    let reply = tokio::time::timeout(Duration::from_secs(4), f.send(false))
        .await
        .expect("server poll advice must not extend the request deadline");
    reply.expect_json(
        StatusCode::SERVICE_UNAVAILABLE,
        async_error("闲时排队超时，请稍后重试或改用 /v1/messages"),
    );
    assert_same_task(&control, 1);
    assert_settles(&control, &["T1"]).await;
    origin.assert_idle();
}

#[tokio::test]
async fn forward_429_code_3105_honors_retry_after_and_reuses_the_unsettled_ticket() {
    let settle = settle_path("T1");
    let control = Mock::start(vec![(TAKE, take_step("T1", "ready")), (&settle, settled())]).await;
    let origin = Mock::start(vec![
        (
            FORWARD,
            Step::json(StatusCode::TOO_MANY_REQUESTS, json!({"code": 3105}))
                .header("retry-after", "1"),
        ),
        (FORWARD, Step::sse()),
    ])
    .await;
    let f = Fixture::new(&control, &origin, 1);
    f.enable();
    let reply = tokio::time::timeout(Duration::from_secs(5), f.send(false))
        .await
        .expect("Retry-After: 1 must replace the 15-second fallback");
    reply.expect_message();
    let forwards = origin.seen(FORWARD);
    assert_eq!(forwards.len(), 2);
    for request in &forwards {
        assert_forward(request, "T1");
    }
    assert!(forwards[1].at.duration_since(forwards[0].at) >= Duration::from_millis(800));
    assert_same_task(&control, 1);
    assert_settles(&control, &["T1"]).await;
    assert!(
        control.seen(&settle)[0].at >= forwards[1].at,
        "same-ticket retry must not settle early"
    );
    f.assert_usage(200).await;
}

#[tokio::test]
async fn bare_or_non_3105_forward_429_cools_and_switches_accounts_instead_of_retrying() {
    for (body, streaming) in [("", false), ("{\"code\":9999}", true)] {
        let first = settle_path("T1");
        let second = settle_path("T2");
        let control = Mock::start(vec![
            (TAKE, take_step("T1", "ready")),
            (TAKE, take_step("T2", "ready")),
            (&first, settled()),
            (&second, settled()),
        ])
        .await;
        let origin = Mock::start(vec![
            (
                FORWARD,
                Step::raw(
                    StatusCode::TOO_MANY_REQUESTS,
                    "application/json",
                    Body::from(body),
                )
                .header("retry-after", "1"),
            ),
            (FORWARD, Step::sse()),
        ])
        .await;
        let f = Fixture::new(&control, &origin, 2);
        f.enable();
        let before = now_secs();
        let reply = f.send(streaming).await;
        if streaming {
            assert_eq!(reply.status, StatusCode::OK, "body={}", reply.body);
            assert!(reply.body.contains(": switching account\n\n"));
            assert!(reply.body.contains(&valid_sse()));
        } else {
            reply.expect_message();
        }
        let forwards = origin.seen(FORWARD);
        assert_eq!(forwards.len(), 2);
        assert_forward(&forwards[0], "T1");
        assert_forward(&forwards[1], "T2");
        assert_ne!(
            forwards[0].headers["authorization"],
            forwards[1].headers["authorization"]
        );
        let tasks = task_ids(&control);
        assert_eq!(tasks.len(), 2);
        assert_ne!(
            tasks[0], tasks[1],
            "a new account attempt needs a new task UUID"
        );
        let email = if forwards[0].headers["authorization"] == format!("Bearer {JWT}") {
            "first@example.test"
        } else {
            assert_eq!(
                forwards[0].headers["authorization"],
                format!("Bearer {OTHER_JWT}")
            );
            "second@example.test"
        };
        f.assert_cooling(email, 30, before).await;
        assert_settles(&control, &["T1", "T2"]).await;
        f.assert_usage(200).await;
    }
}

#[tokio::test]
async fn forward_400_codes_3102_and_legacy_3001_retake_with_the_same_task() {
    for code in [3102, 3001] {
        let first = settle_path("T1");
        let second = settle_path("T2");
        let control = Mock::start(vec![
            (TAKE, take_step("T1", "ready")),
            (TAKE, take_step("T2", "ready")),
            (&first, settled()),
            (&second, settled()),
        ])
        .await;
        let origin = Mock::start(vec![
            (
                FORWARD,
                Step::json(StatusCode::BAD_REQUEST, json!({"code": code})),
            ),
            (FORWARD, Step::sse()),
        ])
        .await;
        let f = Fixture::new(&control, &origin, 1);
        f.enable();
        f.send(false).await.expect_message();
        assert_same_task(&control, 2);
        let forwards = origin.seen(FORWARD);
        assert_eq!(forwards.len(), 2);
        assert_forward(&forwards[0], "T1");
        assert_forward(&forwards[1], "T2");
        assert_settles(&control, &["T1", "T2"]).await;
        f.assert_usage(200).await;
    }
}

#[tokio::test]
async fn forward_3104_and_3106_are_generic_failures_not_the_plain_lane_retake_semantics() {
    // The queue's Go implementation deliberately differs from the plain relay's comment.
    for code in [3104, 3106] {
        let settle = settle_path("T1");
        let control =
            Mock::start(vec![(TAKE, take_step("T1", "ready")), (&settle, settled())]).await;
        let upstream = json!({"code": code});
        let origin = Mock::start(vec![(
            FORWARD,
            Step::json(StatusCode::BAD_REQUEST, upstream.clone()),
        )])
        .await;
        let f = Fixture::new(&control, &origin, 1);
        f.enable();
        f.send(false).await.expect_json(
            StatusCode::BAD_REQUEST,
            api_error(&format!("闲时通道上游错误 HTTP 400: {upstream}")),
        );
        assert_same_task(&control, 1);
        assert_eq!(origin.seen(FORWARD).len(), 1);
        assert_settles(&control, &["T1"]).await;
        f.assert_usage(400).await;
    }
}

#[tokio::test]
async fn successful_http_with_json_instead_of_sse_returns_502_and_cools_for_120_seconds() {
    let settle = settle_path("T1");
    let control = Mock::start(vec![(TAKE, take_step("T1", "ready")), (&settle, settled())]).await;
    let upstream = json!({"message": "not an SSE stream"});
    let origin = Mock::start(vec![(
        FORWARD,
        Step::json(StatusCode::OK, upstream.clone()),
    )])
    .await;
    let f = Fixture::new(&control, &origin, 1);
    f.enable();
    let before = now_secs();
    f.send(false).await.expect_json(
        StatusCode::BAD_GATEWAY,
        api_error(&format!("闲时通道上游返回异常内容 HTTP 200: {upstream}")),
    );
    f.assert_cooling("first@example.test", 120, before).await;
    assert_settles(&control, &["T1"]).await;
    assert_eq!(origin.seen(FORWARD).len(), 1);
}

#[tokio::test]
async fn inline_error_or_clean_eof_without_content_appends_an_error_and_records_502() {
    let inline = sse_prefix()
        + &event(
            "error",
            json!({"type": "error", "error": {
        "type": "overloaded_error", "message": "PUBLIC upstream failed"}}),
        );
    let empty = sse_start() + &event("message_stop", json!({"type": "message_stop"}));
    for (upstream, inline) in [(inline, true), (empty, false)] {
        let settle = settle_path("T1");
        let control =
            Mock::start(vec![(TAKE, take_step("T1", "ready")), (&settle, settled())]).await;
        let origin = Mock::start(vec![(
            FORWARD,
            Step::raw(
                StatusCode::OK,
                "text/event-stream",
                Body::from(upstream.clone()),
            ),
        )])
        .await;
        let f = Fixture::new(&control, &origin, 1);
        f.enable();
        let reply = f.send(true).await;
        assert_eq!(reply.status, StatusCode::OK, "body={}", reply.body);
        assert!(reply.headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream"));
        assert!(
            reply.body.contains(&upstream),
            "upstream bytes must pass through"
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
            if inline { 2 } else { 1 },
            "proxy must append an error event"
        );
        let appended = errors.last().unwrap();
        assert_eq!(appended["type"], "error");
        assert_eq!(appended["error"]["type"], "api_error");
        let message = appended["error"]["message"].as_str().unwrap();
        assert!(!message.is_empty());
        if !inline {
            assert_eq!(
                message,
                "upstream returned an empty response (no content blocks)"
            );
        }
        f.assert_usage(502).await;
        assert_settles(&control, &["T1"]).await;
    }
}

#[tokio::test]
async fn settle_404_is_already_cleaned_and_is_not_retried() {
    let settle = settle_path("T1");
    let control = Mock::start(vec![
        (TAKE, take_step("T1", "ready")),
        (
            &settle,
            Step::json(StatusCode::NOT_FOUND, json!({"message": "already gone"})),
        ),
    ])
    .await;
    let origin = Mock::start(vec![(FORWARD, Step::sse())]).await;
    let f = Fixture::new(&control, &origin, 1);
    f.enable();
    f.send(false).await.expect_message();
    control.wait_for(&settle, 1).await;
    tokio::time::sleep(Duration::from_millis(3500)).await;
    assert_settles(&control, &["T1"]).await;
    f.assert_usage(200).await;
}

#[tokio::test]
async fn settle_transport_failure_retries_once_after_three_seconds() {
    let disconnect = Disconnect::start().await;
    let settle = settle_path("T1");
    let control = Mock::start(vec![
        (TAKE, take_step("T1", "ready")),
        (
            &settle,
            Step::raw(
                StatusCode::TEMPORARY_REDIRECT,
                "application/json",
                Body::empty(),
            )
            .header("location", &disconnect.url),
        ),
        (&settle, settled()),
    ])
    .await;
    let origin = Mock::start(vec![(FORWARD, Step::sse())]).await;
    let f = Fixture::new(&control, &origin, 1);
    f.enable();
    f.send(false).await.expect_message();
    control.wait_for(&settle, 2).await;
    let requests = control.seen(&settle);
    assert_eq!(requests.len(), 2);
    assert!(
        disconnect.connections.load(Ordering::SeqCst) >= 1,
        "first settle must fail at transport"
    );
    assert!(requests[1].at.duration_since(requests[0].at) >= Duration::from_millis(2500));
    for request in requests {
        assert_eq!(request.method, "POST");
        assert!(request.body.is_empty());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(control.seen(&settle).len(), 2);
    control.assert_consumed();
    f.assert_usage(200).await;
}

fn queue_fixture_with_management(
    control: &Mock,
    origin: &Mock,
    management: &Mock,
    account_count: usize,
) -> Fixture {
    let Fixture { state, app } = Fixture::new(control, origin, account_count.min(2));
    drop(app);
    let mut state = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("fixture still shared"));
    state.management.billing_base = format!("{}/api/v1/zcode-plan", management.base);
    state.management.quota_limit = format!("{}/management/quota", management.base);
    state.management.subscription = format!("{}/management/subscription", management.base);
    state.management.oauth_token = format!("{}/management/oauth-token", management.base);
    if account_count > 2 {
        let db = state.db.lock().unwrap();
        for index in 2..account_count {
            let jwt = format!("PUBLIC-queue-jwt-{index}");
            let key = format!("PUBLIC-queue-coding-key-{index}");
            store::upsert_account(
                &db,
                &AccountView {
                    email: format!("account-{index}@example.test"),
                    provider: "zai".into(),
                    enabled: true,
                    status: "active".into(),
                    zcode_jwt: jwt.clone(),
                    api_key: key.clone(),
                    ..AccountView::default()
                },
                &jwt,
                &key,
            );
        }
        let rows = store::load_accounts(&db, &state.vault).unwrap();
        *state.accounts.lock().unwrap() = rows.iter().map(|(a, _, _)| a.clone()).collect();
        *state.creds.lock().unwrap() = rows
            .into_iter()
            .map(|(a, jwt, key)| {
                (
                    a.id,
                    zcode_proxy::state::Creds {
                        zcode_jwt: jwt,
                        api_key: key,
                    },
                )
            })
            .collect();
    }
    let state = Arc::new(state);
    Fixture {
        app: build_router(state.clone()),
        state,
    }
}

fn healthy_queue_billing() -> Step {
    Step::json(
        StatusCode::OK,
        json!({"code": 0, "success": true, "data": {"result": {
            "plans": [{"plan_id": "pro", "name": "Pro", "status": "active"}],
            "balances": [{"plan_id": "pro", "total_units": 100,
                "used_units": 10, "remaining_units": 90}]
        }}}),
    )
}

async fn queue_account_view(f: &Fixture, authorization: &str) -> Value {
    let email = if authorization == format!("Bearer {JWT}") {
        "first@example.test"
    } else {
        assert_eq!(authorization, format!("Bearer {OTHER_JWT}"));
        "second@example.test"
    };
    let reply = f.admin("GET", "/api/accounts", true, Value::Null).await;
    assert_eq!(reply.status, StatusCode::OK, "body={}", reply.body);
    reply.json()["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|account| account["email"] == email)
        .expect("account in admin view")
        .clone()
}

#[tokio::test]
async fn take_401_on_billing_valid_account_does_not_invalidate() {
    const BILLING: &str = "/api/v1/zcode-plan/billing/balance";
    let control = Mock::start(vec![(
        TAKE,
        Step::json(
            StatusCode::UNAUTHORIZED,
            json!({"message": "queue authorization rejected"}),
        ),
    )])
    .await;
    let origin = Mock::start(vec![]).await;
    let management = Mock::start(vec![(BILLING, healthy_queue_billing())]).await;
    let f = queue_fixture_with_management(&control, &origin, &management, 1);
    f.enable();
    let reply = f.send(false).await;
    assert_eq!(
        reply.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "body={}",
        reply.body
    );
    assert_eq!(reply.json()["type"], "error");
    assert!(!reply.json()["error"]["message"]
        .as_str()
        .unwrap()
        .is_empty());
    let billing = management.seen(BILLING);
    assert_eq!(
        billing.len(),
        1,
        "take 401 must attempt credential recovery"
    );
    assert_eq!(billing[0].method, "GET");
    assert_eq!(billing[0].headers["authorization"], format!("Bearer {JWT}"));
    let account = queue_account_view(&f, &format!("Bearer {JWT}")).await;
    assert_ne!(
        account["status"], "invalid",
        "healthy billing without token rotation is not failed recovery"
    );
    let db_status: String = f
        .state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT status FROM accounts WHERE email=?1",
            ["first@example.test"],
            |row| row.get(0),
        )
        .unwrap();
    assert_ne!(
        db_status, "invalid",
        "invalid status must not survive reload either"
    );
    assert_same_task(&control, 1);
    assert_settles(&control, &[]).await;
    management.assert_consumed();
    origin.assert_idle();
}

#[tokio::test]
async fn forward_401_cools_or_invalidates_per_go() {
    const BILLING: &str = "/api/v1/zcode-plan/billing/balance";
    for status in [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN] {
        for recovery in ["healthy", "failed", "cloudflare"] {
            let first = settle_path("T1");
            let second = settle_path("T2");
            let control = Mock::start(vec![
                (TAKE, take_step("T1", "ready")),
                (TAKE, take_step("T2", "ready")),
                (&first, settled()),
                (&second, settled()),
            ])
            .await;
            let rejected = if recovery == "cloudflare" {
                Step::raw(status, "text/html", Body::from(
                    "<html><title>Just a moment...</title><script src='/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1'></script></html>"
                )).header("cf-mitigated", "challenge")
            } else {
                Step::json(status, json!({"message": "credentials rejected"}))
            };
            let origin = Mock::start(vec![(FORWARD, rejected), (FORWARD, Step::sse())]).await;
            let management = Mock::start(match recovery {
                "healthy" => vec![(BILLING, healthy_queue_billing())],
                "failed" => vec![
                    (
                        BILLING,
                        Step::json(StatusCode::UNAUTHORIZED, json!({"message": "JWT rejected"})),
                    ),
                    (
                        "/management/quota",
                        Step::json(StatusCode::UNAUTHORIZED, json!({"message": "key rejected"})),
                    ),
                ],
                _ => vec![],
            })
            .await;
            let f = queue_fixture_with_management(&control, &origin, &management, 2);
            f.enable();
            let before = now_secs();
            f.send(false).await.expect_message();
            let forwards = origin.seen(FORWARD);
            assert_eq!(forwards.len(), 2, "status={status}, recovery={recovery}");
            assert_forward(&forwards[0], "T1");
            assert_forward(&forwards[1], "T2");
            assert_ne!(
                forwards[0].headers["authorization"],
                forwards[1].headers["authorization"]
            );
            let authorization = forwards[0].headers["authorization"].to_str().unwrap();
            let account = queue_account_view(&f, authorization).await;
            match recovery {
                "cloudflare" => {
                    let email = account["email"].as_str().unwrap();
                    f.assert_cooling(email, 300, before).await;
                    management.assert_idle();
                }
                "healthy" => {
                    assert_ne!(
                        account["status"], "invalid",
                        "successful refresh without credential rotation must not invalidate"
                    );
                    assert_eq!(management.seen(BILLING).len(), 1);
                    assert_eq!(
                        management.seen(BILLING)[0].headers["authorization"],
                        authorization
                    );
                }
                "failed" => {
                    assert_eq!(
                        account["status"], "invalid",
                        "definite recovery failure must invalidate"
                    );
                    assert_eq!(management.seen(BILLING).len(), 1);
                    assert_eq!(management.seen("/management/quota").len(), 1);
                }
                _ => unreachable!(),
            }
            let tasks = task_ids(&control);
            assert_eq!(tasks.len(), 2);
            assert_ne!(tasks[0], tasks[1]);
            assert_settles(&control, &["T1", "T2"]).await;
            management.assert_consumed();
        }
    }
}

#[tokio::test]
async fn client_metadata_object_without_user_id_is_left_untouched() {
    for metadata in [
        json!({"custom": "x"}),
        json!("PUBLIC-client-metadata-string"),
    ] {
        let settle = settle_path("T1");
        let control =
            Mock::start(vec![(TAKE, take_step("T1", "ready")), (&settle, settled())]).await;
        let origin = Mock::start(vec![(FORWARD, Step::sse())]).await;
        let f = Fixture::new(&control, &origin, 1);
        f.enable();
        let mut body = request_body(false);
        body["metadata"] = metadata.clone();
        let mut request = f.request(false);
        *request.body_mut() = Body::from(body.to_string());
        f.send_request(request).await.expect_message();
        let forwards = origin.seen(FORWARD);
        assert_eq!(forwards.len(), 1);
        let sent: Value = serde_json::from_slice(&forwards[0].body).unwrap();
        assert_eq!(
            sent["metadata"], metadata,
            "metadata present on the client must remain unchanged"
        );
        assert_eq!(sent["stream"], true);
        assert_settles(&control, &["T1"]).await;
    }
}

#[tokio::test]
async fn attempt_cap_is_five_accounts() {
    let mut steps = Vec::new();
    for _ in 0..5 {
        steps.push((
            TAKE,
            Step::json(
                StatusCode::TOO_MANY_REQUESTS,
                json!({"message": "queue saturated"}),
            ),
        ));
    }
    let control = Mock::start(steps).await;
    let origin = Mock::start(vec![]).await;
    let management = Mock::start(vec![]).await;
    let f = queue_fixture_with_management(&control, &origin, &management, 6);
    f.enable();
    let reply = f.send(false).await;
    assert_eq!(
        reply.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "body={}",
        reply.body
    );
    assert_eq!(reply.json()["type"], "error");
    assert!(!reply.json()["error"]["message"]
        .as_str()
        .unwrap()
        .is_empty());
    let tasks = task_ids(&control);
    assert_eq!(
        tasks.len(),
        5,
        "six eligible accounts must be limited to five attempts, not three"
    );
    let distinct_tasks: std::collections::HashSet<_> = tasks.iter().collect();
    assert_eq!(
        distinct_tasks.len(),
        5,
        "each attempted account needs its own task UUID"
    );
    let authorization: std::collections::HashSet<_> = control
        .seen(TAKE)
        .into_iter()
        .map(|request| {
            request.headers["authorization"]
                .to_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        authorization.len(),
        5,
        "each attempt must select a different account"
    );
    let view = f.admin("GET", "/api/accounts", true, Value::Null).await;
    assert_eq!(view.status, StatusCode::OK);
    let accounts = view.json();
    let accounts = accounts["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 6);
    for account in accounts {
        assert_eq!(
            account["status"], "active",
            "take 429 must not penalize account health"
        );
        assert_eq!(account["cooling_until"], 0);
    }
    assert_settles(&control, &[]).await;
    origin.assert_idle();
    management.assert_idle();
}
