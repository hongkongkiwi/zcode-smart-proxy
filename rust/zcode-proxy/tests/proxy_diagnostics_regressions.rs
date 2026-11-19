//! Independent HTTP regressions for the fixed proxy-diagnostics design contract.
//! All probe destinations and forwarding proxies are real loopback listeners.

use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::params;
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tower::ServiceExt;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    proxy_diagnostics::ProxyDiagnosticsConfig,
    state::{AppState, UpstreamUrls},
    vault::Vault,
};

const HOST: &str = "localhost:8080";
const SESSION: &str = "PUBLIC-diagnostics-session";
const USER: &str = "PUBLIC-diagnostics-user";
const PASS: &str = "PUBLIC-diagnostics-password";
const IP: &str = "203.0.113.42";
const CHILD_MODE: &str = "ZCODE_DIAGNOSTICS_TEST_CHILD";

struct Fixture {
    state: Arc<AppState>,
}

impl Fixture {
    fn new(urls: Vec<String>) -> Self {
        let mut state = AppState::new(
            String::new(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
        );
        state.proxy_diagnostics = ProxyDiagnosticsConfig { exit_ip_urls: urls };
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        Self {
            state: Arc::new(state),
        }
    }

    async fn call(&self, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        call_raw(
            &self.state,
            method,
            uri,
            body.map(|v| v.to_string()),
            Some(SESSION),
            Some("http://localhost:8080"),
        )
        .await
    }

    async fn create_node(&self, proxy: &Mock) -> i64 {
        let (status, reply) = self
            .call("POST", "/api/proxies", Some(node_body(proxy.port())))
            .await;
        assert_eq!(status, StatusCode::OK, "create node: {reply}");
        reply["id"].as_i64().expect("created node id")
    }

    async fn node(&self, id: i64) -> Value {
        let (status, reply) = self.call("GET", "/api/proxies", None).await;
        assert_eq!(status, StatusCode::OK, "list nodes: {reply}");
        reply["proxies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == id)
            .expect("node exists")
            .clone()
    }
}

fn node_body(port: u16) -> Value {
    json!({"name": "PUBLIC diagnostic node", "type": "http", "host": "127.0.0.1",
        "port": port, "username": USER, "password": PASS, "enabled": true})
}

async fn call_raw(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<String>,
    session: Option<&str>,
    origin: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", HOST);
    if let Some(session) = session {
        request = request.header("cookie", format!("{SESSION_COOKIE}={session}"));
    }
    if let Some(origin) = origin {
        request = request.header("origin", origin);
    }
    let body = match body {
        Some(body) => {
            request = request.header("content-type", "application/json");
            Body::from(body)
        }
        None => Body::empty(),
    };
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        build_router(state.clone()).oneshot(request.body(body).unwrap()),
    )
    .await
    .expect("loopback diagnostic API timed out")
    .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        panic!(
            "non-JSON API response ({status}): {}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, value)
}

fn assert_outcome(status: StatusCode, reply: &Value, ok: bool, ip: &str) {
    assert_eq!(status, StatusCode::OK, "diagnostic reply: {reply}");
    assert_eq!(reply["ok"], ok, "diagnostic reply: {reply}");
    assert_eq!(reply["exit_ip"], ip, "diagnostic reply: {reply}");
    assert!(
        reply["elapsed_ms"].as_u64().is_some(),
        "nonnegative elapsed_ms: {reply}"
    );
    if !ok {
        assert!(
            !reply["message"].as_str().unwrap_or("").is_empty(),
            "failure needs a message: {reply}"
        );
    }
}

fn assert_no_credentials(value: &Value, ciphertext: Option<&str>) {
    let text = value.to_string();
    for secret in [
        USER.to_owned(),
        PASS.to_owned(),
        STANDARD.encode(format!("{USER}:{PASS}")),
        "vault1:".into(),
    ] {
        assert!(
            !text.contains(&secret),
            "diagnostic leaked synthetic credentials"
        );
    }
    if let Some(ciphertext) = ciphertext {
        assert!(
            !text.contains(ciphertext),
            "diagnostic leaked encrypted credentials"
        );
    }
}

#[derive(Clone, Debug)]
struct Hit {
    target: String,
    authorization: Option<String>,
    proxy_authorization: Option<String>,
}

struct Gate {
    entered: Semaphore,
    release: Semaphore,
}

impl Gate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
        })
    }

    async fn wait(&self) {
        tokio::time::timeout(Duration::from_secs(5), self.entered.acquire())
            .await
            .expect("probe never reached loopback target")
            .unwrap()
            .forget();
    }
}

struct Mock {
    authority: String,
    hits: Arc<Mutex<Vec<Hit>>>,
    reject: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Mock {
    async fn target(responses: Vec<String>, gate: Option<Arc<Gate>>) -> Self {
        Self::start(Some(responses), gate).await
    }

    async fn proxy() -> Self {
        Self::start(None, None).await
    }

    async fn start(responses: Option<Vec<String>>, gate: Option<Arc<Gate>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let hits = Arc::new(Mutex::new(Vec::new()));
        let log = hits.clone();
        let reject = Arc::new(AtomicBool::new(false));
        let rejected = reject.clone();
        let task = tokio::spawn(async move {
            let mut responses = responses.map(VecDeque::from);
            while let Ok((mut stream, _)) = listener.accept().await {
                let Ok(Some(head)) =
                    tokio::time::timeout(Duration::from_secs(5), read_head(&mut stream)).await
                else {
                    continue;
                };
                let mut lines = head.split("\r\n");
                let first = lines.next().unwrap_or_default();
                let mut parts = first.split_whitespace();
                let method = parts.next().unwrap_or_default();
                let target = parts.next().unwrap_or_default();
                let headers: Vec<_> = lines.filter_map(|line| line.split_once(':')).collect();
                let header = |name: &str| {
                    headers
                        .iter()
                        .find(|(key, _)| key.eq_ignore_ascii_case(name))
                        .map(|(_, value)| value.trim().to_owned())
                };
                let proxy_auth = header("proxy-authorization");
                log.lock().unwrap().push(Hit {
                    target: target.into(),
                    authorization: header("authorization"),
                    proxy_authorization: proxy_auth.clone(),
                });
                if let Some(gate) = &gate {
                    gate.entered.add_permits(1);
                    let Ok(permit) = gate.release.acquire().await else {
                        break;
                    };
                    permit.forget();
                }
                if let Some(responses) = &mut responses {
                    let wire = responses
                        .pop_front()
                        .unwrap_or_else(|| wire(500, "unexpected extra request", false));
                    let _ = stream.write_all(wire.as_bytes()).await;
                    continue;
                }
                let expected = format!("Basic {}", STANDARD.encode(format!("{USER}:{PASS}")));
                if rejected.load(Ordering::SeqCst)
                    || proxy_auth.as_deref() != Some(expected.as_str())
                {
                    let _ = stream
                        .write_all(wire(407, "proxy auth required", false).as_bytes())
                        .await;
                    continue;
                }
                // A forwarding proxy may contact only a configured IPv4 loopback target.
                let Ok(url) = reqwest::Url::parse(target) else {
                    continue;
                };
                if method != "GET"
                    || url.scheme() != "http"
                    || url.host_str() != Some("127.0.0.1")
                    || !url.username().is_empty()
                    || url.password().is_some()
                {
                    let _ = stream
                        .write_all(wire(502, "non-loopback destination refused", false).as_bytes())
                        .await;
                    continue;
                }
                let Ok(mut upstream) =
                    TcpStream::connect(("127.0.0.1", url.port_or_known_default().unwrap())).await
                else {
                    continue;
                };
                let mut path = url.path().to_owned();
                if let Some(query) = url.query() {
                    path.push('?');
                    path.push_str(query);
                }
                let mut forwarded = format!("GET {path} HTTP/1.1\r\n");
                for (key, value) in headers {
                    if !key.eq_ignore_ascii_case("proxy-authorization")
                        && !key.eq_ignore_ascii_case("proxy-connection")
                        && !key.eq_ignore_ascii_case("connection")
                    {
                        forwarded.push_str(&format!("{key}:{value}\r\n"));
                    }
                }
                forwarded.push_str("connection: close\r\n\r\n");
                if upstream.write_all(forwarded.as_bytes()).await.is_ok() {
                    let _ = tokio::time::timeout(
                        Duration::from_secs(5),
                        tokio::io::copy(&mut upstream, &mut stream),
                    )
                    .await;
                }
            }
        });
        Self {
            authority,
            hits,
            reject,
            task,
        }
    }

    fn url(&self) -> String {
        format!("http://{}/exit?format=json", self.authority)
    }
    fn proxy_url(&self) -> String {
        format!("http://{USER}:{PASS}@{}", self.authority)
    }
    fn port(&self) -> u16 {
        self.authority.rsplit_once(':').unwrap().1.parse().unwrap()
    }
    fn hits(&self) -> Vec<Hit> {
        self.hits.lock().unwrap().clone()
    }
}

async fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    loop {
        let count = stream.read(&mut buffer).await.ok()?;
        if count == 0 {
            return None;
        }
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            return Some(String::from_utf8_lossy(&bytes[..end]).into_owned());
        }
        if bytes.len() > 65536 {
            return None;
        }
    }
}

fn wire(status: u16, body: &str, chunked: bool) -> String {
    let mut response = format!(
        "HTTP/1.1 {status} Mock\r\ncontent-type: application/json\r\nconnection: close\r\n"
    );
    if chunked {
        response.push_str("transfer-encoding: chunked\r\n\r\n");
        for chunk in body.as_bytes().chunks(31) {
            response.push_str(&format!(
                "{:x}\r\n{}\r\n",
                chunk.len(),
                std::str::from_utf8(chunk).unwrap()
            ));
        }
        response.push_str("0\r\n\r\n");
    } else {
        response.push_str(&format!("content-length: {}\r\n\r\n{body}", body.len()));
    }
    response
}

fn ip_wire() -> String {
    wire(200, &json!({"ip": IP}).to_string(), false)
}

#[test]
fn default_targets_are_the_verified_go_providers() {
    let expected = vec![
        "https://api.ipify.org/?format=json".to_owned(),
        "https://ipinfo.io/json".to_owned(),
    ];
    assert_eq!(ProxyDiagnosticsConfig::default().exit_ip_urls, expected);
    let state = AppState::new(
        String::new(),
        UpstreamUrls {
            zai: String::new(),
            zai_fallback: String::new(),
        },
    );
    assert_eq!(state.proxy_diagnostics.exit_ip_urls, expected);
}

#[tokio::test]
async fn explicit_direct_bypasses_invalid_global_and_default_node() {
    let target = Mock::target(vec![ip_wire(), ip_wire(), ip_wire()], None).await;
    let proxy = Mock::proxy().await;
    let f = Fixture::new(vec![target.url()]);
    let id = f.create_node(&proxy).await;
    f.state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE proxy_nodes SET is_default=1 WHERE id=?1", [id])
        .unwrap();
    f.state
        .persist_settings(&[("upstream_proxy", "http://127.0.0.1:0")])
        .unwrap();
    for body in [None, Some(json!({})), Some(json!({"url": " \t\r\n "}))] {
        let (status, reply) = f.call("POST", "/api/proxies/test-url", body).await;
        assert_outcome(status, &reply, true, IP);
    }
    assert_eq!(target.hits().len(), 3);
    assert!(
        proxy.hits().is_empty(),
        "explicit direct must not use the default node"
    );
    assert_eq!(
        f.state.setting("upstream_proxy").as_deref(),
        Some("http://127.0.0.1:0"),
        "diagnostics must not change routing settings"
    );
}

#[tokio::test]
async fn authenticated_http_proxy_forwards_without_leaking_credentials_to_target_or_reply() {
    let target = Mock::target(vec![ip_wire()], None).await;
    let proxy = Mock::proxy().await;
    let f = Fixture::new(vec![target.url()]);
    f.state
        .persist_settings(&[("upstream_proxy", "http://127.0.0.1:0")])
        .unwrap();
    let (status, reply) = f
        .call(
            "POST",
            "/api/proxies/test-url",
            Some(json!({"url": proxy.proxy_url()})),
        )
        .await;
    assert_outcome(status, &reply, true, IP);
    assert_no_credentials(&reply, None);
    let hits = proxy.hits();
    assert_eq!(hits.len(), 1, "must actually use the proxy");
    assert_eq!(hits[0].target, target.url());
    assert_eq!(
        hits[0].proxy_authorization,
        Some(format!(
            "Basic {}",
            STANDARD.encode(format!("{USER}:{PASS}"))
        ))
    );
    let hits = target.hits();
    assert_eq!(hits.len(), 1, "proxy must forward to the real target");
    assert_eq!(hits[0].target, "/exit?format=json");
    assert!(hits[0].authorization.is_none());
    assert!(hits[0].proxy_authorization.is_none());
}

#[tokio::test]
async fn providers_fall_back_after_failure_and_stop_at_first_success() {
    let failed = Mock::target(vec![wire(503, "unavailable", false)], None).await;
    let success = Mock::target(vec![ip_wire()], None).await;
    let unused = Mock::target(vec![ip_wire()], None).await;
    let f = Fixture::new(vec![failed.url(), success.url(), unused.url()]);
    let (status, reply) = f.call("POST", "/api/proxies/test-url", None).await;
    assert_outcome(status, &reply, true, IP);
    assert_eq!(failed.hits().len(), 1);
    assert_eq!(success.hits().len(), 1);
    assert!(
        unused.hits().is_empty(),
        "first successful provider must end the probe"
    );
}

#[tokio::test]
async fn invalid_proxy_scheme_fails_without_direct_fallback() {
    let target = Mock::target(vec![ip_wire()], None).await;
    let f = Fixture::new(vec![target.url()]);
    let (status, reply) = f
        .call(
            "POST",
            "/api/proxies/test-url",
            Some(json!({"url": format!("ftp://{USER}:{PASS}@127.0.0.1:12345")})),
        )
        .await;
    assert_outcome(status, &reply, false, "");
    assert_no_credentials(&reply, None);
    assert!(
        target.hits().is_empty(),
        "invalid explicit proxy must never mean direct"
    );
}

#[tokio::test]
async fn response_body_limit_is_inclusive_and_enforced_for_chunked_bodies() {
    for (size, chunked, ok) in [(4096, false, true), (4096, true, true), (4097, true, false)] {
        let mut body = json!({"ip": IP}).to_string();
        body.push_str(&" ".repeat(size - body.len()));
        let target = Mock::target(vec![wire(200, &body, chunked)], None).await;
        let f = Fixture::new(vec![target.url()]);
        let (status, reply) = f.call("POST", "/api/proxies/test-url", None).await;
        assert_outcome(status, &reply, ok, if ok { IP } else { "" });
        assert_eq!(target.hits().len(), 1, "size={size}, chunked={chunked}");
    }
}

#[tokio::test]
async fn redirects_are_not_followed_and_invalid_ip_values_are_not_successes() {
    let destination = Mock::target(vec![ip_wire()], None).await;
    let redirect = Mock::target(
        vec![format!(
            "HTTP/1.1 302 Found\r\nlocation: {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            destination.url()
        )],
        None,
    )
    .await;
    let f = Fixture::new(vec![redirect.url()]);
    let (status, reply) = f.call("POST", "/api/proxies/test-url", None).await;
    assert_outcome(status, &reply, false, "");
    assert!(
        destination.hits().is_empty(),
        "redirect target must not be contacted"
    );
    for body in [
        json!({"ip": "not an IP"}),
        json!({"ip": "203.0.113.999"}),
        json!({"ip": ""}),
        json!({"ip": 42}),
        json!({}),
    ] {
        let bad = Mock::target(vec![wire(200, &body.to_string(), false)], None).await;
        let good = Mock::target(vec![wire(200, "{\"ip\":\"2001:db8::42\"}", false)], None).await;
        let f = Fixture::new(vec![bad.url(), good.url()]);
        let (status, reply) = f.call("POST", "/api/proxies/test-url", None).await;
        assert_outcome(status, &reply, true, "2001:db8::42");
        assert_eq!(
            good.hits().len(),
            1,
            "invalid provider body must fall back: {body}"
        );
    }
}

#[tokio::test]
async fn malformed_body_and_node_ids_have_client_error_statuses_without_network() {
    let target = Mock::target(vec![ip_wire()], None).await;
    let f = Fixture::new(vec![target.url()]);
    for body in ["{not json", "{\"url\":17}"] {
        let (status, reply) = call_raw(
            &f.state,
            "POST",
            "/api/proxies/test-url",
            Some(body.into()),
            Some(SESSION),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "malformed request: {reply}"
        );
    }
    for (id, expected) in [
        ("abc", StatusCode::BAD_REQUEST),
        ("12x", StatusCode::BAD_REQUEST),
        ("999999", StatusCode::NOT_FOUND),
    ] {
        let (status, reply) = f
            .call("POST", &format!("/api/proxies/{id}/test"), None)
            .await;
        assert_eq!(status, expected, "id={id}: {reply}");
    }
    assert!(target.hits().is_empty());
}

#[tokio::test]
async fn diagnostics_require_live_sessions_and_same_origin_writes() {
    let target = Mock::target(vec![ip_wire()], None).await;
    let f = Fixture::new(vec![target.url()]);
    f.state
        .sessions
        .lock()
        .unwrap()
        .insert("PUBLIC-expired".into(), now_secs() - 1);
    for (method, uri) in [
        ("GET", "/api/proxies/system"),
        ("GET", "/api/proxies/probe-ports"),
        ("POST", "/api/proxies/test-url"),
        ("POST", "/api/proxies/1/test"),
    ] {
        for session in [None, Some("PUBLIC-expired")] {
            let (status, reply) = call_raw(&f.state, method, uri, None, session, None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}: {reply}");
        }
    }
    for uri in ["/api/proxies/test-url", "/api/proxies/1/test"] {
        let (status, reply) = call_raw(
            &f.state,
            "POST",
            uri,
            None,
            Some(SESSION),
            Some("http://evil.example.invalid"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "cross-origin {uri}: {reply}");
    }
    assert!(
        target.hits().is_empty(),
        "gates must precede diagnostic traffic"
    );
}

#[tokio::test]
async fn node_probe_persists_success_and_sanitized_failure_and_reports_database_failure() {
    let target = Mock::target(vec![ip_wire()], None).await;
    let proxy = Mock::proxy().await;
    let f = Fixture::new(vec![target.url()]);
    let id = f.create_node(&proxy).await;
    let cipher: String = f
        .state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT password FROM proxy_nodes WHERE id=?1",
            [id],
            |row| row.get(0),
        )
        .unwrap();
    let uri = format!("/api/proxies/{id}/test");
    let (status, reply) = f.call("POST", &uri, None).await;
    assert_outcome(status, &reply, true, IP);
    assert_no_credentials(&reply, Some(&cipher));
    let display = reqwest::Url::parse(reply["proxy"].as_str().expect("masked proxy URL")).unwrap();
    assert!(display.username().is_empty() && display.password().is_none());
    assert_eq!(display.port(), Some(proxy.port()));
    let node = f.node(id).await;
    assert_eq!(node["check_status"], "ok");
    assert_eq!(node["check_ip"], IP);
    assert_eq!(node["check_latency"], reply["elapsed_ms"]);
    assert_eq!(node["check_msg"], "");
    assert!(!node["check_at"].as_str().unwrap_or("").is_empty());
    assert_eq!(proxy.hits().len(), 1);
    assert_eq!(target.hits().len(), 1);

    proxy.reject.store(true, Ordering::SeqCst);
    let (status, reply) = f.call("POST", &uri, None).await;
    assert_outcome(status, &reply, false, "");
    assert_no_credentials(&reply, Some(&cipher));
    let node = f.node(id).await;
    assert_eq!(node["check_status"], "fail");
    assert_eq!(node["check_ip"], "", "failed check must clear the prior IP");
    assert_eq!(node["check_latency"], reply["elapsed_ms"]);
    assert_eq!(node["check_msg"], reply["message"]);
    assert!(!node["check_at"].as_str().unwrap_or("").is_empty());
    let diagnostic_fields = json!({"message": node["check_msg"], "proxy": reply["proxy"]});
    assert_no_credentials(&diagnostic_fields, Some(&cipher));
    assert_eq!(proxy.hits().len(), 2);
    assert_eq!(
        target.hits().len(),
        1,
        "proxy failure must not fall back direct"
    );

    f.state.db.lock().unwrap().execute_batch("CREATE TRIGGER reject_diagnostic_update BEFORE UPDATE OF check_status ON proxy_nodes BEGIN SELECT RAISE(FAIL, 'PUBLIC diagnostic write failure'); END;").unwrap();
    let before = f.node(id).await;
    let (status, reply) = f.call("POST", &uri, None).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "persistence failure must not claim success: {reply}"
    );
    assert_no_credentials(&reply, Some(&cipher));
    assert_eq!(
        f.node(id).await,
        before,
        "failed diagnostic write must leave the previous row intact"
    );
}

#[tokio::test]
async fn corrupted_encrypted_node_credentials_fail_closed_even_without_username() {
    let target = Mock::target(vec![ip_wire()], None).await;
    let proxy = Mock::proxy().await;
    let f = Fixture::new(vec![target.url()]);
    let id = f.create_node(&proxy).await;
    let foreign = Vault::from_secret("PUBLIC unrelated diagnostic vault seed").unwrap();
    let cipher = foreign.encrypt(PASS).unwrap();
    for username in [USER, ""] {
        f.state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE proxy_nodes SET username=?1,password=?2 WHERE id=?3",
                params![username, cipher, id],
            )
            .unwrap();
        let (status, reply) = f
            .call("POST", &format!("/api/proxies/{id}/test"), None)
            .await;
        assert_outcome(status, &reply, false, "");
        assert_no_credentials(&reply, Some(&cipher));
    }
    assert!(
        proxy.hits().is_empty(),
        "broken credentials must not attempt unauthenticated proxy traffic"
    );
    assert!(
        target.hits().is_empty(),
        "broken credentials must not fall back direct"
    );
}

#[tokio::test]
async fn editing_connection_during_probe_rejects_stale_result_without_overwriting_diagnostics() {
    let gate = Gate::new();
    let target = Mock::target(vec![ip_wire()], Some(gate.clone())).await;
    let proxy = Mock::proxy().await;
    let replacement = Mock::proxy().await;
    let f = Fixture::new(vec![target.url()]);
    let id = f.create_node(&proxy).await;
    let state = f.state.clone();
    let request = tokio::spawn(async move {
        call_raw(
            &state,
            "POST",
            &format!("/api/proxies/{id}/test"),
            None,
            Some(SESSION),
            None,
        )
        .await
    });
    gate.wait().await;
    let (status, reply) = f
        .call(
            "PUT",
            &format!("/api/proxies/{id}"),
            Some(node_body(replacement.port())),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "concurrent edit: {reply}");
    f.state.db.lock().unwrap().execute("UPDATE proxy_nodes SET check_status='fail',check_latency=73,check_ip='198.51.100.7',check_msg='PUBLIC newer diagnostic',check_at='PUBLIC newer timestamp' WHERE id=?1", [id]).unwrap();
    let before = f.node(id).await;
    gate.release.add_permits(1);
    let (status, reply) = request.await.unwrap();
    assert_eq!(status, StatusCode::CONFLICT, "stale snapshot: {reply}");
    assert_eq!(
        f.node(id).await,
        before,
        "old probe must not overwrite any newer diagnostics or connection fields"
    );
    assert!(
        replacement.hits().is_empty(),
        "in-flight probe uses its original snapshot"
    );
}

#[tokio::test]
async fn deletion_during_probe_returns_not_found_without_resurrecting_node() {
    let gate = Gate::new();
    let target = Mock::target(vec![ip_wire()], Some(gate.clone())).await;
    let proxy = Mock::proxy().await;
    let f = Fixture::new(vec![target.url()]);
    let id = f.create_node(&proxy).await;
    let state = f.state.clone();
    let request = tokio::spawn(async move {
        call_raw(
            &state,
            "POST",
            &format!("/api/proxies/{id}/test"),
            None,
            Some(SESSION),
            None,
        )
        .await
    });
    gate.wait().await;
    let (status, reply) = f.call("DELETE", &format!("/api/proxies/{id}"), None).await;
    assert_eq!(status, StatusCode::OK, "concurrent deletion: {reply}");
    gate.release.add_permits(1);
    let (status, reply) = request.await.unwrap();
    assert_eq!(status, StatusCode::NOT_FOUND, "deleted snapshot: {reply}");
    let (status, reply) = f.call("GET", "/api/proxies", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reply["proxies"], json!([]));
}

#[tokio::test]
async fn probe_ports_returns_only_fixed_loopback_entries_in_configured_order() {
    let fixed = [
        (7897u16, "Clash Verge 混合端口（常见默认）"),
        (7890, "Clash 混合端口（常见默认）"),
        (7891, "Clash HTTP 端口"),
        (7899, "Clash Verge 备用端口"),
        (1080, "SOCKS5 通用端口"),
        (10808, "v2rayN SOCKS 端口"),
        (2080, "sing-box 混合端口"),
        (8889, "HTTP 代理通用端口"),
        (8118, "Privoxy HTTP 端口"),
    ];
    let mut owned = Vec::new();
    for (port, _) in fixed {
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)).await {
            owned.push((port, listener));
        }
    }
    let f = Fixture::new(vec![]);
    let (status, reply) = f
        .call(
            "GET",
            "/api/proxies/probe-ports?host=192.0.2.1&ports=1",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "probe ports: {reply}");
    let ports = reply["ports"]
        .as_array()
        .expect("ports must be an array, including when empty");
    let mut indices = Vec::new();
    for item in ports {
        let port = item["port"].as_u64().expect("numeric port");
        let index = fixed
            .iter()
            .position(|(p, _)| u64::from(*p) == port)
            .expect("only fixed ports may be returned");
        assert_eq!(item["url"], format!("http://127.0.0.1:{port}"));
        assert_eq!(item["label"], fixed[index].1);
        indices.push(index);
    }
    assert!(
        indices.windows(2).all(|w| w[0] < w[1]),
        "must preserve configured ordering with no duplicates: {reply}"
    );
    for (port, _listener) in &owned {
        assert!(
            ports.iter().any(|item| item["port"] == *port),
            "known listening port {port} was omitted"
        );
    }
}

#[cfg(not(windows))]
async fn child_run(mode: &str, envs: &[(&str, &str)]) {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["diagnostics_environment_child", "--exact", "--nocapture"])
        .env_clear()
        .env(CHILD_MODE, mode)
        .envs(envs.iter().copied());
    let output = tokio::task::spawn_blocking(move || {
        command.output().expect("spawn isolated diagnostics child")
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "isolated child failed: status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("DIAGNOSTICS_CHILD_CHECKED"),
        "child did not execute assertions"
    );
}

#[cfg(not(windows))]
#[tokio::test]
async fn system_proxy_env_precedence_trimming_validation_and_userinfo_redaction_are_isolated() {
    let keys = ["http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"];
    for first in 0..keys.len() {
        let mut envs = vec![
            ("DIAGNOSTICS_EXPECT_URL", "http://127.0.0.1:18080"),
            ("DIAGNOSTICS_EXPECT_ENABLED", "true"),
        ];
        for (index, key) in keys.iter().enumerate() {
            envs.push((*key, if index < first { " \t " } else if index == first { " \t http://PUBLIC-diagnostics-user:PUBLIC-diagnostics-password@127.0.0.1:18080 \n " } else { "http://127.0.0.1:18081" }));
        }
        envs.push(("https_proxy", "http://127.0.0.1:18082"));
        child_run("system", &envs).await;
    }
    child_run(
        "system",
        &[
            ("http_proxy", " \t "),
            ("HTTPS_PROXY", "http://127.0.0.1:18082"),
            ("DIAGNOSTICS_EXPECT_URL", ""),
            ("DIAGNOSTICS_EXPECT_ENABLED", "false"),
        ],
    )
    .await;
    child_run(
        "system",
        &[
            (
                "http_proxy",
                "ftp://PUBLIC-diagnostics-user:PUBLIC-diagnostics-password@127.0.0.1:18080",
            ),
            ("DIAGNOSTICS_EXPECT_URL", ""),
            ("DIAGNOSTICS_EXPECT_ENABLED", "false"),
        ],
    )
    .await;
}

#[cfg(not(windows))]
#[tokio::test]
async fn explicit_direct_ignores_ambient_proxy_environment_in_isolated_process() {
    let ambient = Mock::proxy().await;
    let url = ambient.proxy_url();
    child_run(
        "direct",
        &[
            ("http_proxy", &url),
            ("HTTP_PROXY", &url),
            ("all_proxy", &url),
            ("ALL_PROXY", &url),
            ("https_proxy", &url),
            ("HTTPS_PROXY", &url),
            ("NO_PROXY", ""),
            ("no_proxy", ""),
        ],
    )
    .await;
    assert!(
        ambient.hits().is_empty(),
        "explicit direct must ignore ambient proxy settings"
    );
}

#[cfg(not(windows))]
#[tokio::test]
async fn diagnostics_environment_child() {
    let Ok(mode) = std::env::var(CHILD_MODE) else {
        return;
    };
    match mode.as_str() {
        "system" => {
            let f = Fixture::new(vec![]);
            let (status, reply) = f.call("GET", "/api/proxies/system", None).await;
            assert_eq!(status, StatusCode::OK, "system proxy: {reply}");
            assert_eq!(
                reply["enabled"],
                std::env::var("DIAGNOSTICS_EXPECT_ENABLED").unwrap() == "true"
            );
            assert_eq!(
                reply["url"],
                std::env::var("DIAGNOSTICS_EXPECT_URL").unwrap()
            );
            assert_no_credentials(&reply, None);
            assert!(
                f.state
                    .setting("upstream_proxy")
                    .unwrap_or_default()
                    .is_empty(),
                "discovery must not silently enable outbound proxy routing"
            );
        }
        "direct" => {
            let target = Mock::target(vec![ip_wire()], None).await;
            let f = Fixture::new(vec![target.url()]);
            let (status, reply) = f
                .call("POST", "/api/proxies/test-url", Some(json!({"url": " "})))
                .await;
            assert_outcome(status, &reply, true, IP);
            assert_eq!(target.hits().len(), 1);
        }
        _ => panic!("unexpected diagnostics child mode"),
    }
    println!("DIAGNOSTICS_CHILD_CHECKED");
}
