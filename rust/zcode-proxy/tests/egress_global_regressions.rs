//! Independent Packet-A regressions for the global egress proxy (design:
//! .agents/state/rust-migration/egress-design.md, baseline 007f6fb).
//!
//! Covers `zcode_proxy::egress::{validate_proxy_url, display_proxy_url,
//! client_builder}` plus the /api/settings upstream_proxy surface and real
//! loopback HTTP forward-proxy transport for inference, management quota,
//! refresh-token exchange, OAuth code exchange, and install telemetry.
//! The egress module is absent while this file lands, so the target fails to
//! compile until the writer adds it; that is the intended baseline failure.
//! HTTPS-proxy TLS verification and a local SOCKS5 mock are explicit gaps:
//! the crate has no TLS-fixture or reqwest socks dependency today.

use std::{
    collections::{BTreeMap, VecDeque},
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Body,
    extract::{Request as IncomingRequest, State},
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::OptionalExtension;
use serde_json::{json, Value};
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tower::ServiceExt;
use zcode_core::AccountView;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    egress::{client_builder, display_proxy_url, validate_proxy_url},
    install_sequence::send_install_sequence,
    state::{AppState, Creds, UpstreamUrls},
    store,
    vault::Vault,
};

const HOST: &str = "localhost:8080";
const SESSION: &str = "PUBLIC-egress-session";
const VERSION: &str = "PUBLIC-egress-version";
const JWT: &str = "PUBLIC-egress-jwt";
const API_KEY: &str = "PUBLIC-egress-api-key";
const DEVICE: &str = "PUBLIC-egress-device-mid";
const PROXY_USER: &str = "egress-proxy-user";
const PROXY_PASS: &str = "egress-proxy-secret-PUBLIC";
const SSE_EGRESS: &str = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_egress\",\"model\":\"GLM-5.3\",\"usage\":{\"input_tokens\":11}}}\n\n\
event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n\
event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"EGRESS-PROXY-OK\"}}\n\n\
event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n\
event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":4}}\n\n\
event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
const CHILD_MODE: &str = "EGRESS_TEST_CHILD_MODE";

// ---- validation ----

#[test]
fn validate_proxy_url_accepts_supported_schemes_and_credentials() {
    for (label, url) in [
        ("http", "http://127.0.0.1:3128"),
        ("https", "https://egress-proxy.example.invalid:8443"),
        ("socks5", "socks5://127.0.0.1:1080"),
        ("socks5h", "socks5h://127.0.0.1:1080"),
        ("implicit-port", "http://127.0.0.1"),
        ("root-path", "http://127.0.0.1:3128/"),
        ("private-host", "http://10.1.2.3:3128"),
        ("ipv6-loopback", "http://[::1]:3128"),
        (
            "credentials",
            "http://egress-user:egress-secret@127.0.0.1:3128",
        ),
        (
            "percent-encoded-credentials",
            "http://egress-user%40domain:p%40ssword@127.0.0.1:3128",
        ),
        (
            "socks-credentials",
            "socks5h://egress-user:egress-secret@127.0.0.1:1080",
        ),
    ] {
        match validate_proxy_url(url) {
            Ok(Some(stored)) => assert_eq!(
                stored.contains('@'),
                url.contains('@'),
                "{label}: stored form must keep credentials for encrypted persistence"
            ),
            other => panic!("{label} must validate, got {other:?}"),
        }
    }
    for (label, url) in [("empty", ""), ("spaces", "   "), ("tab", "\t")] {
        assert_eq!(
            validate_proxy_url(url).ok(),
            Some(None),
            "{label} must clear the proxy"
        );
    }
}

#[test]
fn validate_proxy_url_rejects_invalid_proxy_targets() {
    for (label, url) in [
        ("scheme", "ftp://127.0.0.1:1"),
        ("scheme-socks4", "socks4://127.0.0.1:1"),
        ("host-empty", "http://:3128"),
        ("host-missing", "http:///proxy"),
        ("userinfo-without-host", "http://egress-user@:3128"),
        ("port-zero", "http://127.0.0.1:0"),
        ("port-invalid", "http://127.0.0.1:notaport"),
        ("port-range", "http://127.0.0.1:99999"),
        ("path", "http://127.0.0.1:3128/proxy"),
        ("query", "http://127.0.0.1:3128?x=1"),
        ("fragment", "http://127.0.0.1:3128#f"),
        ("unparseable", "not a url"),
    ] {
        assert!(validate_proxy_url(url).is_err(), "{label} must be rejected");
    }
}

#[test]
fn display_proxy_url_strips_all_userinfo() {
    assert_eq!(
        display_proxy_url("http://egress-user:egress-secret@127.0.0.1:3128").unwrap(),
        "http://127.0.0.1:3128"
    );
    assert_eq!(
        display_proxy_url("socks5h://egress-user@127.0.0.1:1080").unwrap(),
        "socks5h://127.0.0.1:1080"
    );
    assert_eq!(
        display_proxy_url("http://127.0.0.1:3128").unwrap(),
        "http://127.0.0.1:3128"
    );
    let shown = display_proxy_url("http://u:egress-secret@egress-host:1").unwrap();
    assert!(
        !shown.contains("egress-secret"),
        "display leaked the secret"
    );
    assert!(!shown.contains('@'), "display kept userinfo: {shown}");
    assert!(
        display_proxy_url("http://127.0.0.1:99999").is_err(),
        "display of an invalid proxy must fail closed"
    );
}

// ---- /api/settings surface ----

struct SettingsFixture {
    state: Arc<AppState>,
}

impl SettingsFixture {
    fn new() -> Self {
        let state = Arc::new(AppState::new(
            String::new(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
        ));
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        Self { state }
    }

    async fn put(&self, body: Value) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("PUT")
            .uri("/api/settings")
            .header("host", HOST)
            .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        read_json(
            build_router(self.state.clone())
                .oneshot(request)
                .await
                .unwrap(),
        )
        .await
    }

    async fn get(&self) -> Value {
        let request = Request::builder()
            .method("GET")
            .uri("/api/settings")
            .header("host", HOST)
            .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
            .body(Body::empty())
            .unwrap();
        let (status, body) = read_json(
            build_router(self.state.clone())
                .oneshot(request)
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "GET /api/settings body={body}");
        body
    }

    fn sql(&self, sql: &str) {
        self.state.db.lock().unwrap().execute_batch(sql).unwrap();
    }

    fn seed_setting(&self, key: &str, value: &str) {
        self.state
            .db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO settings(key, value) VALUES(?1, ?2)",
                [key, value],
            )
            .unwrap();
        self.state
            .settings
            .lock()
            .unwrap()
            .insert(key.into(), value.into());
    }

    fn stored_settings(&self) -> BTreeMap<String, String> {
        let db = self.state.db.lock().unwrap();
        let mut stmt = db
            .prepare("SELECT key, value FROM settings ORDER BY key")
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    fn memory_settings(&self) -> BTreeMap<String, String> {
        self.state
            .settings
            .lock()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    fn stored_proxy_row(&self) -> Option<String> {
        self.state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT value FROM settings WHERE key='upstream_proxy'",
                [],
                |row| row.get(0),
            )
            .optional()
            .unwrap()
    }
}

const AUTHED_PROXY: &str = "http://egress-user:egress-secret-PUBLIC@127.0.0.1:3128";
const STRIPPED_PROXY: &str = "http://127.0.0.1:3128";

#[tokio::test]
async fn upstream_proxy_roundtrip_masks_credentials_and_encrypts_at_rest() {
    let f = SettingsFixture::new();
    let (status, reply) = f.put(json!({"upstream_proxy": AUTHED_PROXY})).await;
    assert_eq!(status, StatusCode::OK, "reply={reply}");
    let updated: Vec<&str> = reply["updated"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert!(
        updated.contains(&"upstream_proxy"),
        "PUT must report upstream_proxy updated: {reply}"
    );
    let body = f.get().await;
    assert_eq!(
        body["upstream_proxy"],
        json!(STRIPPED_PROXY),
        "GET body={body}"
    );
    assert_eq!(
        body["upstream_proxy_has_auth"],
        json!(true),
        "GET body={body}"
    );
    assert!(
        !body.to_string().contains(PROXY_PASS),
        "GET leaked proxy credentials"
    );
    let row = f.stored_proxy_row().expect("encrypted proxy row");
    assert!(
        row.starts_with("vault1:"),
        "upstream_proxy must persist through sensitive_setting encryption"
    );
    assert!(!row.contains(PROXY_PASS), "raw row leaked credentials");
    assert_eq!(
        f.state.vault.decrypt(&row).unwrap(),
        AUTHED_PROXY,
        "stored ciphertext must preserve the secret for runtime use"
    );
    assert_eq!(
        f.state.setting("upstream_proxy").as_deref(),
        Some(AUTHED_PROXY),
        "runtime mirror must hold the full authenticated URL"
    );
}

#[tokio::test]
async fn masked_upstream_proxy_put_preserves_stored_secret() {
    let f = SettingsFixture::new();
    let (status, reply) = f.put(json!({"upstream_proxy": AUTHED_PROXY})).await;
    assert_eq!(status, StatusCode::OK, "reply={reply}");
    let masked = f.get().await["upstream_proxy"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(masked, STRIPPED_PROXY);
    let (status, reply) = f.put(json!({"upstream_proxy": masked})).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "masked roundtrip PUT must be accepted: {reply}"
    );
    let body = f.get().await;
    assert_eq!(body["upstream_proxy"], json!(STRIPPED_PROXY));
    assert_eq!(body["upstream_proxy_has_auth"], json!(true));
    let row = f.stored_proxy_row().expect("proxy row");
    assert_eq!(
        f.state.vault.decrypt(&row).unwrap(),
        AUTHED_PROXY,
        "masked roundtrip must keep the original credentials"
    );
    assert_eq!(
        f.state.setting("upstream_proxy").as_deref(),
        Some(AUTHED_PROXY)
    );
}

#[tokio::test]
async fn empty_upstream_proxy_clears_configuration() {
    let f = SettingsFixture::new();
    for (label, clear_value) in [("empty", ""), ("whitespace", "   ")] {
        let (status, reply) = f.put(json!({"upstream_proxy": AUTHED_PROXY})).await;
        assert_eq!(status, StatusCode::OK, "reply={reply}");
        let (status, reply) = f.put(json!({"upstream_proxy": clear_value})).await;
        assert_eq!(status, StatusCode::OK, "{label} clear failed: {reply}");
        assert!(
            f.state
                .setting("upstream_proxy")
                .is_none_or(|value| value.is_empty()),
            "{label} clear left a configured proxy"
        );
        let row = f.stored_proxy_row();
        assert!(
            row.as_deref().is_none_or(str::is_empty),
            "{label} clear left a stored proxy"
        );
        let body = f.get().await;
        assert!(
            body.get("upstream_proxy")
                .is_none_or(|value| value == &json!("")),
            "{label} clear still advertises a proxy: {body}"
        );
        assert!(
            body.get("upstream_proxy_has_auth")
                .is_none_or(|value| value == &json!(false)),
            "{label} clear still reports auth: {body}"
        );
        assert!(!body.to_string().contains(PROXY_PASS));
    }
}

#[tokio::test]
async fn new_authenticated_upstream_proxy_replaces_previous_secret() {
    let f = SettingsFixture::new();
    let replacement = "http://egress-user-two:egress-secret-two@127.0.0.2:3128";
    let (status, reply) = f.put(json!({"upstream_proxy": AUTHED_PROXY})).await;
    assert_eq!(status, StatusCode::OK, "reply={reply}");
    let (status, reply) = f.put(json!({"upstream_proxy": replacement})).await;
    assert_eq!(status, StatusCode::OK, "reply={reply}");
    let body = f.get().await;
    assert_eq!(body["upstream_proxy"], json!("http://127.0.0.2:3128"));
    assert_eq!(body["upstream_proxy_has_auth"], json!(true));
    assert!(!body.to_string().contains(PROXY_PASS));
    let row = f.stored_proxy_row().expect("proxy row");
    let decrypted = f.state.vault.decrypt(&row).unwrap();
    assert_eq!(decrypted, replacement);
    let parsed = reqwest::Url::parse(&decrypted).unwrap();
    assert_eq!(
        parsed.password(),
        Some("egress-secret-two"),
        "stored password must be the replacement secret"
    );
    assert_ne!(
        parsed.password(),
        Some(PROXY_PASS),
        "old secret survived the replacement"
    );
    assert_eq!(
        f.state.setting("upstream_proxy").as_deref(),
        Some(replacement)
    );
}

#[tokio::test]
async fn invalid_upstream_proxy_rejects_whole_batch_without_echo() {
    let f = SettingsFixture::new();
    f.seed_setting("gateway_paused", "0");
    for (label, bad) in [
        ("port-range", "http://127.0.0.1:99999"),
        ("scheme", "ftp://127.0.0.1:1"),
        ("path", "http://127.0.0.1:1/proxy"),
        ("query", "http://127.0.0.1:1?x=1"),
        ("fragment", "http://127.0.0.1:1#f"),
        (
            "credential-leak-candidate",
            "http://egress-leak-user:egress-leak-secret@127.0.0.1:0",
        ),
    ] {
        let before_db = f.stored_settings();
        let before_memory = f.memory_settings();
        let (status, reply) = f
            .put(json!({"gateway_paused": "1", "upstream_proxy": bad}))
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{label} must reject the batch, reply={reply}"
        );
        assert_eq!(
            f.stored_settings(),
            before_db,
            "{label}: rejected batch must not touch SQLite"
        );
        assert_eq!(
            f.memory_settings(),
            before_memory,
            "{label}: rejected batch must not touch the mirror"
        );
        let text = reply.to_string();
        assert!(
            !text.contains("egress-leak-secret"),
            "{label} echoed the password"
        );
        assert!(
            !text.contains("egress-leak-user"),
            "{label} echoed the user"
        );
        assert!(!text.contains("99999"), "{label} echoed the URL");
    }
}

#[tokio::test]
async fn upstream_proxy_storage_failure_rolls_back_whole_batch() {
    let f = SettingsFixture::new();
    f.seed_setting("gateway_paused", "0");
    f.sql(
        "CREATE TRIGGER fail_proxy_insert BEFORE INSERT ON settings
         WHEN NEW.key = 'upstream_proxy'
         BEGIN SELECT RAISE(FAIL, 'PUBLIC egress injected insert failure'); END;
         CREATE TRIGGER fail_proxy_update BEFORE UPDATE ON settings
         WHEN NEW.key = 'upstream_proxy'
         BEGIN SELECT RAISE(FAIL, 'PUBLIC egress injected update failure'); END;",
    );
    let before_db = f.stored_settings();
    let before_memory = f.memory_settings();
    let (status, reply) = f
        .put(json!({"upstream_proxy": AUTHED_PROXY, "gateway_paused": "1"}))
        .await;
    assert!(
        status.is_server_error(),
        "trigger failure must surface as 5xx, got {status} reply={reply}"
    );
    assert_eq!(
        f.stored_settings(),
        before_db,
        "failed batch must roll back SQLite"
    );
    assert_eq!(
        f.memory_settings(),
        before_memory,
        "failed batch must not publish to the mirror"
    );
    assert!(
        !reply.to_string().contains(PROXY_PASS),
        "failure leaked the secret"
    );
}

// ---- runtime client builder ----

#[tokio::test]
async fn client_builder_without_proxy_serves_direct_requests() {
    let target = TargetMock::start().await;
    target.push(StatusCode::OK, json!({"code": 0}));
    let state = AppState::new(
        String::new(),
        UpstreamUrls {
            zai: "http://127.0.0.1:1/unused".into(),
            zai_fallback: "http://127.0.0.1:1/unused".into(),
        },
    );
    let client = client_builder(&state, None)
        .expect("direct builder")
        .build()
        .expect("client");
    let response = client
        .get(format!("{}/direct-probe", target.base))
        .send()
        .await
        .expect("direct request");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(target.seen().len(), 1);
}

#[tokio::test]
async fn client_builder_fails_closed_on_invalid_stored_proxy() {
    let state = AppState::new(
        String::new(),
        UpstreamUrls {
            zai: "http://127.0.0.1:1/unused".into(),
            zai_fallback: "http://127.0.0.1:1/unused".into(),
        },
    );
    state
        .persist_settings(&[(
            "upstream_proxy",
            "http://egress-user:egress-secret@127.0.0.1:0",
        )])
        .unwrap();
    let error = client_builder(&state, None)
        .expect_err("invalid stored proxy must fail closed, never fall back to direct");
    let message = error.to_string();
    assert!(
        !message.contains("egress-secret"),
        "error leaked the password: {message}"
    );
    assert!(
        !message.contains("127.0.0.1"),
        "error leaked the URL host: {message}"
    );
}

// ---- shared loopback mocks ----

#[derive(Debug)]
struct Script {
    steps: Mutex<VecDeque<(StatusCode, Value)>>,
    seen: Mutex<Vec<(String, HeaderMap)>>,
}

/// Upstream target mock (axum) recording every request; scripts JSON responses
/// and serves one SSE inference route.
struct TargetMock {
    base: String,
    script: Arc<Script>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TargetMock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TargetMock {
    async fn start() -> Self {
        async fn serve_json(
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
                .unwrap_or((StatusCode::INTERNAL_SERVER_ERROR, json!({"code": 500})));
            (status, Json(body))
        }
        async fn serve_sse(
            State(script): State<Arc<Script>>,
            request: IncomingRequest,
        ) -> Response {
            script
                .seen
                .lock()
                .unwrap()
                .push((request.uri().to_string(), request.headers().clone()));
            ([("content-type", "text/event-stream")], SSE_EGRESS).into_response()
        }
        let script = Arc::new(Script {
            steps: Mutex::new(VecDeque::new()),
            seen: Mutex::new(Vec::new()),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .fallback(serve_json)
            .route("/sse-upstream", post(serve_sse))
            .with_state(script.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { base, script, task }
    }

    fn push(&self, status: StatusCode, body: Value) {
        self.script.steps.lock().unwrap().push_back((status, body));
    }

    fn seen(&self) -> Vec<(String, HeaderMap)> {
        self.script.seen.lock().unwrap().clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProxyObservation {
    method: String,
    target: String,
    proxy_authorization: Option<String>,
}

struct RequestHead {
    request_line: String,
    headers: Vec<(String, String)>,
    rest: Vec<u8>,
}

/// Real loopback HTTP forward proxy: accepts absolute-form requests, enforces
/// optional Basic proxy auth, tunnels to the target, and never forwards
/// Proxy-Authorization upstream.
struct ForwardProxy {
    authority: String,
    expected_basic: String,
    observations: Arc<Mutex<Vec<ProxyObservation>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ForwardProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl ForwardProxy {
    async fn start(user: &str, pass: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let expected_basic = format!("Basic {}", STANDARD.encode(format!("{user}:{pass}")));
        let observations = Arc::new(Mutex::new(Vec::new()));
        let gate = expected_basic.clone();
        let log = observations.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let gate = gate.clone();
                let log = log.clone();
                tokio::spawn(async move {
                    serve_proxy_connection(stream, Some(gate), log).await;
                });
            }
        });
        Self {
            authority,
            expected_basic,
            observations,
            task,
        }
    }

    fn url(&self, user: &str, pass: &str) -> String {
        format!("http://{user}:{pass}@{}", self.authority)
    }

    fn observations(&self) -> Vec<ProxyObservation> {
        self.observations.lock().unwrap().clone()
    }
}

async fn read_head(stream: &mut TcpStream) -> Option<RequestHead> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let text = String::from_utf8_lossy(&buffer[..position]).to_string();
            let mut lines = text.split("\r\n");
            let request_line = lines.next().unwrap_or_default().to_string();
            let headers = lines
                .filter_map(|line| {
                    line.split_once(':').map(|(name, value)| {
                        (name.trim().to_ascii_lowercase(), value.trim().to_string())
                    })
                })
                .collect();
            return Some(RequestHead {
                request_line,
                headers,
                rest: buffer[position + 4..].to_vec(),
            });
        }
        if buffer.len() > 65536 {
            return None;
        }
    }
}

async fn serve_proxy_connection(
    mut client: TcpStream,
    expected_basic: Option<String>,
    log: Arc<Mutex<Vec<ProxyObservation>>>,
) {
    let head = match tokio::time::timeout(Duration::from_secs(10), read_head(&mut client)).await {
        Ok(Some(head)) => head,
        _ => return,
    };
    let mut parts = head.request_line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        let _ = client
            .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n")
            .await;
        return;
    };
    let method = method.to_string();
    let target = target.to_string();
    let proxy_authorization = head
        .headers
        .iter()
        .find(|(name, _)| name == "proxy-authorization")
        .map(|(_, value)| value.clone());
    log.lock().unwrap().push(ProxyObservation {
        proxy_authorization: proxy_authorization.clone(),
        method: method.clone(),
        target: target.clone(),
    });
    if let Some(expected) = expected_basic.as_deref() {
        if proxy_authorization.as_deref() != Some(expected) {
            let _ = client
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nproxy-authenticate: Basic\r\ncontent-length: 0\r\n\r\n",
                )
                .await;
            return;
        }
    }
    let Ok(url) = reqwest::Url::parse(&target) else {
        let _ = client
            .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n")
            .await;
        return;
    };
    let Some(host) = url.host_str().map(str::to_string) else {
        return;
    };
    let port = url.port().unwrap_or(80);
    let mut upstream = match tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        _ => {
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n")
                .await;
            return;
        }
    };
    let origin = match url.query() {
        Some(query) => format!("{}?{}", url.path(), query),
        None => url.path().to_string(),
    };
    let mut forwarded = format!("{method} {origin} HTTP/1.1\r\n");
    for (name, value) in &head.headers {
        if name == "proxy-authorization" || name == "proxy-connection" {
            continue;
        }
        forwarded.push_str(&format!("{name}: {value}\r\n"));
    }
    forwarded.push_str("\r\n");
    if upstream.write_all(forwarded.as_bytes()).await.is_err() {
        return;
    }
    if !head.rest.is_empty() && upstream.write_all(&head.rest).await.is_err() {
        return;
    }
    let _ = tokio::time::timeout(
        Duration::from_secs(30),
        copy_bidirectional(&mut client, &mut upstream),
    )
    .await;
}

fn assert_target_headers_clean(seen: &[(String, HeaderMap)], proxy_basic: &str) {
    for (uri, headers) in seen {
        assert!(
            headers.get("proxy-authorization").is_none(),
            "Proxy-Authorization forwarded to the upstream at {uri}"
        );
        for (name, value) in headers {
            let value = value.to_str().unwrap_or("");
            assert_ne!(
                value, proxy_basic,
                "proxy Basic credentials reached the upstream as {name} at {uri}"
            );
            assert!(
                !value.contains(PROXY_PASS),
                "proxy password material reached the upstream as {name} at {uri}"
            );
        }
    }
}

// ---- transport fixtures ----

fn apply_loopback_urls(state: &mut AppState, target_base: &str) {
    state.management.billing_base = format!("{target_base}/api/v1/zcode-plan");
    state.management.quota_limit = format!("{target_base}/api/monitor/usage/quota/limit");
    state.management.subscription = format!("{target_base}/api/biz/subscription/list");
    state.management.oauth_token = format!("{target_base}/api/v1/oauth/token");
    state.management.app_version = VERSION.into();
    state.install_urls.client_configs = format!("{target_base}/api/v1/client/configs");
    state.install_urls.event_report = format!("{target_base}/api/v1/event/report");
}

fn unused_upstream() -> UpstreamUrls {
    UpstreamUrls {
        zai: "http://127.0.0.1:1/unused".into(),
        zai_fallback: "http://127.0.0.1:1/unused".into(),
    }
}

fn engine_state(proxy_url: &str, sse_url: &str) -> Arc<AppState> {
    let state = AppState::new(
        "sk-egress-root".into(),
        UpstreamUrls {
            zai: sse_url.into(),
            zai_fallback: sse_url.into(),
        },
    );
    state.accounts.lock().unwrap().push(AccountView {
        id: 1,
        provider: "zai".into(),
        enabled: true,
        status: "active".into(),
        zcode_jwt: JWT.into(),
        api_key: API_KEY.into(),
        paid_fallback: true,
        ..Default::default()
    });
    state.creds.lock().unwrap().insert(
        1,
        Creds {
            zcode_jwt: JWT.into(),
            api_key: API_KEY.into(),
        },
    );
    state
        .persist_settings(&[("upstream_proxy", proxy_url)])
        .unwrap();
    Arc::new(state)
}

fn account_state(
    proxy_url: &str,
    target_base: &str,
    jwt: &str,
    key: &str,
    refresh: Option<&str>,
    user_info: &str,
) -> (Arc<AppState>, i64) {
    let db = store::open(":memory:");
    let vault = Vault::from_secret("PUBLIC egress fixture seed").unwrap();
    let id = store::insert_account_encrypted(
        &db,
        &vault,
        &AccountView {
            email: "egress@example.invalid".into(),
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
    if let Some(refresh) = refresh {
        db.execute(
            "UPDATE accounts SET refresh_token=?1 WHERE id=?2",
            rusqlite::params![refresh, id],
        )
        .unwrap();
    }
    if !user_info.is_empty() {
        db.execute(
            "UPDATE accounts SET user_info=?1 WHERE id=?2",
            rusqlite::params![user_info, id],
        )
        .unwrap();
    }
    let mut state =
        AppState::try_from_db_with_vault(String::new(), unused_upstream(), db, vault).unwrap();
    apply_loopback_urls(&mut state, target_base);
    state
        .sessions
        .lock()
        .unwrap()
        .insert(SESSION.into(), now_secs() + 3600);
    state
        .persist_settings(&[("upstream_proxy", proxy_url)])
        .unwrap();
    (Arc::new(state), id)
}

async fn read_json(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn admin_call(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", HOST)
        .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
        .header("origin", format!("http://{HOST}"));
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let body = match body {
        Some(value) => Body::from(value.to_string()),
        None => Body::empty(),
    };
    build_router(state.clone())
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap()
}

async fn inference(state: &Arc<AppState>) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("x-api-key", "sk-egress-root")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"model":"glm-5.3","stream":false,"messages":[{"role":"user","content":"hi"}]}"#
                .to_string(),
        ))
        .unwrap();
    read_json(build_router(state.clone()).oneshot(request).await.unwrap()).await
}

fn billing_body() -> Value {
    json!({"code":0,"data":{"plans":[{"plan_id":"pro","status":"active",
        "expireTime":"2096-12-31 23:59"}],"balances":[{"plan_id":"pro",
        "total_units":100,"remaining_units":75,"period_end":3976283040_i64}]}})
}

// ---- transport regressions ----

#[tokio::test]
async fn inference_egress_routes_through_global_proxy_with_proxy_auth() {
    let target = TargetMock::start().await;
    let proxy = ForwardProxy::start(PROXY_USER, PROXY_PASS).await;
    let sse_url = format!("{}/sse-upstream", target.base);
    let state = engine_state(&proxy.url(PROXY_USER, PROXY_PASS), &sse_url);
    let (status, body) = inference(&state).await;
    assert_eq!(status, StatusCode::OK, "proxied inference body={body}");
    assert_eq!(body["content"][0]["text"], "EGRESS-PROXY-OK");
    let observations = proxy.observations();
    assert_eq!(observations.len(), 1, "observations={observations:?}");
    assert_eq!(observations[0].method, "POST");
    assert_eq!(
        observations[0].target, sse_url,
        "absolute-form target mismatch"
    );
    assert_eq!(
        observations[0].proxy_authorization.as_deref(),
        Some(proxy.expected_basic.as_str()),
        "proxy credentials from the URL must reach the proxy"
    );
    let seen = target.seen();
    assert_eq!(
        seen.len(),
        1,
        "request must tunnel to the target exactly once"
    );
    let bearer = format!("Bearer {JWT}");
    assert_eq!(
        seen[0]
            .1
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some(bearer.as_str()),
        "upstream Authorization must carry the account JWT"
    );
    assert_target_headers_clean(&seen, &proxy.expected_basic);

    state.persist_settings(&[("upstream_proxy", "")]).unwrap();
    let (status, body) = inference(&state).await;
    assert_eq!(status, StatusCode::OK, "post-clear body={body}");
    assert_eq!(
        proxy.observations().len(),
        1,
        "cleared proxy must not intercept later requests"
    );
    assert_eq!(target.seen().len(), 2, "cleared proxy must go direct");
}

#[tokio::test]
async fn management_quota_egress_routes_through_global_proxy() {
    let target = TargetMock::start().await;
    let proxy = ForwardProxy::start(PROXY_USER, PROXY_PASS).await;
    let (state, id) = account_state(
        &proxy.url(PROXY_USER, PROXY_PASS),
        &target.base,
        JWT,
        API_KEY,
        None,
        "",
    );
    target.push(StatusCode::OK, billing_body());
    let response = admin_call(&state, "POST", &format!("/api/accounts/{id}/refresh"), None).await;
    let (status, body) = read_json(response).await;
    assert_eq!(status, StatusCode::OK, "quota refresh body={body}");
    assert_eq!(body["success"], true);
    let observations = proxy.observations();
    assert_eq!(observations.len(), 1, "observations={observations:?}");
    let expected = format!(
        "{}/api/v1/zcode-plan/billing/balance?app_version={VERSION}",
        target.base
    );
    assert_eq!(observations[0].method, "GET");
    assert_eq!(observations[0].target, expected);
    assert_eq!(
        observations[0].proxy_authorization.as_deref(),
        Some(proxy.expected_basic.as_str())
    );
    let seen = target.seen();
    assert_eq!(seen.len(), 1);
    let bearer = format!("Bearer {JWT}");
    assert_eq!(
        seen[0]
            .1
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some(bearer.as_str())
    );
    assert_target_headers_clean(&seen, &proxy.expected_basic);
}

#[tokio::test]
async fn refresh_token_exchange_egress_routes_through_global_proxy() {
    let target = TargetMock::start().await;
    let proxy = ForwardProxy::start(PROXY_USER, PROXY_PASS).await;
    let (state, id) = account_state(
        &proxy.url(PROXY_USER, PROXY_PASS),
        &target.base,
        JWT,
        "",
        Some("PUBLIC-egress-refresh"),
        "",
    );
    target.push(StatusCode::UNAUTHORIZED, json!({"code": 401}));
    target.push(
        StatusCode::OK,
        json!({"code":0,"data":{"token":"PUBLIC-egress-rotated-jwt",
            "zai":{"access_token":"PUBLIC-egress-access","refresh_token":"PUBLIC-egress-rotated-refresh"}}}),
    );
    let response = admin_call(&state, "POST", &format!("/api/accounts/{id}/refresh"), None).await;
    let (status, body) = read_json(response).await;
    assert_eq!(status, StatusCode::OK, "refresh body={body}");
    assert_eq!(body["success"], true);
    let observations = proxy.observations();
    assert_eq!(observations.len(), 2, "observations={observations:?}");
    let exchange_url = format!("{}/api/v1/oauth/token", target.base);
    let exchange = observations
        .iter()
        .find(|observation| observation.method == "POST" && observation.target == exchange_url)
        .unwrap_or_else(|| panic!("token exchange never reached the proxy: {observations:?}"));
    assert_eq!(
        exchange.proxy_authorization.as_deref(),
        Some(proxy.expected_basic.as_str())
    );
    let seen = target.seen();
    assert_eq!(seen.len(), 2);
    let exchange_seen = seen
        .iter()
        .find(|(uri, _)| uri == "/api/v1/oauth/token")
        .expect("exchange request must tunnel to the target");
    assert!(
        exchange_seen.1.get("authorization").is_none(),
        "token exchange must not forward proxy credentials as Authorization"
    );
    assert_target_headers_clean(&seen, &proxy.expected_basic);
    assert_eq!(
        state.accounts.lock().unwrap()[0].zcode_jwt,
        "PUBLIC-egress-rotated-jwt",
        "rotated token must publish"
    );
}

#[tokio::test]
async fn oauth_code_exchange_egress_routes_through_global_proxy() {
    let target = TargetMock::start().await;
    let proxy = ForwardProxy::start(PROXY_USER, PROXY_PASS).await;
    let (state, _id) = account_state(
        &proxy.url(PROXY_USER, PROXY_PASS),
        &target.base,
        "",
        "",
        None,
        "",
    );
    target.push(
        StatusCode::OK,
        json!({"code":0,"data":{"token":"PUBLIC-egress-oauth-jwt",
            "zai":{"refresh_token":"PUBLIC-egress-oauth-refresh"},
            "user":{"email":"egress-oauth@example.invalid","user_id":"PUBLIC-egress-oauth-user"}}}),
    );
    let response = admin_call(&state, "POST", "/api/accounts/oauth/start", Some(json!({}))).await;
    let (status, body) = read_json(response).await;
    assert_eq!(status, StatusCode::OK, "oauth start body={body}");
    let flow_state = body["state"].as_str().unwrap().to_string();
    let response = admin_call(
        &state,
        "GET",
        &format!("/oauth/callback?code=PUBLIC-egress-code&state={flow_state}"),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&bytes);
    assert!(
        html.contains("Authorization complete"),
        "callback did not complete the OAuth exchange: {html}"
    );
    let observations = proxy.observations();
    assert_eq!(observations.len(), 1, "observations={observations:?}");
    let exchange_url = format!("{}/api/v1/oauth/token", target.base);
    assert_eq!(observations[0].method, "POST");
    assert_eq!(observations[0].target, exchange_url);
    assert_eq!(
        observations[0].proxy_authorization.as_deref(),
        Some(proxy.expected_basic.as_str())
    );
    let seen = target.seen();
    assert_eq!(seen.len(), 1);
    assert!(
        seen[0].1.get("authorization").is_none(),
        "OAuth exchange must not forward proxy credentials as Authorization"
    );
    assert_target_headers_clean(&seen, &proxy.expected_basic);
    let accounts = state.accounts.lock().unwrap();
    let imported = accounts
        .iter()
        .find(|account| account.email == "egress-oauth@example.invalid")
        .expect("OAuth account must import");
    assert_eq!(imported.zcode_jwt, "PUBLIC-egress-oauth-jwt");
}

#[tokio::test]
async fn install_telemetry_egress_routes_through_global_proxy() {
    let target = TargetMock::start().await;
    let proxy = ForwardProxy::start(PROXY_USER, PROXY_PASS).await;
    let (state, id) = account_state(
        &proxy.url(PROXY_USER, PROXY_PASS),
        &target.base,
        JWT,
        API_KEY,
        None,
        r#"{"user_id":"PUBLIC-egress-install-user"}"#,
    );
    for _ in 0..3 {
        target.push(StatusCode::OK, json!({"code": 0}));
    }
    let report = send_install_sequence(&state, id).await.unwrap();
    assert_eq!(report.attempted, 3);
    assert_eq!(report.succeeded, 3, "install telemetry must succeed");
    assert!(!report.skipped);
    let observations = proxy.observations();
    assert_eq!(observations.len(), 3, "observations={observations:?}");
    assert_eq!(observations[0].method, "GET");
    assert_eq!(
        observations[0].target,
        format!(
            "{}/api/v1/client/configs?app_version={VERSION}",
            target.base
        )
    );
    for observation in &observations[1..] {
        assert_eq!(observation.method, "POST");
        assert_eq!(
            observation.target,
            format!("{}/api/v1/event/report", target.base)
        );
        assert_eq!(
            observation.proxy_authorization.as_deref(),
            Some(proxy.expected_basic.as_str())
        );
    }
    assert_eq!(
        observations[0].proxy_authorization.as_deref(),
        Some(proxy.expected_basic.as_str())
    );
    let seen = target.seen();
    assert_eq!(seen.len(), 3);
    let bearer = format!("Bearer {JWT}");
    for (uri, headers) in &seen[1..] {
        assert_eq!(
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some(bearer.as_str()),
            "event report at {uri} must carry the account JWT"
        );
    }
    assert_target_headers_clean(&seen, &proxy.expected_basic);
}

#[tokio::test]
async fn wrong_proxy_credentials_fail_closed_without_direct_fallback() {
    let target = TargetMock::start().await;
    let proxy = ForwardProxy::start(PROXY_USER, PROXY_PASS).await;
    let wrong_url = proxy.url(PROXY_USER, "WRONG-egress-secret");
    let state = engine_state(&wrong_url, &format!("{}/sse-upstream", target.base));
    let (status, body) = inference(&state).await;
    assert!(
        !status.is_success(),
        "rejected proxy credentials must fail the request, got {status} body={body}"
    );
    let observations = proxy.observations();
    assert!(!observations.is_empty(), "request must reach the proxy");
    let wrong_basic = format!(
        "Basic {}",
        STANDARD.encode(format!("{PROXY_USER}:WRONG-egress-secret"))
    );
    for observation in &observations {
        assert_eq!(
            observation.proxy_authorization.as_deref(),
            Some(wrong_basic.as_str()),
            "proxy auth must come from the configured URL"
        );
    }
    assert!(
        target.seen().is_empty(),
        "a 407 proxy must never fall back to a direct upstream connection"
    );
}

// ---- ambient proxy environment isolation (subprocess) ----

async fn child_run(envs: &[(&str, &str)]) -> std::process::Output {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["egress_ambient_child", "--exact", "--nocapture"])
        .env(CHILD_MODE, "1")
        .envs(envs.iter().copied());
    tokio::task::spawn_blocking(move || command.output().expect("spawn isolated child"))
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_egress_ignores_ambient_proxy_environment() {
    let target = TargetMock::start().await;
    target.push(StatusCode::OK, json!({"code": 0}));
    let dead = "http://127.0.0.1:1";
    let child_target = format!("{}/ambient-probe", target.base);
    let output = child_run(&[
        ("EGRESS_CHILD_TARGET", child_target.as_str()),
        ("HTTP_PROXY", dead),
        ("http_proxy", dead),
        ("HTTPS_PROXY", dead),
        ("https_proxy", dead),
        ("ALL_PROXY", "socks5://127.0.0.1:1"),
        ("all_proxy", "socks5://127.0.0.1:1"),
        ("NO_PROXY", "*"),
        ("no_proxy", "*"),
    ])
    .await;
    assert!(
        output.status.success(),
        "isolated child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("EGRESS_CHILD_DIRECT_OK"),
        "child did not complete the direct request"
    );
    assert_eq!(
        target.seen().len(),
        1,
        "ambient proxy env must not intercept"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn configured_proxy_wins_over_ambient_bypass_environment() {
    let target = TargetMock::start().await;
    target.push(StatusCode::OK, json!({"code": 0}));
    let proxy = ForwardProxy::start(PROXY_USER, PROXY_PASS).await;
    let dead = "http://127.0.0.1:1";
    let child_target = format!("{}/ambient-probe", target.base);
    let child_proxy = format!("{PROXY_USER}:{PROXY_PASS}@{}", proxy.authority);
    let output = child_run(&[
        ("EGRESS_CHILD_TARGET", child_target.as_str()),
        ("EGRESS_CHILD_PROXY", child_proxy.as_str()),
        ("HTTP_PROXY", dead),
        ("http_proxy", dead),
        ("HTTPS_PROXY", dead),
        ("https_proxy", dead),
        ("ALL_PROXY", "socks5://127.0.0.1:1"),
        ("all_proxy", "socks5://127.0.0.1:1"),
        ("NO_PROXY", "*"),
        ("no_proxy", "*"),
    ])
    .await;
    assert!(
        output.status.success(),
        "isolated child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("EGRESS_CHILD_PROXIED_OK"),
        "child did not complete the proxied request"
    );
    let observations = proxy.observations();
    assert_eq!(
        observations.len(),
        1,
        "NO_PROXY=* must not bypass the configured proxy: {observations:?}"
    );
    assert_eq!(
        observations[0].proxy_authorization.as_deref(),
        Some(proxy.expected_basic.as_str())
    );
    assert_eq!(target.seen().len(), 1);
}

#[tokio::test]
async fn egress_ambient_child() {
    if std::env::var(CHILD_MODE).is_err() {
        return;
    }
    let target = std::env::var("EGRESS_CHILD_TARGET").expect("child target");
    let state = AppState::new(String::new(), unused_upstream());
    if let Ok(proxy) = std::env::var("EGRESS_CHILD_PROXY") {
        state
            .persist_settings(&[("upstream_proxy", &format!("http://{proxy}"))])
            .unwrap();
    }
    let client = client_builder(&state, None)
        .expect("client builder")
        .build()
        .expect("client");
    let response = client
        .get(target.as_str())
        .send()
        .await
        .expect("request through the egress client");
    assert_eq!(response.status().as_u16(), 200, "child request failed");
    if state
        .setting("upstream_proxy")
        .is_some_and(|value| !value.is_empty())
    {
        println!("EGRESS_CHILD_PROXIED_OK");
    } else {
        println!("EGRESS_CHILD_DIRECT_OK");
    }
}
