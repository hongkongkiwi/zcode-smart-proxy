//! Independent regressions for group/default proxy nodes (design:
//! .agents/state/rust-migration/proxy-nodes-design.md, baseline 4e62795).
//!
//! Covers the session/Origin-gated /api/proxies CRUD surface (Go handler
//! parity for validation, id semantics, password encryption/masking, default
//! transaction atomicity) and `egress::client_builder` node resolution
//! (group -> default -> global -> direct) against real loopback HTTP proxies.
//! The routes and the proxy_nodes table are absent while this file lands, so
//! the targets fail until the writer adds them; that is the intended baseline
//! failure. Probe/test-url/system-port endpoints are a separate packet and
//! are intentionally not exercised.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tower::ServiceExt;
use zcode_core::AccountView;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    egress::client_builder,
    state::{AppState, UpstreamUrls},
    store,
    vault::Vault,
};

const HOST: &str = "localhost:8080";
const SESSION: &str = "PUBLIC-proxy-nodes-session";
const NODE_USER: &str = "node-proxy-user";
const NODE_PASS: &str = "node-proxy-secret-PUBLIC";
const FOREIGN_SEED: &str = "PUBLIC foreign node vault seed";
const ROUTING_SEED: &str = "PUBLIC proxy-nodes routing seed";
/// Go emits exactly these keys per node in handleListProxies (api_handlers.go);
/// "password" must never appear and no ciphertext may leak.
const PUBLIC_VIEW_KEYS: [&str; 18] = [
    "id",
    "name",
    "type",
    "host",
    "port",
    "username",
    "has_password",
    "password_broken",
    "is_default",
    "group_name",
    "enabled",
    "check_status",
    "check_latency",
    "check_ip",
    "check_msg",
    "check_at",
    "created_at",
    "updated_at",
];

fn unused_upstream() -> UpstreamUrls {
    UpstreamUrls {
        zai: "http://127.0.0.1:1/unused".into(),
        zai_fallback: "http://127.0.0.1:1/unused".into(),
    }
}

// ---- CRUD harness ----

struct NodesFixture {
    state: Arc<AppState>,
}

impl NodesFixture {
    fn new() -> Self {
        let state = Arc::new(AppState::new(String::new(), unused_upstream()));
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        Self { state }
    }

    async fn call(
        &self,
        method: &str,
        uri: &str,
        body: Option<Value>,
        origin: Option<&str>,
    ) -> (StatusCode, Value) {
        self.call_raw(method, uri, body.map(|v| v.to_string()), origin)
            .await
    }

    async fn call_raw(
        &self,
        method: &str,
        uri: &str,
        body: Option<String>,
        origin: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", HOST)
            .header("cookie", format!("{SESSION_COOKIE}={SESSION}"));
        if let Some(origin) = origin {
            builder = builder.header("origin", origin);
        }
        if let Some(body) = body {
            builder = builder.header("content-type", "application/json");
            let (status, value) = read_json(
                build_router(self.state.clone())
                    .oneshot(builder.body(Body::from(body)).unwrap())
                    .await
                    .unwrap(),
            )
            .await;
            return (status, value);
        }
        read_json(
            build_router(self.state.clone())
                .oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await
    }

    async fn create(&self, body: Value) -> i64 {
        let (status, reply) = self.call("POST", "/api/proxies", Some(body), None).await;
        assert_eq!(status, StatusCode::OK, "POST /api/proxies reply={reply}");
        reply["id"]
            .as_i64()
            .unwrap_or_else(|| panic!("no id: {reply}"))
    }

    async fn list(&self) -> Vec<Value> {
        let (status, body) = self.call("GET", "/api/proxies", None, None).await;
        assert_eq!(status, StatusCode::OK, "GET /api/proxies body={body}");
        body["proxies"]
            .as_array()
            .unwrap_or_else(|| panic!("proxies array missing: {body}"))
            .clone()
    }

    fn sql(&self, sql: &str) {
        self.state.db.lock().unwrap().execute_batch(sql).unwrap();
    }

    fn stored_password(&self, id: i64) -> Option<String> {
        self.state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT password FROM proxy_nodes WHERE id=?1",
                [id],
                |row| row.get(0),
            )
            .optional()
            .unwrap()
    }

    fn node_count(&self) -> i64 {
        self.state
            .db
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM proxy_nodes", [], |r| r.get(0))
            .unwrap()
    }

    fn default_flags(&self) -> Vec<(i64, bool)> {
        let db = self.state.db.lock().unwrap();
        let mut stmt = db
            .prepare("SELECT id, is_default FROM proxy_nodes ORDER BY id")
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get::<_, i64>(1)? == 1)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    fn seed_broken_password(&self, id: i64) -> String {
        let foreign = Vault::from_secret(FOREIGN_SEED).unwrap();
        let cipher = foreign.encrypt("PUBLIC foreign node password").unwrap();
        self.state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE proxy_nodes SET password=?1 WHERE id=?2",
                params![cipher, id],
            )
            .unwrap();
        cipher
    }
}

fn node_body(host: &str, port: i64, node_type: &str) -> Value {
    json!({
        "name": format!("node-{node_type}"),
        "type": node_type,
        "host": host,
        "port": port,
        "enabled": true,
    })
}

async fn read_json(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

// ---- session and Origin gating ----

#[tokio::test]
async fn proxies_routes_require_a_live_session() {
    let f = NodesFixture::new();
    for (method, uri) in [
        ("GET", "/api/proxies"),
        ("POST", "/api/proxies"),
        ("PUT", "/api/proxies/1"),
        ("DELETE", "/api/proxies/1"),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", HOST)
            .header("cookie", format!("{SESSION_COOKIE}=PUBLIC-expired-session"))
            .body(Body::empty())
            .unwrap();
        let (status, body) = read_json(
            build_router(f.state.clone())
                .oneshot(request)
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {uri} body={body}"
        );
    }
    assert_eq!(f.node_count(), 0, "rejected calls must not create rows");
}

#[tokio::test]
async fn proxies_writes_enforce_same_origin() {
    let f = NodesFixture::new();
    let evil = "http://evil.example.invalid";
    let (status, body) = f
        .call(
            "POST",
            "/api/proxies",
            Some(node_body("proxy.example.invalid", 1080, "socks5")),
            Some(evil),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "cross-origin POST body={body}"
    );
    let (status, body) = f.call("DELETE", "/api/proxies/1", None, Some(evil)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "cross-origin DELETE body={body}"
    );
    assert_eq!(f.node_count(), 0, "rejected writes must not create rows");
    let (status, reply) = f
        .call(
            "POST",
            "/api/proxies",
            Some(node_body("proxy.example.invalid", 1080, "socks5")),
            Some(&format!("http://{HOST}")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "matching origin body={reply}");
}

// ---- list shape and Go field parity ----

#[tokio::test]
async fn empty_proxy_list_is_an_empty_array() {
    let f = NodesFixture::new();
    let (status, body) = f.call("GET", "/api/proxies", None, None).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(
        body["proxies"],
        json!([]),
        "fresh list must be [], not null"
    );
}

#[tokio::test]
async fn list_matches_go_public_view_and_orders_by_id() {
    let f = NodesFixture::new();
    // Go json.Decode leaves an absent "enabled" bool at its zero value false
    // and SaveProxyNode inserts that value explicitly
    // (api_handlers.go handleSaveProxy, database_ops.go SaveProxyNode), so an
    // omitted enabled means disabled. Pinned from Go source, not invented.
    let first = f
        .create(json!({
            "name": "first", "type": "socks5",
            "host": "proxy.example.invalid", "port": 1080,
        }))
        .await;
    let second = f
        .create(node_body("default.example.invalid", 8443, "https"))
        .await;
    let nodes = f.list().await;
    let ids: Vec<i64> = nodes.iter().map(|n| n["id"].as_i64().unwrap()).collect();
    assert_eq!(ids, vec![first, second], "list must be ordered by id");
    for node in &nodes {
        let mut keys: Vec<&str> = node
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        let mut expected = PUBLIC_VIEW_KEYS.to_vec();
        expected.sort_unstable();
        assert_eq!(keys, expected, "public view keys must match Go exactly");
        assert!(node.get("password").is_none(), "password key leaked");
    }
    let (first_node, second_node) = (&nodes[0], &nodes[1]);
    assert_eq!(
        first_node["enabled"],
        json!(false),
        "omitted enabled is false"
    );
    assert_eq!(second_node["enabled"], json!(true));
    for node in [first_node, second_node] {
        assert_eq!(node["username"], json!(""));
        assert_eq!(node["group_name"], json!(""));
        assert_eq!(node["is_default"], json!(false));
        assert_eq!(node["has_password"], json!(false));
        assert_eq!(node["password_broken"], json!(false));
        assert_eq!(node["check_status"], json!(""));
        assert_eq!(node["check_latency"], json!(0));
        assert_eq!(node["check_ip"], json!(""));
        assert_eq!(node["check_msg"], json!(""));
        assert_eq!(node["check_at"], json!(""));
        assert!(
            !node["created_at"].as_str().unwrap_or("").is_empty(),
            "created_at must be populated"
        );
        assert!(
            !node["updated_at"].as_str().unwrap_or("").is_empty(),
            "updated_at must be populated"
        );
    }
}

// ---- validation ----

#[tokio::test]
async fn save_rejects_invalid_host_port_and_type_without_persisting() {
    let f = NodesFixture::new();
    let valid = node_body("proxy.example.invalid", 1080, "socks5");
    let mut cases: Vec<(&str, Value)> = Vec::new();
    for (label, host) in [
        ("empty", ""),
        ("scheme", "http://proxy.example.invalid"),
        ("path", "proxy.example.invalid/p"),
        ("query", "proxy.example.invalid?q=1"),
        ("fragment", "proxy.example.invalid#f"),
        ("userinfo", "user:pass@proxy.example.invalid"),
        ("whitespace", "proxy exam ple"),
        ("control", "proxy\texample"),
    ] {
        let mut body = valid.clone();
        body["host"] = json!(host);
        cases.push((label, body));
    }
    for (label, port) in [("zero", 0), ("negative", -1), ("range", 70000)] {
        let mut body = valid.clone();
        body["port"] = json!(port);
        cases.push((label, body));
    }
    for (label, node_type) in [
        ("missing", ""),
        ("socks4", "socks4"),
        ("socks5h", "socks5h"),
        ("case", "HTTP"),
    ] {
        let mut body = valid.clone();
        body["type"] = json!(node_type);
        cases.push((label, body));
    }
    for (label, body) in cases {
        let (status, reply) = f
            .call("POST", "/api/proxies", Some(body.clone()), None)
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{label} must be rejected, reply={reply}"
        );
        let (status, reply) = f.call("PUT", "/api/proxies/1", Some(body), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label} PUT reply={reply}");
    }
    let (status, reply) = f
        .call_raw("POST", "/api/proxies", Some("{not valid json".into()), None)
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "malformed body reply={reply}"
    );
    assert_eq!(f.node_count(), 0, "rejected saves must not persist rows");
}

#[tokio::test]
async fn save_accepts_boundary_ports_and_supported_types() {
    let f = NodesFixture::new();
    for body in [
        node_body("127.0.0.1", 1, "http"),
        node_body("proxy.example.invalid", 65535, "https"),
        node_body("127.0.0.1", 1080, "socks5"),
    ] {
        let (status, reply) = f.call("POST", "/api/proxies", Some(body), None).await;
        assert_eq!(status, StatusCode::OK, "reply={reply}");
    }
    assert_eq!(f.node_count(), 3);
}

// ---- id semantics ----

#[tokio::test]
async fn post_ignores_body_id() {
    let f = NodesFixture::new();
    let mut body = node_body("proxy.example.invalid", 1080, "socks5");
    body["id"] = json!(4242);
    let id = f.create(body).await;
    assert_ne!(id, 4242, "POST must not honor the body id");
    let (status, reply) = f
        .call(
            "PUT",
            "/api/proxies/4242",
            Some(node_body("other.example.invalid", 1080, "socks5")),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "reply={reply}");
    let nodes = f.list().await;
    assert_eq!(
        nodes.len(),
        1,
        "body id must not have created a second node"
    );
    assert_eq!(nodes[0]["id"], json!(id));
}

#[tokio::test]
async fn put_uses_path_id_and_rejects_malformed_or_missing_ids() {
    let f = NodesFixture::new();
    let first = f
        .create(node_body("first.example.invalid", 1080, "socks5"))
        .await;
    let second = f
        .create(node_body("second.example.invalid", 1080, "socks5"))
        .await;
    for malformed in ["abc", "12x"] {
        let (status, reply) = f
            .call(
                "PUT",
                &format!("/api/proxies/{malformed}"),
                Some(node_body("x.example.invalid", 1080, "socks5")),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{malformed} reply={reply}");
    }
    let (status, reply) = f
        .call(
            "PUT",
            "/api/proxies/999999",
            Some(node_body("x.example.invalid", 1080, "socks5")),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "missing node reply={reply}");
    let mut body = node_body("renamed.example.invalid", 1080, "socks5");
    body["id"] = json!(first);
    let (status, reply) = f
        .call("PUT", &format!("/api/proxies/{second}"), Some(body), None)
        .await;
    assert_eq!(status, StatusCode::OK, "path id must win, reply={reply}");
    let nodes = f.list().await;
    assert_eq!(
        nodes[0]["host"],
        json!("first.example.invalid"),
        "body id target"
    );
    assert_eq!(
        nodes[1]["host"],
        json!("renamed.example.invalid"),
        "path id target"
    );
}

#[tokio::test]
async fn delete_missing_node_still_succeeds_with_go_parity() {
    let f = NodesFixture::new();
    let id = f
        .create(node_body("proxy.example.invalid", 1080, "socks5"))
        .await;
    let (status, reply) = f
        .call("DELETE", &format!("/api/proxies/{id}"), None, None)
        .await;
    assert_eq!(status, StatusCode::OK, "reply={reply}");
    assert_eq!(reply["success"], json!(true));
    assert_eq!(f.node_count(), 0);
    let (status, reply) = f
        .call("DELETE", &format!("/api/proxies/{id}"), None, None)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "deleting a missing node must stay 200 (Go parity), reply={reply}"
    );
    assert_eq!(reply["success"], json!(true));
    let (status, reply) = f.call("DELETE", "/api/proxies/abc", None, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "reply={reply}");
}

// ---- password secrecy at rest and in views ----

#[tokio::test]
async fn node_password_is_encrypted_at_rest_and_masked_in_list() {
    let f = NodesFixture::new();
    let mut body = node_body("proxy.example.invalid", 1080, "socks5");
    body["username"] = json!("node-user");
    body["password"] = json!("node-secret-PUBLIC-1");
    let id = f.create(body).await;
    let nodes = f.list().await;
    assert_eq!(nodes[0]["has_password"], json!(true));
    assert_eq!(nodes[0]["password_broken"], json!(false));
    let text = serde_json::to_string(&nodes).unwrap();
    assert!(
        !text.contains("node-secret-PUBLIC-1"),
        "list leaked the password"
    );
    assert!(!text.contains("vault1:"), "list leaked ciphertext");
    let stored = f.stored_password(id).unwrap();
    assert!(
        stored.starts_with("vault1:"),
        "password must be vault encrypted"
    );
    assert!(!stored.contains("node-secret-PUBLIC-1"));
    assert_eq!(
        f.state.vault.decrypt(&stored).unwrap(),
        "node-secret-PUBLIC-1",
        "stored ciphertext must preserve the runtime secret"
    );
}

#[tokio::test]
async fn empty_password_on_put_preserves_exact_ciphertext() {
    let f = NodesFixture::new();
    let mut body = node_body("proxy.example.invalid", 1080, "socks5");
    body["password"] = json!("node-secret-PUBLIC-2");
    let id = f.create(body).await;
    let before = f.stored_password(id).unwrap();
    for (label, mut put) in [
        (
            "omitted",
            node_body("proxy.example.invalid", 1080, "socks5"),
        ),
        ("explicit-empty", {
            let mut b = node_body("proxy.example.invalid", 1080, "socks5");
            b["password"] = json!("");
            b
        }),
    ] {
        put["name"] = json!(format!("renamed-{label}"));
        let (status, reply) = f
            .call("PUT", &format!("/api/proxies/{id}"), Some(put), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{label} reply={reply}");
        assert_eq!(
            f.stored_password(id),
            Some(before.clone()),
            "{label} must keep the stored ciphertext byte-for-byte"
        );
        assert_eq!(
            f.state.vault.decrypt(&before).unwrap(),
            "node-secret-PUBLIC-2",
            "{label} must not damage the stored secret"
        );
    }
}

#[tokio::test]
async fn broken_ciphertext_is_flagged_preserved_and_repairable() {
    let f = NodesFixture::new();
    let mut body = node_body("proxy.example.invalid", 1080, "socks5");
    body["username"] = json!("node-user");
    let id = f.create(body).await;
    let broken_cipher = f.seed_broken_password(id);
    let nodes = f.list().await;
    // Go vaultDecryptOK returns "" for undecryptable rows, so the public view
    // reports has_password=false alongside password_broken=true.
    assert_eq!(
        nodes[0]["password_broken"],
        json!(true),
        "broken must be visible"
    );
    assert_eq!(
        nodes[0]["has_password"],
        json!(false),
        "Go parity on broken rows"
    );
    let mut keep = node_body("proxy.example.invalid", 1080, "socks5");
    keep["username"] = json!("node-user");
    keep["password"] = json!("");
    let (status, reply) = f
        .call("PUT", &format!("/api/proxies/{id}"), Some(keep), None)
        .await;
    assert_eq!(status, StatusCode::OK, "empty-password PUT reply={reply}");
    assert_eq!(
        f.stored_password(id),
        Some(broken_cipher.clone()),
        "undecryptable ciphertext must survive metadata updates byte-for-byte"
    );
    let nodes = f.list().await;
    assert_eq!(
        nodes[0]["password_broken"],
        json!(true),
        "still broken after keep"
    );
    let mut repair = node_body("proxy.example.invalid", 1080, "socks5");
    repair["username"] = json!("node-user");
    repair["password"] = json!("node-secret-PUBLIC-repaired");
    let (status, reply) = f
        .call("PUT", &format!("/api/proxies/{id}"), Some(repair), None)
        .await;
    assert_eq!(status, StatusCode::OK, "repair reply={reply}");
    let stored = f.stored_password(id).unwrap();
    assert_eq!(
        f.state.vault.decrypt(&stored).unwrap(),
        "node-secret-PUBLIC-repaired",
        "replacement password must be re-encrypted"
    );
    let nodes = f.list().await;
    assert_eq!(
        nodes[0]["password_broken"],
        json!(false),
        "repair must clear broken"
    );
    assert_eq!(nodes[0]["has_password"], json!(true));
}

// ---- default switch atomicity ----

#[tokio::test]
async fn default_switch_is_exclusive_and_rolls_back_atomically() {
    let f = NodesFixture::new();
    let mut body = node_body("a.example.invalid", 1080, "socks5");
    body["is_default"] = json!(true);
    let a = f.create(body.clone()).await;
    assert_eq!(f.default_flags(), vec![(a, true)]);
    let mut body_b = node_body("b.example.invalid", 1080, "socks5");
    body_b["is_default"] = json!(true);
    let b = f.create(body_b).await;
    assert_eq!(
        f.default_flags(),
        vec![(a, false), (b, true)],
        "POST switch must clear the previous default in the same transaction"
    );
    let mut body_a = node_body("a.example.invalid", 1080, "socks5");
    body_a["is_default"] = json!(true);
    let (status, reply) = f
        .call("PUT", &format!("/api/proxies/{a}"), Some(body_a), None)
        .await;
    assert_eq!(status, StatusCode::OK, "PUT switch reply={reply}");
    assert_eq!(f.default_flags(), vec![(a, true), (b, false)]);

    // A failure while clearing the old default must roll back both the clear
    // and the new row/update, never leaving zero defaults or a half switch.
    f.sql(
        "CREATE TRIGGER block_default_clear BEFORE UPDATE ON proxy_nodes
         WHEN NEW.is_default = 0 AND OLD.is_default = 1
         BEGIN SELECT RAISE(FAIL, 'PUBLIC injected default-clear failure'); END;",
    );
    let mut body_c = node_body("c.example.invalid", 1080, "socks5");
    body_c["is_default"] = json!(true);
    let (status, reply) = f.call("POST", "/api/proxies", Some(body_c), None).await;
    assert!(
        status.is_server_error(),
        "triggered POST failure must surface 5xx, got {status} reply={reply}"
    );
    assert_eq!(
        f.default_flags(),
        vec![(a, true), (b, false)],
        "failed POST must roll back the clear and the new row"
    );
    assert_eq!(f.node_count(), 2, "failed POST must not leave a new row");
    let mut body_b2 = node_body("b.example.invalid", 1080, "socks5");
    body_b2["is_default"] = json!(true);
    let (status, reply) = f
        .call("PUT", &format!("/api/proxies/{b}"), Some(body_b2), None)
        .await;
    assert!(
        status.is_server_error(),
        "triggered PUT failure must surface 5xx, got {status} reply={reply}"
    );
    assert_eq!(
        f.default_flags(),
        vec![(a, true), (b, false)],
        "failed PUT must roll back the default switch"
    );
    f.sql("DROP TRIGGER block_default_clear;");
}

// ---- loopback sinks ----

#[derive(Debug, Clone)]
struct Hit {
    method: String,
    target: String,
    proxy_authorization: Option<String>,
}

/// Minimal loopback HTTP sink: records one plain or absolute-form request per
/// connection, enforces optional proxy Basic auth, then answers with a fixed
/// marker body and closes. No tunnelling is needed to prove where the egress
/// client connected.
struct Sink {
    authority: String,
    port: u16,
    expected_basic: Option<String>,
    hits: Arc<Mutex<Vec<Hit>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Sink {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Sink {
    async fn start(auth: Option<(&str, &str)>, marker: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let authority = listener.local_addr().unwrap().to_string();
        let expected_basic =
            auth.map(|(user, pass)| format!("Basic {}", STANDARD.encode(format!("{user}:{pass}"))));
        let hits = Arc::new(Mutex::new(Vec::new()));
        let gate = expected_basic.clone();
        let log = hits.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let gate = gate.clone();
                let log = log.clone();
                tokio::spawn(async move {
                    serve_sink(stream, gate, marker, log).await;
                });
            }
        });
        Self {
            authority,
            port,
            expected_basic,
            hits,
            task,
        }
    }

    fn url(&self, user: &str, pass: &str) -> String {
        format!("http://{user}:{pass}@{}", self.authority)
    }

    fn hits(&self) -> Vec<Hit> {
        self.hits.lock().unwrap().clone()
    }
}

async fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            return Some(String::from_utf8_lossy(&buffer[..position]).into_owned());
        }
        if buffer.len() > 65536 {
            return None;
        }
    }
}

async fn serve_sink(
    mut stream: TcpStream,
    expected_basic: Option<String>,
    marker: &'static str,
    log: Arc<Mutex<Vec<Hit>>>,
) {
    let head = match tokio::time::timeout(Duration::from_secs(10), read_head(&mut stream)).await {
        Ok(Some(head)) => head,
        _ => return,
    };
    let mut lines = head.split("\r\n");
    let mut parts = lines.next().unwrap_or_default().split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return;
    };
    let proxy_authorization = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization"))
        .map(|(_, value)| value.trim().to_string());
    log.lock().unwrap().push(Hit {
        method: method.to_string(),
        target: target.to_string(),
        proxy_authorization: proxy_authorization.clone(),
    });
    let response = match (&expected_basic, proxy_authorization.as_deref()) {
        (Some(expected), Some(got)) if expected == got => {
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{marker}",
                marker.len()
            )
        }
        (Some(_), _) => "HTTP/1.1 407 Proxy Authentication Required\r\nproxy-authenticate: Basic\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".into(),
        (None, _) => {
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{marker}",
                marker.len()
            )
        }
    };
    let _ = stream.write_all(response.as_bytes()).await;
}

// ---- resolution harness ----

struct RoutingFixture {
    state: Arc<AppState>,
    account: i64,
    target: Sink,
}

impl RoutingFixture {
    async fn new(account_group: &str) -> Self {
        let db = store::open(":memory:");
        let vault = Vault::from_secret(ROUTING_SEED).unwrap();
        let account = store::insert_account_encrypted(
            &db,
            &vault,
            &AccountView {
                email: "proxy-nodes@example.invalid".into(),
                provider: "zai".into(),
                enabled: true,
                status: "active".into(),
                account_group: account_group.into(),
                ..Default::default()
            },
            "PUBLIC proxy-nodes jwt",
            "PUBLIC proxy-nodes api key",
        )
        .unwrap();
        let state =
            AppState::try_from_db_with_vault(String::new(), unused_upstream(), db, vault).unwrap();
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        Self {
            state: Arc::new(state),
            account,
            target: Sink::start(None, "TARGET-HIT").await,
        }
    }

    async fn create_node(&self, proxy: &Sink, group: &str, default: bool) -> i64 {
        let mut body = node_body("127.0.0.1", proxy.port.into(), "http");
        body["group_name"] = json!(group);
        body["is_default"] = json!(default);
        body["username"] = json!(NODE_USER);
        body["password"] = json!(NODE_PASS);
        self.post(body).await
    }

    async fn post(&self, body: Value) -> i64 {
        let (status, reply) = call_api(&self.state, "POST", "/api/proxies", Some(body)).await;
        assert_eq!(status, StatusCode::OK, "node create reply={reply}");
        reply["id"].as_i64().unwrap()
    }

    async fn set_account_group(&self, group: &str) {
        self.state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE accounts SET account_group=?1 WHERE id=?2",
                params![group, self.account],
            )
            .unwrap();
    }

    async fn probe(&self, account: Option<i64>) -> Result<String, String> {
        probe_with(
            &self.state,
            account,
            &format!("{}/probe", self.target_url()),
        )
        .await
    }

    fn target_url(&self) -> String {
        format!("http://{}", self.target.authority)
    }
}

async fn probe_with(state: &AppState, account: Option<i64>, url: &str) -> Result<String, String> {
    let builder =
        client_builder(state, account).map_err(|error| format!("builder failed: {error}"))?;
    let client = builder
        .build()
        .map_err(|error| format!("build failed: {error}"))?;
    match client.get(url.to_owned()).send().await {
        Ok(response) => Ok(response.text().await.unwrap()),
        Err(error) => Err(format!("send failed: {error}")),
    }
}

async fn call_api(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", HOST)
        .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
        .header("origin", format!("http://{HOST}"));
    let body = match body {
        Some(value) => {
            builder = builder.header("content-type", "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    read_json(
        build_router(state.clone())
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap(),
    )
    .await
}

fn seed_broken_node(state: &AppState, group: &str, default: bool, username: &str) {
    let foreign = Vault::from_secret(FOREIGN_SEED).unwrap();
    let cipher = foreign.encrypt("PUBLIC foreign node password").unwrap();
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO proxy_nodes
             (name, type, host, port, username, password, is_default, group_name, enabled)
             VALUES ('PUBLIC broken', 'http', '127.0.0.1', 1, ?1, ?2, ?3, ?4, 1)",
            params![username, cipher, default as i64, group],
        )
        .unwrap();
}

// ---- resolution and transport ----

#[tokio::test]
async fn group_nodes_route_traffic_with_exact_multigroup_semantics() {
    let f = RoutingFixture::new("beta").await;
    let group_proxy = Sink::start(Some((NODE_USER, NODE_PASS)), "PROXY-GROUP").await;
    let default_proxy = Sink::start(Some((NODE_USER, NODE_PASS)), "PROXY-DEFAULT").await;
    f.create_node(&group_proxy, "alpha, beta", false).await;
    f.create_node(&default_proxy, "", true).await;

    let body = f.probe(Some(f.account)).await.unwrap();
    assert_eq!(body, "PROXY-GROUP");
    let hits = group_proxy.hits();
    assert_eq!(hits.len(), 1, "group node must serve the account");
    assert_eq!(hits[0].method, "GET");
    assert_eq!(
        hits[0].target,
        format!("{}/probe", f.target_url()),
        "proxy must see the absolute-form target"
    );
    assert_eq!(
        hits[0].proxy_authorization.as_deref(),
        group_proxy.expected_basic.as_deref(),
        "node credentials must reach the proxy"
    );
    assert_eq!(default_proxy.hits().len(), 0);
    assert_eq!(
        f.target.hits().len(),
        0,
        "group routing must not fall back direct"
    );

    f.set_account_group("alpha").await;
    assert_eq!(f.probe(Some(f.account)).await.unwrap(), "PROXY-GROUP");

    // Segment matching is exact: no prefix match, and the account group is
    // never comma-split (Go compares the full account group to one trimmed
    // node segment).
    f.set_account_group("alphabet").await;
    assert_eq!(
        f.probe(Some(f.account)).await.unwrap(),
        "PROXY-DEFAULT",
        "prefix segments must not match"
    );
    f.set_account_group("alpha, beta").await;
    assert_eq!(
        f.probe(Some(f.account)).await.unwrap(),
        "PROXY-DEFAULT",
        "account groups must not be split"
    );

    let trimmed_proxy = Sink::start(Some((NODE_USER, NODE_PASS)), "PROXY-TRIM").await;
    f.create_node(&trimmed_proxy, " gamma , delta ", false)
        .await;
    f.set_account_group("delta").await;
    assert_eq!(
        f.probe(Some(f.account)).await.unwrap(),
        "PROXY-TRIM",
        "node group segments must be trimmed before comparison"
    );
    assert_eq!(group_proxy.hits().len(), 2, "earlier probes");
    assert_eq!(default_proxy.hits().len(), 2, "default probes");
}

#[tokio::test]
async fn resolution_falls_back_default_then_global_then_direct() {
    let f = RoutingFixture::new("lonely").await;
    let default_proxy = Sink::start(Some((NODE_USER, NODE_PASS)), "PROXY-DEFAULT").await;
    let global_proxy = Sink::start(Some((NODE_USER, NODE_PASS)), "PROXY-GLOBAL").await;
    let default_id = f.create_node(&default_proxy, "", true).await;
    assert_eq!(f.probe(Some(f.account)).await.unwrap(), "PROXY-DEFAULT");

    f.call_delete(default_id).await;
    f.state
        .persist_settings(&[("upstream_proxy", &global_proxy.url(NODE_USER, NODE_PASS))])
        .unwrap();
    assert_eq!(
        f.probe(Some(f.account)).await.unwrap(),
        "PROXY-GLOBAL",
        "deleted default must fall to the global setting"
    );
    assert_eq!(default_proxy.hits().len(), 1, "only the default probe");

    f.state.persist_settings(&[("upstream_proxy", "")]).unwrap();
    assert_eq!(
        f.probe(Some(f.account)).await.unwrap(),
        "TARGET-HIT",
        "no node/default/global must mean explicit direct"
    );
    assert_eq!(global_proxy.hits().len(), 1, "only the global probe");
    assert_eq!(f.target.hits().len(), 1, "direct probe reached the target");
}

impl RoutingFixture {
    async fn call_delete(&self, id: i64) {
        let (status, reply) =
            call_api(&self.state, "DELETE", &format!("/api/proxies/{id}"), None).await;
        assert_eq!(status, StatusCode::OK, "delete reply={reply}");
    }
}

#[tokio::test]
async fn node_disable_delete_and_group_reassignment_take_effect_immediately() {
    let f = RoutingFixture::new("g").await;
    let group_proxy = Sink::start(Some((NODE_USER, NODE_PASS)), "PROXY-GROUP").await;
    let default_proxy = Sink::start(Some((NODE_USER, NODE_PASS)), "PROXY-DEFAULT").await;
    let other_proxy = Sink::start(Some((NODE_USER, NODE_PASS)), "PROXY-OTHER").await;
    let groupless_proxy = Sink::start(Some((NODE_USER, NODE_PASS)), "PROXY-GROUPLESS").await;
    let group_id = f.create_node(&group_proxy, "g", false).await;
    f.create_node(&default_proxy, "", true).await;
    assert_eq!(f.probe(Some(f.account)).await.unwrap(), "PROXY-GROUP");

    let mut disable_body = node_body("127.0.0.1", group_proxy.port.into(), "http");
    disable_body["group_name"] = json!("g");
    disable_body["username"] = json!(NODE_USER);
    disable_body["password"] = json!(NODE_PASS);
    disable_body["enabled"] = json!(false);
    let (status, reply) = call_api(
        &f.state,
        "PUT",
        &format!("/api/proxies/{group_id}"),
        Some(disable_body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "disable reply={reply}");
    assert_eq!(
        f.probe(Some(f.account)).await.unwrap(),
        "PROXY-DEFAULT",
        "disabled group node must be skipped"
    );

    let mut enable_body = node_body("127.0.0.1", group_proxy.port.into(), "http");
    enable_body["group_name"] = json!("g");
    enable_body["username"] = json!(NODE_USER);
    enable_body["password"] = json!(NODE_PASS);
    enable_body["enabled"] = json!(true);
    let (status, reply) = call_api(
        &f.state,
        "PUT",
        &format!("/api/proxies/{group_id}"),
        Some(enable_body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "re-enable reply={reply}");
    assert_eq!(f.probe(Some(f.account)).await.unwrap(), "PROXY-GROUP");

    f.call_delete(group_id).await;
    assert_eq!(
        f.probe(Some(f.account)).await.unwrap(),
        "PROXY-DEFAULT",
        "deleted group node must not pin routing"
    );

    let other_id = f.create_node(&other_proxy, "other", false).await;
    f.set_account_group("other").await;
    assert_eq!(f.probe(Some(f.account)).await.unwrap(), "PROXY-OTHER");
    f.call_delete(other_id).await;

    f.create_node(&groupless_proxy, "", false).await;
    f.set_account_group("").await;
    assert_eq!(
        f.probe(Some(f.account)).await.unwrap(),
        "PROXY-DEFAULT",
        "empty account group must skip group matching (Go parity)"
    );
    assert_eq!(
        groupless_proxy.hits().len(),
        0,
        "empty-group node must not match"
    );
}

#[tokio::test]
async fn none_account_stays_global_only() {
    let f = RoutingFixture::new("beta").await;
    let group_proxy = Sink::start(Some((NODE_USER, NODE_PASS)), "PROXY-GROUP").await;
    let default_proxy = Sink::start(Some((NODE_USER, NODE_PASS)), "PROXY-DEFAULT").await;
    let global_proxy = Sink::start(Some((NODE_USER, NODE_PASS)), "PROXY-GLOBAL").await;
    f.create_node(&group_proxy, "beta", false).await;
    f.create_node(&default_proxy, "", true).await;
    f.state
        .persist_settings(&[("upstream_proxy", &global_proxy.url(NODE_USER, NODE_PASS))])
        .unwrap();
    // Go nil-account goes global only; pre-enrollment OAuth callers pass None.
    assert_eq!(f.probe(None).await.unwrap(), "PROXY-GLOBAL");
    assert_eq!(group_proxy.hits().len(), 0, "nodes must not apply to None");
    assert_eq!(
        default_proxy.hits().len(),
        0,
        "default must not apply to None"
    );
    assert_eq!(
        f.probe(Some(f.account)).await.unwrap(),
        "PROXY-GROUP",
        "known accounts still resolve their node"
    );
    f.state.persist_settings(&[("upstream_proxy", "")]).unwrap();
    assert_eq!(f.probe(None).await.unwrap(), "TARGET-HIT");
}

#[tokio::test]
async fn unknown_account_id_fails_closed_instead_of_going_global() {
    let f = RoutingFixture::new("beta").await;
    let node_proxy = Sink::start(Some((NODE_USER, NODE_PASS)), "PROXY-GROUP").await;
    f.create_node(&node_proxy, "beta", false).await;
    let error = f
        .probe(Some(987_654_321))
        .await
        .expect_err("missing id must fail");
    assert!(
        error.starts_with("builder failed"),
        "unexpected error: {error}"
    );
    assert_eq!(node_proxy.hits().len(), 0);
    assert_eq!(
        f.target.hits().len(),
        0,
        "no direct fallback for missing ids"
    );
}

#[tokio::test]
async fn invalid_global_is_ignored_for_selected_nodes_and_fails_on_fallback() {
    let f = RoutingFixture::new("beta").await;
    let node_proxy = Sink::start(Some((NODE_USER, NODE_PASS)), "PROXY-GROUP").await;
    let node_id = f.create_node(&node_proxy, "beta", false).await;
    f.state
        .persist_settings(&[("upstream_proxy", "http://127.0.0.1:0")])
        .unwrap();
    assert_eq!(
        f.probe(Some(f.account)).await.unwrap(),
        "PROXY-GROUP",
        "a valid selected node must outrank an invalid global setting"
    );
    f.call_delete(node_id).await;
    let error = f
        .probe(Some(f.account))
        .await
        .expect_err("invalid global must fail");
    assert!(
        error.starts_with("builder failed"),
        "unexpected error: {error}"
    );
    assert_eq!(
        f.target.hits().len(),
        0,
        "invalid global must never go direct"
    );
}

#[tokio::test]
async fn selected_broken_node_fails_closed_without_privacy_fallback() {
    let f = RoutingFixture::new("beta").await;
    let global_proxy = Sink::start(Some((NODE_USER, NODE_PASS)), "PROXY-GLOBAL").await;
    f.state
        .persist_settings(&[("upstream_proxy", &global_proxy.url(NODE_USER, NODE_PASS))])
        .unwrap();
    seed_broken_node(&f.state, "beta", false, "node-user");
    let error = f
        .probe(Some(f.account))
        .await
        .expect_err("broken group node must fail closed");
    assert!(
        error.starts_with("builder failed"),
        "unexpected error: {error}"
    );
    assert_eq!(
        global_proxy.hits().len(),
        0,
        "no global fallback for a broken node"
    );
    assert_eq!(
        f.target.hits().len(),
        0,
        "no direct fallback for a broken node"
    );

    // Fail closed consistently: even an empty username must not half-auth route.
    f.state
        .db
        .lock()
        .unwrap()
        .execute("DELETE FROM proxy_nodes", [])
        .unwrap();
    seed_broken_node(&f.state, "beta", false, "");
    let error = f
        .probe(Some(f.account))
        .await
        .expect_err("broken node without username must fail closed too");
    assert!(
        error.starts_with("builder failed"),
        "unexpected error: {error}"
    );

    f.state
        .db
        .lock()
        .unwrap()
        .execute("DELETE FROM proxy_nodes", [])
        .unwrap();
    seed_broken_node(&f.state, "", true, "node-user");
    f.set_account_group("lonely").await;
    let error = f
        .probe(Some(f.account))
        .await
        .expect_err("broken default must fail closed");
    assert!(
        error.starts_with("builder failed"),
        "unexpected error: {error}"
    );
    assert_eq!(
        global_proxy.hits().len(),
        0,
        "no global fallback for a broken default"
    );
}

#[tokio::test]
async fn unrelated_broken_node_does_not_block_other_groups() {
    let f = RoutingFixture::new("alpha").await;
    let alpha_proxy = Sink::start(Some((NODE_USER, NODE_PASS)), "PROXY-ALPHA").await;
    f.create_node(&alpha_proxy, "alpha", false).await;
    seed_broken_node(&f.state, "bravo", false, "node-user");
    assert_eq!(f.probe(Some(f.account)).await.unwrap(), "PROXY-ALPHA");
    assert_eq!(alpha_proxy.hits().len(), 1);
    assert_eq!(f.target.hits().len(), 0);
}

#[tokio::test]
async fn broken_first_group_match_does_not_silently_skip_to_a_later_node() {
    let f = RoutingFixture::new("g").await;
    let later_proxy = Sink::start(Some((NODE_USER, NODE_PASS)), "PROXY-LATER").await;
    seed_broken_node(&f.state, "g", false, "node-user");
    f.create_node(&later_proxy, "g", false).await;
    let error = f.probe(Some(f.account)).await.expect_err(
        "the first enabled match is the selected node; its broken password must fail closed",
    );
    assert!(
        error.starts_with("builder failed"),
        "unexpected error: {error}"
    );
    assert_eq!(
        later_proxy.hits().len(),
        0,
        "must not skip to the later node"
    );
    assert_eq!(f.target.hits().len(), 0, "must not skip to direct");
}

#[tokio::test]
async fn socks5_node_never_falls_back_to_direct() {
    let f = RoutingFixture::new("g").await;
    let mut body = node_body("127.0.0.1", 1, "socks5");
    body["group_name"] = json!("g");
    f.post(body).await;
    let error = f
        .probe(Some(f.account))
        .await
        .expect_err("dead socks5 proxy must fail");
    assert!(
        error.starts_with("send failed"),
        "unexpected error: {error}"
    );
    assert_eq!(
        f.target.hits().len(),
        0,
        "socks5 failure must not go direct"
    );
}
