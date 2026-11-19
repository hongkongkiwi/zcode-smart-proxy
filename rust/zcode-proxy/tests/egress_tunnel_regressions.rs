//! Egress tunnel regressions for `zcode_proxy::egress::client_builder`.
//!
//! Companion to `tests/egress_global_regressions.rs` (which covers the
//! plaintext HTTP forward proxy and the settings surface) and ported in
//! spirit from the Go reference `client_proxy_tls_security_test.go`:
//!
//! * HTTPS target reached through an HTTP CONNECT proxy, with the proxy
//!   Basic credentials scoped to the CONNECT request only.
//! * HTTPS proxy (TLS listener) trusted-certificate tunnel with Basic auth
//!   on the proxy leg, and fail-closed zero-CONNECT on an untrusted proxy
//!   certificate.
//! * HTTPS target certificate validation through the tunnel (no blanket
//!   invalid-certificate acceptance).
//! * socks5 (local DNS) and socks5h (proxy-side DNS) against a real local
//!   SOCKS5 mock enforcing RFC 1929 auth, never forwarding proxy
//!   credentials to the target.
//!
//! Runtime tooling: the `openssl` CLI generates a per-run synthetic CA and
//! leaf certificates and serves the HTTPS target via `openssl s_server`;
//! `python3` (stdlib only) serves the TLS CONNECT proxy from
//! `tests/fixtures/egress_tls/https_proxy.py`. No Cargo manifest changes
//! and no committed secrets: every certificate is created inside a
//! per-process temp directory and dies with it.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use zcode_proxy::{
    egress::client_builder,
    state::{AppState, UpstreamUrls},
};

const PROXY_USER: &str = "egress-tunnel-user";
const PROXY_PASS: &str = "egress-tunnel-secret-PUBLIC";
const SOCKS_USER: &str = "egress-socks-user";
const SOCKS_PASS: &str = "egress-socks-secret-PUBLIC";
const SOCKS_WRONG_PASS: &str = "WRONG-egress-socks-secret";
const SOCKS_REMOTE_HOST: &str = "egress-socks-target.invalid";
const TARGET_BODY: &str = "EGRESS-TUNNEL-TARGET-OK";
const SEND_TIMEOUT: Duration = Duration::from_secs(15);

fn basic(user: &str, pass: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{pass}")))
}

fn unused_upstream() -> UpstreamUrls {
    UpstreamUrls {
        zai: "http://127.0.0.1:1/unused".into(),
        zai_fallback: "http://127.0.0.1:1/unused".into(),
    }
}

fn proxy_state(proxy_url: &str) -> AppState {
    let state = AppState::new(String::new(), unused_upstream());
    state
        .persist_settings(&[("upstream_proxy", proxy_url)])
        .expect("seed upstream_proxy");
    state
}

async fn send_get(client: &reqwest::Client, url: &str) -> Result<reqwest::Response, String> {
    match tokio::time::timeout(SEND_TIMEOUT, client.get(url).send()).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("request timed out".into()),
    }
}

// ---- synthetic PKI via the openssl CLI ----

struct TlsMaterial {
    ca_pem: Vec<u8>,
    leaf_cert: PathBuf,
    leaf_key: PathBuf,
    dir: PathBuf,
}

fn scratch_dir(label: &str) -> PathBuf {
    let unique = format!(
        "zcode-egress-tunnel-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let dir = std::env::temp_dir().join(unique).join(label);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn openssl_run(dir: &Path, args: &[String]) {
    let output = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("spawn openssl");
    assert!(
        output.status.success(),
        "openssl {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}

impl TlsMaterial {
    /// Fresh CA plus a leaf with SAN IP:127.0.0.1,DNS:localhost. Verified
    /// against OpenSSL 4.1.0; `req -config`/`x509 -extfile` keep the flags
    /// portable across LibreSSL and OpenSSL 3.x.
    fn generate(label: &str) -> Self {
        let dir = scratch_dir(label);
        let config = "[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n";
        std::fs::write(dir.join("ca.cnf"), config).unwrap();
        std::fs::write(dir.join("leaf.cnf"), "[req]\ndistinguished_name=dn\n[dn]\n").unwrap();
        std::fs::write(
            dir.join("leaf.ext"),
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n",
        )
        .unwrap();
        let subject = format!("/CN=zcode egress {label}");
        openssl_run(
            &dir,
            &[
                "req".into(),
                "-x509".into(),
                "-newkey".into(),
                "rsa:2048".into(),
                "-nodes".into(),
                "-days".into(),
                "2".into(),
                "-keyout".into(),
                "ca.key".into(),
                "-out".into(),
                "ca.crt".into(),
                "-subj".into(),
                subject,
                "-config".into(),
                "ca.cnf".into(),
                "-extensions".into(),
                "v3_ca".into(),
            ],
        );
        openssl_run(
            &dir,
            &[
                "req".into(),
                "-newkey".into(),
                "rsa:2048".into(),
                "-nodes".into(),
                "-keyout".into(),
                "leaf.key".into(),
                "-out".into(),
                "leaf.csr".into(),
                "-subj".into(),
                "/CN=localhost".into(),
                "-config".into(),
                "leaf.cnf".into(),
            ],
        );
        openssl_run(
            &dir,
            &[
                "x509".into(),
                "-req".into(),
                "-in".into(),
                "leaf.csr".into(),
                "-CA".into(),
                "ca.crt".into(),
                "-CAkey".into(),
                "ca.key".into(),
                "-CAcreateserial".into(),
                "-days".into(),
                "2".into(),
                "-out".into(),
                "leaf.crt".into(),
                "-extfile".into(),
                "leaf.ext".into(),
            ],
        );
        openssl_run(
            &dir,
            &[
                "verify".into(),
                "-CAfile".into(),
                "ca.crt".into(),
                "leaf.crt".into(),
            ],
        );
        let ca_pem = std::fs::read(dir.join("ca.crt")).expect("read ca.crt");
        Self {
            ca_pem,
            leaf_cert: dir.join("leaf.crt"),
            leaf_key: dir.join("leaf.key"),
            dir,
        }
    }
}

fn loopback_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
    listener.local_addr().expect("reserved addr").port()
}

fn wait_port_open(port: u16, what: &str) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    panic!("{what} on 127.0.0.1:{port} never became reachable");
}

/// HTTPS target served by `openssl s_server -www`: terminates TLS with the
/// given leaf and answers any request with an HTTP 200 status page.
struct SServerTarget {
    port: u16,
    child: Child,
}

impl Drop for SServerTarget {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl SServerTarget {
    fn start(material: &TlsMaterial) -> Self {
        let port = loopback_port();
        let cert = material.leaf_cert.display().to_string();
        let key = material.leaf_key.display().to_string();
        let child = Command::new("openssl")
            .arg("s_server")
            .arg("-accept")
            .arg(format!("127.0.0.1:{port}"))
            .arg("-cert")
            .arg(&cert)
            .arg("-key")
            .arg(&key)
            .arg("-www")
            .arg("-quiet")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn openssl s_server");
        wait_port_open(port, "openssl s_server target");
        Self { port, child }
    }
}

// ---- plaintext CONNECT proxy (tokio) ----

#[derive(Debug, Clone)]
struct ConnectObservation {
    method: String,
    target: String,
    proxy_authorization: Option<String>,
    tunnel_prefix: Vec<u8>,
}

struct PlainConnectProxy {
    authority: String,
    expected_basic: String,
    observations: Arc<Mutex<Vec<ConnectObservation>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for PlainConnectProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_head_bytes(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            buffer.truncate(position);
            return Some(buffer);
        }
        if buffer.len() > 65536 {
            return None;
        }
    }
}

fn head_header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then_some(value.trim())
    })
}

impl PlainConnectProxy {
    async fn start(user: &str, pass: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let observations = Arc::new(Mutex::new(Vec::new()));
        let expected_basic = basic(user, pass);
        let gate = expected_basic.clone();
        let log = observations.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let log = log.clone();
                let gate = gate.clone();
                tokio::spawn(async move {
                    let head = match tokio::time::timeout(
                        Duration::from_secs(10),
                        read_head_bytes(&mut stream),
                    )
                    .await
                    {
                        Ok(Some(bytes)) => String::from_utf8_lossy(&bytes).to_string(),
                        _ => return,
                    };
                    let mut parts = head.split_whitespace();
                    let method = parts.next().unwrap_or_default().to_string();
                    let target = parts.next().unwrap_or_default().to_string();
                    let proxy_authorization =
                        head_header(&head, "proxy-authorization").map(str::to_string);
                    log.lock().unwrap().push(ConnectObservation {
                        proxy_authorization: proxy_authorization.clone(),
                        method: method.clone(),
                        target: target.clone(),
                        tunnel_prefix: Vec::new(),
                    });
                    if method != "CONNECT" {
                        let _ = stream
                            .write_all(
                                b"HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\n\r\n",
                            )
                            .await;
                        return;
                    }
                    if proxy_authorization.as_deref() != Some(gate.as_str()) {
                        let _ = stream
                            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nproxy-authenticate: Basic\r\ncontent-length: 0\r\n\r\n")
                            .await;
                        return;
                    }
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await;
                    let mut prefix = [0u8; 16];
                    let prefix_len = match tokio::time::timeout(
                        Duration::from_secs(10),
                        stream.read(&mut prefix),
                    )
                    .await
                    {
                        Ok(Ok(n)) if n > 0 => n,
                        _ => return,
                    };
                    let prefix = prefix[..prefix_len].to_vec();
                    log.lock().unwrap().last_mut().unwrap().tunnel_prefix = prefix.clone();
                    let mut upstream = match TcpStream::connect(target.as_str()).await {
                        Ok(stream) => stream,
                        Err(_) => return,
                    };
                    if upstream.write_all(&prefix).await.is_err() {
                        return;
                    }
                    let _ = tokio::time::timeout(
                        Duration::from_secs(30),
                        copy_bidirectional(&mut stream, &mut upstream),
                    )
                    .await;
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

    fn observations(&self) -> Vec<ConnectObservation> {
        self.observations.lock().unwrap().clone()
    }
}

// ---- python3 TLS CONNECT proxy ----

struct PythonTlsProxy {
    authority: String,
    log_path: PathBuf,
    child: Child,
}

impl Drop for PythonTlsProxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl PythonTlsProxy {
    fn start(material: &TlsMaterial, require_basic: Option<&str>) -> Self {
        let port = loopback_port();
        let log_path = material.dir.join(format!("pyproxy-{port}.jsonl"));
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/egress_tls/https_proxy.py");
        let cert = material.leaf_cert.display().to_string();
        let key = material.leaf_key.display().to_string();
        let mut command = Command::new("python3");
        command
            .arg(script)
            .arg("--port")
            .arg(port.to_string())
            .arg("--cert")
            .arg(&cert)
            .arg("--key")
            .arg(&key)
            .arg("--log")
            .arg(&log_path);
        if let Some(required) = require_basic {
            command.arg("--require-auth").arg(required);
        }
        let mut child = command
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn python3 TLS proxy");
        wait_port_open(port, "python3 TLS proxy");
        if let Ok(Some(status)) = child.try_wait() {
            let _ = child.wait();
            panic!("python3 TLS proxy exited early with {status}");
        }
        Self {
            authority: format!("127.0.0.1:{port}"),
            log_path,
            child,
        }
    }

    fn records(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.log_path)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).expect("parse proxy log line"))
            .collect()
    }

    fn events<'a>(records: &'a [Value], event: &str) -> Vec<&'a Value> {
        records
            .iter()
            .filter(|record| record["event"] == event)
            .collect()
    }

    fn wait_for_records(&self, event: &str, minimum: usize) -> Vec<Value> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let records = self.records();
            if Self::events(&records, event).len() >= minimum {
                return records;
            }
            if Instant::now() > deadline {
                panic!("python3 TLS proxy log never held {minimum} '{event}' records: {records:?}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

// ---- plaintext HTTP target (SOCKS leg) ----

struct PlainHttpTarget {
    port: u16,
    heads: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for PlainHttpTarget {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl PlainHttpTarget {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let heads = Arc::new(Mutex::new(Vec::new()));
        let log = heads.clone();
        let body = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{TARGET_BODY}",
            TARGET_BODY.len()
        );
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let log = log.clone();
                let body = body.clone();
                tokio::spawn(async move {
                    let head = match tokio::time::timeout(
                        Duration::from_secs(10),
                        read_head_bytes(&mut stream),
                    )
                    .await
                    {
                        Ok(Some(bytes)) => String::from_utf8_lossy(&bytes).to_string(),
                        _ => return,
                    };
                    log.lock().unwrap().push(head);
                    let _ = stream.write_all(body.as_bytes()).await;
                });
            }
        });
        Self { port, heads, task }
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }
}

// ---- SOCKS5 mock with RFC 1929 auth (tokio) ----

#[derive(Debug, Clone)]
struct SocksObservation {
    auth_user: String,
    auth_pass: String,
    auth_ok: bool,
    atyp: u8,
    addr: String,
    port: u16,
}

struct SocksProxy {
    authority: String,
    expected_user: String,
    expected_pass: String,
    observations: Arc<Mutex<Vec<SocksObservation>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for SocksProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn socks_read_exact(stream: &mut TcpStream, n: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; n];
    match tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buffer)).await {
        Ok(Ok(_)) => Some(buffer),
        _ => None,
    }
}

impl SocksProxy {
    async fn start(user: &str, pass: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let observations = Arc::new(Mutex::new(Vec::new()));
        let expected_user = user.to_string();
        let expected_pass = pass.to_string();
        let auth_user = expected_user.clone();
        let auth_pass = expected_pass.clone();
        let log = observations.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let log = log.clone();
                let expected_user = auth_user.clone();
                let expected_pass = auth_pass.clone();
                tokio::spawn(async move {
                    // RFC 1928 greeting: the mock only offers username/password auth.
                    let Some(greeting) = socks_read_exact(&mut stream, 2).await else {
                        return;
                    };
                    if greeting[0] != 0x05 {
                        return;
                    }
                    let Some(methods) = socks_read_exact(&mut stream, greeting[1] as usize).await
                    else {
                        return;
                    };
                    if !methods.contains(&0x02) {
                        let _ = stream.write_all(&[0x05, 0xFF]).await;
                        return;
                    }
                    let _ = stream.write_all(&[0x05, 0x02]).await;
                    // RFC 1929 username/password subnegotiation.
                    let Some(version) = socks_read_exact(&mut stream, 2).await else {
                        return;
                    };
                    if version[0] != 0x01 {
                        return;
                    }
                    let Some(user) = socks_read_exact(&mut stream, version[1] as usize).await
                    else {
                        return;
                    };
                    let Some(pass_len) = socks_read_exact(&mut stream, 1).await else {
                        return;
                    };
                    let Some(pass) = socks_read_exact(&mut stream, pass_len[0] as usize).await
                    else {
                        return;
                    };
                    let user = String::from_utf8_lossy(&user).to_string();
                    let pass = String::from_utf8_lossy(&pass).to_string();
                    let auth_ok = user == expected_user && pass == expected_pass;
                    let _ = stream
                        .write_all(&[0x01, if auth_ok { 0x00 } else { 0xFF }])
                        .await;
                    if !auth_ok {
                        log.lock().unwrap().push(SocksObservation {
                            auth_user: user,
                            auth_pass: pass,
                            auth_ok,
                            atyp: 0,
                            addr: String::new(),
                            port: 0,
                        });
                        return;
                    }
                    // CONNECT request: keep socks5h hostnames verbatim.
                    let mut request = [0u8; 4];
                    match tokio::time::timeout(
                        Duration::from_secs(10),
                        stream.read_exact(&mut request),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {}
                        _ => return,
                    }
                    let (cmd, atyp) = (request[1], request[3]);
                    if cmd != 0x01 {
                        return;
                    }
                    let addr = match atyp {
                        0x01 => {
                            let Some(octets) = socks_read_exact(&mut stream, 4).await else {
                                return;
                            };
                            octets
                                .iter()
                                .map(|byte| byte.to_string())
                                .collect::<Vec<_>>()
                                .join(".")
                        }
                        0x03 => {
                            let Some(len) = socks_read_exact(&mut stream, 1).await else {
                                return;
                            };
                            let Some(name) = socks_read_exact(&mut stream, len[0] as usize).await
                            else {
                                return;
                            };
                            String::from_utf8_lossy(&name).to_string()
                        }
                        _ => return,
                    };
                    let Some(port_bytes) = socks_read_exact(&mut stream, 2).await else {
                        return;
                    };
                    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
                    log.lock().unwrap().push(SocksObservation {
                        auth_user: user,
                        auth_pass: pass,
                        auth_ok,
                        atyp,
                        addr: addr.clone(),
                        port,
                    });
                    let _ = stream
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    // Only the fixed remote-DNS fixture host bypasses resolution.
                    let connect_to = if atyp == 0x03 && addr == "egress-socks-target.invalid" {
                        format!("127.0.0.1:{port}")
                    } else {
                        format!("{addr}:{port}")
                    };
                    let Ok(mut upstream) = TcpStream::connect(connect_to.as_str()).await else {
                        return;
                    };
                    let _ = tokio::time::timeout(
                        Duration::from_secs(30),
                        copy_bidirectional(&mut stream, &mut upstream),
                    )
                    .await;
                });
            }
        });
        Self {
            authority,
            expected_user,
            expected_pass,
            observations,
            task,
        }
    }

    fn observations(&self) -> Vec<SocksObservation> {
        self.observations.lock().unwrap().clone()
    }
}

// ---- regressions ----

#[tokio::test]
async fn https_target_tunnels_through_http_connect_proxy_with_scoped_basic_auth() {
    let tls = TlsMaterial::generate("connect-target");
    let target = SServerTarget::start(&tls);
    let proxy = PlainConnectProxy::start(PROXY_USER, PROXY_PASS).await;
    let state = proxy_state(&format!(
        "http://{PROXY_USER}:{PROXY_PASS}@{}",
        proxy.authority
    ));
    let client = client_builder(&state, None)
        .expect("builder")
        .add_root_certificate(reqwest::Certificate::from_pem(&tls.ca_pem).expect("synthetic CA"))
        .build()
        .expect("client");
    let url = format!("https://127.0.0.1:{}/egress-connect-probe", target.port);
    let response = send_get(&client, &url)
        .await
        .expect("HTTPS request through the CONNECT proxy");
    assert_eq!(response.status().as_u16(), 200);
    assert!(!response.text().await.unwrap().is_empty());

    let observations = proxy.observations();
    assert_eq!(observations.len(), 1, "observations={observations:?}");
    assert_eq!(observations[0].method, "CONNECT");
    assert_eq!(
        observations[0].target,
        format!("127.0.0.1:{}", target.port),
        "CONNECT authority mismatch"
    );
    assert_eq!(
        observations[0].proxy_authorization.as_deref(),
        Some(proxy.expected_basic.as_str()),
        "proxy credentials from the URL must reach the proxy only"
    );
    let prefix = &observations[0].tunnel_prefix;
    assert!(
        prefix.first() == Some(&0x16) && prefix.get(1) == Some(&0x03),
        "post-CONNECT client bytes must open a TLS ClientHello (0x16 0x03), got {prefix:?}: \
         plaintext HTTP or leaked proxy credentials would appear here"
    );
}

#[tokio::test]
async fn https_target_with_untrusted_certificate_fails_closed_through_connect_tunnel() {
    let trusted = TlsMaterial::generate("target-roots");
    let rogue = TlsMaterial::generate("target-rogue");
    let target = SServerTarget::start(&rogue);
    let proxy = PlainConnectProxy::start(PROXY_USER, PROXY_PASS).await;
    let state = proxy_state(&format!(
        "http://{PROXY_USER}:{PROXY_PASS}@{}",
        proxy.authority
    ));
    let client = client_builder(&state, None)
        .expect("builder")
        .add_root_certificate(
            reqwest::Certificate::from_pem(&trusted.ca_pem).expect("unrelated CA"),
        )
        .build()
        .expect("client");
    let url = format!("https://127.0.0.1:{}/rogue-target", target.port);
    let error = send_get(&client, &url)
        .await
        .expect_err("client must reject an HTTPS target certificate outside its roots");
    assert!(
        !error.is_empty(),
        "error must carry a reason for the failure"
    );
    let observations = proxy.observations();
    assert_eq!(
        observations.len(),
        1,
        "exactly one CONNECT: the tunnel is established and the failure is target-side \
         validation, observations={observations:?}"
    );
    assert_eq!(observations[0].method, "CONNECT");
}

#[tokio::test]
async fn https_proxy_with_trusted_certificate_tunnels_with_basic_auth() {
    let tls = TlsMaterial::generate("proxy-trusted");
    let target = SServerTarget::start(&tls);
    let py = PythonTlsProxy::start(&tls, Some(&basic(PROXY_USER, PROXY_PASS)));
    let state = proxy_state(&format!(
        "https://{PROXY_USER}:{PROXY_PASS}@{}",
        py.authority
    ));
    let client = client_builder(&state, None)
        .expect("builder")
        .add_root_certificate(reqwest::Certificate::from_pem(&tls.ca_pem).expect("proxy CA"))
        .build()
        .expect("client");
    let url = format!("https://127.0.0.1:{}/proxy-tls-probe", target.port);
    let response = send_get(&client, &url)
        .await
        .expect("HTTPS proxy with a trusted certificate must tunnel");
    assert_eq!(response.status().as_u16(), 200);

    let records = py.wait_for_records("request", 1);
    let requests = PythonTlsProxy::events(&records, "request");
    assert_eq!(requests.len(), 1, "records={records:?}");
    assert_eq!(requests[0]["method"], "CONNECT");
    assert_eq!(
        requests[0]["target"].as_str().unwrap(),
        format!("127.0.0.1:{}", target.port),
        "CONNECT must carry the target authority"
    );
    assert_eq!(
        requests[0]["auth"].as_str().unwrap(),
        basic(PROXY_USER, PROXY_PASS),
        "Basic proxy credentials must reach the HTTPS proxy only"
    );
    assert!(
        !PythonTlsProxy::events(&records, "tls_handshake_ok").is_empty(),
        "trusted proxy certificate must complete the TLS handshake: {records:?}"
    );
}

#[tokio::test]
async fn https_proxy_with_untrusted_certificate_fails_closed_with_zero_connect() {
    let tls = TlsMaterial::generate("proxy-untrusted");
    let target = SServerTarget::start(&tls);
    let py = PythonTlsProxy::start(&tls, Some(&basic(PROXY_USER, PROXY_PASS)));
    let state = proxy_state(&format!(
        "https://{PROXY_USER}:{PROXY_PASS}@{}",
        py.authority
    ));
    // No add_root_certificate: the freshly generated CA is not in the
    // system roots, so the proxy certificate must be rejected.
    let client = client_builder(&state, None)
        .expect("builder")
        .build()
        .expect("client");
    let url = format!("https://127.0.0.1:{}/never-reached", target.port);
    let error = send_get(&client, &url)
        .await
        .expect_err("client must reject an untrusted HTTPS proxy certificate");
    assert!(!error.is_empty());

    // The handshake attempt must be observable, but no request head - and
    // therefore no CONNECT and no Basic credentials - may ever arrive.
    let records = py.wait_for_records("tls_handshake_failed", 1);
    assert!(
        PythonTlsProxy::events(&records, "request").is_empty(),
        "untrusted HTTPS proxy received a request (CONNECT or otherwise): {records:?}"
    );
    assert!(
        PythonTlsProxy::events(&records, "tls_handshake_ok").is_empty(),
        "untrusted HTTPS proxy completed a handshake: {records:?}"
    );
}

#[tokio::test]
async fn socks5_and_socks5h_route_through_local_mock_with_scoped_auth() {
    let target = PlainHttpTarget::start().await;
    let socks = SocksProxy::start(SOCKS_USER, SOCKS_PASS).await;
    assert_eq!(socks.expected_user, SOCKS_USER);
    assert_eq!(socks.expected_pass, SOCKS_PASS);

    // socks5: the client resolves the target locally and sends an IPv4
    // address to the mock.
    let state = proxy_state(&format!(
        "socks5://{SOCKS_USER}:{SOCKS_PASS}@{}",
        socks.authority
    ));
    let client = client_builder(&state, None)
        .expect("builder")
        .build()
        .expect("client");
    let url = format!("http://127.0.0.1:{}/socks-local-dns", target.port);
    let response = send_get(&client, &url)
        .await
        .expect("socks5 request through the local mock");
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.text().await.unwrap(), TARGET_BODY);
    let observations = socks.observations();
    let local = observations
        .iter()
        .find(|o| o.addr == "127.0.0.1" && o.port == target.port)
        .expect("socks5 CONNECT observation");
    assert!(local.auth_ok, "socks5 auth: {local:?}");
    assert_eq!(local.auth_user, SOCKS_USER);
    assert_eq!(local.auth_pass, SOCKS_PASS);
    assert_eq!(local.atyp, 0x01, "socks5 must send an IPv4 address");

    // socks5h: the hostname travels verbatim to the mock (remote DNS).
    let state = proxy_state(&format!(
        "socks5h://{SOCKS_USER}:{SOCKS_PASS}@{}",
        socks.authority
    ));
    let client = client_builder(&state, None)
        .expect("builder")
        .build()
        .expect("client");
    let url = format!(
        "http://{SOCKS_REMOTE_HOST}:{}/socks-remote-dns",
        target.port
    );
    let response = send_get(&client, &url)
        .await
        .expect("socks5h request through the local mock");
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.text().await.unwrap(), TARGET_BODY);
    let observations = socks.observations();
    let remote = observations
        .iter()
        .find(|o| o.addr == SOCKS_REMOTE_HOST)
        .expect("socks5h CONNECT observation");
    assert!(remote.auth_ok, "socks5h auth: {remote:?}");
    assert_eq!(remote.atyp, 0x03, "socks5h must send the hostname domain");
    assert_eq!(remote.port, target.port);

    // Wrong SOCKS credentials must fail closed without touching the target.
    let state = proxy_state(&format!(
        "socks5://{SOCKS_USER}:{SOCKS_WRONG_PASS}@{}",
        socks.authority
    ));
    let client = client_builder(&state, None)
        .expect("builder")
        .build()
        .expect("client");
    let url = format!("http://127.0.0.1:{}/socks-wrong-auth", target.port);
    send_get(&client, &url)
        .await
        .expect_err("rejected SOCKS credentials must fail the request");
    let observations = socks.observations();
    let rejected = observations
        .iter()
        .find(|o| o.auth_pass == SOCKS_WRONG_PASS)
        .expect("rejected SOCKS auth observation");
    assert!(!rejected.auth_ok);
    assert!(
        rejected.atyp == 0,
        "no CONNECT request may follow failed SOCKS auth: {rejected:?}"
    );

    // Proxy credentials never reach the plaintext target.
    let heads = target.heads();
    assert_eq!(
        heads.len(),
        2,
        "only the two successful requests: {heads:?}"
    );
    for head in &heads {
        assert!(
            !head.to_ascii_lowercase().contains("proxy-authorization"),
            "Proxy-Authorization forwarded to the target: {head}"
        );
        assert!(
            !head.contains(SOCKS_PASS),
            "socks password reached the target: {head}"
        );
        assert!(
            !head.contains(&basic(SOCKS_USER, SOCKS_PASS)),
            "socks Basic credentials reached the target: {head}"
        );
    }
    assert!(
        heads
            .iter()
            .all(|head| head.contains("/socks-local-dns") || head.contains("/socks-remote-dns")),
        "unexpected target requests: {heads:?}"
    );
}
