//! Session-protected proxy connectivity and local discovery diagnostics.

use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use futures_util::{stream, StreamExt};
use rusqlite::params;
use serde::Deserialize;
use serde_json::json;

use crate::{egress, state::AppState, store};

#[derive(Clone)]
pub struct ProxyDiagnosticsConfig {
    pub exit_ip_urls: Vec<String>,
}

impl Default for ProxyDiagnosticsConfig {
    fn default() -> Self {
        Self {
            exit_ip_urls: vec![
                "https://api.ipify.org/?format=json".into(),
                "https://ipinfo.io/json".into(),
            ],
        }
    }
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"message": message}))).into_response()
}

struct Outcome {
    ip: String,
    elapsed_ms: u64,
    message: &'static str,
}

async fn probe(urls: &[String], proxy: Result<Option<String>, ()>) -> Outcome {
    let start = Instant::now();
    let result = async {
        let proxy = proxy.map_err(|_| "invalid proxy configuration")?;
        let client = egress::builder_with_proxy(proxy)
            .map_err(|_| "invalid proxy configuration")?
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "unable to build proxy client")?;
        for url in urls {
            let Ok(response) = client.get(url).send().await else {
                continue;
            };
            if response.status() != reqwest::StatusCode::OK {
                continue;
            }
            let mut body = Vec::new();
            let mut chunks = response.bytes_stream();
            let mut valid = true;
            while let Some(chunk) = chunks.next().await {
                match chunk {
                    Ok(chunk) if body.len() + chunk.len() <= 4096 => body.extend_from_slice(&chunk),
                    _ => {
                        valid = false;
                        break;
                    }
                }
            }
            if valid {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) {
                    if let Some(ip) = value.get("ip").and_then(|v| v.as_str()) {
                        if ip.parse::<IpAddr>().is_ok() {
                            return Ok(ip.to_owned());
                        }
                    }
                }
            }
        }
        Err("unable to obtain exit IP")
    }
    .await;
    let elapsed_ms = start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    match result {
        Ok(ip) => Outcome {
            ip,
            elapsed_ms,
            message: "",
        },
        Err(message) => Outcome {
            ip: String::new(),
            elapsed_ms,
            message,
        },
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct TestBody {
    url: String,
}

pub async fn handle_test_url(State(state): State<Arc<AppState>>, body: String) -> Response {
    let body: TestBody = if body.trim().is_empty() {
        TestBody::default()
    } else {
        match serde_json::from_str(&body) {
            Ok(body) => body,
            Err(_) => return error(StatusCode::BAD_REQUEST, "invalid body"),
        }
    };
    let proxy = egress::validate_proxy_url(&body.url).map_err(|_| ());
    let outcome = probe(&state.proxy_diagnostics.exit_ip_urls, proxy).await;
    if outcome.message.is_empty() {
        Json(json!({"ok": true, "exit_ip": outcome.ip, "elapsed_ms": outcome.elapsed_ms}))
            .into_response()
    } else {
        Json(json!({"ok": false, "exit_ip": outcome.ip, "elapsed_ms": outcome.elapsed_ms, "message": outcome.message})).into_response()
    }
}

pub async fn handle_test_node(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let Ok(id) = id.parse::<i64>() else {
        return error(StatusCode::BAD_REQUEST, "invalid id");
    };
    let node = {
        let db = state.db.lock().unwrap();
        match store::list_proxy_nodes(&db) {
            Ok(nodes) => match nodes.into_iter().find(|node| node.id == id) {
                Some(node) => node,
                None => return error(StatusCode::NOT_FOUND, "proxy node not found"),
            },
            Err(_) => {
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "storage operation failed",
                )
            }
        }
    };
    let proxy = egress::node_url(&node, &state);
    let display = proxy
        .as_ref()
        .ok()
        .and_then(|url| egress::display_proxy_url(url).ok())
        .unwrap_or_default();
    let outcome = probe(
        &state.proxy_diagnostics.exit_ip_urls,
        proxy.map(Some).map_err(|_| ()),
    )
    .await;
    let ok = outcome.message.is_empty();
    {
        let db = state.db.lock().unwrap();
        let updated = db.execute(
            "UPDATE proxy_nodes SET check_status=?1,check_latency=?2,check_ip=?3,check_msg=?4,
             check_at=datetime('now','localtime') WHERE id=?5 AND type=?6 AND host=?7 AND port=?8
             AND username=?9 AND password=?10",
            params![
                if ok { "ok" } else { "fail" },
                outcome.elapsed_ms as i64,
                outcome.ip,
                outcome.message,
                id,
                node.kind,
                node.host,
                node.port,
                node.username,
                node.password
            ],
        );
        match updated {
            Err(_) => {
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "storage operation failed",
                )
            }
            Ok(0) => {
                let exists: rusqlite::Result<bool> = db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM proxy_nodes WHERE id=?1)",
                    [id],
                    |row| row.get(0),
                );
                return match exists {
                    Ok(true) => error(StatusCode::CONFLICT, "proxy node changed"),
                    Ok(false) => error(StatusCode::NOT_FOUND, "proxy node not found"),
                    Err(_) => error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "storage operation failed",
                    ),
                };
            }
            Ok(_) => {}
        }
    }
    Json(
        json!({"ok": ok, "exit_ip": outcome.ip, "elapsed_ms": outcome.elapsed_ms,
        "message": outcome.message, "proxy": display}),
    )
    .into_response()
}

#[cfg(not(windows))]
async fn system_proxy() -> Option<String> {
    ["http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"]
        .iter()
        .filter_map(|key| std::env::var(key).ok())
        .map(|value| value.trim().to_owned())
        .find(|value| !value.is_empty())
}

#[cfg(windows)]
async fn system_proxy() -> Option<String> {
    tokio::time::timeout(
        Duration::from_secs(3),
        tokio::task::spawn_blocking(|| {
            fn query(name: &str) -> Option<String> {
                use std::process::{Command, Stdio};
                let mut child = Command::new("reg.exe")
                    .args([
                        "query",
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                        "/v",
                        name,
                    ])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .ok()?;
                let deadline = Instant::now() + Duration::from_secs(1);
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) if status.success() => {
                            use std::io::Read;
                            let mut output = String::new();
                            child
                                .stdout
                                .take()?
                                .take(8192)
                                .read_to_string(&mut output)
                                .ok()?;
                            return Some(output);
                        }
                        Ok(Some(_)) | Err(_) => return None,
                        Ok(None) if Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(20))
                        }
                        Ok(None) => {
                            let _ = child.kill();
                            let _ = child.wait();
                            return None;
                        }
                    }
                }
            }
            let enabled = query("ProxyEnable")?;
            if !enabled
                .lines()
                .any(|line| line.split_whitespace().last() == Some("0x1"))
            {
                return None;
            }
            let output = query("ProxyServer")?;
            let server = output
                .lines()
                .find(|line| line.contains("ProxyServer"))?
                .split_whitespace()
                .skip(2)
                .collect::<Vec<_>>()
                .join(" ");
            let mut selected = server.trim().to_owned();
            if selected.contains('=') {
                let entries: Vec<_> = selected
                    .split(';')
                    .filter_map(|part| part.split_once('='))
                    .map(|(key, value)| (key.trim(), value.trim()))
                    .filter(|(_, value)| !value.is_empty())
                    .collect();
                let (kind, value) = entries
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case("https"))
                    .or_else(|| {
                        entries
                            .iter()
                            .find(|(key, _)| key.eq_ignore_ascii_case("http"))
                    })
                    .or_else(|| entries.first())
                    .copied()?;
                selected = if kind.eq_ignore_ascii_case("socks") && !value.contains("://") {
                    format!("socks5://{value}")
                } else {
                    value.to_owned()
                };
            }
            if !selected.contains("://") {
                selected = format!("http://{selected}");
            }
            Some(selected)
        }),
    )
    .await
    .ok()?
    .ok()?
}

pub async fn handle_system() -> Response {
    // Discovery never returns userinfo or changes the active egress configuration.
    let url = system_proxy()
        .await
        .and_then(|value| egress::display_proxy_url(&value).ok())
        .unwrap_or_default();
    Json(json!({"enabled": !url.is_empty(), "url": url})).into_response()
}

pub async fn handle_probe_ports() -> Response {
    let ports = [
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
    let ports: Vec<_> = stream::iter(
        ports
            .into_iter()
            .map(|(port, label)| (port, label.to_owned()))
            .collect::<Vec<_>>(),
    )
    .map(probe_port)
    .buffered(9)
    .filter_map(|item| async move { item })
    .collect()
    .await;
    Json(json!({"ports": ports})).into_response()
}

async fn probe_port((port, label): (u16, String)) -> Option<serde_json::Value> {
    let open = matches!(
        tokio::time::timeout(
            Duration::from_millis(500),
            tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        )
        .await,
        Ok(Ok(_))
    );
    open.then(|| json!({"url": format!("http://127.0.0.1:{port}"), "port": port, "label": label}))
}
