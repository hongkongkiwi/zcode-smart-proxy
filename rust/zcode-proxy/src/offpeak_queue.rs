//! Server-side off-peak ticket queue.

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use futures_util::{stream, StreamExt};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{sync::mpsc, time::Instant};
use zcode_core::AccountView;

use crate::{account_refresh, auth::ResolvedKey, engine, state::AppState, streaming};

static ROTATION: AtomicU64 = AtomicU64::new(0);
const TIMEOUT: &str = "闲时排队超时，请稍后重试或改用 /v1/messages";
// Go relay.go maxAccountAttempts applies to the off-peak lane too.
const OFFPEAK_MAX_ACCOUNT_ATTEMPTS: usize = 5;

type Sender = mpsc::Sender<Result<Bytes, std::io::Error>>;

fn error(status: StatusCode, kind: &str, message: &str) -> Response {
    (
        status,
        Json(json!({"type":"error","error":{"type":kind,"message":message}})),
    )
        .into_response()
}

fn setting(state: &AppState, name: &str, default: u64) -> u64 {
    state
        .setting(name)
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|n| *n >= 0)
        .map(|n| n as u64)
        .unwrap_or(default)
}

pub(crate) async fn handle_messages(
    State(state): State<Arc<AppState>>,
    Extension(key): Extension<ResolvedKey>,
    method: Method,
    headers: HeaderMap,
    body: String,
) -> Response {
    if method != Method::POST {
        return error(
            StatusCode::METHOD_NOT_ALLOWED,
            "api_error",
            "method not allowed",
        );
    }
    if state.setting("async_enabled").as_deref() != Some("1") {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "api_error",
            "async (off-peak) channel is disabled; enable async_enabled in settings",
        );
    }
    if state.setting("gateway_paused").as_deref() == Some("1") {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "api_error",
            "网关已全局暂停（panic stop），请在管理面板恢复",
        );
    }
    let value: Value = match serde_json::from_str(&body) {
        Ok(value) => value,
        Err(_) => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "body is not valid JSON",
            )
        }
    };
    let Value::Object(mut obj) = value else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "body must be an object",
        );
    };
    let model = obj.get("model").and_then(Value::as_str).unwrap_or("");
    if model.starts_with("bigmodel/")
        || headers.get("x-provider").and_then(|v| v.to_str().ok()) == Some("bigmodel")
    {
        return error(
            StatusCode::BAD_REQUEST,
            "api_error",
            "async channel only supports zai accounts",
        );
    }
    let model = zcode_core::normalize_model_name(model, &[]).to_lowercase();
    obj.insert("model".into(), json!(model));
    obj.entry("max_tokens").or_insert(json!(4096));
    fix_thinking(&mut obj, &model);
    if let Some(response) = engine::named_key_gate(&key.named, &model) {
        return response;
    }
    let streaming = obj.get("stream").and_then(Value::as_bool).unwrap_or(false);
    obj.insert("stream".into(), json!(true));
    let wait = setting(&state, "async_max_wait_sec", 1800);
    let deadline = if wait == 0 {
        None
    } else {
        Instant::now().checked_add(Duration::from_secs(wait))
    };
    let opts = Options {
        state,
        headers,
        body: Value::Object(obj),
        key_id: key.named.as_ref().map_or(0, |k| k.id),
        deadline,
    };
    if !streaming {
        return run(opts, None).await;
    }
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(8);
    tokio::spawn(async move {
        let closed = tx.clone();
        tokio::select! { _ = run(opts, Some(tx)) => {}, _ = closed.closed() => {} }
    });
    let body = Body::from_stream(stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    }));
    (
        StatusCode::OK,
        [
            ("content-type", "text/event-stream"),
            ("cache-control", "no-cache"),
        ],
        body,
    )
        .into_response()
}

fn fix_thinking(obj: &mut serde_json::Map<String, Value>, model: &str) {
    let reasoning = obj.remove("reasoning_effort");
    if !model.contains("5.3") {
        return;
    }
    let disabled = obj
        .get("thinking")
        .and_then(|v| v.get("type"))
        .and_then(Value::as_str)
        == Some("disabled");
    let mut output = obj
        .get("output_config")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if disabled {
        obj.insert("thinking".into(), json!({"type":"disabled"}));
        output.remove("effort");
        if output.is_empty() {
            obj.remove("output_config");
        } else {
            obj.insert("output_config".into(), Value::Object(output));
        }
        return;
    }
    let requested = output
        .get("effort")
        .and_then(Value::as_str)
        .or_else(|| reasoning.as_ref().and_then(Value::as_str));
    let effort = match requested {
        Some("low" | "minimal") => "low",
        Some("max") => "max",
        Some(_) => "high",
        None => match obj
            .get("thinking")
            .and_then(|v| v.get("budget_tokens"))
            .and_then(Value::as_i64)
        {
            Some(n) if n >= 32768 => "max",
            Some(n) if n < 4096 => "low",
            _ => "high",
        },
    };
    output.insert("effort".into(), json!(effort));
    obj.insert("thinking".into(), json!({"type":"adaptive"}));
    obj.insert("output_config".into(), Value::Object(output));
}

struct Options {
    state: Arc<AppState>,
    headers: HeaderMap,
    body: Value,
    key_id: i64,
    deadline: Option<Instant>,
}

fn client(
    state: &AppState,
    account: &AccountView,
    control: bool,
) -> Result<reqwest::Client, String> {
    let mut builder = crate::egress::client_builder_for_group(state, &account.account_group)
        .map_err(|_| "client setup failed".to_owned())?;
    if control {
        builder = builder.timeout(Duration::from_secs(15));
    } else {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }
    builder.build().map_err(|_| "client setup failed".into())
}

fn device_mid(state: &AppState, account: &AccountView) -> Result<String, crate::store::StoreError> {
    let db = state.db.lock().unwrap();
    let identity = crate::account_billing::identity_snapshot(state, &db, account)?;
    if identity.device_mid.is_empty() {
        crate::identity::ensure_locked(&db, account.id)
    } else {
        Ok(identity.device_mid)
    }
}

fn identity(
    request: reqwest::RequestBuilder,
    state: &AppState,
    account: &AccountView,
    device: &str,
) -> reqwest::RequestBuilder {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        x => x,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        x => x,
    };
    let version = &state.management.app_version;
    let mut request = request
        .header("authorization", format!("Bearer {}", account.zcode_jwt))
        .header("user-agent", format!("ZCode/{version}"))
        .header("http-referer", "https://zcode.z.ai")
        .header("x-title", "Z Code@electron")
        .header("x-zcode-app-version", version)
        .header("x-platform", format!("{os}-{arch}"))
        .header("x-release-channel", "stable")
        .header("x-client-language", "zh-CN")
        .header(
            "x-client-timezone",
            iana_time_zone::get_timezone().unwrap_or_else(|_| "UTC".into()),
        )
        .header("x-os-category", if os == "win32" { "windows" } else { os })
        .header("x-request-id", account_refresh::request_id());
    if !account.api_key.is_empty() {
        request = request.header("x-coding-plan-api-key", &account.api_key);
    }
    if !device.is_empty() {
        request = request.header("x-device-mid", device);
    }
    request
}

async fn control(
    state: &AppState,
    account: &AccountView,
    device: &str,
    path: &str,
    body: Value,
) -> Result<Value, String> {
    let request = client(state, account, true)?
        .post(format!(
            "{}{}",
            state.offpeak_control_base.trim_end_matches('/'),
            path
        ))
        .json(&body);
    let response = identity(request, state, account, device)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = response.status();
    let bytes = streaming::collect_bounded(response, None).await?;
    if !status.is_success() {
        return Err(format!(
            "HTTP {}: {}",
            status.as_u16(),
            String::from_utf8_lossy(&bytes)
                .chars()
                .take(200)
                .collect::<String>()
        ));
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid JSON".to_owned())?;
    if let Some(code) = value.get("code") {
        if code.as_i64() != Some(0) {
            return Err(format!("business code {code}"));
        }
        if let Some(data) = value.get("data").filter(|v| v.is_object()) {
            return Ok(data.clone());
        }
    }
    Ok(value)
}

struct TicketGuard {
    state: Arc<AppState>,
    account: AccountView,
    device: String,
    id: String,
}
impl Drop for TicketGuard {
    fn drop(&mut self) {
        let state = self.state.clone();
        let mut account = self.account.clone();
        let id = self.id.clone();
        let device = self.device.clone();
        tokio::spawn(async move {
            let credentials = {
                let db = state.db.lock().unwrap();
                db.query_row(
                    "SELECT zcode_jwt,api_key FROM accounts WHERE id=?1",
                    [account.id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .ok()
                .and_then(|(jwt, key)| {
                    Some((
                        state.vault.decrypt(&jwt).ok()?,
                        state.vault.decrypt(&key).ok()?,
                    ))
                })
            };
            let Some((jwt, key)) = credentials else {
                return;
            };
            account.zcode_jwt = jwt;
            account.api_key = key;
            let Ok(client) = client(&state, &account, true) else {
                return;
            };
            let escaped: String = url::form_urlencoded::byte_serialize(id.as_bytes()).collect();
            let url = format!(
                "{}/ticket/{escaped}/settle",
                state.offpeak_control_base.trim_end_matches('/')
            );
            for attempt in 0..2 {
                if attempt > 0 {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
                match identity(client.post(&url), &state, &account, &device)
                    .send()
                    .await
                {
                    Ok(response) if response.status().as_u16() < 500 => return,
                    _ => {}
                }
            }
        });
    }
}

struct Ticket {
    id: String,
    state: String,
    active_deadline: i64,
    poll: u64,
}
fn ticket(value: &Value, poll: u64) -> Result<Ticket, String> {
    let id = value
        .get("ticket_id")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or("missing ticket_id")?;
    let state = value
        .get("state")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or("missing state")?;
    Ok(Ticket {
        id: id.into(),
        state: state.into(),
        active_deadline: value
            .get("active_deadline")
            .and_then(Value::as_i64)
            .unwrap_or(0),
        poll,
    })
}
fn advice(value: &Value, fallback: u64) -> u64 {
    value
        .get("next_poll_after")
        .and_then(Value::as_u64)
        .filter(|v| *v > 0)
        .map(|v| v.saturating_mul(1000).clamp(500, 300_000))
        .unwrap_or(fallback)
}
fn cool(state: &AppState, id: i64, seconds: i64) {
    if let Some(a) = state
        .accounts
        .lock()
        .unwrap()
        .iter_mut()
        .find(|a| a.id == id)
    {
        a.status = "cooling".into();
        a.cooling_until = engine::now_secs() + seconds;
    }
}

fn mark_failed(state: &AppState, id: i64, message: &str) {
    if let Err(error) = state.db.lock().unwrap().execute(
        "UPDATE accounts SET last_error=?1 WHERE id=?2",
        rusqlite::params![message, id],
    ) {
        eprintln!("account failure recording failed: {error}");
    }
}

fn mark_invalid(state: &AppState, account: &AccountView, message: &str) {
    let db = state.db.lock().unwrap();
    let mut accounts = state.accounts.lock().unwrap();
    let Some(current) = accounts
        .iter_mut()
        .find(|a| a.id == account.id && a.zcode_jwt == account.zcode_jwt)
    else {
        return;
    };
    let stored = db.query_row(
        "SELECT zcode_jwt FROM accounts WHERE id=?1",
        [account.id],
        |row| row.get::<_, String>(0),
    );
    if stored
        .ok()
        .and_then(|jwt| state.vault.decrypt(&jwt).ok())
        .is_none_or(|jwt| jwt != account.zcode_jwt)
    {
        return;
    }
    match db.execute(
        "UPDATE accounts SET status='invalid',cooling_until=0,last_error=?1 WHERE id=?2",
        rusqlite::params![message, account.id],
    ) {
        Ok(1) => {
            current.status = "invalid".into();
            current.cooling_until = 0;
        }
        Ok(_) => {}
        Err(error) => eprintln!("account invalidation failed: {error}"),
    }
}
async fn refresh_or_invalidate(state: &AppState, account: &AccountView, message: &str) {
    if account_refresh::refresh_account(state, account.id)
        .await
        .is_err()
    {
        mark_invalid(state, account, message);
    }
}

async fn emit(tx: &Option<Sender>, text: String) {
    if let Some(tx) = tx {
        let _ = tx.send(Ok(Bytes::from(text))).await;
    }
}
async fn fail(tx: &Option<Sender>, status: StatusCode, kind: &str, message: &str) -> Response {
    if tx.is_some() {
        emit(
            tx,
            format!(
                "event: error\ndata: {}\n\n",
                json!({"type":"error","error":{"type":kind,"message":message}})
            ),
        )
        .await;
    }
    error(status, kind, message)
}

async fn wait(
    duration: Duration,
    deadline: Option<Instant>,
    next: &mut Instant,
    keepalive: Duration,
    tx: &Option<Sender>,
) -> bool {
    let end = Instant::now() + duration;
    loop {
        let now = Instant::now();
        if deadline.is_some_and(|d| now >= d) {
            return false;
        }
        if now >= end {
            return true;
        }
        let until = deadline.map_or(end, |d| d.min(end));
        let until = if tx.is_some() {
            until.min(*next)
        } else {
            until
        };
        tokio::time::sleep_until(until).await;
        if tx.is_some() && Instant::now() >= *next {
            emit(tx, ": keepalive\n\n".into()).await;
            *next = Instant::now() + keepalive;
        }
    }
}

async fn run(opts: Options, tx: Option<Sender>) -> Response {
    let state = &opts.state;
    let poll = setting(state, "async_poll_interval_ms", 1000).clamp(500, 300_000);
    let keepalive = Duration::from_millis(setting(state, "async_keepalive_ms", 15000).max(3000));
    let retries = setting(state, "async_max_retries", 3);
    let mut next_keepalive = Instant::now() + keepalive;
    let group = opts
        .headers
        .get("x-zcode-group")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mut accounts: Vec<_> = state
        .accounts
        .lock()
        .unwrap()
        .iter()
        .filter(|a| {
            a.enabled
                && a.provider == "zai"
                && !a.zcode_jwt.is_empty()
                && (group.is_empty() || a.account_group.split(',').any(|g| g.trim() == group))
        })
        .cloned()
        .collect();
    if !accounts.is_empty() {
        let len = accounts.len();
        accounts.rotate_left((ROTATION.fetch_add(1, Ordering::Relaxed) as usize) % len);
    }
    let eligible = accounts.len();
    let mut reasons = Vec::new();
    let mut settled = HashSet::new();
    for (index, account) in accounts
        .into_iter()
        .take(OFFPEAK_MAX_ACCOUNT_ATTEMPTS)
        .enumerate()
    {
        if index > 0 {
            emit(&tx, ": switching account\n\n".into()).await;
        }
        let Ok(device) = device_mid(state, &account) else {
            reasons.push(format!("{}: device identity unavailable", account.email));
            continue;
        };
        let mut reason;
        let task = account_refresh::request_id();
        let mut attempt = 0;
        'retake: loop {
            if opts.deadline.is_some_and(|d| Instant::now() >= d) {
                return fail(&tx, StatusCode::SERVICE_UNAVAILABLE, "async_error", TIMEOUT).await;
            }
            // Like Go, the deadline is checked between control calls, not during a call.
            let data = match control(state, &account, &device, "/ticket", json!({"task_id":task}))
                .await
            {
                Ok(data) => data,
                Err(e) => {
                    reason = format!("闲时取票失败: {}", e.chars().take(160).collect::<String>());
                    if e.contains("HTTP 401") || e.contains("HTTP 403") {
                        refresh_or_invalidate(state, &account, &e).await;
                    } else if e.contains("HTTP 429") {
                        // Queue saturation does not cool an otherwise healthy account.
                    } else if e.contains("HTTP") {
                        mark_failed(state, account.id, &e);
                    } else {
                        cool(state, account.id, 60);
                    }
                    break 'retake;
                }
            };
            let mut current = match ticket(&data, advice(&data, poll)) {
                Ok(t) => t,
                Err(e) => {
                    reason = format!("闲时取票失败: {e}");
                    cool(state, account.id, 60);
                    break 'retake;
                }
            };
            let guard = if settled.insert(current.id.clone()) {
                Some(TicketGuard {
                    state: state.clone(),
                    account: account.clone(),
                    device: device.clone(),
                    id: current.id.clone(),
                })
            } else {
                None
            };
            let mut unknown = 0;
            let mut failures = 0;
            while current.state != "ready"
                && current.state != "active"
                && !matches!(current.state.as_str(), "settled" | "expired" | "not_found")
            {
                if !wait(
                    Duration::from_millis(current.poll),
                    opts.deadline,
                    &mut next_keepalive,
                    keepalive,
                    &tx,
                )
                .await
                {
                    drop(guard);
                    return fail(&tx, StatusCode::SERVICE_UNAVAILABLE, "async_error", TIMEOUT)
                        .await;
                }
                let data = match control(
                    state,
                    &account,
                    &device,
                    "/ticket/status",
                    json!({"ticket_ids":[current.id]}),
                )
                .await
                {
                    Ok(data) => data,
                    Err(e) => {
                        failures += 1;
                        if failures >= 5 {
                            drop(guard);
                            return fail(
                                &tx,
                                StatusCode::BAD_GATEWAY,
                                "async_error",
                                &format!("闲时查票连续失败: {e}"),
                            )
                            .await;
                        }
                        continue;
                    }
                };
                let found = data
                    .get("tickets")
                    .and_then(Value::as_array)
                    .and_then(|items| {
                        items.iter().find(|v| {
                            v.get("ticket_id").and_then(Value::as_str) == Some(current.id.as_str())
                        })
                    });
                match found.and_then(|v| ticket(v, advice(&data, poll)).ok()) {
                    Some(t) => {
                        current = t;
                        failures = 0;
                    }
                    None => {
                        failures += 1;
                        if failures >= 5 {
                            drop(guard);
                            return fail(
                                &tx,
                                StatusCode::BAD_GATEWAY,
                                "async_error",
                                "闲时查票连续失败: missing ticket",
                            )
                            .await;
                        }
                        continue;
                    }
                }
                if matches!(
                    current.state.as_str(),
                    "queued" | "ready" | "active" | "settled" | "expired" | "not_found"
                ) {
                    unknown = 0;
                } else {
                    unknown += 1;
                    if unknown >= 2 {
                        break;
                    }
                }
            }
            if !matches!(current.state.as_str(), "ready" | "active")
                || (current.active_deadline > 0 && engine::now_secs() > current.active_deadline)
            {
                drop(guard);
                if attempt >= retries {
                    reason = "闲时票被回收且重试次数用尽".into();
                    break 'retake;
                }
                attempt += 1;
                continue 'retake;
            }
            loop {
                let response = match forward(&opts, &account, &device, &current.id).await {
                    Ok(response) => response,
                    Err(e) => {
                        reason = format!(
                            "闲时通道连接失败: {}",
                            e.chars().take(160).collect::<String>()
                        );
                        cool(state, account.id, 60);
                        drop(guard);
                        break 'retake;
                    }
                };
                let status = response.status();
                let request_id = response.headers().get("x-request-id").cloned();
                if status.as_u16() >= 400 {
                    let cf_mitigated = response
                        .headers()
                        .get("cf-mitigated")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    let retry_after = response
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.trim().parse::<u64>().ok())
                        .filter(|v| (1..=45).contains(v))
                        .unwrap_or(15);
                    let bytes = streaming::collect_bounded(response, None)
                        .await
                        .unwrap_or_default();
                    let body = String::from_utf8_lossy(&bytes);
                    let code = serde_json::from_slice::<Value>(&bytes)
                        .ok()
                        .and_then(|v| v.get("code").and_then(Value::as_i64))
                        .unwrap_or(0);
                    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
                        drop(guard);
                        if zcode_core::is_cloudflare_challenge(cf_mitigated.as_deref(), &body) {
                            reason =
                                format!("Cloudflare/WAF 挑战 HTTP {}（闲时通道）", status.as_u16());
                            cool(state, account.id, 300);
                        } else {
                            reason = format!("闲时通道鉴权失败 HTTP {}", status.as_u16());
                            refresh_or_invalidate(state, &account, &reason).await;
                        }
                        break 'retake;
                    }
                    if status == StatusCode::TOO_MANY_REQUESTS && code == 3105 {
                        if attempt >= retries {
                            reason = "闲时通道同票重试预算用尽（429/3105）".into();
                            drop(guard);
                            break 'retake;
                        }
                        attempt += 1;
                        if !wait(
                            Duration::from_secs(retry_after),
                            opts.deadline,
                            &mut next_keepalive,
                            keepalive,
                            &tx,
                        )
                        .await
                        {
                            drop(guard);
                            return fail(
                                &tx,
                                StatusCode::SERVICE_UNAVAILABLE,
                                "async_error",
                                TIMEOUT,
                            )
                            .await;
                        }
                        continue;
                    }
                    if status == StatusCode::TOO_MANY_REQUESTS {
                        reason = "闲时通道限流 429".into();
                        cool(state, account.id, 30);
                        drop(guard);
                        break 'retake;
                    }
                    if status == StatusCode::BAD_REQUEST && matches!(code, 3102 | 3001) {
                        drop(guard);
                        if attempt >= retries {
                            reason = format!("票被上游回收（{code}）且重试次数用尽");
                            break 'retake;
                        }
                        attempt += 1;
                        continue 'retake;
                    }
                    drop(guard);
                    let msg = format!(
                        "闲时通道上游错误 HTTP {}: {}",
                        status.as_u16(),
                        body.chars().take(300).collect::<String>()
                    );
                    mark_failed(state, account.id, &msg);
                    let response = fail(&tx, status, "api_error", &msg).await;
                    return engine::terminal_response(state, account.id, opts.key_id, response, 0);
                }
                let sse = response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.contains("text/event-stream"));
                if !sse {
                    let bytes = streaming::collect_bounded(response, None)
                        .await
                        .unwrap_or_default();
                    cool(state, account.id, 120);
                    drop(guard);
                    let msg = format!(
                        "闲时通道上游返回异常内容 HTTP {}: {}",
                        status.as_u16(),
                        String::from_utf8_lossy(&bytes)
                            .chars()
                            .take(300)
                            .collect::<String>()
                    );
                    return fail(&tx, StatusCode::BAD_GATEWAY, "api_error", &msg).await;
                }
                // Streaming headers precede queueing, so only non-stream responses can forward x-request-id.
                if let Some(sender) = &tx {
                    let response =
                        streaming::response(response, state.clone(), account.id, opts.key_id);
                    let mut stream = response.into_body().into_data_stream();
                    while let Some(item) = stream.next().await {
                        match item {
                            Ok(bytes) => {
                                if sender.send(Ok(bytes)).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    drop(guard);
                    return StatusCode::OK.into_response();
                }
                let mut sniff = streaming::UsageSniffer::default();
                let result = streaming::collect_bounded(response, Some(&mut sniff))
                    .await
                    .and_then(|bytes| {
                        if let Some(error) = sniff.failure() {
                            return Err(error.to_owned());
                        }
                        zcode_core::aggregate_anthropic_stream(&mut std::io::Cursor::new(bytes))
                            .map(|(raw, _)| raw)
                            .map_err(|e| format!("upstream stream failed: {e}"))
                    });
                let mut response = match result {
                    Ok(raw) => (StatusCode::OK, [("content-type", "application/json")], raw)
                        .into_response(),
                    Err(e) => error(StatusCode::BAD_GATEWAY, "api_error", &e),
                };
                if let Some(id) = request_id {
                    response.headers_mut().insert("x-request-id", id);
                }
                drop(guard);
                return engine::terminal_response(
                    state,
                    account.id,
                    opts.key_id,
                    response,
                    sniff.charge(),
                );
            }
        }
        if reason.is_empty() {
            reason = account.status.clone();
        }
        let detail = format!("{}: {reason}", account.email);
        if !reasons.contains(&detail) {
            reasons.push(detail);
        }
    }
    let mut message = if eligible == 0 {
        "闲时通道暂无可用账号（全部禁用或无 JWT），请在后台检查账号状态".to_owned()
    } else if eligible > OFFPEAK_MAX_ACCOUNT_ATTEMPTS {
        format!("闲时通道已尝试 {} 个账号达到单次请求上限，其余账号本次未尝试，请稍后重试或改用 /v1/messages", OFFPEAK_MAX_ACCOUNT_ATTEMPTS)
    } else {
        "闲时通道暂不可用（所有账号取票失败），请稍后重试或改用 /v1/messages".to_owned()
    };
    let detail: String = reasons.join("；").chars().take(400).collect();
    if !detail.is_empty() {
        message.push_str(&format!("（最近失败原因: {detail}）"));
    }
    fail(
        &tx,
        StatusCode::SERVICE_UNAVAILABLE,
        "no_available_account",
        &message,
    )
    .await
}

async fn forward(
    opts: &Options,
    account: &AccountView,
    device: &str,
    ticket: &str,
) -> Result<reqwest::Response, String> {
    let mut body = opts.body.clone();
    if body.get("metadata").is_none() {
        body["metadata"] = json!({"user_id": json!({"device_id":device,"account_uuid":"","session_id":""}).to_string()});
    }
    let url = format!(
        "{}/api/v1/off-peak/anthropic/v1/messages",
        opts.state.offpeak_origin.trim_end_matches('/')
    );
    let mut request = identity(
        client(&opts.state, account, false)?.post(url),
        &opts.state,
        account,
        device,
    )
    .header("content-type", "application/json")
    .header("anthropic-version", engine::ANTHROPIC_VERSION)
    .header("x-zcode-agent", "glm")
    .header("x-off-peak-ticket-id", ticket)
    .header("accept", "text/event-stream");
    for (name, value) in &opts.headers {
        let name_str = name.as_str();
        if (matches!(
            name_str,
            "accept-language"
                | "cache-control"
                | "anthropic-beta"
                | "anthropic-dangerous-direct-browser-access"
                | "traceparent"
                | "tracestate"
                | "x-client-request-id"
                | "x-zcode-query-source"
                | "x-zcode-trace-id"
                | "bigmodel-target-type"
                | "bigmodel-organization"
                | "bigmodel-project"
        ) || name_str.starts_with("x-stainless-"))
            && value.len() <= 4096
        {
            request = request.header(name, value);
        }
    }
    request.json(&body).send().await.map_err(|e| e.to_string())
}
