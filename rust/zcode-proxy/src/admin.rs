//! Admin surface: session auth (in-memory, restart revokes — Go parity),
//! login with the bcrypt password hash from settings, and the management
//! endpoints (accounts, settings whitelist, usage, stats).

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::auth::now_secs;
use crate::state::{AppState, UsageRecord};
use crate::store;

pub const SESSION_TTL_SECS: i64 = 86_400;
pub const SESSION_COOKIE: &str = "zcode_rs_session";

fn storage_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"message": "storage operation failed"})),
    )
        .into_response()
}

/// Login lockout (Go auth.go parity): after LOCKOUT_THRESHOLD failures from
/// one client within the window, further attempts are rejected until the
/// window lapses. Bounded per-client state; stale clients are pruned when
/// the map balloons.
const LOCKOUT_THRESHOLD: usize = 5;
const LOCKOUT_WINDOW_SECS: i64 = 900;

/// Require a serialized HTTP(S) origin whose authority matches Host, including port.
fn origin_allowed(headers: &axum::http::HeaderMap) -> bool {
    let mut origins = headers.get_all("origin").iter();
    let Some(origin) = origins.next() else {
        return true;
    };
    if origins.next().is_some() {
        return false;
    }
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    let Some((scheme, authority)) = origin.split_once("://") else {
        return false;
    };
    if !matches!(scheme, "http" | "https")
        || authority.is_empty()
        || authority.contains(['/', '?', '#', '@', '\\'])
        || reqwest::Url::parse(origin).is_err()
    {
        return false;
    }
    let mut hosts = headers.get_all("host").iter();
    let Some(host) = hosts.next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    hosts.next().is_none()
        && host.parse::<axum::http::uri::Authority>().is_ok()
        && authority.eq_ignore_ascii_case(host)
}

#[derive(Default)]
pub struct LoginGuard {
    /// client key -> (failure count, first failure unix secs)
    failures: std::collections::HashMap<String, (usize, i64)>,
}

impl LoginGuard {
    /// Returns remaining lockout seconds (0 = attempt allowed).
    pub fn check(&mut self, client: &str, now_unix: i64) -> i64 {
        self.failures
            .retain(|_, (_, first)| now_unix - *first < LOCKOUT_WINDOW_SECS);
        match self.failures.get(client) {
            Some((count, first)) if *count >= LOCKOUT_THRESHOLD => {
                (first + LOCKOUT_WINDOW_SECS - now_unix).max(0)
            }
            _ => 0,
        }
    }

    pub fn record_failure(&mut self, client: &str, now_unix: i64) {
        self.failures
            .retain(|_, (_, first)| now_unix - *first < LOCKOUT_WINDOW_SECS);
        if self.failures.len() >= 4096 && !self.failures.contains_key(client) {
            if let Some(oldest) = self.failures.iter().min_by_key(|(_, (_, first))| *first) {
                let key = oldest.0.clone();
                self.failures.remove(&key);
            }
        }
        let entry = self
            .failures
            .entry(client.to_string())
            .or_insert((0, now_unix));
        entry.0 += 1;
    }

    pub fn clear(&mut self, client: &str) {
        self.failures.remove(client);
    }
}

fn token() -> String {
    // CSPRNG (OsRng = OS entropy): session tokens are bearer credentials.
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn password_ok(hash: Option<String>, password: &str) -> bool {
    match hash {
        Some(h) if !h.is_empty() => bcrypt::verify(password, &h).unwrap_or(false),
        _ => false,
    }
}

pub async fn handle_login(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    peer: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    body: String,
) -> Response {
    if !origin_allowed(&headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"success": false, "message": "cross-origin request rejected"})),
        )
            .into_response();
    }
    // Proxied clients share the proxy's bucket; forwarded headers are untrusted.
    let client = peer
        .map(|axum::Extension(axum::extract::ConnectInfo(addr))| addr.ip().to_string())
        .unwrap_or_else(|| "local".into());
    let wait = state.login_guard.lock().unwrap().check(&client, now_secs());
    if wait > 0 {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"success": false,
                "message": format!("尝试过于频繁，请 {} 秒后再试", wait + 1)})),
        )
            .into_response();
    }
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let password = v
        .get("password")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let hash = state.setting("admin_password_hash");
    if !password_ok(hash, password) {
        state
            .login_guard
            .lock()
            .unwrap()
            .record_failure(&client, now_secs());
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"success": false, "message": "invalid credentials"})),
        )
            .into_response();
    }
    // Second factor: when a TOTP secret is enrolled+enabled, the login body
    // must carry a current TOTP code or an unused recovery code (single-use,
    // consumed on success). Missing/invalid = 401, same shape as above.
    if state.setting("totp_enabled").as_deref() == Some("1") {
        let code = v
            .get("code")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let mut second_ok = false;
        if let Some(secret_b32) = state.setting("totp_secret") {
            if let Some(secret) = zcode_core::base32_decode(&secret_b32) {
                second_ok = zcode_core::totp_verify(&secret, now_secs(), code);
            }
        }
        if !second_ok {
            second_ok = match state.consume_recovery_code(code) {
                Ok(consumed) => consumed,
                Err(_) => return storage_error(),
            };
        }
        if !second_ok {
            state
                .login_guard
                .lock()
                .unwrap()
                .record_failure(&client, now_secs());
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"success": false, "message": "second factor required"})),
            )
                .into_response();
        }
    }
    state.login_guard.lock().unwrap().clear(&client);
    let t = token();
    state
        .sessions
        .lock()
        .unwrap()
        .insert(t.clone(), now_secs() + SESSION_TTL_SECS);
    let mut resp = (
        StatusCode::OK,
        Json(json!({"success": true, "username": "admin"})),
    )
        .into_response();
    resp.headers_mut().insert(
        "set-cookie",
        format!(
            "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL_SECS}",
            SESSION_COOKIE, t
        )
        .parse()
        .unwrap(),
    );
    resp
}

pub async fn handle_logout(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Some(t) = session_token(&headers) {
        state.sessions.lock().unwrap().remove(&t);
    }
    let mut resp = (StatusCode::OK, Json(json!({"message": "logout success"}))).into_response();
    resp.headers_mut().insert(
        "set-cookie",
        format!("{SESSION_COOKIE}=; Path=/; HttpOnly; Max-Age=-1")
            .parse()
            .unwrap(),
    );
    resp
}

pub async fn handle_check(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let ok = session_token(&headers)
        .map(|t| state.sessions.lock().unwrap().contains_key(&t))
        .unwrap_or(false);
    (StatusCode::OK, Json(json!({"authenticated": ok}))).into_response()
}

pub fn session_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookie = headers.get("cookie")?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(&format!("{SESSION_COOKIE}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

/// /api/* session gate (except /api/login, mounted outside this layer).
pub async fn require_session_mw(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let ok = session_token(req.headers())
        .map(|t| {
            let mut s = state.sessions.lock().unwrap();
            match s.get(&t) {
                Some(&exp) if exp > now_secs() => true,
                Some(_) => {
                    s.remove(&t);
                    false
                }
                None => false,
            }
        })
        .unwrap_or(false);
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": {"message": "unauthorized", "type": "api_error"}})),
        )
            .into_response();
    }
    if !matches!(
        *req.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    ) && !origin_allowed(req.headers())
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"success": false, "message": "cross-origin request rejected"})),
        )
            .into_response();
    }
    next.run(req).await
}

pub async fn handle_accounts(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Response {
    let db = state.db.lock().unwrap();
    let remarks = (|| -> rusqlite::Result<std::collections::HashMap<i64, String>> {
        let mut stmt = db.prepare("SELECT id, remark FROM accounts")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect()
    })();
    let remarks = match remarks {
        Ok(remarks) => remarks,
        Err(_) => return storage_error(),
    };
    let accounts = state.accounts.lock().unwrap().clone();
    let list: Vec<serde_json::Value> = accounts
        .iter()
        .map(|a| {
            json!({
                "id": a.id, "email": a.email, "provider": a.provider,
                "enabled": a.enabled, "status": a.status,
                "cooling_until": a.cooling_until, "remaining": a.remaining,
                "group": a.account_group, "remark": remarks.get(&a.id).map(String::as_str).unwrap_or(""),
                "priority": a.priority, "paid_fallback": a.paid_fallback,
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({"accounts": list}))).into_response()
}

pub async fn handle_get_settings(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Response {
    let settings = state.settings.lock().unwrap();
    let public: std::collections::HashMap<_, _> = settings
        .iter()
        .filter(|(key, _)| SETTINGS_WHITELIST.contains(&key.as_str()))
        .collect();
    (StatusCode::OK, Json(public)).into_response()
}

/// Settings whitelist (Go settingsWhitelist subset the port honors).
const SETTINGS_WHITELIST: &[&str] = &[
    "paid_fallback_mode",
    "selection_strategy",
    "sticky_sessions",
    "gateway_paused",
];

pub async fn handle_put_settings(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    body: String,
) -> Response {
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let Some(map) = v.as_object() else {
        return (StatusCode::BAD_REQUEST, "invalid body").into_response();
    };
    for (key, value) in map {
        if !SETTINGS_WHITELIST.contains(&key.as_str()) {
            continue;
        }
        let valid = matches!(
            (key.as_str(), value.as_str()),
            ("gateway_paused" | "sticky_sessions", Some("0" | "1"))
                | (
                    "paid_fallback_mode",
                    Some("free_first" | "balanced" | "never")
                )
                | (
                    "selection_strategy",
                    Some("random" | "round_robin" | "best_quota" | "priority")
                )
        );
        if !valid {
            return (StatusCode::BAD_REQUEST, "invalid setting value").into_response();
        }
    }
    let values: Vec<_> = map
        .iter()
        .filter(|(key, _)| SETTINGS_WHITELIST.contains(&key.as_str()))
        .map(|(key, value)| (key.as_str(), value.as_str().unwrap()))
        .collect();
    if state.persist_settings(&values).is_err() {
        return storage_error();
    }
    let updated: Vec<_> = values.iter().map(|(key, _)| *key).collect();
    (StatusCode::OK, Json(json!({"updated": updated}))).into_response()
}

pub async fn handle_usage(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Response {
    let rows = {
        let db = state.db.lock().unwrap();
        store::list_usage(&db, 50)
    };
    let list: Vec<serde_json::Value> = rows
        .iter()
        .map(|(ts, acct, st, gk, charge)| {
            json!({"created_at": ts, "account_id": acct, "status": st,
                   "gateway_key_id": gk, "quota_charge": charge})
        })
        .collect();
    (StatusCode::OK, Json(json!({"records": list}))).into_response()
}

pub async fn handle_stats(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Response {
    let accounts = state.accounts.lock().unwrap().len();
    let active = state
        .accounts
        .lock()
        .unwrap()
        .iter()
        .filter(|a| a.status == "active" && a.enabled)
        .count();
    let keys = state.named_keys.lock().unwrap().len();
    let usage_rows = {
        let db = state.db.lock().unwrap();
        store::list_usage(&db, 1000)
    };
    let total_charge: i64 = usage_rows.iter().map(|r| r.4).sum();
    (
        StatusCode::OK,
        Json(json!({
            "accounts": accounts, "active_accounts": active,
            "gateway_keys": keys, "total_quota_charge": total_charge,
        })),
    )
        .into_response()
}

/// Publish memory mirrors only after the usage row and key debit commit.
pub fn record_usage_db(state: &AppState, rec: UsageRecord) -> rusqlite::Result<()> {
    let mut db = state.db.lock().unwrap();
    let balance = store::record_usage(&mut db, now_secs(), &rec)?;
    if rec.gateway_key_id > 0 {
        if balance.is_none() {
            eprintln!(
                "usage recorded without durable key debit: missing key {}",
                rec.gateway_key_id
            );
        }
        if let Some(key) = state
            .named_keys
            .lock()
            .unwrap()
            .iter_mut()
            .find(|key| key.id == rec.gateway_key_id)
        {
            if let Some(balance) = balance {
                key.quota_used = balance;
            } else {
                // Legacy fixtures inject synthetic keys with no durable row.
                key.quota_used += rec.quota_charge;
            }
        }
    }
    let mut usage = state.usage.lock().unwrap();
    usage.push(rec);
    let excess = usage
        .len()
        .saturating_sub(crate::state::MAX_MEMORY_USAGE_RECORDS);
    usage.drain(..excess);
    Ok(())
}

pub fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())
}

/// TOTP enrollment: generate a pending secret + otpauth URL (not enabled
/// until confirm).
pub async fn handle_totp_setup(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    _body: String,
) -> Response {
    if session_token(&headers)
        .map(|t| !state.sessions.lock().unwrap().contains_key(&t))
        .unwrap_or(true)
    {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let secret = zcode_core::new_totp_secret();
    let email = state
        .setting("admin_username")
        .unwrap_or_else(|| "admin".into());
    let expires_at = (now_secs() + 600).to_string();
    if state
        .persist_settings(&[
            ("totp_secret_pending", &secret),
            ("totp_setup_expires_at", &expires_at),
        ])
        .is_err()
    {
        return storage_error();
    }
    (
        StatusCode::OK,
        Json(json!({
            "secret": secret,
            "otpauth_url": zcode_core::otpauth_url(&secret, &email),
        })),
    )
        .into_response()
}

/// Confirm enrollment with current-password step-up and a fresh pending code.
pub async fn handle_totp_confirm(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    peer: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    body: String,
) -> Response {
    if session_token(&headers)
        .map(|t| !state.sessions.lock().unwrap().contains_key(&t))
        .unwrap_or(true)
    {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let client = peer
        .map(|axum::Extension(axum::extract::ConnectInfo(addr))| addr.ip().to_string())
        .unwrap_or_else(|| "local".into());
    let rate_key = format!("{client}|totp-confirm");
    // Serialize admission through commit so concurrent proofs cannot bypass the limit.
    let mut guard = state.step_up_guard.lock().unwrap();
    if guard.check(&rate_key, now_secs()) > 0 {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"message": "too many attempts"})),
        )
            .into_response();
    }
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let password = v
        .get("current_password")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let code = v
        .get("code")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let mut db = state.db.lock().unwrap();
    let mut settings = state.settings.lock().unwrap();
    if password.is_empty() || !password_ok(settings.get("admin_password_hash").cloned(), password) {
        guard.record_failure(&rate_key, now_secs());
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"message": "current password incorrect"})),
        )
            .into_response();
    }
    let now = now_secs();
    let deadline = settings
        .get("totp_setup_expires_at")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    let Some(secret_b32) = settings
        .get("totp_secret_pending")
        .filter(|s| !s.is_empty() && deadline > now)
        .cloned()
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "setup expired, start again"})),
        )
            .into_response();
    };
    let valid = zcode_core::base32_decode(&secret_b32)
        .is_some_and(|secret| zcode_core::totp_verify(&secret, now, code));
    if !valid {
        guard.record_failure(&rate_key, now_secs());
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "code did not verify"})),
        )
            .into_response();
    }
    let existing =
        zcode_core::recovery_codes_from_json(settings.get("recovery_codes").map(String::as_str));
    let (plain, recovery) = if existing.is_empty() {
        let (plain, hashes) = zcode_core::generate_recovery_codes(10);
        (Some(plain), zcode_core::recovery_codes_to_json(&hashes))
    } else {
        (None, zcode_core::recovery_codes_to_json(&existing))
    };
    if state
        .persist_settings_locked(
            &mut db,
            &mut settings,
            &[
                ("totp_secret", &secret_b32),
                ("totp_enabled", "1"),
                ("recovery_codes", &recovery),
                ("totp_secret_pending", ""),
                ("totp_setup_expires_at", ""),
            ],
        )
        .is_err()
    {
        return storage_error();
    }
    guard.clear(&rate_key);
    (
        StatusCode::OK,
        Json(json!({"enabled": true, "recovery_codes": plain})),
    )
        .into_response()
}

/// Disable 2FA with the current password and an active TOTP or recovery proof.
pub async fn handle_totp_disable(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    peer: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    body: String,
) -> Response {
    if session_token(&headers)
        .map(|t| !state.sessions.lock().unwrap().contains_key(&t))
        .unwrap_or(true)
    {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let client = peer
        .map(|axum::Extension(axum::extract::ConnectInfo(addr))| addr.ip().to_string())
        .unwrap_or_else(|| "local".into());
    let rate_key = format!("{client}|totp-disable");
    let mut guard = state.step_up_guard.lock().unwrap();
    if guard.check(&rate_key, now_secs()) > 0 {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"message": "too many attempts"})),
        )
            .into_response();
    }
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let password = v
        .get("current_password")
        .or_else(|| v.get("password"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let code = v
        .get("code")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let mut db = state.db.lock().unwrap();
    let mut settings = state.settings.lock().unwrap();
    if password.is_empty() || !password_ok(settings.get("admin_password_hash").cloned(), password) {
        guard.record_failure(&rate_key, now_secs());
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"message": "current password incorrect"})),
        )
            .into_response();
    }
    let totp_valid = settings
        .get("totp_secret")
        .and_then(|secret| zcode_core::base32_decode(secret))
        .is_some_and(|secret| zcode_core::totp_verify(&secret, now_secs(), code));
    let recovery =
        zcode_core::recovery_codes_from_json(settings.get("recovery_codes").map(String::as_str));
    // Validate without consuming: proof and all secret cleanup commit together.
    if !totp_valid && zcode_core::consume_recovery_code(&recovery, code).is_none() {
        guard.record_failure(&rate_key, now_secs());
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "code did not verify"})),
        )
            .into_response();
    }
    if state
        .persist_settings_locked(
            &mut db,
            &mut settings,
            &[
                ("totp_enabled", ""),
                ("totp_secret", ""),
                ("recovery_codes", ""),
                ("totp_secret_pending", ""),
                ("totp_setup_expires_at", ""),
            ],
        )
        .is_err()
    {
        return storage_error();
    }
    guard.clear(&rate_key);
    (StatusCode::OK, Json(json!({"enabled": false}))).into_response()
}

/// Minimal admin panel: a single functional page (no build step, no deps)
/// calling the JSON API above.
pub async fn handle_panel() -> Response {
    let html = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>zcode-proxy</title>
<style>
:root { color-scheme: light dark; }
body { font: 14px/1.5 ui-monospace, monospace; margin: 2rem; max-width: 60rem; }
h1 { font-size: 1.1rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid #8884; padding: 0.3rem 0.6rem; text-align: left; }
button, input, select { font: inherit; padding: 0.25rem 0.5rem; }
section { margin: 2rem 0; }
#msg { color: #b00; }
</style>
</head>
<body>
<h1>zcode-proxy (Rust port)</h1>
<section id="login-section">
  <h2>Login</h2>
  <input type="password" id="pw" placeholder="admin password">
  <button onclick="login()">Log in</button>
  <span id="msg"></span>
</section>
<section id="app" hidden>
  <h2>Stats</h2>
  <div id="stats"></div>
  <h2>Accounts</h2>
  <table id="accounts"><thead><tr><th>id</th><th>email</th><th>status</th><th>remaining</th></tr></thead><tbody></tbody></table>
  <h2>Usage (last 50)</h2>
  <table id="usage"><thead><tr><th>time</th><th>account</th><th>status</th><th>charge</th></tr></thead><tbody></tbody></table>
  <h2>Settings</h2>
  <div id="settings"></div>
  <button onclick="logout()">Log out</button>
</section>
<script>
let ok = false;
async function j(url, opts) { const r = await fetch(url, opts); return { status: r.status, body: await r.json().catch(() => null) }; }
async function login() {
  const pw = document.getElementById('pw').value;
  const r = await j('/api/login', { method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({ password: pw }) });
  if (r.status === 200) { ok = true; document.getElementById('login-section').hidden = true; document.getElementById('app').hidden = false; load(); }
  else { document.getElementById('msg').textContent = r.body?.message || 'login failed'; }
}
async function logout() { await j('/api/logout', { method: 'POST' }); location.reload(); }
async function load() {
  const [stats, accs, usage, settings] = await Promise.all([
    j('/api/stats'), j('/api/accounts'), j('/api/usage-records'), j('/api/settings'),
  ]);
  if (stats.status !== 200) { location.reload(); return; }
  document.getElementById('stats').textContent = JSON.stringify(stats.body);
  document.querySelector('#accounts tbody').innerHTML = (accs.body.accounts || []).map(a =>
    `<tr><td>${a.id}</td><td>${a.email}</td><td>${a.status}</td><td>${a.remaining}</td></tr>`).join('');
  document.querySelector('#usage tbody').innerHTML = (usage.body.records || []).map(u =>
    `<tr><td>${new Date(u.created_at * 1000).toLocaleString()}</td><td>${u.account_id}</td><td>${u.status}</td><td>${u.quota_charge}</td></tr>`).join('');
  document.getElementById('settings').textContent = JSON.stringify(settings.body);
}
load();
if (!ok) { /* session may still be valid: probe */ j('/api/auth/check').then(async r => {
  if (r.body?.authenticated) { document.getElementById('login-section').hidden = true; document.getElementById('app').hidden = false; load(); } });
}
</script>
</body>
</html>"#;
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

#[cfg(test)]
mod usage_tests {
    use super::*;

    #[test]
    fn memory_usage_keeps_newest_records_and_database_keeps_all() {
        let state = AppState::new(String::new(), AppState::upstream_from_env());
        let total = crate::state::MAX_MEMORY_USAGE_RECORDS + 7;
        for index in 0..total {
            record_usage_db(
                &state,
                UsageRecord {
                    account_id: index as i64,
                    status: 200,
                    gateway_key_id: 0,
                    quota_charge: 1,
                },
            )
            .unwrap();
        }
        let usage = state.usage.lock().unwrap();
        assert_eq!(usage.len(), crate::state::MAX_MEMORY_USAGE_RECORDS);
        assert_eq!(
            usage.iter().map(|rec| rec.account_id).collect::<Vec<_>>(),
            (7..total as i64).collect::<Vec<_>>()
        );
        let records = store::list_usage(&state.db.lock().unwrap(), total as i64 + 1);
        assert_eq!(records.len(), total);
        assert_eq!(records.first().unwrap().1, total as i64 - 1);
        assert_eq!(records.last().unwrap().1, 0);
    }
}
