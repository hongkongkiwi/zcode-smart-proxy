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
    body: String,
) -> Response {
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let password = v
        .get("password")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let hash = state.setting("admin_password_hash");
    if !password_ok(hash, password) {
        // Login failures are not rate-limited in this port yet (Go has a
        // bounded lockout); noted as a follow-up, never a silent gap.
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"success": false, "message": "invalid credentials"})),
        )
            .into_response();
    }
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
    next.run(req).await
}

pub async fn handle_accounts(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Response {
    let accounts = state.accounts.lock().unwrap().clone();
    let list: Vec<serde_json::Value> = accounts
        .iter()
        .map(|a| {
            json!({
                "id": a.id, "email": a.email, "provider": a.provider,
                "enabled": a.enabled, "status": a.status,
                "cooling_until": a.cooling_until, "remaining": a.remaining,
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({"accounts": list}))).into_response()
}

pub async fn handle_get_settings(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Response {
    let all = state.settings.lock().unwrap().clone();
    (StatusCode::OK, Json(all)).into_response()
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
    let mut updated = Vec::new();
    for (k, val) in map {
        if !SETTINGS_WHITELIST.contains(&k.as_str()) {
            continue;
        }
        let Some(s) = val.as_str() else { continue };
        state
            .settings
            .lock()
            .unwrap()
            .insert(k.clone(), s.to_string());
        {
            let db = state.db.lock().unwrap();
            store::set_setting(&db, k, s);
        }
        updated.push(k.clone());
    }
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

/// Admin-side usage insert helper shared with the engine (records to DB +
/// memory). Kept here so the engine's data path stays HTTP-only.
pub fn record_usage_db(state: &AppState, rec: UsageRecord) {
    {
        let db = state.db.lock().unwrap();
        store::insert_usage(
            &db,
            now_secs(),
            rec.account_id,
            rec.status,
            rec.gateway_key_id,
            rec.quota_charge,
        );
    }
    state.usage.lock().unwrap().push(rec);
}

pub fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())
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
