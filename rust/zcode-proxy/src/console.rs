//! Embedded web console and the panel endpoints without a better home.
//! Assets are compiled in with include_str! so the binary stays self-contained.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, Extension, Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use crate::auth::now_secs;
use crate::state::AppState;

const INDEX_HTML: &str = include_str!("../web/index.html");
const APP_JS: &str = include_str!("../web/static/app.js");
const STYLE_CSS: &str = include_str!("../web/static/style.css");
const I18N_JS: &str = include_str!("../web/static/i18n.js");

const CACHE_CONTROL: &str = "no-cache, must-revalidate";
const HTML_TYPE: &str = "text/html; charset=utf-8";

fn index() -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HTML_TYPE),
            (header::CACHE_CONTROL, CACHE_CONTROL),
        ],
        INDEX_HTML,
    )
        .into_response()
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CACHE_CONTROL, CACHE_CONTROL)],
        "",
    )
        .into_response()
}

fn storage_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"message": "storage operation failed"})),
    )
        .into_response()
}

fn peer_ip(peer: Option<Extension<ConnectInfo<SocketAddr>>>) -> String {
    peer.map(|Extension(ConnectInfo(addr))| addr.ip().to_string())
        .unwrap_or_else(|| "local".into())
}

fn valid_username(name: &str) -> bool {
    (3..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'-'))
}

fn generated_api_key() -> String {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("sk-{hex}")
}

fn masked_api_key(key: &str) -> String {
    if key.len() <= 12 {
        return "****".into();
    }
    match (key.get(..8), key.get(key.len() - 4..)) {
        (Some(head), Some(tail)) => format!("{head}…{tail}"),
        _ => "****".into(),
    }
}

/// GET /web, /web/ and any unmatched /web/<path>: the console index.
pub async fn handle_index() -> Response {
    index()
}

/// GET /web/static/<name>: exact match against the embedded assets.
pub async fn handle_static(Path(name): Path<String>) -> Response {
    if name.split('/').any(|segment| segment == "..") {
        return not_found();
    }
    let (body, content_type) = match name.as_str() {
        "app.js" => (APP_JS, "text/javascript; charset=utf-8"),
        "style.css" => (STYLE_CSS, "text/css; charset=utf-8"),
        "i18n.js" => (I18N_JS, "text/javascript; charset=utf-8"),
        _ => return not_found(),
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, CACHE_CONTROL),
        ],
        body,
    )
        .into_response()
}

/// GET /web/*path: console index fallback, rejecting static misses and traversal.
pub async fn handle_web_path(Path(path): Path<String>) -> Response {
    if path.split('/').any(|segment| segment == "..") || path.starts_with("static/") {
        return not_found();
    }
    index()
}

/// GET /api/auth/login-info (open): whether bootstrap defaults are still active.
pub async fn handle_login_info(State(state): State<Arc<AppState>>) -> Response {
    let initial_password = state.setting("admin_password_default").as_deref() == Some("1");
    let totp_enabled = state.setting("totp_enabled").as_deref() == Some("1");
    (
        StatusCode::OK,
        Json(json!({
            "initial_password": initial_password,
            "totp_enabled": totp_enabled,
        })),
    )
        .into_response()
}

/// GET /api/auth/totp/status
pub async fn handle_totp_status(State(state): State<Arc<AppState>>) -> Response {
    let enabled = state.setting("totp_enabled").as_deref() == Some("1");
    let remaining =
        zcode_core::recovery_codes_from_json(state.setting("recovery_codes").as_deref()).len();
    (
        StatusCode::OK,
        Json(json!({"enabled": enabled, "recovery_remaining": remaining})),
    )
        .into_response()
}

/// POST /api/auth/username
pub async fn handle_username_change(
    State(state): State<Arc<AppState>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: String,
) -> Response {
    let value: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let name = value
        .get("new_username")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if !valid_username(name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "username must be 3-32 characters of letters, digits, dot, underscore, dash or @"})),
        )
            .into_response();
    }
    let password = value
        .get("current_password")
        .and_then(Value::as_str)
        .unwrap_or("");
    let rate_key = format!("{}|username-change", peer_ip(peer));
    let mut guard = state.step_up_guard.lock().unwrap();
    if guard.check(&rate_key, now_secs()) > 0 {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"message": "too many attempts"})),
        )
            .into_response();
    }
    if !crate::admin::password_ok(state.setting("admin_password_hash"), password) {
        guard.record_failure(&rate_key, now_secs());
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"message": "current password incorrect"})),
        )
            .into_response();
    }
    if state.persist_settings(&[("admin_username", name)]).is_err() {
        return storage_error();
    }
    guard.clear(&rate_key);
    (
        StatusCode::OK,
        Json(json!({"username": name, "message": "username updated"})),
    )
        .into_response()
}

/// GET /api/settings/api-key: presence and mask only, never plaintext.
pub async fn handle_get_api_key(State(state): State<Arc<AppState>>) -> Response {
    let key = state.setting("api_key").unwrap_or_default();
    if key.is_empty() {
        return (StatusCode::OK, Json(json!({"has_api_key": false}))).into_response();
    }
    (
        StatusCode::OK,
        Json(json!({
            "has_api_key": true,
            "api_key_masked": masked_api_key(&key),
        })),
    )
        .into_response()
}

/// POST /api/settings/api-key/reveal
pub async fn handle_reveal_api_key(
    State(state): State<Arc<AppState>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: String,
) -> Response {
    let value: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let password = value
        .get("verify_password")
        .and_then(Value::as_str)
        .unwrap_or("");
    let rate_key = format!("{}|api-key-reveal", peer_ip(peer));
    let mut guard = state.step_up_guard.lock().unwrap();
    if guard.check(&rate_key, now_secs()) > 0 {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"message": "too many attempts"})),
        )
            .into_response();
    }
    if !crate::admin::password_ok(state.setting("admin_password_hash"), password) {
        guard.record_failure(&rate_key, now_secs());
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "current password incorrect"})),
        )
            .into_response();
    }
    guard.clear(&rate_key);
    drop(guard);
    let key = state.setting("api_key").unwrap_or_default();
    (
        StatusCode::OK,
        Json(json!({"has_api_key": !key.is_empty(), "api_key": key})),
    )
        .into_response()
}

/// POST /api/settings/api-key/generate
pub async fn handle_generate_api_key(
    State(state): State<Arc<AppState>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: String,
) -> Response {
    let value: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let password = value
        .get("verify_password")
        .and_then(Value::as_str)
        .unwrap_or("");
    let rate_key = format!("{}|api-key-generate", peer_ip(peer));
    let mut guard = state.step_up_guard.lock().unwrap();
    if guard.check(&rate_key, now_secs()) > 0 {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"message": "too many attempts"})),
        )
            .into_response();
    }
    if !crate::admin::password_ok(state.setting("admin_password_hash"), password) {
        guard.record_failure(&rate_key, now_secs());
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "current password incorrect"})),
        )
            .into_response();
    }
    let key = generated_api_key();
    // Persist and publish under the publication lock; a failed write leaves
    // the previous key active.
    if state.rotate_root_key(&key).is_err() {
        return storage_error();
    }
    guard.clear(&rate_key);
    drop(guard);
    (
        StatusCode::OK,
        Json(json!({"api_key": key, "message": "API key generated"})),
    )
        .into_response()
}

/// GET /api/dashboard
pub async fn handle_dashboard(State(state): State<Arc<AppState>>) -> Response {
    let now = now_secs();
    let mut status_count: BTreeMap<String, i64> = BTreeMap::new();
    let mut group_count: BTreeMap<String, i64> = BTreeMap::new();
    let mut total_remaining = 0.0f64;
    let mut selectable = 0usize;
    let total = {
        let accounts = state.accounts.lock().unwrap();
        for account in accounts.iter() {
            let status = zcode_core::selection::effective_status(
                &account.status,
                account.cooling_until,
                now,
            );
            *status_count.entry(status).or_insert(0) += 1;
            let group = if account.account_group.is_empty() {
                "未分组"
            } else {
                account.account_group.as_str()
            };
            *group_count.entry(group.to_owned()).or_insert(0) += 1;
            total_remaining += account.remaining;
            if account.enabled
                && zcode_core::selection::account_selectable(
                    &account.status,
                    account.cooling_until,
                    now,
                )
            {
                selectable += 1;
            }
        }
        accounts.len()
    };
    let gateway_paused = state.setting("gateway_paused").as_deref() == Some("1");
    (
        StatusCode::OK,
        Json(json!({
            "account_total": total,
            "account_selectable": selectable,
            "status_count": status_count,
            "group_count": group_count,
            "total_remaining": total_remaining,
            "usage_7d": crate::admin::stats_json(&state),
            "gateway_paused": gateway_paused,
            "captcha": {"available": false, "reason": "not ported"},
            "app_version": "",
        })),
    )
        .into_response()
}

fn collect_groups(groups: &mut BTreeSet<String>, value: &str) {
    for part in value.split(',') {
        let part = part.trim();
        if !part.is_empty() {
            groups.insert(part.to_owned());
        }
    }
}

/// GET /api/groups: account groups plus proxy-node groups, sorted and deduplicated.
pub async fn handle_groups(State(state): State<Arc<AppState>>) -> Response {
    let mut groups = BTreeSet::new();
    {
        let accounts = state.accounts.lock().unwrap();
        for account in accounts.iter() {
            collect_groups(&mut groups, &account.account_group);
        }
    }
    let proxy_groups = {
        let db = state.db.lock().unwrap();
        let query = || -> rusqlite::Result<Vec<String>> {
            let mut stmt = db.prepare("SELECT COALESCE(group_name, '') FROM proxy_nodes")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect()
        };
        match query() {
            Ok(values) => values,
            Err(_) => return storage_error(),
        }
    };
    for value in &proxy_groups {
        collect_groups(&mut groups, value);
    }
    (
        StatusCode::OK,
        Json(json!({"groups": groups.into_iter().collect::<Vec<_>>()})),
    )
        .into_response()
}

/// GET /api/fingerprints
pub async fn handle_fingerprints() -> Response {
    let list: Vec<Value> = crate::engine::TLS_FINGERPRINT_PRESETS
        .iter()
        .map(|(id, label, group)| json!({"id": id, "label": label, "group": group}))
        .collect();
    (StatusCode::OK, Json(json!({"fingerprints": list}))).into_response()
}

/// GET /api/models: the same catalog the data plane serves.
pub async fn handle_models() -> Response {
    (
        StatusCode::OK,
        Json(json!({"models": crate::engine::MODEL_IDS})),
    )
        .into_response()
}
