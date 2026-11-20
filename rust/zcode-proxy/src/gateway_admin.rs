//! Session-protected gateway key management. Plaintext is returned only on creation.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use serde_json::json;

use crate::{
    auth::{key_hash, now_secs},
    state::{AppState, NamedKey},
    store,
};

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"message": message}))).into_response()
}

fn storage_error() -> Response {
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "storage operation failed",
    )
}

#[derive(Default, Deserialize)]
struct KeyBody {
    name: Option<String>,
    enabled: Option<bool>,
    models: Option<String>,
    rpm_limit: Option<i64>,
    rate_5h: Option<i64>,
    rate_1d: Option<i64>,
    rate_7d: Option<i64>,
    quota_total: Option<i64>,
    verify_password: Option<String>,
}

fn normalize_models(models: &str) -> String {
    let mut normalized = Vec::new();
    for model in models.split(',') {
        let model = model.trim().to_lowercase();
        let model = model.split_once('/').map_or(model.as_str(), |(_, m)| m);
        let model = zcode_core::canonical_model_name(model).to_lowercase();
        if !model.is_empty() && !normalized.contains(&model) {
            normalized.push(model);
        }
    }
    normalized.join(",")
}

impl KeyBody {
    fn apply(&self, key: &mut NamedKey) -> Result<(), &'static str> {
        if let Some(name) = &self.name {
            key.name = name.trim().to_owned();
        }
        if key.name.is_empty() || key.name.len() > 64 {
            return Err("name is required and must not exceed 64 bytes");
        }
        if let Some(enabled) = self.enabled {
            key.enabled = enabled;
        }
        if let Some(models) = &self.models {
            key.models = normalize_models(models);
        }
        if let Some(rpm) = self.rpm_limit {
            if !(0..=100_000).contains(&rpm) {
                return Err("rpm_limit must be between 0 and 100000");
            }
            key.rpm_limit = rpm;
        }
        for (value, target) in [
            (self.rate_5h, &mut key.rate_5h),
            (self.rate_1d, &mut key.rate_1d),
            (self.rate_7d, &mut key.rate_7d),
        ] {
            if let Some(value) = value {
                if !(0..=10_000_000).contains(&value) {
                    return Err("rolling rate limits must be between 0 and 10000000");
                }
                *target = value;
            }
        }
        if let Some(quota) = self.quota_total {
            if quota < 0 {
                return Err("quota_total must not be negative");
            }
            key.quota_total = quota;
        }
        Ok(())
    }
}

pub async fn handle_list(State(state): State<Arc<AppState>>) -> Response {
    let db = state.db.lock().unwrap();
    match store::try_list_gateway_keys(&db) {
        Ok(rows) => {
            Json(json!({"keys": rows.iter().map(|row| row.public_view()).collect::<Vec<_>>()}))
                .into_response()
        }
        Err(_) => storage_error(),
    }
}

pub async fn handle_create(
    State(state): State<Arc<AppState>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: String,
) -> Response {
    let body: KeyBody = match serde_json::from_str(&body) {
        Ok(body) => body,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid body"),
    };
    let client = peer
        .map(|Extension(ConnectInfo(addr))| addr.ip().to_string())
        .unwrap_or_else(|| "local".into());
    let rate_key = format!("{client}|api-key-create");
    let mut guard = state.step_up_guard.lock().unwrap();
    if guard.check(&rate_key, now_secs()) > 0 {
        return error(StatusCode::TOO_MANY_REQUESTS, "too many attempts");
    }
    let mut db = state.db.lock().unwrap();
    // Keep the current password stable through commit, using the settings writer lock order.
    let settings = state.settings.lock().unwrap();
    let password = body.verify_password.as_deref().unwrap_or("");
    let valid = !password.is_empty()
        && settings
            .get("admin_password_hash")
            .filter(|hash| !hash.is_empty())
            .is_some_and(|hash| bcrypt::verify(password, hash).unwrap_or(false));
    if !valid {
        guard.record_failure(&rate_key, now_secs());
        return error(
            StatusCode::UNAUTHORIZED,
            "administrator password verification failed",
        );
    }
    guard.clear(&rate_key);
    let mut key = NamedKey {
        id: 0,
        name: String::new(),
        key_hash: String::new(),
        enabled: true,
        models: String::new(),
        rpm_limit: 0,
        rate_5h: 0,
        rate_1d: 0,
        rate_7d: 0,
        quota_total: 0,
        quota_used: 0,
    };
    if let Err(message) = body.apply(&mut key) {
        return error(StatusCode::BAD_REQUEST, message);
    }
    let tx = match db.transaction() {
        Ok(tx) => tx,
        Err(_) => return storage_error(),
    };
    let rows = match store::try_list_gateway_keys(&tx) {
        Ok(rows) => rows,
        Err(_) => return storage_error(),
    };
    if rows.iter().any(|row| row.key.name == key.name) {
        return error(StatusCode::CONFLICT, "gateway key name already exists");
    }
    let mut bytes = [0u8; 24];
    if OsRng.try_fill_bytes(&mut bytes).is_err() {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "key generation failed");
    }
    let plain = format!(
        "sk-{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    key.key_hash = key_hash(&plain);
    let prefix = format!("{}…", &plain[..10]);
    key.id = match store::create_gateway_key(&tx, &key, &prefix) {
        Ok(id) => id,
        Err(_) => return storage_error(),
    };
    let row = match store::try_list_gateway_keys(&tx)
        .map(|rows| rows.into_iter().find(|row| row.key.id == key.id))
    {
        Ok(Some(row)) => row,
        _ => return storage_error(),
    };
    let mut live = state.named_keys.lock().unwrap();
    if tx.commit().is_err() {
        return storage_error();
    }
    let mut public = row.public_view();
    live.push(row.key);
    public["key"] = json!(plain);
    Json(json!({"key": public, "message": "Save this key now; it is shown only once"}))
        .into_response()
}

pub async fn handle_update(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: String,
) -> Response {
    let Ok(id) = id.parse::<i64>() else {
        return error(StatusCode::BAD_REQUEST, "invalid id");
    };
    let mut db = state.db.lock().unwrap();
    let tx = match db.transaction() {
        Ok(tx) => tx,
        Err(_) => return storage_error(),
    };
    let rows = match store::try_list_gateway_keys(&tx) {
        Ok(rows) => rows,
        Err(_) => return storage_error(),
    };
    let Some(existing) = rows.iter().find(|row| row.key.id == id) else {
        return error(StatusCode::NOT_FOUND, "gateway key not found");
    };
    let body: KeyBody = match serde_json::from_str(&body) {
        Ok(body) => body,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid body"),
    };
    let mut key = existing.key.clone();
    if let Err(message) = body.apply(&mut key) {
        return error(StatusCode::BAD_REQUEST, message);
    }
    if rows
        .iter()
        .any(|row| row.key.id != id && row.key.name == key.name)
    {
        return error(StatusCode::CONFLICT, "gateway key name already exists");
    }
    if store::update_gateway_key(&tx, &key).is_err() {
        return storage_error();
    }
    let row = match store::try_list_gateway_keys(&tx)
        .map(|rows| rows.into_iter().find(|row| row.key.id == id))
    {
        Ok(Some(row)) => row,
        _ => return storage_error(),
    };
    let mut live = state.named_keys.lock().unwrap();
    if tx.commit().is_err() {
        return storage_error();
    }
    let public = row.public_view();
    if let Some(key) = live.iter_mut().find(|key| key.id == id) {
        *key = row.key;
    } else {
        live.push(row.key);
    }
    Json(json!({"key": public})).into_response()
}

pub async fn handle_delete(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Ok(id) = id.parse::<i64>() else {
        return error(StatusCode::BAD_REQUEST, "invalid id");
    };
    let mut db = state.db.lock().unwrap();
    let tx = match db.transaction() {
        Ok(tx) => tx,
        Err(_) => return storage_error(),
    };
    if store::delete_gateway_key(&tx, id).is_err() {
        return storage_error();
    }
    let mut live = state.named_keys.lock().unwrap();
    if tx.commit().is_err() {
        return storage_error();
    }
    live.retain(|key| key.id != id);
    state.windows.lock().unwrap().forget(id);
    Json(json!({"success": true})).into_response()
}
