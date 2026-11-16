//! Account management routes (Go api_handlers.go accounts subset).

use axum::{
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use zcode_core::AccountView;

use crate::state::{AppState, Creds};

fn err(status: StatusCode, msg: &str) -> Response {
    (
        status,
        Json(json!({"error": {"message": msg, "type": "api_error"}})),
    )
        .into_response()
}

/// Import an account into the reduced Rust store, which is not vault-backed yet.
pub async fn handle_account_add(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    body: String,
) -> Response {
    let v: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "body is not valid JSON"),
    };
    let email = v
        .get("email")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    let provider = v
        .get("provider")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("zai")
        .to_string();
    let jwt = v
        .get("zcode_jwt")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    let api_key = v
        .get("api_key")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    if email.is_empty() {
        return err(StatusCode::BAD_REQUEST, "email is required");
    }
    let account = AccountView {
        id: 0,
        email: email.clone(),
        provider,
        enabled: true,
        status: zcode_core::STATUS_ACTIVE.into(),
        zcode_jwt: jwt.clone(),
        api_key: api_key.clone(),
        paid_fallback: !api_key.is_empty(),
        ..Default::default()
    };
    let id = {
        let db = state.db.lock().unwrap();
        crate::store::upsert_account(&db, &account, &jwt, &api_key)
    };
    let mut accounts = state.accounts.lock().unwrap();
    accounts.push(AccountView {
        id,
        email,
        provider: account.provider.clone(),
        enabled: true,
        status: zcode_core::STATUS_ACTIVE.into(),
        zcode_jwt: jwt.clone(),
        api_key: api_key.clone(),
        paid_fallback: !api_key.is_empty(),
        ..Default::default()
    });
    state.creds.lock().unwrap().insert(
        id,
        Creds {
            zcode_jwt: jwt,
            api_key,
        },
    );
    (StatusCode::OK, Json(json!({"ok": true, "id": id}))).into_response()
}

/// DELETE /api/accounts/{id}
pub async fn handle_account_delete(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Response {
    {
        let db = state.db.lock().unwrap();
        crate::store::delete_account(&db, id);
    }
    state.accounts.lock().unwrap().retain(|a| a.id != id);
    state.creds.lock().unwrap().remove(&id);
    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}

/// PUT /api/accounts/{id}/enabled — enable/disable toggle ({"enabled": true|false}).
pub async fn handle_account_enabled(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    body: String,
) -> Response {
    let v: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "body is not valid JSON"),
    };
    let enabled = v.get("enabled").and_then(serde_json::Value::as_bool);
    let Some(enabled) = enabled else {
        return err(StatusCode::BAD_REQUEST, "enabled must be a boolean");
    };
    {
        let db = state.db.lock().unwrap();
        crate::store::set_account_enabled(&db, id, enabled);
    }
    let mut accounts = state.accounts.lock().unwrap();
    if let Some(a) = accounts.iter_mut().find(|a| a.id == id) {
        a.enabled = enabled;
    }
    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}

/// POST /api/auth/password — change the admin password (current required).
pub async fn handle_password_change(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    body: String,
) -> Response {
    let v: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "body is not valid JSON"),
    };
    let current = v
        .get("current_password")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let new_pw = v
        .get("new_password")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if new_pw.len() < 8 {
        return err(
            StatusCode::BAD_REQUEST,
            "new password must be at least 8 characters",
        );
    }
    let hash = state.setting("admin_password_hash");
    let current_ok = match &hash {
        Some(h) if !h.is_empty() => bcrypt::verify(current, h).unwrap_or(false),
        None => true, // first-time bootstrap: no password set yet
        _ => false,
    };
    if !current_ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"message": "current password is incorrect"})),
        )
            .into_response();
    }
    let new_hash = bcrypt::hash(new_pw, bcrypt::DEFAULT_COST).unwrap();
    {
        let db = state.db.lock().unwrap();
        crate::store::set_setting(&db, "admin_password_hash", &new_hash);
    }
    state
        .settings
        .lock()
        .unwrap()
        .insert("admin_password_hash".into(), new_hash.clone());
    // Restart revokes sessions (Go parity).
    state.sessions.lock().unwrap().clear();
    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}

use std::sync::Arc;
