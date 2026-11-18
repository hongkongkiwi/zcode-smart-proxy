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

/// Import an account with encrypted credentials in the reduced Rust store.
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
    let (jwt, api_key) = match (state.vault.decrypt(&jwt), state.vault.decrypt(&api_key)) {
        (Ok(jwt), Ok(key)) => (jwt, key),
        _ => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "credential storage operation failed",
            )
        }
    };
    let mut account = AccountView {
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
    let db = state.db.lock().unwrap();
    let id =
        match crate::store::insert_account_encrypted(&db, &state.vault, &account, &jwt, &api_key) {
            Ok(id) => id,
            Err(_) => {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "storage operation failed",
                )
            }
        };
    account.id = id;
    let mut accounts = state.accounts.lock().unwrap();
    accounts.push(account);
    state.creds.lock().unwrap().insert(
        id,
        Creds {
            zcode_jwt: jwt,
            api_key,
        },
    );
    (StatusCode::OK, Json(json!({"ok": true, "id": id}))).into_response()
}

#[derive(serde::Deserialize)]
struct AccountUpdate {
    group: Option<String>,
    remark: Option<String>,
    enabled: Option<bool>,
    priority: Option<i64>,
    paid_fallback: Option<bool>,
}

/// PUT /api/accounts/{id}
pub async fn handle_account_update(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Path(id): Path<i64>,
    body: String,
) -> Response {
    let update: AccountUpdate = match serde_json::from_str(&body) {
        Ok(update) => update,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid request body"),
    };
    if update.priority.is_some_and(|p| !(1..=9999).contains(&p)) {
        return err(
            StatusCode::BAD_REQUEST,
            "priority must be between 1 and 9999",
        );
    }
    let mut db = state.db.lock().unwrap();
    let result = (|| -> rusqlite::Result<bool> {
        let tx = db.transaction()?;
        let changed = tx.execute(
            "UPDATE accounts SET account_group = COALESCE(?1, account_group),
                remark = COALESCE(?2, remark), enabled = COALESCE(?3, enabled),
                paid_fallback = COALESCE(?4, paid_fallback),
                status = CASE WHEN ?3 = 0 THEN 'disabled'
                    WHEN ?3 = 1 AND status = 'disabled' THEN 'active'
                    ELSE status END
             WHERE id = ?5",
            rusqlite::params![
                update.group,
                update.remark,
                update.enabled,
                update.paid_fallback,
                id
            ],
        )?;
        if changed == 0 {
            return Ok(false);
        }
        if let Some(priority) = update.priority {
            tx.execute(
                "UPDATE accounts SET priority = ?1 WHERE id = ?2",
                rusqlite::params![priority, id],
            )?;
        }
        tx.commit()?;
        Ok(true)
    })();
    match result {
        Ok(true) => {
            if let Some(account) = state
                .accounts
                .lock()
                .unwrap()
                .iter_mut()
                .find(|a| a.id == id)
            {
                if let Some(group) = update.group {
                    account.account_group = group;
                }
                if let Some(enabled) = update.enabled {
                    account.enabled = enabled;
                    if !enabled {
                        account.status = zcode_core::STATUS_DISABLED.into();
                    } else if account.status == zcode_core::STATUS_DISABLED {
                        account.status = zcode_core::STATUS_ACTIVE.into();
                    }
                }
                if let Some(priority) = update.priority {
                    account.priority = priority;
                }
                if let Some(paid_fallback) = update.paid_fallback {
                    account.paid_fallback = paid_fallback;
                }
            }
            (StatusCode::OK, Json(json!({"success": true}))).into_response()
        }
        Ok(false) => err(StatusCode::NOT_FOUND, "account not found"),
        Err(_) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage operation failed",
        ),
    }
}

/// DELETE /api/accounts/{id}
pub async fn handle_account_delete(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Response {
    let db = state.db.lock().unwrap();
    match db.execute("DELETE FROM accounts WHERE id = ?1", [id]) {
        Ok(0) => return err(StatusCode::NOT_FOUND, "account not found"),
        Ok(_) => {}
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage operation failed",
            )
        }
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
    let db = state.db.lock().unwrap();
    match db.execute(
        "UPDATE accounts SET enabled = ?1,
            status = CASE WHEN ?1 = 0 THEN 'disabled'
                WHEN ?1 = 1 AND status = 'disabled' THEN 'active'
                ELSE status END
         WHERE id = ?2",
        rusqlite::params![enabled as i64, id],
    ) {
        Ok(0) => return err(StatusCode::NOT_FOUND, "account not found"),
        Ok(_) => {}
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage operation failed",
            )
        }
    }
    let mut accounts = state.accounts.lock().unwrap();
    if let Some(a) = accounts.iter_mut().find(|a| a.id == id) {
        a.enabled = enabled;
        if !enabled {
            a.status = zcode_core::STATUS_DISABLED.into();
        } else if a.status == zcode_core::STATUS_DISABLED {
            a.status = zcode_core::STATUS_ACTIVE.into();
        }
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
    if state
        .persist_settings(&[("admin_password_hash", &new_hash)])
        .is_err()
    {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage operation failed",
        );
    }
    // Restart revokes sessions (Go parity).
    state.sessions.lock().unwrap().clear();
    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}

use std::sync::Arc;
