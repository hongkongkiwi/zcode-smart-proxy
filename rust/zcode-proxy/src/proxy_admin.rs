//! Session-protected proxy node management. Passwords never enter public views.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use rusqlite::params;
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::{egress, state::AppState, store};

#[derive(Default, Deserialize)]
#[serde(default)]
struct NodeBody {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    host: String,
    port: i64,
    username: String,
    password: String,
    is_default: bool,
    group_name: String,
    enabled: bool,
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"message": message}))).into_response()
}

fn storage_error() -> Response {
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "storage operation failed",
    )
}

pub async fn handle_list(State(state): State<Arc<AppState>>) -> Response {
    let db = state.db.lock().unwrap();
    let nodes = match store::list_proxy_nodes(&db) {
        Ok(nodes) => nodes,
        Err(_) => return storage_error(),
    };
    let proxies: Vec<_> = nodes
        .iter()
        .map(|node| {
            let password = state.vault.decrypt(&node.password).map(Zeroizing::new);
            json!({
                "id": node.id,
                "name": node.name,
                "type": node.kind,
                "host": node.host,
                "port": node.port,
                "username": node.username,
                "has_password": password.as_ref().is_ok_and(|value| !value.is_empty()),
                "password_broken": password.is_err(),
                "is_default": node.is_default,
                "group_name": node.group_name,
                "enabled": node.enabled,
                "check_status": node.check_status,
                "check_latency": node.check_latency,
                "check_ip": node.check_ip,
                "check_msg": node.check_msg,
                "check_at": node.check_at,
                "created_at": node.created_at,
                "updated_at": node.updated_at,
            })
        })
        .collect();
    Json(json!({"proxies": proxies})).into_response()
}

pub async fn handle_create(State(state): State<Arc<AppState>>, body: String) -> Response {
    save(&state, None, &body)
}

pub async fn handle_update(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: String,
) -> Response {
    let Ok(id) = id.parse::<i64>() else {
        return error(StatusCode::BAD_REQUEST, "invalid id");
    };
    save(&state, Some(id), &body)
}

fn save(state: &AppState, id: Option<i64>, body: &str) -> Response {
    let body: NodeBody = match serde_json::from_str(body) {
        Ok(body) => body,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid body"),
    };
    if egress::validate_node(&body.kind, &body.host, body.port).is_err() {
        return error(StatusCode::BAD_REQUEST, "invalid proxy host, port or type");
    }
    let mut db = state.db.lock().unwrap();
    let tx = match db.transaction() {
        Ok(tx) => tx,
        Err(_) => return storage_error(),
    };
    if let Some(id) = id {
        let exists: bool = match tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM proxy_nodes WHERE id=?1)",
            [id],
            |r| r.get(0),
        ) {
            Ok(exists) => exists,
            Err(_) => return storage_error(),
        };
        if !exists {
            return error(StatusCode::NOT_FOUND, "proxy node not found");
        }
    }
    let password = match state.vault.encrypt(&body.password) {
        Ok(password) => password,
        Err(_) => return storage_error(),
    };
    if body.is_default
        && tx
            .execute("UPDATE proxy_nodes SET is_default=0 WHERE is_default=1", [])
            .is_err()
    {
        return storage_error();
    }
    let saved = if let Some(id) = id {
        // Empty PUT passwords leave the stored bytes intact, including broken ciphertext.
        tx.execute(
            "UPDATE proxy_nodes SET name=?1,type=?2,host=?3,port=?4,username=?5,
             password=CASE WHEN ?6='' THEN password ELSE ?6 END,
             is_default=?7,group_name=?8,enabled=?9,
             updated_at=datetime('now','localtime') WHERE id=?10",
            params![
                body.name,
                body.kind,
                body.host,
                body.port,
                body.username,
                password,
                body.is_default,
                body.group_name,
                body.enabled,
                id
            ],
        )
        .map(|_| id)
    } else {
        tx.execute(
            "INSERT INTO proxy_nodes(name,type,host,port,username,password,is_default,group_name,enabled)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![body.name, body.kind, body.host, body.port, body.username,
                password, body.is_default, body.group_name, body.enabled],
        )
        .map(|_| tx.last_insert_rowid())
    };
    let id = match saved {
        Ok(id) => id,
        Err(_) => return storage_error(),
    };
    if tx.commit().is_err() {
        return storage_error();
    }
    Json(json!({"success": true, "id": id})).into_response()
}

pub async fn handle_delete(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Ok(id) = id.parse::<i64>() else {
        return error(StatusCode::BAD_REQUEST, "invalid id");
    };
    let db = state.db.lock().unwrap();
    if db
        .execute("DELETE FROM proxy_nodes WHERE id=?1", [id])
        .is_err()
    {
        return storage_error();
    }
    Json(json!({"success": true})).into_response()
}
