//! Synchronous paste import. JWT claims are import data, not verified identity.

use std::sync::Arc;

use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    account_bundle::BundleAccount,
    state::{AppState, Creds},
    store,
};

const MAX_REQUEST: usize = 1 << 20;
const MAX_SECRET: usize = 256 << 10;

#[derive(Default, Deserialize)]
#[serde(default)]
struct PasteRequest {
    provider: String,
    name: String,
    secret: String,
    group: String,
}

fn error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({"error": {"message": message, "type": "api_error"}})),
    )
        .into_response()
}

fn looks_like_jwt(secret: &str) -> bool {
    let parts: Vec<_> = secret.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

fn user_id(provider: &str, secret: &str, is_jwt: bool) -> String {
    if is_jwt {
        if let Some(claims) = secret
            .split('.')
            .nth(1)
            .and_then(|payload| URL_SAFE_NO_PAD.decode(payload).ok())
            .and_then(|payload| serde_json::from_slice::<Value>(&payload).ok())
        {
            for key in ["user_id", "sub"] {
                if let Some(value) = claims
                    .get(key)
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty())
                {
                    return value.to_owned();
                }
            }
        }
    }
    let hash = Sha256::digest(format!("{provider}:{secret}").as_bytes());
    let suffix: String = hash[..8].iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{provider}-{suffix}")
}

pub async fn handle_import(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let body = match to_bytes(request.into_body(), MAX_REQUEST).await {
        Ok(body) => body,
        Err(_) => return error(StatusCode::BAD_REQUEST, "request too large"),
    };
    let request: PasteRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid request body"),
    };
    let secret = request.secret.trim();
    if secret.is_empty() || secret.len() > MAX_SECRET {
        return error(StatusCode::BAD_REQUEST, "invalid credential length");
    }
    let provider = if request.provider.is_empty() {
        "zai"
    } else {
        &request.provider
    };
    let is_jwt = provider == "zai" && looks_like_jwt(secret);
    let mut account = BundleAccount {
        user_id: user_id(provider, secret, is_jwt),
        display_name: request.name.trim().to_owned(),
        provider: provider.to_owned(),
        auth_type: if is_jwt { "jwt" } else { "apikey" }.into(),
        zcode_jwt: if is_jwt {
            secret.to_owned()
        } else {
            String::new()
        },
        api_key: if is_jwt {
            String::new()
        } else {
            secret.to_owned()
        },
        account_group: request.group,
        remark: "粘贴导入".into(),
        ..Default::default()
    };
    let public = json!({
        "user_id": account.user_id, "email": "", "display_name": account.display_name,
        "provider": account.provider, "auth_type": account.auth_type,
        "has_jwt": is_jwt, "has_api_key": !is_jwt, "has_access_token": false,
        "has_creds_snapshot": false, "status": "active", "raw_status": "active",
        "enabled": true, "group": account.account_group, "remark": account.remark,
        "priority": 100
    });
    if account
        .transform_credentials(|value| state.vault.encrypt(value))
        .is_err()
    {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "credential storage operation failed",
        );
    }
    let mut db = state.db.lock().unwrap();
    let mut accounts = state.accounts.lock().unwrap();
    let mut creds = state.creds.lock().unwrap();
    let result = match store::import_bundle_accounts_with_ids(&mut db, &state.vault, &[account]) {
        Ok(result) => result,
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "credential storage operation failed",
            )
        }
    };
    for (account, jwt, key) in result.accounts {
        creds.insert(
            account.id,
            Creds {
                zcode_jwt: jwt,
                api_key: key,
            },
        );
        if let Some(existing) = accounts.iter_mut().find(|a| a.id == account.id) {
            *existing = account;
        } else {
            accounts.push(account);
        }
    }
    let mut public = public;
    public["id"] = json!(result.ids[0]);
    Json(json!({"success": true, "account": public})).into_response()
}
