//! Local desktop import. Unverified profile and JWT claims identify the imported row.

use std::{
    collections::HashMap,
    fs::File,
    io::{ErrorKind, Read},
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    account_bundle::BundleAccount,
    state::{AppState, Creds},
    store,
};

const MAX_REQUEST: usize = 16 << 10;
const MAX_FILE: usize = 1 << 20;
static IMPORT_JOBS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

#[derive(Default, Deserialize)]
#[serde(default)]
struct ImportRequest {
    group: String,
}

fn error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({"success": false, "error": {"message": message, "type": "api_error"}})),
    )
        .into_response()
}

fn read_file(path: &Path) -> Result<Option<String>, ()> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    if !file.metadata().map_err(|_| ())?.is_file() {
        return Err(());
    }
    let mut bytes = Vec::new();
    file.take((MAX_FILE + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > MAX_FILE {
        return Err(());
    }
    String::from_utf8(bytes).map(Some).map_err(|_| ())
}

fn local_path(selected: Option<PathBuf>) -> Result<PathBuf, ()> {
    if let Some(path) = selected {
        return Ok(path);
    }
    let variable = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let home = std::env::var_os(variable)
        .filter(|home| !home.is_empty())
        .ok_or(())?;
    // ImportFromLocalClient uses os.UserHomeDir, not ZCODE_SWITCH_HOME.
    Ok(PathBuf::from(home).join(".zcode/v2/credentials.json"))
}

fn string<'a>(value: &'a Value, keys: &[&str]) -> &'a str {
    keys.iter()
        .find_map(|key| {
            value
                .get(key)
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or("")
}

fn claims(token: &str) -> Value {
    let mut parts = token.split('.');
    let _ = parts.next();
    let payload = parts.next();
    if parts.next().is_none() || parts.next().is_some() {
        return Value::Null;
    }
    payload
        .and_then(|payload| URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok())
        .and_then(|payload| serde_json::from_slice(&payload).ok())
        .unwrap_or(Value::Null)
}

fn read_account(
    selected: Option<PathBuf>,
    secret: Option<&str>,
    group: String,
) -> Result<BundleAccount, ()> {
    let path = local_path(selected)?;
    let directory = path.parent().ok_or(())?;
    let raw = read_file(&path)?.ok_or(())?;
    let credentials: HashMap<String, String> = serde_json::from_str(&raw).map_err(|_| ())?;
    let decode = |key: &str| {
        crate::desktop_credentials::decrypt(
            credentials.get(key).map(String::as_str).unwrap_or(""),
            secret,
        )
    };
    let provider = decode("oauth:active_provider")?;
    let provider = if provider.is_empty() {
        "zai".to_owned()
    } else {
        provider
    };
    let jwt = decode("zcodejwttoken")?;
    let access = decode(&format!("oauth:{provider}:access_token"))?;
    let user_info = decode(&format!("oauth:{provider}:user_info"))?;
    if jwt.is_empty() && access.is_empty() {
        return Err(());
    }
    let profile: Value = serde_json::from_str(&user_info).unwrap_or(Value::Null);
    let jwt_claims = claims(&jwt);
    let access_claims = claims(&access);
    let user_id = [
        string(&profile, &["user_id", "id"]),
        string(&jwt_claims, &["user_id", "sub"]),
        string(&access_claims, &["user_id", "sub"]),
    ]
    .into_iter()
    .find(|id| !id.is_empty())
    .ok_or(())?
    .to_owned();
    let config = read_file(&directory.join("config.json")).ok().flatten();
    let mut api_key = String::new();
    if let Some(value) = config
        .as_ref()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
    {
        if let Some(providers) = value.get("provider").and_then(Value::as_object) {
            for (id, value) in providers {
                let key = value
                    .get("options")
                    .and_then(|options| options.get("apiKey"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if id.contains("coding-plan")
                    && id.contains(&provider)
                    && !key.is_empty()
                    && !key.starts_with("enc:")
                {
                    api_key = key.to_owned();
                    break;
                }
            }
        }
    }
    let telemetry = read_file(&directory.join("telemetry-state.json"))
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or(Value::Null);
    let mut snapshot = json!({"credentials.json": raw});
    if let Some(config) = config {
        snapshot["config.json"] = config.into();
    }
    Ok(BundleAccount {
        user_id,
        email: string(&profile, &["email"]).to_owned(),
        display_name: string(&profile, &["name", "username", "displayName"]).to_owned(),
        provider,
        auth_type: if jwt.is_empty() { "apikey" } else { "jwt" }.into(),
        access_token: access,
        zcode_jwt: jwt,
        api_key,
        user_info,
        device_mid: string(&telemetry, &["deviceMid"]).to_owned(),
        creds_raw: snapshot.to_string(),
        account_group: group,
        remark: "本地客户端导入".into(),
        ..Default::default()
    })
}

fn persist(state: &AppState, mut account: BundleAccount) -> Result<Value, ()> {
    let mut db = state.db.lock().unwrap();
    let mut accounts = state.accounts.lock().unwrap();
    let mut creds = state.creds.lock().unwrap();
    let previous = db.query_row(
        "SELECT email,display_name,account_group,access_token<>'' FROM accounts WHERE user_id=?1",
        [&account.user_id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, bool>(3)?)),
    ).optional().map_err(|_| ())?;
    let mut public = json!({
        "user_id": account.user_id, "email": account.email, "display_name": account.display_name,
        "provider": account.provider, "auth_type": account.auth_type,
        "has_access_token": !account.access_token.is_empty(), "has_jwt": !account.zcode_jwt.is_empty(),
        "has_api_key": !account.api_key.is_empty(), "has_creds_snapshot": true,
        "group": account.account_group, "remark": account.remark,
    });
    if let Some((email, name, group, has_access)) = previous {
        public["has_access_token"] = (has_access || !account.access_token.is_empty()).into();
        for (key, old) in [("email", email), ("display_name", name), ("group", group)] {
            if public[key] == "" {
                public[key] = old.into();
            }
        }
    }
    account
        .transform_credentials(|value| state.vault.encrypt(value))
        .map_err(|_| ())?;
    let result = store::import_bundle_accounts_with_ids(&mut db, &state.vault, &[account])
        .map_err(|_| ())?;
    let id = result.ids[0];
    for (account, jwt, key) in result.accounts {
        if account.id == id {
            public["id"] = id.into();
            public["has_jwt"] = (!jwt.is_empty()).into();
            public["has_api_key"] = (!key.is_empty()).into();
            public["status"] = zcode_core::effective_status(
                &account.status,
                account.cooling_until,
                crate::auth::now_secs(),
            )
            .into();
            public["raw_status"] = account.status.clone().into();
            public["enabled"] = account.enabled.into();
            public["priority"] = account.priority.into();
        }
        creds.insert(
            account.id,
            Creds {
                zcode_jwt: jwt,
                api_key: key,
            },
        );
        if let Some(existing) = accounts
            .iter_mut()
            .find(|existing| existing.id == account.id)
        {
            *existing = account;
        } else {
            accounts.push(account);
        }
    }
    Ok(public)
}

pub async fn handle_import(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let body = match to_bytes(request.into_body(), MAX_REQUEST).await {
        Ok(body) => body,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid local import request"),
    };
    let request = if body.is_empty() {
        ImportRequest::default()
    } else {
        let value = match serde_json::from_slice::<Value>(&body) {
            Ok(value) if value.is_object() => value,
            _ => return error(StatusCode::BAD_REQUEST, "invalid local import request"),
        };
        match serde_json::from_value::<ImportRequest>(value) {
            Ok(request) => request,
            Err(_) => return error(StatusCode::BAD_REQUEST, "invalid local import request"),
        }
    };
    let permit = match IMPORT_JOBS.acquire().await {
        Ok(permit) => permit,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "local import busy"),
    };
    let result = tokio::task::spawn_blocking(move || {
        // Cancellation must not release admission while the blocking job still runs.
        let _permit = permit;
        let account = read_account(
            state.local_credentials_path.clone(),
            state
                .local_credentials_secret
                .as_deref()
                .map(String::as_str),
            request.group,
        )
        .map_err(|_| StatusCode::BAD_REQUEST)?;
        persist(&state, account).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    })
    .await;
    match result {
        Ok(Ok(account)) => Json(json!({"success": true, "account": account})).into_response(),
        Ok(Err(StatusCode::BAD_REQUEST)) => error(
            StatusCode::BAD_REQUEST,
            "local credentials unavailable or invalid",
        ),
        _ => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "credential storage operation failed",
        ),
    }
}
