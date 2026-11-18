//! Local desktop import. Unverified profile and JWT claims identify the imported row.

use std::{
    collections::HashMap,
    fs::{self, File},
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
const MAX_INSTANCES: usize = 64;
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
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() || metadata.len() > MAX_FILE as u64 => return Err(()),
        Ok(_) => (),
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    }
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

fn local_home() -> Result<PathBuf, ()> {
    let variable = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    // ImportFromLocalClient uses os.UserHomeDir, not ZCODE_SWITCH_HOME.
    std::env::var_os(variable)
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .ok_or(())
}

// HOME is the trust anchor; no directory below it may redirect discovery.
fn check_directory(home: &Path, directory: &Path) -> Result<bool, ()> {
    let mut path = home.to_owned();
    for component in directory.strip_prefix(home).map_err(|_| ())?.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err(());
        }
        path.push(component);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => (),
            Ok(_) => return Err(()),
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(()),
        }
    }
    Ok(true)
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
    path: &Path,
    secret: Option<&str>,
    fallback_home: Option<&Path>,
    group: String,
    remark: String,
) -> Result<Option<BundleAccount>, ()> {
    let directory = path.parent().ok_or(())?;
    let Some(raw) = read_file(path)? else {
        return Ok(None);
    };
    let credentials: HashMap<String, String> = serde_json::from_str(&raw).map_err(|_| ())?;
    let decode = |key: &str| {
        crate::desktop_credentials::decrypt(
            credentials.get(key).map(String::as_str).unwrap_or(""),
            secret,
            fallback_home,
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
    Ok(Some(BundleAccount {
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
        remark,
        ..Default::default()
    }))
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
    drop(creds);
    drop(accounts);
    drop(db);
    if let Some(worker) = state.background_refresh() {
        if !worker.refresh_after_import(id) {
            eprintln!(
                "background quota refresh admission refused after local import for account {id}"
            );
        }
    }
    Ok(public)
}

fn import_local(state: &AppState, group: String) -> Result<(StatusCode, Value), ()> {
    let secret = state
        .local_credentials_secret
        .as_deref()
        .map(String::as_str);
    let mut imported = Vec::new();
    let mut errors = Vec::new();
    let mut storage_failed = false;
    let home = if state.local_credentials_path.is_none() {
        Some(local_home()?)
    } else {
        None
    };
    let primary = match &state.local_credentials_path {
        Some(path) => path.clone(),
        None => home.as_ref().ok_or(())?.join(".zcode/v2/credentials.json"),
    };
    let primary_present = match &home {
        Some(home) => match check_directory(home, primary.parent().ok_or(())?) {
            Ok(present) => present,
            Err(()) => {
                errors.push(json!({"instance": "primary", "error": "primary directory unavailable or invalid"}));
                false
            }
        },
        None => true,
    };
    // A selected or present primary must parse before any instance can commit.
    let primary_account = if primary_present {
        read_account(
            &primary,
            secret,
            home.as_deref(),
            group.clone(),
            "本地客户端导入".into(),
        )?
    } else {
        None
    };
    if state.local_credentials_path.is_some() && primary_account.is_none() {
        return Err(());
    }
    if let Some(account) = primary_account {
        match persist(state, account) {
            Ok(account) => imported.push(account),
            Err(()) => {
                storage_failed = true;
                errors.push(
                    json!({"instance": "primary", "error": "credential storage operation failed"}),
                );
            }
        }
    }
    if let Some(home) = home {
        let mut roots = vec![home.join(".zcode-multi")];
        if cfg!(target_os = "macos") {
            roots.push(home.join("Library/Application Support/zcode-multi"));
        }
        let mut scanned = 0;
        for root in roots {
            if scanned == MAX_INSTANCES {
                break;
            }
            match check_directory(&home, &root) {
                Ok(false) => continue,
                Ok(true) => (),
                Err(()) => {
                    errors.push(json!({"instance": "discovery", "error": "instance directory unavailable or invalid"}));
                    continue;
                }
            }
            let entries = match fs::read_dir(&root) {
                Ok(entries) => entries,
                Err(_) => {
                    errors.push(json!({"instance": "discovery", "error": "instance directory unavailable or invalid"}));
                    continue;
                }
            };
            let mut candidates = std::collections::BTreeMap::new();
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => {
                        errors.push(json!({"instance": "discovery", "error": "instance directory unavailable or invalid"}));
                        continue;
                    }
                };
                let kind = match entry.file_type() {
                    Ok(kind) => kind,
                    Err(_) => {
                        errors.push(json!({"instance": entry.file_name().to_string_lossy(), "error": "instance directory unavailable or invalid"}));
                        continue;
                    }
                };
                if !kind.is_dir() && !kind.is_symlink() {
                    continue;
                }
                candidates.insert(entry.file_name(), entry);
                if candidates.len() > MAX_INSTANCES - scanned {
                    candidates.pop_last();
                }
            }
            for entry in candidates.into_values() {
                scanned += 1;
                let name = entry.file_name().to_string_lossy().into_owned();
                let instance = entry.path();
                let directory = instance.join("v2");
                match check_directory(&home, &directory) {
                    Ok(false) => continue,
                    Ok(true) => (),
                    Err(()) => {
                        errors.push(json!({"instance": name, "error": "instance directory unavailable or invalid"}));
                        continue;
                    }
                }
                match read_account(
                    &directory.join("credentials.json"),
                    secret,
                    Some(&instance),
                    group.clone(),
                    format!("多实例导入: {name}"),
                ) {
                    Ok(Some(account)) => match persist(state, account) {
                        Ok(account) => imported.push(account),
                        Err(()) => {
                            storage_failed = true;
                            errors.push(json!({"instance": name, "error": "credential storage operation failed"}));
                        }
                    },
                    Ok(None) => (),
                    Err(()) => errors.push(json!({"instance": name, "error": "local credentials unavailable or invalid"})),
                }
            }
        }
    }
    let status = if storage_failed {
        StatusCode::INTERNAL_SERVER_ERROR
    } else if imported.is_empty() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    let mut reply = json!({
        "success": status == StatusCode::OK,
        "account": imported.first(),
        "imported": imported.len(),
        "accounts": imported,
        "errors": errors,
    });
    if status != StatusCode::OK {
        reply["error"] = json!({
            "message": if storage_failed { "credential storage operation failed" } else { "local credentials unavailable or invalid" },
            "type": "api_error",
        });
    }
    Ok((status, reply))
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
        import_local(&state, request.group)
    })
    .await;
    match result {
        Ok(Ok((status, reply))) => (status, Json(reply)).into_response(),
        Ok(Err(())) => error(
            StatusCode::BAD_REQUEST,
            "local credentials unavailable or invalid",
        ),
        _ => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "credential storage operation failed",
        ),
    }
}
