use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::Path,
    sync::{Arc, Mutex},
};

use axum::{
    body::Bytes,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use rusqlite::OptionalExtension;
use serde_json::{json, Map, Value};

use crate::{desktop_credentials, state::AppState};

static LOCAL_WRITE: Mutex<()> = Mutex::new(());
const FILES: [&str; 2] = ["credentials.json", "config.json"];

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"message": message}))).into_response()
}

struct Account {
    provider: String,
    jwt: String,
    api_key: String,
    access_token: String,
    user_info: String,
    snapshot: String,
}

fn account(state: &AppState, id: i64) -> Result<Option<Account>, ()> {
    let db = state.db.lock().map_err(|_| ())?;
    let row: Option<Account> = db.query_row(
        "SELECT provider,zcode_jwt,api_key,access_token,user_info,creds_raw FROM accounts WHERE id=?1",
        [id],
        |row| {
            Ok(Account {
                provider: row.get(0)?,
                jwt: row.get(1)?,
                api_key: row.get(2)?,
                access_token: row.get(3)?,
                user_info: row.get(4)?,
                snapshot: row.get(5)?,
            })
        },
    )
    .optional()
    .map_err(|_| ())?;
    row.map(|mut account| {
        account.jwt = state.vault.decrypt(&account.jwt).map_err(|_| ())?;
        account.api_key = state.vault.decrypt(&account.api_key).map_err(|_| ())?;
        account.access_token = state.vault.decrypt(&account.access_token).map_err(|_| ())?;
        account.user_info = state.vault.decrypt(&account.user_info).map_err(|_| ())?;
        account.snapshot = state.vault.decrypt(&account.snapshot).map_err(|_| ())?;
        Ok(account)
    })
    .transpose()
}

fn read_target(path: &Path) -> Result<Option<Vec<u8>>, ()> {
    // Confinement requires no other process to replace entries in the configured directory;
    // std::fs does not provide descriptor-relative writes.
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => fs::read(path).map(Some).map_err(|_| ()),
        Ok(_) => Err(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(_) => Err(()),
    }
}

fn private_file(path: &Path, data: &[u8]) -> Result<(), ()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| ())?;
    if file.write_all(data).and_then(|_| file.sync_all()).is_err() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(());
    }
    Ok(())
}

fn write_files(
    dir: &Path,
    originals: &[Option<Vec<u8>>; 2],
    replacements: &[Option<Vec<u8>>; 2],
) -> Result<(), String> {
    // Reject symlinks before any backup or target change, including cache and temp paths.
    for name in [
        "credentials.json",
        "config.json",
        "cache.json",
        "credentials.json.tmp-zproxy",
        "config.json.tmp-zproxy",
    ] {
        match fs::symlink_metadata(dir.join(name)) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(name.into()),
            Ok(_) => (),
            Err(err) if err.kind() == ErrorKind::NotFound => (),
            Err(_) => return Err(name.into()),
        }
    }
    if originals.iter().any(Option::is_some) {
        let backup_dir = dir.join("backups");
        match fs::symlink_metadata(&backup_dir) {
            Ok(meta) if meta.file_type().is_dir() => (),
            Ok(_) => return Err("backups".into()),
            Err(err) if err.kind() == ErrorKind::NotFound => {
                fs::create_dir(&backup_dir).map_err(|_| "backups".to_owned())?
            }
            Err(_) => return Err("backups".into()),
        }
        let stamp = format!("{:032x}", rand::random::<u128>());
        for (name, original) in FILES.iter().zip(originals) {
            if let Some(data) = original {
                let path = backup_dir.join(format!("{name}.{stamp}.bak"));
                private_file(&path, data).map_err(|_| "backups".to_owned())?;
            }
        }
    }
    for (name, replacement) in FILES.iter().zip(replacements) {
        if let Some(data) = replacement {
            let temp = dir.join(format!("{name}.tmp-zproxy"));
            if private_file(&temp, data).is_err() {
                return Err((*name).to_owned());
            }
            if fs::rename(&temp, dir.join(name)).is_err() {
                let _ = fs::remove_file(&temp);
                return Err((*name).to_owned());
            }
        }
    }
    match fs::remove_file(dir.join("cache.json")) {
        Ok(()) => (),
        Err(err) if err.kind() == ErrorKind::NotFound => (),
        Err(_) => return Err("cache.json".into()),
    }
    Ok(())
}

fn originals(dir: &Path) -> Result<[Option<Vec<u8>>; 2], ()> {
    Ok([
        read_target(&dir.join(FILES[0]))?,
        read_target(&dir.join(FILES[1]))?,
    ])
}

fn object(bytes: Option<&Vec<u8>>) -> Result<Map<String, Value>, ()> {
    match bytes {
        Some(bytes) => serde_json::from_slice::<Map<String, Value>>(bytes).map_err(|_| ()),
        None => Ok(Map::new()),
    }
}

fn snapshot_decryptable(value: &Value) -> bool {
    match value {
        Value::String(value) if value.starts_with("enc:") => {
            value.starts_with("enc:v1:") && desktop_credentials::decrypt(value, None, None).is_ok()
        }
        Value::Array(values) => values.iter().all(snapshot_decryptable),
        Value::Object(values) => values.values().all(snapshot_decryptable),
        _ => true,
    }
}

fn child_object<'a>(parent: &'a mut Map<String, Value>, name: &str) -> &'a mut Map<String, Value> {
    let value = parent.entry(name.to_owned()).or_insert_with(|| json!({}));
    if !value.is_object() {
        *value = json!({});
    }
    value.as_object_mut().unwrap()
}

pub(crate) async fn switch_back(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    body: Bytes,
) -> Response {
    let Some(dir) = state.local_client_dir.as_deref() else {
        return error(
            StatusCode::BAD_REQUEST,
            "no local client directory configured",
        );
    };
    if !body.is_empty() && serde_json::from_slice::<Value>(&body).is_err() {
        return error(StatusCode::BAD_REQUEST, "invalid JSON");
    }
    let account = match account(&state, id) {
        Ok(Some(account)) => account,
        Ok(None) => return error(StatusCode::NOT_FOUND, "account not found"),
        Err(()) => return error(StatusCode::INTERNAL_SERVER_ERROR, "account read failed"),
    };
    if account.jwt.is_empty() {
        return error(StatusCode::BAD_REQUEST, "account has no JWT");
    }
    let provider = if account.provider.is_empty() {
        "zai"
    } else {
        &account.provider
    };
    let _guard = match LOCAL_WRITE.lock() {
        Ok(guard) => guard,
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "local write failed"),
    };
    let original = match originals(dir) {
        Ok(files) => files,
        Err(()) => return error(StatusCode::INTERNAL_SERVER_ERROR, "local read failed"),
    };
    let mut credentials = match object(original[0].as_ref()) {
        Ok(value) => value,
        Err(()) => return error(StatusCode::BAD_REQUEST, "invalid credentials JSON"),
    };
    let mut config = match object(original[1].as_ref()) {
        Ok(value) => value,
        Err(()) => return error(StatusCode::BAD_REQUEST, "invalid config JSON"),
    };
    for (key, value, optional) in [
        ("zcodejwttoken".to_owned(), account.jwt.as_str(), false),
        (
            format!("oauth:{provider}:access_token"),
            account.access_token.as_str(),
            true,
        ),
        (
            format!("oauth:{provider}:user_info"),
            account.user_info.as_str(),
            true,
        ),
        ("oauth:active_provider".to_owned(), provider, false),
    ] {
        if optional && value.is_empty() {
            credentials.remove(&key);
        } else {
            match desktop_credentials::encrypt(value, None, None) {
                Ok(value) => {
                    credentials.insert(key, value.into());
                }
                Err(()) => {
                    return error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "credential encryption failed",
                    )
                }
            }
        }
    }
    let providers = child_object(&mut config, "provider");
    for (suffix, key, enabled) in [
        ("start-plan", account.jwt.as_str(), true),
        (
            "coding-plan",
            account.api_key.as_str(),
            !account.api_key.is_empty(),
        ),
    ] {
        let entry = child_object(providers, &format!("builtin:{provider}-{suffix}"));
        child_object(entry, "options").insert("apiKey".into(), key.into());
        entry.insert("enabled".into(), enabled.into());
    }
    let replacements = [
        Some(Value::Object(credentials).to_string().into_bytes()),
        Some(Value::Object(config).to_string().into_bytes()),
    ];
    match write_files(dir, &original, &replacements) {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({"success": true, "killed": false})),
        )
            .into_response(),
        Err(name) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to write {name}"),
        ),
    }
}

pub(crate) async fn restore_local(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    body: Bytes,
) -> Response {
    let Some(dir) = state.local_client_dir.as_deref() else {
        return error(
            StatusCode::BAD_REQUEST,
            "no local client directory configured",
        );
    };
    if !body.is_empty() && serde_json::from_slice::<Value>(&body).is_err() {
        return error(StatusCode::BAD_REQUEST, "invalid JSON");
    }
    let snapshot = match account(&state, id) {
        Ok(Some(account)) => account.snapshot,
        Ok(None) => return error(StatusCode::NOT_FOUND, "account not found"),
        Err(()) => return error(StatusCode::INTERNAL_SERVER_ERROR, "account read failed"),
    };
    let snapshot: HashMap<String, String> = match serde_json::from_str(&snapshot) {
        Ok(snapshot) => snapshot,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid snapshot"),
    };
    if snapshot.is_empty() {
        return error(StatusCode::BAD_REQUEST, "empty snapshot");
    }
    for name in FILES {
        if let Some(content) = snapshot.get(name).filter(|content| !content.is_empty()) {
            let valid = serde_json::from_str::<Value>(content)
                .map(|value| snapshot_decryptable(&value))
                .unwrap_or(false);
            if !valid {
                return error(StatusCode::BAD_REQUEST, "snapshot cannot be decrypted");
            }
        }
    }
    let replacements = [
        snapshot.get(FILES[0]).map(|s| s.as_bytes().to_vec()),
        snapshot.get(FILES[1]).map(|s| s.as_bytes().to_vec()),
    ];
    let _guard = match LOCAL_WRITE.lock() {
        Ok(guard) => guard,
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "local write failed"),
    };
    let original = match originals(dir) {
        Ok(files) => files,
        Err(()) => return error(StatusCode::INTERNAL_SERVER_ERROR, "local read failed"),
    };
    match write_files(dir, &original, &replacements) {
        Ok(()) => (StatusCode::OK, Json(json!({"success": true}))).into_response(),
        Err(name) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to write {name}"),
        ),
    }
}
