//! Go-compatible encrypted account bundles. Local IDs never cross the wire.

use std::{net::SocketAddr, sync::Arc};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    auth::now_secs,
    state::{AppState, Creds},
    store,
};

const MAX_REQUEST: usize = 1 << 20;
const MAX_PAYLOAD: usize = 512 << 10;
const MAX_ACCOUNTS: usize = 1024;
const MAX_PASSWORD: usize = 4096;
const MAX_BUNDLE: usize = 5 + (MAX_PAYLOAD + 44).div_ceil(3) * 4;
// Only two KDF jobs may enter the blocking pool at once.
static CRYPTO_JOBS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct BundleAccount {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub provider: String,
    pub auth_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub access_token: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub refresh_token: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub zcode_jwt: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub api_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub user_info: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub device_mid: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub creds_raw: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub account_group: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub remark: String,
}

impl BundleAccount {
    pub(crate) fn transform_credentials<E>(
        &mut self,
        mut transform: impl FnMut(&str) -> Result<String, E>,
    ) -> Result<(), E> {
        for value in [
            &mut self.access_token,
            &mut self.refresh_token,
            &mut self.zcode_jwt,
            &mut self.api_key,
            &mut self.user_info,
            &mut self.creds_raw,
        ] {
            *value = transform(value)?;
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
struct Payload {
    #[serde(default)]
    version: i64,
    #[serde(default)]
    accounts: Vec<BundleAccount>,
}

#[derive(Deserialize)]
struct ExportRequest {
    password: String,
    #[serde(default)]
    admin_password: String,
    #[serde(default)]
    ids: Vec<i64>,
}

#[derive(Deserialize)]
struct ImportRequest {
    password: String,
    bundle: String,
}

fn error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({"success": false, "imported": 0,
        "error": {"message": message, "type": "api_error"}})),
    )
        .into_response()
}

fn cipher(password: &str, salt: &[u8], rounds: u32) -> Aes256Gcm {
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, rounds, key.as_mut());
    Aes256Gcm::new_from_slice(key.as_ref()).expect("AES-256 key length")
}

fn encrypt(password: &str, accounts: Vec<BundleAccount>) -> Result<String, ()> {
    if accounts.is_empty() || accounts.len() > MAX_ACCOUNTS {
        return Err(());
    }
    let plain = Zeroizing::new(
        serde_json::to_vec(&Payload {
            version: 1,
            accounts,
        })
        .map_err(|_| ())?,
    );
    if plain.len() > MAX_PAYLOAD {
        return Err(());
    }
    let mut raw = vec![0u8; 28];
    OsRng.try_fill_bytes(&mut raw).map_err(|_| ())?;
    let ct = cipher(password, &raw[..16], 600_000)
        .encrypt(Nonce::from_slice(&raw[16..28]), plain.as_slice())
        .map_err(|_| ())?;
    raw.extend_from_slice(&ct);
    Ok(format!("zcb1:{}", STANDARD.encode(raw)))
}

fn decrypt(password: &str, bundle: &str) -> Result<Vec<BundleAccount>, ()> {
    let bundle = bundle.trim();
    if bundle.len() > MAX_BUNDLE {
        return Err(());
    }
    let raw = STANDARD
        .decode(bundle.strip_prefix("zcb1:").ok_or(())?)
        .map_err(|_| ())?;
    if raw.len() < 44 || raw.len() > MAX_PAYLOAD + 44 {
        return Err(());
    }
    let plain = [600_000, 120_000]
        .into_iter()
        .find_map(|rounds| {
            cipher(password, &raw[..16], rounds)
                .decrypt(Nonce::from_slice(&raw[16..28]), &raw[28..])
                .ok()
        })
        .ok_or(())?;
    let plain = Zeroizing::new(plain);
    let payload: Payload = serde_json::from_slice(&plain).map_err(|_| ())?;
    if payload.version > 1 || payload.accounts.len() > MAX_ACCOUNTS {
        return Err(());
    }
    // Match Go's non-importable account filtering after validating the entire JSON.
    let mut accounts: Vec<_> = payload
        .accounts
        .into_iter()
        .filter(|a| !a.user_id.is_empty() && (!a.zcode_jwt.is_empty() || !a.api_key.is_empty()))
        .collect();
    for a in &mut accounts {
        if a.provider.is_empty() {
            a.provider = "zai".into();
        }
        if a.auth_type.is_empty() {
            a.auth_type = "jwt".into();
        }
    }
    Ok(accounts)
}

pub async fn handle_export(
    State(state): State<Arc<AppState>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: String,
) -> Response {
    if body.len() > MAX_REQUEST {
        return error(StatusCode::BAD_REQUEST, "request too large");
    }
    let request: ExportRequest = match serde_json::from_str(&body) {
        Ok(request) => request,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid request body"),
    };
    if request.password.len() > MAX_PASSWORD
        || request.admin_password.len() > MAX_PASSWORD
        || request.ids.len() > MAX_ACCOUNTS
    {
        return error(StatusCode::BAD_REQUEST, "request too large");
    }
    let client = format!(
        "{}|export",
        peer.map(|Extension(ConnectInfo(addr))| addr.ip().to_string())
            .unwrap_or_else(|| "local".into())
    );
    let Ok(permit) = CRYPTO_JOBS.acquire().await else {
        return error(StatusCode::TOO_MANY_REQUESTS, "bundle operations busy");
    };
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        if state
            .step_up_guard
            .lock()
            .unwrap()
            .check(&client, now_secs())
            > 0
        {
            return error(StatusCode::TOO_MANY_REQUESTS, "export temporarily locked");
        }
        let hash = state.setting("admin_password_hash");
        let verified = hash
            .as_ref()
            .filter(|h| !h.is_empty())
            .is_some_and(|h| bcrypt::verify(&request.admin_password, h).unwrap_or(false));
        let mut guard = state.step_up_guard.lock().unwrap();
        // Recheck after bcrypt so simultaneous failures cannot bypass the lockout.
        if guard.check(&client, now_secs()) > 0 {
            return error(StatusCode::TOO_MANY_REQUESTS, "export temporarily locked");
        }
        if !verified {
            guard.record_failure(&client, now_secs());
            return error(StatusCode::UNAUTHORIZED, "invalid admin password");
        }
        guard.clear(&client);
        drop(guard);
        if request.password.is_empty() {
            return error(StatusCode::BAD_REQUEST, "bundle password required");
        }
        let accounts = {
            let db = state.db.lock().unwrap();
            match store::load_bundle_accounts(&db, &state.vault) {
                Ok(accounts) => accounts,
                Err(_) => {
                    return error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "credential storage operation failed",
                    )
                }
            }
        };
        let accounts = accounts
            .into_iter()
            .filter(|(id, _)| request.ids.is_empty() || request.ids.contains(id))
            .map(|(_, a)| a)
            .collect();
        match encrypt(&request.password, accounts) {
            Ok(bundle) => Json(json!({"bundle": bundle})).into_response(),
            Err(_) => error(
                StatusCode::BAD_REQUEST,
                "bundle export failed or no exportable accounts",
            ),
        }
    })
    .await
    .unwrap_or_else(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "bundle operation failed"))
}

pub async fn handle_import(State(state): State<Arc<AppState>>, body: String) -> Response {
    if body.len() > MAX_REQUEST {
        return error(StatusCode::BAD_REQUEST, "request too large");
    }
    let request: ImportRequest = match serde_json::from_str(&body) {
        Ok(request) => request,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid request body"),
    };
    if request.password.len() > MAX_PASSWORD || request.bundle.len() > MAX_BUNDLE + 1024 {
        return error(StatusCode::BAD_REQUEST, "request too large");
    }
    let Ok(permit) = CRYPTO_JOBS.acquire().await else {
        return error(StatusCode::TOO_MANY_REQUESTS, "bundle operations busy");
    };
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut imported = match decrypt(&request.password, &request.bundle) {
            Ok(accounts) => accounts,
            Err(_) => return error(StatusCode::BAD_REQUEST, "invalid bundle or password"),
        };
        for account in &mut imported {
            if account
                .transform_credentials(|value| state.vault.encrypt(value))
                .is_err()
            {
                return error(StatusCode::BAD_REQUEST, "invalid bundle credentials");
            }
        }
        let mut db = state.db.lock().unwrap();
        let mut accounts = state.accounts.lock().unwrap();
        let mut creds = state.creds.lock().unwrap();
        let rows = match store::import_bundle_accounts(&mut db, &state.vault, &imported) {
            Ok(rows) => rows,
            Err(_) => {
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "credential storage operation failed",
                )
            }
        };
        for (account, jwt, key) in rows {
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
        Json(json!({"success": true, "imported": imported.len()})).into_response()
    })
    .await
    .unwrap_or_else(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "bundle operation failed"))
}
