//! Best-effort client enrollment using the installation wire contract in Go identity.go.

use std::time::Duration;

use reqwest::Method;
use serde_json::{json, Value};

use crate::{
    account_billing::identity_snapshot,
    account_refresh::{os_version, request_id, Client},
    state::AppState,
    store::StoreError,
};

#[derive(Clone)]
pub struct InstallUrls {
    pub client_configs: String,
    pub event_report: String,
}

impl Default for InstallUrls {
    fn default() -> Self {
        Self {
            client_configs: "https://zcode.z.ai/api/v1/client/configs".into(),
            event_report: "https://zcode.z.ai/api/v1/event/report".into(),
        }
    }
}

#[derive(Debug, Default)]
pub struct InstallReport {
    pub attempted: usize,
    pub succeeded: usize,
    pub skipped: bool,
}

#[derive(PartialEq)]
struct Account {
    jwt: String,
    key: String,
    user_id: String,
    device_mid: String,
}

fn snapshot(state: &AppState, id: i64) -> Result<Option<Account>, StoreError> {
    let db = state.db.lock().unwrap();
    let accounts = state.accounts.lock().unwrap();
    let Some(account) = accounts.iter().find(|a| a.id == id) else {
        return Ok(None);
    };
    if !account.enabled || account.status == "disabled" || account.zcode_jwt.is_empty() {
        return Ok(None);
    }
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM accounts WHERE id=?1)",
        [id],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    let identity = identity_snapshot(state, &db, account)?;
    if identity.user_id.is_empty() {
        return Ok(None);
    }
    let device_mid = if identity.device_mid.is_empty() {
        crate::identity::ensure_locked(&db, id)?
    } else {
        identity.device_mid
    };
    Ok(Some(Account {
        jwt: account.zcode_jwt.clone(),
        key: account.api_key.clone(),
        user_id: identity.user_id,
        device_mid,
    }))
}

pub async fn send_install_sequence(
    state: &AppState,
    account_id: i64,
) -> Result<InstallReport, StoreError> {
    send_install_sequence_until(state, account_id, || false).await
}

pub(crate) async fn send_install_sequence_until(
    state: &AppState,
    account_id: i64,
    stopped: impl Fn() -> bool,
) -> Result<InstallReport, StoreError> {
    let mut report = InstallReport::default();
    if stopped() {
        report.skipped = true;
        return Ok(report);
    }
    let Some(account) = snapshot(state, account_id)? else {
        report.skipped = true;
        return Ok(report);
    };
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    };
    let version = os_version();
    let timezone = iana_time_zone::get_timezone().unwrap_or_else(|_| "UTC".into());
    for element in [None, Some("app_launch"), Some("app_daily_active")] {
        if stopped() || snapshot(state, account_id)?.as_ref() != Some(&account) {
            report.skipped = true;
            break;
        }
        let payload = element.map(|element| {
            json!({"event_id":request_id(),"client_timezone":timezone,
                "client_language":"zh-CN","element_name":element,"event_region":"app",
                "event_type":"view","event_text":"","event_extra_detail":{},
                "user_id":account.user_id,"screen_resolution":"2560x1440",
                "app_version":state.management.app_version,"device_os_category":os,
                "device_os_version":version,"device_mid":account.device_mid,
                "mac_id":"","marketing_params":"{}"})
        });
        report.attempted += 1;
        if tokio::time::timeout(
            Duration::from_secs(5),
            request(state, &account, payload.as_ref()),
        )
        .await
        .unwrap_or(false)
        {
            report.succeeded += 1;
        }
    }
    Ok(report)
}

async fn request(state: &AppState, account: &Account, payload: Option<&Value>) -> bool {
    let endpoint = if payload.is_some() {
        &state.install_urls.event_report
    } else {
        &state.install_urls.client_configs
    };
    let Ok(mut url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    url.set_query(None);
    if payload.is_none() {
        url.query_pairs_mut()
            .append_pair("app_version", &state.management.app_version);
    }
    let Ok(client) = Client::new(&state.management.app_version, &account.device_mid) else {
        return false;
    };
    let mut request = client
        .http
        .request(
            if payload.is_some() {
                Method::POST
            } else {
                Method::GET
            },
            url,
        )
        .timeout(Duration::from_secs(5))
        .header("accept", "application/json")
        .header("x-request-id", request_id());
    if let Some(payload) = payload {
        request = request.bearer_auth(&account.jwt).json(payload);
    }
    let Ok(mut response) = request.send().await else {
        return false;
    };
    if !response.status().is_success() {
        return false;
    }
    let mut bytes = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if bytes.len() + chunk.len() <= 1 << 20 => {
                bytes.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            _ => return false,
        }
    }
    let Ok(body) = serde_json::from_slice::<Value>(&bytes) else {
        return false;
    };
    let code = body["code"]
        .as_i64()
        .or_else(|| body["code"].as_str()?.parse().ok());
    matches!(code, Some(0 | -1 | 200)) && body["success"] != false
}
