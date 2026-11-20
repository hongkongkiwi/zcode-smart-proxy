//! Read-only off-peak ticket availability.

use std::{sync::Arc, time::Duration};

use axum::{extract::State, Json};
use serde_json::{json, Value};
use zcode_core::AccountView;

use crate::{account_refresh, egress, state::AppState};

pub(crate) async fn handle_availability(State(state): State<Arc<AppState>>) -> Json<Value> {
    let accounts = state.accounts.lock().unwrap().clone();
    let mut last_error = None;
    for account in accounts
        .iter()
        .filter(|a| a.enabled && a.provider == "zai" && !a.zcode_jwt.is_empty())
    {
        match probe(&state, account).await {
            Ok((can_take, next_take_at)) => {
                return Json(json!({
                    "ok": true, "can_take": can_take, "next_take_at": next_take_at,
                    "account": account.email
                }));
            }
            Err(detail) => last_error = Some(format!("{}: {detail}", account.email)),
        }
    }
    let error = match last_error {
        Some(detail) => format!(
            "所有账号探测失败（{}）",
            detail.chars().take(300).collect::<String>()
        ),
        None => "无可用 JWT 账号".into(),
    };
    Json(json!({"ok": false, "error": error}))
}

async fn probe(state: &AppState, account: &AccountView) -> Result<(bool, i64), String> {
    let client = egress::client_builder_for_group(state, &account.account_group)
        .map_err(|_| "client setup failed".to_owned())?
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "client setup failed".to_owned())?;
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    };
    let version = &state.management.app_version;
    let timezone = iana_time_zone::get_timezone().unwrap_or_else(|_| "UTC".into());
    let mut request = client
        .get(format!(
            "{}/ticket/availability",
            state.offpeak_control_base
        ))
        .header("authorization", format!("Bearer {}", account.zcode_jwt))
        .header("user-agent", format!("ZCode/{version}"))
        .header("http-referer", "https://zcode.z.ai")
        .header("x-title", "Z Code@electron")
        .header("x-zcode-app-version", version)
        .header("x-platform", format!("{os}-{arch}"))
        .header("x-release-channel", "stable")
        .header("x-client-language", "zh-CN")
        .header("x-client-timezone", timezone)
        .header("x-os-category", if os == "win32" { "windows" } else { os })
        .header("x-request-id", account_refresh::request_id());
    if !account.api_key.is_empty() {
        request = request.header("x-coding-plan-api-key", &account.api_key);
    }
    let mut response = request
        .send()
        .await
        .map_err(|_| "request failed".to_owned())?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status().as_u16()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "response read failed".to_owned())?
    {
        if chunk.len() > (1 << 20) - bytes.len() {
            return Err("response too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let body: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid JSON".to_owned())?;
    if !body.is_object() {
        return Err("invalid JSON object".into());
    }
    let data = if let Some(code) = body.get("code") {
        let code = code
            .as_i64()
            .ok_or_else(|| "invalid business code".to_owned())?;
        if code != 0 {
            return Err(format!("business code {code}"));
        }
        body.get("data")
            .filter(|data| data.is_object())
            .unwrap_or(&body)
    } else {
        &body
    };
    let can_take = match data.get("can_take_number") {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| "invalid availability".to_owned())?,
        None => false,
    };
    let next_take_at = data.get("next_take_at").map_or(0, |value| {
        value
            .as_i64()
            .unwrap_or_else(|| value.as_f64().unwrap_or(0.0) as i64)
    });
    Ok((can_take, next_take_at))
}
