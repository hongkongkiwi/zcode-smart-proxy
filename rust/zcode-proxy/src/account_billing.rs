//! Explicit manual billing actions. No scheduled claims or implicit reset spending.

use std::{sync::Arc, time::Duration};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Serialize;
use serde_json::{json, Value};

use crate::{
    account_refresh::{self, request_id, Client},
    auth::now_secs,
    state::AppState,
    store,
};

struct Account {
    id: i64,
    email: String,
    jwt: String,
    key: String,
    device_mid: String,
    user_id: String,
    remark: Value,
}

struct Flight<'a> {
    state: &'a AppState,
    id: i64,
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        self.state
            .automation_inflight
            .lock()
            .unwrap()
            .remove(&self.id);
    }
}

fn error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({"error":{"type":"api_error","message":message}})),
    )
        .into_response()
}

struct AccountError(StatusCode, &'static str);

impl IntoResponse for AccountError {
    fn into_response(self) -> Response {
        error(self.0, self.1)
    }
}

fn account(state: &AppState, id: &str) -> Result<Account, AccountError> {
    let id = id
        .parse::<i64>()
        .map_err(|_| AccountError(StatusCode::BAD_REQUEST, "invalid id"))?;
    let db = state.db.lock().unwrap();
    let accounts = state.accounts.lock().unwrap();
    let a = accounts
        .iter()
        .find(|a| a.id == id)
        .ok_or(AccountError(StatusCode::NOT_FOUND, "account not found"))?;
    let (mid, info, access, remark, stored_id) = db
        .query_row(
            "SELECT device_mid,user_info,access_token,remark,COALESCE(user_id,'') FROM accounts WHERE id=?1",
            [id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            },
        )
        .map_err(|_| {
            AccountError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage operation failed",
            )
        })?;
    let info = state.vault.decrypt(&info).map_err(|_| {
        AccountError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "credential storage operation failed",
        )
    })?;
    let access = state.vault.decrypt(&access).map_err(|_| {
        AccountError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "credential storage operation failed",
        )
    })?;
    let info: Value = serde_json::from_str(&info).unwrap_or(Value::Null);
    let mut user_id = first_text(&info, &["id", "user_id"]).to_owned();
    if user_id.is_empty() {
        for token in [&access, &a.zcode_jwt] {
            if let Some(claims) = token
                .split('.')
                .nth(1)
                .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            {
                user_id = first_text(&claims, &["user_id", "sub"]).to_owned();
                if !user_id.is_empty() {
                    break;
                }
            }
        }
    }
    if user_id.is_empty() && !synthetic_user_id(&stored_id) {
        user_id = stored_id;
    }
    Ok(Account {
        id,
        email: a.email.clone(),
        jwt: a.zcode_jwt.clone(),
        key: a.api_key.clone(),
        device_mid: mid,
        user_id,
        remark: serde_json::from_str(&remark).unwrap_or(Value::Null),
    })
}

fn synthetic_user_id(id: &str) -> bool {
    let hex =
        |suffix: &str, len| suffix.len() == len && suffix.bytes().all(|b| b.is_ascii_hexdigit());
    id.strip_prefix("rust:").is_some_and(|suffix| hex(suffix, 32))
        || id.strip_prefix("oauth-").is_some_and(|suffix| hex(suffix, 8) || hex(suffix, 64))
        // The original provider prefix survives later provider metadata changes.
        || id.rsplit_once('-').is_some_and(|(_, suffix)| hex(suffix, 16))
}

fn first_text<'a>(v: &'a Value, keys: &[&str]) -> &'a str {
    keys.iter()
        .find_map(|k| v[*k].as_str().filter(|s| !s.is_empty()))
        .unwrap_or("")
}

fn platform() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        os => os,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        arch => arch,
    };
    format!("{os}-{arch}")
}

fn billing_token(a: &Account) -> &str {
    if a.jwt.is_empty() {
        &a.key
    } else {
        &a.jwt
    }
}

async fn request(
    state: &AppState,
    a: &Account,
    method: reqwest::Method,
    endpoint: &str,
    payload: Option<&Value>,
    captcha: Option<&str>,
    reset: bool,
) -> Result<(u16, Value), ()> {
    let token = if reset {
        a.jwt.as_str()
    } else {
        billing_token(a)
    };
    if token.is_empty() {
        return Err(());
    }
    let mut url = reqwest::Url::parse(endpoint).map_err(|_| ())?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(());
    }
    if method == reqwest::Method::GET && !reset {
        url.query_pairs_mut()
            .append_pair("app_version", &state.management.app_version)
            .append_pair("platform", &platform());
    }
    let client = Client::new(&state.management.app_version, &a.device_mid).map_err(|_| ())?;
    let mut req = client
        .http
        .request(method, url)
        .header("authorization", format!("Bearer {token}"))
        .header("accept", "application/json")
        .header("x-request-id", request_id());
    if reset {
        if !a.key.is_empty() {
            req = req.header("x-bigmodel-authorization", &a.key);
        }
        let org = first_text(&a.remark["team"], &["org"]);
        let proj = first_text(&a.remark["team"], &["proj"]);
        if !org.is_empty() && !proj.is_empty() {
            req = req
                .header("bigmodel-target-type", "TEAM")
                .header("bigmodel-organization", org)
                .header("bigmodel-project", proj);
        } else {
            req = req.header("bigmodel-target-type", "PERSONAL");
        }
    }
    if let Some(param) = captcha {
        req = req.header("x-aliyun-captcha-verify-param", param);
        if !state.automation.captcha_region.trim().is_empty() {
            req = req.header(
                "x-aliyun-captcha-verify-region",
                state.automation.captcha_region.trim(),
            );
        }
    }
    if let Some(payload) = payload {
        req = req.json(payload);
    }
    let mut response = req.send().await.map_err(|_| ())?;
    let status = response.status().as_u16();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if bytes.len() + chunk.len() > 1 << 20 {
            return Err(());
        }
        bytes.extend_from_slice(&chunk);
    }
    let body: Value = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if !body.is_object() {
        return Err(());
    }
    Ok((status, body))
}

fn code(body: &Value) -> i64 {
    body["code"]
        .as_i64()
        .or_else(|| body["code"].as_str()?.parse().ok())
        .unwrap_or(-1)
}

fn acknowledged(status: u16, body: &Value) -> bool {
    (200..300).contains(&status) && code(body) == 0 && body["success"] != false
}

#[derive(Serialize)]
struct Plan {
    plan_id: String,
    name: String,
    description: String,
    priority: i64,
    grants: Vec<String>,
    grant_items: Vec<Value>,
}

async fn preview(state: &AppState, a: &Account) -> Result<Vec<Plan>, ()> {
    let (status, body) = request(
        state,
        a,
        reqwest::Method::GET,
        &state.automation.billing_preview,
        None,
        None,
        false,
    )
    .await?;
    if !acknowledged(status, &body) {
        return Err(());
    }
    let mut plans = Vec::new();
    for p in body["data"]["plans"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
    {
        let id = first_text(p, &["plan_id", "planId"]).trim();
        if id.is_empty() {
            continue;
        }
        let mut plan = Plan {
            plan_id: id.into(),
            name: first_text(p, &["name"]).trim().into(),
            description: first_text(p, &["description"]).trim().into(),
            priority: p["priority"].as_i64().unwrap_or(0).max(0),
            grants: Vec::new(),
            grant_items: Vec::new(),
        };
        for e in p["entitlements"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            let name = first_text(e, &["show_name", "showName"]).trim();
            if e["meter"] != "model_usage"
                || first_text(e, &["unit_type", "unitType"]) != "token"
                || name.is_empty()
            {
                continue;
            }
            let units = e
                .get("grant_units")
                .or_else(|| e.get("grantUnits"))
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let period = match first_text(e, &["period"]) {
                "" => "one_time",
                p => p,
            };
            let label = match period {
                "daily" => "每日",
                "weekly" => "每周",
                "monthly" => "每月",
                _ => "一次性",
            };
            let amount = if units >= 1e8 {
                format!("{}亿", (units / 1e7).round() / 10.0)
            } else if units >= 1e4 {
                format!("{}万", (units / 1e3).round() / 10.0)
            } else {
                format!("{}", units.round())
            };
            plan.grants
                .push(format!("{name} · {amount} Token（{label}）"));
            let capabilities: Vec<_> = e["capabilities"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or(&[])
                .iter()
                .filter_map(Value::as_str)
                .filter(|s| !s.is_empty())
                .collect();
            plan.grant_items.push(json!({"name":name,"units":units,"period":period,
                "priority":e["priority"].as_i64().unwrap_or(0),"capabilities":capabilities,
                "effective_at":e.get("effective_at").or_else(|| e.get("effectiveAt")).and_then(Value::as_i64).unwrap_or(0)}));
        }
        plans.push(plan);
    }
    plans.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.plan_id.cmp(&b.plan_id))
    });
    Ok(plans)
}

#[derive(Clone, Serialize)]
struct ResultBody {
    ok: bool,
    code: i64,
    message: String,
    plan_id: String,
    plan_name: String,
    next_at: i64,
    server_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    plan: Option<Value>,
}

impl ResultBody {
    fn failure(message: &str) -> Self {
        Self {
            ok: false,
            code: -1,
            message: message.into(),
            plan_id: String::new(),
            plan_name: String::new(),
            next_at: 0,
            server_time: 0,
            plan: None,
        }
    }
}

fn publish(
    state: &AppState,
    a: &Account,
    task: &str,
    result: ResultBody,
    used_at: i64,
    quota: Option<account_refresh::Quota>,
) -> Response {
    let mut db = state.db.lock().unwrap();
    let mut accounts = state.accounts.lock().unwrap();
    // A remote acknowledgement cannot be rolled back if the account changed during HTTP.
    let quota = quota.filter(|_| {
        accounts.iter().any(|current| {
            current.id == a.id && current.zcode_jwt == a.jwt && current.api_key == a.key
        })
    });
    let record = store::ClaimRecord {
        account_id: a.id,
        email: &a.email,
        task_type: task,
        plan_id: &result.plan_id,
        plan_name: &result.plan_name,
        success: result.ok,
        code: result.code,
        message: &result.message,
        next_at: result.next_at,
        used_at,
    };
    let mut recovered = accounts.iter().find(|current| current.id == a.id).cloned();
    let confirmed = quota
        .as_ref()
        .zip(recovered.as_mut())
        .map(|(quota, current)| {
            let (status, cooling, last_error) = quota.confirmed_state(current);
            current.status = status.to_owned();
            current.cooling_until = cooling;
            current.remaining = quota.remaining.unwrap_or(0.0);
            store::ConfirmedQuota {
                quota,
                account: &*current,
                last_error,
            }
        });
    if store::persist_claim_result(&mut db, &record, confirmed).is_err() {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "local billing persistence failed; the remote action may already have taken effect",
        );
    }
    if quota.is_some() {
        if let Some(current) = accounts.iter_mut().find(|current| current.id == a.id) {
            *current = recovered.take().unwrap();
        }
    }
    Json(result).into_response()
}

pub async fn handle_detect(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let a = match account(&state, &id) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let preview = preview(&state, &a).await;
    let mut result = ResultBody::failure("billing preview failed");
    if let Ok(plans) = &preview {
        result.ok = true;
        result.code = 0;
        result.plan_id = plans.first().map(|p| p.plan_id.clone()).unwrap_or_default();
        result.plan_name = plans
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>()
            .join("、");
        result.message = if plans.is_empty() {
            "无可领取活动".into()
        } else {
            format!("发现 {} 个活动: {}", plans.len(), result.plan_name)
        };
    }
    let persisted = publish(&state, &a, "detect", result, 0, None);
    if persisted.status() != StatusCode::OK {
        return persisted;
    }
    match preview {
        Ok(plans) => Json(json!({"total":plans.len(),"plans":plans})).into_response(),
        Err(()) => error(StatusCode::BAD_GATEWAY, "billing preview failed"),
    }
}

async fn solve(state: &AppState) -> Option<String> {
    let solver = state.automation_solver.clone();
    let scene = state.automation.captcha_scene.clone();
    let prefix = state.automation.captcha_prefix.clone();
    tokio::time::timeout(
        Duration::from_secs(25),
        tokio::task::spawn_blocking(move || solver.solve(&scene, &prefix)),
    )
    .await
    .ok()?
    .ok()?
    .filter(|p| !p.trim().is_empty())
}

async fn claim(state: &AppState, a: &Account) -> ResultBody {
    let plans = match preview(state, a).await {
        Ok(p) => p,
        Err(()) => return ResultBody::failure("billing preview failed"),
    };
    let Some(plan) = plans.first() else {
        let mut result = ResultBody::failure("当前无可领取活动");
        result.ok = true;
        result.code = 0;
        return result;
    };
    let mut result = ResultBody::failure("CAPTCHA verification unavailable");
    result.plan_id = plan.plan_id.clone();
    result.plan_name = plan.name.clone();
    for attempt in 0..2 {
        let Some(param) = solve(state).await else {
            return result;
        };
        let response = request(
            state,
            a,
            reqwest::Method::POST,
            &state.automation.billing_claim,
            Some(&json!({"plan_id":plan.plan_id})),
            Some(param.trim()),
            false,
        )
        .await;
        let (status, body) = match response {
            Ok(r) => r,
            Err(()) => {
                result.message = "claim response unavailable; remote outcome is unknown".into();
                return result;
            }
        };
        result.code = code(&body);
        result.server_time = body["data"]["server_time"]
            .as_i64()
            .unwrap_or(0)
            .saturating_mul(1000);
        result.ok = (200..300).contains(&status)
            && matches!(result.code, 0 | 1003)
            && body["success"] != false;
        result.message = match result.code {
            0 if result.ok => "领取成功",
            1003 if result.ok => "该套餐已经领取过（幂等成功）",
            1005 => "今日领取名额已用完",
            3001 | 3007 => "CAPTCHA verification rejected",
            _ => "billing claim rejected",
        }
        .into();
        if result.code == 1005 {
            result.next_at = body["data"]["plan"]["ends_at"]
                .as_i64()
                .unwrap_or(0)
                .max(0)
                .saturating_mul(1000);
        }
        if result.ok && result.code == 0 && body["data"]["plan"].is_object() {
            let p = &body["data"]["plan"];
            result.plan = Some(json!({"user_plan_id":first_text(p,&["user_plan_id"]),
                "plan_id":match first_text(p,&["plan_id"]) { "" => plan.plan_id.as_str(), id => id },
                "status":first_text(p,&["status"]),"starts_at":p["starts_at"].as_i64().unwrap_or(0),
                "ends_at":p["ends_at"].as_i64().unwrap_or(0)}));
            let name = first_text(p, &["name", "plan_id"]);
            if !name.is_empty() {
                result.plan_name = name.into();
            }
        }
        if attempt == 0 && matches!(result.code, 3001 | 3007) {
            continue;
        }
        return result;
    }
    result
}

async fn audit_then_confirm(
    state: &AppState,
    a: &Account,
    task: &str,
    mut result: ResultBody,
    used_at: i64,
) -> Response {
    let audited = publish(state, a, task, result.clone(), used_at, None);
    if audited.status() != StatusCode::OK {
        return audited;
    }
    let Some(quota) = confirm_action(state, a, &mut result).await else {
        return Json(result).into_response();
    };
    let mut db = state.db.lock().unwrap();
    let mut accounts = state.accounts.lock().unwrap();
    let Some(current) = accounts.iter_mut().find(|current| {
        current.id == a.id && current.zcode_jwt == a.jwt && current.api_key == a.key
    }) else {
        result
            .message
            .push_str("; confirmed quota discarded because the account changed");
        return Json(result).into_response();
    };
    let mut recovered = current.clone();
    let (status, cooling, last_error) = quota.confirmed_state(current);
    recovered.status = status.to_owned();
    recovered.cooling_until = cooling;
    recovered.remaining = quota.remaining.unwrap_or(0.0);
    if store::persist_confirmation(
        &mut db,
        a.id,
        store::ConfirmedQuota {
            quota: &quota,
            account: &recovered,
            last_error,
        },
    )
    .is_err()
    {
        return error(StatusCode::INTERNAL_SERVER_ERROR,
            "local billing persistence failed; remote action is audited but quota was not published");
    }
    *current = recovered;
    Json(result).into_response()
}

async fn confirm_action(
    state: &AppState,
    a: &Account,
    result: &mut ResultBody,
) -> Option<account_refresh::Quota> {
    let current = state.accounts.lock().unwrap().iter().any(|current| {
        current.id == a.id && current.zcode_jwt == a.jwt && current.api_key == a.key
    });
    if !current {
        result
            .message
            .push_str("; quota confirmation skipped because the account changed");
        return None;
    }
    match account_refresh::confirm_billing(state, billing_token(a), &a.device_mid).await {
        Ok(quota) => Some(quota),
        Err(_) => {
            result
                .message
                .push_str("; remote action acknowledged but quota confirmation failed");
            None
        }
    }
}

pub async fn handle_claim(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let a = match account(&state, &id) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if !state.automation_inflight.lock().unwrap().insert(a.id) {
        return Json(ResultBody::failure(
            "account billing action already in progress",
        ))
        .into_response();
    }
    let _flight = Flight {
        state: &state,
        id: a.id,
    };
    let result = claim(&state, &a).await;
    if result.ok && !result.plan_id.is_empty() {
        audit_then_confirm(&state, &a, "claim", result, 0).await
    } else {
        publish(&state, &a, "claim", result, 0, None)
    }
}

pub async fn handle_activate(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let a = match account(&state, &id) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if !state.automation_inflight.lock().unwrap().insert(a.id) {
        return Json(ResultBody::failure(
            "account billing action already in progress",
        ))
        .into_response();
    }
    let _flight = Flight {
        state: &state,
        id: a.id,
    };
    let mut result = ResultBody::failure("activation identity unavailable");
    if a.user_id.is_empty() {
        return publish(&state, &a, "activate", result, 0, None);
    }
    for element in ["app_launch", "app_daily_active"] {
        let os = if std::env::consts::OS == "macos" {
            "darwin"
        } else {
            std::env::consts::OS
        };
        let payload = json!({"event_id":request_id(),"client_timezone":iana_time_zone::get_timezone().unwrap_or_else(|_| "UTC".into()),
            "client_language":"zh-CN","element_name":element,"event_region":"app","event_type":"view",
            "event_text":"","event_extra_detail":{},"user_id":a.user_id,"screen_resolution":"2560x1440",
            "app_version":state.management.app_version,"device_os_category":os,"device_os_version":"",
            "device_mid":a.device_mid,"mac_id":"","marketing_params":"{}"});
        match request(
            &state,
            &a,
            reqwest::Method::POST,
            &state.automation.event_report,
            Some(&payload),
            None,
            false,
        )
        .await
        {
            Ok((status, body)) if acknowledged(status, &body) => {}
            _ => {
                result.message = "activation event failed; remote outcome may be partial".into();
                return publish(&state, &a, "activate", result, 0, None);
            }
        }
    }
    let quota = account_refresh::confirm_billing(&state, billing_token(&a), &a.device_mid).await;
    match quota {
        Ok(quota) => {
            result.ok = true;
            result.code = 0;
            result.plan_name = quota.plan_tier.clone();
            result.message = "激活成功，已确认当前套餐".into();
            publish(&state, &a, "activate", result, 0, Some(quota))
        }
        Err(_) => {
            result.message = "activation events acknowledged; quota confirmation failed".into();
            publish(&state, &a, "activate", result, 0, None)
        }
    }
}

async fn reset_status(state: &AppState, a: &Account) -> Result<Value, ()> {
    let (status, body) = request(
        state,
        a,
        reqwest::Method::GET,
        &state.automation.reset_status,
        None,
        None,
        true,
    )
    .await?;
    if !acknowledged(status, &body) || !body["data"].is_object() {
        return Err(());
    }
    let mut data = body["data"].clone();
    for key in ["available_five_hour_resets", "available_week_resets"] {
        if let Some(slots) = data[key].as_array_mut() {
            for slot in slots {
                if let Some(n) = slot["expire_at"].as_i64().filter(|n| *n > 100_000_000_000) {
                    slot["expire_at"] = json!(n / 1000);
                }
            }
        }
    }
    Ok(data)
}

pub async fn handle_reset_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let a = match account(&state, &id) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    match reset_status(&state, &a).await {
        Ok(status) => Json(json!({"ok":true,"status":status,"upstream_synced":0})).into_response(),
        Err(()) => {
            Json(json!({"ok":false,"message":"reset status retrieval failed"})).into_response()
        }
    }
}

pub async fn handle_reset(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let a = match account(&state, &id) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if !state.automation_inflight.lock().unwrap().insert(a.id) {
        return Json(ResultBody::failure(
            "account billing action already in progress",
        ))
        .into_response();
    }
    let _flight = Flight {
        state: &state,
        id: a.id,
    };
    let mut result = ResultBody::failure("reset status retrieval failed");
    let status = match reset_status(&state, &a).await {
        Ok(s) => s,
        Err(()) => return publish(&state, &a, "reset", result, 0, None),
    };
    let reset_type = [
        ("available_five_hour_resets", "FIVE_HOUR"),
        ("available_week_resets", "WEEK"),
    ]
    .into_iter()
    .find(|(key, _)| {
        status[*key].as_array().is_some_and(|slots| {
            slots
                .iter()
                .any(|s| s["expire_at"].as_i64().is_some_and(|n| n > now_secs()))
        })
    })
    .map(|(_, typ)| typ);
    let Some(reset_type) = reset_type else {
        result.ok = true;
        result.code = 0;
        result.message = "无可用重置机会".into();
        return publish(&state, &a, "reset", result, 0, None);
    };
    let payload = json!({"idempotency_key":request_id(),"reset_type":reset_type});
    let mut used_at = 0;
    match request(
        &state,
        &a,
        reqwest::Method::POST,
        &state.automation.reset_use,
        Some(&payload),
        None,
        true,
    )
    .await
    {
        Ok((status, body)) => {
            result.code = code(&body);
            result.ok = acknowledged(status, &body) && body["data"]["used"] != false;
            result.plan_name = format!("配额重置({reset_type})");
            result.message = if result.ok {
                "重置成功"
            } else {
                "reset rejected or unused"
            }
            .into();
            if result.ok {
                used_at = now_secs();
            }
        }
        Err(()) => {
            result.message =
                "reset response unavailable; the slot may already have been consumed".into()
        }
    }
    if result.ok {
        audit_then_confirm(&state, &a, "reset", result, used_at).await
    } else {
        publish(&state, &a, "reset", result, used_at, None)
    }
}
