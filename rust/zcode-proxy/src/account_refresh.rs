//! Manual quota refresh, with billing and monitor channel selection from quota.go.

use std::{sync::Arc, time::Duration};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, FixedOffset, Local, NaiveDateTime, TimeZone};
use serde::Serialize;
use serde_json::{json, Value};

use crate::{auth::now_secs, state::AppState};

#[derive(Default, Clone, Serialize)]
struct Item {
    name: String,
    total: Option<f64>,
    used: Option<f64>,
    remaining: Option<f64>,
    percent_used: Option<f64>,
    unit: String,
    period_end: String,
}

#[derive(Default, Serialize)]
struct Plan {
    plan_id: String,
    name: String,
    tier: String,
    status: String,
    expire: String,
    total: Option<f64>,
    used: Option<f64>,
    remaining: Option<f64>,
    percent_used: Option<f64>,
    items: Vec<Item>,
}

#[derive(Default, Serialize)]
pub(crate) struct Quota {
    pub(crate) plan_tier: String,
    plan_expire: String,
    total: Option<f64>,
    used: Option<f64>,
    pub(crate) remaining: Option<f64>,
    percent_used: Option<f64>,
    items: Vec<Item>,
    plans: Vec<Plan>,
    source: String,
    refreshed_at: i64,
    not_entitled: bool,
    auth_failed: bool,
    is_empty: bool,
    #[serde(skip_serializing_if = "is_zero")]
    next_reset: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    channels: Vec<Value>,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

impl Quota {
    fn exhausted(&self) -> bool {
        if self.items.is_empty() {
            self.remaining.is_some_and(|n| n <= 0.0)
        } else {
            self.items
                .iter()
                .all(|i| i.remaining.is_some_and(|n| n <= 0.0))
        }
    }

    pub(crate) fn confirmed_state<'a>(
        &self,
        account: &'a zcode_core::AccountView,
    ) -> (&'a str, i64, Option<&'static str>) {
        if !account.enabled || account.status == "disabled" {
            (account.status.as_str(), account.cooling_until, None)
        } else if self.exhausted() {
            ("exhausted", 0, Some("quota exhausted"))
        } else if matches!(
            account.status.as_str(),
            "exhausted" | "inactive" | "invalid"
        ) || (account.status == "cooling" && account.cooling_until <= now_secs())
        {
            ("active", 0, Some(""))
        } else {
            (account.status.as_str(), account.cooling_until, None)
        }
    }

    fn channel(&self) -> Value {
        json!({"source": self.source, "plan_tier": self.plan_tier,
            "remaining": self.remaining.unwrap_or(0.0), "exhausted": self.exhausted(),
            "auth_failed": self.auth_failed, "next_reset": self.next_reset})
    }
}

struct Flight<'a> {
    state: &'a AppState,
    id: i64,
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        self.state
            .quota_refresh_inflight
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

fn snapshot(state: &AppState, id: i64) -> Response {
    let db = state.db.lock().unwrap();
    let accounts = state.accounts.lock().unwrap();
    let Some(account) = accounts.iter().find(|a| a.id == id) else {
        return error(StatusCode::NOT_FOUND, "account not found");
    };
    match crate::store::account_public_view(&db, account) {
        Ok(account) => Json(json!({"success":true,"account":account})).into_response(),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage operation failed",
        ),
    }
}

pub async fn handle_refresh(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let Ok(id) = id.parse::<i64>() else {
        return error(StatusCode::BAD_REQUEST, "invalid id");
    };
    let acquired = state.quota_refresh_inflight.lock().unwrap().insert(id);
    if !acquired {
        return snapshot(&state, id);
    }
    let _flight = Flight { state: &state, id };
    let (credentials, device_mid) = {
        let db = state.db.lock().unwrap();
        let accounts = state.accounts.lock().unwrap();
        let Some(account) = accounts.iter().find(|a| a.id == id) else {
            return error(StatusCode::NOT_FOUND, "account not found");
        };
        match db.query_row(
            "SELECT device_mid,refresh_token FROM accounts WHERE id=?1",
            [id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        ) {
            Ok((device_mid, refresh)) => {
                let Ok(refresh) = state.vault.decrypt(&refresh) else {
                    return error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "credential storage operation failed",
                    );
                };
                (
                    (account.zcode_jwt.clone(), account.api_key.clone(), refresh),
                    device_mid,
                )
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return error(StatusCode::NOT_FOUND, "account not found")
            }
            Err(_) => {
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "storage operation failed",
                )
            }
        }
    };
    let quota = match fetch(&state, &credentials.0, &credentials.1, &device_mid).await {
        Ok(quota) => quota,
        Err(_) => return error(StatusCode::BAD_GATEWAY, "quota retrieval failed"),
    };
    let exchange = if quota.auth_failed {
        let eligible = {
            let db = state.db.lock().unwrap();
            let accounts = state.accounts.lock().unwrap();
            accounts.iter().find(|a| a.id == id).is_some_and(|a| {
                a.provider == "zai"
                    && a.enabled
                    && a.status != "disabled"
                    && a.zcode_jwt == credentials.0
                    && a.api_key == credentials.1
                    && !credentials.2.is_empty()
                    && refresh_matches(&db, &state, id, &credentials.2)
            })
        };
        let attempt = eligible && {
            let mut attempts = state.token_refresh_attempts.lock().unwrap();
            if attempts
                .get(&id)
                .is_some_and(|last| last.elapsed() < Duration::from_secs(90))
            {
                false
            } else {
                attempts.insert(id, std::time::Instant::now());
                true
            }
        };
        if attempt {
            exchange_token(&state.management.oauth_token, &credentials.2)
                .await
                .ok()
        } else {
            None
        }
    } else {
        None
    };
    // Re-read under the writer lock: deletion, disabling, or credential import can race HTTP.
    let db = state.db.lock().unwrap();
    let mut accounts = state.accounts.lock().unwrap();
    let Some(account) = accounts.iter_mut().find(|a| a.id == id) else {
        return error(StatusCode::NOT_FOUND, "account not found");
    };
    if account.zcode_jwt != credentials.0
        || account.api_key != credentials.1
        || !refresh_matches(&db, &state, id, &credentials.2)
    {
        return match crate::store::account_public_view(&db, account) {
            Ok(view) => Json(json!({"success":true,"account":view})).into_response(),
            Err(_) => error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage operation failed",
            ),
        };
    }
    if account.enabled && account.status != "disabled" && account.provider == "zai" {
        if let Some(tokens) = exchange {
            let mut creds = state.creds.lock().unwrap();
            if crate::store::update_account_tokens(&db, &state.vault, id, &tokens).is_ok() {
                account.zcode_jwt = tokens.jwt;
                account.status = "active".into();
                account.cooling_until = 0;
                creds.insert(
                    id,
                    crate::state::Creds {
                        zcode_jwt: account.zcode_jwt.clone(),
                        api_key: account.api_key.clone(),
                    },
                );
                return match crate::store::account_public_view(&db, account) {
                    Ok(view) => Json(json!({"success":true,"account":view})).into_response(),
                    Err(_) => error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "storage operation failed",
                    ),
                };
            }
        }
    }
    let mut status = account.status.as_str();
    let mut cooling = account.cooling_until;
    let mut last_error = None;
    if !account.enabled || status == "disabled" {
        // A quota result cannot undo an explicit administrator disable.
    } else if quota.auth_failed {
        status = "invalid";
        cooling = 0;
        last_error = Some("quota authentication failed (401/403)");
    } else if quota.not_entitled {
        status = "inactive";
        cooling = 0;
        last_error = Some("Coding Plan is not activated");
    } else {
        (status, cooling, last_error) = quota.confirmed_state(account);
    }
    // Auth/entitlement failures change state only, preserving the previous quota snapshot.
    let result = if quota.auth_failed || quota.not_entitled {
        db.execute(
            "UPDATE accounts SET status=?1,cooling_until=?2,last_error=?3 WHERE id=?4",
            rusqlite::params![status, cooling, last_error.unwrap_or(""), id],
        )
    } else {
        db.execute(
            "UPDATE accounts SET status=?1,cooling_until=?2,last_error=COALESCE(?3,last_error),
                quota_json=?4,plan_tier=?5,plan_expire=?6,total_units=?7,used_units=?8,
                remaining=?9,last_checked_at=?10 WHERE id=?11",
            rusqlite::params![
                status,
                cooling,
                last_error,
                serde_json::to_string(&quota).unwrap(),
                quota.plan_tier,
                quota.plan_expire,
                quota.total.unwrap_or(0.0),
                quota.used.unwrap_or(0.0),
                quota.remaining.unwrap_or(0.0),
                now_secs(),
                id
            ],
        )
    };
    match result {
        Ok(0) => return error(StatusCode::NOT_FOUND, "account not found"),
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage operation failed",
            )
        }
        Ok(_) => {}
    }
    account.status = status.to_owned();
    account.cooling_until = cooling;
    if !quota.auth_failed && !quota.not_entitled {
        account.remaining = quota.remaining.unwrap_or(0.0);
    }
    match crate::store::account_public_view(&db, account) {
        Ok(account) => Json(json!({"success":true,"account":account})).into_response(),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage operation failed",
        ),
    }
}

fn refresh_matches(db: &rusqlite::Connection, state: &AppState, id: i64, expected: &str) -> bool {
    db.query_row(
        "SELECT refresh_token FROM accounts WHERE id=?1",
        [id],
        |row| row.get::<_, String>(0),
    )
    .ok()
    .and_then(|value| state.vault.decrypt(&value).ok())
    .is_some_and(|value| value == expected)
}

async fn exchange_token(
    url: &str,
    refresh: &str,
) -> Result<crate::store::AccountTokens, FetchError> {
    // Go's refresh POST uses no billing identity or authorization headers.
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| FetchError::Operational)?;
    let mut response = client
        .post(parse_url(url)?)
        .json(&json!({"provider":"zai","refresh_token":refresh}))
        .send()
        .await
        .map_err(|_| FetchError::Operational)?;
    if !response.status().is_success() {
        return Err(FetchError::Auth);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| FetchError::Operational)?
    {
        if bytes.len() + chunk.len() > 1 << 20 {
            return Err(FetchError::InvalidBody);
        }
        bytes.extend_from_slice(&chunk);
    }
    let body: Value = serde_json::from_slice(&bytes).map_err(|_| FetchError::InvalidBody)?;
    if !business_ok(&body) || !body["data"].is_object() {
        return Err(FetchError::InvalidBody);
    }
    let data = &body["data"];
    let jwt = text(data, "token");
    if jwt.is_empty() {
        return Err(FetchError::InvalidBody);
    }
    let zai = &data["zai"];
    let access = text(zai, "access_token");
    let access = if access.is_empty() {
        text(zai, "accessToken")
    } else {
        access
    };
    Ok(crate::store::AccountTokens {
        jwt: jwt.to_owned(),
        access: access.to_owned(),
        refresh: text(zai, "refresh_token").to_owned(),
        user_info: String::new(),
    })
}

pub(crate) struct Client {
    pub(crate) http: reqwest::Client,
}

pub(crate) fn request_id() -> String {
    use rand::RngCore;
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

fn os_version() -> String {
    if std::env::consts::OS != "windows" {
        return String::new();
    }
    if let Ok(output) = std::process::Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "/v",
            "CurrentBuildNumber",
        ])
        .output()
    {
        if let Some(build) = String::from_utf8_lossy(&output.stdout)
            .lines()
            .find(|line| line.contains("CurrentBuildNumber"))
            .and_then(|line| line.split_whitespace().last())
        {
            return format!("10.0.{build}");
        }
    }
    "10.0.19044".into()
}

pub(crate) enum FetchError {
    Auth,
    Operational,
    InvalidBody,
}

impl Client {
    pub(crate) fn new(app_version: &str, device_mid: &str) -> Result<Self, FetchError> {
        let os = match std::env::consts::OS {
            "macos" => "darwin",
            other => other,
        };
        let platform_os = if os == "windows" { "win32" } else { os };
        let arch = match std::env::consts::ARCH {
            "x86_64" => "x64",
            "aarch64" => "arm64",
            other => other,
        };
        let timezone = iana_time_zone::get_timezone().unwrap_or_else(|_| {
            if os == "windows" {
                "Asia/Shanghai".into()
            } else {
                "UTC".into()
            }
        });
        let mut headers = reqwest::header::HeaderMap::new();
        for (key, value) in [
            ("user-agent", format!("ZCode/{app_version}")),
            ("http-referer", "https://zcode.z.ai".into()),
            ("x-title", "Z Code@electron".into()),
            ("x-zcode-app-version", app_version.into()),
            ("x-platform", format!("{platform_os}-{arch}")),
            ("x-release-channel", "stable".into()),
            ("x-client-language", "zh-CN".into()),
            ("x-client-timezone", timezone),
            ("x-os-category", os.into()),
            ("content-type", "application/json".into()),
        ] {
            headers.insert(key, value.parse().map_err(|_| FetchError::Operational)?);
        }
        if !device_mid.is_empty() {
            headers.insert(
                "x-device-mid",
                device_mid.parse().map_err(|_| FetchError::Operational)?,
            );
        }
        let os_version = os_version();
        if !os_version.is_empty() {
            headers.insert(
                "x-os-version",
                os_version.parse().map_err(|_| FetchError::Operational)?,
            );
        }
        let http = reqwest::Client::builder()
            .default_headers(headers)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(25))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| FetchError::Operational)?;
        Ok(Self { http })
    }

    async fn get(&self, url: reqwest::Url, auth: &str) -> Result<(u16, Value), FetchError> {
        let mut response = self
            .http
            .get(url)
            .header("authorization", auth)
            .header("x-request-id", request_id())
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|_| FetchError::Operational)?;
        let status = response.status().as_u16();
        if matches!(status, 401 | 403) {
            return Err(FetchError::Auth);
        }
        // Read incrementally so missing or dishonest Content-Length cannot grow memory unbounded.
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| FetchError::Operational)?
        {
            if bytes.len() + chunk.len() > 2 << 20 {
                return Err(FetchError::InvalidBody);
            }
            bytes.extend_from_slice(&chunk);
        }
        let body: Value = serde_json::from_slice(&bytes).map_err(|_| FetchError::InvalidBody)?;
        if number(&body, &["code"]) == Some(401.0) {
            return Err(FetchError::Auth);
        }
        Ok((status, body))
    }
}

async fn fetch(
    state: &AppState,
    jwt: &str,
    key: &str,
    device_mid: &str,
) -> Result<Quota, FetchError> {
    let client = Client::new(&state.management.app_version, device_mid)?;
    if !jwt.is_empty() {
        match billing(&client, state, jwt).await {
            Ok(quota) => {
                if quota.exhausted() && !key.is_empty() {
                    if let Ok(mut monitor) = monitor(&client, state, key).await {
                        if !monitor.exhausted() && !monitor.is_empty && !monitor.not_entitled {
                            monitor.channels = vec![quota.channel(), monitor.channel()];
                            return Ok(monitor);
                        }
                    }
                }
                return Ok(quota);
            }
            Err(FetchError::Operational | FetchError::InvalidBody) => {
                return Err(FetchError::Operational)
            }
            Err(FetchError::Auth) if key.is_empty() => {
                return Ok(Quota {
                    auth_failed: true,
                    ..Default::default()
                })
            }
            Err(FetchError::Auth) => {}
        }
    }
    if key.is_empty() {
        return Err(FetchError::Operational);
    }
    match monitor(&client, state, key).await {
        Err(FetchError::Auth) => Ok(Quota {
            auth_failed: true,
            ..Default::default()
        }),
        result => result,
    }
}

fn parse_url(value: &str) -> Result<reqwest::Url, FetchError> {
    let url = reqwest::Url::parse(value).map_err(|_| FetchError::Operational)?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(FetchError::Operational);
    }
    Ok(url)
}

async fn billing(client: &Client, state: &AppState, jwt: &str) -> Result<Quota, FetchError> {
    let mut not_entitled = false;
    for endpoint in ["balance", "current"] {
        let mut url = parse_url(&format!(
            "{}/billing/{endpoint}",
            state.management.billing_base.trim_end_matches('/')
        ))?;
        url.query_pairs_mut()
            .append_pair("app_version", &state.management.app_version);
        let (status, body) = match client.get(url, &format!("Bearer {jwt}")).await {
            Ok(response) => response,
            Err(FetchError::InvalidBody) => continue,
            Err(error) => return Err(error),
        };
        if status == 200 && business_ok(&body) {
            return Ok(normalize_billing(&body));
        }
        not_entitled |= entitlement_error(&body);
    }
    if not_entitled {
        Ok(Quota {
            not_entitled: true,
            is_empty: true,
            ..Default::default()
        })
    } else {
        Err(FetchError::Operational)
    }
}

pub(crate) async fn confirm_billing(
    state: &AppState,
    jwt: &str,
    device_mid: &str,
) -> Result<Quota, FetchError> {
    let client = Client::new(&state.management.app_version, device_mid)?;
    let quota = billing(&client, state, jwt).await?;
    if quota.auth_failed || quota.not_entitled || quota.plan_tier.is_empty() {
        return Err(FetchError::Operational);
    }
    Ok(quota)
}

async fn monitor(client: &Client, state: &AppState, key: &str) -> Result<Quota, FetchError> {
    let (status, body) = client
        .get(parse_url(&state.management.quota_limit)?, key)
        .await?;
    if status != 200 || !business_ok(&body) {
        return if entitlement_error(&body) {
            Ok(Quota {
                not_entitled: true,
                is_empty: true,
                ..Default::default()
            })
        } else {
            Err(FetchError::Operational)
        };
    }
    let subscription = match client
        .get(parse_url(&state.management.subscription)?, key)
        .await
    {
        Ok((200, body)) if business_ok(&body) => body,
        _ => Value::Null,
    };
    Ok(normalize_monitor(&body, &subscription))
}

fn business_ok(body: &Value) -> bool {
    body.is_object()
        && body["success"] != false
        && (body.get("code").is_none() || matches!(number(body, &["code"]), Some(0.0 | 200.0)))
}

fn entitlement_error(body: &Value) -> bool {
    ["msg", "message", "error"].iter().any(|k| {
        let msg = text(body, k);
        msg.contains("不存在coding plan") || msg.contains("没有资格")
    })
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or("")
}

fn number(value: &Value, keys: &[&str]) -> Option<f64> {
    keys.iter().find_map(|key| {
        let v = &value[*key];
        v.as_f64()
            .or_else(|| v.as_str()?.replace(',', "").trim().parse().ok())
            .filter(|n| n.is_finite())
    })
}

fn unwrap_data(mut value: &Value) -> &Value {
    for _ in 0..4 {
        if value["data"].is_object() {
            value = &value["data"];
        } else if value["result"].is_object() {
            value = &value["result"];
        } else {
            break;
        }
    }
    value
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key].as_array().map(Vec::as_slice).unwrap_or(&[])
}

fn tier(value: &str) -> String {
    let lower = value.to_lowercase();
    for (needle, name) in [("max", "Max"), ("pro", "Pro"), ("lite", "Lite")] {
        if lower.contains(needle) {
            return name.into();
        }
    }
    value.into()
}

fn plan_tier(id: &str, name: &str) -> String {
    let hay = format!("{id} {name}");
    let ranked = tier(&hay);
    if ranked != hay {
        return ranked;
    }
    if hay.to_lowercase().contains("start") {
        return "Start Plan".into();
    }
    if [
        "trial",
        "taste",
        "experience",
        "gift",
        "weekend",
        "promo",
        "activity",
        "体验",
    ]
    .iter()
    .any(|s| hay.to_lowercase().contains(s))
    {
        return "体验".into();
    }
    if id.is_empty() {
        name.into()
    } else {
        id.into()
    }
}

fn percent(total: Option<f64>, used: Option<f64>) -> Option<f64> {
    total
        .zip(used)
        .filter(|(t, _)| *t > 0.0)
        .map(|(t, u)| (u / t * 100.0).clamp(0.0, 100.0))
}

fn sum(items: &[Item], field: fn(&Item) -> Option<f64>) -> Option<f64> {
    items.iter().filter_map(field).reduce(|a, b| a + b)
}

fn normalize_billing(raw: &Value) -> Quota {
    let data = unwrap_data(raw);
    let mut q = Quota {
        source: "zcode.z.ai/billing".into(),
        refreshed_at: now_secs(),
        ..Default::default()
    };
    let plans = array(data, "plans");
    let active = plans
        .iter()
        .find(|p| text(p, "status").eq_ignore_ascii_case("active"))
        .or_else(|| plans.first());
    for p in plans {
        let id = text(p, "plan_id");
        if id.is_empty() || q.plans.iter().any(|p| p.plan_id == id) {
            continue;
        }
        q.plans.push(Plan {
            plan_id: id.into(),
            name: text(p, "name").into(),
            tier: plan_tier(id, text(p, "name")),
            status: text(p, "status").into(),
            expire: expire(p),
            ..Default::default()
        });
    }
    if let Some(p) = active {
        q.plan_tier = plan_tier(text(p, "plan_id"), text(p, "name"));
        q.plan_expire = expire(p);
    }
    let balances = array(data, "balances");
    q.is_empty = data["balances"].is_array() && balances.is_empty();
    for b in balances.iter().filter(|b| b.is_object()) {
        let mut item = Item {
            name: ["show_name", "name", "entitlement_id"]
                .iter()
                .map(|k| text(b, k))
                .find(|s| !s.is_empty())
                .unwrap_or("额度")
                .into(),
            total: number(b, &["total_units", "total", "limit", "usage"]),
            used: number(b, &["used_units", "used", "consumed", "currentValue"]),
            remaining: number(
                b,
                &[
                    "remaining_units",
                    "available_units",
                    "remaining",
                    "available",
                ],
            ),
            unit: if text(b, "unit_type").is_empty() {
                text(b, "meter")
            } else {
                text(b, "unit_type")
            }
            .into(),
            period_end: expire(b),
            ..Default::default()
        };
        if item.remaining.is_none() {
            item.remaining = item.total.zip(item.used).map(|(t, u)| (t - u).max(0.0));
        }
        if item.total.is_none() {
            item.total = item.used.zip(item.remaining).map(|(u, r)| u + r);
        }
        item.percent_used = percent(item.total, item.used);
        if let Some(n) = reset_time(b).filter(|n| *n > now_secs()) {
            if q.next_reset == 0 || n < q.next_reset {
                q.next_reset = n;
            }
        }
        let mut id = text(b, "plan_id");
        if id.is_empty() {
            id = text(b, "planId");
        }
        let id = if id.is_empty() && q.plans.len() == 1 {
            q.plans[0].plan_id.clone()
        } else if id.is_empty() {
            "__other__".into()
        } else {
            id.into()
        };
        if !q.plans.iter().any(|p| p.plan_id == id) {
            q.plans.push(Plan {
                tier: plan_tier(&id, ""),
                plan_id: id.clone(),
                name: "其他额度".into(),
                ..Default::default()
            });
        }
        q.plans
            .iter_mut()
            .find(|p| p.plan_id == id)
            .unwrap()
            .items
            .push(item.clone());
        q.items.push(item);
    }
    q.total = sum(&q.items, |i| i.total).or_else(|| number(data, &["total_units", "total"]));
    q.used = sum(&q.items, |i| i.used).or_else(|| number(data, &["used_units", "used"]));
    q.remaining = sum(&q.items, |i| i.remaining)
        .or_else(|| number(data, &["available_units", "remaining_units", "remaining"]));
    q.percent_used = percent(q.total, q.used);
    for plan in &mut q.plans {
        plan.total = sum(&plan.items, |i| i.total);
        plan.used = sum(&plan.items, |i| i.used);
        plan.remaining = sum(&plan.items, |i| i.remaining);
        plan.percent_used = percent(plan.total, plan.used);
        if plan.name.is_empty() {
            plan.name = plan.plan_id.clone();
        }
    }
    if q.plan_expire.is_empty() {
        q.plan_expire = expire(data);
    }
    q
}

fn normalize_monitor(raw: &Value, sub: &Value) -> Quota {
    let data = unwrap_data(raw);
    let mut q = Quota {
        source: "api.z.ai/monitor".into(),
        refreshed_at: now_secs(),
        plan_tier: tier(text(data, "level")),
        ..Default::default()
    };
    let limits = array(data, "limits");
    q.is_empty = limits.is_empty();
    for limit in limits.iter().filter(|l| l.is_object()) {
        let typ = text(limit, "type");
        let n = number(limit, &["number"]).unwrap_or(5.0) as i64;
        let period = match number(limit, &["unit"]).unwrap_or(0.0) as i64 {
            3 => format!("每 {} 小时", if n <= 0 { 5 } else { n }),
            4 => "每天".into(),
            5 => "每月".into(),
            6 => "每周".into(),
            _ => "每周期".into(),
        };
        let mut item = Item {
            name: match typ {
                "TOKENS_LIMIT" => format!("提示次数（{period}）"),
                "TIME_LIMIT" => format!("使用时长（{period}）"),
                _ => typ.into(),
            },
            total: number(limit, &["usage", "total"]),
            used: number(limit, &["currentValue", "used"]),
            remaining: number(limit, &["remaining"]),
            unit: typ.into(),
            ..Default::default()
        };
        item.percent_used =
            percent(item.total, item.used).or_else(|| number(limit, &["percentage"]));
        if let Some(ms) = number(limit, &["nextResetTime"]).filter(|n| *n > 0.0) {
            let n = (ms / 1000.0) as i64;
            item.period_end = format!("{} 重置", format_epoch(n));
            if n > now_secs() && (q.next_reset == 0 || n < q.next_reset) {
                q.next_reset = n;
            }
        }
        q.items.push(item);
    }
    if let Some(item) = q
        .items
        .iter()
        .find(|i| i.unit == "TIME_LIMIT" && i.total.is_some())
        .or_else(|| q.items.iter().find(|i| i.total.is_some()))
    {
        q.total = item.total;
        q.used = item.used;
        q.remaining = item.remaining;
        q.percent_used = item.percent_used;
    }
    let subscriptions = array(sub, "data");
    if let Some(current) = subscriptions
        .iter()
        .find(|s| text(s, "status") == "VALID" && s["inCurrentPeriod"] != false)
        .or_else(|| subscriptions.first())
    {
        let product = text(current, "productName");
        if !product.is_empty() {
            q.plan_tier = tier(product);
        }
        q.plan_expire = expire(current);
    }
    q
}

fn epoch(value: &Value) -> Option<i64> {
    let n = value
        .as_f64()
        .or_else(|| value.as_str()?.trim().parse::<f64>().ok())?;
    if n > 1e12 {
        Some((n / 1000.0) as i64)
    } else if n > 1e9 {
        Some(n as i64)
    } else {
        None
    }
}

fn reset_time(value: &Value) -> Option<i64> {
    for key in ["period_end", "nextResetTime", "next_reset_time"] {
        if let Some(n) = epoch(&value[key]) {
            return Some(n);
        }
        let s = text(value, key).trim();
        if let Ok(time) = DateTime::parse_from_rfc3339(s) {
            return Some(time.timestamp());
        }
        let wall = s.replacen('T', " ", 1);
        if let Some(minute) = wall.get(..16) {
            if let Ok(time) = NaiveDateTime::parse_from_str(minute, "%Y-%m-%d %H:%M") {
                // Billing wall-clock reset strings use the upstream's fixed UTC+8, never host local time.
                return FixedOffset::east_opt(8 * 3600)?
                    .from_local_datetime(&time)
                    .single()
                    .map(|time| time.timestamp());
            }
        }
    }
    None
}

fn expire(value: &Value) -> String {
    for key in [
        "nextRenewTime",
        "expireTime",
        "expire_time",
        "endTime",
        "end_time",
        "expireAt",
        "expiredTime",
        "validEndTime",
        "expires_at",
        "expiresAt",
        "expired_at",
        "period_end",
        "nextResetTime",
        "ends_at",
    ] {
        if let Some(n) = epoch(&value[key]) {
            return format_epoch(n);
        }
        let s = text(value, key).trim();
        if s.is_empty() {
            continue;
        }
        if let Ok(time) = DateTime::parse_from_rfc3339(s) {
            return time
                .with_timezone(&Local)
                .format("%Y-%m-%d %H:%M")
                .to_string();
        }
        let s = s.replacen('T', " ", 1);
        if s.len() >= 16 && s.as_bytes()[4] == b'-' && s.as_bytes()[7] == b'-' {
            return s.chars().take(16).collect();
        }
        return s;
    }
    String::new()
}

fn format_epoch(seconds: i64) -> String {
    DateTime::from_timestamp(seconds, 0)
        .map(|time| {
            time.with_timezone(&Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_default()
}
