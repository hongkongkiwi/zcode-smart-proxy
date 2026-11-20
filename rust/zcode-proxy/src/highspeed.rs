//! Opt-in highspeed card lane, with plain relay fallback before SSE acceptance.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use rusqlite::Connection;
use serde_json::{json, Map, Value};
use zcode_core::{classify_failure, FailureClass, Shape};

use crate::{account_refresh, engine, state::AppState, streaming};

const MAX_ENTRIES: usize = 1024;
const MAX_CONTROL_BODY: usize = 1 << 20;
const CARD_TTL_MS: i64 = 240_000;
const DRAW_BLOCK_MS: i64 = 600_000;

pub struct HighspeedConfig {
    pub draw_url: String,
    pub messages_url: String,
    pub clock: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl Default for HighspeedConfig {
    fn default() -> Self {
        Self {
            draw_url: "https://zcode.z.ai/api/v1/highspeed/draw".into(),
            messages_url: "https://zcode.z.ai/api/v1/highspeed/anthropic/v1/messages".into(),
            clock: Arc::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis() as i64)
            }),
        }
    }
}

pub(crate) fn enabled(state: &AppState) -> bool {
    matches!(
        state.setting("highspeed_lane_enabled").as_deref(),
        Some("1" | "true")
    )
}

#[derive(PartialEq, Eq)]
struct Account {
    id: i64,
    group: String,
    device: String,
    jwt: String,
    key: String,
    access: String,
    refresh: String,
    user_id: String,
    user_info: String,
    creds_raw: String,
}

impl Account {
    // Keep the stored credential values for exact comparison, even when plaintext is unchanged.
    fn read(db: &Connection, id: i64) -> rusqlite::Result<Self> {
        db.query_row(
            "SELECT account_group,device_mid,zcode_jwt,api_key,access_token,refresh_token,
                    COALESCE(user_id,''),user_info,creds_raw FROM accounts
             WHERE id=?1 AND enabled<>0 AND status<>'disabled' AND provider='zai' AND zcode_jwt<>''",
            [id],
            |row| Ok(Self {
                id,
                group: row.get(0)?,
                device: row.get(1)?,
                jwt: row.get(2)?,
                key: row.get(3)?,
                access: row.get(4)?,
                refresh: row.get(5)?,
                user_id: row.get(6)?,
                user_info: row.get(7)?,
                creds_raw: row.get(8)?,
            }),
        )
    }

    fn is_current(&self, db: &Connection) -> bool {
        Self::read(db, self.id).is_ok_and(|current| current == *self)
    }
}

struct Card {
    id: HeaderValue,
    model: String,
    expires_at: i64,
    drawn_at: i64,
}

impl Card {
    fn valid(&self, now: i64) -> bool {
        now.saturating_sub(self.drawn_at) <= CARD_TTL_MS
            && (self.expires_at <= 0 || now < self.expires_at)
    }
}

#[derive(Default)]
struct Entry {
    drawing: bool,
    cached: Option<(Arc<Account>, Arc<Card>)>,
    blocked: Option<(Arc<Account>, i64)>,
}

#[derive(Default)]
pub(crate) struct CardManager {
    entries: Mutex<HashMap<i64, Entry>>,
    rotation: AtomicUsize,
}

struct DrawSlot<'a> {
    manager: &'a CardManager,
    id: i64,
}

impl Drop for DrawSlot<'_> {
    fn drop(&mut self) {
        let mut entries = self.manager.entries.lock().unwrap();
        if let Some(entry) = entries.get_mut(&self.id) {
            entry.drawing = false;
            if entry.cached.is_none() && entry.blocked.is_none() {
                entries.remove(&self.id);
            }
        }
    }
}

fn pick_account(state: &AppState, group: &str) -> Option<Arc<Account>> {
    let db = state.db.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT id,account_group FROM accounts WHERE enabled<>0 AND status<>'disabled'
         AND provider='zai' AND zcode_jwt<>'' ORDER BY id",
        )
        .ok()?;
    let eligible: Vec<(i64, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .ok()?
        .collect::<rusqlite::Result<_>>()
        .ok()?;
    let now = (state.highspeed.clock)();
    state
        .highspeed_cards
        .entries
        .lock()
        .unwrap()
        .retain(|id, entry| {
            entry.drawing
                || (eligible.binary_search_by_key(id, |(id, _)| *id).is_ok()
                    && (entry
                        .cached
                        .as_ref()
                        .is_some_and(|(_, card)| card.valid(now))
                        || entry
                            .blocked
                            .as_ref()
                            .is_some_and(|(_, until)| *until > now)))
        });
    let candidates: Vec<_> = eligible
        .iter()
        .filter(|(_, account_group)| {
            group.is_empty() || account_group.split(',').any(|g| g.trim() == group)
        })
        .collect();
    if candidates.is_empty() {
        return None;
    }
    let index = state
        .highspeed_cards
        .rotation
        .fetch_add(1, Ordering::Relaxed)
        % candidates.len();
    let id = candidates[index].0;
    let mut account = Account::read(&db, id).ok()?;
    if account.device.is_empty() {
        account.device = crate::identity::ensure_locked(&db, id).ok()?;
    }
    Some(Arc::new(account))
}

fn begin_draw<'a>(
    manager: &'a CardManager,
    account: &Arc<Account>,
    now: i64,
) -> Option<Result<DrawSlot<'a>, Arc<Card>>> {
    let mut entries = manager.entries.lock().unwrap();
    if entries.len() >= MAX_ENTRIES && !entries.contains_key(&account.id) {
        return None;
    }
    let entry = entries.entry(account.id).or_default();
    if entry.drawing {
        return None;
    }
    if entry
        .blocked
        .as_ref()
        .is_some_and(|(owner, until)| owner == account && *until > now)
    {
        return None;
    }
    if let Some((owner, card)) = &entry.cached {
        if owner == account && card.valid(now) {
            return Some(Err(card.clone()));
        }
    }
    entry.cached = None;
    entry.blocked = None;
    entry.drawing = true;
    Some(Ok(DrawSlot {
        manager,
        id: account.id,
    }))
}

async fn card_for(
    state: &AppState,
    account: &Arc<Account>,
    client: &reqwest::Client,
    auth: &HeaderMap,
    model: &str,
) -> Option<Arc<Card>> {
    let slot = {
        let now = (state.highspeed.clock)();
        let db = state.db.lock().unwrap();
        if !account.is_current(&db) {
            return None;
        }
        match begin_draw(&state.highspeed_cards, account, now)? {
            Ok(slot) => slot,
            Err(card) => return Some(card),
        }
    };
    let result = draw(state, account, client, auth, model).await;
    let now = (state.highspeed.clock)();
    let db = state.db.lock().unwrap();
    if !account.is_current(&db) {
        return None;
    }
    let mut entries = slot.manager.entries.lock().unwrap();
    let entry = entries.get_mut(&slot.id)?;
    match result {
        Ok(card) => {
            let card = Arc::new(card);
            entry.cached = Some((account.clone(), card.clone()));
            Some(card)
        }
        Err(next_draw_at) => {
            let delay = if next_draw_at > now {
                next_draw_at.saturating_sub(now).clamp(60_000, 3_600_000)
            } else {
                DRAW_BLOCK_MS
            };
            entry.blocked = Some((account.clone(), now.saturating_add(delay)));
            None
        }
    }
}

fn invalidate_card(state: &AppState, account: &Account, card: &Arc<Card>) {
    let mut entries = state.highspeed_cards.entries.lock().unwrap();
    if let Some(entry) = entries.get_mut(&account.id) {
        if entry
            .cached
            .as_ref()
            .is_some_and(|(_, current)| Arc::ptr_eq(current, card))
        {
            entry.cached = None;
        }
    }
}

fn plan_headers(state: &AppState, account: &Account) -> Option<HeaderMap> {
    let jwt = zeroize::Zeroizing::new(state.vault.decrypt(&account.jwt).ok()?);
    if jwt.is_empty() {
        return None;
    }
    let mut plan = zeroize::Zeroizing::new(state.vault.decrypt(&account.access).ok()?);
    if plan.is_empty() {
        plan = zeroize::Zeroizing::new(state.vault.decrypt(&account.key).ok()?);
    }
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        os => os,
    };
    let platform_os = if os == "windows" { "win32" } else { os };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        arch => arch,
    };
    let version = &state.management.app_version;
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("user-agent", format!("ZCode/{version}")),
        ("http-referer", "https://zcode.z.ai".into()),
        ("x-title", "Z Code@electron".into()),
        ("x-zcode-app-version", version.clone()),
        ("x-platform", format!("{platform_os}-{arch}")),
        ("x-release-channel", "stable".into()),
        ("x-client-language", "zh-CN".into()),
        (
            "x-client-timezone",
            iana_time_zone::get_timezone().unwrap_or_else(|_| "UTC".into()),
        ),
        ("x-os-category", os.into()),
        ("x-device-mid", account.device.clone()),
        ("bigmodel-target-type", "PERSONAL".into()),
    ] {
        headers.insert(name, value.parse().ok()?);
    }
    for (name, token) in [("authorization", jwt), ("x-bigmodel-authorization", plan)] {
        if !token.is_empty() {
            let mut value: HeaderValue = format!("Bearer {}", token.as_str()).parse().ok()?;
            value.set_sensitive(true);
            headers.insert(name, value);
        }
    }
    Some(headers)
}

async fn read_control_body(response: &mut reqwest::Response) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if chunk.len() > MAX_CONTROL_BODY - bytes.len() {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    Some(bytes)
}

async fn draw(
    state: &AppState,
    account: &Account,
    client: &reqwest::Client,
    auth: &HeaderMap,
    model: &str,
) -> Result<Card, i64> {
    let mut response = client.post(&state.highspeed.draw_url)
        .timeout(Duration::from_secs(15))
        .headers(auth.clone())
        .header("x-request-id", account_refresh::request_id())
        .json(&json!({"task_id": account_refresh::request_id(), "provider": "builtin:zai-coding-plan", "model": model}))
        .send().await.map_err(|_| 0_i64)?;
    let status = response.status();
    let bytes = read_control_body(&mut response).await;
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        handle_auth_failure(state, account, response.headers(), status, bytes.as_deref()).await;
    }
    let body: Value = serde_json::from_slice(&bytes.ok_or(0_i64)?).map_err(|_| 0_i64)?;
    let data = &body["data"];
    let next_draw_at = data["next_draw_at"].as_i64().unwrap_or(0);
    if !status.is_success()
        || body
            .get("code")
            .is_some_and(|code| code.as_i64() != Some(0))
    {
        return Err(next_draw_at);
    }
    let card = &data["card"];
    let id = card["card_id"]
        .as_str()
        .filter(|id| !id.trim().is_empty())
        .ok_or(next_draw_at)?;
    let mut id = HeaderValue::from_str(id).map_err(|_| next_draw_at)?;
    id.set_sensitive(true);
    let drawn_at = (state.highspeed.clock)();
    let card = Card {
        id,
        model: card["model"].as_str().unwrap_or_default().into(),
        expires_at: card["expires_at"].as_i64().unwrap_or(0),
        drawn_at,
    };
    card.valid(drawn_at).then_some(card).ok_or(next_draw_at)
}

async fn handle_auth_failure(
    state: &AppState,
    account: &Account,
    headers: &HeaderMap,
    status: StatusCode,
    bytes: Option<&[u8]>,
) {
    let text = |name| headers.get(name).and_then(|h| h.to_str().ok());
    let class = classify_failure(
        Shape::Highspeed,
        status.as_u16(),
        text("cf-mitigated"),
        text("content-type"),
        &String::from_utf8_lossy(bytes.unwrap_or_default()),
    );
    match class {
        FailureClass::Challenge
        | FailureClass::HtmlBlock
        | FailureClass::CaptchaRejected
        | FailureClass::RiskBlocked => {
            let db = state.db.lock().unwrap();
            if !account.is_current(&db) {
                return;
            }
            let mut accounts = state.accounts.lock().unwrap();
            let until = engine::now_secs() + 300;
            if matches!(db.execute(
                "UPDATE accounts SET status='cooling',cooling_until=?1,last_error='highspeed upstream challenge' WHERE id=?2",
                rusqlite::params![until, account.id],
            ), Ok(1)) {
                if let Some(current) = accounts.iter_mut().find(|a| a.id == account.id) {
                    current.status = "cooling".into();
                    current.cooling_until = until;
                }
            }
        }
        FailureClass::CredentialFailure if bytes.is_some() => {
            let current = {
                let db = state.db.lock().unwrap();
                account.is_current(&db)
                    && state.accounts.lock().unwrap().iter().any(|a| {
                        a.id == account.id
                            && a.enabled
                            && a.status != "disabled"
                            && state
                                .vault
                                .decrypt(&account.jwt)
                                .is_ok_and(|jwt| jwt == a.zcode_jwt)
                            && state
                                .vault
                                .decrypt(&account.key)
                                .is_ok_and(|key| key == a.api_key)
                    })
            };
            if current {
                // Only the quota refresh can confirm credential failure; a transport error cannot.
                let _ = account_refresh::refresh_account(state, account.id).await;
            }
        }
        _ => {}
    }
}

fn card_expired(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(name, value)| {
            ((name == "provider_code" || name == "providerErrorCode")
                && (value.as_i64() == Some(3402) || value.as_str() == Some("3402")))
                || card_expired(value)
        }),
        Value::Array(items) => items.iter().any(card_expired),
        _ => false,
    }
}

fn forward_client_headers(outbound: &mut HeaderMap, inbound: &HeaderMap) {
    for name in inbound.keys() {
        let key = name.as_str();
        if matches!(
            key,
            "accept-language"
                | "cache-control"
                | "anthropic-beta"
                | "anthropic-dangerous-direct-browser-access"
                | "traceparent"
                | "tracestate"
                | "x-client-request-id"
                | "x-zcode-query-source"
                | "x-zcode-trace-id"
        ) || key.starts_with("x-stainless-")
        {
            if let Some(value) = inbound.get(name).filter(|v| v.len() <= 4096) {
                outbound.insert(name.clone(), value.clone());
            }
        }
    }
}

pub(crate) async fn relay(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    body: &Map<String, Value>,
    want_stream: bool,
    key_id: i64,
) -> Option<Response> {
    let model = body.get("model").and_then(Value::as_str)?;
    if !model.to_ascii_lowercase().ends_with("-highspeed") {
        return None;
    }
    let group = headers
        .get("x-zcode-group")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let account = pick_account(state, group)?;
    let auth = plan_headers(state, &account)?;
    let client = crate::egress::client_builder_for_group(state, &account.group)
        .ok()?
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(10))
        .build()
        .ok()?;
    let mut outbound = auth.clone();
    outbound.insert("accept", HeaderValue::from_static("text/event-stream"));
    outbound.insert(
        "anthropic-version",
        HeaderValue::from_static(engine::ANTHROPIC_VERSION),
    );
    outbound.insert("x-zcode-agent", HeaderValue::from_static("glm"));
    forward_client_headers(&mut outbound, headers);

    let mut payload = body.clone();
    payload.insert("stream".into(), json!(true));
    payload.entry("metadata").or_insert_with(|| json!({
        "user_id": json!({"device_id": account.device, "account_uuid": "", "session_id": ""}).to_string()
    }));
    for attempt in 0..2 {
        let card = card_for(state, &account, &client, &auth, model).await?;
        outbound.insert("x-highspeed-card-id", card.id.clone());
        payload.insert(
            "model".into(),
            json!(if card.model.is_empty() {
                model
            } else {
                &card.model
            }),
        );
        let mut upstream = client
            .post(&state.highspeed.messages_url)
            .headers(outbound.clone())
            .header("x-request-id", account_refresh::request_id())
            .json(&payload)
            .send()
            .await
            .ok()?;
        let status = upstream.status();
        if status.is_success() {
            let is_sse = upstream
                .headers()
                .get("content-type")
                .and_then(|h| h.to_str().ok())
                .is_some_and(|ct| {
                    ct.split(';')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .eq_ignore_ascii_case("text/event-stream")
                });
            if !is_sse {
                return None;
            }
            return Some(accepted_sse(state, account.id, key_id, want_stream, upstream).await);
        }
        if status.is_redirection() || status == StatusCode::TOO_MANY_REQUESTS {
            return None;
        }
        let bytes = tokio::time::timeout(Duration::from_secs(15), read_control_body(&mut upstream))
            .await
            .ok()
            .flatten();
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            handle_auth_failure(
                state,
                &account,
                upstream.headers(),
                status,
                bytes.as_deref(),
            )
            .await;
            return None;
        }
        let error: Value = serde_json::from_slice(&bytes?).ok()?;
        if !card_expired(&error) {
            return None;
        }
        invalidate_card(state, &account, &card);
        if attempt == 1 {
            return None;
        }
    }
    None
}

async fn accepted_sse(
    state: &Arc<AppState>,
    account_id: i64,
    key_id: i64,
    want_stream: bool,
    upstream: reqwest::Response,
) -> Response {
    let request_id = upstream.headers().get("x-request-id").cloned();
    let mut response = if want_stream {
        let mut response = streaming::response(upstream, state.clone(), account_id, key_id);
        response
            .headers_mut()
            .insert("cache-control", HeaderValue::from_static("no-cache"));
        response
    } else {
        let mut recorder = streaming::Recorder {
            state: state.clone(),
            record: Some(crate::state::UsageRecord {
                account_id,
                gateway_key_id: key_id,
                status: 499,
                quota_charge: 0,
            }),
            sniff: streaming::UsageSniffer::default(),
        };
        let result = streaming::collect_bounded(upstream, Some(&mut recorder.sniff)).await;
        let mut response = match result {
            Ok(bytes) if recorder.sniff.failure().is_none() => {
                match zcode_core::aggregate_anthropic_stream(&mut std::io::Cursor::new(bytes)) {
                    Ok((raw, _)) => (
                        [
                            ("content-type", "application/json"),
                            ("cache-control", "no-store"),
                        ],
                        raw,
                    )
                        .into_response(),
                    Err(_) => engine::error_response(
                        StatusCode::BAD_GATEWAY,
                        "api_error",
                        "upstream SSE aggregation failed",
                    ),
                }
            }
            _ => engine::error_response(
                StatusCode::BAD_GATEWAY,
                "api_error",
                recorder
                    .sniff
                    .failure()
                    .unwrap_or("upstream SSE aggregation failed"),
            ),
        };
        if let Err(error) = recorder.finish(response.status().as_u16()) {
            eprintln!("highspeed usage accounting failed: {error}");
            response = engine::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "api_error",
                "durable usage accounting failed",
            );
        }
        response
    };
    if let Some(id) = request_id {
        response.headers_mut().insert("x-request-id", id);
    }
    response
}

pub(crate) async fn status(State(state): State<Arc<AppState>>) -> Response {
    let enabled = enabled(&state);
    let now = (state.highspeed.clock)();
    let db = state.db.lock().unwrap();
    let accounts = state.accounts.lock().unwrap();
    let entries = state.highspeed_cards.entries.lock().unwrap();
    let accounts: Vec<_> = accounts
        .iter()
        .filter(|a| a.provider == "zai")
        .map(|a| {
            let mut view =
                json!({"id": a.id, "email": a.email, "enabled": a.enabled, "status": a.status});
            if let Some(entry) = entries.get(&a.id) {
                if let Some((account, card)) = &entry.cached {
                    if account.is_current(&db) {
                        view["card_id"] = json!(card.id.to_str().unwrap_or_default());
                        view["card_model"] = json!(card.model);
                        view["card_valid"] = json!(card.valid(now));
                        if card.expires_at > 0 {
                            view["card_expires_in_sec"] =
                                json!(card.expires_at.saturating_sub(now).max(0) / 1000);
                        }
                    }
                }
                if let Some((account, until)) = &entry.blocked {
                    if *until > now && account.is_current(&db) {
                        view["draw_blocked_for_sec"] = json!(until.saturating_sub(now) / 1000);
                    }
                }
            }
            view
        })
        .collect();
    Json(json!({"enabled": enabled, "accounts": accounts})).into_response()
}
