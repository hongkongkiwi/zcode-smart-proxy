//! Authorization-code and bounded poll login. Background quota/install work is deferred.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    body::to_bytes,
    extract::{Query, Request, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    account_bundle::BundleAccount,
    state::{AppState, Creds, OAuthUrls},
    store,
};

const CLIENT_ID: &str = "client_P8X5CMWmlaRO9gyO-KSqtg";
const MAX_FLOWS: usize = 256;
const MAX_ATTEMPTS: u8 = 3;
const MAX_REQUEST: usize = 32 << 10;
const MAX_BODY: usize = 1 << 20;

#[derive(Clone, Serialize)]
struct Flow {
    state: String,
    redirect_uri: String,
    manual: bool,
    group: String,
    created_at: i64,
    status: &'static str,
    message: &'static str,
    account_id: i64,
    email: String,
    #[serde(skip)]
    deadline: Instant,
    #[serde(skip)]
    poll: bool,
    #[serde(skip)]
    attempts: u8,
}

#[derive(Default)]
pub(crate) struct FlowStore {
    flows: HashMap<String, Flow>,
    workers: HashMap<String, tokio::task::AbortHandle>,
}

impl FlowStore {
    // Unlike Go's start-only cleanup, every capability use enforces the strict TTL.
    fn cleanup(&mut self) {
        let now = Instant::now();
        self.flows.retain(|_, flow| now < flow.deadline);
        self.workers.retain(|key, worker| {
            if self.flows.contains_key(key) {
                true
            } else {
                worker.abort();
                false
            }
        });
    }
}

impl Drop for FlowStore {
    fn drop(&mut self) {
        for worker in self.workers.values() {
            worker.abort();
        }
    }
}

fn error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({"error":{"type":"api_error","message":message}})),
    )
        .into_response()
}

fn html(message: &str) -> Response {
    let escaped = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;");
    let mut response = Html(format!(
        "<!doctype html><html><body><p>{escaped}</p></body></html>"
    ))
    .into_response();
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("referrer-policy", "no-referrer".parse().unwrap());
    response.headers_mut().insert(
        "content-security-policy",
        "default-src 'none'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );
    response
}

fn nonce() -> Result<String, &'static str> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| "cannot generate login state")?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct StartRequest {
    manual: bool,
    poll: bool,
    group: String,
}

pub async fn handle_start(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let body = match to_bytes(request.into_body(), MAX_REQUEST).await {
        Ok(body) => body,
        Err(_) => return error(StatusCode::BAD_REQUEST, "request too large"),
    };
    let request: StartRequest = if body.is_empty() {
        StartRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(_) => return error(StatusCode::BAD_REQUEST, "invalid request body"),
        }
    };
    if request.poll {
        return start_poll(state, request.group).await;
    }
    let nonce = match nonce() {
        Ok(nonce) => nonce,
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, message),
    };
    let redirect = if request.manual {
        &state.oauth.manual_redirect
    } else {
        &state.oauth.callback_url
    };
    let capability = if request.manual {
        URL_SAFE_NO_PAD.encode(
            json!({"nonce":nonce,"app_return_to":redirect,"redirect_uri":redirect}).to_string(),
        )
    } else {
        nonce
    };
    let mut authorize = match url(&state.oauth.authorize) {
        Ok(url) => url,
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, message),
    };
    authorize
        .query_pairs_mut()
        .clear()
        .append_pair("redirect_uri", redirect)
        .append_pair("response_type", "code")
        .append_pair("client_id", CLIENT_ID)
        .append_pair("state", &capability);
    let mut flows = state.oauth_flows.lock().unwrap();
    flows.cleanup();
    if flows.flows.len() >= MAX_FLOWS {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many login flows; try later",
        );
    }
    flows.flows.insert(
        capability.clone(),
        Flow {
            state: capability.clone(),
            redirect_uri: redirect.clone(),
            manual: request.manual,
            group: request.group,
            created_at: crate::auth::now_secs(),
            status: "pending",
            message: "",
            account_id: 0,
            email: String::new(),
            deadline: Instant::now() + state.oauth.flow_ttl,
            poll: false,
            attempts: 0,
        },
    );
    Json(json!({"state":capability,"authorize_url":authorize.as_str(),"manual":request.manual}))
        .into_response()
}

async fn start_poll(state: Arc<AppState>, group: String) -> Response {
    {
        let mut flows = state.oauth_flows.lock().unwrap();
        flows.cleanup();
        if flows.flows.len() >= MAX_FLOWS {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                "too many login flows; try later",
            );
        }
    }
    let mut bytes = [0u8; 32];
    if OsRng.try_fill_bytes(&mut bytes).is_err() {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot generate poll token",
        );
    }
    let token: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let client = match Client::new() {
        Ok(client) => client,
        Err(message) => return error(StatusCode::INTERNAL_SERVER_ERROR, message),
    };
    let init = async {
        client
            .request(
                reqwest::Method::POST,
                url(&state.oauth_poll.init)?,
                &token,
                Some(json!({"provider":"zai"})),
            )
            .await
    };
    let response = match tokio::time::timeout(Duration::from_secs(15), init).await {
        Ok(Ok(response)) => response,
        _ => return error(StatusCode::BAD_GATEWAY, "poll initialization failed"),
    };
    let parsed = (|| {
        let data = poll_envelope(&response)?;
        let flow_id = text(data, &["flow_id"]);
        if flow_id.is_empty() || flow_id == "." || flow_id == ".." {
            return Err("invalid poll flow identifier");
        }
        let mut authorize = url(text(data, &["authorize_url"]))?;
        if authorize.scheme() != "https" {
            return Err("invalid poll authorization URL");
        }
        let integer = |name: &str| {
            data.get(name)
                .and_then(|value| {
                    value.as_i64().or_else(|| {
                        value
                            .as_f64()
                            .filter(|number| number.is_finite())
                            .map(|number| number as i64)
                            .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
                    })
                })
                .unwrap_or(0)
        };
        let expires_at = integer("expires_at");
        let seconds = integer("poll_interval_sec");
        let seconds = if seconds < 1 { 2 } else { seconds.min(15) };
        let interval = state
            .oauth_poll
            .interval_override
            .unwrap_or(Duration::from_secs(seconds as u64));
        if interval.is_zero() {
            return Err("invalid poll interval");
        }
        let mut interstitial = url("https://zcode.z.ai/app/oauth/login")?;
        interstitial
            .query_pairs_mut()
            .append_pair("redirect", "zcode://oauth/callback")
            .append_pair("app_version", &state.management.app_version);
        let query: Vec<_> = authorize
            .query_pairs()
            .into_owned()
            .filter(|(key, _)| key != "redirect_uri")
            .collect();
        authorize
            .query_pairs_mut()
            .clear()
            .extend_pairs(query)
            .append_pair("redirect_uri", interstitial.as_str());
        let mut target = url(&state.oauth_poll.poll_base)?;
        if target.query().is_some() {
            return Err("invalid poll endpoint");
        }
        target
            .path_segments_mut()
            .map_err(|_| "invalid poll endpoint")?
            .pop_if_empty()
            .push(flow_id);
        Ok((flow_id.to_owned(), authorize, expires_at, interval, target))
    })();
    let (flow_id, authorize, expires_at, interval, target) = match parsed {
        Ok(parsed) => parsed,
        Err(_) => {
            return error(
                StatusCode::BAD_GATEWAY,
                "invalid poll initialization response",
            )
        }
    };
    // Go starts the flow budget after cli/init; initialization has its own HTTP bound.
    let deadline = Instant::now() + state.oauth_poll.flow_ttl.min(Duration::from_secs(300));
    let deadline = if expires_at > 0 {
        let now = Instant::now();
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let remaining = Duration::from_secs(expires_at as u64).saturating_sub(wall);
        now + remaining.min(deadline.saturating_duration_since(now))
    } else {
        deadline
    };
    let flow = Flow {
        state: flow_id.clone(),
        redirect_uri: String::new(),
        manual: false,
        group,
        created_at: crate::auth::now_secs(),
        status: "pending",
        message: "",
        account_id: 0,
        email: String::new(),
        deadline,
        poll: true,
        attempts: 0,
    };
    let mut flows = state.oauth_flows.lock().unwrap();
    flows.cleanup();
    if flows.flows.len() >= MAX_FLOWS {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many login flows; try later",
        );
    }
    // Never overwrite an existing one-use capability, including completed flows.
    if flows.flows.contains_key(&flow_id) {
        return error(StatusCode::BAD_GATEWAY, "duplicate poll flow identifier");
    }
    flows.flows.insert(flow_id.clone(), flow.clone());
    let weak = Arc::downgrade(&state);
    let oauth = state.oauth.clone();
    let worker = tokio::spawn(async move {
        let work = async {
            loop {
                if Instant::now() >= deadline {
                    return Err("poll authorization expired");
                }
                match client.poll(target.clone(), &token).await? {
                    Some(data) => return ingest_tokens(&client, &oauth, &flow, &data).await,
                    None => tokio::time::sleep(interval).await,
                }
            }
        };
        let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), work).await;
        // All HTTP and enrichment use copied configuration, never a strong application owner.
        if let Some(state) = weak.upgrade() {
            let result = match result {
                Ok(Ok(account)) if Instant::now() < deadline => {
                    publish_account(&state, &flow, account)
                }
                _ => Err("poll authorization failed or expired"),
            };
            let mut flows = state.oauth_flows.lock().unwrap();
            flows.workers.remove(&flow.state);
            if result.is_err() {
                if let Some(current) = flows.flows.get_mut(&flow.state) {
                    current.status = "failed";
                    current.message = "poll authorization failed or expired";
                }
            }
        }
    });
    flows.workers.insert(flow_id.clone(), worker.abort_handle());
    Json(json!({"state":flow_id,"authorize_url":authorize.as_str(),"manual":false,"poll":true}))
        .into_response()
}

fn poll_envelope(response: &Value) -> Result<&Value, &'static str> {
    if response.get("code").and_then(Value::as_f64) != Some(0.0) {
        return Err("poll upstream rejected the request");
    }
    response
        .get("data")
        .filter(|data| data.is_object())
        .ok_or("invalid poll response")
}

#[derive(Deserialize)]
pub struct FlowQuery {
    state: String,
}

pub async fn handle_status(
    State(state): State<Arc<AppState>>,
    Query(query): Query<FlowQuery>,
) -> Response {
    let mut flows = state.oauth_flows.lock().unwrap();
    flows.cleanup();
    match flows.flows.get(&query.state) {
        Some(flow) => Json(json!(flow)).into_response(),
        None => error(
            StatusCode::NOT_FOUND,
            "login flow does not exist or has expired",
        ),
    }
}

#[derive(Deserialize)]
struct ManualRequest {
    state: String,
    input: String,
}

// Pasted URLs must bind to the selected capability. Bare codes remain supported.
fn manual_code(raw: &str, state: &str) -> Result<String, &'static str> {
    let raw = raw.trim().trim_matches(['\'', '"']);
    if raw.is_empty() || raw.len() > 16 << 10 {
        return Err("invalid authorization code");
    }
    if raw.contains("code=") || raw.contains("://") || raw.contains('?') {
        let parsed = reqwest::Url::parse(raw).map_err(|_| "invalid callback URL")?;
        let mut code = None;
        let mut embedded_state = None;
        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "code" if code.is_none() => code = Some(value.into_owned()),
                "state" if embedded_state.is_none() => embedded_state = Some(value.into_owned()),
                "code" | "state" => return Err("duplicate callback parameter"),
                "error" => return Err("authorization was denied"),
                _ => (),
            }
        }
        if embedded_state
            .as_deref()
            .is_some_and(|embedded| embedded != state)
        {
            return Err("callback state does not match login flow");
        }
        return code
            .filter(|code| !code.trim().is_empty())
            .ok_or("callback is missing code");
    }
    if raw.chars().any(char::is_whitespace) || raw.contains(['&', '=', '#']) {
        return Err("invalid authorization code");
    }
    Ok(raw.to_owned())
}

fn begin(state: &AppState, capability: &str) -> Result<Flow, &'static str> {
    let mut flows = state.oauth_flows.lock().unwrap();
    flows.cleanup();
    let flow = flows
        .flows
        .get_mut(capability)
        .ok_or("login flow does not exist or has expired")?;
    if flow.poll {
        return Err("poll login does not accept authorization codes");
    }
    match flow.status {
        "ready" => return Err("login flow is already complete"),
        "exchanging" => return Err("login flow is exchanging"),
        _ => (),
    }
    if flow.attempts >= MAX_ATTEMPTS {
        return Err("login attempt limit reached; start a new flow");
    }
    flow.attempts += 1;
    flow.status = "exchanging";
    flow.message = "exchanging authorization code";
    Ok(flow.clone())
}

struct ExchangeGuard<'a> {
    state: &'a AppState,
    capability: &'a str,
}

impl Drop for ExchangeGuard<'_> {
    fn drop(&mut self) {
        let mut flows = self.state.oauth_flows.lock().unwrap();
        flows.cleanup();
        if let Some(flow) = flows.flows.get_mut(self.capability) {
            if flow.status == "exchanging" {
                flow.status = "failed";
                flow.message = "authorization exchange failed; retry or start a new flow";
            }
        }
    }
}

pub async fn handle_manual(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let body = match to_bytes(request.into_body(), MAX_REQUEST).await {
        Ok(body) => body,
        Err(_) => return error(StatusCode::BAD_REQUEST, "request too large"),
    };
    let request: ManualRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid request body"),
    };
    let code = match manual_code(&request.input, &request.state) {
        Ok(code) => code,
        Err(message) => return error(StatusCode::BAD_REQUEST, message),
    };
    let flow = match begin(&state, &request.state) {
        Ok(flow) => flow,
        Err(message) => return error(StatusCode::BAD_REQUEST, message),
    };
    match complete(&state, &flow, &code).await {
        Ok(()) => Json(json!({"success":true,"message":"authorization complete"})).into_response(),
        Err(message) => error(StatusCode::BAD_REQUEST, message),
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
pub struct CallbackQuery {
    state: String,
    code: String,
    error: String,
}

pub async fn handle_callback(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    {
        let mut flows = state.oauth_flows.lock().unwrap();
        flows.cleanup();
        let Some(flow) = flows.flows.get_mut(&query.state) else {
            return html(
                "Login flow does not exist or has expired. Start again in the admin panel.",
            );
        };
        if flow.poll {
            return html("Poll login does not accept callbacks. Return to the admin panel.");
        }
        if flow.status == "ready" {
            return html("Authorization is already complete. Return to the admin panel.");
        }
        if flow.status == "exchanging" {
            return html("Authorization is in progress. Return to the admin panel.");
        }
        if !query.error.is_empty() {
            flow.status = "failed";
            // Provider descriptions may contain credentials. Never reflect them in HTML or status.
            flow.message = "authorization was denied";
            return html("Authorization was denied. Return to the admin panel.");
        }
    }
    if query.code.trim().is_empty() || query.code.len() > 16 << 10 {
        return html("Callback is missing a valid authorization code.");
    }
    let flow = match begin(&state, &query.state) {
        Ok(flow) => flow,
        Err(message) => return html(message),
    };
    match complete(&state, &flow, &query.code).await {
        Ok(()) => html("Authorization complete. The account was saved. Return to the admin panel."),
        Err(message) => html(message),
    }
}

async fn complete(state: &AppState, flow: &Flow, code: &str) -> Result<(), &'static str> {
    let _guard = ExchangeGuard {
        state,
        capability: &flow.state,
    };
    let account = tokio::time::timeout(Duration::from_secs(90), exchange(state, flow, code))
        .await
        .map_err(|_| "authorization exchange timed out")??;
    publish_account(state, flow, account)
}

fn publish_account(
    state: &AppState,
    flow: &Flow,
    mut account: BundleAccount,
) -> Result<(), &'static str> {
    account
        .transform_credentials(|value| state.vault.encrypt(value))
        .map_err(|_| "credential storage operation failed")?;
    // Lock order is flow, DB, accounts, creds; no flow lock is held during HTTP.
    let mut flows = state.oauth_flows.lock().unwrap();
    flows.cleanup();
    let current = flows
        .flows
        .get_mut(&flow.state)
        .ok_or("login flow has expired")?;
    if current.status != if flow.poll { "pending" } else { "exchanging" } {
        return Err("login flow is no longer accepting credentials");
    }
    let mut db = state.db.lock().unwrap();
    let mut accounts = state.accounts.lock().unwrap();
    let mut creds = state.creds.lock().unwrap();
    let result = store::import_bundle_accounts_before(
        &mut db,
        &state.vault,
        &[account],
        Some(flow.deadline),
    )
    .map_err(|_| "account storage operation failed")?;
    let id = result.ids[0];
    let mut email = String::new();
    for (account, jwt, key) in result.accounts {
        if account.id == id {
            email = account.email.clone();
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
    current.status = "ready";
    current.message = "authorization complete";
    current.account_id = id;
    current.email = email;
    Ok(())
}

fn text<'a>(value: &'a Value, keys: &[&str]) -> &'a str {
    keys.iter()
        .find_map(|key| {
            value
                .get(*key)
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or("")
}

fn url(raw: &str) -> Result<reqwest::Url, &'static str> {
    let url = reqwest::Url::parse(raw).map_err(|_| "invalid OAuth endpoint")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("invalid OAuth endpoint");
    }
    Ok(url)
}

struct Client(reqwest::Client);

impl Client {
    fn new() -> Result<Self, &'static str> {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map(Self)
            .map_err(|_| "cannot initialize OAuth client")
    }

    async fn request(
        &self,
        method: reqwest::Method,
        target: reqwest::Url,
        bearer: &str,
        body: Option<Value>,
    ) -> Result<Value, &'static str> {
        // Per-request headers and disabled redirects isolate access and business tokens by host.
        let mut request = self.0.request(method, target);
        if !bearer.is_empty() {
            request = request.bearer_auth(bearer);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|_| "OAuth upstream request failed")?;
        if !response.status().is_success() {
            return Err("OAuth upstream rejected the request");
        }
        Self::body(response).await
    }

    async fn poll(
        &self,
        target: reqwest::Url,
        bearer: &str,
    ) -> Result<Option<Value>, &'static str> {
        let response = match self.0.get(target).bearer_auth(bearer).send().await {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };
        let status = response.status();
        if status.as_u16() == 408 || status.as_u16() == 429 || status.is_server_error() {
            return Ok(None);
        }
        if !status.is_success() {
            return Err("poll upstream rejected the request");
        }
        let response = match Self::body(response).await {
            Err("OAuth upstream response failed") => return Ok(None),
            result => result?,
        };
        let data = poll_envelope(&response)?;
        match text(data, &["status"]) {
            "pending" => Ok(None),
            "ready" if !text(data, &["token"]).is_empty() => Ok(Some(data.clone())),
            _ => Err("invalid poll authorization result"),
        }
    }

    async fn body(mut response: reqwest::Response) -> Result<Value, &'static str> {
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "OAuth upstream response failed")?
        {
            if bytes.len() + chunk.len() > MAX_BODY {
                return Err("OAuth upstream response too large");
            }
            bytes.extend_from_slice(&chunk);
        }
        let body: Value =
            serde_json::from_slice(&bytes).map_err(|_| "invalid OAuth upstream response")?;
        Ok(body)
    }

    async fn get(&self, target: reqwest::Url, bearer: &str) -> Result<Value, &'static str> {
        self.request(reqwest::Method::GET, target, bearer, None)
            .await
    }
}

async fn exchange(
    state: &AppState,
    flow: &Flow,
    code: &str,
) -> Result<BundleAccount, &'static str> {
    let client = Client::new()?;
    let response = client.request(reqwest::Method::POST, url(&state.management.oauth_token)?, "",
        Some(json!({"provider":"zai","code":code,"redirect_uri":flow.redirect_uri,"state":flow.state}))).await?;
    if let Some(code) = response.get("code") {
        let code = code
            .as_i64()
            .or_else(|| code.as_str().and_then(|s| s.parse().ok()));
        if !matches!(code, Some(0 | 200)) {
            return Err("OAuth upstream rejected the request");
        }
    }
    ingest_tokens(&client, &state.oauth, flow, &response["data"]).await
}

async fn ingest_tokens(
    client: &Client,
    oauth: &OAuthUrls,
    flow: &Flow,
    data: &Value,
) -> Result<BundleAccount, &'static str> {
    let jwt = text(data, &["token"]);
    if jwt.is_empty() {
        return Err("OAuth response is missing the Coding Plan token");
    }
    let access = text(&data["zai"], &["access_token", "accessToken"]);
    let refresh = text(&data["zai"], &["refresh_token"]);
    let mut user = data
        .get("user")
        .filter(|user| user.is_object())
        .cloned()
        .unwrap_or(json!({}));
    if text(&user, &["email"]).is_empty()
        && text(&user, &["user_id"]).is_empty()
        && !access.is_empty()
    {
        if let Ok(info) = client.get(url(&oauth.userinfo)?, access).await {
            if info["data"].is_object() {
                user = info["data"].clone();
            }
        }
    }
    let mut user_id = text(&user, &["user_id", "id"]).to_owned();
    if user_id.is_empty() {
        if let Some(claims) = jwt
            .split('.')
            .nth(1)
            .and_then(|part| URL_SAFE_NO_PAD.decode(part).ok())
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        {
            user_id = text(&claims, &["user_id", "sub"]).to_owned();
        }
    }
    if user_id.is_empty() {
        let hash = Sha256::digest(jwt.as_bytes());
        let suffix: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
        user_id = format!("oauth-{suffix}");
    }
    let api_key = if access.is_empty() {
        String::new()
    } else {
        api_key(client, oauth, access).await.unwrap_or_default()
    };
    let mut name = text(
        &user,
        &["name", "username", "nickName", "nickname", "displayName"],
    )
    .trim()
    .to_owned();
    if name.is_empty() {
        let email = text(&user, &["email", "mail"]);
        if let Some((prefix, _)) = email.split_once('@') {
            name = prefix.to_owned();
        }
    }
    if name.is_empty() {
        let phone = text(&user, &["phone", "phone_number", "phoneNumber", "mobile"]);
        if !phone.is_empty() {
            name = format!("账号{phone}");
        }
    }
    Ok(BundleAccount {
        user_id,
        email: text(&user, &["email"]).to_owned(),
        display_name: name,
        provider: "zai".into(),
        auth_type: "jwt".into(),
        access_token: access.to_owned(),
        refresh_token: refresh.to_owned(),
        zcode_jwt: jwt.to_owned(),
        api_key,
        user_info: user.to_string(),
        account_group: flow.group.clone(),
        ..Default::default()
    })
}

fn identifier(value: &Value) -> Result<String, &'static str> {
    match value {
        Value::String(value) if !value.is_empty() => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        _ => Err("missing organization or project identifier"),
    }
}

async fn api_key(client: &Client, oauth: &OAuthUrls, access: &str) -> Result<String, &'static str> {
    let login = client
        .request(
            reqwest::Method::POST,
            url(&oauth.business_login)?,
            "",
            Some(json!({"token":access})),
        )
        .await?;
    let business = text(&login["data"], &["access_token", "accessToken"]);
    if business.is_empty() {
        return Err("missing business token");
    }
    let customer = client.get(url(&oauth.customer_info)?, business).await?;
    let orgs = customer["data"]["organizations"]
        .as_array()
        .ok_or("missing organizations")?;
    let org = orgs
        .iter()
        .find(|org| text(org, &["organizationName"]).contains("默认机构"))
        .or_else(|| orgs.first())
        .ok_or("missing organization")?;
    let projects = org["projects"].as_array().ok_or("missing projects")?;
    let project = projects
        .iter()
        .find(|project| text(project, &["projectName"]).contains("默认项目"))
        .or_else(|| projects.first())
        .ok_or("missing project")?;
    let mut keys_url = url(&oauth.project_keys_base)?;
    keys_url
        .path_segments_mut()
        .map_err(|_| "invalid project key endpoint")?
        .pop_if_empty()
        .push(&identifier(&org["organizationId"])?)
        .push("projects")
        .push(&identifier(&project["projectId"])?)
        .push("api_keys");
    let keys = client.get(keys_url.clone(), business).await?;
    let mut key = keys["data"]
        .as_array()
        .and_then(|keys| {
            keys.iter().find(|key| {
                text(key, &["name"]) == "zcode-api-key" && !text(key, &["apiKey"]).is_empty()
            })
        })
        .map(|key| text(key, &["apiKey"]).to_owned())
        .unwrap_or_default();
    if key.is_empty() {
        let created = client
            .request(
                reqwest::Method::POST,
                keys_url.clone(),
                business,
                Some(json!({"name":"zcode-api-key"})),
            )
            .await?;
        key = text(&created["data"], &["apiKey"]).to_owned();
    }
    if key.is_empty() {
        return Err("missing API key");
    }
    keys_url
        .path_segments_mut()
        .map_err(|_| "invalid project key endpoint")?
        .push("copy")
        .push(&key);
    let copied = client.get(keys_url, business).await?;
    let secret = text(&copied["data"], &["secretKey"]);
    if secret.is_empty() {
        return Err("missing API key secret");
    }
    Ok(format!("{key}.{secret}"))
}
