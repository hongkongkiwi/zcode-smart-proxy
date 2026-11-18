//! Authorization-code login only. Poll login and background quota/install work are deferred.

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
    state::{AppState, Creds},
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
    created: Instant,
    #[serde(skip)]
    attempts: u8,
}

#[derive(Default)]
pub(crate) struct FlowStore {
    flows: HashMap<String, Flow>,
}

impl FlowStore {
    // Unlike Go's start-only cleanup, every capability use enforces the strict TTL.
    fn cleanup(&mut self, ttl: Duration) {
        self.flows.retain(|_, flow| flow.created.elapsed() < ttl);
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
        return error(StatusCode::BAD_REQUEST, "poll login is not supported");
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
    flows.cleanup(state.oauth.flow_ttl);
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
            created: Instant::now(),
            attempts: 0,
        },
    );
    Json(json!({"state":capability,"authorize_url":authorize.as_str(),"manual":request.manual}))
        .into_response()
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
    flows.cleanup(state.oauth.flow_ttl);
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
    flows.cleanup(state.oauth.flow_ttl);
    let flow = flows
        .flows
        .get_mut(capability)
        .ok_or("login flow does not exist or has expired")?;
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
        flows.cleanup(self.state.oauth.flow_ttl);
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
        flows.cleanup(state.oauth.flow_ttl);
        let Some(flow) = flows.flows.get_mut(&query.state) else {
            return html(
                "Login flow does not exist or has expired. Start again in the admin panel.",
            );
        };
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
    let mut account = tokio::time::timeout(Duration::from_secs(90), exchange(state, flow, code))
        .await
        .map_err(|_| "authorization exchange timed out")??;
    account
        .transform_credentials(|value| state.vault.encrypt(value))
        .map_err(|_| "credential storage operation failed")?;
    // Lock order is flow, DB, accounts, creds; no flow lock is held during HTTP.
    let mut flows = state.oauth_flows.lock().unwrap();
    flows.cleanup(state.oauth.flow_ttl);
    let current = flows
        .flows
        .get_mut(&flow.state)
        .ok_or("login flow has expired")?;
    if current.status != "exchanging" {
        return Err("login flow is no longer exchanging");
    }
    let mut db = state.db.lock().unwrap();
    let mut accounts = state.accounts.lock().unwrap();
    let mut creds = state.creds.lock().unwrap();
    let result = store::import_bundle_accounts_with_ids(&mut db, &state.vault, &[account])
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
        let mut response = request
            .send()
            .await
            .map_err(|_| "OAuth upstream request failed")?;
        if !response.status().is_success() {
            return Err("OAuth upstream rejected the request");
        }
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
    let data = &response["data"];
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
        if let Ok(info) = client.get(url(&state.oauth.userinfo)?, access).await {
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
        api_key(&client, state, access).await.unwrap_or_default()
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

async fn api_key(client: &Client, state: &AppState, access: &str) -> Result<String, &'static str> {
    let login = client
        .request(
            reqwest::Method::POST,
            url(&state.oauth.business_login)?,
            "",
            Some(json!({"token":access})),
        )
        .await?;
    let business = text(&login["data"], &["access_token", "accessToken"]);
    if business.is_empty() {
        return Err("missing business token");
    }
    let customer = client
        .get(url(&state.oauth.customer_info)?, business)
        .await?;
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
    let mut keys_url = url(&state.oauth.project_keys_base)?;
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
