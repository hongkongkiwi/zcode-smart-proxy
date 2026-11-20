//! CAPTCHA configuration and parameter cache; browser solving is supplied by a solver.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zcode_core::egress::{CaptchaSolver, NoopSolver};

use crate::{account_refresh, egress, state::AppState, store};

const FRESH: Duration = Duration::from_secs(45);
const STALE_GRACE: Duration = Duration::from_secs(300);
const COOLDOWN: Duration = Duration::from_secs(60);
const CONFIG_TTL: Duration = Duration::from_secs(600);
const BODY_LIMIT: usize = 4 << 20;

#[derive(Clone, Deserialize, Serialize)]
struct CaptchaConfig {
    enabled: bool,
    region: String,
    prefix: String,
    #[serde(rename(deserialize = "sceneId"))]
    scene_id: String,
}

#[derive(Deserialize)]
struct ConfigEnvelope {
    code: i64,
    data: ConfigData,
}

#[derive(Deserialize)]
struct ConfigData {
    configs: Configs,
}

#[derive(Deserialize)]
struct Configs {
    captcha: CaptchaConfig,
}

struct Entry {
    param: String,
    region: String,
    at: Instant,
}

#[derive(Default)]
struct Cache {
    entries: HashMap<String, Entry>,
    failures: HashMap<String, Instant>,
    config: Option<(CaptchaConfig, Instant)>,
    solve_gates: HashMap<String, std::sync::Weak<Mutex<()>>>,
}

pub struct CaptchaService {
    pub solver: Arc<dyn CaptchaSolver>,
    cache: Mutex<Cache>,
}

impl Default for CaptchaService {
    fn default() -> Self {
        Self {
            solver: Arc::new(NoopSolver),
            cache: Mutex::new(Cache::default()),
        }
    }
}

#[derive(Default, Deserialize)]
struct SolveRequest {
    account_id: Option<i64>,
}

type Reply = (StatusCode, Json<Value>);

fn error(status: StatusCode, message: &str) -> Reply {
    (status, Json(json!({"success": false, "message": message})))
}

fn success(param_len: usize, region: &str) -> Reply {
    (
        StatusCode::OK,
        Json(json!({"success": true, "param_len": param_len, "region": region})),
    )
}

pub(crate) async fn handle_status(State(state): State<Arc<AppState>>) -> Json<Value> {
    let cache = state.captcha.cache.lock().unwrap();
    let oldest = cache
        .entries
        .values()
        .map(|entry| entry.at.elapsed())
        .max()
        .unwrap_or_default();
    Json(json!({
        "has_param": !cache.entries.is_empty(),
        "param_age_s": oldest.as_secs(),
        "fresh": cache.entries.values().any(|entry| entry.at.elapsed() < FRESH),
        "manual_mode": false,
        "cache_keys": cache.entries.len(),
        "config": cache.config.as_ref().map(|(config, _)| config),
    }))
}

pub(crate) async fn handle_invalidate(State(state): State<Arc<AppState>>) -> Json<Value> {
    state.captcha.cache.lock().unwrap().entries.clear();
    Json(json!({"success": true}))
}

pub(crate) async fn handle_solve(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
) -> Reply {
    let body = match to_bytes(request.into_body(), 64 * 1024).await {
        Ok(body) => body,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid request body"),
    };
    let request: SolveRequest = if body.is_empty() {
        SolveRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(_) => return error(StatusCode::BAD_REQUEST, "invalid request body"),
        }
    };
    let key = match request.account_id {
        Some(id) => {
            let group = state
                .accounts
                .lock()
                .unwrap()
                .iter()
                .find(|account| account.id == id)
                .map(|account| account.account_group.clone());
            let Some(group) = group else {
                return error(StatusCode::NOT_FOUND, "account not found");
            };
            match proxy_for_group(&state, &group) {
                Ok(key) => key,
                Err(()) => return error(StatusCode::BAD_GATEWAY, "captcha egress unavailable"),
            }
        }
        None => match proxy_for_group(&state, "") {
            Ok(key) => key,
            Err(()) => return error(StatusCode::BAD_GATEWAY, "captcha egress unavailable"),
        },
    };
    if state.setting("captcha_mode").as_deref() == Some("off") {
        return success(0, "");
    }
    let cached = {
        let cache = state.captcha.cache.lock().unwrap();
        cache.entries.get(&key).and_then(|entry| {
            let age = entry.at.elapsed();
            (age < FRESH + STALE_GRACE)
                .then(|| (entry.param.len(), entry.region.clone(), age >= FRESH))
        })
    };
    if let Some((len, region, stale)) = cached {
        if stale {
            let state = state.clone();
            tokio::spawn(async move {
                let _ = solve_miss(state, key).await;
            });
        }
        return success(len, &region);
    }
    solve_miss(state, key).await
}

fn proxy_for_group(state: &AppState, group: &str) -> Result<String, ()> {
    let db = state.db.lock().unwrap();
    let nodes = store::list_proxy_nodes(&db).map_err(|_| ())?;
    let selected = nodes
        .iter()
        .find(|node| {
            node.enabled
                && !group.is_empty()
                && node
                    .group_name
                    .split(',')
                    .any(|segment| segment.trim() == group)
        })
        .or_else(|| nodes.iter().find(|node| node.enabled && node.is_default));
    if let Some(node) = selected {
        return egress::node_url(node, state).map_err(|_| ());
    }
    egress::validate_proxy_url(&state.setting("upstream_proxy").unwrap_or_default())
        .map(|url| url.unwrap_or_default())
        .map_err(|_| ())
}

async fn solve_miss(state: Arc<AppState>, key: String) -> Reply {
    {
        let cache = state.captcha.cache.lock().unwrap();
        if cache
            .failures
            .get(&key)
            .is_some_and(|at| at.elapsed() < COOLDOWN)
        {
            return error(StatusCode::BAD_GATEWAY, "captcha solver is cooling down");
        }
    }
    let config = match fetch_config(&state).await {
        Ok(config) => config,
        Err(()) => return error(StatusCode::BAD_GATEWAY, "captcha config fetch failed"),
    };
    if !config.enabled {
        return success(0, "");
    }
    let gate = {
        let mut cache = state.captcha.cache.lock().unwrap();
        cache.solve_gates.retain(|_, gate| gate.strong_count() > 0);
        match cache.solve_gates.get(&key).and_then(|gate| gate.upgrade()) {
            Some(gate) => gate,
            None => {
                let gate = Arc::new(Mutex::new(()));
                cache.solve_gates.insert(key.clone(), Arc::downgrade(&gate));
                gate
            }
        }
    };
    tokio::task::spawn_blocking(move || {
        let _gate = gate.lock().unwrap();
        {
            let cache = state.captcha.cache.lock().unwrap();
            if cache
                .failures
                .get(&key)
                .is_some_and(|at| at.elapsed() < COOLDOWN)
            {
                return error(StatusCode::BAD_GATEWAY, "captcha solver is cooling down");
            }
            if let Some(entry) = cache
                .entries
                .get(&key)
                .filter(|entry| entry.at.elapsed() < FRESH)
            {
                return success(entry.param.len(), &entry.region);
            }
        }
        let param = state.captcha.solver.solve(&config.scene_id, &config.prefix);
        let mut cache = state.captcha.cache.lock().unwrap();
        let Some(param) = param else {
            cache.failures.insert(key, Instant::now());
            return error(StatusCode::BAD_GATEWAY, "captcha solver failed");
        };
        let len = param.len();
        let region = config.region;
        cache.failures.remove(&key);
        cache.entries.insert(
            key,
            Entry {
                param,
                region: region.clone(),
                at: Instant::now(),
            },
        );
        success(len, &region)
    })
    .await
    .unwrap_or_else(|_| error(StatusCode::BAD_GATEWAY, "captcha solver failed"))
}

async fn fetch_config(state: &AppState) -> Result<CaptchaConfig, ()> {
    {
        let cache = state.captcha.cache.lock().unwrap();
        if let Some((config, at)) = &cache.config {
            if at.elapsed() < CONFIG_TTL {
                return Ok(config.clone());
            }
        }
    }
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
    let mut url = reqwest::Url::parse(&state.install_urls.client_configs).map_err(|_| ())?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(());
    }
    url.set_query(None);
    url.query_pairs_mut()
        .append_pair("version", &state.management.app_version)
        .append_pair("os", os);
    let client = egress::client_builder_for_group(state, "")
        .map_err(|_| ())?
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| ())?;
    let version = &state.management.app_version;
    let timezone = iana_time_zone::get_timezone().unwrap_or_else(|_| "UTC".into());
    let mut request = client
        .get(url)
        .header("user-agent", format!("ZCode/{version}"))
        .header("http-referer", "https://zcode.z.ai")
        .header("x-title", "Z Code@electron")
        .header("x-zcode-app-version", version)
        .header("x-platform", format!("{os}-{arch}"))
        .header("x-release-channel", "stable")
        .header("x-client-language", "zh-CN")
        .header("x-client-timezone", timezone)
        .header("x-os-category", if os == "win32" { "windows" } else { os })
        .header("content-type", "application/json")
        .header("x-request-id", account_refresh::request_id());
    let os_version = account_refresh::os_version();
    if !os_version.is_empty() {
        request = request.header("x-os-version", os_version);
    }
    let mut response = request.send().await.map_err(|_| ())?;
    if !response.status().is_success() {
        return Err(());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if chunk.len() > BODY_LIMIT - body.len() {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    let envelope: ConfigEnvelope = serde_json::from_slice(&body).map_err(|_| ())?;
    if envelope.code != 0 {
        return Err(());
    }
    let config = envelope.data.configs.captcha;
    state.captcha.cache.lock().unwrap().config = Some((config.clone(), Instant::now()));
    Ok(config)
}
