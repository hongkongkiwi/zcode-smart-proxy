use std::{collections::HashSet, sync::Arc, time::Duration};

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{account_refresh, egress, state::AppState};

const BODY_LIMIT: usize = 4 << 20;

#[derive(Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
struct CatalogModel {
    model_id: String,
    name: String,
    context_window: i64,
    priority: i64,
    vision: bool,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct CatalogData {
    #[serde(deserialize_with = "null_default")]
    builtin_models: Vec<CatalogModel>,
    #[serde(deserialize_with = "null_default")]
    providers: Vec<Provider>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Provider {
    #[serde(deserialize_with = "null_default")]
    models: Vec<CatalogModel>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Envelope {
    code: i64,
    #[serde(deserialize_with = "null_default")]
    data: CatalogData,
}

fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

pub(crate) async fn handle_catalog(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let models = state
        .setting("model_catalog")
        .and_then(|raw| serde_json::from_str::<Vec<CatalogModel>>(&raw).ok());
    Json(json!({"models": models}))
}

pub(crate) async fn handle_sync(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let models = match fetch_catalog(&state).await {
        Ok(models) => models,
        Err(()) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"success": false, "message": "model catalog fetch failed"})),
            );
        }
    };
    let serialized = match serde_json::to_string(&models) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"success": false, "message": "model catalog storage failed"})),
            );
        }
    };
    if state
        .persist_settings(&[("model_catalog", &serialized)])
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"success": false, "message": "model catalog storage failed"})),
        );
    }
    let total = models.len();
    (
        StatusCode::OK,
        Json(json!({"success": true, "models": models, "total": total})),
    )
}

async fn fetch_catalog(state: &AppState) -> Result<Vec<CatalogModel>, ()> {
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
    let envelope: Envelope = serde_json::from_slice(&body).map_err(|_| ())?;
    if envelope.code != 0 {
        return Err(());
    }
    let models = if envelope.data.builtin_models.is_empty() {
        envelope
            .data
            .providers
            .into_iter()
            .flat_map(|p| p.models)
            .collect::<Vec<_>>()
    } else {
        envelope.data.builtin_models
    };
    let mut seen = HashSet::new();
    Ok(models
        .into_iter()
        .filter(|model| !model.model_id.is_empty() && seen.insert(model.model_id.clone()))
        .collect())
}
