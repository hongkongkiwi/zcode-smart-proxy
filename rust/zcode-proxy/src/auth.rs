//! Port of auth.go's data-plane key resolution + relay.go's gateway-key
//! gates, as an axum middleware function.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::state::{AppState, NamedKey};

pub fn key_hash(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    format!("{:x}", h.finalize())
}

fn const_eq(a: &str, b: &str) -> bool {
    // Constant-time via digest comparison (Go subtle.ConstantTimeCompare).
    key_hash(a) == key_hash(b)
}

#[derive(Clone)]
pub struct ResolvedKey {
    /// None = root key (unrestricted). Some = named key (gates apply).
    pub named: Option<NamedKey>,
}

pub async fn resolve_key_mw(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let provided = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            req.headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(|s| s.to_string())
        });

    let Some(provided) = provided.filter(|s| !s.is_empty()) else {
        return unauthorized();
    };

    let root = state.root_key.clone();
    if !root.is_empty() && const_eq(&root, &provided) {
        req.extensions_mut().insert(ResolvedKey { named: None });
        return next.run(req).await;
    }

    let hash = key_hash(&provided);
    let named = state
        .named_keys
        .lock()
        .unwrap()
        .iter()
        .find(|k| k.key_hash == hash && k.enabled)
        .cloned();
    let Some(k) = named else {
        return unauthorized();
    };

    // RPM gate (auth-moment counting; rejected hits are not recorded).
    if k.rpm_limit > 0 {
        let ok = state
            .rpm
            .lock()
            .unwrap()
            .allow(k.id, k.rpm_limit, now_secs());
        if !ok {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"type": "error", "error": {"type": "rate_limit_error",
                    "message": format!("gateway key rate limited ({} rpm): {}", k.rpm_limit, k.name)}})),
            )
                .into_response();
        }
    }
    // Rolling windows (5h/24h/7d), first tripped window wins.
    if k.rate_5h > 0 || k.rate_1d > 0 || k.rate_7d > 0 {
        let specs = [
            zcode_core::GwWindowSpec {
                hours: 5,
                limit: k.rate_5h,
                label: "5h",
            },
            zcode_core::GwWindowSpec {
                hours: 24,
                limit: k.rate_1d,
                label: "24h",
            },
            zcode_core::GwWindowSpec {
                hours: 168,
                limit: k.rate_7d,
                label: "7d",
            },
        ];
        let mut windows = state.windows.lock().unwrap();
        if let Some(rej) = windows.admit(k.id, &specs, now_secs()) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"type": "error", "error": {"type": "rate_limit_error",
                    "message": format!("gateway key rate limited ({} rolling window): {}", rej.window, k.name)}})),
            )
                .into_response();
        }
    }
    // Quota + model whitelist are checked per-request in routes (they need
    // the parsed body); stash the key for them.
    req.extensions_mut().insert(ResolvedKey { named: Some(k) });
    next.run(req).await
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"type": "error", "error": {"type": "authentication_error",
            "message": "API key required. Use 'Authorization: Bearer <key>' or 'x-api-key: <key>'"}})),
    )
        .into_response()
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
