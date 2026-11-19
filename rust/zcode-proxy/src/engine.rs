//! The forward engine: the free-first fallback ladder over the classified
//! ladder from zcode-core. Phase 4 skeleton: captcha solving rides the
//! NoopSolver seam (captcha-required free attempts degrade to paid fallback,
//! matching the Go path with a broken browser) and TLS is direct (the
//! fingerprint dialer seam is not wired to rquest yet).

use axum::response::{IntoResponse, Response};
use reqwest::StatusCode;
use serde_json::{json, Value};
use zcode_core::{
    aggregate_anthropic_stream, classify_failure, classify_ok_body, FailureClass, OkBodyClass,
    Shape,
};

use crate::state::{AppState, Creds, UsageRecord};

pub const CHANNEL_FREE: &str = "free";
pub const CHANNEL_PAID: &str = "paid";
pub const ANTHROPIC_VERSION: &str = "2023-06-01";
const MAX_ACCOUNT_ATTEMPTS: usize = 3;

/// Terminal responses carry a token charge; streaming responses defer accounting to body completion.
enum Attempt {
    /// Response is fully written (success or terminal error).
    Written(Response, i64),
    Streaming(reqwest::Response),
    Exhausted,
    /// Try the next candidate; the account cools for `cool_secs` (0 = none).
    /// `soft` marks content-quality failures (challenge/captcha/risk) that
    /// balanced mode cascades to the same account's paid channel.
    NextAccount {
        cool_secs: u64,
        soft: bool,
    },
}

fn endpoint_for(state: &AppState, channel: &str) -> String {
    if channel == CHANNEL_FREE {
        state.upstream.zai.clone()
    } else {
        state.upstream.zai_fallback.clone()
    }
}

fn auth_headers(creds: &Creds, channel: &str) -> Vec<(String, String)> {
    let mut h = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("accept".to_string(), "application/json".to_string()),
        (
            "anthropic-version".to_string(),
            ANTHROPIC_VERSION.to_string(),
        ),
    ];
    if channel == CHANNEL_FREE {
        h.push((
            "Authorization".to_string(),
            format!("Bearer {}", creds.zcode_jwt),
        ));
    } else {
        h.push(("x-api-key".to_string(), creds.api_key.clone()));
    }
    h
}

fn error_response(status: StatusCode, err_type: &str, msg: &str) -> Response {
    (
        status,
        axum::Json(json!({
            "type": "error",
            "error": {"type": err_type, "message": msg}
        })),
    )
        .into_response()
}

fn headers_vec_to_map(h: Vec<(String, String)>) -> reqwest::header::HeaderMap {
    let mut m = reqwest::header::HeaderMap::new();
    for (k, v) in h {
        if let (Ok(k), Ok(v)) = (
            reqwest::header::HeaderName::from_bytes(k.as_bytes()),
            reqwest::header::HeaderValue::from_str(&v),
        ) {
            m.insert(k, v);
        }
    }
    m
}

/// Classify a >=400 response via the core ladder and map to outcomes.
fn classify_to_attempt(
    status: StatusCode,
    cf: Option<String>,
    ct: Option<String>,
    body: String,
    shape: Shape,
) -> Attempt {
    let status_num = status.as_u16();
    let cf_ref = cf.as_deref();
    let ct_ref = ct.as_deref();
    match classify_failure(shape, status_num, cf_ref, ct_ref, &body) {
        FailureClass::Redirect => Attempt::NextAccount {
            cool_secs: 120,
            soft: false,
        },
        FailureClass::Challenge | FailureClass::HtmlBlock => Attempt::NextAccount {
            cool_secs: 300,
            soft: true,
        },
        FailureClass::CaptchaRejected => Attempt::NextAccount {
            cool_secs: 60,
            soft: true,
        },
        FailureClass::RiskBlocked => Attempt::NextAccount {
            cool_secs: 120,
            soft: false,
        },
        FailureClass::ProtocolPassthrough => {
            let resp = (status, body).into_response();
            Attempt::Written(resp, 0)
        }
        FailureClass::CredentialFailure => Attempt::NextAccount {
            cool_secs: 0,
            soft: false,
        },
        FailureClass::RateLimited => Attempt::NextAccount {
            cool_secs: 30,
            soft: false,
        },
        FailureClass::Exhausted => Attempt::Exhausted,
        FailureClass::UpstreamError => {
            let msg = truncate(&body, 300);
            Attempt::Written(
                error_response(
                    status,
                    "api_error",
                    &format!("upstream error HTTP {status_num}: {msg}"),
                ),
                0,
            )
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// POST /v1/messages/count_tokens — the ported estimator.
pub async fn handle_count_tokens(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    body: String,
) -> Response {
    let _ = state;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let est = zcode_core::EST_BASE_TOKENS
        + zcode_core::estimate_messages_tokens(v.get("messages"))
        + zcode_core::estimate_content_tokens(v.get("system"))
        + v.get("tools")
            .and_then(serde_json::Value::as_str)
            .map(zcode_core::estimate_text_tokens)
            .unwrap_or_else(|| {
                v.get("tools")
                    .map(|t| zcode_core::estimate_text_tokens(&t.to_string()))
                    .unwrap_or(0)
            });
    (
        axum::http::StatusCode::OK,
        Json(json!({"input_tokens": est})),
    )
        .into_response()
}

/// GET /v1/models — the default catalog (settings override is a service-layer
/// feature; the skeleton ships the fixed list).
pub async fn handle_models() -> Response {
    let now = now_secs();
    let models = [
        "GLM-5.3",
        "GLM-5.3-Flash",
        "GLM-5.2",
        "GLM-5.1",
        "GLM-5",
        "GLM-5-Turbo",
        "GLM-5V-Turbo",
        "GLM-5.1-Highspeed",
    ];
    let data: Vec<serde_json::Value> = models
        .iter()
        .map(|m| {
            json!({
                "id": m, "object": "model", "type": "model",
                "display_name": m, "created": now, "owned_by": "zcode-proxy-rs"
            })
        })
        .collect();
    (
        axum::http::StatusCode::OK,
        Json(json!({"object": "list", "data": data})),
    )
        .into_response()
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// One upstream attempt: HTTP call + classification. 2xx non-stream bodies
/// go through the envelope path (L3 ordering); stream responses pass bytes
/// through untouched.
async fn attempt_upstream(
    state: &AppState,
    account_id: i64,
    url: &str,
    headers: Vec<(String, String)>,
    payload: &[u8],
    want_stream: bool,
    shape: Shape,
) -> Attempt {
    let client = crate::egress::client_builder(state, Some(account_id)).and_then(|builder| {
        builder
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| crate::store::StoreError::Vault)
    });
    let Ok(client) = client else {
        return Attempt::Written(
            error_response(
                StatusCode::BAD_GATEWAY,
                "api_error",
                "cannot initialize upstream client",
            ),
            0,
        );
    };
    let resp = match client
        .post(url)
        .headers(headers_vec_to_map(headers))
        .body(payload.to_vec())
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => {
            return Attempt::NextAccount {
                cool_secs: 60,
                soft: true,
            }
        }
    };
    let status = resp.status();
    if (300..400).contains(&status.as_u16()) {
        return Attempt::NextAccount {
            cool_secs: 120,
            soft: false,
        };
    }
    if status.as_u16() >= 400 {
        // Headers before body: .text() consumes the response.
        let cf = resp
            .headers()
            .get("cf-mitigated")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let body = match crate::streaming::collect_bounded(resp, None)
            .await
            .and_then(|bytes| String::from_utf8(bytes).map_err(|e| e.to_string()))
        {
            Ok(body) => body,
            Err(error) => {
                return Attempt::Written(
                    error_response(StatusCode::BAD_GATEWAY, "api_error", &error),
                    0,
                )
            }
        };
        return classify_to_attempt(status, cf, ct, body, shape);
    }
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if ct.contains("text/event-stream") && want_stream {
        return Attempt::Streaming(resp);
    }
    if ct.contains("text/event-stream") {
        // Non-stream client: aggregate the upstream SSE (64MB cap). Usage
        // from the aggregate feeds the gateway-key quota charge (in+out+
        // cache_creation+cache_read/10, Go gatewayKeyQuotaCharge).
        let mut sniff = crate::streaming::UsageSniffer::default();
        let bytes = match crate::streaming::collect_bounded(resp, Some(&mut sniff)).await {
            Ok(bytes) => bytes,
            Err(error) => {
                return Attempt::Written(
                    error_response(StatusCode::BAD_GATEWAY, "api_error", &error),
                    sniff.charge(),
                )
            }
        };
        if let Some(error) = sniff.failure() {
            return Attempt::Written(
                error_response(StatusCode::BAD_GATEWAY, "api_error", error),
                sniff.charge(),
            );
        }
        let mut cursor = std::io::Cursor::new(bytes);
        return match aggregate_anthropic_stream(&mut cursor) {
            Ok((raw, _)) => {
                let charge = sniff.charge();
                Attempt::Written(
                    (
                        axum::http::StatusCode::OK,
                        [("content-type", "application/json")],
                        raw,
                    )
                        .into_response(),
                    charge,
                )
            }
            Err(e) => Attempt::Written(
                error_response(
                    StatusCode::BAD_GATEWAY,
                    "api_error",
                    &format!("upstream stream failed: {e}"),
                ),
                sniff.charge(),
            ),
        };
    }
    // 2xx JSON: envelope path (L3 ordering).
    let body = match crate::streaming::collect_bounded(resp, None)
        .await
        .and_then(|bytes| String::from_utf8(bytes).map_err(|e| e.to_string()))
    {
        Ok(body) => body,
        Err(error) => {
            return Attempt::Written(
                error_response(StatusCode::BAD_GATEWAY, "api_error", &error),
                0,
            )
        }
    };
    match classify_ok_body(&body) {
        OkBodyClass::Success => {
            let charge = crate::streaming::json_charge(body.as_bytes());
            Attempt::Written(
                (status, [("content-type", "application/json")], body).into_response(),
                charge,
            )
        }
        OkBodyClass::EmptyMessage => Attempt::NextAccount {
            cool_secs: 60,
            soft: true,
        },
        OkBodyClass::ExhaustedEnvelope => Attempt::Exhausted,
        OkBodyClass::ErrorEnvelope => Attempt::Written(
            (status, [("content-type", "application/json")], body).into_response(),
            0,
        ),
    }
}

use axum::Json;
use std::collections::HashMap;
use std::sync::Arc;

fn terminal_response(
    state: &Arc<AppState>,
    account_id: i64,
    gateway_key_id: i64,
    response: Response,
    charge: i64,
) -> Response {
    if let Err(error) = crate::admin::record_usage_db(
        state,
        UsageRecord {
            account_id,
            status: response.status().as_u16(),
            gateway_key_id,
            quota_charge: charge,
        },
    ) {
        eprintln!("usage accounting failed: {error}");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "api_error",
            "durable usage accounting failed",
        );
    }
    response
}

fn persist_exhausted(
    state: &AppState,
    id: i64,
    expected: &Creds,
) -> Result<bool, crate::store::StoreError> {
    use rusqlite::OptionalExtension;

    let db = state.db.lock().unwrap();
    let mut accounts = state.accounts.lock().unwrap();
    let creds = state.creds.lock().unwrap();
    let Some(account) = accounts.iter_mut().find(|a| a.id == id) else {
        return Ok(false);
    };
    if !account.enabled
        || account.status == "disabled"
        || account.zcode_jwt != expected.zcode_jwt
        || account.api_key != expected.api_key
        || !creds.get(&id).is_some_and(|current| {
            current.zcode_jwt == expected.zcode_jwt && current.api_key == expected.api_key
        })
    {
        return Ok(false);
    }
    let stored: Option<(bool, String, String, String)> = db
        .query_row(
            "SELECT enabled,status,zcode_jwt,api_key FROM accounts WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((enabled, status, jwt, key)) = stored else {
        return Ok(false);
    };
    if !enabled
        || status == "disabled"
        || state.vault.decrypt(&jwt)? != expected.zcode_jwt
        || state.vault.decrypt(&key)? != expected.api_key
    {
        return Ok(false);
    }
    // Publish only after the durable write, without replacing the quota snapshot.
    let updated = db.execute(
        "UPDATE accounts SET status='exhausted',cooling_until=0,last_error='quota exhausted' WHERE id=?1",
        [id],
    )?;
    if updated == 0 {
        return Ok(false);
    }
    account.status = "exhausted".into();
    account.cooling_until = 0;
    Ok(true)
}

/// POST /v1/messages (+ shape aliases): the free-first fallback ladder.
pub async fn handle_messages(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    extension: axum::Extension<crate::auth::ResolvedKey>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    if state.setting("gateway_paused").as_deref() == Some("1") {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "api_error",
            "gateway is globally paused (panic stop); resume it from the admin panel",
        );
    }
    let named = extension.named.clone();
    let parsed: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "body is not valid JSON",
            )
        }
    };
    let mut obj = match parsed {
        Value::Object(o) => o,
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "body must be an object",
            )
        }
    };
    // Model normalization (core): strip provider/ prefix, alias table,
    // config-catalog case-insensitive fallback.
    let config_models: Vec<&str> = vec![];
    if let Some(m) = obj.get("model").and_then(Value::as_str) {
        let normalized = zcode_core::normalize_model_name(m, &config_models);
        obj.insert("model".into(), Value::String(normalized));
    }
    // Named-key per-request gates: quota + model whitelist.
    if let Some(k) = &named {
        if k.quota_total > 0 && k.quota_used >= k.quota_total {
            return error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_error",
                &format!(
                    "gateway key token quota exhausted ({}/{}): {}",
                    k.quota_used, k.quota_total, k.name
                ),
            );
        }
        let model = obj
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_lowercase();
        if !zcode_core::model_allowed(&k.models, &model) {
            return error_response(
                StatusCode::FORBIDDEN,
                "api_error",
                &format!("model not allowed for this gateway key: {model}"),
            );
        }
    }
    let want_stream = obj.get("stream").and_then(Value::as_bool).unwrap_or(false);
    let shape = if headers
        .get("x-zcode-rs-shape")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .contains("highspeed")
    {
        Shape::Highspeed
    } else if headers
        .get("x-zcode-rs-shape")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .contains("off-peak")
    {
        Shape::OffPeak
    } else {
        Shape::Plain
    };
    let session_key = zcode_core::session_key(
        obj.get("metadata")
            .and_then(|m| m.get("user_id"))
            .and_then(Value::as_str),
        None,
    );
    let payload = serde_json::to_vec(&Value::Object(obj)).unwrap_or_default();

    let mode = state
        .setting("paid_fallback_mode")
        .unwrap_or_else(|| "free_first".into());
    let accounts = state.accounts.lock().unwrap().clone();
    let creds_map = state.creds.lock().unwrap().clone();

    // Never mode still serves pure-APIKey accounts through paid_only.
    let phases = if mode == "free_first" || mode == "balanced" {
        vec![CHANNEL_FREE, CHANNEL_PAID]
    } else {
        vec![CHANNEL_FREE, "paid_only"]
    };

    let mut free_tried = HashMap::new();
    for phase in phases {
        let mut skip: HashMap<i64, bool> = if phase == CHANNEL_PAID && mode == "balanced" {
            free_tried.clone()
        } else {
            HashMap::new()
        };
        for _ in 0..MAX_ACCOUNT_ATTEMPTS {
            let now = now_secs();
            let q = zcode_core::SelectionQuery {
                provider: "zai",
                group: "",
                skip: &skip,
                channel: phase,
                now_unix: now,
            };
            let sel = {
                let settings = state.settings.lock().unwrap();
                let mut selector = state.selector.lock().unwrap();
                selector.set_config(zcode_core::StrategyConfig {
                    strategy: settings
                        .get("selection_strategy")
                        .cloned()
                        .unwrap_or_else(|| "round_robin".into()),
                    sticky_enabled: settings.get("sticky_sessions").is_none_or(|v| v != "0"),
                });
                selector.select_sticky_channel(&accounts, &q, &session_key)
            };
            let Some(a) = sel.account else { break };
            let acct = a.clone();
            skip.insert(acct.id, true);
            if phase == CHANNEL_FREE {
                free_tried.insert(acct.id, true);
            }
            let Some(creds) = creds_map.get(&acct.id) else {
                continue;
            };

            let (url, _) = (endpoint_for(&state, phase), ());
            let out = attempt_upstream(
                &state,
                acct.id,
                &url,
                auth_headers(creds, phase),
                &payload,
                want_stream,
                shape,
            )
            .await;
            match out {
                Attempt::Written(resp, charge) => {
                    return terminal_response(
                        &state,
                        acct.id,
                        named.as_ref().map(|k| k.id).unwrap_or(0),
                        resp,
                        charge,
                    );
                }
                Attempt::Streaming(resp) => {
                    return crate::streaming::response(
                        resp,
                        state.clone(),
                        acct.id,
                        named.as_ref().map(|k| k.id).unwrap_or(0),
                    );
                }
                Attempt::Exhausted => {
                    if phase == CHANNEL_FREE {
                        match persist_exhausted(&state, acct.id, creds) {
                            Ok(true) => {
                                if let Some(manager) = state.auto_reset() {
                                    manager.enqueue(acct.id, crate::autoreset::ResetTrigger::Relay);
                                }
                            }
                            Ok(false) => {}
                            Err(error) => {
                                eprintln!("exhausted status persistence failed: {error}");
                                return error_response(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "api_error",
                                    "storage operation failed",
                                );
                            }
                        }
                    }
                }
                Attempt::NextAccount { cool_secs, soft } => {
                    if cool_secs > 0 {
                        state.accounts.lock().unwrap().iter_mut().for_each(|aa| {
                            if aa.id == acct.id {
                                if phase == CHANNEL_FREE {
                                    aa.status = zcode_core::STATUS_COOLING.into();
                                    aa.cooling_until = now_secs() + cool_secs as i64;
                                } else {
                                    aa.paid_cooling_until = now_secs() + cool_secs as i64;
                                }
                            }
                        });
                    }
                    // Balanced mode: soft free-phase failures cascade to the
                    // same account's paid channel immediately.
                    if soft && mode == "balanced" && phase == CHANNEL_FREE {
                        let paid_available = state
                            .accounts
                            .lock()
                            .unwrap()
                            .iter()
                            .find(|a| a.id == acct.id)
                            .is_some_and(|a| zcode_core::paid_channel_available(a, now_secs()));
                        if paid_available {
                            if let Some(creds) = creds_map.get(&acct.id) {
                                let url = endpoint_for(&state, CHANNEL_PAID);
                                let out = attempt_upstream(
                                    &state,
                                    acct.id,
                                    &url,
                                    auth_headers(creds, CHANNEL_PAID),
                                    &payload,
                                    want_stream,
                                    shape,
                                )
                                .await;
                                if let Attempt::NextAccount { cool_secs, .. } = &out {
                                    if *cool_secs > 0 {
                                        state.accounts.lock().unwrap().iter_mut().for_each(|aa| {
                                            if aa.id == acct.id {
                                                aa.paid_cooling_until =
                                                    now_secs() + *cool_secs as i64;
                                            }
                                        });
                                    }
                                }
                                match out {
                                    Attempt::Written(resp, charge) => {
                                        return terminal_response(
                                            &state,
                                            acct.id,
                                            named.as_ref().map(|k| k.id).unwrap_or(0),
                                            resp,
                                            charge,
                                        )
                                    }
                                    Attempt::Streaming(resp) => {
                                        return crate::streaming::response(
                                            resp,
                                            state.clone(),
                                            acct.id,
                                            named.as_ref().map(|k| k.id).unwrap_or(0),
                                        )
                                    }
                                    Attempt::NextAccount { .. } | Attempt::Exhausted => {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "no_available_account",
        "all accounts failed for this request; try again later",
    )
}
