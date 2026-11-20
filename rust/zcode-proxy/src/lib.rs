//! Library surface: data plane + admin panel, exposed for integration tests
//! (bin entrypoint in main.rs).

pub mod account_billing;
pub mod account_bundle;
pub mod account_local;
pub mod account_oauth;
pub mod account_paste;
pub mod account_refresh;
pub mod account_routes;
pub mod admin;
pub mod auth;
pub mod autoreset;
pub mod background_refresh;
pub mod captcha;
pub mod console;
mod cron;
mod desktop_credentials;
pub mod egress;
pub mod engine;
pub mod gateway_admin;
pub mod go_compat;
pub mod go_import;
pub mod highspeed;
pub mod identity;
pub mod install_sequence;
mod local_switchback;
mod model_catalog;
mod offpeak;
mod offpeak_queue;
pub mod openai_routes;
mod openai_stream;
pub mod passkey;
mod plan_admin;
mod proxy_admin;
pub mod proxy_diagnostics;
pub mod scheduler;
pub mod state;
pub mod store;
mod streaming;
pub mod vault;

use std::sync::Arc;

use axum::{
    middleware,
    routing::{get, post, put},
    Router,
};

use state::AppState;

/// Data plane behind the API-key gate.
fn data_plane(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/async/v1/messages",
            axum::routing::any(offpeak_queue::handle_messages),
        )
        .route("/v1/messages", post(engine::handle_messages))
        .route("/v1/chat/completions", post(openai_routes::handle_chat))
        .route("/v1/completions", post(openai_routes::handle_completions))
        .route("/v1/responses", post(openai_routes::handle_responses))
        .route(
            "/v1/messages/count_tokens",
            post(engine::handle_count_tokens),
        )
        .route("/v1/models", get(engine::handle_models))
        .route(
            "/api/v1/ultra/anthropic/v1/messages",
            post(engine::handle_messages),
        )
        .route(
            "/api/v1/ultra-zai/anthropic/v1/messages",
            post(engine::handle_messages),
        )
        .route(
            "/api/v1/highspeed/anthropic/v1/messages",
            post(engine::handle_highspeed_messages),
        )
        .route(
            "/api/v1/off-peak/anthropic/v1/messages",
            post(engine::handle_offpeak_messages),
        )
        .route(
            "/api/v1/zcode-plan/anthropic/v1/messages",
            post(engine::handle_messages),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::resolve_key_mw,
        ))
        .with_state(state)
}

/// Admin API behind the session gate (login mounted open below).
fn admin_api(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/accounts", get(admin::handle_accounts))
        .route("/api/highspeed/status", get(highspeed::status))
        .route(
            "/api/offpeak/availability",
            get(offpeak::handle_availability),
        )
        .route("/api/captcha/status", get(captcha::handle_status))
        .route("/api/captcha/invalidate", post(captcha::handle_invalidate))
        .route("/api/captcha/solve", post(captcha::handle_solve))
        .route(
            "/api/proxies",
            get(proxy_admin::handle_list).post(proxy_admin::handle_create),
        )
        .route(
            "/api/proxies/:id",
            put(proxy_admin::handle_update).delete(proxy_admin::handle_delete),
        )
        .route("/api/proxies/system", get(proxy_diagnostics::handle_system))
        .route(
            "/api/proxies/probe-ports",
            get(proxy_diagnostics::handle_probe_ports),
        )
        .route(
            "/api/proxies/test-url",
            post(proxy_diagnostics::handle_test_url),
        )
        .route(
            "/api/proxies/:id/test",
            post(proxy_diagnostics::handle_test_node),
        )
        .route(
            "/api/plans",
            get(plan_admin::handle_list).post(plan_admin::handle_create),
        )
        .route(
            "/api/plans/:id",
            put(plan_admin::handle_update).delete(plan_admin::handle_delete),
        )
        .route("/api/plans/:id/run", post(scheduler::handle_run))
        .route("/api/plans/running", get(scheduler::handle_running))
        .route("/api/claim-records", get(plan_admin::handle_claim_records))
        .route("/api/plan-runs", get(plan_admin::handle_plan_runs))
        .route(
            "/api/keys",
            get(gateway_admin::handle_list).post(gateway_admin::handle_create),
        )
        .route(
            "/api/keys/:id",
            put(gateway_admin::handle_update).delete(gateway_admin::handle_delete),
        )
        .route(
            "/api/accounts/oauth/start",
            post(account_oauth::handle_start),
        )
        .route(
            "/api/accounts/oauth/manual",
            post(account_oauth::handle_manual),
        )
        .route(
            "/api/accounts/oauth/status",
            get(account_oauth::handle_status),
        )
        .route(
            "/api/accounts/add",
            post(crate::account_routes::handle_account_add),
        )
        .route(
            "/api/accounts/import/paste",
            post(account_paste::handle_import),
        )
        .route("/api/accounts/export", post(account_bundle::handle_export))
        .route(
            "/api/accounts/:id/switch-back",
            post(local_switchback::switch_back),
        )
        .route(
            "/api/accounts/:id/restore-local",
            post(local_switchback::restore_local),
        )
        .route(
            "/api/accounts/import/bundle",
            post(account_bundle::handle_import),
        )
        .route(
            "/api/accounts/:id",
            axum::routing::delete(crate::account_routes::handle_account_delete)
                .put(crate::account_routes::handle_account_update),
        )
        .route(
            "/api/accounts/:id/detect",
            post(account_billing::handle_detect),
        )
        .route(
            "/api/accounts/:id/claim",
            post(account_billing::handle_claim),
        )
        .route(
            "/api/accounts/:id/activate",
            post(account_billing::handle_activate),
        )
        .route(
            "/api/accounts/:id/reset",
            post(account_billing::handle_reset),
        )
        .route(
            "/api/accounts/:id/reset-status",
            get(account_billing::handle_reset_status),
        )
        .route(
            "/api/accounts/:id/reset-history/sync",
            post(account_billing::handle_reset_history_sync),
        )
        .route(
            "/api/accounts/:id/refresh",
            post(account_refresh::handle_refresh),
        )
        .route(
            "/api/accounts/:id/enabled",
            put(crate::account_routes::handle_account_enabled),
        )
        .route(
            "/api/auth/password",
            post(crate::account_routes::handle_password_change),
        )
        .route(
            "/api/settings",
            get(admin::handle_get_settings).put(admin::handle_put_settings),
        )
        .route("/api/usage-records", get(admin::handle_usage))
        .route("/api/stats", get(admin::handle_stats))
        .route("/api/logout", post(admin::handle_logout))
        .route(
            "/api/accounts/import/local",
            post(account_local::handle_import),
        )
        .route("/api/auth/check", get(admin::handle_check))
        .route("/api/auth/passkey/status", get(passkey::handle_status))
        .route(
            "/api/auth/passkey/register/begin",
            post(passkey::handle_register_begin),
        )
        .route(
            "/api/auth/passkey/register/finish",
            post(passkey::handle_register_finish),
        )
        .route("/api/auth/passkey/delete", post(passkey::handle_delete))
        .route("/api/auth/totp/setup", post(admin::handle_totp_setup))
        .route("/api/auth/totp/confirm", post(admin::handle_totp_confirm))
        .route("/api/auth/totp/enable", post(admin::handle_totp_confirm))
        .route("/api/auth/totp/status", get(console::handle_totp_status))
        .route("/api/auth/totp/disable", post(admin::handle_totp_disable))
        .route("/api/auth/username", post(console::handle_username_change))
        .route("/api/settings/api-key", get(console::handle_get_api_key))
        .route(
            "/api/settings/api-key/reveal",
            post(console::handle_reveal_api_key),
        )
        .route(
            "/api/settings/api-key/generate",
            post(console::handle_generate_api_key),
        )
        .route("/api/dashboard", get(console::handle_dashboard))
        .route("/api/groups", get(console::handle_groups))
        .route("/api/fingerprints", get(console::handle_fingerprints))
        .route("/api/models", get(console::handle_models))
        .route("/api/models/catalog", get(model_catalog::handle_catalog))
        .route("/api/models/sync", post(model_catalog::handle_sync))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admin::require_session_mw,
        ))
        .with_state(state)
}

/// Open routes: login + panel + health.
fn open_routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/login", post(admin::handle_login))
        .route("/api/auth/login-info", get(console::handle_login_info))
        .route(
            "/api/login/passkey/begin",
            post(passkey::handle_login_begin),
        )
        .route(
            "/api/login/passkey/finish",
            post(passkey::handle_login_finish),
        )
        .route("/api/login/totp", post(passkey::handle_login_totp))
        .route("/oauth/callback", get(account_oauth::handle_callback))
        .route("/web", get(console::handle_index))
        .route("/web/", get(console::handle_index))
        .route("/web/static/:name", get(console::handle_static))
        .route("/web/*path", get(console::handle_web_path))
        .route("/health", get(|| async { "ok" }))
        .with_state(state)
}

/// Router builder, shared by main and the E2E tests.
pub fn build_router(state: Arc<AppState>) -> Router {
    data_plane(state.clone())
        .merge(admin_api(state.clone()))
        .merge(open_routes(state))
        .layer(middleware::from_fn(admin::no_store_mw))
}
