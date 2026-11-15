//! Library surface: data plane + admin panel, exposed for integration tests
//! (bin entrypoint in main.rs).

pub mod admin;
pub mod auth;
pub mod engine;
pub mod state;
pub mod store;
mod streaming;

use std::sync::Arc;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};

use state::AppState;

/// Data plane behind the API-key gate.
fn data_plane(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/messages", post(engine::handle_messages))
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
            post(engine::handle_messages),
        )
        .route(
            "/api/v1/off-peak/anthropic/v1/messages",
            post(engine::handle_messages),
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
        .route(
            "/api/settings",
            get(admin::handle_get_settings).put(admin::handle_put_settings),
        )
        .route("/api/usage-records", get(admin::handle_usage))
        .route("/api/stats", get(admin::handle_stats))
        .route("/api/logout", post(admin::handle_logout))
        .route("/api/auth/check", get(admin::handle_check))
        .route("/api/auth/totp/setup", post(admin::handle_totp_setup))
        .route("/api/auth/totp/confirm", post(admin::handle_totp_confirm))
        .route("/api/auth/totp/disable", post(admin::handle_totp_disable))
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
        .route("/web", get(admin::handle_panel))
        .route("/health", get(|| async { "ok" }))
        .with_state(state)
}

/// Router builder, shared by main and the E2E tests.
pub fn build_router(state: Arc<AppState>) -> Router {
    data_plane(state.clone())
        .merge(admin_api(state.clone()))
        .merge(open_routes(state))
}
