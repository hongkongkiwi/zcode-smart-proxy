//! Bin entrypoint: env config + serve. All routing lives in lib.rs.

use std::sync::Arc;

use zcode_proxy::build_router;
use zcode_proxy::state::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root_key = std::env::var("ZCODE_RS_ROOT_KEY").unwrap_or_default();
    let upstream = AppState::upstream_from_env();
    let bind = std::env::var("ZCODE_RS_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let db_path = std::env::var("ZCODE_RS_DB").unwrap_or_else(|_| "zcode-rs.db".into());
    let vault = zcode_proxy::vault::Vault::for_database(&db_path)?;
    let db = zcode_proxy::store::try_open(&db_path)?;
    let state = AppState::try_from_db_with_vault(root_key, upstream, db, vault)?;
    // The bootstrap environment must not overwrite a rotated stored password.
    if state.setting("admin_password_hash").is_none() {
        if let Ok(pw) = std::env::var("ZCODE_RS_ADMIN_PASSWORD") {
            if !pw.is_empty() {
                let hash = bcrypt::hash(&pw, bcrypt::DEFAULT_COST)?;
                state.persist_settings(&[("admin_password_hash", &hash)])?;
            }
        }
    }
    let state = Arc::new(state);

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    println!("zcode-proxy-rs listening on {bind}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
