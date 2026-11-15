//! Bin entrypoint: env config + serve. All routing lives in lib.rs.

use std::sync::Arc;

use zcode_proxy::build_router;
use zcode_proxy::state::AppState;

#[tokio::main]
async fn main() {
    let root_key = std::env::var("ZCODE_RS_ROOT_KEY").unwrap_or_default();
    let upstream = AppState::upstream_from_env();
    let bind = std::env::var("ZCODE_RS_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let db_path = std::env::var("ZCODE_RS_DB").unwrap_or_else(|_| "zcode-rs.db".into());
    let db = zcode_proxy::store::open(&db_path);
    // Admin password bootstrap: env wins, hashed into settings (Go parity:
    // the plaintext is never stored).
    if let Ok(pw) = std::env::var("ZCODE_RS_ADMIN_PASSWORD") {
        if !pw.is_empty() {
            let hash = bcrypt::hash(&pw, bcrypt::DEFAULT_COST).expect("hash");
            zcode_proxy::store::set_setting(&db, "admin_password_hash", &hash);
        }
    }
    let state = Arc::new(AppState::from_db(root_key, upstream, db));

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    println!("zcode-proxy-rs listening on {bind}");
    axum::serve(listener, app).await.unwrap();
}
