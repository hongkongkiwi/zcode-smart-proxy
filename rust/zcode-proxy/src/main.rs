//! Bin entrypoint: env config + serve. All routing lives in lib.rs.

use std::sync::Arc;

use zcode_proxy::build_router;
use zcode_proxy::state::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let usage = "Usage: zcode-proxy-rs [import-go <source-db> <destination-dir>]\nStop all source writers before importing. Set ZCODE_PROXY_VAULT_SECRET explicitly.";
    if !args.is_empty() {
        if (args.len() == 1 && args[0] == "--help")
            || (args.len() == 2 && args[0] == "import-go" && args[1] == "--help")
        {
            println!("{usage}");
            return Ok(());
        }
        if args.len() != 3 || args[0] != "import-go" {
            return Err(usage.into());
        }
        let secret = zeroize::Zeroizing::new(
            std::env::var("ZCODE_PROXY_VAULT_SECRET")
                .ok()
                .filter(|value| !value.is_empty())
                .ok_or("import-go requires a nonempty ZCODE_PROXY_VAULT_SECRET")?,
        );
        let report = zcode_proxy::go_import::import_database(
            std::path::Path::new(&args[1]),
            std::path::Path::new(&args[2]),
            &secret,
        )?;
        println!("{}", serde_json::to_string(&report)?);
        return Ok(());
    }
    let root_key = std::env::var("ZCODE_RS_ROOT_KEY").unwrap_or_default();
    let upstream = AppState::upstream_from_env();
    let bind = std::env::var("ZCODE_RS_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let db_path = std::env::var("ZCODE_RS_DB").unwrap_or_else(|_| "zcode-rs.db".into());
    let vault = zcode_proxy::vault::Vault::for_database(&db_path)?;
    let db = zcode_proxy::store::try_open(&db_path)?;
    let mut state = AppState::try_from_db_with_vault(root_key, upstream, db, vault)?;
    state.install_reporting_enabled = true;
    zcode_proxy::identity::backfill_device_identities(&state)?;
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

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    let scheduler = Arc::new(zcode_proxy::scheduler::Scheduler::new(state.clone()));
    state
        .set_scheduler(scheduler.clone())
        .map_err(|_| "scheduler already installed")?;
    scheduler.start()?;
    let background = Arc::new(zcode_proxy::background_refresh::BackgroundRefresh::new(
        state.clone(),
    ));
    state
        .set_background_refresh(background.clone())
        .map_err(|_| "background refresh already installed")?;
    let app = build_router(state);
    let (drain, drained) = tokio::sync::oneshot::channel();
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let stopping = scheduler.clone();
    let stopping_background = background.clone();
    let signal = async move {
        #[cfg(unix)]
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result { eprintln!("SIGINT listener failed: {error}"); }
            }
            _ = terminate.recv() => ()
        }
        #[cfg(not(unix))]
        if let Err(error) = tokio::signal::ctrl_c().await {
            eprintln!("SIGINT listener failed: {error}");
        }
        stop_background_work(&stopping, &stopping_background).await;
        let _ = drain.send(());
    };
    println!("zcode-proxy-rs listening on {bind}");
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(signal);
    let server = std::future::IntoFuture::into_future(server);
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => {
            stop_background_work(&scheduler, &background).await;
            result?;
        }
        _ = drained => {
            match tokio::time::timeout(std::time::Duration::from_secs(10), &mut server).await {
                Ok(result) => result?,
                Err(_) => eprintln!("HTTP drain timed out"),
            }
        }
    }
    Ok(())
}

async fn stop_background_work(
    scheduler: &zcode_proxy::scheduler::Scheduler,
    background: &zcode_proxy::background_refresh::BackgroundRefresh,
) {
    scheduler.stop();
    background.stop();
    let (scheduled, refreshed) = tokio::join!(scheduler.shutdown(), background.shutdown());
    if !scheduled.tick_stopped || !scheduled.tasks_drained {
        eprintln!(
            "scheduler shutdown incomplete: tick_stopped={}, tasks_drained={}, abandoned={:?}",
            scheduled.tick_stopped, scheduled.tasks_drained, scheduled.abandoned
        );
    }
    if !refreshed.drained {
        eprintln!(
            "background quota shutdown incomplete: abandoned={:?}, cancelled={}",
            refreshed.abandoned, refreshed.cancelled
        );
    }
}
