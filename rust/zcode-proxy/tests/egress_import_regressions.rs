//! Independent import-path regressions for upstream_proxy fail-closed
//! handling (design: .agents/state/rust-migration/egress-design.md; review
//! finding on go_import.rs settings projection, baseline 007f6fb).
//!
//! Contract pinned: a Go source database carrying an invalid upstream_proxy is
//! rejected before destination publication (source untouched, no partial
//! archive, no secrets in the error); a valid authenticated proxy imports
//! re-encrypted and GET /api/settings redacts it; a runtime store that already
//! holds an invalid proxy stays readable with an explicit invalid marker and
//! never echoes the value, the setting is retained for admin repair (not
//! silently dropped or quarantined as empty), and client_builder fails closed;
//! manual PUT repair or clearing removes the invalid indicator. The importer
//! currently accepts invalid proxy values, so these fail red until fixed.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    egress::client_builder,
    go_compat, go_import,
    state::{AppState, UpstreamUrls},
    store,
    vault::Vault,
};

const PUBLIC_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const HOST: &str = "localhost:8080";
const SESSION: &str = "PUBLIC-egress-import-session";
const AUTHED_PROXY: &str = "http://PUBLIC-egress-user:PUBLIC-egress-secret@127.0.0.1:3128";
const STRIPPED_PROXY: &str = "http://127.0.0.1:3128";
const INVALID_PROXY: &str = "http://PUBLIC-egress-leak-user:PUBLIC-egress-leak-secret@127.0.0.1:0";

fn unused_upstream() -> UpstreamUrls {
    UpstreamUrls {
        zai: "http://127.0.0.1:1/unused".into(),
        zai_fallback: "http://127.0.0.1:1/unused".into(),
    }
}

fn files(path: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                result.insert(
                    entry.path().strip_prefix(root).unwrap().to_path_buf(),
                    vec![],
                );
                visit(root, &entry.path(), result);
            } else {
                result.insert(
                    entry.path().strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(path, path, &mut result);
    result
}

/// Go source database whose only variable is the upstream_proxy setting value.
struct ImportFixture {
    root: PathBuf,
    source: PathBuf,
    destination: PathBuf,
}

impl ImportFixture {
    fn new(proxy: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "zcode-egress-import-{}-{:032x}",
            std::process::id(),
            rand::random::<u128>()
        ));
        fs::create_dir(&root).unwrap();
        let source_dir = root.join("source");
        fs::create_dir(&source_dir).unwrap();
        let source = source_dir.join("zcode.db");
        let destination = root.join("imported");
        fs::write(
            source_dir.join("vault.key"),
            format!(" \n{PUBLIC_SEED}\r\n"),
        )
        .unwrap();
        let vault = Vault::from_secret(PUBLIC_SEED).unwrap();
        let db = Connection::open(&source).unwrap();
        db.execute_batch(include_str!("fixtures/go_schema.sql"))
            .unwrap();
        db.execute(
            "INSERT INTO settings(key, value, updated_at)
             VALUES('upstream_proxy', ?1, '2026-01-01 00:00:00')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [vault.encrypt(proxy).unwrap()],
        )
        .unwrap();
        drop(db);
        Self {
            root,
            source,
            destination,
        }
    }
}

impl Drop for ImportFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn sessioned_state(state: AppState) -> Arc<AppState> {
    let state = Arc::new(state);
    state
        .sessions
        .lock()
        .unwrap()
        .insert(SESSION.into(), now_secs() + 3600);
    state
}

async fn settings_call(
    state: &Arc<AppState>,
    method: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri("/api/settings")
        .header("host", HOST)
        .header("cookie", format!("{SESSION_COOKIE}={SESSION}"));
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let body = match body {
        Some(value) => Body::from(value.to_string()),
        None => Body::empty(),
    };
    let response = build_router(state.clone())
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn settings_get(state: &Arc<AppState>) -> Value {
    let (status, body) = settings_call(state, "GET", None).await;
    assert_eq!(status, StatusCode::OK, "GET /api/settings body={body}");
    body
}

#[test]
fn invalid_upstream_proxy_rejects_import_before_destination_publish() {
    for bad in [
        INVALID_PROXY,
        "http://127.0.0.1:99999",
        "ftp://proxy.example.invalid:1080",
    ] {
        let f = ImportFixture::new(bad);
        let before = files(&f.root);
        let error = go_import::import_database(&f.source, &f.destination, PUBLIC_SEED).unwrap_err();
        let text = error.to_string();
        assert!(
            !text.contains("PUBLIC-egress-leak-secret")
                && !text.contains("PUBLIC-egress-leak-user"),
            "import error leaked proxy credentials"
        );
        assert!(
            !f.destination.exists(),
            "invalid upstream_proxy must not publish a destination"
        );
        assert_eq!(
            files(&f.root),
            before,
            "rejected import must leave the source tree untouched (archive atomicity)"
        );
    }
}

#[tokio::test]
async fn valid_authenticated_proxy_imports_reencrypted_and_redacts_on_get() {
    let f = ImportFixture::new(AUTHED_PROXY);
    go_import::import_database(&f.source, &f.destination, PUBLIC_SEED).unwrap();
    let runtime_path = f.destination.join("zcode-rs.db");
    let db = store::try_open(runtime_path.to_str().unwrap()).unwrap();
    let raw: String = db
        .query_row(
            "SELECT value FROM settings WHERE key='upstream_proxy'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        raw.starts_with("vault1:"),
        "imported proxy must be re-encrypted under the runtime vault"
    );
    let seed = go_compat::load_vault_key(f.destination.to_str().unwrap()).unwrap();
    let vault = Vault::from_secret(&seed).unwrap();
    assert_eq!(
        vault.decrypt(&raw).unwrap(),
        AUTHED_PROXY,
        "re-encryption must preserve the authenticated URL"
    );
    let state = sessioned_state(
        AppState::try_from_db_with_vault(String::new(), unused_upstream(), db, vault).unwrap(),
    );
    assert_eq!(
        state.setting("upstream_proxy").as_deref(),
        Some(AUTHED_PROXY)
    );
    let body = settings_get(&state).await;
    assert_eq!(body["upstream_proxy"], json!(STRIPPED_PROXY), "body={body}");
    assert_eq!(body["upstream_proxy_has_auth"], json!(true), "body={body}");
    assert!(
        !body.to_string().contains("PUBLIC-egress-secret"),
        "GET leaked imported proxy credentials"
    );
}

#[tokio::test]
async fn invalid_stored_proxy_marks_get_and_fails_client_builder_closed() {
    let state = sessioned_state(AppState::new(String::new(), unused_upstream()));
    state
        .persist_settings(&[("gateway_paused", "0"), ("upstream_proxy", INVALID_PROXY)])
        .unwrap();
    assert_eq!(
        state.setting("upstream_proxy").as_deref(),
        Some(INVALID_PROXY),
        "invalid proxy must be retained for admin repair, not silently dropped"
    );
    let raw: String = state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT value FROM settings WHERE key='upstream_proxy'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        state.vault.decrypt(&raw).unwrap(),
        INVALID_PROXY,
        "invalid proxy must not be quarantined as an empty stored value"
    );
    let body = settings_get(&state).await;
    assert_eq!(
        body["gateway_paused"],
        json!("0"),
        "other settings must stay readable: {body}"
    );
    assert_eq!(
        body["upstream_proxy_invalid"],
        json!(true),
        "GET must report the explicit invalid marker: {body}"
    );
    assert!(
        body.get("upstream_proxy_has_auth")
            .is_none_or(|value| value == &json!(false)),
        "invalid proxy must not report auth: {body}"
    );
    assert!(
        body.get("upstream_proxy")
            .is_none_or(|value| value == &json!("")),
        "GET must never echo the invalid proxy value: {body}"
    );
    let text = body.to_string();
    assert!(
        !text.contains("PUBLIC-egress-leak-secret"),
        "GET leaked the invalid proxy secret"
    );
    assert!(
        !text.contains("127.0.0.1:0"),
        "GET echoed the invalid proxy URL"
    );
    assert!(
        client_builder(&state, None).is_err(),
        "invalid stored proxy must fail closed, never fall back to direct egress"
    );
}

#[tokio::test]
async fn manual_put_repair_or_clear_removes_invalid_indicator() {
    let state = sessioned_state(AppState::new(String::new(), unused_upstream()));
    state
        .persist_settings(&[("upstream_proxy", INVALID_PROXY)])
        .unwrap();
    let (status, reply) =
        settings_call(&state, "PUT", Some(json!({"upstream_proxy": AUTHED_PROXY}))).await;
    assert_eq!(status, StatusCode::OK, "valid repair PUT failed: {reply}");
    let body = settings_get(&state).await;
    assert!(
        body.get("upstream_proxy_invalid")
            .is_none_or(|value| value == &json!(false)),
        "repaired store must not report invalid: {body}"
    );
    assert_eq!(body["upstream_proxy"], json!(STRIPPED_PROXY));
    assert_eq!(body["upstream_proxy_has_auth"], json!(true));
    assert!(
        client_builder(&state, None).is_ok(),
        "repaired proxy must build a client again"
    );

    let (status, reply) = settings_call(&state, "PUT", Some(json!({"upstream_proxy": ""}))).await;
    assert_eq!(status, StatusCode::OK, "clearing PUT failed: {reply}");
    let body = settings_get(&state).await;
    assert!(
        body.get("upstream_proxy_invalid")
            .is_none_or(|value| value == &json!(false)),
        "cleared store must not report invalid: {body}"
    );
    assert!(
        body.get("upstream_proxy")
            .is_none_or(|value| value == &json!("")),
        "cleared store must not advertise a proxy: {body}"
    );
    assert!(
        body.get("upstream_proxy_has_auth")
            .is_none_or(|value| value == &json!(false)),
        "cleared store must not report auth: {body}"
    );
    assert!(
        client_builder(&state, None).is_ok(),
        "explicit clear is a valid direct state"
    );
}
