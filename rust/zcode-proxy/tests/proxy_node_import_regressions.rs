//! Independent regressions for the offline Go proxy_nodes import projection
//! (design: .agents/state/rust-migration/proxy-nodes-design.md, baseline
//! 4e62795).
//!
//! The Go archive keeps its complete proxy_nodes table; the runtime database
//! additionally projects nodes with preserved ids/default/group/check metadata
//! and timestamps, re-encrypts passwords under the fresh runtime vault, keeps
//! legacy plaintext upgradeable, rejects any invalid row atomically before
//! publication, and preserves sqlite_sequence so imported ids are never reused.
//! The projection is absent while this file lands, so the assertions fail
//! until the writer adds them; that is the intended baseline failure.

use std::{fs, path::PathBuf, sync::Arc};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use rusqlite::{types::Value as SqlValue, Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router, go_compat, go_import,
    state::{AppState, UpstreamUrls},
    store,
    vault::Vault,
};

const HOST: &str = "localhost:8080";
const SESSION: &str = "PUBLIC-proxy-import-session";
/// Not a 64-hex seed, so import_database derives a fresh random runtime seed
/// and the runtime vault is guaranteed to differ from the source vault.
const SOURCE_SECRET: &str = "PUBLIC proxy import source passphrase";
const SOURCE_PASSWORD: &str = "PUBLIC proxy node password";
const LEGACY_PASSWORD: &str = "PUBLIC legacy node password";

struct ImportFixture {
    root: PathBuf,
    source: PathBuf,
    destination: PathBuf,
}

impl ImportFixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "zcode-proxy-node-import-{}-{:032x}",
            std::process::id(),
            rand::random::<u128>()
        ));
        fs::create_dir_all(root.join("source")).unwrap();
        let source = root.join("source").join("zcode.db");
        let destination = root.join("imported");
        let db = Connection::open(&source).unwrap();
        db.execute_batch(include_str!("fixtures/go_schema.sql"))
            .unwrap();
        let vault = Vault::from_secret(SOURCE_SECRET).unwrap();
        db.execute(
            "INSERT INTO proxy_nodes
             (id, name, type, host, port, username, password, is_default, group_name,
              enabled, check_status, check_latency, check_ip, check_msg, check_at,
              created_at, updated_at)
             VALUES (501, 'PUBLIC group node', 'socks5', 'proxy.example.invalid', 1080,
                     'PUBLIC proxy user', ?1, 0, 'alpha, beta', 1, 'ok', 42,
                     '203.0.113.7', 'PUBLIC check message', '2026-02-03 04:05:06',
                     '2026-01-01 00:00:00', '2026-01-02 00:00:00')",
            [vault.encrypt(SOURCE_PASSWORD).unwrap()],
        )
        .unwrap();
        // Legacy plaintext password: accepted by the source vault policy and
        // expected to arrive re-encrypted under the runtime vault.
        db.execute(
            "INSERT INTO proxy_nodes
             (id, name, type, host, port, username, password, is_default, group_name,
              enabled, created_at, updated_at)
             VALUES (502, 'PUBLIC default node', 'http', 'default.example.invalid', 8080,
                     '', ?1, 1, '', 1, '2026-01-01 00:00:00', '2026-01-02 00:00:00')",
            [LEGACY_PASSWORD],
        )
        .unwrap();
        db.execute(
            "INSERT INTO proxy_nodes
             (id, name, type, host, port, username, password, is_default, group_name,
              enabled, check_status, check_latency, check_ip, check_msg, check_at,
              created_at, updated_at)
             VALUES (503, 'PUBLIC disabled node', 'https', 'down.example.invalid', 8443,
                     '', '', 0, 'gamma', 0, 'fail', 5000, '', 'PUBLIC down',
                     '2026-03-04 05:06:07', '2026-01-01 00:00:00', '2026-01-02 00:00:00')",
            [],
        )
        .unwrap();
        // A deleted high id must keep the sequence above every projected id.
        db.execute(
            "INSERT INTO proxy_nodes (id, name) VALUES (601, 'PUBLIC deleted node')",
            [],
        )
        .unwrap();
        db.execute("DELETE FROM proxy_nodes WHERE id = 601", [])
            .unwrap();
        drop(db);
        Self {
            root,
            source,
            destination,
        }
    }

    fn import(&self) -> Result<(), go_import::ImportError> {
        go_import::import_database(&self.source, &self.destination, SOURCE_SECRET).map(|_| ())
    }

    fn runtime_path(&self) -> PathBuf {
        self.destination.join("zcode-rs.db")
    }

    fn runtime(&self) -> Connection {
        Connection::open_with_flags(self.runtime_path(), OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
    }

    fn runtime_vault(&self) -> Vault {
        let seed = go_compat::load_vault_key(self.destination.to_str().unwrap()).unwrap();
        Vault::from_secret(&seed).unwrap()
    }
}

impl Drop for ImportFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn rows(db: &Connection, sql: &str) -> Vec<Vec<SqlValue>> {
    let mut stmt = db.prepare(sql).unwrap();
    let width = stmt.column_count();
    stmt.query_map([], |row| (0..width).map(|i| row.get(i)).collect())
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[tokio::test]
async fn import_projects_nodes_with_ids_metadata_and_reencrypted_passwords() {
    let f = ImportFixture::new();
    f.import().expect("import with valid nodes must succeed");
    let db = f.runtime();
    let projected = rows(
        &db,
        "SELECT id, name, type, host, port, username, is_default, group_name, enabled,
                check_status, check_latency, check_ip, check_msg, check_at,
                created_at, updated_at
         FROM proxy_nodes ORDER BY id",
    );
    assert_eq!(
        projected.len(),
        3,
        "every source node must project, no more"
    );
    assert_eq!(
        projected[0],
        vec![
            SqlValue::Integer(501),
            SqlValue::Text("PUBLIC group node".into()),
            SqlValue::Text("socks5".into()),
            SqlValue::Text("proxy.example.invalid".into()),
            SqlValue::Integer(1080),
            SqlValue::Text("PUBLIC proxy user".into()),
            SqlValue::Integer(0),
            SqlValue::Text("alpha, beta".into()),
            SqlValue::Integer(1),
            SqlValue::Text("ok".into()),
            SqlValue::Integer(42),
            SqlValue::Text("203.0.113.7".into()),
            SqlValue::Text("PUBLIC check message".into()),
            SqlValue::Text("2026-02-03 04:05:06".into()),
            SqlValue::Text("2026-01-01 00:00:00".into()),
            SqlValue::Text("2026-01-02 00:00:00".into()),
        ],
        "ids, group binding, check metadata, and timestamps must survive verbatim"
    );
    assert_eq!(
        projected[1][6],
        SqlValue::Integer(1),
        "the source default must stay the default"
    );
    assert_eq!(
        projected[1][8],
        SqlValue::Integer(1),
        "enabled nodes stay enabled"
    );
    assert_eq!(
        projected[2][8],
        SqlValue::Integer(0),
        "disabled nodes stay disabled"
    );
    let defaults: i64 = db
        .query_row(
            "SELECT count(*) FROM proxy_nodes WHERE is_default = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(defaults, 1, "exactly one default after import");

    let vault = f.runtime_vault();
    let stored: Vec<(i64, String)> = rows(&db, "SELECT id, password FROM proxy_nodes ORDER BY id")
        .into_iter()
        .map(|row| match (row[0].clone(), row[1].clone()) {
            (SqlValue::Integer(id), SqlValue::Text(password)) => (id, password),
            other => panic!("unexpected password row shape: {other:?}"),
        })
        .collect();
    let password = |id: i64| {
        stored
            .iter()
            .find(|row| row.0 == id)
            .unwrap_or_else(|| panic!("missing node {id}"))
            .1
            .clone()
    };
    assert!(
        password(501).starts_with("vault1:"),
        "encrypted source passwords must stay encrypted at rest"
    );
    assert_eq!(
        vault.decrypt(&password(501)).unwrap(),
        SOURCE_PASSWORD,
        "runtime vault must decrypt the re-encrypted password"
    );
    assert!(
        password(502).starts_with("vault1:"),
        "legacy plaintext must be upgraded during import"
    );
    assert_eq!(
        vault.decrypt(&password(502)).unwrap(),
        LEGACY_PASSWORD,
        "upgraded legacy password must keep its plaintext"
    );
    assert_eq!(password(503), "", "empty passwords stay empty");
    drop(db);

    // The public list view must serve the projected rows immediately.
    let state = AppState::try_from_db_with_vault(
        String::new(),
        UpstreamUrls {
            zai: "http://127.0.0.1:1/unused".into(),
            zai_fallback: "http://127.0.0.1:1/unused".into(),
        },
        store::try_open(f.runtime_path().to_str().unwrap()).unwrap(),
        vault,
    )
    .unwrap();
    let state = Arc::new(state);
    state
        .sessions
        .lock()
        .unwrap()
        .insert(SESSION.into(), now_secs() + 3600);
    let request = Request::builder()
        .method("GET")
        .uri("/api/proxies")
        .header("host", HOST)
        .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
        .body(Body::empty())
        .unwrap();
    let response = build_router(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status, StatusCode::OK, "list over imported db body={body}");
    let nodes = body["proxies"].as_array().unwrap();
    let ids: Vec<i64> = nodes.iter().map(|n| n["id"].as_i64().unwrap()).collect();
    assert_eq!(ids, vec![501, 502, 503]);
    for node in nodes {
        let id = node["id"].as_i64().unwrap();
        assert_eq!(node["password_broken"], json!(false), "node {id}");
        assert_eq!(
            node["has_password"],
            json!(id != 503),
            "node {id} password visibility"
        );
        assert!(
            node.get("password").is_none(),
            "node {id} leaked ciphertext"
        );
    }
    assert_eq!(nodes[0]["group_name"], json!("alpha, beta"));
    assert_eq!(nodes[1]["is_default"], json!(true));
    assert_eq!(nodes[2]["enabled"], json!(false));
}

#[test]
fn import_preserves_proxy_nodes_sequence_so_ids_are_never_reused() {
    let f = ImportFixture::new();
    f.import().expect("import must succeed");
    let db = f.runtime();
    let seq: Option<i64> = db
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name='proxy_nodes'",
            [],
            |r| r.get(0),
        )
        .optional()
        .unwrap();
    assert_eq!(seq, Some(601), "source sequence must be preserved");
    drop(db);
    let writable = Connection::open(f.runtime_path()).unwrap();
    writable
        .execute(
            "INSERT INTO proxy_nodes (name) VALUES ('PUBLIC post-import node')",
            [],
        )
        .unwrap();
    assert_eq!(
        writable.last_insert_rowid(),
        602,
        "new nodes must never reuse a deleted imported id"
    );
}

#[test]
fn import_rejects_any_invalid_node_atomically_without_publishing() {
    for (label, mutation) in [
        (
            "empty-host",
            "UPDATE proxy_nodes SET host = '' WHERE id = 501",
        ),
        (
            "scheme-in-host",
            "UPDATE proxy_nodes SET host = 'http://proxy.example.invalid' WHERE id = 501",
        ),
        (
            "port-zero",
            "UPDATE proxy_nodes SET port = 0 WHERE id = 501",
        ),
        (
            "port-range",
            "UPDATE proxy_nodes SET port = 70000 WHERE id = 501",
        ),
        (
            "bad-type",
            "UPDATE proxy_nodes SET type = 'socks4' WHERE id = 501",
        ),
        (
            "empty-type",
            "UPDATE proxy_nodes SET type = '' WHERE id = 501",
        ),
    ] {
        let f = ImportFixture::new();
        let db = Connection::open(&f.source).unwrap();
        db.execute(mutation, []).unwrap();
        drop(db);
        assert!(
            f.import().is_err(),
            "{label} node must reject the entire import"
        );
        assert!(
            !f.destination.exists(),
            "{label}: nothing may be published for a rejected import"
        );
    }
}
