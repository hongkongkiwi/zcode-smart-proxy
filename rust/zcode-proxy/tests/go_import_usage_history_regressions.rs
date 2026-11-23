use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use rusqlite::{types::Value as SqlValue, Connection, OpenFlags};
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_proxy::{
    admin::{record_usage_db, SESSION_COOKIE},
    build_router, go_import,
    state::{AppState, UpstreamUrls, UsageRecord},
    vault::Vault,
};

const PUBLIC_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SESSION: &str = "PUBLIC-usage-history-session";
const USAGE_COLUMNS: &str = "id, created_at, account_id, email, model, prompt_tokens,
    completion_tokens, total_tokens, cache_read_tokens, cache_creation_tokens, stream,
    status_code, duration_ms, ttft_ms, gateway_key_id, key_name, channel";
const USAGE_ROW: &str = "UPDATE gateway_keys SET quota_used = 123 WHERE id = 1;
    INSERT INTO usage_records
        (id, created_at, account_id, email, model, prompt_tokens, completion_tokens,
         total_tokens, cache_read_tokens, cache_creation_tokens, stream, status_code,
         duration_ms, ttft_ms, gateway_key_id, key_name, channel)
    VALUES (1201, '2026-11-01 01:30:00.123', 101, 'a@example.invalid', 'PUBLIC-model',
            23, 29, 4000000000, 13, 17, 1, 502, 123, 19, 1, 'PUBLIC named key', 'paid');";

struct Fixture {
    root: PathBuf,
    source: PathBuf,
    destination: PathBuf,
}

impl Fixture {
    fn new(sql: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "zcode-go-import-usage-{}-{:032x}",
            std::process::id(),
            rand::random::<u128>()
        ));
        fs::create_dir(&root).unwrap();
        let f = Self {
            source: root.join("go.sqlite"),
            destination: root.join("imported"),
            root,
        };
        let db = Connection::open(&f.source).unwrap();
        db.execute_batch(include_str!("fixtures/go_schema.sql"))
            .unwrap();
        db.execute_batch(sql).unwrap();
        f
    }

    fn import(&self) -> Result<go_import::ImportReport, go_import::ImportError> {
        go_import::import_database(&self.source, &self.destination, PUBLIC_SEED)
    }

    fn runtime(&self) -> Connection {
        Connection::open(self.destination.join("zcode-rs.db")).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn read_only(path: &Path) -> Connection {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
}

fn rows(db: &Connection, sql: &str) -> Vec<Vec<SqlValue>> {
    let mut stmt = db.prepare(sql).unwrap_or_else(|err| panic!("{sql}: {err}"));
    let width = stmt.column_count();
    let rows = stmt
        .query_map([], |row| (0..width).map(|i| row.get(i)).collect())
        .unwrap();
    rows.collect::<rusqlite::Result<_>>().unwrap()
}

fn integer(db: &Connection, sql: &str) -> i64 {
    db.query_row(sql, [], |row| row.get(0)).unwrap()
}

#[test]
fn import_projects_go_usage_without_replaying_billing_or_changing_the_archive() {
    let f = Fixture::new(&format!(
        "{USAGE_ROW}
         ALTER TABLE usage_records ADD COLUMN future_metadata BLOB;
         UPDATE usage_records SET future_metadata = x'00ff' WHERE id = 1201;"
    ));
    let original = fs::read(&f.source).unwrap();
    f.import().unwrap();
    assert!(
        fs::read(&f.source).unwrap() == original,
        "source bytes changed"
    );

    let source = read_only(&f.source);
    let archive = read_only(&f.destination.join("go-source.sqlite"));
    let archive_query = "SELECT * FROM usage_records ORDER BY id";
    assert_eq!(rows(&archive, archive_query), rows(&source, archive_query));

    let runtime = f.runtime();
    assert_eq!(integer(&runtime, "SELECT count(*) FROM usage_records"), 0);
    assert_eq!(
        integer(&runtime, "SELECT quota_used FROM gateway_keys WHERE id = 1"),
        123
    );
    assert_eq!(
        integer(
            &runtime,
            "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'go_usage_history'",
        ),
        1,
        "missing Go usage reporting table"
    );
    assert_eq!(
        rows(
            &runtime,
            "SELECT name, upper(type) FROM pragma_table_info('go_usage_history') ORDER BY name"
        ),
        rows(
            &source,
            "SELECT name, upper(type) FROM pragma_table_info('usage_records')
             WHERE name != 'future_metadata' ORDER BY name"
        )
    );
    assert_eq!(
        rows(
            &runtime,
            &format!("SELECT {USAGE_COLUMNS} FROM go_usage_history ORDER BY id")
        ),
        rows(
            &source,
            &format!("SELECT {USAGE_COLUMNS} FROM usage_records ORDER BY id")
        ),
        "all Go fields must be preserved, including the local timestamp text"
    );
}

#[test]
fn next_live_id_exceeds_both_the_source_sequence_and_edited_archive_ids() {
    for archive_id in [900, 1100] {
        let f = Fixture::new(&format!(
            "INSERT INTO usage_records (id) VALUES (800), (1000);
             DELETE FROM usage_records WHERE id = 1000;
             UPDATE usage_records SET id = {archive_id} WHERE id = 800;"
        ));
        f.import().unwrap();
        let runtime = f.runtime();
        runtime
            .execute(
                "INSERT INTO usage_records (created_at) VALUES (1700000000)",
                [],
            )
            .unwrap();
        let id = runtime.last_insert_rowid();
        assert!(
            id > 1000 && id > archive_id,
            "live ID {id} must exceed source sequence 1000 and archive ID {archive_id}"
        );
    }
}

fn assert_rejected_usage(cases: &[(&str, &str)]) {
    let mut violations = Vec::new();
    for &(label, mutation) in cases {
        let f = Fixture::new(&format!("{USAGE_ROW}\n{mutation}"));
        let before = fs::read(&f.source).unwrap();
        let accepted = f.import().is_ok();
        let published = f.destination.exists();
        assert!(
            fs::read(&f.source).unwrap() == before,
            "source changed: {label}"
        );
        if accepted || published {
            violations.push((label, accepted, published));
        }
    }
    assert!(
        violations.is_empty(),
        "invalid usage cases (case, accepted, published): {violations:?}"
    );
}

#[test]
fn import_rejects_a_missing_or_incomplete_usage_table() {
    assert_rejected_usage(&[
        ("missing table", "DROP TABLE usage_records;"),
        (
            "view instead of table",
            "ALTER TABLE usage_records RENAME TO old_usage;
             CREATE VIEW usage_records AS SELECT * FROM old_usage;",
        ),
        (
            "missing ttft_ms",
            "ALTER TABLE usage_records DROP COLUMN ttft_ms;",
        ),
        (
            "missing cache_creation_tokens",
            "ALTER TABLE usage_records DROP COLUMN cache_creation_tokens;",
        ),
    ]);
}

#[test]
fn import_rejects_malformed_values_in_usage_rows() {
    assert_rejected_usage(&[
        (
            "stream outside 0/1",
            "UPDATE usage_records SET stream = 2 WHERE id = 1201;",
        ),
        (
            "noninteger stream",
            "UPDATE usage_records SET stream = 'invalid' WHERE id = 1201;",
        ),
        (
            "fractional token count",
            "UPDATE usage_records SET cache_read_tokens = 1.25 WHERE id = 1201;",
        ),
        (
            "blob timestamp",
            "UPDATE usage_records SET created_at = x'00ff' WHERE id = 1201;",
        ),
        (
            "null email",
            "UPDATE usage_records SET email = NULL WHERE id = 1201;",
        ),
    ]);
}

async fn usage_response(app: &Router, query: &str, session: bool) -> (StatusCode, Value) {
    let mut request = Request::builder().uri(format!("/api/usage-records{query}"));
    if session {
        request = request.header("cookie", format!("{SESSION_COOKIE}={SESSION}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn usage_records(app: &Router, query: &str) -> Vec<Value> {
    let (status, body) = usage_response(app, query, true).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "GET /api/usage-records{query}: {body}"
    );
    body["records"].as_array().unwrap().clone()
}

#[tokio::test]
async fn usage_route_merges_live_and_go_records_under_one_session_gated_limit() {
    let f = Fixture::new(&format!(
        "{USAGE_ROW}
         WITH RECURSIVE ids(id) AS (VALUES (2) UNION ALL SELECT id + 1 FROM ids WHERE id < 1050)
         INSERT INTO usage_records (id, created_at) SELECT id, '2099-01-01 00:00:00' FROM ids;"
    ));
    f.import().unwrap();
    let state = Arc::new(
        AppState::try_from_db_with_vault(
            String::new(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
            f.runtime(),
            Vault::from_secret(PUBLIC_SEED).unwrap(),
        )
        .unwrap(),
    );
    state
        .sessions
        .lock()
        .unwrap()
        .insert(SESSION.into(), i64::MAX);
    let app = build_router(state.clone());
    assert_eq!(
        usage_response(&app, "", false).await.0,
        StatusCode::UNAUTHORIZED
    );

    for (status, gateway_key_id, quota_charge) in [(200, 1, 7), (429, 0, 0)] {
        record_usage_db(
            &state,
            UsageRecord {
                account_id: 101,
                status,
                gateway_key_id,
                quota_charge,
            },
        )
        .unwrap();
    }

    let default = usage_records(&app, "").await;
    assert_eq!(default.len(), 50);
    assert_eq!(usage_records(&app, "?limit=1").await, default[..1]);
    assert_eq!(usage_records(&app, "?limit=3").await, default[..3]);
    let capped = usage_records(&app, "?limit=1001").await;
    assert_eq!(capped.len(), 1000);
    assert_eq!(capped[..50], default);
    assert_eq!(capped[999]["id"], 54);

    for (row, status, key, charge) in [(&default[0], 429, 0, 0), (&default[1], 200, 1, 7)] {
        assert!(row["created_at"].is_i64());
        assert_eq!(row["account_id"], 101);
        assert_eq!(row["status"], status);
        assert_eq!(row["status_code"], status);
        assert_eq!(row["gateway_key_id"], key);
        assert_eq!(row["quota_charge"], charge);
        for key in ["model", "prompt_tokens", "stream"] {
            assert!(row[key].is_null(), "live ledger has no value for {key}");
        }
    }
    let expected = json!({
        "id": 1201, "created_at": "2026-11-01 01:30:00.123", "account_id": 101,
        "email": "a@example.invalid", "model": "PUBLIC-model", "prompt_tokens": 23,
        "completion_tokens": 29, "total_tokens": 4_000_000_000_i64, "cache_read_tokens": 13,
        "cache_creation_tokens": 17, "stream": true, "status_code": 502, "duration_ms": 123,
        "ttft_ms": 19, "gateway_key_id": 1, "key_name": "PUBLIC named key", "channel": "paid"
    });
    for (key, value) in expected.as_object().unwrap() {
        assert_eq!(
            default[2].get(key.as_str()),
            Some(value),
            "Go usage field {key}"
        );
    }
    assert_eq!(default[3]["id"], 1050);
    assert_eq!(default[3]["stream"], false);
    assert_eq!(default[49]["id"], 1004);

    let runtime = f.runtime();
    assert_eq!(integer(&runtime, "SELECT count(*) FROM usage_records"), 2);
    assert_eq!(
        integer(&runtime, "SELECT quota_used FROM gateway_keys WHERE id = 1"),
        130,
        "import and reporting must not debit quota; the live charge must post once"
    );
}

#[test]
fn import_rejects_an_exhausted_live_usage_id_space() {
    let max = i64::MAX;
    assert_rejected_usage(&[
        (
            "deleted row left the source sequence at i64::MAX",
            &format!(
                "INSERT INTO usage_records (id) VALUES ({max});
                 DELETE FROM usage_records WHERE id = {max};"
            ),
        ),
        (
            "archived row ID raised to i64::MAX above the source sequence",
            &format!("UPDATE usage_records SET id = {max} WHERE id = 1201;"),
        ),
    ]);
}
