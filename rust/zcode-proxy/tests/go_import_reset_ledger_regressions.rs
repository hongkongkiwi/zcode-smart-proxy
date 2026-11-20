use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    extract::{Request, State},
    http::{Method, StatusCode},
    Json, Router,
};
use rusqlite::{types::Value as SqlValue, Connection, OpenFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zcode_proxy::{
    autoreset::{AutoReset, AutoResetConfig, ResetTrigger},
    go_compat, go_import,
    state::{AppState, UpstreamUrls},
    store,
    vault::Vault,
};

const PUBLIC_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const NOW: i64 = 1_780_272_000; // 2026-06-01 00:00:00 UTC

struct Fixture {
    root: PathBuf,
    source: PathBuf,
    destination: PathBuf,
}

impl Fixture {
    fn new(sql: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "zcode-go-import-reset-{}-{:032x}",
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
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn checksum(path: &Path) -> String {
    format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
}

fn read_only(path: &Path) -> Connection {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
}

fn ledger(db: &Connection) -> Vec<Vec<SqlValue>> {
    let mut stmt = db
        .prepare(
            "SELECT id, created_at, account_id, email, task_type, plan_id, plan_name,
                    success, code, message, next_at, used_at
             FROM claim_records ORDER BY id",
        )
        .unwrap();
    let width = stmt.column_count();
    let rows = stmt
        .query_map([], |row| (0..width).map(|i| row.get(i)).collect())
        .unwrap();
    rows.collect::<rusqlite::Result<_>>().unwrap()
}

#[test]
fn import_projects_only_exact_reset_rows_and_keeps_the_ledger_high_water() {
    let f = Fixture::new(
        "INSERT INTO claim_records
             (id, created_at, account_id, email, task_type, plan_id, plan_name,
              success, code, message, next_at, used_at)
         VALUES
             (701, '2026-05-31 23:59:30.123', 101, 'historical@example.invalid',
              'reset', '00042', '配额重置(FIVE_HOUR)', 1, 0, ' PUBLIC restored 配额 ', 1980000000, 1780271970),
             (705, '2026-05-31 23:59:40', 101, 'a@example.invalid',
              'reset', 'plan-7', '配额重置(WEEK)', 0, -17, 'PUBLIC failed', 1980000001, 1780271980),
             (709, '2026-06-01 00:00:00', 102, 'b@example.invalid',
              'reset', '', '配额重置(WEEK)', 1, 0, 'PUBLIC legacy wall clock', 0, 0),
             (850, '2026-06-01 00:00:01', 102, 'b@example.invalid',
              'claim', '00042', 'PUBLIC archived claim', 1, 0, 'PUBLIC other history', 0, 1780272000000),
             (851, '2026-06-01 00:00:02', 102, 'b@example.invalid',
              'RESET', '', 'PUBLIC archived task', 1, 0, 'PUBLIC distinct task type', 0, 1780272002);
         INSERT INTO claim_records (id, task_type) VALUES (1200, 'reset');
         DELETE FROM claim_records WHERE id = 1200;",
    );
    let source_checksum = checksum(&f.source);
    let source = ledger(&read_only(&f.source));
    let expected_resets = source[..3].to_vec();

    f.import().unwrap();

    assert_eq!(checksum(&f.source), source_checksum, "source bytes changed");
    let archive = read_only(&f.destination.join("go-source.sqlite"));
    assert_eq!(
        ledger(&archive),
        source,
        "archive lost or changed ledger rows"
    );
    let runtime = Connection::open(f.destination.join("zcode-rs.db")).unwrap();
    assert_eq!(
        ledger(&runtime),
        expected_resets,
        "runtime must preserve all reset fields, including legacy used_at=0, and omit every other task type"
    );
    runtime
        .execute("INSERT INTO claim_records (task_type) VALUES ('reset')", [])
        .unwrap();
    assert_eq!(
        runtime.last_insert_rowid(),
        1201,
        "the next reset ID must exceed the source high-water mark, even when that row was deleted"
    );
}

#[test]
fn next_runtime_id_skips_archive_only_ids_above_the_source_sequence() {
    let f = Fixture::new(
        "INSERT INTO claim_records (id, task_type) VALUES (701, 'reset'), (850, 'claim');
         UPDATE claim_records SET id = 851 WHERE id = 850;",
    );
    f.import().unwrap();
    let runtime = Connection::open(f.destination.join("zcode-rs.db")).unwrap();
    runtime
        .execute("INSERT INTO claim_records (task_type) VALUES ('reset')", [])
        .unwrap();
    assert_eq!(runtime.last_insert_rowid(), 852);
}

fn assert_rejected_ledgers(seed: &str, cases: &[(&str, &str)]) {
    let mut violations = Vec::new();
    for &(label, mutation) in cases {
        let f = Fixture::new(&format!("{seed}\n{mutation}"));
        let source_checksum = checksum(&f.source);
        let accepted = f.import().is_ok();
        let published = f.destination.exists();
        assert_eq!(
            checksum(&f.source),
            source_checksum,
            "source changed: {label}"
        );
        if accepted || published {
            violations.push((label, accepted, published));
        }
    }
    assert!(
        violations.is_empty(),
        "invalid ledger cases (case, accepted, published): {violations:?}"
    );
}

#[test]
fn import_rejects_missing_or_incomplete_reset_ledger_schema_without_publishing() {
    assert_rejected_ledgers(
        "",
        &[
            ("missing table", "DROP TABLE claim_records;"),
            (
                "view instead of table",
                "ALTER TABLE claim_records RENAME TO old_records;
                 CREATE VIEW claim_records AS SELECT * FROM old_records;",
            ),
            (
                "missing used_at",
                "ALTER TABLE claim_records DROP COLUMN used_at;",
            ),
            (
                "missing message",
                "ALTER TABLE claim_records DROP COLUMN message;",
            ),
        ],
    );
}

#[test]
fn import_rejects_malformed_selected_reset_rows_without_publishing() {
    assert_rejected_ledgers(
        "INSERT INTO claim_records (id, task_type, success, used_at)
         VALUES (701, 'reset', 1, 1780271970), (702, 'reset', 1, 1780271980);",
        &[
            (
                "negative used_at",
                "UPDATE claim_records SET used_at = -1 WHERE id = 702;",
            ),
            (
                "millisecond used_at",
                "UPDATE claim_records SET used_at = 1780271980000 WHERE id = 702;",
            ),
            (
                "success outside 0/1",
                "UPDATE claim_records SET success = 2 WHERE id = 702;",
            ),
            (
                "noninteger success",
                "UPDATE claim_records SET success = 'invalid' WHERE id = 702;",
            ),
        ],
    );
}

type Requests = Arc<Mutex<Vec<(&'static str, i64)>>>;

async fn reset_upstream(
    State(requests): State<Requests>,
    request: Request,
) -> (StatusCode, Json<Value>) {
    let authorization = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok());
    let id = match authorization {
        Some("Bearer PUBLIC recent reset JWT") => 101,
        Some("Bearer PUBLIC legacy reset JWT") => 102,
        _ => return (StatusCode::UNAUTHORIZED, Json(json!({"code":401}))),
    };
    let (event, body) = match (request.method(), request.uri().path()) {
        (&Method::GET, "/status") => (
            "status",
            json!({"code":0,"data":{"available_five_hour_resets":[{"expire_at":NOW + 600}]}}),
        ),
        (&Method::POST, "/use") => ("use", json!({"code":0,"data":{"used":true}})),
        _ => return (StatusCode::NOT_FOUND, Json(json!({"code":404}))),
    };
    requests.lock().unwrap().push((event, id));
    (StatusCode::OK, Json(body))
}

#[tokio::test]
async fn imported_recent_success_blocks_cold_autoreset_but_legacy_zero_does_not() {
    let f = Fixture::new(
        "UPDATE accounts SET enabled = 1, status = 'active', provider = 'zai',
             zcode_jwt = 'PUBLIC recent reset JWT', api_key = 'PUBLIC recent reset key'
         WHERE id = 101;
         UPDATE accounts SET enabled = 1, status = 'active', provider = 'zai',
             zcode_jwt = 'PUBLIC legacy reset JWT', api_key = 'PUBLIC legacy reset key'
         WHERE id = 102;
         INSERT INTO settings (key, value) VALUES ('auto_reset_expiry_enabled', '1');
         INSERT INTO claim_records (created_at, account_id, task_type, success, used_at)
         VALUES ('2026-05-31 23:59:00', 101, 'reset', 1, 1780271940),
                ('2026-06-01 00:00:00', 102, 'reset', 1, 0);",
    );
    f.import().unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let requests = Requests::default();
    let upstream = Router::new()
        .fallback(reset_upstream)
        .with_state(requests.clone());
    let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });

    let seed = go_compat::load_vault_key(f.destination.to_str().unwrap()).unwrap();
    let mut state = AppState::try_from_db_with_vault(
        String::new(),
        UpstreamUrls {
            zai: base.clone(),
            zai_fallback: base.clone(),
        },
        store::try_open(f.destination.join("zcode-rs.db").to_str().unwrap()).unwrap(),
        Vault::from_secret(&seed).unwrap(),
    )
    .unwrap();
    state.automation.reset_status = format!("{base}/status");
    state.automation.reset_use = format!("{base}/use");
    let manager = AutoReset::with_config(
        Arc::new(state),
        AutoResetConfig {
            capacity: 1,
            clock: Arc::new(|| NOW),
            ..AutoResetConfig::default()
        },
    );
    for id in [101, 102] {
        assert!(manager.enqueue(id, ResetTrigger::Sweep));
        tokio::time::timeout(Duration::from_secs(8), manager.wait_idle())
            .await
            .expect("loopback reset attempt did not finish");
    }
    assert!(manager.shutdown().await.drained);
    server.abort();

    let requests = requests.lock().unwrap();
    let accounts_for = |event| {
        requests
            .iter()
            .filter_map(|&(kind, id)| (kind == event).then_some(id))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        accounts_for("status"),
        [101, 102],
        "both accounts checked a spendable slot"
    );
    assert_eq!(
        accounts_for("use"),
        [102],
        "the cold runtime must suppress the recent spend without treating legacy used_at=0 as a spend"
    );
}
