use std::{
    fs,
    path::{Path, PathBuf},
};

use rusqlite::{types::Value as SqlValue, Connection, OpenFlags};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zcode_proxy::go_import;

const PUBLIC_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const PLANS: &str = "SELECT id, plan_name, cron_expr, is_active, target_type, account_id,
    account_group, task_type, auto_pick, delay_seconds, last_run_at, last_run_status,
    last_run_msg, created_at, updated_at FROM claim_plans ORDER BY id";
const RUNS: &str = "SELECT id, plan_id, plan_name, task_type, target_type, account_id,
    run_at, status, message, total, success_count, fail_count, duration_ms
    FROM plan_run_records ORDER BY id";

struct Fixture {
    root: PathBuf,
    source: PathBuf,
    destination: PathBuf,
}

impl Fixture {
    fn new(sql: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "zcode-go-import-schedule-{}-{:032x}",
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

fn rows(db: &Connection, sql: &str) -> Vec<Vec<SqlValue>> {
    let mut stmt = db.prepare(sql).unwrap();
    let width = stmt.column_count();
    let rows = stmt
        .query_map([], |row| (0..width).map(|i| row.get(i)).collect())
        .unwrap();
    rows.collect::<rusqlite::Result<_>>().unwrap()
}

#[test]
fn import_preserves_schedule_rows_except_for_disabling_plans() {
    let f = Fixture::new(
        "INSERT INTO claim_plans
             (id, plan_name, cron_expr, is_active, target_type, account_id, account_group,
              task_type, auto_pick, delay_seconds, last_run_at, last_run_status, last_run_msg,
              created_at, updated_at)
         VALUES
             (701, 'PUBLIC 配额计划', '7 8 * * 1-5', 1, 'group', 0, 'PUBLIC group',
              'reset', 0, 47, '2026-05-31 08:07:05.123', 'running', ' PUBLIC 执行中 ',
              '2026-04-01 04:23:00', '2026-05-31 08:07:00'),
             (705, 'PUBLIC disabled plan', '13 4 * * 0', 0, 'single_account', 102, '',
              'claim', 1, 19, '2026-05-31 04:13:03', 'success', 'PUBLIC success',
              '2026-04-02 08:37:12', '2026-05-31 04:13:00');
         INSERT INTO plan_run_records
             (id, plan_id, plan_name, task_type, target_type, account_id, run_at, status,
              message, total, success_count, fail_count, duration_ms)
         VALUES
             (801, 701, 'PUBLIC earlier plan name', 'reset', 'group', 0,
              '2026-05-30 08:07:05.456', 'partial', ' PUBLIC 部分成功 ', 5, 3, 2, 127),
             (807, 699, 'PUBLIC deleted plan', 'claim', 'single_account', 101,
              '2026-05-29 02:31:09', 'failed', 'PUBLIC failure', 1, 0, 1, 293);",
    );
    let source_checksum = checksum(&f.source);
    let source = read_only(&f.source);
    let mut expected_plans = rows(&source, PLANS);
    let expected_runs = rows(&source, RUNS);
    drop(source);

    f.import().unwrap();

    assert_eq!(checksum(&f.source), source_checksum, "source bytes changed");
    let archive = read_only(&f.destination.join("go-source.sqlite"));
    assert_eq!(rows(&archive, PLANS), expected_plans, "archived plans");
    assert_eq!(rows(&archive, RUNS), expected_runs, "archived runs");
    let manifest: Value =
        serde_json::from_slice(&fs::read(f.destination.join("import-manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["history_projection"], "deferred");

    for plan in &mut expected_plans {
        plan[3] = SqlValue::Integer(0); // is_active
    }
    let runtime = read_only(&f.destination.join("zcode-rs.db"));
    assert_eq!(
        rows(&runtime, PLANS),
        expected_plans,
        "runtime plans must be disabled with every other field preserved, including running status"
    );
    assert_eq!(
        rows(&runtime, RUNS),
        expected_runs,
        "runtime history must include records for deleted plans"
    );
}

#[test]
fn next_schedule_ids_exceed_deleted_and_updated_source_ids() {
    let tables = ["claim_plans", "plan_run_records"];
    let next_ids = [false, true].map(|raise_id| {
        let f = Fixture::new("");
        let source = Connection::open(&f.source).unwrap();
        for table in tables {
            source
                .execute_batch(&format!(
                    "INSERT INTO {table} (id) VALUES (1200);
                     DELETE FROM {table} WHERE id = 1200;"
                ))
                .unwrap();
            if raise_id {
                source
                    .execute_batch(&format!(
                        "INSERT INTO {table} (id) VALUES (701);
                         UPDATE {table} SET id = 1300 WHERE id = 701;"
                    ))
                    .unwrap();
            }
        }
        drop(source);

        f.import().unwrap();

        let archive = read_only(&f.destination.join("go-source.sqlite"));
        let runtime = Connection::open(f.destination.join("zcode-rs.db")).unwrap();
        tables.map(|table| {
            let seq: i64 = archive
                .query_row(
                    "SELECT seq FROM sqlite_sequence WHERE name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(seq, 1200, "archived sequence changed for {table}");
            // The updated ID must not be reused even after the runtime row is deleted.
            runtime
                .execute(&format!("DELETE FROM {table} WHERE id = 1300"), [])
                .unwrap();
            runtime
                .execute(&format!("INSERT INTO {table} DEFAULT VALUES"), [])
                .unwrap();
            runtime.last_insert_rowid()
        })
    });
    assert_eq!(
        next_ids,
        [[1201, 1201], [1301, 1301]],
        "next [plan, run] IDs after deleting a source ID and after updating a source ID above its sequence"
    );
}

fn assert_rejected_imports(seed: &str, cases: &[(&str, &str)]) {
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
        "invalid schedule cases (case, accepted, published): {violations:?}"
    );
}

#[test]
fn import_rejects_missing_or_incomplete_schedule_tables_without_publishing() {
    assert_rejected_imports(
        "",
        &[
            ("missing plans", "DROP TABLE claim_plans;"),
            (
                "view instead of plans table",
                "ALTER TABLE claim_plans RENAME TO old_plans;
                 CREATE VIEW claim_plans AS SELECT * FROM old_plans;",
            ),
            (
                "missing plan column",
                "ALTER TABLE claim_plans DROP COLUMN last_run_msg;",
            ),
            ("missing runs", "DROP TABLE plan_run_records;"),
            (
                "view instead of runs table",
                "ALTER TABLE plan_run_records RENAME TO old_runs;
                 CREATE VIEW plan_run_records AS SELECT * FROM old_runs;",
            ),
            (
                "missing run column",
                "ALTER TABLE plan_run_records DROP COLUMN duration_ms;",
            ),
        ],
    );
}

#[test]
fn import_rejects_malformed_schedule_rows_without_publishing() {
    assert_rejected_imports(
        "INSERT INTO claim_plans (id, is_active) VALUES (701, 1), (705, 0);
         INSERT INTO plan_run_records (id, plan_id) VALUES (801, 701), (807, 705);",
        &[
            (
                "plan is_active outside 0/1",
                "UPDATE claim_plans SET is_active = 2 WHERE id = 705;",
            ),
            (
                "noninteger plan is_active",
                "UPDATE claim_plans SET is_active = 'invalid' WHERE id = 705;",
            ),
            (
                "NULL plan name",
                "UPDATE claim_plans SET plan_name = NULL WHERE id = 705;",
            ),
            (
                "noninteger run duration",
                "UPDATE plan_run_records SET duration_ms = 'invalid' WHERE id = 807;",
            ),
        ],
    );
}

#[tokio::test]
async fn scheduler_start_preserves_imported_running_plan_and_terminal_history() {
    use std::{sync::Arc, time::Duration};
    use zcode_proxy::{
        go_compat,
        scheduler::{Scheduler, SchedulerConfig},
        state::{AppState, UpstreamUrls},
        store,
        vault::Vault,
    };

    let f = Fixture::new(
        "INSERT INTO claim_plans
             (id, plan_name, is_active, last_run_at, last_run_status, last_run_msg)
         VALUES (701, 'PUBLIC imported plan', 1, '2026-05-31 08:07:05.123',
                 'running', 'PUBLIC Go run in progress');
         INSERT INTO plan_run_records
             (id, plan_id, plan_name, run_at, status, message, total, success_count, duration_ms)
         VALUES (801, 701, 'PUBLIC imported plan', '2026-05-30 08:07:05.456',
                 'success', 'PUBLIC previous run finished', 1, 1, 57);",
    );
    let source = read_only(&f.source);
    let mut expected_plans = rows(&source, PLANS);
    expected_plans[0][3] = SqlValue::Integer(0); // is_active
    let expected_history = rows(&source, RUNS);
    drop(source);

    f.import().unwrap();

    let seed = go_compat::load_vault_key(f.destination.to_str().unwrap()).unwrap();
    let runtime_path = f.destination.join("zcode-rs.db");
    let state = Arc::new(
        AppState::try_from_db_with_vault(
            String::new(),
            UpstreamUrls {
                zai: "http://unused.example.invalid".into(),
                zai_fallback: "http://unused.example.invalid".into(),
            },
            store::try_open(runtime_path.to_str().unwrap()).unwrap(),
            Vault::from_secret(&seed).unwrap(),
        )
        .unwrap(),
    );
    let scheduler = Arc::new(Scheduler::with_config(
        state.clone(),
        SchedulerConfig {
            tick_interval: Duration::from_secs(3600),
            ..SchedulerConfig::default()
        },
    ));
    state.set_scheduler(scheduler.clone()).unwrap();
    scheduler.start().unwrap();
    scheduler.shutdown().await;

    let runtime = state.db.lock().unwrap();
    assert_eq!(
        (rows(&runtime, PLANS), rows(&runtime, RUNS)),
        (expected_plans, expected_history),
        "startup must leave the imported running plan and terminal history unchanged"
    );
}

#[test]
fn next_plan_id_exceeds_deleted_plan_referenced_by_imported_history() {
    let f = Fixture::new(
        "INSERT INTO claim_plans (id) VALUES (701), (702);
         UPDATE claim_plans SET id = 1300 WHERE id = 702;
         INSERT INTO plan_run_records (id, plan_id, status) VALUES (801, 1300, 'success');
         DELETE FROM claim_plans WHERE id = 1300;",
    );

    f.import().unwrap();

    let runtime = Connection::open(f.destination.join("zcode-rs.db")).unwrap();
    runtime
        .execute("INSERT INTO claim_plans DEFAULT VALUES", [])
        .unwrap();
    assert_eq!(
        runtime.last_insert_rowid(),
        1301,
        "a new plan ID must not collide with the plan ID preserved in imported history"
    );
}
