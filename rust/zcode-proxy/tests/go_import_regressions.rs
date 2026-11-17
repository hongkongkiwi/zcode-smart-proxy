use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use rusqlite::{types::Value as SqlValue, Connection, OpenFlags};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zcode_proxy::{
    go_compat, go_import,
    state::{AppState, UpstreamUrls},
    store,
    vault::Vault,
};

// Public synthetic seed shared with the Go-produced vault interop fixture.
const PUBLIC_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const CREDENTIALS: [(&str, &str); 6] = [
    ("access_token", "PUBLIC access token"),
    ("refresh_token", "PUBLIC refresh token"),
    ("zcode_jwt", "PUBLIC jwt"),
    ("api_key", "PUBLIC account key"),
    ("user_info", "{\"PUBLIC\":\"用户\"}"),
    ("creds_raw", "PUBLIC credentials café\nline 2\0end"),
];
const SECRET_SETTINGS: [&str; 7] = [
    "api_key",
    "password_hash",
    "upstream_proxy",
    "totp_secret",
    "totp_recovery",
    "passkey_credentials",
    "passkey_user_handle",
];

struct Fixture {
    root: PathBuf,
    source: PathBuf,
    destination: PathBuf,
    settings: BTreeMap<String, String>,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "zcode-go-import-{}-{:032x}",
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
        db.execute_batch(
            "PRAGMA user_version = 37;
             PRAGMA application_id = 1514357829;
             ALTER TABLE accounts ADD COLUMN future_metadata BLOB;
             UPDATE accounts SET future_metadata = x'00ff807f',
                 display_name = 'PUBLIC archived name', quota_json = '{\"PUBLIC\":17}',
                 auth_type = 'oauth', remark = 'PUBLIC archived remark'
                 WHERE id = 101;
             UPDATE accounts SET remaining = 0.25 WHERE id = 102;
             UPDATE gateway_keys SET id = 801, rpm_limit = 31, rate_5h = 41,
                 rate_1d = 51, rate_7d = 61, quota_total = 9000, quota_used = 123,
                 models = 'PUBLIC-model,other', last_used_at = 1700000000;
             INSERT INTO gateway_keys
                 (id, name, key_hash, key_prefix, enabled, rpm_limit, quota_total,
                  quota_used, models, rate_5h, rate_1d, rate_7d, created_at, updated_at)
                 VALUES (802, 'PUBLIC disabled key', 'PUBLIC-disabled-hash',
                     'PUBLIC-disabled-prefix', 0, 0, 0, 77, '', 0, 0, 0,
                     '2026-01-01 00:00:00', '2026-01-02 00:00:00');
             UPDATE usage_records SET gateway_key_id = 801,
                 key_name = 'PUBLIC named key', total_tokens = 4000000000,
                 cache_read_tokens = 13, cache_creation_tokens = 17,
                 status_code = 200, duration_ms = 123, ttft_ms = 19;
             INSERT INTO usage_records
                 (id, created_at, account_id, email, model, prompt_tokens,
                  completion_tokens, total_tokens, stream, status_code, channel,
                  gateway_key_id, key_name)
                 VALUES (909, '2026-11-01 01:30:00', 101, 'a@example.invalid',
                     'PUBLIC-model', 23, 29, 52, 1, 502, 'paid', 801, 'PUBLIC named key');
             INSERT INTO claim_plans
                 (id, plan_name, cron_expr, account_id, last_run_at, created_at, updated_at)
                 VALUES (701, 'PUBLIC claim plan', '0 9 * * *', 101,
                     'PUBLIC timestamp retained verbatim',
                     '2026-01-01 00:00:00', '2026-01-02 00:00:00');
             INSERT INTO claim_records
                 (id, created_at, account_id, plan_id, success, message, next_at, used_at)
                 VALUES (702, 'PUBLIC timestamp without a timezone', 101, '701', 1,
                     'PUBLIC claim message 用户', 2000000000, 1700000000);
             INSERT INTO plan_run_records
                 (id, plan_id, account_id, run_at, status, message, total,
                  success_count, fail_count, duration_ms)
                 VALUES (703, 701, 101, '2026-11-01 01:30:00', 'partial',
                     'PUBLIC run message', 2, 1, 1, 57);
             INSERT INTO proxy_nodes
                 (id, name, host, port, username, password, created_at, updated_at)
                 VALUES (601, 'PUBLIC proxy', 'proxy.example.invalid', 1080,
                     'PUBLIC proxy user', '', '2026-01-01 00:00:00', '2026-01-02 00:00:00');
             CREATE TABLE \"PUBLIC future metadata\" (
                 name TEXT PRIMARY KEY, payload, optional BLOB
             ) WITHOUT ROWID;
             INSERT INTO \"PUBLIC future metadata\" VALUES
                 ('blob', x'00ff807f', NULL), ('integer', 9223372036854775806, x''),
                 ('real', 0.125, x'0102'), ('text', 'vault1:PUBLIC-not-a-secret', NULL);
             CREATE INDEX \"PUBLIC future index\" ON accounts(future_metadata)
                 WHERE future_metadata IS NOT NULL;
             CREATE VIEW \"PUBLIC future view\" AS SELECT name, payload
                 FROM \"PUBLIC future metadata\";
             CREATE TRIGGER \"PUBLIC future trigger\" AFTER UPDATE OF remark ON accounts
                 BEGIN INSERT OR REPLACE INTO \"PUBLIC future metadata\"
                     VALUES ('trigger', NEW.remark, NULL); END;",
        )
        .unwrap();
        for (column, plain) in CREDENTIALS {
            db.execute(
                &format!("UPDATE accounts SET {column} = ?1 WHERE id = 101"),
                [vault.encrypt(plain).unwrap()],
            )
            .unwrap();
        }
        let settings: BTreeMap<String, String> = BTreeMap::from([
            ("api_key".into(), "PUBLIC root key".into()),
            (
                "password_hash".into(),
                bcrypt::hash("PUBLIC admin password", 4).unwrap(),
            ),
            (
                "upstream_proxy".into(),
                "socks5://PUBLIC:PUBLIC@proxy.example.invalid:1080".into(),
            ),
            ("totp_secret".into(), "JBSWY3DPEHPK3PXP".into()),
            (
                "totp_recovery".into(),
                serde_json::to_string(&vec![hash("abcdoll2"), hash("efgh2345")]).unwrap(),
            ),
            (
                "passkey_credentials".into(),
                "[{\"PUBLIC\":\"credential\"}]".into(),
            ),
            ("passkey_user_handle".into(), "PUBLIC passkey handle".into()),
            ("admin_user".into(), "PUBLIC-admin".into()),
            ("totp_enabled".into(), "1".into()),
            ("selection_strategy".into(), "priority".into()),
            (
                "PUBLIC-unknown-setting".into(),
                "vault1:PUBLIC-not-an-envelope".into(),
            ),
        ]);
        for (key, plain) in &settings {
            let stored = if SECRET_SETTINGS.contains(&key.as_str()) {
                vault.encrypt(plain).unwrap()
            } else {
                plain.clone()
            };
            db.execute(
                "INSERT INTO settings(key, value, updated_at)
                 VALUES(?1, ?2, '2026-01-01 00:00:00')
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [key, &stored],
            )
            .unwrap();
        }
        db.execute(
            "UPDATE proxy_nodes SET password = ?1 WHERE id = 601",
            [vault.encrypt("PUBLIC proxy password").unwrap()],
        )
        .unwrap();
        drop(db);
        Self {
            root,
            source,
            destination,
            settings,
        }
    }

    fn import(&self) {
        go_import::import_database(&self.source, &self.destination, PUBLIC_SEED).unwrap();
    }

    fn runtime(&self) -> Connection {
        read_only(&self.destination.join("zcode-rs.db"))
    }

    fn archive(&self) -> Connection {
        read_only(&self.destination.join("go-source.sqlite"))
    }

    fn vault(&self) -> Vault {
        let seed = go_compat::load_vault_key(self.destination.to_str().unwrap()).unwrap();
        Vault::from_secret(&seed).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn hash(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn read_only(path: &Path) -> Connection {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
}

fn quote(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn rows(db: &Connection, sql: &str) -> Vec<Vec<SqlValue>> {
    let mut stmt = db.prepare(sql).unwrap();
    let width = stmt.column_count();
    let result = stmt
        .query_map([], |row| (0..width).map(|i| row.get(i)).collect())
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    result
}

fn snapshot(db: &Connection) -> BTreeMap<String, Vec<Vec<SqlValue>>> {
    let mut result = BTreeMap::from([
        (
            "schema".into(),
            rows(
                db,
                "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name",
            ),
        ),
        ("user_version".into(), rows(db, "PRAGMA user_version")),
        ("application_id".into(), rows(db, "PRAGMA application_id")),
    ]);
    let mut stmt = db
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")
        .unwrap();
    let names = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for name in names {
        let table = quote(&name);
        let width = db
            .prepare(&format!("SELECT * FROM {table}"))
            .unwrap()
            .column_count();
        let order = (1..=width)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        result.insert(
            format!("table:{name}"),
            rows(db, &format!("SELECT * FROM {table} ORDER BY {order}")),
        );
    }
    result
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

fn count(db: &Connection, table: &str) -> i64 {
    db.query_row(&format!("SELECT count(*) FROM {}", quote(table)), [], |r| {
        r.get(0)
    })
    .unwrap()
}

#[test]
fn complete_sqlite_archive_retains_exact_schema_typed_rows_and_source_bytes() {
    let f = Fixture::new();
    let before_files = files(f.source.parent().unwrap());
    let source = read_only(&f.source);
    let before = snapshot(&source);
    f.import();
    assert_eq!(snapshot(&f.archive()), before);
    assert_eq!(snapshot(&source), before);
    assert_eq!(files(f.source.parent().unwrap()), before_files);
    let integrity: String = f
        .archive()
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    for artifact in [
        "go-source.sqlite",
        "zcode-rs.db",
        "vault.key",
        "import-manifest.json",
    ] {
        assert!(f.destination.join(artifact).is_file(), "missing {artifact}");
    }
}

#[test]
fn runtime_accounts_settings_auth_aliases_and_named_keys_reload_with_explicit_vault() {
    let f = Fixture::new();
    f.import();
    let db = f.runtime();
    store::check_schema(&db).unwrap();
    let vault = f.vault();
    let accounts = store::load_accounts(&db, &vault).unwrap();
    assert_eq!(accounts.len(), 2);
    let (a, jwt, key) = accounts.iter().find(|(a, _, _)| a.id == 101).unwrap();
    assert_eq!(a.email, "a@example.invalid");
    assert_eq!(a.provider, "zai");
    assert!(a.enabled);
    assert!(a.paid_fallback);
    assert_eq!(a.status, "cooling");
    assert_eq!(a.cooling_until, 2_000_000_000);
    assert_eq!(a.paid_cooling_until, 2_000_000_100);
    assert_eq!(a.account_group, "one,two");
    assert_eq!(a.priority, 50);
    assert_eq!(a.remaining, 12.5);
    assert_eq!(jwt, "PUBLIC jwt");
    assert_eq!(key, "PUBLIC account key");
    let (b, jwt, key) = accounts.iter().find(|(a, _, _)| a.id == 102).unwrap();
    assert!(!b.enabled);
    assert!(!b.paid_fallback);
    assert_eq!(b.provider, "bigmodel");
    assert_eq!(b.status, "disabled");
    assert_eq!(b.priority, 100);
    assert_eq!(b.remaining, 0.25);
    assert_eq!(jwt, "PUBLIC legacy jwt");
    assert_eq!(key, "PUBLIC legacy api key");
    for row in rows(&db, "SELECT zcode_jwt, api_key FROM accounts ORDER BY id") {
        for stored in row {
            assert!(matches!(stored, SqlValue::Text(s) if s.starts_with("vault1:")));
        }
    }
    let settings = store::load_settings(&db, &vault).unwrap();
    for (key, expected) in &f.settings {
        assert_eq!(settings.get(key), Some(expected), "setting {key}");
    }
    for (go, rust) in [
        ("password_hash", "admin_password_hash"),
        ("admin_user", "admin_username"),
        ("totp_recovery", "recovery_codes"),
    ] {
        assert_eq!(
            settings.get(rust),
            f.settings.get(go),
            "alias {go} -> {rust}"
        );
    }
    assert!(bcrypt::verify("PUBLIC admin password", &settings["admin_password_hash"]).unwrap());
    for key in SECRET_SETTINGS
        .into_iter()
        .chain(["admin_password_hash", "recovery_codes"])
    {
        assert!(
            store::get_setting(&db, key).unwrap().starts_with("vault1:"),
            "unencrypted {key}"
        );
    }
    let keys = store::list_gateway_keys(&db);
    assert_eq!(keys.len(), 2);
    let key = keys.iter().find(|key| key.id == 801).unwrap();
    assert_eq!(key.name, "PUBLIC named key");
    assert_eq!(key.key_hash, "PUBLIC-not-a-real-hash");
    assert!(key.enabled);
    assert_eq!(key.models, "PUBLIC-model,other");
    assert_eq!(
        (key.rpm_limit, key.rate_5h, key.rate_1d, key.rate_7d),
        (31, 41, 51, 61)
    );
    assert_eq!((key.quota_total, key.quota_used), (9000, 123));
    let disabled = keys.iter().find(|key| key.id == 802).unwrap();
    assert!(!disabled.enabled);
    assert_eq!((disabled.quota_total, disabled.quota_used), (0, 77));
    drop(db);

    let state = AppState::try_from_db_with_vault(
        String::new(),
        UpstreamUrls {
            zai: "http://127.0.0.1:1/unused".into(),
            zai_fallback: "http://127.0.0.1:1/unused".into(),
        },
        store::try_open(f.destination.join("zcode-rs.db").to_str().unwrap()).unwrap(),
        f.vault(),
    )
    .unwrap();
    assert_eq!(state.accounts.lock().unwrap().len(), 2);
    assert_eq!(state.named_keys.lock().unwrap().len(), 2);
    assert!(state.consume_recovery_code(" ABCD-O112 ").unwrap());
    assert!(!state.consume_recovery_code("abcd-oil2").unwrap());
    assert!(state.consume_recovery_code("efgh-2345").unwrap());
}

#[test]
fn wrong_secret_and_every_malformed_or_foreign_cipher_location_leave_no_destination() {
    let f = Fixture::new();
    let before = files(&f.root);
    assert!(go_import::import_database(&f.source, &f.destination, "PUBLIC wrong secret").is_err());
    assert_eq!(files(&f.root), before);
    assert!(!f.destination.exists());

    let foreign = Vault::from_secret("PUBLIC foreign seed").unwrap();
    for location in CREDENTIALS
        .iter()
        .map(|(column, _)| ("accounts", *column))
        .chain(SECRET_SETTINGS.into_iter().map(|key| ("settings", key)))
        .chain([("proxy_nodes", "password")])
    {
        for broken in [
            "vault1:PUBLIC-invalid-envelope".to_owned(),
            foreign.encrypt("PUBLIC foreign credential").unwrap(),
        ] {
            let f = Fixture::new();
            let db = Connection::open(&f.source).unwrap();
            let (table, column) = location;
            if table == "settings" {
                db.execute(
                    "UPDATE settings SET value = ?1 WHERE key = ?2",
                    [&broken, column],
                )
                .unwrap();
            } else {
                db.execute(&format!("UPDATE {table} SET {column} = ?1"), [&broken])
                    .unwrap();
            }
            drop(db);
            let before = files(&f.root);
            assert!(
                go_import::import_database(&f.source, &f.destination, PUBLIC_SEED).is_err(),
                "accepted broken {table}.{column}"
            );
            assert!(
                !f.destination.exists(),
                "published destination for {table}.{column}"
            );
            assert_eq!(files(&f.root), before, "changed files for {table}.{column}");
        }
    }
    let f = Fixture::new();
    let db = Connection::open(&f.source).unwrap();
    db.execute(
        "UPDATE accounts SET priority = 'PUBLIC-not-an-integer' WHERE id = 102",
        [],
    )
    .unwrap();
    drop(db);
    let before = files(&f.root);
    assert!(go_import::import_database(&f.source, &f.destination, PUBLIC_SEED).is_err());
    assert_eq!(
        files(&f.root),
        before,
        "typed row failure published a partial import"
    );
}

#[test]
fn existing_destination_is_never_overwritten_even_if_empty_or_already_imported() {
    for kind in [
        "empty directory",
        "nonempty directory",
        "file",
        "completed import",
        "source directory",
    ] {
        let f = Fixture::new();
        let destination = if kind == "source directory" {
            f.source.parent().unwrap().to_path_buf()
        } else {
            f.destination.clone()
        };
        match kind {
            "empty directory" => fs::create_dir(&destination).unwrap(),
            "nonempty directory" => {
                fs::create_dir(&destination).unwrap();
                for name in [
                    "go-source.sqlite",
                    "zcode-rs.db",
                    "vault.key",
                    "import-manifest.json",
                    "PUBLIC-marker",
                ] {
                    fs::write(destination.join(name), format!("PUBLIC existing {name}")).unwrap();
                }
            }
            "file" => fs::write(&destination, "PUBLIC existing file").unwrap(),
            "completed import" => f.import(),
            "source directory" => (),
            _ => unreachable!(),
        }
        let before = files(&f.root);
        assert!(
            go_import::import_database(&f.source, &destination, PUBLIC_SEED).is_err(),
            "accepted {kind}"
        );
        assert_eq!(files(&f.root), before, "overwrote {kind}");
    }
}

#[test]
fn unknown_metadata_claims_and_history_are_archived_without_timezone_projection() {
    let f = Fixture::new();
    f.import();
    let source = read_only(&f.source);
    let archive = f.archive();
    for table in [
        "PUBLIC future metadata",
        "claim_plans",
        "claim_records",
        "plan_run_records",
        "usage_records",
        "proxy_nodes",
    ] {
        let query = format!("SELECT * FROM {} ORDER BY 1", quote(table));
        assert_eq!(
            rows(&archive, &query),
            rows(&source, &query),
            "archived {table}"
        );
    }
    assert_eq!(
        rows(
            &archive,
            "SELECT typeof(payload) FROM \"PUBLIC future metadata\" ORDER BY name"
        ),
        vec![
            vec![SqlValue::Text("blob".into())],
            vec![SqlValue::Text("integer".into())],
            vec![SqlValue::Text("real".into())],
            vec![SqlValue::Text("text".into())]
        ]
    );
    let db = f.runtime();
    assert_eq!(
        count(&db, "usage_records"),
        0,
        "ambiguous Go timestamps must not be guessed"
    );
    let manifest: Value =
        serde_json::from_slice(&fs::read(f.destination.join("import-manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["complete"], true);
    assert_eq!(manifest["archive"], "go-source.sqlite");
    assert_eq!(manifest["runtime"], "zcode-rs.db");
    assert_eq!(manifest["history_projection"], "deferred");
}

#[test]
fn existing_balances_are_copied_once_without_replaying_historical_usage_debits() {
    let f = Fixture::new();
    f.import();
    let before = snapshot(&f.runtime());
    for _ in 0..2 {
        let db = f.runtime();
        let keys = store::list_gateway_keys(&db);
        assert_eq!(
            keys.iter().find(|key| key.id == 801).unwrap().quota_used,
            123
        );
        assert_eq!(
            keys.iter().find(|key| key.id == 802).unwrap().quota_used,
            77
        );
        let accounts = store::load_accounts(&db, &f.vault()).unwrap();
        assert_eq!(
            accounts
                .iter()
                .find(|(a, _, _)| a.id == 101)
                .unwrap()
                .0
                .remaining,
            12.5
        );
        assert_eq!(
            accounts
                .iter()
                .find(|(a, _, _)| a.id == 102)
                .unwrap()
                .0
                .remaining,
            0.25
        );
        assert_eq!(count(&db, "usage_records"), 0);
        assert_eq!(snapshot(&db), before);
    }
    let second = f.root.join("second-import");
    go_import::import_database(&f.source, &second, PUBLIC_SEED).unwrap();
    let second_db = read_only(&second.join("zcode-rs.db"));
    assert_eq!(
        rows(
            &second_db,
            "SELECT id, quota_total, quota_used FROM gateway_keys ORDER BY id"
        ),
        rows(
            &f.runtime(),
            "SELECT id, quota_total, quota_used FROM gateway_keys ORDER BY id"
        )
    );
    assert_eq!(
        rows(&second_db, "SELECT id, remaining FROM accounts ORDER BY id"),
        rows(
            &f.runtime(),
            "SELECT id, remaining FROM accounts ORDER BY id"
        )
    );
    assert_eq!(count(&second_db, "usage_records"), 0);
    assert_eq!(snapshot(&f.runtime()), before);
    assert_eq!(count(&f.archive(), "usage_records"), 2);
}
