use std::{
    fs,
    path::{Path, PathBuf},
};

use rusqlite::{params, types::Value as SqlValue, Connection, OpenFlags};
use serde_json::{json, Value};
use zcode_proxy::{go_compat, go_import, store, vault::Vault};

const PUBLIC_SECRET: &str = "PUBLIC offline metadata source vault secret";
const CREDENTIAL_COLUMNS: [&str; 6] = [
    "access_token",
    "refresh_token",
    "zcode_jwt",
    "api_key",
    "user_info",
    "creds_raw",
];

fn expected_accounts() -> [(i64, Value); 2] {
    [
        (
            101,
            json!({
                "user_id": "PUBLIC-stable-user-a",
                "email": "PUBLIC-shared@example.invalid",
                "display_name": "PUBLIC 用户 café",
                "provider": "zai",
                "auth_type": "oauth",
                "access_token": "PUBLIC access a",
                "refresh_token": "PUBLIC refresh a",
                "zcode_jwt": "PUBLIC jwt a",
                "api_key": "PUBLIC api key a",
                "user_info": "{\"PUBLIC\":\"用户 a\"}",
                "device_mid": "PUBLIC device a",
                "creds_raw": "PUBLIC raw a\nline 2\0end",
                "account_group": "PUBLIC-one,PUBLIC-two",
                "remark": "PUBLIC remark a 用户"
            }),
        ),
        (
            102,
            json!({
                "user_id": "PUBLIC-stable-user-b",
                "email": "PUBLIC-shared@example.invalid",
                "display_name": "PUBLIC other user",
                "provider": "bigmodel",
                "auth_type": "jwt",
                "access_token": "PUBLIC legacy access b",
                "refresh_token": "PUBLIC legacy refresh b",
                "zcode_jwt": "PUBLIC legacy jwt b",
                "api_key": "PUBLIC legacy api key b",
                "user_info": "{\"PUBLIC\":\"user b\"}",
                "device_mid": "PUBLIC device b",
                "creds_raw": "PUBLIC legacy raw b",
                "account_group": "PUBLIC-three",
                "remark": "PUBLIC remark b"
            }),
        ),
    ]
}

struct Fixture {
    root: PathBuf,
    source: PathBuf,
    destination: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "zcode-go-import-metadata-{}-{:032x}",
            std::process::id(),
            rand::random::<u128>()
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("go.db");
        let destination = root.join("imported");
        let db = Connection::open(&source).unwrap();
        db.execute_batch(include_str!("fixtures/go_schema.sql"))
            .unwrap();
        let vault = Vault::from_secret(PUBLIC_SECRET).unwrap();
        for (id, account) in expected_accounts() {
            for (column, value) in account.as_object().unwrap() {
                let plain = value.as_str().unwrap();
                // Exercise encrypted Go rows and legacy plaintext in the same import.
                let stored = if id == 101 && CREDENTIAL_COLUMNS.contains(&column.as_str()) {
                    vault.encrypt(plain).unwrap()
                } else {
                    plain.to_owned()
                };
                db.execute(
                    &format!("UPDATE accounts SET {column} = ?1 WHERE id = ?2"),
                    params![stored, id],
                )
                .unwrap();
            }
        }
        db.execute_batch(
            "UPDATE accounts SET status = 'cooling', enabled = 1, priority = 37,
                cooling_until = 2000000000, paid_cooling_until = 2000000100,
                remaining = 12.5, paid_fallback = 0 WHERE id = 101;
             UPDATE accounts SET status = 'disabled', enabled = 0, priority = -9,
                cooling_until = 2000000200, paid_cooling_until = 2000000300,
                remaining = 0.25, paid_fallback = 1 WHERE id = 102;",
        )
        .unwrap();
        Self {
            root,
            source,
            destination,
        }
    }

    fn import(&self) {
        go_import::import_database(&self.source, &self.destination, PUBLIC_SECRET).unwrap();
    }

    fn runtime(&self) -> Connection {
        read_only(&self.destination.join("zcode-rs.db"))
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

fn read_only(path: &Path) -> Connection {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
}

fn account_rows(db: &Connection) -> Vec<Vec<SqlValue>> {
    let mut stmt = db.prepare("SELECT * FROM accounts ORDER BY id").unwrap();
    let width = stmt.column_count();
    let rows = stmt
        .query_map([], |row| (0..width).map(|i| row.get(i)).collect())
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    rows
}

#[test]
fn offline_import_projects_all_bundle_metadata_with_stable_ids_and_shared_email() {
    let f = Fixture::new();
    f.import();

    let accounts = store::load_bundle_accounts(&f.runtime(), &f.vault()).unwrap();
    let actual: Vec<_> = accounts
        .into_iter()
        .map(|(id, account)| (id, serde_json::to_value(account).unwrap()))
        .collect();
    assert_eq!(actual, expected_accounts().to_vec());
}

#[test]
fn offline_import_encrypts_all_six_credentials_for_destination_vault_reload() {
    let f = Fixture::new();
    f.import();
    let db = f.runtime();
    let vault = f.vault();
    let source_vault = Vault::from_secret(PUBLIC_SECRET).unwrap();

    for (id, expected) in expected_accounts() {
        for column in CREDENTIAL_COLUMNS {
            let stored: String = db
                .query_row(
                    &format!("SELECT {column} FROM accounts WHERE id = ?1"),
                    [id],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(stored.starts_with("vault1:"), "account {id}: {column}");
            assert_eq!(
                vault.decrypt(&stored).unwrap(),
                expected[column].as_str().unwrap(),
                "account {id}: {column} must decrypt with the published destination key"
            );
            assert!(
                source_vault.decrypt(&stored).is_err(),
                "account {id}: {column} must not retain source-key encryption"
            );
        }
    }
    drop(db);
    drop(vault);

    let reloaded = store::load_bundle_accounts(&f.runtime(), &f.vault()).unwrap();
    for ((id, account), (expected_id, expected)) in reloaded.iter().zip(expected_accounts()) {
        assert_eq!(*id, expected_id);
        let account = serde_json::to_value(account).unwrap();
        for column in CREDENTIAL_COLUMNS {
            assert_eq!(account[column], expected[column], "account {id}: {column}");
        }
    }
    assert_eq!(reloaded.len(), 2);
}

#[test]
fn offline_import_preserves_account_state_and_original_archived_account_rows() {
    let f = Fixture::new();
    let source_bytes = fs::read(&f.source).unwrap();
    let source_rows = account_rows(&read_only(&f.source));
    f.import();

    assert_eq!(fs::read(&f.source).unwrap(), source_bytes);
    assert_eq!(account_rows(&read_only(&f.source)), source_rows);
    assert_eq!(
        account_rows(&read_only(&f.destination.join("go-source.sqlite"))),
        source_rows
    );
    let accounts = store::load_accounts(&f.runtime(), &f.vault()).unwrap();
    let mut actual: Vec<_> = accounts
        .into_iter()
        .map(|(a, _, _)| {
            (
                a.id,
                a.status,
                a.enabled,
                a.priority,
                a.cooling_until,
                a.paid_cooling_until,
                a.remaining,
                a.paid_fallback,
            )
        })
        .collect();
    actual.sort_by_key(|a| a.0);
    assert_eq!(
        actual,
        vec![
            (
                101,
                "cooling".into(),
                true,
                37,
                2_000_000_000,
                2_000_000_100,
                12.5,
                false
            ),
            (
                102,
                "disabled".into(),
                false,
                -9,
                2_000_000_200,
                2_000_000_300,
                0.25,
                true
            ),
        ]
    );
}
