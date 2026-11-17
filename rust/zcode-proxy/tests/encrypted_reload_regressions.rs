use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicUsize, Ordering},
};

use rusqlite::{types::Value as SqlValue, Connection, OpenFlags};
use zcode_proxy::{
    state::{AppState, UpstreamUrls},
    store,
    vault::Vault,
};

// Public fixture seeds, never application keyfiles or environment overrides.
const PUBLIC_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const FOREIGN_SEED: &str = "PUBLIC encrypted reload deliberately foreign seed";
const SECRET_SETTINGS: [(&str, &str); 11] = [
    ("api_key", "PUBLIC gateway API key"),
    ("password_hash", "PUBLIC Go password hash"),
    ("upstream_proxy", "http://PUBLIC:fixture@proxy.invalid:8080"),
    ("totp_secret", "JBSWY3DPEHPK3PXP"),
    ("totp_recovery", "[\"PUBLIC Go recovery hash\"]"),
    ("passkey_credentials", "[{\"id\":\"PUBLIC passkey\"}]"),
    ("passkey_user_handle", "PUBLIC passkey user handle"),
    ("admin_password_hash", "PUBLIC Rust password hash"),
    ("totp_secret_pending", "PUBLIC Rust pending TOTP secret"),
    (
        "pending_totp_secret",
        "PUBLIC compatibility pending TOTP secret",
    ),
    ("recovery_codes", "[\"PUBLIC Rust recovery hash\"]"),
];
const PUBLIC_SETTINGS: [(&str, &str); 3] = [
    ("gateway_paused", "0"),
    ("selection_strategy", "priority"),
    ("admin_user", "vault1:PUBLIC literal public setting"),
];

fn vault() -> Vault {
    Vault::from_secret(PUBLIC_SEED).unwrap()
}

fn upstream() -> UpstreamUrls {
    UpstreamUrls {
        zai: "http://127.0.0.1:1/unused".into(),
        zai_fallback: "http://127.0.0.1:1/unused".into(),
    }
}

fn load(db: Connection) -> Result<AppState, store::StoreError> {
    AppState::try_from_db_with_vault("PUBLIC root key".into(), upstream(), db, vault())
}

fn seed_setting(db: &Connection, key: &str, value: &str) {
    db.execute(
        "INSERT INTO settings(key, value) VALUES(?1, ?2)",
        [key, value],
    )
    .unwrap();
}

fn seed_account(db: &Connection, id: i64, jwt: &str, api_key: &str) {
    db.execute(
        "INSERT INTO accounts(id, email, zcode_jwt, api_key) VALUES(?1, ?2, ?3, ?4)",
        rusqlite::params![id, format!("public-{id}@example.invalid"), jwt, api_key],
    )
    .unwrap();
}

fn stored_settings(db: &Connection) -> BTreeMap<String, String> {
    let mut stmt = db
        .prepare("SELECT key, value FROM settings ORDER BY key")
        .unwrap();
    let values = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    values
}

fn memory_settings(state: &AppState) -> BTreeMap<String, String> {
    state
        .settings
        .lock()
        .unwrap()
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn rows(db: &Connection, sql: &str) -> Vec<Vec<SqlValue>> {
    let mut stmt = db.prepare(sql).unwrap();
    let width = stmt.column_count();
    let values = stmt
        .query_map([], |row| (0..width).map(|i| row.get(i)).collect())
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    values
}

fn snapshot(db: &Connection) -> Vec<Vec<Vec<SqlValue>>> {
    let mut result = vec![rows(
        db,
        "SELECT type, name, tbl_name, rootpage, sql FROM sqlite_schema ORDER BY name",
    )];
    for table in [
        "accounts",
        "settings",
        "gateway_keys",
        "usage_records",
        "sqlite_sequence",
    ] {
        result.push(rows(db, &format!("SELECT * FROM {table} ORDER BY rowid")));
    }
    result
}

// The observer survives a consuming constructor returning Err, without a disk database.
fn observed_database() -> (Connection, Connection) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let uri = format!(
        "file:PUBLIC-encrypted-reload-{}?mode=memory&cache=shared",
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let db = store::open(&uri);
    let observer = Connection::open_with_flags(
        &uri,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_MEMORY,
    )
    .unwrap();
    (db, observer)
}

fn assert_account(state: &AppState, id: i64, jwt: &str, api_key: &str) {
    let accounts = state.accounts.lock().unwrap();
    let account = accounts.iter().find(|account| account.id == id).unwrap();
    assert_eq!(account.zcode_jwt, jwt);
    assert_eq!(account.api_key, api_key);
    let creds = state.creds.lock().unwrap();
    assert_eq!(creds[&id].zcode_jwt, jwt);
    assert_eq!(creds[&id].api_key, api_key);
}

#[test]
fn secret_setting_union_is_encrypted_and_fresh_state_reloads_plaintext_and_accounts() {
    let db = store::open(":memory:");
    seed_account(
        &db,
        1,
        &vault().encrypt("PUBLIC encrypted JWT").unwrap(),
        &vault().encrypt("PUBLIC encrypted API key").unwrap(),
    );
    seed_account(&db, 2, "PUBLIC legacy JWT", "");
    let state = load(db).unwrap();
    let values: Vec<_> = SECRET_SETTINGS.into_iter().chain(PUBLIC_SETTINGS).collect();
    state.persist_settings(&values).unwrap();
    let before = snapshot(&state.db.lock().unwrap());
    let stored = stored_settings(&state.db.lock().unwrap());
    for (key, plain) in SECRET_SETTINGS {
        assert!(stored[key].starts_with("vault1:"), "{key} is not encrypted");
        assert_ne!(stored[key], plain, "{key} is plaintext at rest");
        assert_eq!(vault().decrypt(&stored[key]).unwrap(), plain, "{key}");
        assert_eq!(state.setting(key).as_deref(), Some(plain), "{key}");
    }
    for (key, plain) in PUBLIC_SETTINGS {
        assert_eq!(stored[key], plain, "public {key} was transformed");
    }
    let reloaded = load(state.db.into_inner().unwrap()).unwrap();
    for (key, plain) in values {
        assert_eq!(reloaded.setting(key).as_deref(), Some(plain), "{key}");
    }
    assert_eq!(reloaded.accounts.lock().unwrap().len(), 2);
    assert_eq!(reloaded.creds.lock().unwrap().len(), 2);
    assert_account(
        &reloaded,
        1,
        "PUBLIC encrypted JWT",
        "PUBLIC encrypted API key",
    );
    assert_account(&reloaded, 2, "PUBLIC legacy JWT", "");
    assert_eq!(snapshot(&reloaded.db.lock().unwrap()), before);
}

#[test]
fn one_bad_account_credential_rejects_the_entire_reload_without_database_mutation() {
    let foreign = Vault::from_secret(FOREIGN_SEED).unwrap();
    for column in ["zcode_jwt", "api_key"] {
        for (kind, invalid) in [
            ("malformed", "vault1:PUBLIC-invalid-envelope".to_owned()),
            (
                "foreign key",
                foreign.encrypt("PUBLIC foreign credential").unwrap(),
            ),
        ] {
            let (db, observer) = observed_database();
            seed_setting(
                &db,
                "totp_secret",
                &vault().encrypt("PUBLIC valid secret").unwrap(),
            );
            seed_account(&db, 1, &vault().encrypt("PUBLIC valid JWT").unwrap(), "");
            seed_account(&db, 2, "PUBLIC legacy JWT", "PUBLIC legacy key");
            db.execute(
                &format!("UPDATE accounts SET {column} = ?1 WHERE id = 2"),
                [&invalid],
            )
            .unwrap();
            let before = snapshot(&observer);
            let result = load(db);
            assert!(
                result.is_err(),
                "{kind} {column} yielded a partial or usable state"
            );
            assert_eq!(
                snapshot(&observer),
                before,
                "{kind} {column} changed the database"
            );
        }
    }
}

#[test]
fn one_bad_secret_setting_rejects_the_entire_reload_without_database_mutation() {
    let foreign = Vault::from_secret(FOREIGN_SEED).unwrap();
    for (key, _) in SECRET_SETTINGS {
        for (kind, invalid) in [
            ("malformed", "vault1:PUBLIC-invalid-envelope".to_owned()),
            (
                "foreign key",
                foreign.encrypt("PUBLIC foreign setting").unwrap(),
            ),
        ] {
            let (db, observer) = observed_database();
            seed_account(&db, 1, &vault().encrypt("PUBLIC valid JWT").unwrap(), "");
            for (secret_key, plain) in SECRET_SETTINGS {
                let value = if secret_key == key {
                    invalid.clone()
                } else {
                    vault().encrypt(plain).unwrap()
                };
                seed_setting(&db, secret_key, &value);
            }
            seed_setting(&db, "gateway_paused", "0");
            let before = snapshot(&observer);
            let result = load(db);
            assert!(
                result.is_err(),
                "{kind} {key} yielded a partial or usable state"
            );
            assert_eq!(
                snapshot(&observer),
                before,
                "{kind} {key} changed the database"
            );
        }
    }
}

#[test]
fn failed_settings_sql_batch_preserves_database_and_live_settings() {
    let db = store::open(":memory:");
    seed_setting(&db, "gateway_paused", "0");
    seed_setting(&db, "totp_secret", "PUBLIC legacy active secret");
    let state = load(db).unwrap();
    state
        .db
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_secret_insert BEFORE INSERT ON settings
         WHEN NEW.key = 'totp_secret'
         BEGIN SELECT RAISE(FAIL, 'PUBLIC injected settings failure'); END;
         CREATE TRIGGER fail_secret_update BEFORE UPDATE ON settings
         WHEN NEW.key = 'totp_secret'
         BEGIN SELECT RAISE(FAIL, 'PUBLIC injected settings failure'); END;",
        )
        .unwrap();
    let before_db = snapshot(&state.db.lock().unwrap());
    let before_memory = memory_settings(&state);
    let result = state.persist_settings(&[
        ("gateway_paused", "1"),
        ("recovery_codes", "PUBLIC new recovery hashes"),
        ("totp_secret", "PUBLIC replacement secret"),
        ("selection_strategy", "priority"),
    ]);
    assert!(
        result.is_err(),
        "SQL trigger failure was reported as success"
    );
    assert_eq!(snapshot(&state.db.lock().unwrap()), before_db);
    assert_eq!(memory_settings(&state), before_memory);
}

#[test]
fn invalid_secret_envelope_aborts_the_whole_settings_batch() {
    let foreign = Vault::from_secret(FOREIGN_SEED).unwrap();
    for (key, _) in SECRET_SETTINGS {
        for (kind, invalid) in [
            ("malformed", "vault1:PUBLIC-invalid-envelope".to_owned()),
            (
                "foreign key",
                foreign.encrypt("PUBLIC foreign setting").unwrap(),
            ),
        ] {
            let db = store::open(":memory:");
            seed_setting(&db, "gateway_paused", "0");
            seed_setting(&db, key, "PUBLIC legacy secret");
            let state = load(db).unwrap();
            let before_db = snapshot(&state.db.lock().unwrap());
            let before_memory = memory_settings(&state);
            let result = state.persist_settings(&[
                ("gateway_paused", "1"),
                (key, &invalid),
                ("selection_strategy", "priority"),
            ]);
            assert!(result.is_err(), "{kind} {key} was accepted");
            assert_eq!(
                snapshot(&state.db.lock().unwrap()),
                before_db,
                "{kind} {key}"
            );
            assert_eq!(memory_settings(&state), before_memory, "{kind} {key}");
        }
    }
}

#[test]
fn authenticated_ciphertext_is_not_double_encrypted_or_published_as_a_live_secret() {
    let state = load(store::open(":memory:")).unwrap();
    let encrypted: Vec<_> = SECRET_SETTINGS
        .iter()
        .map(|(key, plain)| (*key, vault().encrypt(plain).unwrap()))
        .collect();
    let values: Vec<_> = encrypted
        .iter()
        .map(|(key, ciphertext)| (*key, ciphertext.as_str()))
        .collect();
    for _ in 0..2 {
        state.persist_settings(&values).unwrap();
        let stored = stored_settings(&state.db.lock().unwrap());
        for ((key, ciphertext), (_, plain)) in encrypted.iter().zip(SECRET_SETTINGS) {
            assert_eq!(&stored[*key], ciphertext, "{key} envelope was rewritten");
            assert_eq!(vault().decrypt(&stored[*key]).unwrap(), plain, "{key}");
            assert_eq!(state.setting(key).as_deref(), Some(plain), "{key}");
        }
    }
    let reloaded = load(state.db.into_inner().unwrap()).unwrap();
    for (key, plain) in SECRET_SETTINGS {
        assert_eq!(reloaded.setting(key).as_deref(), Some(plain), "{key}");
    }
    reloaded
        .persist_settings(&[("totp_secret_pending", "")])
        .unwrap();
    assert_eq!(reloaded.setting("totp_secret_pending").as_deref(), Some(""));
    assert_eq!(
        stored_settings(&reloaded.db.lock().unwrap())["totp_secret_pending"],
        ""
    );
}
