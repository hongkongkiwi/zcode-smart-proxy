use std::{fs, path::PathBuf};

use rusqlite::{types::Value as SqlValue, Connection};
use serde_json::Value;
use zcode_proxy::{go_compat, vault::Vault};

// Public test seed from the Go-produced vault_interop.json, not a real keyfile.
const PUBLIC_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const CREDENTIALS: [(&str, &str); 6] = [
    ("access_token", "PUBLIC access token"),
    ("refresh_token", "PUBLIC refresh token"),
    ("zcode_jwt", "PUBLIC jwt"),
    ("api_key", "PUBLIC api key"),
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

fn database() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(include_str!("fixtures/go_schema.sql"))
        .unwrap();
    conn
}

fn encrypted_database(vault: &Vault) -> Connection {
    let conn = database();
    for (column, plain) in CREDENTIALS {
        let ciphertext = vault.encrypt(plain).unwrap();
        conn.execute(
            &format!("UPDATE accounts SET {column} = ?1 WHERE id = 101"),
            [&ciphertext],
        )
        .unwrap();
    }
    conn
}

fn rows(conn: &Connection, sql: &str) -> Vec<Vec<SqlValue>> {
    let mut stmt = conn.prepare(sql).unwrap();
    let width = stmt.column_count();
    let result = stmt
        .query_map([], |row| (0..width).map(|i| row.get(i)).collect())
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    result
}

fn snapshot(conn: &Connection) -> Vec<Vec<Vec<SqlValue>>> {
    let mut result = vec![rows(
        conn,
        "SELECT type, name, tbl_name, rootpage, sql FROM sqlite_schema ORDER BY name",
    )];
    for table in [
        "accounts",
        "settings",
        "claim_plans",
        "claim_records",
        "usage_records",
        "proxy_nodes",
        "plan_run_records",
        "gateway_keys",
        "sqlite_sequence",
    ] {
        result.push(rows(conn, &format!("SELECT * FROM {table} ORDER BY rowid")));
    }
    result
}

struct KeyDirectory(PathBuf);

impl KeyDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "zcode-go-storage-tests-{}-{:032x}",
            std::process::id(),
            rand::random::<u128>()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn as_str(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for KeyDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn go_accounts_retain_paid_fallback_and_all_decrypted_credentials() {
    let vault = Vault::from_secret(PUBLIC_SEED).unwrap();
    let conn = encrypted_database(&vault);
    let accounts = go_compat::load_go_accounts(&conn, &vault).unwrap();
    assert_eq!(accounts.len(), 2);
    let a = accounts.iter().find(|a| a.view.id == 101).unwrap();
    assert_eq!(a.user_id, "PUBLIC-user-a");
    assert_eq!(a.view.email, "a@example.invalid");
    assert_eq!(a.view.provider, "zai");
    assert!(a.view.enabled);
    assert!(
        a.view.paid_fallback,
        "Go's default-on paid fallback was lost"
    );
    assert_eq!(a.view.status, "cooling");
    assert_eq!(a.view.cooling_until, 2_000_000_000);
    assert_eq!(a.view.paid_cooling_until, 2_000_000_100);
    assert_eq!(a.view.account_group, "one,two");
    assert_eq!(a.view.remaining, 12.5);
    assert_eq!(a.view.priority, 50);
    for (actual, (_, expected)) in [
        a.access_token.as_str(),
        a.refresh_token.as_str(),
        a.view.zcode_jwt.as_str(),
        a.view.api_key.as_str(),
        a.user_info.as_str(),
        a.creds_raw.as_str(),
    ]
    .into_iter()
    .zip(CREDENTIALS)
    {
        assert_eq!(actual, expected);
    }
    let b = accounts.iter().find(|a| a.view.id == 102).unwrap();
    assert_eq!(b.user_id, "PUBLIC-user-b");
    assert!(!b.view.enabled);
    assert!(!b.view.paid_fallback);
    assert_eq!(b.view.provider, "bigmodel");
    assert_eq!(b.view.status, "disabled");
    assert_eq!(b.view.priority, 100);
    assert_eq!(b.access_token, "PUBLIC legacy access");
    assert_eq!(b.view.zcode_jwt, "PUBLIC legacy jwt");
    assert_eq!(b.view.api_key, "PUBLIC legacy api key");
    assert_eq!(b.user_info, "{}");
    assert_eq!(b.refresh_token, "");
    assert_eq!(b.creds_raw, "");
}

#[test]
fn go_produced_ciphertext_loads_with_hex_secret_string_key() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/vault_interop.json")).unwrap();
    let case = fixture["decrypt_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "hex_secret_utf8")
        .unwrap();
    assert_eq!(fixture["public_secrets"]["public_hex_secret"], PUBLIC_SEED);
    let dir = KeyDirectory::new();
    fs::write(dir.0.join("vault.key"), format!(" \n{PUBLIC_SEED}\r\n")).unwrap();
    let seed = go_compat::load_vault_key(dir.as_str()).unwrap();
    assert_eq!(seed, PUBLIC_SEED);
    let vault = Vault::from_secret(&seed).unwrap();
    let conn = database();
    conn.execute(
        "UPDATE accounts SET zcode_jwt = ?1 WHERE id = 101",
        [case["value"].as_str().unwrap()],
    )
    .unwrap();
    let accounts = go_compat::load_go_accounts(&conn, &vault).unwrap();
    let a = accounts.iter().find(|a| a.view.id == 101).unwrap();
    assert_eq!(a.view.zcode_jwt, case["plaintext"].as_str().unwrap());
}

#[test]
fn account_loading_is_read_only_for_schema_and_stored_ciphertext() {
    let vault = Vault::from_secret(PUBLIC_SEED).unwrap();
    let conn = encrypted_database(&vault);
    let before = snapshot(&conn);
    let schema_version: i64 = conn
        .query_row("PRAGMA schema_version", [], |r| r.get(0))
        .unwrap();
    conn.execute_batch("PRAGMA query_only = ON").unwrap();
    let accounts = go_compat::load_go_accounts(&conn, &vault).unwrap();
    assert_eq!(
        accounts.len(),
        2,
        "loading must work on a read-only Go database"
    );
    assert_eq!(
        snapshot(&conn),
        before,
        "loading changed schema or stored data"
    );
    let after_version: i64 = conn
        .query_row("PRAGMA schema_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(after_version, schema_version);
}

#[test]
fn account_loading_rejects_every_broken_credential_without_mutation() {
    let vault = Vault::from_secret(PUBLIC_SEED).unwrap();
    let wrong = Vault::from_secret("PUBLIC deliberately wrong key").unwrap();
    let mut violations = Vec::new();
    for (column, _) in CREDENTIALS {
        for (kind, ciphertext) in [
            ("malformed", "vault1:PUBLIC-invalid-envelope".to_owned()),
            (
                "wrong key",
                wrong.encrypt("PUBLIC foreign credential").unwrap(),
            ),
        ] {
            let conn = encrypted_database(&vault);
            conn.execute(
                &format!("UPDATE accounts SET {column} = ?1 WHERE id = 102"),
                [&ciphertext],
            )
            .unwrap();
            let before = snapshot(&conn);
            if go_compat::load_go_accounts(&conn, &vault).is_ok() {
                violations.push(format!("{column}: {kind} was accepted"));
            }
            assert_eq!(snapshot(&conn), before, "{column}: {kind} changed data");
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("; "));
}

#[test]
fn schema_and_row_errors_are_not_successful_empty_or_partial_account_lists() {
    let vault = Vault::from_secret(PUBLIC_SEED).unwrap();
    let empty = database();
    empty.execute("DELETE FROM accounts", []).unwrap();
    assert!(go_compat::load_go_accounts(&empty, &vault)
        .unwrap()
        .is_empty());

    let missing = Connection::open_in_memory().unwrap();
    assert!(
        go_compat::load_go_accounts(&missing, &vault).is_err(),
        "missing accounts table must not look like an empty account list"
    );
    let conn = database();
    conn.execute(
        "UPDATE accounts SET priority = 'PUBLIC-not-an-integer' WHERE id = 102",
        [],
    )
    .unwrap();
    assert!(
        go_compat::load_go_accounts(&conn, &vault).is_err(),
        "one unreadable row must not silently disappear"
    );
}

#[test]
fn null_account_fields_fail_like_go_scan_without_mutation() {
    let vault = Vault::from_secret(PUBLIC_SEED).unwrap();
    let mut accepted = Vec::new();
    // Go scanAccount scans these directly into typed values, not sql.Null*.
    for column in [
        "email",
        "provider",
        "enabled",
        "status",
        "cooling_until",
        "account_group",
        "remaining",
        "access_token",
        "refresh_token",
        "zcode_jwt",
        "api_key",
        "user_info",
        "creds_raw",
    ] {
        let conn = database();
        conn.execute(
            &format!("UPDATE accounts SET {column} = NULL WHERE id = 102"),
            [],
        )
        .unwrap();
        let before = snapshot(&conn);
        if go_compat::load_go_accounts(&conn, &vault).is_ok() {
            accepted.push(column);
        }
        assert_eq!(snapshot(&conn), before, "NULL {column} changed stored data");
    }
    assert!(
        accepted.is_empty(),
        "NULL fields silently normalized: {accepted:?}"
    );
}

#[test]
fn vault_keyfile_requires_64_hex_characters_and_never_creates_or_replaces_files() {
    let dir = KeyDirectory::new();
    let path = dir.0.join("vault.key");
    assert!(go_compat::load_vault_key(dir.as_str()).is_err());
    assert!(
        !path.exists(),
        "read-only key loading generated a replacement key"
    );
    let mut violations = Vec::new();
    for invalid in [
        String::new(),
        " \n\r\t".to_owned(),
        "a".repeat(63),
        "a".repeat(65),
        "g".repeat(64),
        format!("{} {}", "a".repeat(31), "b".repeat(32)),
    ] {
        fs::write(&path, &invalid).unwrap();
        if go_compat::load_vault_key(dir.as_str()).is_ok() {
            violations.push(format!(
                "invalid keyfile of {} bytes accepted",
                invalid.len()
            ));
        }
        assert_eq!(fs::read(&path).unwrap(), invalid.as_bytes());
    }
    assert!(violations.is_empty(), "{}", violations.join("; "));

    let uppercase = PUBLIC_SEED.to_uppercase();
    for seed in [PUBLIC_SEED, uppercase.as_str()] {
        let raw = format!("\u{2003} \n{seed}\r\n\t");
        fs::write(&path, &raw).unwrap();
        assert_eq!(go_compat::load_vault_key(dir.as_str()).unwrap(), seed);
        assert_eq!(fs::read(&path).unwrap(), raw.as_bytes());
    }
}

#[test]
fn credential_wrappers_preserve_plaintext_and_authenticated_ciphertext() {
    let vault = Vault::from_secret(PUBLIC_SEED).unwrap();
    for plain in [
        "",
        "PUBLIC legacy credential",
        "vault1",
        "vault2:PUBLIC legacy",
    ] {
        assert_eq!(go_compat::decrypt_credential(&vault, plain).unwrap(), plain);
    }
    assert_eq!(go_compat::encrypt_credential(&vault, "").unwrap(), "");
    let ciphertext = go_compat::encrypt_credential(&vault, "PUBLIC credential").unwrap();
    assert!(ciphertext.starts_with("vault1:"));
    assert_eq!(vault.decrypt(&ciphertext).unwrap(), "PUBLIC credential");
    assert_eq!(
        go_compat::encrypt_credential(&vault, &ciphertext).unwrap(),
        ciphertext
    );
}

#[test]
fn credential_and_setting_wrappers_propagate_vault_errors() {
    let vault = Vault::from_secret(PUBLIC_SEED).unwrap();
    let wrong = Vault::from_secret("PUBLIC deliberately wrong key").unwrap();
    let mut violations = Vec::new();
    for stored in [
        "vault1:PUBLIC-invalid-envelope".to_owned(),
        wrong.encrypt("PUBLIC foreign credential").unwrap(),
    ] {
        for (operation, result) in [
            (
                "decrypt credential",
                go_compat::decrypt_credential(&vault, &stored),
            ),
            (
                "encrypt credential",
                go_compat::encrypt_credential(&vault, &stored),
            ),
        ] {
            if result.is_ok() {
                violations.push(operation.to_owned());
            }
        }
        for key in SECRET_SETTINGS {
            for (operation, result) in [
                ("decrypt", go_compat::decrypt_setting(&vault, key, &stored)),
                ("encrypt", go_compat::encrypt_setting(&vault, key, &stored)),
            ] {
                if result.is_ok() {
                    violations.push(format!("{operation} setting {key}"));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "errors swallowed: {}",
        violations.join("; ")
    );
}

#[test]
fn setting_wrappers_encrypt_only_go_secret_settings() {
    let vault = Vault::from_secret(PUBLIC_SEED).unwrap();
    for key in SECRET_SETTINGS {
        assert!(go_compat::is_encrypted_setting(key));
        for plain in ["", "PUBLIC setting 凭证"] {
            assert_eq!(
                go_compat::decrypt_setting(&vault, key, plain).unwrap(),
                plain
            );
            let stored = go_compat::encrypt_setting(&vault, key, plain).unwrap();
            if plain.is_empty() {
                assert_eq!(stored, "");
            } else {
                assert!(stored.starts_with("vault1:"), "{key}");
            }
            assert_eq!(
                go_compat::decrypt_setting(&vault, key, &stored).unwrap(),
                plain
            );
            assert_eq!(
                go_compat::encrypt_setting(&vault, key, &stored).unwrap(),
                stored
            );
        }
    }
    for key in ["selection_strategy", "PUBLIC-unknown-setting"] {
        assert!(!go_compat::is_encrypted_setting(key));
        let plain = "vault1:PUBLIC-not-an-envelope";
        assert_eq!(
            go_compat::decrypt_setting(&vault, key, plain).unwrap(),
            plain
        );
        assert_eq!(
            go_compat::encrypt_setting(&vault, key, plain).unwrap(),
            plain
        );
    }
}
