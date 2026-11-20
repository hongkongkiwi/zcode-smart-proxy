#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use rusqlite::{Connection, OpenFlags};
use zcode_proxy::{store, vault::Vault};

const PUBLIC_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const PUBLIC_ENV_SECRET: &str = "PUBLIC startup environment override";
const CHILD_MARKER: &str = "ZCODE_STARTUP_TEST_CHILD";

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "zcode-vault-startup-{}-{:032x}",
            std::process::id(),
            rand::random::<u128>()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("synthetic.db")
    }

    fn key(&self, bytes: &[u8], mode: u32) -> PathBuf {
        let path = self.0.join("vault.key");
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn log_command(command: &mut Command, path: &Path) -> Process {
    let log = fs::File::create(path).unwrap();
    Process(
        command
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    )
}

// Re-exec only this test so runtime key resolution never observes the caller's environment.
fn isolated(test: &str, secret: Option<&str>) -> bool {
    if std::env::var_os(CHILD_MARKER).is_some() {
        return false;
    }
    let dir = Directory::new();
    let log = dir.0.join("child.log");
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .env_clear()
        .env(CHILD_MARKER, "1")
        .current_dir(&dir.0)
        .args(["--exact", test, "--nocapture"]);
    if let Some(secret) = secret {
        command.env("ZCODE_PROXY_VAULT_SECRET", secret);
    }
    let mut child = log_command(&mut command, &log);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            let output = fs::read_to_string(&log).unwrap();
            assert!(status.success(), "isolated {test} failed: {output}");
            assert!(
                output.contains("test result: ok. 1 passed"),
                "isolated {test} did not execute exactly one test: {output}"
            );
            return true;
        }
        assert!(Instant::now() < deadline, "isolated {test} timed out");
        thread::sleep(Duration::from_millis(20));
    }
}

fn entries(dir: &Directory) -> Vec<std::ffi::OsString> {
    let mut entries: Vec<_> = fs::read_dir(&dir.0)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    entries.sort();
    entries
}

#[test]
fn fresh_key_is_private_hex_and_reused_byte_for_byte() {
    if isolated("fresh_key_is_private_hex_and_reused_byte_for_byte", None) {
        return;
    }
    let dir = Directory::new();
    let path = dir.database();
    let vault = Vault::for_database(path.to_str().unwrap()).unwrap();
    assert!(!path.exists(), "key resolution created the database");
    let key = dir.0.join("vault.key");
    let before = fs::read(&key).unwrap();
    let raw = std::str::from_utf8(&before).unwrap();
    let seed = raw.trim();
    assert_eq!(seed.len(), 64);
    assert!(seed.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(
        fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let ciphertext = vault.encrypt("PUBLIC restart credential").unwrap();
    assert_eq!(
        Vault::from_secret(seed)
            .unwrap()
            .decrypt(&ciphertext)
            .unwrap(),
        "PUBLIC restart credential"
    );
    drop(store::try_open(path.to_str().unwrap()).unwrap());
    let reopened = Vault::for_database(path.to_str().unwrap()).unwrap();
    assert_eq!(
        reopened.decrypt(&ciphertext).unwrap(),
        "PUBLIC restart credential"
    );
    assert_eq!(fs::read(&key).unwrap(), before);
}

#[test]
fn invalid_or_overly_permissive_key_is_refused_without_replacement() {
    if isolated(
        "invalid_or_overly_permissive_key_is_refused_without_replacement",
        None,
    ) {
        return;
    }
    for (raw, mode) in [
        (String::new(), 0o600),
        ("a".repeat(63), 0o600),
        ("a".repeat(65), 0o600),
        ("g".repeat(64), 0o600),
        (PUBLIC_SEED.to_owned(), 0o640),
        (PUBLIC_SEED.to_owned(), 0o644),
    ] {
        let dir = Directory::new();
        let path = dir.database();
        let key = dir.key(raw.as_bytes(), mode);
        assert!(matches!(
            Vault::for_database(path.to_str().unwrap()),
            Err(store::StoreError::Vault)
        ));
        assert_eq!(fs::read(&key).unwrap(), raw.as_bytes());
        assert_eq!(
            fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            mode
        );
        assert!(!path.exists(), "refused key created a database");
        assert_eq!(entries(&dir), vec![std::ffi::OsString::from("vault.key")]);
    }
}

#[test]
fn missing_key_with_ciphertext_is_refused_but_plaintext_can_initialize() {
    if isolated(
        "missing_key_with_ciphertext_is_refused_but_plaintext_can_initialize",
        None,
    ) {
        return;
    }
    let ciphertext = Vault::from_secret(PUBLIC_SEED)
        .unwrap()
        .encrypt("PUBLIC stored credential")
        .unwrap();
    for location in ["zcode_jwt", "api_key", "settings", "plaintext"] {
        let dir = Directory::new();
        let path = dir.database();
        let db = store::try_open(path.to_str().unwrap()).unwrap();
        if location == "settings" {
            db.execute(
                "INSERT INTO settings(key, value) VALUES('totp_secret', ?1)",
                [&ciphertext],
            )
            .unwrap();
        } else {
            let column = if location == "plaintext" {
                "zcode_jwt"
            } else {
                location
            };
            let value = if location == "plaintext" {
                "PUBLIC legacy JWT"
            } else {
                &ciphertext
            };
            db.execute(
                &format!("INSERT INTO accounts({column}) VALUES(?1)"),
                [value],
            )
            .unwrap();
        }
        drop(db);
        let before = fs::read(&path).unwrap();
        let result = Vault::for_database(path.to_str().unwrap());
        if location == "plaintext" {
            assert!(
                result.is_ok(),
                "plaintext-only database could not initialize a key"
            );
            assert!(dir.0.join("vault.key").exists());
        } else {
            assert!(
                matches!(result, Err(store::StoreError::Vault)),
                "{location}"
            );
            assert!(
                !dir.0.join("vault.key").exists(),
                "{location} generated a new key"
            );
        }
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "{location} changed SQLite"
        );
    }
}

#[test]
fn go_schema_is_refused_without_database_or_key_mutation() {
    if isolated(
        "go_schema_is_refused_without_database_or_key_mutation",
        None,
    ) {
        return;
    }
    for schema in [
        include_str!("fixtures/go_schema.sql"),
        "CREATE TABLE accounts(user_id TEXT);",
        "CREATE TABLE settings(key TEXT, value TEXT, updated_at TEXT);",
    ] {
        for existing_key in [false, true] {
            let dir = Directory::new();
            let path = dir.database();
            let db = Connection::open(&path).unwrap();
            db.execute_batch(schema).unwrap();
            drop(db);
            let key = existing_key.then(|| dir.key(PUBLIC_SEED.as_bytes(), 0o600));
            let before_db = fs::read(&path).unwrap();
            let before_entries = entries(&dir);
            let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
            assert!(matches!(
                store::check_schema(&db),
                Err(store::StoreError::UnsupportedSchema)
            ));
            drop(db);
            assert!(matches!(
                store::try_open(path.to_str().unwrap()),
                Err(store::StoreError::UnsupportedSchema)
            ));
            assert!(matches!(
                Vault::for_database(path.to_str().unwrap()),
                Err(store::StoreError::UnsupportedSchema)
            ));
            assert_eq!(fs::read(&path).unwrap(), before_db);
            assert_eq!(entries(&dir), before_entries);
            if let Some(key) = key {
                assert_eq!(fs::read(&key).unwrap(), PUBLIC_SEED.as_bytes());
                assert_eq!(
                    fs::metadata(&key).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }
}

#[test]
fn explicit_environment_secret_wins_and_empty_override_fails_closed() {
    let test = "explicit_environment_secret_wins_and_empty_override_fails_closed";
    if isolated(test, Some(PUBLIC_ENV_SECRET)) {
        assert!(isolated(test, Some("")));
        return;
    }
    let secret = std::env::var("ZCODE_PROXY_VAULT_SECRET").unwrap();
    for existing_key in [false, true] {
        let dir = Directory::new();
        let path = dir.database();
        let key_bytes = if secret.is_empty() {
            PUBLIC_SEED.as_bytes()
        } else {
            b"PUBLIC invalid file seed"
        };
        let mode = if secret.is_empty() { 0o600 } else { 0o644 };
        let key = existing_key.then(|| dir.key(key_bytes, mode));
        let result = Vault::for_database(path.to_str().unwrap());
        if secret.is_empty() {
            assert!(
                matches!(result, Err(store::StoreError::Vault)),
                "empty override fell back to a keyfile or generated a key"
            );
        } else {
            let ciphertext = Vault::from_secret(PUBLIC_ENV_SECRET)
                .unwrap()
                .encrypt("PUBLIC environment-selected credential")
                .unwrap();
            assert_eq!(
                result.unwrap().decrypt(&ciphertext).unwrap(),
                "PUBLIC environment-selected credential"
            );
        }
        assert!(!path.exists());
        if let Some(key) = key {
            assert_eq!(fs::read(&key).unwrap(), key_bytes);
            assert_eq!(
                fs::metadata(&key).unwrap().permissions().mode() & 0o777,
                mode
            );
        } else {
            assert!(
                entries(&dir).is_empty(),
                "environment resolution generated a keyfile"
            );
        }
    }
}

#[test]
fn binary_bootstrap_does_not_overwrite_stored_password() {
    let dir = Directory::new();
    let path = dir.database();
    let key = dir.key(PUBLIC_SEED.as_bytes(), 0o600);
    let vault = Vault::from_secret(PUBLIC_SEED).unwrap();
    let hash = bcrypt::hash("PUBLIC rotated password", 4).unwrap();
    let mut db = store::try_open(path.to_str().unwrap()).unwrap();
    store::persist_settings(&mut db, &vault, &[("admin_password_hash", &hash)]).unwrap();
    let before = store::get_setting(&db, "admin_password_hash").unwrap();
    drop(db);

    let log = dir.0.join("server.log");
    let mut command = Command::new(env!("CARGO_BIN_EXE_zcode-proxy-rs"));
    command
        .env_clear()
        .current_dir(&dir.0)
        .env("TOKIO_WORKER_THREADS", "2")
        .env("ZCODE_RS_DB", &path)
        .env("ZCODE_RS_BIND", "127.0.0.1:0")
        .env(
            "ZCODE_RS_ADMIN_PASSWORD",
            "PUBLIC obsolete bootstrap password",
        )
        .env("ZCODE_RS_UPSTREAM_ZAI", "http://127.0.0.1:1/unused")
        .env("ZCODE_RS_UPSTREAM_FALLBACK", "http://127.0.0.1:1/unused");
    let mut server = log_command(&mut command, &log);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let output = fs::read_to_string(&log).unwrap();
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "server exited before readiness: {output}"
        );
        if output.contains("zcode-proxy-rs listening on 127.0.0.1:0") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "server startup timed out: {output}"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let after = store::get_setting(&db, "admin_password_hash").unwrap();
    assert_eq!(
        after, before,
        "bootstrap replaced the stored password envelope"
    );
    let loaded_hash = vault.decrypt(&after).unwrap();
    assert!(bcrypt::verify("PUBLIC rotated password", &loaded_hash).unwrap());
    assert!(!bcrypt::verify("PUBLIC obsolete bootstrap password", &loaded_hash).unwrap());
    assert_eq!(fs::read(&key).unwrap(), PUBLIC_SEED.as_bytes());
}
