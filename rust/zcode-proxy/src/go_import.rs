//! Explicit offline Go import. History and unknown schema remain in the archive;
//! only the current Rust runtime surface is projected. The Go service must be stopped.
//! Forced termination can leave a private `.zcode-import-*` sibling directory.
//! Inspect it and confirm no import is running before manually removing it.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use rusqlite::{
    backup::{Backup, StepResult},
    params, Connection, OpenFlags, OptionalExtension,
};
use zeroize::Zeroizing;

use crate::{store, vault::Vault};

#[derive(Debug)]
pub struct ImportError;

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("offline database import failed; destination was not published")
    }
}
impl std::error::Error for ImportError {}
impl From<std::io::Error> for ImportError {
    fn from(_: std::io::Error) -> Self {
        Self
    }
}
impl From<rusqlite::Error> for ImportError {
    fn from(_: rusqlite::Error) -> Self {
        Self
    }
}
impl From<store::StoreError> for ImportError {
    fn from(_: store::StoreError) -> Self {
        Self
    }
}
impl From<crate::vault::VaultError> for ImportError {
    fn from(_: crate::vault::VaultError) -> Self {
        Self
    }
}

#[derive(Debug, serde::Serialize)]
pub struct ImportReport {
    pub complete: bool,
    pub archive: &'static str,
    pub runtime: &'static str,
    pub history_projection: &'static str,
}

/// Import without opening SQLite against the original files.
///
/// The caller must stop the Go service and every other writer for the entire
/// import. File identity checks detect some changes, not a consistent live copy.
/// `secret` is the Go vault secret, not a command-line argument. A new runtime
/// seed is generated when that secret is not itself a 64-character hex seed.
pub fn import_database(
    source: &Path,
    destinationdir: &Path,
    secret: &str,
) -> Result<ImportReport, ImportError> {
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (source, destinationdir, secret);
        return Err(ImportError);
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        absent(destinationdir)?;
        let parent = destinationdir
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if destinationdir.file_name().is_none() {
            return Err(ImportError);
        }
        let vault = Vault::from_secret(secret)?;
        let staging = Staging::create(parent)?;
        let snapshot_dir = staging.path.join("snapshot");
        private_dir(&snapshot_dir)?;
        let snapshot = snapshot_dir.join("source.sqlite");
        let original_state = source_state(source)?;
        copy_private(source, &snapshot)?;
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut original = source.as_os_str().to_owned();
            original.push(suffix);
            let mut copied = snapshot.as_os_str().to_owned();
            copied.push(suffix);
            match fs::symlink_metadata(&original) {
                Ok(_) => copy_private(Path::new(&original), Path::new(&copied))?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(_) => return Err(ImportError),
            }
        }
        if original_state != source_state(source)? {
            return Err(ImportError);
        }
        // Recovery and WAL handling occur only on our private disposable copy.
        let source_db = Connection::open_with_flags(&snapshot, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        source_db.pragma_update(None, "trusted_schema", false)?;
        let archive_path = staging.path.join("go-source.sqlite");
        private_file(&archive_path)?;
        let mut archive = Connection::open(&archive_path)?;
        {
            let backup = Backup::new(&source_db, &mut archive)?;
            if !matches!(backup.step(-1)?, StepResult::Done) {
                return Err(ImportError);
            }
        }
        drop(source_db);
        archive.pragma_update(None, "trusted_schema", false)?;
        integrity(&archive)?;
        validate_go_schema(&archive)?;
        validate_credentials(&archive, &vault)?;
        let seed = Zeroizing::new(
            if secret.len() == 64 && secret.bytes().all(|b| b.is_ascii_hexdigit()) {
                secret.to_owned()
            } else {
                use rand::RngCore;
                let mut bytes = Zeroizing::new([0u8; 32]);
                rand::rngs::OsRng
                    .try_fill_bytes(bytes.as_mut())
                    .map_err(|_| ImportError)?;
                bytes.iter().map(|b| format!("{b:02x}")).collect()
            },
        );
        let runtime_vault = Vault::from_secret(&seed)?;
        let runtime_path = staging.path.join("zcode-rs.db");
        private_file(&runtime_path)?;
        let mut runtime = store::try_open(runtime_path.to_str().ok_or(ImportError)?)?;
        project(&archive, &mut runtime, &vault, &runtime_vault)?;
        integrity(&runtime)?;
        store::load_accounts(&runtime, &runtime_vault)?;
        store::load_settings(&runtime, &runtime_vault)?;
        // A standalone database is published, with no runtime WAL dependency.
        runtime.pragma_update(None, "journal_mode", "DELETE")?;
        runtime.close().map_err(|_| ImportError)?;
        archive.close().map_err(|_| ImportError)?;
        fs::remove_dir_all(&snapshot_dir)?;
        let mut key = private_file(&staging.path.join("vault.key"))?;
        key.write_all(seed.as_bytes())?;
        key.write_all(b"\n")?;
        key.sync_all()?;
        let report = ImportReport {
            complete: true,
            archive: "go-source.sqlite",
            runtime: "zcode-rs.db",
            history_projection: "deferred",
        };
        let mut manifest = private_file(&staging.path.join("import-manifest.json"))?;
        serde_json::to_writer(&mut manifest, &report).map_err(|_| ImportError)?;
        manifest.write_all(b"\n")?;
        manifest.sync_all()?;
        for entry in fs::read_dir(&staging.path)? {
            let path = entry?.path();
            fs::set_permissions(&path, private_permissions())?;
            File::open(path)?.sync_all()?;
        }
        File::open(&staging.path)?.sync_all()?;
        if original_state != source_state(source)? {
            return Err(ImportError);
        }
        absent(destinationdir)?;
        publish(&staging.path, destinationdir)?;
        // Rename is the commit point. Do not report a rollback after publication.
        let _ = File::open(parent).and_then(|dir| dir.sync_all());
        Ok(report)
    }
}

fn integrity(db: &Connection) -> Result<(), ImportError> {
    let mut stmt = db.prepare("PRAGMA integrity_check")?;
    let results = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if results != ["ok"] {
        return Err(ImportError);
    }
    Ok(())
}

fn validate_go_schema(db: &Connection) -> Result<(), ImportError> {
    for (table, columns) in [
        ("accounts", "id,user_id,email,display_name,provider,auth_type,enabled,status,cooling_until,paid_cooling_until,paid_fallback,zcode_jwt,api_key,account_group,remaining,priority,access_token,refresh_token,user_info,device_mid,creds_raw,remark"),
        ("settings", "key,value,updated_at"),
        ("gateway_keys", "id,name,key_hash,enabled,models,rpm_limit,rate_5h,rate_1d,rate_7d,quota_total,quota_used"),
        ("proxy_nodes", "password"),
    ] {
        let kind: String = db.query_row("SELECT type FROM sqlite_schema WHERE name=?1", [table], |r| r.get(0))?;
        if kind != "table" { return Err(ImportError); }
        let mut stmt = db.prepare(&format!("PRAGMA table_info({table})"))?;
        let names = stmt.query_map([], |r| r.get::<_, String>(1))?.collect::<rusqlite::Result<Vec<_>>>()?;
        if columns.split(',').any(|c| !names.iter().any(|n| n == c)) { return Err(ImportError); }
    }
    Ok(())
}

fn validate_credentials(db: &Connection, vault: &Vault) -> Result<(), ImportError> {
    let mut stmt = db.prepare(
        "SELECT access_token,refresh_token,zcode_jwt,api_key,user_info,creds_raw FROM accounts",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        for i in 0..6 {
            let _plain = Zeroizing::new(vault.decrypt(&row.get::<_, String>(i)?)?);
        }
    }
    let mut stmt = db.prepare("SELECT password FROM proxy_nodes")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let _plain = Zeroizing::new(vault.decrypt(&row.get::<_, String>(0)?)?);
    }
    // load_settings validates Go's seven secret keys and the Rust aliases.
    store::load_settings(db, vault)?;
    Ok(())
}

fn project(
    source: &Connection,
    runtime: &mut Connection,
    source_vault: &Vault,
    runtime_vault: &Vault,
) -> Result<(), ImportError> {
    let tx = runtime.transaction()?;
    let mut stmt = source.prepare("SELECT id,email,provider,enabled,status,cooling_until,paid_cooling_until,paid_fallback,zcode_jwt,api_key,account_group,remaining,priority,user_id,display_name,auth_type,access_token,refresh_token,user_info,device_mid,creds_raw,remark FROM accounts")?;
    let mut rows = stmt.query([])?;
    while let Some(r) = rows.next()? {
        let jwt = Zeroizing::new(source_vault.decrypt(&r.get::<_, String>(8)?)?);
        let key = Zeroizing::new(source_vault.decrypt(&r.get::<_, String>(9)?)?);
        let access = Zeroizing::new(source_vault.decrypt(&r.get::<_, String>(16)?)?);
        let refresh = Zeroizing::new(source_vault.decrypt(&r.get::<_, String>(17)?)?);
        let user_info = Zeroizing::new(source_vault.decrypt(&r.get::<_, String>(18)?)?);
        let creds_raw = Zeroizing::new(source_vault.decrypt(&r.get::<_, String>(20)?)?);
        let remaining: f64 = r.get(11)?;
        if !remaining.is_finite() {
            return Err(ImportError);
        }
        tx.execute("INSERT INTO accounts(id,email,provider,enabled,status,cooling_until,paid_cooling_until,paid_fallback,zcode_jwt,api_key,account_group,remaining,priority,user_id,display_name,auth_type,access_token,refresh_token,user_info,device_mid,creds_raw,remark) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22)", params![
            r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, boolean(r,3)?, r.get::<_, String>(4)?, r.get::<_, i64>(5)?, r.get::<_, i64>(6)?, boolean(r,7)?, runtime_vault.encrypt(&jwt)?, runtime_vault.encrypt(&key)?, r.get::<_, String>(10)?, remaining, r.get::<_, i64>(12)?, r.get::<_, String>(13)?, r.get::<_, String>(14)?, r.get::<_, String>(15)?, runtime_vault.encrypt(&access)?, runtime_vault.encrypt(&refresh)?, runtime_vault.encrypt(&user_info)?, r.get::<_, String>(19)?, runtime_vault.encrypt(&creds_raw)?, r.get::<_, String>(21)?
        ])?;
    }
    let mut stmt = source.prepare("SELECT id,name,key_hash,enabled,models,rpm_limit,rate_5h,rate_1d,rate_7d,quota_total,quota_used FROM gateway_keys")?;
    let mut rows = stmt.query([])?;
    while let Some(r) = rows.next()? {
        tx.execute("INSERT INTO gateway_keys(id,name,key_hash,enabled,models,rpm_limit,rate_5h,rate_1d,rate_7d,quota_total,quota_used) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)", params![
            r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, boolean(r,3)?, r.get::<_, String>(4)?, r.get::<_, i64>(5)?, r.get::<_, i64>(6)?, r.get::<_, i64>(7)?, r.get::<_, i64>(8)?, r.get::<_, i64>(9)?, r.get::<_, i64>(10)?
        ])?;
    }
    let settings = store::load_settings(source, source_vault)?;
    let mut settings: BTreeMap<_, _> = settings.into_iter().collect();
    for (go, rust) in [
        ("password_hash", "admin_password_hash"),
        ("admin_user", "admin_username"),
        ("totp_recovery", "recovery_codes"),
    ] {
        if let Some(value) = settings.get(go).cloned() {
            if settings.get(rust).is_some_and(|other| other != &value) {
                return Err(ImportError);
            }
            settings.insert(rust.to_owned(), value);
        }
    }
    for (key, value) in &settings {
        let value = if store::sensitive_setting(key) {
            runtime_vault.encrypt(value)?
        } else {
            value.clone()
        };
        tx.execute(
            "INSERT INTO settings(key,value) VALUES(?1,?2)",
            [key, &value],
        )?;
    }
    // Deleted IDs must not be reused, including history IDs whose projection is deferred.
    for table in ["accounts", "gateway_keys", "usage_records"] {
        let seq: Option<i64> = source
            .query_row(
                "SELECT seq FROM sqlite_sequence WHERE name=?1",
                [table],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(seq) = seq {
            let current: Option<i64> = tx
                .query_row(
                    "SELECT seq FROM sqlite_sequence WHERE name=?1",
                    [table],
                    |r| r.get(0),
                )
                .optional()?;
            if seq < 0 {
                return Err(ImportError);
            }
            match current {
                Some(current) if current > seq => return Err(ImportError),
                Some(_) => {
                    tx.execute(
                        "UPDATE sqlite_sequence SET seq=?1 WHERE name=?2",
                        params![seq, table],
                    )?;
                }
                None => {
                    tx.execute(
                        "INSERT INTO sqlite_sequence(name,seq) VALUES(?1,?2)",
                        params![table, seq],
                    )?;
                }
            }
        }
    }
    tx.commit()?;
    Ok(())
}

fn boolean(row: &rusqlite::Row<'_>, column: usize) -> Result<i64, ImportError> {
    let value: i64 = row.get(column)?;
    if value != 0 && value != 1 {
        return Err(ImportError);
    }
    Ok(value)
}

fn absent(path: &Path) -> Result<(), ImportError> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(ImportError),
    }
}

#[cfg(unix)]
fn private_permissions() -> fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    fs::Permissions::from_mode(0o600)
}
#[cfg(not(unix))]
fn private_permissions() -> fs::Permissions {
    unreachable!()
}

fn private_file(path: &Path) -> Result<File, ImportError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn private_dir(path: &Path) -> Result<(), ImportError> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    Ok(builder.create(path)?)
}

#[cfg(unix)]
type FileIdentity = (u64, u64, u64, i64, i64);

#[cfg(unix)]
fn source_state(source: &Path) -> Result<Vec<Option<FileIdentity>>, ImportError> {
    use std::os::unix::fs::MetadataExt;
    let mut state = Vec::new();
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut path = source.as_os_str().to_owned();
        path.push(suffix);
        match fs::symlink_metadata(path) {
            Ok(m) if m.is_file() => {
                state.push(Some((m.dev(), m.ino(), m.len(), m.mtime(), m.mtime_nsec())))
            }
            Err(e) if !suffix.is_empty() && e.kind() == std::io::ErrorKind::NotFound => {
                state.push(None)
            }
            _ => return Err(ImportError),
        }
    }
    Ok(state)
}

fn copy_private(source: &Path, destination: &Path) -> Result<(), ImportError> {
    if !fs::symlink_metadata(source)?.file_type().is_file() {
        return Err(ImportError);
    }
    let mut input = File::open(source)?;
    let mut output = private_file(destination)?;
    std::io::copy(&mut input, &mut output)?;
    output.flush()?;
    Ok(())
}

struct Staging {
    path: PathBuf,
    identity: fs::Metadata,
}
impl Staging {
    fn create(parent: &Path) -> Result<Self, ImportError> {
        let path = parent.join(format!(".zcode-import-{:032x}", rand::random::<u128>()));
        private_dir(&path)?;
        let identity = fs::symlink_metadata(&path)?;
        Ok(Self { path, identity })
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(current) = fs::symlink_metadata(&self.path) {
                if current.is_dir()
                    && current.dev() == self.identity.dev()
                    && current.ino() == self.identity.ino()
                {
                    let _ = fs::remove_dir_all(&self.path);
                }
            }
        }
    }
}

// std::fs::rename may replace an empty directory. Use an exclusive rename instead.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn publish(source: &Path, destination: &Path) -> Result<(), ImportError> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let source = CString::new(source.as_os_str().as_bytes()).map_err(|_| ImportError)?;
    let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| ImportError)?;
    #[cfg(target_os = "macos")]
    let result = {
        extern "C" {
            fn renamex_np(
                from: *const std::ffi::c_char,
                to: *const std::ffi::c_char,
                flags: u32,
            ) -> i32;
        }
        // RENAME_EXCL prevents replacement even when the target is an empty directory.
        unsafe { renamex_np(source.as_ptr(), destination.as_ptr(), 0x00000004) }
    };
    #[cfg(target_os = "linux")]
    let result = {
        extern "C" {
            fn renameat2(
                fromfd: i32,
                from: *const std::ffi::c_char,
                tofd: i32,
                to: *const std::ffi::c_char,
                flags: u32,
            ) -> i32;
        }
        unsafe { renameat2(-100, source.as_ptr(), -100, destination.as_ptr(), 1) }
    };
    if result != 0 {
        return Err(ImportError);
    }
    Ok(())
}
