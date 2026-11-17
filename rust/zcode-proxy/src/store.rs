//! SQLite persistence (port of database*.go's minimal surface: settings,
//! accounts, gateway keys, usage records). Single connection behind a mutex,
//! matching the Go pool's serialized-writer discipline. Additive migrations
//! inspect existing columns before changing the schema.

use rusqlite::Connection;

/// Errors deliberately omit SQL, bound values, and credential material.
#[derive(Debug)]
pub enum StoreError {
    Database,
    Vault,
    UnsupportedSchema,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Database => "storage operation failed",
            Self::Vault => "credential storage operation failed",
            Self::UnsupportedSchema => "Go database schema requires an explicit importer",
        })
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Database
    }
}

impl From<crate::vault::VaultError> for StoreError {
    fn from(_: crate::vault::VaultError) -> Self {
        Self::Vault
    }
}

/// Reject the Go schema before changing pragmas or creating reduced tables.
pub fn check_schema(conn: &Connection) -> Result<(), StoreError> {
    for (table, marker) in [("accounts", "user_id"), ("settings", "updated_at")] {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let columns = stmt.query_map([], |r| r.get::<_, String>(1))?;
        for column in columns {
            if column? == marker {
                return Err(StoreError::UnsupportedSchema);
            }
        }
    }
    Ok(())
}

pub fn has_ciphertext(conn: &Connection) -> Result<bool, StoreError> {
    for (table, query) in [
        ("accounts", "SELECT EXISTS(SELECT 1 FROM accounts WHERE substr(zcode_jwt,1,7) = 'vault1:' OR substr(api_key,1,7) = 'vault1:')"),
        ("settings", "SELECT EXISTS(SELECT 1 FROM settings WHERE substr(value,1,7) = 'vault1:')"),
    ] {
        let exists: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)", [table], |r| r.get(0))?;
        if exists && conn.query_row(query, [], |r| r.get::<_, bool>(0))? { return Ok(true); }
    }
    Ok(false)
}

pub fn try_open(path: &str) -> Result<Connection, StoreError> {
    let conn = Connection::open(path)?;
    check_schema(&conn)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    try_migrate(&conn)?;
    Ok(conn)
}

/// Fixture convenience; runtime startup uses the fallible API.
pub fn open(path: &str) -> Connection {
    try_open(path).expect("open reduced Rust database")
}

#[cfg(test)]
fn migrate(conn: &Connection) {
    try_migrate(conn).expect("migrate fixture database");
}

fn try_migrate(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL DEFAULT '',
            provider TEXT NOT NULL DEFAULT 'zai',
            enabled INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'active',
            cooling_until INTEGER NOT NULL DEFAULT 0,
            paid_cooling_until INTEGER NOT NULL DEFAULT 0,
            paid_fallback INTEGER NOT NULL DEFAULT 1,
            zcode_jwt TEXT NOT NULL DEFAULT '',
            api_key TEXT NOT NULL DEFAULT '',
            account_group TEXT NOT NULL DEFAULT '',
            remaining REAL NOT NULL DEFAULT 0,
            priority INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS gateway_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            key_hash TEXT NOT NULL UNIQUE,
            enabled INTEGER NOT NULL DEFAULT 1,
            models TEXT NOT NULL DEFAULT '',
            rpm_limit INTEGER NOT NULL DEFAULT 0,
            rate_5h INTEGER NOT NULL DEFAULT 0,
            rate_1d INTEGER NOT NULL DEFAULT 0,
            rate_7d INTEGER NOT NULL DEFAULT 0,
            quota_total INTEGER NOT NULL DEFAULT 0,
            quota_used INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS usage_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at INTEGER NOT NULL,
            account_id INTEGER NOT NULL DEFAULT 0,
            status INTEGER NOT NULL DEFAULT 0,
            gateway_key_id INTEGER NOT NULL DEFAULT 0,
            quota_charge INTEGER NOT NULL DEFAULT 0
        );",
    )?;
    let mut stmt = conn.prepare("PRAGMA table_info(accounts)")?;
    let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut has_remark = false;
    for column in columns {
        has_remark |= column? == "remark";
    }
    if !has_remark {
        conn.execute(
            "ALTER TABLE accounts ADD COLUMN remark TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    Ok(())
}

pub fn sensitive_setting(key: &str) -> bool {
    matches!(
        key,
        "api_key"
            | "password_hash"
            | "upstream_proxy"
            | "totp_secret"
            | "totp_recovery"
            | "passkey_credentials"
            | "passkey_user_handle"
            | "admin_password_hash"
            | "totp_secret_pending"
            | "pending_totp_secret"
            | "recovery_codes"
    )
}

pub fn load_settings(
    conn: &Connection,
    vault: &crate::vault::Vault,
) -> Result<std::collections::HashMap<String, String>, StoreError> {
    let mut stmt = conn.prepare("SELECT key, value FROM settings")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut settings = std::collections::HashMap::new();
    for row in rows {
        let (key, value) = row?;
        let value = if sensitive_setting(&key) {
            vault.decrypt(&value)?
        } else {
            value
        };
        settings.insert(key, value);
    }
    Ok(settings)
}

pub fn persist_settings(
    conn: &mut Connection,
    vault: &crate::vault::Vault,
    values: &[(&str, &str)],
) -> Result<(), StoreError> {
    let tx = conn.transaction()?;
    for &(key, value) in values {
        let value = if sensitive_setting(key) {
            vault.encrypt(value)?
        } else {
            value.to_owned()
        };
        tx.execute(
            "INSERT INTO settings(key, value) VALUES(?1, ?2)
            ON CONFLICT(key) DO UPDATE SET value = ?2",
            [key, &value],
        )?;
    }
    tx.commit()?;
    Ok(())
}

pub fn get_setting(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
        r.get::<_, String>(0)
    })
    .ok()
}

pub fn set_setting(conn: &Connection, key: &str, value: &str) {
    conn.execute(
        "INSERT INTO settings(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = ?2",
        [key, value],
    )
    .ok();
}

// ---- accounts ----

pub fn upsert_account(
    conn: &Connection,
    a: &zcode_core::AccountView,
    jwt: &str,
    api_key: &str,
) -> i64 {
    insert_account(conn, a, jwt, api_key).expect("seed fixture account")
}

pub fn insert_account_encrypted(
    conn: &Connection,
    vault: &crate::vault::Vault,
    a: &zcode_core::AccountView,
    jwt: &str,
    api_key: &str,
) -> Result<i64, StoreError> {
    let jwt = vault.encrypt(jwt)?;
    let api_key = vault.encrypt(api_key)?;
    insert_account(conn, a, &jwt, &api_key)
}

fn insert_account(
    conn: &Connection,
    a: &zcode_core::AccountView,
    jwt: &str,
    api_key: &str,
) -> Result<i64, StoreError> {
    conn.execute(
        "INSERT INTO accounts(email, provider, enabled, status, cooling_until,
            paid_cooling_until, paid_fallback, zcode_jwt, api_key, account_group,
            remaining, priority)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        rusqlite::params![
            a.email,
            a.provider,
            a.enabled as i64,
            a.status,
            a.cooling_until,
            a.paid_cooling_until,
            a.paid_fallback as i64,
            jwt,
            api_key,
            a.account_group,
            a.remaining,
            a.priority,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn update_account_state(conn: &Connection, id: i64, status: &str, cooling_until: i64) {
    let _ = conn.execute(
        "UPDATE accounts SET status = ?1, cooling_until = ?2 WHERE id = ?3",
        rusqlite::params![status, cooling_until, id],
    );
}

pub fn list_accounts(conn: &Connection) -> Vec<(zcode_core::AccountView, String, String)> {
    read_accounts(conn).unwrap_or_default()
}

pub fn load_accounts(
    conn: &Connection,
    vault: &crate::vault::Vault,
) -> Result<Vec<(zcode_core::AccountView, String, String)>, StoreError> {
    let mut rows = read_accounts(conn)?;
    for (account, jwt, key) in &mut rows {
        *jwt = vault.decrypt(jwt)?;
        *key = vault.decrypt(key)?;
        account.zcode_jwt = jwt.clone();
        account.api_key = key.clone();
    }
    Ok(rows)
}

fn read_accounts(
    conn: &Connection,
) -> Result<Vec<(zcode_core::AccountView, String, String)>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT id, email, provider, enabled, status, cooling_until,
            paid_cooling_until, paid_fallback, zcode_jwt, api_key,
            account_group, remaining, priority FROM accounts",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            zcode_core::AccountView {
                id: r.get(0)?,
                email: r.get(1)?,
                provider: r.get(2)?,
                enabled: r.get::<_, i64>(3)? != 0,
                status: r.get(4)?,
                cooling_until: r.get(5)?,
                paid_cooling_until: r.get(6)?,
                paid_fallback: r.get::<_, i64>(7)? != 0,
                zcode_jwt: r.get(8)?,
                api_key: r.get(9)?,
                account_group: r.get(10)?,
                remaining: r.get(11)?,
                priority: r.get(12)?,
            },
            r.get::<_, String>(8)?,
            r.get::<_, String>(9)?,
        ))
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

pub fn delete_account(conn: &Connection, id: i64) {
    let _ = conn.execute("DELETE FROM accounts WHERE id = ?1", [id]);
}

pub fn set_account_enabled(conn: &Connection, id: i64, enabled: bool) {
    let _ = conn.execute(
        "UPDATE accounts SET enabled = ?1 WHERE id = ?2",
        rusqlite::params![enabled as i64, id],
    );
}

// ---- gateway keys ----

pub fn upsert_gateway_key(conn: &Connection, k: &crate::state::NamedKey) {
    let _ = conn.execute(
        "INSERT INTO gateway_keys(name, key_hash, enabled, models, rpm_limit,
            rate_5h, rate_1d, rate_7d, quota_total, quota_used)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        rusqlite::params![
            k.name,
            k.key_hash,
            k.enabled as i64,
            k.models,
            k.rpm_limit,
            k.rate_5h,
            k.rate_1d,
            k.rate_7d,
            k.quota_total,
            k.quota_used,
        ],
    );
}

pub fn list_gateway_keys(conn: &Connection) -> Vec<crate::state::NamedKey> {
    let mut stmt = match conn.prepare(
        "SELECT id, name, key_hash, enabled, models, rpm_limit, rate_5h,
            rate_1d, rate_7d, quota_total, quota_used FROM gateway_keys",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |r| {
        Ok(crate::state::NamedKey {
            id: r.get(0)?,
            name: r.get(1)?,
            key_hash: r.get(2)?,
            enabled: r.get::<_, i64>(3)? != 0,
            models: r.get(4)?,
            rpm_limit: r.get(5)?,
            rate_5h: r.get(6)?,
            rate_1d: r.get(7)?,
            rate_7d: r.get(8)?,
            quota_total: r.get(9)?,
            quota_used: r.get(10)?,
        })
    });
    match rows {
        Ok(iter) => iter.filter_map(Result::ok).collect(),
        Err(_) => Vec::new(),
    }
}

pub fn bump_gateway_key_usage(conn: &Connection, id: i64, charge: i64) {
    let _ = conn.execute(
        "UPDATE gateway_keys SET quota_used = quota_used + ?1 WHERE id = ?2",
        rusqlite::params![charge, id],
    );
}

// ---- usage records ----

pub fn insert_usage(
    conn: &Connection,
    created_at: i64,
    account_id: i64,
    status: u16,
    gateway_key_id: i64,
    quota_charge: i64,
) {
    let _ = conn.execute(
        "INSERT INTO usage_records(created_at, account_id, status, gateway_key_id, quota_charge)
         VALUES(?1,?2,?3,?4,?5)",
        rusqlite::params![
            created_at,
            account_id,
            status as i64,
            gateway_key_id,
            quota_charge
        ],
    );
}

/// Returns the committed key balance, or None for root/synthetic keys absent from storage.
pub fn record_usage(
    conn: &mut Connection,
    created_at: i64,
    rec: &crate::state::UsageRecord,
) -> rusqlite::Result<Option<i64>> {
    use rusqlite::OptionalExtension;

    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO usage_records(created_at, account_id, status, gateway_key_id, quota_charge)
         VALUES(?1,?2,?3,?4,?5)",
        rusqlite::params![
            created_at,
            rec.account_id,
            rec.status,
            rec.gateway_key_id,
            rec.quota_charge
        ],
    )?;
    let balance = if rec.gateway_key_id > 0 {
        tx.execute(
            "UPDATE gateway_keys SET quota_used = quota_used + ?1 WHERE id = ?2",
            rusqlite::params![rec.quota_charge, rec.gateway_key_id],
        )?;
        tx.query_row(
            "SELECT quota_used FROM gateway_keys WHERE id = ?1",
            [rec.gateway_key_id],
            |row| row.get(0),
        )
        .optional()?
    } else {
        None
    };
    tx.commit()?;
    Ok(balance)
}

pub fn list_usage(conn: &Connection, limit: i64) -> Vec<(i64, i64, u16, i64, i64)> {
    let mut stmt = match conn.prepare(
        "SELECT created_at, account_id, status, gateway_key_id, quota_charge
         FROM usage_records ORDER BY id DESC LIMIT ?1",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([limit], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)? as u16,
            r.get::<_, i64>(3)?,
            r.get::<_, i64>(4)?,
        ))
    });
    match rows {
        Ok(iter) => iter.filter_map(Result::ok).collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcode_core::AccountView;

    #[test]
    fn settings_round_trip() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn);
        assert_eq!(get_setting(&conn, "missing"), None);
        set_setting(&conn, "paid_fallback_mode", "balanced");
        assert_eq!(
            get_setting(&conn, "paid_fallback_mode"),
            Some("balanced".into())
        );
        set_setting(&conn, "paid_fallback_mode", "never");
        assert_eq!(
            get_setting(&conn, "paid_fallback_mode"),
            Some("never".into())
        );
    }

    #[test]
    fn account_round_trip() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn);
        let a = AccountView {
            email: "a@t".into(),
            provider: "zai".into(),
            enabled: true,
            status: "active".into(),
            zcode_jwt: "j".into(),
            api_key: "k".into(),
            paid_fallback: true,
            remaining: 42.0,
            ..Default::default()
        };
        let id = upsert_account(&conn, &a, "j", "k");
        let rows = list_accounts(&conn);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0.id, id);
        assert_eq!(rows[0].0.remaining, 42.0);
        assert_eq!(rows[0].1, "j");
        update_account_state(&conn, id, "cooling", 999);
        assert_eq!(list_accounts(&conn)[0].0.status, "cooling");
        delete_account(&conn, id);
        assert!(list_accounts(&conn).is_empty());
    }

    #[test]
    fn failed_debit_rolls_back_usage_row() {
        let mut conn = open(":memory:");
        conn.execute_batch(
            "CREATE TRIGGER fail_debit BEFORE UPDATE ON gateway_keys
            BEGIN SELECT RAISE(FAIL, 'debit unavailable'); END;
            INSERT INTO gateway_keys(name, key_hash) VALUES('test', 'hash');",
        )
        .unwrap();
        let rec = crate::state::UsageRecord {
            account_id: 1,
            gateway_key_id: 1,
            status: 200,
            quota_charge: 45,
        };
        assert!(record_usage(&mut conn, 1000, &rec).is_err());
        assert!(list_usage(&conn, 10).is_empty());
        assert_eq!(list_gateway_keys(&conn)[0].quota_used, 0);
    }

    #[test]
    fn keys_and_usage_round_trip() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn);
        let k = crate::state::NamedKey {
            id: 0,
            name: "t".into(),
            key_hash: "h".into(),
            enabled: true,
            models: "glm-5.3".into(),
            rpm_limit: 5,
            rate_5h: 0,
            rate_1d: 0,
            rate_7d: 0,
            quota_total: 100,
            quota_used: 3,
        };
        upsert_gateway_key(&conn, &k);
        let keys = list_gateway_keys(&conn);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].quota_used, 3);
        bump_gateway_key_usage(&conn, keys[0].id, 7);
        assert_eq!(list_gateway_keys(&conn)[0].quota_used, 10);
        insert_usage(&conn, 1000, 1, 200, 0, 12);
        let usage = list_usage(&conn, 10);
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].4, 12);
    }
}
