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
const RUST_APPLICATION_ID: i64 = 0x5a435253;

pub fn check_schema(conn: &Connection) -> Result<(), StoreError> {
    let application_id: i64 = conn.pragma_query_value(None, "application_id", |r| r.get(0))?;
    for (table, marker) in [("accounts", "user_id"), ("settings", "updated_at")] {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let columns = stmt.query_map([], |r| r.get::<_, String>(1))?;
        for column in columns {
            if column? == marker && !(table == "accounts" && application_id == RUST_APPLICATION_ID)
            {
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
        ("proxy_nodes", "SELECT EXISTS(SELECT 1 FROM proxy_nodes WHERE substr(password,1,7) = 'vault1:')"),
    ] {
        let exists: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)", [table], |r| r.get(0))?;
        if exists && conn.query_row(query, [], |r| r.get::<_, bool>(0))? { return Ok(true); }
        if exists && table == "accounts" {
            let mut stmt = conn.prepare("PRAGMA table_info(accounts)")?;
            let columns = stmt.query_map([], |r| r.get::<_, String>(1))?;
            for column in columns {
                let column = column?;
                if matches!(column.as_str(), "access_token" | "refresh_token" | "user_info" | "creds_raw")
                    && conn.query_row(
                        &format!("SELECT EXISTS(SELECT 1 FROM accounts WHERE substr({column},1,7) = 'vault1:')"),
                        [], |r| r.get::<_, bool>(0),
                    )?
                {
                    return Ok(true);
                }
            }
        }
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
    let tx = conn.unchecked_transaction()?;
    let conn = &tx;
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
        CREATE TABLE IF NOT EXISTS proxy_nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT DEFAULT '',
            type TEXT DEFAULT 'socks5',
            host TEXT DEFAULT '',
            port INTEGER DEFAULT 0,
            username TEXT DEFAULT '',
            password TEXT DEFAULT '',
            is_default INTEGER DEFAULT 0,
            group_name TEXT DEFAULT '',
            enabled INTEGER DEFAULT 1,
            check_status TEXT DEFAULT '',
            check_latency INTEGER DEFAULT 0,
            check_ip TEXT DEFAULT '',
            check_msg TEXT DEFAULT '',
            check_at TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now','localtime')),
            updated_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_nodes_default
            ON proxy_nodes(is_default) WHERE is_default = 1;
        CREATE TABLE IF NOT EXISTS claim_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plan_name TEXT NOT NULL DEFAULT '',
            cron_expr TEXT NOT NULL DEFAULT '0 9 * * *',
            is_active INTEGER NOT NULL DEFAULT 1,
            target_type TEXT NOT NULL DEFAULT 'all_accounts',
            account_id INTEGER NOT NULL DEFAULT 0,
            account_group TEXT NOT NULL DEFAULT '',
            task_type TEXT NOT NULL DEFAULT 'claim',
            auto_pick INTEGER NOT NULL DEFAULT 1,
            delay_seconds INTEGER NOT NULL DEFAULT 30,
            last_run_at TEXT NOT NULL DEFAULT '',
            last_run_status TEXT NOT NULL DEFAULT '',
            last_run_msg TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        );
        CREATE INDEX IF NOT EXISTS idx_claim_plans_active ON claim_plans(is_active);
        CREATE TABLE IF NOT EXISTS plan_run_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plan_id INTEGER NOT NULL DEFAULT 0,
            plan_name TEXT NOT NULL DEFAULT '',
            task_type TEXT NOT NULL DEFAULT '',
            target_type TEXT NOT NULL DEFAULT '',
            account_id INTEGER NOT NULL DEFAULT 0,
            run_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            status TEXT NOT NULL DEFAULT '',
            message TEXT NOT NULL DEFAULT '',
            total INTEGER NOT NULL DEFAULT 0,
            success_count INTEGER NOT NULL DEFAULT 0,
            fail_count INTEGER NOT NULL DEFAULT 0,
            duration_ms INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_plan_run_records_run_at ON plan_run_records(run_at);
        CREATE INDEX IF NOT EXISTS idx_plan_run_records_plan ON plan_run_records(plan_id);
        CREATE TABLE IF NOT EXISTS claim_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            account_id INTEGER NOT NULL DEFAULT 0,
            email TEXT NOT NULL DEFAULT '',
            task_type TEXT NOT NULL DEFAULT 'claim',
            plan_id TEXT NOT NULL DEFAULT '',
            plan_name TEXT NOT NULL DEFAULT '',
            success INTEGER NOT NULL DEFAULT 0,
            code INTEGER NOT NULL DEFAULT 0,
            message TEXT NOT NULL DEFAULT '',
            next_at INTEGER NOT NULL DEFAULT 0,
            used_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_claim_records_account ON claim_records(account_id);
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
    let columns = columns.collect::<Result<Vec<_>, _>>()?;
    for (name, definition) in [
        ("remark", "TEXT NOT NULL DEFAULT ''"),
        ("user_id", "TEXT"),
        ("display_name", "TEXT NOT NULL DEFAULT ''"),
        ("auth_type", "TEXT NOT NULL DEFAULT 'jwt'"),
        ("access_token", "TEXT NOT NULL DEFAULT ''"),
        ("refresh_token", "TEXT NOT NULL DEFAULT ''"),
        ("user_info", "TEXT NOT NULL DEFAULT ''"),
        ("device_mid", "TEXT NOT NULL DEFAULT ''"),
        ("creds_raw", "TEXT NOT NULL DEFAULT ''"),
        ("quota_json", "TEXT NOT NULL DEFAULT ''"),
        ("plan_tier", "TEXT NOT NULL DEFAULT ''"),
        ("plan_expire", "TEXT NOT NULL DEFAULT ''"),
        ("total_units", "REAL NOT NULL DEFAULT 0"),
        ("used_units", "REAL NOT NULL DEFAULT 0"),
        ("last_checked_at", "INTEGER NOT NULL DEFAULT 0"),
        ("last_error", "TEXT NOT NULL DEFAULT ''"),
        ("last_claim_at", "TEXT NOT NULL DEFAULT ''"),
        ("last_claim_plan", "TEXT NOT NULL DEFAULT ''"),
        ("last_claim_msg", "TEXT NOT NULL DEFAULT ''"),
    ] {
        if !columns.iter().any(|column| column == name) {
            conn.execute(
                &format!("ALTER TABLE accounts ADD COLUMN {name} {definition}"),
                [],
            )?;
        }
    }
    conn.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS accounts_user_id ON accounts(user_id);
        UPDATE accounts SET user_id = 'rust:' || lower(hex(randomblob(16)))
        WHERE user_id IS NULL OR user_id = ''; ",
    )?;
    let mut gateway_stmt = conn.prepare("PRAGMA table_info(gateway_keys)")?;
    let gateway_columns = gateway_stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (name, definition) in [
        ("key_prefix", "TEXT NOT NULL DEFAULT ''"),
        ("last_used_at", "INTEGER NOT NULL DEFAULT 0"),
        ("created_at", "TEXT NOT NULL DEFAULT ''"),
        ("updated_at", "TEXT NOT NULL DEFAULT ''"),
    ] {
        if !gateway_columns.iter().any(|column| column == name) {
            conn.execute(
                &format!("ALTER TABLE gateway_keys ADD COLUMN {name} {definition}"),
                [],
            )?;
        }
    }
    drop(gateway_stmt);
    conn.pragma_update(None, "application_id", RUST_APPLICATION_ID)?;
    drop(stmt);
    tx.commit()?;
    Ok(())
}

pub(crate) struct ProxyNode {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub host: String,
    pub port: i64,
    pub username: String,
    pub password: String,
    pub is_default: bool,
    pub group_name: String,
    pub enabled: bool,
    pub check_status: String,
    pub check_latency: i64,
    pub check_ip: String,
    pub check_msg: String,
    pub check_at: String,
    pub created_at: String,
    pub updated_at: String,
}

pub(crate) fn list_proxy_nodes(conn: &Connection) -> Result<Vec<ProxyNode>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT id,name,type,host,port,username,password,is_default,group_name,enabled,
         check_status,check_latency,check_ip,check_msg,check_at,created_at,updated_at
         FROM proxy_nodes ORDER BY id",
    )?;
    let rows = stmt.query_map([], |r| {
        let boolean = |column| {
            let value: i64 = r.get(column)?;
            match value {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(rusqlite::Error::IntegralValueOutOfRange(column, value)),
            }
        };
        Ok(ProxyNode {
            id: r.get(0)?,
            name: r.get(1)?,
            kind: r.get(2)?,
            host: r.get(3)?,
            port: r.get(4)?,
            username: r.get(5)?,
            password: r.get(6)?,
            is_default: boolean(7)?,
            group_name: r.get(8)?,
            enabled: boolean(9)?,
            check_status: r.get(10)?,
            check_latency: r.get(11)?,
            check_ip: r.get(12)?,
            check_msg: r.get(13)?,
            check_at: r.get(14)?,
            created_at: r.get(15)?,
            updated_at: r.get(16)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
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
            remaining, priority, user_id)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,'rust:' || lower(hex(randomblob(16))))",
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
    // Validate every credential column at startup, including metadata not in AccountView.
    load_bundle_accounts(conn, vault)?;
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

pub fn load_bundle_accounts(
    conn: &Connection,
    vault: &crate::vault::Vault,
) -> Result<Vec<(i64, crate::account_bundle::BundleAccount)>, StoreError> {
    use crate::account_bundle::BundleAccount;
    let mut stmt = conn.prepare(
        "SELECT id,user_id,email,display_name,provider,auth_type,access_token,refresh_token,
            zcode_jwt,api_key,user_info,device_mid,creds_raw,account_group,remark
         FROM accounts ORDER BY id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get(0)?,
            BundleAccount {
                user_id: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                email: r.get(2)?,
                display_name: r.get(3)?,
                provider: r.get(4)?,
                auth_type: r.get(5)?,
                access_token: r.get(6)?,
                refresh_token: r.get(7)?,
                zcode_jwt: r.get(8)?,
                api_key: r.get(9)?,
                user_info: r.get(10)?,
                device_mid: r.get(11)?,
                creds_raw: r.get(12)?,
                account_group: r.get(13)?,
                remark: r.get(14)?,
            },
        ))
    })?;
    let mut accounts = rows.collect::<Result<Vec<_>, _>>()?;
    for (_, account) in &mut accounts {
        account.transform_credentials(|value| vault.decrypt(value))?;
    }
    Ok(accounts)
}

/// Credentials are encrypted before entering this transaction. All fallible reads
/// finish before commit so callers can publish the returned runtime snapshot atomically.
pub fn import_bundle_accounts(
    conn: &mut Connection,
    vault: &crate::vault::Vault,
    accounts: &[crate::account_bundle::BundleAccount],
) -> Result<Vec<(zcode_core::AccountView, String, String)>, StoreError> {
    Ok(import_bundle_accounts_with_ids(conn, vault, accounts)?.accounts)
}

pub(crate) struct ImportResult {
    pub accounts: Vec<(zcode_core::AccountView, String, String)>,
    pub ids: Vec<i64>,
}

pub(crate) fn import_bundle_accounts_with_ids(
    conn: &mut Connection,
    vault: &crate::vault::Vault,
    accounts: &[crate::account_bundle::BundleAccount],
) -> Result<ImportResult, StoreError> {
    import_bundle_accounts_before(conn, vault, accounts, None)
}

pub(crate) fn import_bundle_accounts_before(
    conn: &mut Connection,
    vault: &crate::vault::Vault,
    accounts: &[crate::account_bundle::BundleAccount],
    deadline: Option<std::time::Instant>,
) -> Result<ImportResult, StoreError> {
    let expired = || deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline);
    if expired() {
        return Err(StoreError::Database);
    }
    let tx = conn.transaction()?;
    let mut ids = Vec::with_capacity(accounts.len());
    for a in accounts {
        tx.execute(
            "INSERT INTO accounts(user_id,email,display_name,provider,auth_type,
                access_token,refresh_token,zcode_jwt,api_key,user_info,device_mid,creds_raw,
                account_group,remark,status,enabled,priority,paid_fallback)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,'active',1,100,?15)
             ON CONFLICT(user_id) DO UPDATE SET
                email=COALESCE(NULLIF(excluded.email,''),accounts.email),
                display_name=COALESCE(NULLIF(excluded.display_name,''),accounts.display_name),
                provider=excluded.provider,auth_type=excluded.auth_type,
                access_token=COALESCE(NULLIF(excluded.access_token,''),accounts.access_token),
                refresh_token=COALESCE(NULLIF(excluded.refresh_token,''),accounts.refresh_token),
                zcode_jwt=COALESCE(NULLIF(excluded.zcode_jwt,''),accounts.zcode_jwt),
                api_key=COALESCE(NULLIF(excluded.api_key,''),accounts.api_key),
                user_info=COALESCE(NULLIF(excluded.user_info,''),accounts.user_info),
                device_mid=COALESCE(NULLIF(excluded.device_mid,''),accounts.device_mid),
                creds_raw=COALESCE(NULLIF(excluded.creds_raw,''),accounts.creds_raw),
                account_group=COALESCE(NULLIF(excluded.account_group,''),accounts.account_group),
                remark=COALESCE(NULLIF(excluded.remark,''),accounts.remark),
                status=CASE WHEN accounts.status='disabled' THEN accounts.status ELSE 'active' END,
                enabled=1",
            rusqlite::params![
                a.user_id,
                a.email,
                a.display_name,
                a.provider,
                a.auth_type,
                a.access_token,
                a.refresh_token,
                a.zcode_jwt,
                a.api_key,
                a.user_info,
                a.device_mid,
                a.creds_raw,
                a.account_group,
                a.remark,
                !a.api_key.is_empty()
            ],
        )?;
        ids.push(tx.query_row(
            "SELECT id FROM accounts WHERE user_id = ?1",
            [&a.user_id],
            |row| row.get(0),
        )?);
    }
    let rows = load_accounts(&tx, vault)?;
    // Expiry rolls back writes and snapshot reads before admitting the commit.
    if expired() {
        return Err(StoreError::Database);
    }
    tx.commit()?;
    Ok(ImportResult {
        accounts: rows,
        ids,
    })
}

pub(crate) struct AccountTokens {
    pub jwt: String,
    pub access: String,
    pub refresh: String,
    pub user_info: String,
}

/// One transaction commits rotated credentials and recovery together.
/// Empty optional fields retain their existing encrypted values.
pub(crate) fn update_account_tokens(
    conn: &Connection,
    vault: &crate::vault::Vault,
    id: i64,
    tokens: &AccountTokens,
) -> Result<(), StoreError> {
    let jwt = vault.encrypt(&tokens.jwt)?;
    let access = vault.encrypt(&tokens.access)?;
    let refresh = vault.encrypt(&tokens.refresh)?;
    let user_info = vault.encrypt(&tokens.user_info)?;
    let tx = conn.unchecked_transaction()?;
    let changed = tx.execute(
        "UPDATE accounts SET zcode_jwt=?1,
            access_token=COALESCE(NULLIF(?2,''),access_token),
            refresh_token=COALESCE(NULLIF(?3,''),refresh_token),
            user_info=COALESCE(NULLIF(?4,''),user_info),
            status='active',cooling_until=0,last_error=''
         WHERE id=?5 AND enabled<>0 AND status<>'disabled'",
        rusqlite::params![jwt, access, refresh, user_info, id],
    )?;
    if changed != 1 {
        return Err(StoreError::Database);
    }
    tx.commit()?;
    Ok(())
}

pub(crate) fn account_public_view(
    conn: &Connection,
    account: &zcode_core::AccountView,
) -> rusqlite::Result<serde_json::Value> {
    conn.query_row(
        "SELECT remark,quota_json,plan_tier,plan_expire,total_units,used_units,last_checked_at,last_error,
            last_claim_at,last_claim_plan,last_claim_msg
         FROM accounts WHERE id=?1",
        [account.id],
        |row| {
            let quota: String = row.get(1)?;
            let quota = serde_json::from_str::<serde_json::Value>(&quota).unwrap_or(serde_json::Value::Null);
            Ok(serde_json::json!({
                "id":account.id,"email":account.email,"provider":account.provider,
                "enabled":account.enabled,
                "status":zcode_core::effective_status(&account.status, account.cooling_until, crate::auth::now_secs()),
                "raw_status":account.status,
                "cooling_until":account.cooling_until,"remaining":account.remaining,
                "group":account.account_group,"remark":row.get::<_,String>(0)?,
                "priority":account.priority,"paid_fallback":account.paid_fallback,
                "quota":quota,"plan_tier":row.get::<_,String>(2)?,
                "plan_expire":row.get::<_,String>(3)?,"total_units":row.get::<_,f64>(4)?,
                "used_units":row.get::<_,f64>(5)?,"last_checked_at":row.get::<_,i64>(6)?,
                "last_error":row.get::<_,String>(7)?,
                "last_claim_at":row.get::<_,String>(8)?,
                "last_claim_plan":row.get::<_,String>(9)?,
                "last_claim_msg":row.get::<_,String>(10)?,
            }))
        },
    )
}

pub(crate) fn recent_reset_spend(
    conn: &Connection,
    account_id: i64,
    now: i64,
) -> Result<bool, StoreError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM claim_records WHERE account_id=?1 AND task_type='reset' AND success=1 AND used_at>=?2)",
        rusqlite::params![account_id, now.saturating_sub(1800)],
        |row| row.get(0),
    )?)
}

pub(crate) struct ClaimRecord<'a> {
    pub account_id: i64,
    pub email: &'a str,
    pub task_type: &'a str,
    pub plan_id: &'a str,
    pub plan_name: &'a str,
    pub success: bool,
    pub code: i64,
    pub message: &'a str,
    pub next_at: i64,
    pub used_at: i64,
}

pub(crate) struct ConfirmedQuota<'a> {
    pub quota: &'a crate::account_refresh::Quota,
    pub account: &'a zcode_core::AccountView,
    pub last_error: Option<&'a str>,
}

/// The ledger, account summary, and optional confirmed quota commit before live publication.
pub(crate) fn persist_claim_result(
    conn: &mut Connection,
    record: &ClaimRecord<'_>,
    quota: Option<ConfirmedQuota<'_>>,
) -> Result<(), StoreError> {
    let tx = conn.transaction()?;
    if record.task_type != "detect" {
        tx.execute(
            "UPDATE accounts SET last_claim_at=datetime('now','localtime'),
                last_claim_plan=?1,last_claim_msg=?2 WHERE id=?3",
            rusqlite::params![record.plan_name, record.message, record.account_id],
        )?;
    }
    tx.execute(
        "INSERT INTO claim_records(account_id,email,task_type,plan_id,plan_name,success,
            code,message,next_at,used_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        rusqlite::params![
            record.account_id,
            record.email,
            record.task_type,
            record.plan_id,
            record.plan_name,
            record.success,
            record.code,
            record.message,
            record.next_at,
            record.used_at
        ],
    )?;
    if let Some(quota) = quota {
        update_confirmed_quota(&tx, record.account_id, quota)?;
    }
    tx.commit()?;
    Ok(())
}

/// History rows and their per-kind anchors are one commit; callers publish the mirror afterward.
pub(crate) fn persist_reset_history(
    conn: &mut Connection,
    vault: &crate::vault::Vault,
    account_id: i64,
    email: &str,
    latest: &[(&str, i64)],
) -> Result<(usize, Option<String>), StoreError> {
    use rusqlite::OptionalExtension;

    let tx = conn.transaction()?;
    let key = format!("reset_history_seen:{account_id}");
    let raw: Option<String> = tx
        .query_row("SELECT value FROM settings WHERE key=?1", [&key], |r| {
            r.get(0)
        })
        .optional()?;
    let raw = raw
        .map(|raw| {
            if sensitive_setting(&key) {
                vault.decrypt(&raw).map_err(StoreError::from)
            } else {
                Ok(raw)
            }
        })
        .transpose()?;
    let mut anchor: std::collections::HashMap<String, i64> = raw
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default();
    let mut inserted = 0;
    let mut changed = false;
    for &(kind, used_ms) in latest {
        let used_sec = used_ms / 1000;
        if used_sec <= anchor.get(kind).copied().unwrap_or(0) / 1000 {
            continue;
        }
        // Go's legacy wall clock uses today's UTC offset, allowing historical DST skew.
        let duplicate: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM claim_records
             WHERE account_id=?1 AND task_type='reset' AND success=1 AND plan_name LIKE ?3
               AND (used_at=?2 OR (used_at>0 AND ABS(used_at-?2)<900)
                 OR (used_at=0 AND ABS(CAST(strftime('%s',created_at) AS INTEGER)
                    - (CAST(strftime('%s','now','localtime') AS INTEGER)
                       - CAST(strftime('%s','now') AS INTEGER)) - ?2)<5400)))",
            rusqlite::params![account_id, used_sec, format!("%({kind})%")],
            |r| r.get(0),
        )?;
        if !duplicate {
            tx.execute(
                "INSERT INTO claim_records(account_id,email,task_type,plan_name,success,message,used_at)
                 VALUES(?1,?2,'reset',?3,1,'上游重置记录（非本网关执行）',?4)",
                rusqlite::params![account_id, email, format!("配额重置({kind})"), used_sec],
            )?;
            inserted += 1;
        }
        anchor.insert(kind.to_owned(), used_ms);
        changed = true;
    }
    let updated = if changed {
        let value = serde_json::to_string(&anchor).map_err(|_| StoreError::Database)?;
        let stored = if sensitive_setting(&key) {
            vault.encrypt(&value)?
        } else {
            value.clone()
        };
        tx.execute(
            "INSERT INTO settings(key,value) VALUES(?1,?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            rusqlite::params![key, stored],
        )?;
        Some(value)
    } else {
        None
    };
    tx.commit()?;
    Ok((inserted, updated))
}

#[derive(serde::Serialize)]
pub(crate) struct ClaimPlanRow {
    pub id: i64,
    pub plan_name: String,
    pub cron_expr: String,
    pub is_active: bool,
    pub target_type: String,
    pub account_id: i64,
    pub account_group: String,
    pub task_type: String,
    pub auto_pick: bool,
    pub delay_seconds: i64,
    pub last_run_at: String,
    pub last_run_status: String,
    pub last_run_msg: String,
    pub created_at: String,
    pub updated_at: String,
}

pub(crate) fn list_claim_plans(conn: &Connection) -> Result<Vec<ClaimPlanRow>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT id,plan_name,cron_expr,is_active,target_type,account_id,account_group,
            task_type,auto_pick,delay_seconds,last_run_at,last_run_status,last_run_msg,
            created_at,updated_at FROM claim_plans ORDER BY id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(ClaimPlanRow {
            id: r.get(0)?,
            plan_name: r.get(1)?,
            cron_expr: r.get(2)?,
            is_active: r.get::<_, i64>(3)? == 1,
            target_type: r.get(4)?,
            account_id: r.get(5)?,
            account_group: r.get(6)?,
            task_type: r.get(7)?,
            auto_pick: r.get::<_, i64>(8)? == 1,
            delay_seconds: r.get(9)?,
            last_run_at: r.get(10)?,
            last_run_status: r.get(11)?,
            last_run_msg: r.get(12)?,
            created_at: r.get(13)?,
            updated_at: r.get(14)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub(crate) fn claim_plan_minute(
    conn: &Connection,
    id: i64,
    run_at: &str,
) -> Result<bool, StoreError> {
    Ok(conn.execute(
        "UPDATE claim_plans SET last_run_at=?2,last_run_status='running',last_run_msg='执行中'
         WHERE id=?1 AND (last_run_at='' OR substr(last_run_at,1,16)<>substr(?2,1,16))",
        rusqlite::params![id, run_at],
    )? == 1)
}

pub(crate) fn update_claim_plan_run(
    conn: &Connection,
    id: i64,
    status: &str,
    message: &str,
    run_at: &str,
) -> Result<(), StoreError> {
    conn.execute(
        "UPDATE claim_plans SET last_run_at=?4,last_run_status=?2,last_run_msg=?3 WHERE id=?1",
        rusqlite::params![id, status, message, run_at],
    )?;
    Ok(())
}

pub(crate) struct PlanRunRow<'a> {
    pub plan: &'a ClaimPlanRow,
    pub run_at: &'a str,
    pub status: &'a str,
    pub message: &'a str,
    pub total: i64,
    pub success: i64,
    pub fail: i64,
    pub duration_ms: i64,
}

pub(crate) fn insert_plan_run_record(
    conn: &Connection,
    run: &PlanRunRow<'_>,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO plan_run_records(plan_id,plan_name,task_type,target_type,account_id,
            run_at,status,message,total,success_count,fail_count,duration_ms)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        rusqlite::params![
            run.plan.id,
            run.plan.plan_name,
            run.plan.task_type,
            run.plan.target_type,
            run.plan.account_id,
            run.run_at,
            run.status,
            run.message,
            run.total,
            run.success,
            run.fail,
            run.duration_ms
        ],
    )?;
    Ok(())
}

pub(crate) fn finish_plan_run(
    conn: &mut Connection,
    run: &PlanRunRow<'_>,
) -> Result<(), StoreError> {
    let tx = conn.transaction()?;
    update_claim_plan_run(&tx, run.plan.id, run.status, run.message, run.run_at)?;
    insert_plan_run_record(&tx, run)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn reconcile_plan_runs(
    conn: &mut Connection,
    fallback: &str,
) -> Result<usize, StoreError> {
    let tx = conn.transaction()?;
    let plans = list_claim_plans(&tx)?;
    let mut count = 0;
    for plan in plans.iter().filter(|p| p.last_run_status == "running") {
        let run_at = if plan.last_run_at.is_empty() {
            fallback
        } else {
            &plan.last_run_at
        };
        let changed = tx.execute(
            "UPDATE claim_plans SET last_run_status='failed',last_run_msg='进程重启中断',last_run_at=?2
             WHERE id=?1 AND last_run_status='running'",
            rusqlite::params![plan.id,run_at],
        )?;
        if changed == 1 {
            insert_plan_run_record(
                &tx,
                &PlanRunRow {
                    plan,
                    run_at,
                    status: "failed",
                    message: "进程重启中断",
                    total: 0,
                    success: 0,
                    fail: 0,
                    duration_ms: 0,
                },
            )?;
            count += 1;
        }
    }
    tx.commit()?;
    Ok(count)
}

pub(crate) fn persist_confirmation(
    conn: &mut Connection,
    id: i64,
    quota: ConfirmedQuota<'_>,
) -> Result<(), StoreError> {
    let tx = conn.transaction()?;
    update_confirmed_quota(&tx, id, quota)?;
    tx.commit()?;
    Ok(())
}

fn update_confirmed_quota(
    conn: &Connection,
    id: i64,
    ConfirmedQuota {
        quota: confirmed,
        account,
        last_error,
    }: ConfirmedQuota<'_>,
) -> Result<(), StoreError> {
    let quota = serde_json::to_value(confirmed).map_err(|_| StoreError::Database)?;
    conn.execute(
        "UPDATE accounts SET quota_json=?1,plan_tier=?2,plan_expire=?3,total_units=?4,
                used_units=?5,remaining=?6,last_checked_at=?7,status=?9,cooling_until=?10,
                last_error=COALESCE(?11,last_error) WHERE id=?8",
        rusqlite::params![
            quota.to_string(),
            quota["plan_tier"].as_str().unwrap_or(""),
            quota["plan_expire"].as_str().unwrap_or(""),
            quota["total"].as_f64().unwrap_or(0.0),
            quota["used"].as_f64().unwrap_or(0.0),
            quota["remaining"].as_f64().unwrap_or(0.0),
            crate::auth::now_secs(),
            id,
            account.status,
            account.cooling_until,
            last_error
        ],
    )?;
    Ok(())
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

pub struct GatewayKeyRow {
    pub key: crate::state::NamedKey,
    pub key_prefix: String,
    pub last_used_at: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl GatewayKeyRow {
    pub fn public_view(&self) -> serde_json::Value {
        let k = &self.key;
        serde_json::json!({
            "id": k.id, "name": k.name, "key_prefix": self.key_prefix,
            "enabled": k.enabled, "models": k.models, "rpm_limit": k.rpm_limit,
            "rate_5h": k.rate_5h, "rate_1d": k.rate_1d, "rate_7d": k.rate_7d,
            "quota_total": k.quota_total, "quota_used": k.quota_used,
            "last_used_at": self.last_used_at, "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
    }
}

pub fn try_list_gateway_keys(conn: &Connection) -> rusqlite::Result<Vec<GatewayKeyRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, key_hash, enabled, models, rpm_limit, rate_5h,
            rate_1d, rate_7d, quota_total, quota_used, key_prefix, last_used_at,
            created_at, updated_at FROM gateway_keys ORDER BY id ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(GatewayKeyRow {
            key: crate::state::NamedKey {
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
            },
            key_prefix: r.get(11)?,
            last_used_at: r.get(12)?,
            created_at: r.get(13)?,
            updated_at: r.get(14)?,
        })
    })?;
    rows.collect()
}

pub fn list_gateway_keys(conn: &Connection) -> Vec<crate::state::NamedKey> {
    try_list_gateway_keys(conn)
        .unwrap_or_default()
        .into_iter()
        .map(|row| row.key)
        .collect()
}

pub fn create_gateway_key(
    conn: &Connection,
    key: &crate::state::NamedKey,
    prefix: &str,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO gateway_keys(name,key_hash,key_prefix,enabled,models,rpm_limit,
            rate_5h,rate_1d,rate_7d,quota_total,quota_used,created_at,updated_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0,
            datetime('now','localtime'),datetime('now','localtime'))",
        rusqlite::params![
            key.name,
            key.key_hash,
            prefix,
            key.enabled,
            key.models,
            key.rpm_limit,
            key.rate_5h,
            key.rate_1d,
            key.rate_7d,
            key.quota_total
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn update_gateway_key(conn: &Connection, key: &crate::state::NamedKey) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE gateway_keys SET name=?1,enabled=?2,models=?3,rpm_limit=?4,
            rate_5h=?5,rate_1d=?6,rate_7d=?7,quota_total=?8,
            updated_at=datetime('now','localtime') WHERE id=?9",
        rusqlite::params![
            key.name,
            key.enabled,
            key.models,
            key.rpm_limit,
            key.rate_5h,
            key.rate_1d,
            key.rate_7d,
            key.quota_total,
            key.id
        ],
    )?;
    Ok(())
}

pub fn delete_gateway_key(conn: &Connection, id: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM gateway_keys WHERE id=?1", [id])?;
    Ok(())
}

pub fn bump_gateway_key_usage(conn: &Connection, id: i64, charge: i64) {
    let _ = conn.execute(
        "UPDATE gateway_keys SET quota_used = quota_used + ?1, last_used_at = ?3 WHERE id = ?2",
        rusqlite::params![charge, id, crate::auth::now_secs()],
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
            "UPDATE gateway_keys SET quota_used = quota_used + ?1, last_used_at = ?3 WHERE id = ?2",
            rusqlite::params![rec.quota_charge, rec.gateway_key_id, created_at],
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
