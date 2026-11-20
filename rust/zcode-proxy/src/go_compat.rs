//! Read-only compatibility helpers for Go account storage.

use std::path::Path;

use rusqlite::Connection;
use zcode_core::AccountView;

use crate::vault::{Vault, VaultError};

#[derive(Debug)]
pub enum CompatError {
    KeyFile,
    InvalidKey,
    Database,
    Vault,
}

impl std::fmt::Display for CompatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::KeyFile => "vault keyfile read failed",
            Self::InvalidKey => "invalid vault keyfile",
            Self::Database => "account database read failed",
            Self::Vault => "vault operation failed",
        })
    }
}

impl std::error::Error for CompatError {}

impl From<rusqlite::Error> for CompatError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Database
    }
}

impl From<VaultError> for CompatError {
    fn from(_: VaultError) -> Self {
        Self::Vault
    }
}

/// Read the Go keyfile as a hexadecimal secret string, not decoded bytes.
pub fn load_vault_key(data_dir: &str) -> Result<String, CompatError> {
    let contents = std::fs::read_to_string(Path::new(data_dir).join("vault.key"))
        .map_err(|_| CompatError::KeyFile)?;
    let secret = contents.trim();
    if secret.len() != 64 || !secret.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CompatError::InvalidKey);
    }
    Ok(secret.to_owned())
}

pub fn decrypt_credential(vault: &Vault, stored: &str) -> Result<String, CompatError> {
    Ok(vault.decrypt(stored)?)
}

pub fn encrypt_credential(vault: &Vault, plain: &str) -> Result<String, CompatError> {
    Ok(vault.encrypt(plain)?)
}

pub struct GoAccount {
    pub view: AccountView,
    pub user_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub user_info: String,
    pub creds_raw: String,
}

impl std::fmt::Debug for GoAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GoAccount { .. }")
    }
}

/// Load accounts without changing the database; any unreadable row aborts the load.
pub fn load_go_accounts(conn: &Connection, vault: &Vault) -> Result<Vec<GoAccount>, CompatError> {
    let mut stmt = conn.prepare(
        "SELECT id, user_id, email, provider, enabled, status, cooling_until,
            paid_cooling_until, paid_fallback, zcode_jwt, api_key, account_group,
            remaining, priority, access_token, refresh_token, user_info, creds_raw
         FROM accounts",
    )?;
    let mut rows = stmt.query([])?;
    let mut accounts = Vec::new();
    while let Some(row) = rows.next()? {
        let view = AccountView {
            id: row.get(0)?,
            email: row.get(2)?,
            provider: row.get(3)?,
            enabled: row.get::<_, i64>(4)? == 1,
            status: row.get(5)?,
            cooling_until: row.get(6)?,
            paid_cooling_until: row.get(7)?,
            paid_fallback: row.get::<_, i64>(8)? == 1,
            zcode_jwt: decrypt_credential(vault, &row.get::<_, String>(9)?)?,
            api_key: decrypt_credential(vault, &row.get::<_, String>(10)?)?,
            account_group: row.get(11)?,
            remaining: row.get(12)?,
            priority: row.get(13)?,
        };
        accounts.push(GoAccount {
            view,
            user_id: row.get(1)?,
            access_token: decrypt_credential(vault, &row.get::<_, String>(14)?)?,
            refresh_token: decrypt_credential(vault, &row.get::<_, String>(15)?)?,
            user_info: decrypt_credential(vault, &row.get::<_, String>(16)?)?,
            creds_raw: decrypt_credential(vault, &row.get::<_, String>(17)?)?,
        });
    }
    Ok(accounts)
}

const ENCRYPTED_SETTING_KEYS: &[&str] = &[
    "api_key",
    "password_hash",
    "upstream_proxy",
    "totp_secret",
    "totp_recovery",
    "passkey_credentials",
    "passkey_user_handle",
];

pub fn is_encrypted_setting(key: &str) -> bool {
    ENCRYPTED_SETTING_KEYS.contains(&key)
}

pub fn decrypt_setting(vault: &Vault, key: &str, stored: &str) -> Result<String, CompatError> {
    if is_encrypted_setting(key) {
        decrypt_credential(vault, stored)
    } else {
        Ok(stored.to_owned())
    }
}

pub fn encrypt_setting(vault: &Vault, key: &str, plain: &str) -> Result<String, CompatError> {
    if is_encrypted_setting(key) {
        encrypt_credential(vault, plain)
    } else {
        Ok(plain.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_plaintext() {
        let vault = Vault::from_secret("test").unwrap();
        assert_eq!(
            decrypt_credential(&vault, "plain-jwt").unwrap(),
            "plain-jwt"
        );
        assert_eq!(decrypt_credential(&vault, "").unwrap(), "");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let vault = Vault::from_secret("test").unwrap();
        let enc = encrypt_credential(&vault, "secret-jwt-value").unwrap();
        assert!(enc.starts_with("vault1:"));
        assert_eq!(
            decrypt_credential(&vault, &enc).unwrap(),
            "secret-jwt-value"
        );
    }

    #[test]
    fn empty_stays_empty() {
        let vault = Vault::from_secret("test").unwrap();
        let enc = encrypt_credential(&vault, "").unwrap();
        assert_eq!(enc, "");
        assert_eq!(decrypt_credential(&vault, "").unwrap(), "");
    }
}
