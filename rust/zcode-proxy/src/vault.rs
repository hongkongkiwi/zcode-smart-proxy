use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const PREFIX: &str = "vault1:";

#[derive(Debug)]
pub struct VaultError;

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("vault operation failed")
    }
}

impl std::error::Error for VaultError {}

pub struct Vault {
    key: Zeroizing<[u8; 32]>,
}

impl Vault {
    pub fn ephemeral() -> Result<Self, VaultError> {
        let mut key = [0u8; 32];
        OsRng.try_fill_bytes(&mut key).map_err(|_| VaultError)?;
        Ok(Self {
            key: Zeroizing::new(key),
        })
    }

    pub fn from_secret(secret: &str) -> Result<Self, VaultError> {
        if secret.is_empty() {
            return Err(VaultError);
        }
        Ok(Self {
            key: Zeroizing::new(Sha256::digest(secret.as_bytes()).into()),
        })
    }

    /// Resolve a durable seed before runtime startup is allowed to write SQLite.
    pub fn for_database(path: &str) -> Result<Self, crate::store::StoreError> {
        use crate::store::StoreError;
        use std::io::Write;
        use std::path::Path;
        if path == ":memory:" {
            return Ok(Self::ephemeral()?);
        }
        // File paths only: URI memory databases belong to fixture constructors.
        if path.is_empty() || path.starts_with("file:") {
            return Err(StoreError::Database);
        }
        let existing = if Path::new(path)
            .try_exists()
            .map_err(|_| StoreError::Database)?
        {
            let db = rusqlite::Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            crate::store::check_schema(&db)?;
            Some(db)
        } else {
            None
        };
        match std::env::var("ZCODE_PROXY_VAULT_SECRET") {
            Ok(secret) => return Ok(Self::from_secret(&secret)?),
            Err(std::env::VarError::NotUnicode(_)) => return Err(StoreError::Vault),
            Err(std::env::VarError::NotPresent) => (),
        }
        let parent = Path::new(path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let key_path = parent.join("vault.key");
        match std::fs::read_to_string(&key_path) {
            Ok(raw) => {
                let seed = raw.trim();
                if seed.len() != 64 || !seed.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(StoreError::Vault);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if std::fs::metadata(&key_path)
                        .map_err(|_| StoreError::Vault)?
                        .permissions()
                        .mode()
                        & 0o077
                        != 0
                    {
                        return Err(StoreError::Vault);
                    }
                }
                return Ok(Self::from_secret(seed)?);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(StoreError::Vault),
        }
        if let Some(db) = existing.as_ref() {
            if crate::store::has_ciphertext(db)? {
                return Err(StoreError::Vault);
            }
        }
        #[cfg(not(unix))]
        {
            return Err(StoreError::Vault);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut bytes = Zeroizing::new([0u8; 32]);
            OsRng
                .try_fill_bytes(bytes.as_mut())
                .map_err(|_| StoreError::Vault)?;
            let seed = Zeroizing::new(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&key_path)
                .map_err(|_| StoreError::Vault)?;
            file.write_all(seed.as_bytes())
                .map_err(|_| StoreError::Vault)?;
            file.write_all(b"\n").map_err(|_| StoreError::Vault)?;
            file.sync_all().map_err(|_| StoreError::Vault)?;
            std::fs::File::open(parent)
                .and_then(|dir| dir.sync_all())
                .map_err(|_| StoreError::Vault)?;
            Ok(Self::from_secret(&seed)?)
        }
    }

    pub fn encrypt(&self, plain: &str) -> Result<String, VaultError> {
        if plain.is_empty() {
            return Ok(String::new());
        }
        if plain.starts_with(PREFIX) {
            self.decrypt(plain)?;
            return Ok(plain.to_owned());
        }
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| VaultError)?;
        let mut nonce = [0u8; 12];
        OsRng.try_fill_bytes(&mut nonce).map_err(|_| VaultError)?;
        let sealed = cipher
            .encrypt(Nonce::from_slice(&nonce), plain.as_bytes())
            .map_err(|_| VaultError)?;
        let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
        Ok(format!(
            "{PREFIX}{}.{}.{}",
            URL_SAFE_NO_PAD.encode(nonce),
            URL_SAFE_NO_PAD.encode(tag),
            URL_SAFE_NO_PAD.encode(ciphertext)
        ))
    }

    pub fn decrypt(&self, value: &str) -> Result<String, VaultError> {
        let Some(body) = value.strip_prefix(PREFIX) else {
            return Ok(value.to_owned());
        };
        let mut parts = body.split('.');
        let nonce = URL_SAFE_NO_PAD
            .decode(parts.next().ok_or(VaultError)?)
            .map_err(|_| VaultError)?;
        let tag = URL_SAFE_NO_PAD
            .decode(parts.next().ok_or(VaultError)?)
            .map_err(|_| VaultError)?;
        let mut ciphertext = URL_SAFE_NO_PAD
            .decode(parts.next().ok_or(VaultError)?)
            .map_err(|_| VaultError)?;
        if parts.next().is_some() || nonce.len() != 12 || tag.len() != 16 {
            return Err(VaultError);
        }
        ciphertext.extend_from_slice(&tag);
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| VaultError)?;
        let plain = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|_| VaultError)?;
        String::from_utf8(plain).map_err(|_| VaultError)
    }
}
