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
    pub fn from_secret(secret: &str) -> Result<Self, VaultError> {
        if secret.is_empty() {
            return Err(VaultError);
        }
        Ok(Self {
            key: Zeroizing::new(Sha256::digest(secret.as_bytes()).into()),
        })
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
