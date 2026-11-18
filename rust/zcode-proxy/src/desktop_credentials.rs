use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

fn secret(explicit: Option<&str>) -> Result<Zeroizing<String>, ()> {
    if let Some(secret) = explicit {
        return Ok(Zeroizing::new(secret.to_owned()));
    }
    match std::env::var("ZCODE_CREDENTIAL_SECRET") {
        Ok(value) if !value.is_empty() => return Ok(Zeroizing::new(value)),
        Err(std::env::VarError::NotUnicode(_)) => return Err(()),
        _ => (),
    }
    let home_var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let home = std::env::var(home_var).unwrap_or_default();
    let username = ["USERNAME", "USER", "LOGNAME"]
        .into_iter()
        .filter_map(|name| std::env::var(name).ok())
        .find(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".into());
    let platform = match std::env::consts::OS {
        "windows" => "win32",
        "macos" => "darwin",
        platform => platform,
    };
    Ok(Zeroizing::new(format!(
        "zcode-credential-fallback:{platform}:{home}:{username}"
    )))
}

pub(crate) fn decrypt(value: &str, explicit: Option<&str>) -> Result<String, ()> {
    let Some(body) = value.strip_prefix("enc:v1:") else {
        return Ok(value.to_owned());
    };
    let mut parts = body.split('.');
    let nonce = URL_SAFE_NO_PAD
        .decode(parts.next().ok_or(())?)
        .map_err(|_| ())?;
    let tag = URL_SAFE_NO_PAD
        .decode(parts.next().ok_or(())?)
        .map_err(|_| ())?;
    let mut ciphertext = URL_SAFE_NO_PAD
        .decode(parts.next().ok_or(())?)
        .map_err(|_| ())?;
    if parts.next().is_some() || nonce.len() != 12 || tag.len() != 16 {
        return Err(());
    }
    ciphertext.extend_from_slice(&tag);
    let secret = secret(explicit)?;
    let key = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(secret.as_bytes())));
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| ())?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|_| ())?,
    );
    Ok(std::str::from_utf8(&plaintext).map_err(|_| ())?.to_owned())
}
