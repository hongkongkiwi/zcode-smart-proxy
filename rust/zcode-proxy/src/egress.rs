//! Global outbound proxy policy. Account-specific routing is reserved for a later packet.

use crate::{state::AppState, store::StoreError};

pub fn validate_proxy_url(value: &str) -> Result<Option<String>, StoreError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let invalid = || StoreError::Vault;
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) || value.contains('\\') {
        return Err(invalid());
    }
    let (_, rest) = value.split_once("://").ok_or_else(invalid)?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if !matches!(&rest[end..], "" | "/") || authority.is_empty() {
        return Err(invalid());
    }
    let host = if let Some((credentials, host)) = authority.split_once('@') {
        if host.contains('@') || credentials.is_empty() {
            return Err(invalid());
        }
        let bytes = credentials.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                if i + 2 >= bytes.len()
                    || !bytes[i + 1].is_ascii_hexdigit()
                    || !bytes[i + 2].is_ascii_hexdigit()
                {
                    return Err(invalid());
                }
                i += 3;
            } else {
                i += 1;
            }
        }
        host
    } else {
        authority
    };
    if host.is_empty() || host.ends_with(':') {
        return Err(invalid());
    }
    let url = reqwest::Url::parse(value).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "http" | "https" | "socks5" | "socks5h")
        || url.host_str().is_none()
        || url.port() == Some(0)
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(Some(value.to_owned()))
}

pub fn display_proxy_url(value: &str) -> Result<String, StoreError> {
    let Some(value) = validate_proxy_url(value)? else {
        return Ok(String::new());
    };
    // Preserve the configured spelling and optional root slash for masked roundtrips.
    let (scheme, rest) = value.split_once("://").ok_or(StoreError::Vault)?;
    Ok(match rest.split_once('@') {
        Some((_, host)) => format!("{scheme}://{host}"),
        None => value,
    })
}

pub fn client_builder(
    state: &AppState,
    _account_id: Option<i64>,
) -> Result<reqwest::ClientBuilder, StoreError> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .min_tls_version(reqwest::tls::Version::TLS_1_2);
    if let Some(value) = validate_proxy_url(&state.setting("upstream_proxy").unwrap_or_default())? {
        let proxy = if value.contains('@') {
            // Reqwest's All(Url) Debug exposes userinfo; Custom's Debug hides its capture.
            reqwest::Proxy::custom(move |_| Some(value.clone()))
        } else {
            reqwest::Proxy::all(value).map_err(|_| StoreError::Vault)?
        };
        builder = builder.proxy(proxy);
    }
    Ok(builder)
}
