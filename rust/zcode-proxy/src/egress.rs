//! Outbound proxy policy: account group, default node, global setting, then direct.

use crate::{
    state::AppState,
    store::{self, StoreError},
};

pub(crate) fn validate_node(kind: &str, host: &str, port: i64) -> Result<(), StoreError> {
    if !matches!(kind, "socks5" | "http" | "https") || !(1..=65535).contains(&port) {
        return Err(StoreError::Vault);
    }
    let literal = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = literal.parse::<std::net::IpAddr>() {
        if host.starts_with('[') && ip.is_ipv4() {
            return Err(StoreError::Vault);
        }
        return Ok(());
    }
    let hostname = host.strip_suffix('.').unwrap_or(host);
    if hostname.is_empty()
        || host.len() > 253
        || hostname.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err(StoreError::Vault);
    }
    Ok(())
}

fn node_url(node: &store::ProxyNode, state: &AppState) -> Result<String, StoreError> {
    validate_node(&node.kind, &node.host, node.port)?;
    // Decrypt even without a username: a selected broken credential never changes routing.
    let password = zeroize::Zeroizing::new(state.vault.decrypt(&node.password)?);
    let mut url = reqwest::Url::parse(&format!("{}://localhost", node.kind))
        .map_err(|_| StoreError::Vault)?;
    let host = if node.host.contains(':') && !node.host.starts_with('[') {
        format!("[{}]", node.host)
    } else {
        node.host.clone()
    };
    url.set_host(Some(&host)).map_err(|_| StoreError::Vault)?;
    url.set_port(Some(node.port as u16))
        .map_err(|_| StoreError::Vault)?;
    if !node.username.is_empty() {
        // URL setters escape userinfo delimiters but leave literal percent signs unchanged.
        url.set_username(&node.username.replace('%', "%25"))
            .map_err(|_| StoreError::Vault)?;
        url.set_password(Some(&password.replace('%', "%25")))
            .map_err(|_| StoreError::Vault)?;
    }
    Ok(url.into())
}

fn resolve_proxy(state: &AppState, account_id: Option<i64>) -> Result<Option<String>, StoreError> {
    if let Some(id) = account_id {
        let db = state.db.lock().unwrap();
        let group: String = db.query_row(
            "SELECT account_group FROM accounts WHERE id=?1",
            [id],
            |r| r.get(0),
        )?;
        return resolve_group_proxy(state, &db, &group);
    }
    validate_proxy_url(&state.setting("upstream_proxy").unwrap_or_default())
}

fn resolve_group_proxy(
    state: &AppState,
    db: &rusqlite::Connection,
    group: &str,
) -> Result<Option<String>, StoreError> {
    let nodes = store::list_proxy_nodes(db)?;
    let selected = nodes
        .iter()
        .find(|node| {
            node.enabled
                && !group.is_empty()
                && node
                    .group_name
                    .split(',')
                    .any(|segment| segment.trim() == group)
        })
        .or_else(|| nodes.iter().find(|node| node.enabled && node.is_default));
    if let Some(node) = selected {
        return node_url(node, state).map(Some);
    }
    validate_proxy_url(&state.setting("upstream_proxy").unwrap_or_default())
}

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
    account_id: Option<i64>,
) -> Result<reqwest::ClientBuilder, StoreError> {
    builder_with_proxy(resolve_proxy(state, account_id)?)
}

pub(crate) fn client_builder_for_group(
    state: &AppState,
    group: &str,
) -> Result<reqwest::ClientBuilder, StoreError> {
    // Inference retains its request-start account snapshot across retries and deletion.
    let db = state.db.lock().unwrap();
    builder_with_proxy(resolve_group_proxy(state, &db, group)?)
}

fn builder_with_proxy(value: Option<String>) -> Result<reqwest::ClientBuilder, StoreError> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .min_tls_version(reqwest::tls::Version::TLS_1_2);
    if let Some(value) = value {
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
