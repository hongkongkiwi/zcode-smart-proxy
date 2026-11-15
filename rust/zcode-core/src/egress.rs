//! Phase 3 egress abstraction (ports of pool/egress shapes; live integrations
//! pending).
//!
//! The Go proxy's two hard external dependencies are deliberate trait seams
//! here:
//! - utls Chrome TLS fingerprinting -> a `FingerprintDialer` implementation
//!   (target crate: rquest). The fingerprint payload itself is not a wire
//!   contract the proxy controls; behavior must be validated live against
//!   the upstream WAF before any Rust deployment claims parity.
//! - rod headless-Chromium captcha solving -> a `CaptchaSolver`
//!   implementation (target crate: chromiumoxide), same live-validation
//!   caveat.
//!
//! Default impls below are honest placeholders: dial direct (no fingerprint)
//! and fail captcha solving (the Go path would degrade to risk-cooled
//! JWT-direct too when the browser is unavailable).

/// Per-account egress proxy resolution (Go EgressProxy.ProxyURLForAccount):
/// None = direct. Parsed URL when a proxy applies.
pub fn proxy_url_for_account(
    global_proxy: Option<&str>,
    account_proxy: Option<&str>,
) -> Option<String> {
    account_proxy
        .map(|s| s.to_string())
        .or_else(|| global_proxy.map(|s| s.to_string()))
}

/// TLS-fingerprint dialer seam (Go dialRaw with utls).
pub trait FingerprintDialer: Send + Sync {
    /// True when this dialer can produce a Chrome-fingerprinted connection.
    fn available(&self) -> bool;
}

/// Direct (non-fingerprinted) dialer: the Go fallback path when the
/// fingerprint client is unavailable.
#[derive(Default)]
pub struct DirectDialer;

impl FingerprintDialer for DirectDialer {
    fn available(&self) -> bool {
        false
    }
}

/// Captcha-solver seam (Go captcha.go rod automation).
pub trait CaptchaSolver: Send + Sync {
    /// Solve for the given scene/prefix; None = unavailable or failed
    /// (caller cools the account and retries later; never blocks forever).
    fn solve(&self, scene: &str, prefix: &str) -> Option<String>;
}

/// No-op solver: captcha-required traffic degrades exactly like the Go path
/// with a broken browser (risk-cooled direct), never hangs.
#[derive(Default)]
pub struct NoopSolver;

impl CaptchaSolver for NoopSolver {
    fn solve(&self, _scene: &str, _prefix: &str) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_resolution_account_overrides_global() {
        assert_eq!(
            proxy_url_for_account(Some("socks5://g"), Some("http://a")).as_deref(),
            Some("http://a")
        );
        assert_eq!(
            proxy_url_for_account(Some("socks5://g"), None).as_deref(),
            Some("socks5://g")
        );
        assert_eq!(proxy_url_for_account(None, None), None);
    }

    #[test]
    fn placeholder_seams_fail_closed() {
        assert!(!DirectDialer.available());
        assert!(NoopSolver.solve("scene", "prefix").is_none());
    }
}
