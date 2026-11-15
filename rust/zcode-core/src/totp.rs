//! TOTP (RFC 6238, SHA-1, 6 digits, 30s step) + recovery-code handling —
//! the portable half of the Go 2FA wave (WebAuthn stays a deploy-time item:
//! it needs a domain RP and browser ceremony).
//!
//! Login contract parity: when a TOTP secret is enrolled and enabled, the
//! admin login additionally requires a current TOTP code or an unused
//! recovery code.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

// HMAC-SHA1 here is the RFC 6238 wire standard for TOTP — authenticator
// apps (Google Authenticator et al.) require it. Not a general-purpose
// hash choice; do not "upgrade".

fn hotp(secret: &[u8], counter: u64, digits: u32) -> u64 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(&counter.to_be_bytes());
    let sum = mac.finalize().into_bytes();
    let offset = (sum[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([
        sum[offset],
        sum[offset + 1],
        sum[offset + 2],
        sum[offset + 3],
    ]);
    (bin & 0x7fff_ffff) as u64 % 10u64.pow(digits)
}

/// Current TOTP code for a secret at unix time `t` (30s step, 6 digits).
pub fn totp_now(secret: &[u8], t: i64) -> String {
    totp_at(secret, t, 0)
}

/// TOTP with a verification window: checks steps -1, 0, +1 (clock drift
/// tolerance, Go auth wave parity).
pub fn totp_verify(secret: &[u8], t: i64, code: &str) -> bool {
    (-1..=1).any(|w| totp_at(secret, t, w) == code)
}

fn totp_at(secret: &[u8], t: i64, window: i64) -> String {
    let step = ((t + window) / 30).max(0) as u64;
    format!("{:06}", hotp(secret, step, 6))
}

/// Base32 (RFC 4648, no padding) — secrets are distributed in otpauth URLs.
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHA[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHA[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in s.chars() {
        if c == '=' {
            continue;
        }
        let v = ALPHA
            .iter()
            .position(|&a| a == c.to_ascii_uppercase() as u8)? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Generate a new enrollment secret (20 random bytes, base32).
pub fn new_totp_secret() -> String {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut b = [0u8; 20];
    OsRng.fill_bytes(&mut b);
    base32_encode(&b)
}

/// otpauth:// enrollment URL (authenticator apps scan this).
pub fn otpauth_url(secret_b32: &str, email: &str) -> String {
    format!("otpauth://totp/zcode-proxy:{email}?secret={secret_b32}&issuer=zcode-proxy")
}

// ---- recovery codes ----

/// Generate `n` recovery codes (xxxx-xxxx, CSPRNG); returns plaintext codes
/// and their sha256 hashes (storage shape: hashes only, Go parity).
pub fn generate_recovery_codes(n: usize) -> (Vec<String>, Vec<String>) {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut plain = Vec::with_capacity(n);
    let mut hashes = Vec::with_capacity(n);
    for _ in 0..n {
        let mut b = [0u8; 4];
        OsRng.fill_bytes(&mut b);
        let c = format!(
            "{:04x}-{:04x}",
            u16::from_be_bytes([b[0], b[1]]),
            u16::from_be_bytes([b[2], b[3]])
        );
        hashes.push(sha256_hex_code(&c));
        plain.push(c);
    }
    (plain, hashes)
}

fn sha256_hex_code(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())
}

/// Verify a recovery code against the stored hash list; on match returns the
/// updated list minus the consumed code (single-use).
pub fn consume_recovery_code(hashes: &[String], code: &str) -> Option<Vec<String>> {
    let h = sha256_hex_code(code);
    let idx = hashes.iter().position(|x| *x == h)?;
    let mut rest = hashes.to_vec();
    rest.remove(idx);
    Some(rest)
}

/// Settings-value (de)serialization for the recovery hash list.
pub fn recovery_codes_to_json(hashes: &[String]) -> String {
    serde_json::to_string(&hashes).unwrap_or_else(|_| "[]".into())
}

pub fn recovery_codes_from_json(raw: Option<&str>) -> Vec<String> {
    raw.and_then(|r| serde_json::from_str::<serde_json::Value>(r).ok())
        .and_then(|v| v.as_array().cloned())
        .map(|a| {
            a.into_iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B vectors (SHA-1, secret "12345678901234567890"),
    // reduced to 6 digits per this implementation.
    #[test]
    fn rfc6238_vectors() {
        let secret = b"12345678901234567890";
        assert_eq!(totp_now(secret, 59), "287082");
        assert_eq!(totp_now(secret, 1111111109), "081804");
        assert_eq!(totp_now(secret, 1111111111), "050471");
        assert_eq!(totp_now(secret, 1234567890), "005924");
        assert_eq!(totp_now(secret, 2000000000), "279037");
        assert_eq!(totp_now(secret, 20000000000), "353130");
    }

    #[test]
    fn verify_window_tolerates_one_step_drift() {
        let secret = b"12345678901234567890";
        let t = 59i64;
        assert!(totp_verify(secret, t, &totp_now(secret, t)));
        assert!(
            totp_verify(secret, t, &totp_now(secret, t + 30)),
            "next step accepted"
        );
        assert!(!totp_verify(secret, t, "000000"));
    }

    #[test]
    fn base32_round_trip() {
        let enc = base32_encode(b"12345678901234567890");
        assert_eq!(
            base32_decode(&enc).unwrap(),
            b"12345678901234567890".to_vec()
        );
    }

    #[test]
    fn recovery_codes_single_use() {
        let (plain, hashes) = generate_recovery_codes(3);
        assert_eq!(plain.len(), 3);
        assert_eq!(hashes.len(), 3);
        // Correct code consumes exactly itself.
        let rest = consume_recovery_code(&hashes, &plain[0]).unwrap();
        assert_eq!(rest.len(), 2);
        // Replay is rejected.
        assert!(consume_recovery_code(&rest, &plain[0]).is_none());
        // Unknown code rejected.
        assert!(consume_recovery_code(&hashes, "0000-0000").is_none());
        // JSON round trip.
        let raw = recovery_codes_to_json(&hashes);
        assert_eq!(recovery_codes_from_json(Some(&raw)), hashes);
        assert!(recovery_codes_from_json(None).is_empty());
    }

    #[test]
    fn otpauth_url_shape() {
        let u = otpauth_url("ABC234", "a@t");
        assert!(u.starts_with("otpauth://totp/zcode-proxy:a@t?secret=ABC234&issuer=zcode-proxy"));
    }
}
