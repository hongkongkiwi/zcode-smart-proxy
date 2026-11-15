use std::collections::HashMap;

use serde::Deserialize;
use zcode_proxy::vault::Vault;

#[derive(Deserialize)]
struct Fixture {
    public_secrets: HashMap<String, String>,
    decrypt_cases: Vec<DecryptCase>,
    encrypt_cases: Vec<EncryptCase>,
}

#[derive(Deserialize)]
struct DecryptCase {
    id: String,
    secret_id: String,
    value: String,
    plaintext: Option<String>,
    expect_error: bool,
}

#[derive(Deserialize)]
struct EncryptCase {
    id: String,
    secret_id: String,
    input: String,
    expected: String,
    expect_error: bool,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/vault_interop.json")).unwrap()
}

#[test]
fn go_decrypt_fixture() {
    let fixture = fixture();
    assert_eq!(fixture.decrypt_cases.len(), 14);
    for case in &fixture.decrypt_cases {
        let vault = Vault::from_secret(&fixture.public_secrets[&case.secret_id]).unwrap();
        let result = vault.decrypt(&case.value);
        if case.expect_error {
            assert!(result.is_err(), "{}", case.id);
        } else {
            assert_eq!(
                result.unwrap(),
                *case.plaintext.as_ref().unwrap(),
                "{}",
                case.id
            );
        }
    }
}

#[test]
fn source_wrapper_fixture() {
    let fixture = fixture();
    assert_eq!(fixture.encrypt_cases.len(), 4);
    for case in &fixture.encrypt_cases {
        let vault = Vault::from_secret(&fixture.public_secrets[&case.secret_id]).unwrap();
        let result = vault.encrypt(&case.input);
        if case.expect_error {
            assert!(result.is_err(), "{}", case.id);
        } else {
            assert_eq!(result.unwrap(), case.expected, "{}", case.id);
        }
    }
}

#[test]
fn random_nonce_utf8_roundtrip_and_wrong_secret() {
    let vault = Vault::from_secret("密钥 café").unwrap();
    let other = Vault::from_secret("wrong secret").unwrap();
    let plain = "凭证 café e\u{301}\n\0end";
    let first = vault.encrypt(plain).unwrap();
    let second = vault.encrypt(plain).unwrap();
    assert_ne!(first, second);
    assert_ne!(first.split('.').next(), second.split('.').next());
    assert_eq!(vault.decrypt(&first).unwrap(), plain);
    assert_eq!(vault.decrypt(&second).unwrap(), plain);
    assert!(other.decrypt(&first).is_err());
    assert!(other.encrypt(&first).is_err());
}

#[test]
fn secret_validation_and_redacted_errors() {
    assert!(Vault::from_secret("").is_err());
    // Go's environment override accepts whitespace without trimming it.
    let vault = Vault::from_secret(" ").unwrap();
    let ciphertext = vault.encrypt("sensitive plaintext").unwrap();
    assert_eq!(vault.decrypt(&ciphertext).unwrap(), "sensitive plaintext");
    let error = vault.decrypt("vault1:sensitive plaintext").unwrap_err();
    assert!(!error.to_string().contains("sensitive plaintext"));
    assert!(!format!("{error:?}").contains("sensitive plaintext"));
}

#[test]
fn rejects_padded_or_invalid_components() {
    let vault = Vault::from_secret("secret").unwrap();
    let ciphertext = vault.encrypt("plain").unwrap();
    let parts: Vec<_> = ciphertext.split('.').collect();
    for invalid in [
        format!("{}=.{}.{}", parts[0], parts[1], parts[2]),
        format!("{}.{}=.{}", parts[0], parts[1], parts[2]),
        format!("{}.{}.{}=", parts[0], parts[1], parts[2]),
        format!("{}.{}.!", parts[0], parts[1]),
    ] {
        assert!(vault.decrypt(&invalid).is_err());
        assert!(vault.encrypt(&invalid).is_err());
    }
}
