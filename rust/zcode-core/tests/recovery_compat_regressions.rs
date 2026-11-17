use sha2::{Digest, Sha256};
use zcode_core::{consume_recovery_code, recovery_codes_from_json, recovery_codes_to_json};

fn hash(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

#[test]
fn go_recovery_hashes_accept_go_normalization_and_remain_single_use() {
    // Go auth_totp.go hashes "abcd-oil2" as "abcdoll2", not the displayed code.
    let hashes = vec![hash("abcdoll2"), hash("efgh2345")];
    let stored = recovery_codes_to_json(&hashes);
    let restored = recovery_codes_from_json(Some(&stored));
    assert_eq!(restored, hashes);
    let mut rejected = Vec::new();
    for code in [
        "abcd-oil2",
        "ABCD-OIL2",
        " \tabcd o112 \r\n",
        "\u{2003}ABCD-OIL2\u{2003}",
    ] {
        match consume_recovery_code(&restored, code) {
            Some(rest) => {
                assert_eq!(rest, vec![hash("efgh2345")]);
                assert!(consume_recovery_code(&rest, code).is_none());
                assert_eq!(consume_recovery_code(&rest, "efgh-2345"), Some(vec![]));
            }
            None => rejected.push(code),
        }
    }
    assert!(consume_recovery_code(&restored, "abcd-oil3").is_none());
    assert_eq!(restored, hashes, "verification mutated the input hash list");
    assert!(
        rejected.is_empty(),
        "persisted Go hashes rejected Go-compatible codes: {rejected:?}"
    );
}

#[test]
fn existing_rust_raw_code_hashes_still_work_after_go_compatibility() {
    let hashes = vec![hash("abcd-1234"), hash("ef01-2345")];
    let stored = recovery_codes_to_json(&hashes);
    let restored = recovery_codes_from_json(Some(&stored));
    let rest = consume_recovery_code(&restored, "abcd-1234").unwrap();
    assert_eq!(rest, vec![hash("ef01-2345")]);
    assert!(consume_recovery_code(&rest, "abcd-1234").is_none());
    assert!(consume_recovery_code(&rest, "PUBLIC-not-a-recovery-code").is_none());
    assert_eq!(consume_recovery_code(&rest, "ef01-2345"), Some(vec![]));
    assert_eq!(restored, hashes);
}
