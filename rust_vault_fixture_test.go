package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const rustVaultFixturePath = "rust/zcode-proxy/tests/fixtures/vault_interop.json"

// These are deliberately public test secrets, never credentials or live keyfile contents.
var rustVaultPublicSecrets = map[string]string{
	"public_hex_secret":   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	"public_utf8_secret":  "PUBLIC TEST ONLY: 密钥 café",
	"public_wrong_secret": "PUBLIC TEST ONLY: deliberately wrong vault key",
}

type rustVaultFixtureCase struct {
	ID          string  `json:"id"`
	SecretID    string  `json:"secret_id"`
	Value       string  `json:"value"`
	Plaintext   *string `json:"plaintext,omitempty"`
	ExpectError bool    `json:"expect_error"`
	Nonce       string  `json:"nonce_b64url,omitempty"`
	Tag         string  `json:"tag_b64url,omitempty"`
	Ciphertext  *string `json:"ciphertext_b64url,omitempty"`
}

type rustVaultEncryptCase struct {
	ID          string `json:"id"`
	SecretID    string `json:"secret_id"`
	Input       string `json:"input"`
	Expected    string `json:"expected"`
	ExpectError bool   `json:"expect_error"`
}

type rustVaultFixture struct {
	Notice            string                 `json:"notice"`
	Format            string                 `json:"format"`
	KeyDerivation     string                 `json:"key_derivation"`
	Producer          string                 `json:"producer"`
	Regenerate        string                 `json:"regenerate"`
	Verify            string                 `json:"verify"`
	SourceRevision    string                 `json:"source_revision"`
	SourceSHA256      map[string]string      `json:"source_sha256"`
	Secrets           map[string]string      `json:"public_secrets"`
	DerivedKeyHex     map[string]string      `json:"derived_key_hex"`
	DecryptCases      []rustVaultFixtureCase `json:"decrypt_cases"`
	EncryptValidation string                 `json:"encrypt_cases_validation"`
	EncryptCases      []rustVaultEncryptCase `json:"encrypt_cases"`
}

func TestRustVaultFixture(t *testing.T) {
	if os.Getenv("UPDATE_RUST_VAULT_FIXTURE") == "1" {
		fixture := newRustVaultFixture(t)
		raw, err := json.MarshalIndent(fixture, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(rustVaultFixturePath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rustVaultFixturePath, append(raw, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}

	raw, err := os.ReadFile(rustVaultFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var fixture rustVaultFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.DecryptCases) == 0 {
		t.Fatal("fixture has no decrypt cases")
	}
	for _, tc := range fixture.DecryptCases {
		t.Run(tc.ID, func(t *testing.T) {
			secret, exists := fixture.Secrets[tc.SecretID]
			if !exists {
				t.Fatalf("unknown public secret %q", tc.SecretID)
			}
			value := tc.Value
			if strings.HasPrefix(value, "vault1:") {
				// This is vault.go's envelope mapping, not an independent crypto implementation.
				value = "enc:v1:" + strings.TrimPrefix(value, "vault1:")
			}
			got, err := DecryptCredential(value, secret)
			if tc.ExpectError {
				if err == nil {
					t.Fatal("expected malformed or unauthenticated ciphertext to fail")
				}
				return
			}
			if err != nil {
				t.Fatalf("production Go decrypt: %v", err)
			}
			if tc.Plaintext == nil || got != *tc.Plaintext {
				t.Fatalf("unexpected plaintext %q", got)
			}
			if tc.Ciphertext != nil {
				want := "vault1:" + tc.Nonce + "." + tc.Tag + "." + *tc.Ciphertext
				if tc.Value != want {
					t.Fatal("encoded nonce/tag/ciphertext do not match the envelope")
				}
				for i, part := range []string{tc.Nonce, tc.Tag, *tc.Ciphertext} {
					decoded, err := base64.RawURLEncoding.DecodeString(part)
					if err != nil {
						t.Fatalf("component %d is not unpadded base64url: %v", i, err)
					}
					if i == 0 && len(decoded) != 12 || i == 1 && len(decoded) != 16 {
						t.Fatalf("component %d has wrong byte length %d", i, len(decoded))
					}
				}
			}
		})
	}
	t.Logf("public fixture SHA-256: %x", sha256.Sum256(raw))
}

func newRustVaultFixture(t *testing.T) rustVaultFixture {
	t.Helper()
	command := "go test -count=1 -run '^TestRustVaultFixture$' -v credential_crypto.go rust_vault_fixture_test.go"
	f := rustVaultFixture{
		Notice:            "PUBLIC SYNTHETIC TEST DATA ONLY. All secrets, nonces, tags and plaintexts may be published. Never use these keys outside tests.",
		Format:            "vault1: + unpadded base64url(nonce12) + . + unpadded base64url(tag16) + . + unpadded base64url(ciphertext); AES-256-GCM, no AAD",
		KeyDerivation:     "SHA-256 of the UTF-8 secret string. A 64-hex-character vault.key is the SECRET STRING, not a hex-decoded AES key.",
		Producer:          "EncryptCredential and DecryptCredential from credential_crypto.go; vault.go's prefix-only mapping. OS-random nonces generated once and recorded; no live DB, keyfile or environment secret used.",
		Regenerate:        "UPDATE_RUST_VAULT_FIXTURE=1 " + command,
		Verify:            command,
		SourceRevision:    "8baae3b4549a1235d7150975b5e17a2a16cdd678",
		SourceSHA256:      make(map[string]string),
		Secrets:           rustVaultPublicSecrets,
		DerivedKeyHex:     make(map[string]string),
		EncryptValidation: "Source-derived vaultEncrypt contract from vault.go, not executed by the file-list Go verification command. EncryptCredential itself encrypts empty input; vaultEncrypt returns empty unchanged.",
	}
	for _, path := range []string{"credential_crypto.go", "vault.go"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		f.SourceSHA256[path] = hex.EncodeToString(sumRustVaultFixture(raw))
	}
	for id, secret := range f.Secrets {
		f.DerivedKeyHex[id] = hex.EncodeToString(sumRustVaultFixture([]byte(secret)))
	}
	for _, input := range []struct{ id, secretID, plain string }{
		{"hex_secret_utf8", "public_hex_secret", "PUBLIC TEST ONLY: 凭证 café e\u0301\nline 2\x00end"},
		{"hex_secret_encrypted_empty", "public_hex_secret", ""},
		{"utf8_secret", "public_utf8_secret", "PUBLIC TEST ONLY: synthetic token"},
	} {
		enc, err := EncryptCredential(input.plain, f.Secrets[input.secretID])
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(strings.TrimPrefix(enc, "enc:v1:"), ".")
		if len(parts) != 3 {
			t.Fatal("production Go encrypt returned unexpected envelope")
		}
		plain, ct := input.plain, parts[2]
		f.DecryptCases = append(f.DecryptCases, rustVaultFixtureCase{
			ID: input.id, SecretID: input.secretID,
			Value: "vault1:" + strings.TrimPrefix(enc, "enc:v1:"), Plaintext: &plain,
			Nonce: parts[0], Tag: parts[1], Ciphertext: &ct,
		})
	}
	valid := f.DecryptCases[0]
	tag, err := base64.RawURLEncoding.DecodeString(valid.Tag)
	if err != nil {
		t.Fatal(err)
	}
	tag[0] ^= 1
	badTag := "vault1:" + valid.Nonce + "." + base64.RawURLEncoding.EncodeToString(tag) + "." + *valid.Ciphertext
	f.DecryptCases = append(f.DecryptCases,
		rustVaultFixtureCase{ID: "tampered_tag", SecretID: valid.SecretID, Value: badTag, ExpectError: true},
		rustVaultFixtureCase{ID: "wrong_key", SecretID: "public_wrong_secret", Value: valid.Value, ExpectError: true},
		rustVaultFixtureCase{ID: "malformed_prefix_only", SecretID: valid.SecretID, Value: "vault1:", ExpectError: true},
		rustVaultFixtureCase{ID: "malformed_extra_segment", SecretID: valid.SecretID, Value: valid.Value + ".extra", ExpectError: true},
		rustVaultFixtureCase{ID: "malformed_nonce_encoding", SecretID: valid.SecretID, Value: "vault1:!." + valid.Tag + "." + *valid.Ciphertext, ExpectError: true},
		rustVaultFixtureCase{ID: "malformed_nonce_length", SecretID: valid.SecretID, Value: "vault1:AA." + valid.Tag + "." + *valid.Ciphertext, ExpectError: true},
		rustVaultFixtureCase{ID: "malformed_tag_length", SecretID: valid.SecretID, Value: "vault1:" + valid.Nonce + ".AA." + *valid.Ciphertext, ExpectError: true},
	)
	for _, input := range []struct{ id, value string }{
		{"legacy_plaintext", "PUBLIC TEST ONLY: legacy plaintext 凭证"},
		{"legacy_empty", ""},
		{"legacy_near_prefix", "vault1"},
		{"legacy_other_version", "vault2:legacy public text"},
	} {
		plain := input.value
		f.DecryptCases = append(f.DecryptCases, rustVaultFixtureCase{
			ID: input.id, SecretID: valid.SecretID, Value: input.value, Plaintext: &plain,
		})
	}
	f.EncryptCases = []rustVaultEncryptCase{
		{ID: "empty_passthrough", SecretID: valid.SecretID, Input: "", Expected: ""},
		{ID: "same_key_ciphertext_passthrough", SecretID: valid.SecretID, Input: valid.Value, Expected: valid.Value},
		{ID: "wrong_key_ciphertext_rejected", SecretID: "public_wrong_secret", Input: valid.Value, ExpectError: true},
		{ID: "malformed_ciphertext_rejected", SecretID: valid.SecretID, Input: "vault1:", ExpectError: true},
	}
	return f
}

func sumRustVaultFixture(raw []byte) []byte {
	h := sha256.Sum256(raw)
	return h[:]
}
