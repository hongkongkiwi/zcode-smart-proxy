package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func newTOTPTestAuth(t *testing.T) (*AuthManager, *DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := NewDB(filepath.Join(dir, "totp-test.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { db.Close(); resetVaultSeed() })
	return NewAuthManager(db, "test-password"), db
}

// TestTOTPAcceptsCurrentAndAdjacentStep 允许 ±1 步偏移（时钟抖动/输入耗时），
// 但必须拒绝窗口外的旧码和任意错误码。
func TestTOTPAcceptsCurrentAndAdjacentStep(t *testing.T) {
	secret, err := totpGenerateSecret()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)

	for _, offset := range []int{-1, 0, 1} {
		at := now.Add(time.Duration(offset*totpPeriod) * time.Second)
		code, err := totpCodeAt(secret, at)
		if err != nil {
			t.Fatalf("code: %v", err)
		}
		if !totpValidate(secret, code, now) {
			t.Fatalf("code from step %+d rejected", offset)
		}
	}

	stale, err := totpCodeAt(secret, now.Add(-3*totpPeriod*time.Second))
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	if totpValidate(secret, stale, now) {
		t.Fatal("code from 3 steps ago accepted")
	}
	if totpValidate(secret, "000000", now) && stale != "000000" {
		t.Skip("random collision with 000000")
	}
	if totpValidate(secret, "12345", now) {
		t.Fatal("short code accepted")
	}
}

// TestTOTPRejectsAnotherSecret 两个独立 secret 的码互不通过。
func TestTOTPRejectsAnotherSecret(t *testing.T) {
	a, _ := totpGenerateSecret()
	b, _ := totpGenerateSecret()
	now := time.Now()
	codeA, err := totpCodeAt(a, now)
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	if totpValidate(b, codeA, now) && a != b {
		t.Fatal("code verified against a different secret")
	}
}

// TestTwoFactorDisabledUntilEnrolled 两个因素都未配置时保持单因子登录。
func TestTwoFactorDisabledUntilEnrolled(t *testing.T) {
	am, db := newTOTPTestAuth(t)
	if am.twoFactorEnabled() {
		t.Fatal("2FA enabled on a fresh database")
	}
	if got := am.twoFactorMethods(); len(got) != 0 {
		t.Fatalf("methods = %v, want none", got)
	}

	if err := db.SetSetting(totpSettingEnabled, "1"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !am.twoFactorEnabled() {
		t.Fatal("TOTP enabled but twoFactorEnabled false")
	}
	if got := am.twoFactorMethods(); len(got) != 1 || got[0] != "totp" {
		t.Fatalf("methods = %v, want [totp]", got)
	}

	// passkey 单独存在也算启用了第二因素
	if err := db.SetSetting(totpSettingEnabled, ""); err != nil {
		t.Fatalf("disable: %v", err)
	}
	pk := []storedPasskey{{Credential: webauthn.Credential{ID: []byte{1}}, Label: "test"}}
	raw, _ := json.Marshal(pk)
	if err := db.SetSetting(passkeySettingCredentials, string(raw)); err != nil {
		t.Fatalf("store passkey: %v", err)
	}
	if !am.twoFactorEnabled() {
		t.Fatal("passkey stored but twoFactorEnabled false")
	}
	if got := am.twoFactorMethods(); len(got) != 1 || got[0] != "passkey" {
		t.Fatalf("methods = %v, want [passkey]", got)
	}
}

// TestRecoveryCodeIsSingleUse 恢复码用一次即失效，其余保持可用。
func TestRecoveryCodeIsSingleUse(t *testing.T) {
	am, _ := newTOTPTestAuth(t)
	codes, err := generateRecoveryCodes()
	if err != nil {
		t.Fatalf("codes: %v", err)
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = hashRecoveryCode(c)
	}
	enc, _ := json.Marshal(hashes)
	// 恢复码是 vault 机密键，必须走 SetSetting 加密写入
	if err := am.db.SetSetting(totpSettingRecovery, string(enc)); err != nil {
		t.Fatalf("store: %v", err)
	}
	if n := len(am.recoveryHashes()); n != len(codes) {
		t.Fatalf("stored %d hashes, want %d", n, len(codes))
	}
	if !am.consumeRecoveryCode(codes[0]) {
		t.Fatal("valid recovery code rejected")
	}
	if am.consumeRecoveryCode(codes[0]) {
		t.Fatal("recovery code accepted twice")
	}
	if n := len(am.recoveryHashes()); n != len(codes)-1 {
		t.Fatalf("%d codes left, want %d", n, len(codes)-1)
	}
}

// TestLoginChallengeExpiryAndAttempts 挑战票一次性、有尝试上限。
func TestLoginChallengeExpiryAndAttempts(t *testing.T) {
	am, _ := newTOTPTestAuth(t)
	token, err := am.newLoginChallenge()
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	if !am.peekChallenge(token) {
		t.Fatal("fresh challenge not valid")
	}
	for i := 1; i <= challengeAttempts; i++ {
		if am.takeChallenge(token) == nil {
			t.Fatalf("attempt %d rejected before the cap", i)
		}
	}
	if am.takeChallenge(token) != nil {
		t.Fatal("challenge accepted past the attempt cap")
	}
	if am.peekChallenge(token) {
		t.Fatal("exhausted challenge still valid")
	}
}

// TestLoginTOTPHandlerCompletesSession 口令步骤发出的票 + 正确验证码 → 会话 cookie。
func TestLoginTOTPHandlerCompletesSession(t *testing.T) {
	am, db := newTOTPTestAuth(t)
	secret, err := totpGenerateSecret()
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	if err := db.SetSetting(totpSettingSecret, secret); err != nil {
		t.Fatalf("store secret: %v", err)
	}
	if err := db.SetSetting(totpSettingEnabled, "1"); err != nil {
		t.Fatalf("enable: %v", err)
	}

	// 口令步骤：启用 2FA 时不发会话，只发票
	loginBody := `{"username":"admin","password":"test-password"}`
	rec := httptest.NewRecorder()
	am.HandleLogin(rec, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(loginBody)))
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%s", rec.Code, rec.Body.String())
	}
	var loginResp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &loginResp); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	if loginResp["two_factor_required"] != true {
		t.Fatalf("expected two_factor_required, got %v", loginResp)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			t.Fatal("session cookie issued before the second factor")
		}
	}
	challenge, _ := loginResp["challenge"].(string)
	if challenge == "" {
		t.Fatal("no challenge issued")
	}

	code, err := totpCodeAt(secret, time.Now())
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"challenge": challenge, "code": code})
	rec2 := httptest.NewRecorder()
	am.HandleLoginTOTP(rec2, httptest.NewRequest(http.MethodPost, "/api/login/totp", strings.NewReader(string(body))))
	if rec2.Code != http.StatusOK {
		t.Fatalf("totp login status = %d body=%s", rec2.Code, rec2.Body.String())
	}
	var found bool
	for _, c := range rec2.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			found = true
			if !c.HttpOnly {
				t.Fatal("session cookie missing HttpOnly")
			}
		}
	}
	if !found {
		t.Fatal("no session cookie after the second factor")
	}
	// 票是一次性的
	rec3 := httptest.NewRecorder()
	am.HandleLoginTOTP(rec3, httptest.NewRequest(http.MethodPost, "/api/login/totp", strings.NewReader(string(body))))
	if rec3.Code == http.StatusOK {
		t.Fatal("replayed challenge accepted")
	}
}

// TestPasskeyUserHandleStable 改用户名不能让已注册 passkey 失效。
func TestPasskeyUserHandleStable(t *testing.T) {
	am, db := newTOTPTestAuth(t)
	h1, err := am.userHandle()
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if err := db.SetAdminUser("renamed-admin"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	h2, err := am.userHandle()
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if base64.StdEncoding.EncodeToString(h1) != base64.StdEncoding.EncodeToString(h2) {
		t.Fatal("user handle changed after rename")
	}
}
