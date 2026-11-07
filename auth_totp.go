package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// RFC 6238 TOTP over the panel login. The secret lives in the settings table
// (vault-encrypted via vaultSecretSettings); challenges and pending setups are
// process memory only, so a restart invalidates both.

const (
	totpSettingSecret   = "totp_secret"
	totpSettingEnabled  = "totp_enabled"
	totpSettingRecovery = "totp_recovery"

	totpDigits      = 6
	totpPeriod      = 30
	totpSecretBytes = 20
	// ±1 step absorbs clock skew and the few seconds a code takes to type.
	totpSkewSteps = 1
	totpIssuer    = "ZCode Proxy"

	challengeTTL      = 5 * time.Minute
	challengeAttempts = 5
	setupTTL          = 10 * time.Minute
	recoveryCodeCount = 10
)

type pendingTOTPSetup struct {
	secret    string
	expiresAt time.Time
}

type loginChallenge struct {
	expiresAt time.Time
	attempts  int
}

// ---- TOTP primitives ----

var totpBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func totpGenerateSecret() (string, error) {
	b := make([]byte, totpSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return totpBase32.EncodeToString(b), nil
}

func totpCodeAt(secret string, t time.Time) (string, error) {
	key, err := totpBase32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/totpPeriod))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%0*d", totpDigits, bin%1_000_000), nil
}

func totpValidate(secret, code string, now time.Time) bool {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return false
	}
	for step := -totpSkewSteps; step <= totpSkewSteps; step++ {
		want, err := totpCodeAt(secret, now.Add(time.Duration(step*totpPeriod)*time.Second))
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func totpProvisioningURI(user, secret string) string {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", totpIssuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", totpPeriod))
	return "otpauth://totp/" + url.PathEscape(totpIssuer+":"+user) + "?" + q.Encode()
}

// totpQRDataURI renders the provisioning URI as an inline PNG.
func totpQRDataURI(uri string) (string, error) {
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

// ---- Recovery codes ----

func generateRecoveryCodes() ([]string, error) {
	codes := make([]string, 0, recoveryCodeCount)
	buf := make([]byte, 5) // 40 bits per code, shown as xxxx-xxxx
	for len(codes) < recoveryCodeCount {
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		raw := strings.ToLower(totpBase32.EncodeToString(buf))
		codes = append(codes, raw[:4]+"-"+raw[4:8])
	}
	return codes, nil
}

func normalizeRecoveryCode(code string) string {
	c := strings.ToLower(strings.TrimSpace(code))
	c = strings.ReplaceAll(c, "-", "")
	c = strings.ReplaceAll(c, " ", "")
	// 用户常把 0/o、1/i/l 抄错：统一到 base32 字母表
	c = strings.NewReplacer("0", "o", "1", "l", "i", "l").Replace(c)
	return c
}

func hashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(normalizeRecoveryCode(code)))
	return hex.EncodeToString(sum[:])
}

// ---- Persisted state ----

func (am *AuthManager) totpEnabled() bool {
	if am.db == nil {
		return false
	}
	v, err := am.db.GetSetting(totpSettingEnabled)
	return err == nil && v == "1"
}

func (am *AuthManager) totpSecret() string {
	if am.db == nil {
		return ""
	}
	v, _ := am.db.GetSetting(totpSettingSecret)
	return v
}

func (am *AuthManager) recoveryHashes() []string {
	if am.db == nil {
		return nil
	}
	raw, _ := am.db.GetSetting(totpSettingRecovery)
	if raw == "" {
		return nil
	}
	var hashes []string
	if err := json.Unmarshal([]byte(raw), &hashes); err != nil {
		return nil
	}
	return hashes
}

// consumeRecoveryCode 命中即删除并用一次，避免重放。
func (am *AuthManager) consumeRecoveryCode(code string) bool {
	hashes := am.recoveryHashes()
	if len(hashes) == 0 {
		return false
	}
	want := hashRecoveryCode(code)
	hit := -1
	for i, h := range hashes {
		if subtle.ConstantTimeCompare([]byte(h), []byte(want)) == 1 {
			hit = i
			break
		}
	}
	if hit < 0 {
		return false
	}
	remaining := append(append([]string{}, hashes[:hit]...), hashes[hit+1:]...)
	if enc, err := json.Marshal(remaining); err == nil {
		if err := am.db.SetSetting(totpSettingRecovery, string(enc)); err != nil {
			log.Printf("[auth] failed to persist recovery codes after use: %v", err)
			return false
		}
	}
	log.Printf("[auth] recovery code used, %d left", len(remaining))
	return true
}

// ---- Login challenges ----

func (am *AuthManager) newLoginChallenge() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	now := time.Now()
	am.totpMu.Lock()
	if am.challenges == nil {
		am.challenges = map[string]*loginChallenge{}
	}
	for k, c := range am.challenges {
		if now.After(c.expiresAt) {
			delete(am.challenges, k)
		}
	}
	am.challenges[token] = &loginChallenge{expiresAt: now.Add(challengeTTL)}
	am.totpMu.Unlock()
	return token, nil
}

// takeChallenge 取票并计数；返回 nil 表示票不存在/已过期/尝试次数耗尽。
func (am *AuthManager) takeChallenge(token string) *loginChallenge {
	am.totpMu.Lock()
	defer am.totpMu.Unlock()
	c, ok := am.challenges[token]
	if !ok || time.Now().After(c.expiresAt) {
		delete(am.challenges, token)
		return nil
	}
	c.attempts++
	if c.attempts > challengeAttempts {
		delete(am.challenges, token)
		return nil
	}
	return c
}

func (am *AuthManager) dropChallenge(token string) {
	am.totpMu.Lock()
	delete(am.challenges, token)
	am.totpMu.Unlock()
}

// ---- Handlers ----

// HandleLoginInfo GET /api/auth/login-info（免认证）
// 只回报"初始口令是否仍在使用"，供登录页决定是否显示首启提示。
// 这确实向未认证客户端暴露了轮换状态；换来的是提示不会在改密后继续误导，
// 而部署本身位于内网 vhost 之后。
func (am *AuthManager) HandleLoginInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"initial_password": am.isDefaultPassword(),
		"totp_enabled":     am.totpEnabled(),
	})
}

// HandleLoginTOTP POST /api/login/totp（免认证，凭一次性挑战票）
func (am *AuthManager) HandleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Challenge == "" || strings.TrimSpace(body.Code) == "" {
		writeAPIError(w, http.StatusBadRequest, "challenge and code are required")
		return
	}
	// 每次挑战只给 5 次机会，但持有口令的攻击者可反复换票重试：
	// 第二因素必须有自己的退避，否则 6 位码在换票之间可被持续爆破。
	rateKey := "2fa|" + clientIP(r)
	if wait := am.checkLoginRate(rateKey); wait > 0 {
		writeAPIError(w, http.StatusTooManyRequests,
			fmt.Sprintf("验证尝试过于频繁，请 %d 秒后再试", int(wait.Seconds())+1))
		return
	}
	if am.takeChallenge(body.Challenge) == nil {
		writeAPIError(w, http.StatusUnauthorized, "2FA challenge expired, sign in again")
		return
	}
	secret := am.totpSecret()
	ok := secret != "" && totpValidate(secret, body.Code, time.Now())
	if !ok {
		// 恢复码是第二因素的长效备份，同样只允许在票的有效期内使用
		ok = am.consumeRecoveryCode(body.Code)
	}
	if !ok {
		am.recordLoginFail(rateKey)
		writeAPIError(w, http.StatusUnauthorized, "invalid verification code")
		return
	}
	am.clearLoginFail(rateKey)
	am.dropChallenge(body.Challenge)
	user := am.adminUser()
	token := am.issueSession(user)
	setSessionCookie(w, r, token)
	log.Printf("[auth] login success (2FA): user=%s", user)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"username": user,
	})
}

// HandleTOTPStatus GET /api/auth/totp/status
func (am *AuthManager) HandleTOTPStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":            am.totpEnabled(),
		"recovery_remaining": len(am.recoveryHashes()),
	})
}

// HandleTOTPSetup POST /api/auth/totp/setup
// 只生成待确认 secret：未验证前不落库，半途放弃不会把账号锁死。
func (am *AuthManager) HandleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	secret, err := totpGenerateSecret()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to generate secret")
		return
	}
	uri := totpProvisioningURI(am.adminUser(), secret)
	qr, err := totpQRDataURI(uri)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to render QR code")
		return
	}
	am.totpMu.Lock()
	if am.pendingTOTP == nil {
		am.pendingTOTP = map[string]pendingTOTPSetup{}
	}
	am.pendingTOTP[am.adminUser()] = pendingTOTPSetup{secret: secret, expiresAt: time.Now().Add(setupTTL)}
	am.totpMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"secret":         secret,
		"otpauth_uri":    uri,
		"qr_data_uri":    qr,
		"recovery_codes": nil,
	})
}

// HandleTOTPEnable POST /api/auth/totp/enable
func (am *AuthManager) HandleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	if am.db == nil {
		writeAPIError(w, http.StatusNotImplemented, "2FA requires a database")
		return
	}
	var body struct {
		Code            string `json:"code"`
		CurrentPassword string `json:"current_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	am.totpMu.Lock()
	pending, ok := am.pendingTOTP[am.adminUser()]
	am.totpMu.Unlock()
	if !ok || time.Now().After(pending.expiresAt) {
		writeAPIError(w, http.StatusBadRequest, "setup expired, start again")
		return
	}
	// 口令步进：拿到会话的人不应能悄悄给账号绑定自己的验证器
	rateKey := clientIP(r) + "|totp-enable"
	if wait := am.checkLoginRate(rateKey); wait > 0 {
		writeAPIError(w, http.StatusTooManyRequests,
			fmt.Sprintf("尝试过于频繁，请 %d 秒后再试", int(wait.Seconds())+1))
		return
	}
	if !am.verifyPassword(body.CurrentPassword) {
		am.recordLoginFail(rateKey)
		writeAPIError(w, http.StatusForbidden, "current password incorrect")
		return
	}
	if !totpValidate(pending.secret, body.Code, time.Now()) {
		writeAPIError(w, http.StatusBadRequest, "invalid verification code")
		return
	}
	// 恢复码是两种因素共用的一组。已有（例如先加了 passkey）就保留，
	// 否则启用 TOTP 会静默作废用户已经离线保存的那一份。
	var codes []string
	if len(am.recoveryHashes()) == 0 {
		var err error
		codes, err = am.issueRecoveryCodes()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "failed to store recovery codes")
			return
		}
	}
	if err := am.db.SetSetting(totpSettingSecret, pending.secret); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to store secret")
		return
	}
	if err := am.db.SetSetting(totpSettingEnabled, "1"); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to enable 2FA")
		return
	}
	am.totpMu.Lock()
	delete(am.pendingTOTP, am.adminUser())
	am.totpMu.Unlock()
	am.clearLoginFail(rateKey)
	log.Printf("[auth] 2FA enabled for user=%s", am.adminUser())
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":            true,
		"recovery_codes":     codes,
		"recovery_remaining": len(am.recoveryHashes()),
	})
}

// issueRecoveryCodes 生成并持久化一组恢复码，返回明文（只在调用时展示一次）。
// passkey 与 TOTP 共用：任一因素单独存在时，恢复码都是唯一的人工回退路径。
func (am *AuthManager) issueRecoveryCodes() ([]string, error) {
	codes, err := generateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = hashRecoveryCode(c)
	}
	enc, err := json.Marshal(hashes)
	if err != nil {
		return nil, err
	}
	if err := am.db.SetSetting(totpSettingRecovery, string(enc)); err != nil {
		return nil, err
	}
	return codes, nil
}

// HandleTOTPDisable POST /api/auth/totp/disable
func (am *AuthManager) HandleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	if am.db == nil {
		writeAPIError(w, http.StatusNotImplemented, "2FA requires a database")
		return
	}
	var body struct {
		Code            string `json:"code"`
		CurrentPassword string `json:"current_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	rateKey := clientIP(r) + "|totp-disable"
	if wait := am.checkLoginRate(rateKey); wait > 0 {
		writeAPIError(w, http.StatusTooManyRequests,
			fmt.Sprintf("尝试过于频繁，请 %d 秒后再试", int(wait.Seconds())+1))
		return
	}
	if !am.verifyPassword(body.CurrentPassword) {
		am.recordLoginFail(rateKey)
		writeAPIError(w, http.StatusForbidden, "current password incorrect")
		return
	}
	secret := am.totpSecret()
	if secret == "" || !totpValidate(secret, body.Code, time.Now()) {
		if !am.consumeRecoveryCode(body.Code) {
			writeAPIError(w, http.StatusBadRequest, "invalid verification code")
			return
		}
	}
	for _, key := range []string{totpSettingEnabled, totpSettingSecret, totpSettingRecovery} {
		if err := am.db.SetSetting(key, ""); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "failed to disable 2FA")
			return
		}
	}
	am.clearLoginFail(rateKey)
	log.Printf("[auth] 2FA disabled for user=%s", am.adminUser())
	writeJSON(w, http.StatusOK, map[string]interface{}{"enabled": false})
}
