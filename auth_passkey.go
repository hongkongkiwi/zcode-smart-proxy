package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	waproto "github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Passkeys as the preferred second factor. The password is always required
// first; a passkey or a TOTP/recovery code completes the second step, so
// "passkey" here is 2FA, not passwordless login.
//
// Credentials and the stable user handle live in the settings table, which
// vault-encrypts those keys. Ceremony state (SessionData) is process memory:
// a restart mid-ceremony just means starting the ceremony again.

const (
	passkeySettingCredentials = "passkey_credentials"
	passkeySettingUserHandle  = "passkey_user_handle"

	passkeyTicketTTL = 5 * time.Minute
	passkeyRPName    = "ZCode Proxy"
)

type storedPasskey struct {
	Credential webauthn.Credential `json:"credential"`
	Label      string              `json:"label"`
	CreatedAt  time.Time           `json:"created_at"`
}

type passkeyTicket struct {
	kind      string // "register" | "login"
	label     string
	challenge string // login challenge token, for kind=login
	session   *webauthn.SessionData
	expiresAt time.Time
}

// passkeyUser adapts the single admin account to the library's User interface.
type passkeyUser struct {
	id          []byte
	name        string
	credentials []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte                         { return u.id }
func (u *passkeyUser) WebAuthnName() string                       { return u.name }
func (u *passkeyUser) WebAuthnDisplayName() string                { return u.name }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// ---- Persisted state ----

func (am *AuthManager) passkeys() []storedPasskey {
	if am.db == nil {
		return nil
	}
	raw, _ := am.db.GetSetting(passkeySettingCredentials)
	if raw == "" {
		return nil
	}
	var list []storedPasskey
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		log.Printf("[auth] passkey store unreadable: %v", err)
		return nil
	}
	return list
}

func (am *AuthManager) passkeyCount() int { return len(am.passkeys()) }

func (am *AuthManager) savePasskeys(list []storedPasskey) error {
	if len(list) == 0 {
		return am.db.SetSetting(passkeySettingCredentials, "")
	}
	enc, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return am.db.SetSetting(passkeySettingCredentials, string(enc))
}

// userHandle 稳定的 WebAuthn user handle：改用户名不能让已注册的 passkey 失效。
func (am *AuthManager) userHandle() ([]byte, error) {
	if am.db == nil {
		return nil, errors.New("passkeys require a database")
	}
	if v, _ := am.db.GetSetting(passkeySettingUserHandle); v != "" {
		if b, err := base64.StdEncoding.DecodeString(v); err == nil && len(b) > 0 {
			return b, nil
		}
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := am.db.SetSetting(passkeySettingUserHandle, base64.StdEncoding.EncodeToString(b)); err != nil {
		return nil, err
	}
	return b, nil
}

func (am *AuthManager) passkeyUserFor() (*passkeyUser, error) {
	handle, err := am.userHandle()
	if err != nil {
		return nil, err
	}
	list := am.passkeys()
	creds := make([]webauthn.Credential, 0, len(list))
	for _, p := range list {
		creds = append(creds, p.Credential)
	}
	return &passkeyUser{id: handle, name: am.adminUser(), credentials: creds}, nil
}

// ---- Relying party ----

// rpFor 从请求推导 RP ID/origin。面板可能同时经内网域名和本机端口访问，
// 写死一个 origin 会让另一种访问方式直接无法注册/验证。
// RP ID 必须是域名：WebAuthn 规范不接受 IP，按 IP 访问时 passkey 无法使用
// （TOTP 仍然可用），这里给出可操作的提示而不是库的原始校验错误。
func rpFor(r *http.Request) (*webauthn.WebAuthn, error) {
	host := r.Host
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}
	if net.ParseIP(hostname) != nil {
		return nil, fmt.Errorf("passkeys need a domain name (currently reached via IP %s); use a hostname or TOTP", hostname)
	}
	scheme := "https"
	if r.TLS == nil && hostname == "localhost" {
		scheme = "http"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "http" || proto == "https" {
		scheme = proto
	}
	return webauthn.New(&webauthn.Config{
		RPID:          hostname,
		RPDisplayName: passkeyRPName,
		RPOrigins:     []string{scheme + "://" + host},
	})
}

// ---- Ceremony tickets ----

func (am *AuthManager) newPasskeyTicket(t *passkeyTicket) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	t.expiresAt = time.Now().Add(passkeyTicketTTL)
	am.passkeyMu.Lock()
	if am.passkeyTickets == nil {
		am.passkeyTickets = map[string]*passkeyTicket{}
	}
	now := time.Now()
	for k, v := range am.passkeyTickets {
		if now.After(v.expiresAt) {
			delete(am.passkeyTickets, k)
		}
	}
	am.passkeyTickets[token] = t
	am.passkeyMu.Unlock()
	return token, nil
}

// takePasskeyTicket 一次性取票；kind 不匹配视为无效。
func (am *AuthManager) takePasskeyTicket(token, kind string) *passkeyTicket {
	am.passkeyMu.Lock()
	defer am.passkeyMu.Unlock()
	t, ok := am.passkeyTickets[token]
	if !ok || t.kind != kind || time.Now().After(t.expiresAt) {
		delete(am.passkeyTickets, token)
		return nil
	}
	delete(am.passkeyTickets, token)
	return t
}

// peekChallenge 只验证登录挑战票仍然有效，不计尝试次数（begin 不是猜测）。
func (am *AuthManager) peekChallenge(token string) bool {
	am.totpMu.Lock()
	defer am.totpMu.Unlock()
	c, ok := am.challenges[token]
	return ok && time.Now().Before(c.expiresAt)
}

// ---- Two-factor policy ----

func (am *AuthManager) twoFactorEnabled() bool {
	return am.totpEnabled() || am.passkeyCount() > 0
}

// twoFactorMethods 顺序即 UI 的默认顺序：有 passkey 时先推 passkey。
func (am *AuthManager) twoFactorMethods() []string {
	hasPasskey := am.passkeyCount() > 0
	hasTOTP := am.totpEnabled()
	out := make([]string, 0, 2)
	if hasPasskey {
		out = append(out, "passkey")
	}
	if hasTOTP {
		out = append(out, "totp")
	}
	return out
}

// ---- Handlers: management ----

// HandlePasskeyStatus GET /api/auth/passkey/status
func (am *AuthManager) HandlePasskeyStatus(w http.ResponseWriter, r *http.Request) {
	list := am.passkeys()
	items := make([]map[string]interface{}, 0, len(list))
	for _, p := range list {
		items = append(items, map[string]interface{}{
			"id":         base64.RawURLEncoding.EncodeToString(p.Credential.ID),
			"label":      p.Label,
			"created_at": p.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"count": len(list),
		"items": items,
	})
}

// HandlePasskeyRegisterBegin POST /api/auth/passkey/register/begin
// 注册绑定第二因素，因此需要当前口令：仅有会话的人不能给自己加一把钥匙。
func (am *AuthManager) HandlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CurrentPassword string `json:"current_password"`
		Label           string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	rateKey := clientIP(r) + "|passkey-register"
	if wait := am.checkLoginRate(rateKey); wait > 0 {
		writeAPIError(w, http.StatusTooManyRequests,
			fmt.Sprintf("尝试过于频繁，请 %d 秒后再试", int(wait.Seconds())+1))
		return
	}
	if !am.verifyPassword(body.CurrentPassword) {
		am.recordLoginFail(rateKey)
		writeAPIError(w, http.StatusUnauthorized, "current password incorrect")
		return
	}
	wa, err := rpFor(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, err := am.passkeyUserFor()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	options, session, err := wa.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(waproto.AuthenticatorSelection{
			// 第二因素：不要求 resident key，但允许平台验证器
			UserVerification: waproto.VerificationPreferred,
		}),
		webauthn.WithExclusions(credentialsDescriptors(user.credentials)),
	)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to start registration: "+err.Error())
		return
	}
	label := strings.TrimSpace(body.Label)
	if label == "" {
		label = "Passkey"
	}
	ticket, err := am.newPasskeyTicket(&passkeyTicket{kind: "register", label: label, session: session})
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to start registration")
		return
	}
	am.clearLoginFail(rateKey)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ticket":  ticket,
		"options": options,
	})
}

// HandlePasskeyRegisterFinish POST /api/auth/passkey/register/finish?ticket=...
func (am *AuthManager) HandlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	ticket := am.takePasskeyTicket(r.URL.Query().Get("ticket"), "register")
	if ticket == nil {
		writeAPIError(w, http.StatusBadRequest, "registration expired, start again")
		return
	}
	wa, err := rpFor(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, err := am.passkeyUserFor()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cred, err := wa.FinishRegistration(user, *ticket.session, r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "registration failed: "+err.Error())
		return
	}
	list := am.passkeys()
	for _, p := range list {
		if string(p.Credential.ID) == string(cred.ID) {
			writeAPIError(w, http.StatusConflict, "this authenticator is already registered")
			return
		}
	}
	label := ticket.label
	list = append(list, storedPasskey{Credential: *cred, Label: label, CreatedAt: time.Now()})
	if err := am.savePasskeys(list); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to store passkey")
		return
	}
	log.Printf("[auth] passkey registered (label=%q), %d total", label, len(list))
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "count": len(list)})
}

// HandlePasskeyDelete POST /api/auth/passkey/delete
func (am *AuthManager) HandlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID              string `json:"id"`
		CurrentPassword string `json:"current_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	rateKey := clientIP(r) + "|passkey-delete"
	if wait := am.checkLoginRate(rateKey); wait > 0 {
		writeAPIError(w, http.StatusTooManyRequests,
			fmt.Sprintf("尝试过于频繁，请 %d 秒后再试", int(wait.Seconds())+1))
		return
	}
	if !am.verifyPassword(body.CurrentPassword) {
		am.recordLoginFail(rateKey)
		writeAPIError(w, http.StatusUnauthorized, "current password incorrect")
		return
	}
	list := am.passkeys()
	kept := make([]storedPasskey, 0, len(list))
	found := false
	for _, p := range list {
		if base64.RawURLEncoding.EncodeToString(p.Credential.ID) == body.ID {
			found = true
			continue
		}
		kept = append(kept, p)
	}
	if !found {
		writeAPIError(w, http.StatusNotFound, "passkey not found")
		return
	}
	if err := am.savePasskeys(kept); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to delete passkey")
		return
	}
	am.clearLoginFail(rateKey)
	log.Printf("[auth] passkey deleted, %d left", len(kept))
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "count": len(kept)})
}

// ---- Handlers: login ceremony (public) ----

// HandlePasskeyLoginBegin POST /api/login/passkey/begin {challenge}
// 必须持有口令步骤发出的一次性挑战票：passkey 是第二因素，不能单独登录。
func (am *AuthManager) HandlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Challenge string `json:"challenge"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !am.peekChallenge(body.Challenge) {
		writeAPIError(w, http.StatusUnauthorized, "2FA challenge expired, sign in again")
		return
	}
	user, err := am.passkeyUserFor()
	if err != nil || len(user.credentials) == 0 {
		writeAPIError(w, http.StatusBadRequest, "no passkey registered")
		return
	}
	wa, err := rpFor(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	options, session, err := wa.BeginLogin(user,
		webauthn.WithAllowedCredentials(credentialsDescriptors(user.credentials)),
		webauthn.WithUserVerification(waproto.VerificationPreferred),
	)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to start passkey login: "+err.Error())
		return
	}
	ticket, err := am.newPasskeyTicket(&passkeyTicket{kind: "login", challenge: body.Challenge, session: session})
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to start passkey login")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ticket":  ticket,
		"options": options,
	})
}

// HandlePasskeyLoginFinish POST /api/login/passkey/finish?ticket=...
func (am *AuthManager) HandlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	ticket := am.takePasskeyTicket(r.URL.Query().Get("ticket"), "login")
	if ticket == nil {
		writeAPIError(w, http.StatusBadRequest, "passkey ceremony expired, start again")
		return
	}
	if !am.peekChallenge(ticket.challenge) {
		writeAPIError(w, http.StatusUnauthorized, "2FA challenge expired, sign in again")
		return
	}
	wa, err := rpFor(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, err := am.passkeyUserFor()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cred, err := wa.FinishLogin(user, *ticket.session, r)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, "passkey verification failed")
		return
	}
	if cred.Authenticator.CloneWarning {
		writeAPIError(w, http.StatusUnauthorized, "authenticator reported a cloned credential")
		return
	}
	// 写回计数器：防重放/克隆检测依赖每次成功登录后的 signCount
	list := am.passkeys()
	for i := range list {
		if string(list[i].Credential.ID) == string(cred.ID) {
			list[i].Credential = *cred
			break
		}
	}
	if err := am.savePasskeys(list); err != nil {
		log.Printf("[auth] failed to persist passkey counter: %v", err)
	}
	am.dropChallenge(ticket.challenge)
	name := am.adminUser()
	token := am.issueSession(name)
	setSessionCookie(w, r, token)
	log.Printf("[auth] login success (passkey): user=%s", name)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"username": name,
	})
}

func credentialsDescriptors(creds []webauthn.Credential) []waproto.CredentialDescriptor {
	out := make([]waproto.CredentialDescriptor, 0, len(creds))
	for i := range creds {
		out = append(out, creds[i].Descriptor())
	}
	return out
}
