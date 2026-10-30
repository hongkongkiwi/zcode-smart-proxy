package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---- 闲时/高速卡形状专属业务码识别 ----

// 语义对齐 zai-org/ZCode offpeak-retry.ts / highspeed.ts：码表形状作用域化，
// 不得全局化（同一批码在其它 bigmodel 接口另有含义）
func TestIsSpecialProtocolBizCode(t *testing.T) {
	cases := []struct {
		name   string
		shape  string
		status int
		text   string
		want   bool
	}{
		{"offpeak queued code", specialProtoOffPeak, 429, `{"code":3105,"msg":"queued"}`, true},
		{"offpeak bare 429 = queue signal", specialProtoOffPeak, 429, `{"error":{"message":"busy"}}`, true},
		{"offpeak ticket expired", specialProtoOffPeak, 400, `{"code":3102,"msg":"ticket unavailable"}`, true},
		{"offpeak ticket wrong state (3.17.1)", specialProtoOffPeak, 400, `{"code":3104,"msg":"invalid off-peak ticket"}`, true},
		{"offpeak window expired (3.17.1)", specialProtoOffPeak, 400, `{"code":3106,"msg":"off-peak active window expired"}`, true},
		{"offpeak legacy 3001 compat", specialProtoOffPeak, 400, `{"code": 3001}`, true},
		{"offpeak eligibility", specialProtoOffPeak, 400, `{"code":3101}`, true},
		{"offpeak idle quota", specialProtoOffPeak, 400, `{"code":3103}`, true},
		{"offpeak long code boundary", specialProtoOffPeak, 400, `{"code":31021}`, false},
		{"offpeak unrelated 400", specialProtoOffPeak, 400, `{"error":{"message":"bad request"}}`, false},
		{"highspeed card expired quoted", specialProtoHighspeed, 400, `{"error":{"provider_code":"3402"}}`, true},
		{"highspeed card expired numeric", specialProtoHighspeed, 400, `{"provider_code": 3402}`, true},
		{"highspeed providerErrorCode spelling", specialProtoHighspeed, 400, `{"providerErrorCode":"3402"}`, true},
		{"highspeed long code boundary", specialProtoHighspeed, 400, `{"provider_code":"34021"}`, false},
		{"highspeed generic biz code not matched", specialProtoHighspeed, 400, `{"code":3402}`, false},
		{"plain shape never special", "", 429, `{"code":3105}`, false},
	}
	for _, c := range cases {
		if got := isSpecialProtocolBizCode(c.shape, c.status, c.text); got != c.want {
			t.Errorf("%s: isSpecialProtocolBizCode(%q,%d) = %v, want %v", c.name, c.shape, c.status, got, c.want)
		}
	}
}

func TestHasProviderCode(t *testing.T) {
	cases := []struct {
		text string
		code string
		want bool
	}{
		{`{"provider_code":"3402"}`, "3402", true},
		{`{"provider_code":3402}`, "3402", true},
		{`{"provider_code": "3402"}`, "3402", true},
		{`{"provider_code":"34021"}`, "3402", false},
		{`{"provider_code":"13402"}`, "3402", false},
		{`{"providerErrorCode":"3402"}`, "3402", true},
		{`{"other":"3402"}`, "3402", false},
		{`{}`, "3402", false},
	}
	for _, c := range cases {
		if got := hasProviderCode(strings.ToLower(c.text), c.code); got != c.want {
			t.Errorf("hasProviderCode(%q,%q) = %v, want %v", c.text, c.code, got, c.want)
		}
	}
}

// ---- forwardOnce 透传分支：形状作用域 + 不惩罚账号 ----

func newSpecialProtoTestAPI(t *testing.T, handler http.HandlerFunc) (*ZCodeAPI, *Account, int64, *atomic.Int32) {
	t.Helper()
	p, db := newPaidTestPool(t)
	a := mkDualAccount("special-proto", StatusActive)
	id, err := db.UpsertAccount(a)
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	cfg := &FileConfig{Upstream: UpstreamURLs{Zai: server.URL, ZaiFallback: server.URL, Bigmodel: server.URL}}
	z := &ZCodeAPI{cfg: cfg, db: db, pool: p, egress: NewEgressProxy(db),
		captcha: NewCaptchaService(cfg, db, "test"),
		routing: &EndpointRouter{snapshot: &routingSnapshot{expiresAt: time.Now().Add(time.Hour)}},
	}
	return z, a, id, &hits
}

func relaySpecialProto(t *testing.T, z *ZCodeAPI, shape string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	z.relay(w, httptest.NewRequest(http.MethodPost, "/v1/messages", nil), &relayCtx{
		provider: "zai", proto: protocolAnthropic, specialProto: shape,
		body: map[string]interface{}{"model": "GLM-5.3", "messages": []interface{}{map[string]interface{}{"role": "user", "content": "hello"}}},
	})
	return w
}

// 400/3102 票据过期：原样透传，账号分毫不动（健康账号不得白计失败/冷却）
func TestOffPeakTicketExpiredPassthrough(t *testing.T) {
	z, _, id, _ := newSpecialProtoTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"code":3102,"msg":"ticket expired"}`)
	})
	w := relaySpecialProto(t, z, specialProtoOffPeak)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("HTTP status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "3102") {
		t.Fatalf("biz code must pass through verbatim, got %s", w.Body.String())
	}
	fresh, err := z.db.GetAccount(id)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.FailCount != 0 || fresh.LastError != "" || fresh.Status != StatusActive || fresh.CoolingUntil != 0 {
		t.Fatalf("ticket expiry must not penalize the account, got fail=%d err=%q status=%s cooling=%d",
			fresh.FailCount, fresh.LastError, fresh.Status, fresh.CoolingUntil)
	}
}

// 429/3105 排队应答：立即透传状态 + Retry-After（客户端按 min(Retry-After,5min)
// 钳制等待后幂等重试），不进代理内重试/冷却/529 聚合
func TestOffPeakQueuedPassthrough(t *testing.T) {
	z, _, id, hits := newSpecialProtoTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "90")
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, `{"code":3105,"msg":"queued"}`)
	})
	w := relaySpecialProto(t, z, specialProtoOffPeak)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("HTTP status = %d, want 429; body=%s", w.Code, w.Body.String())
	}
	if ra := w.Header().Get("Retry-After"); ra != "90" {
		t.Fatalf("Retry-After = %q, want 90", ra)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("upstream hits = %d, want 1 (client owns the queue wait, proxy must not retry)", n)
	}
	fresh, err := z.db.GetAccount(id)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.FailCount != 0 || fresh.CoolingUntil != 0 {
		t.Fatalf("queue-full must not penalize the account, got fail=%d cooling=%d", fresh.FailCount, fresh.CoolingUntil)
	}
}

// 3402 高速卡过期：原样透传（客户端回落原模型），账号不动
func TestHighspeedCardExpiredPassthrough(t *testing.T) {
	z, _, id, _ := newSpecialProtoTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"type":"error","error":{"type":"invalid_request_error","provider_code":"3402","message":"card expired"}}`)
	})
	w := relaySpecialProto(t, z, specialProtoHighspeed)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "3402") {
		t.Fatalf("card expiry must pass through verbatim, got %d %s", w.Code, w.Body.String())
	}
	fresh, err := z.db.GetAccount(id)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.FailCount != 0 || fresh.CoolingUntil != 0 {
		t.Fatalf("card expiry must not penalize the account, got fail=%d cooling=%d", fresh.FailCount, fresh.CoolingUntil)
	}
}

// 对照组：普通形状（无 specialProto）保持既有行为——400 白计失败、429 代理内
// 重试后进入聚合终态。证明码表作用域隔离生效
func TestPlainShapeKeepsLegacyErrorPath(t *testing.T) {
	z, _, id, _ := newSpecialProtoTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"code":3102,"msg":"ticket expired"}`)
	})
	w := relaySpecialProto(t, z, "")
	fresh, err := z.db.GetAccount(id)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.FailCount == 0 || fresh.LastError == "" {
		t.Fatalf("plain-shape 400 must keep the legacy MarkFailed path, got fail=%d err=%q", fresh.FailCount, fresh.LastError)
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("plain-shape 400 verbatim passthrough = %d, want 400; body=%s", w.Code, w.Body.String())
	}

	z2, _, _, hits2 := newSpecialProtoTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, `{"code":3105,"msg":"queued"}`)
	})
	w2 := relaySpecialProto(t, z2, "")
	if n := hits2.Load(); n < 2 {
		t.Fatalf("plain-shape 429 must retry in-proxy (hits=%d, want >=2)", n)
	}
	if w2.Code != 529 {
		t.Fatalf("plain-shape 429 exhaustion should aggregate to 529 overloaded_error, got %d; body=%s", w2.Code, w2.Body.String())
	}
}

// ---- 路由注册与认证 ----

// 闲时推理形状注册到 HandleMessages 且走 API Key 认证；管理面取票端点
// 不得被模型别名吞掉；count_tokens 变体走本地估算（不触发上游真实计费）
func TestOffPeakRouteAndCountTokens(t *testing.T) {
	p, db := newPaidTestPool(t)
	cfg := &FileConfig{}
	z := &ZCodeAPI{cfg: cfg, db: db, pool: p, egress: NewEgressProxy(db),
		captcha: NewCaptchaService(cfg, db, "test")}
	if err := db.SetAPIKey("root-test-key"); err != nil {
		t.Fatal(err)
	}
	am := NewAuthManager(db, "")
	mux := http.NewServeMux()
	registerModelRoutes(mux, z)
	handler := am.Middleware(mux)

	// 未认证 → 401（路由活着且被 API Key 认证拦截，绝不能是未认证模型端点）
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/off-peak/anthropic/v1/messages", strings.NewReader(`{"model":"GLM-5.3","messages":[]}`)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated off-peak inference = %d, want 401; body=%s", w.Code, w.Body.String())
	}

	// 认证后到达 HandleMessages（坏 body 由 validateMessagesBody 拒 400，而非 404/405）
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/off-peak/anthropic/v1/messages", strings.NewReader(`{"model":"GLM-5.3","messages":[]}`))
	req2.Header.Set("x-api-key", "root-test-key")
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("authenticated off-peak inference = %d, want 400 (body validation), got body=%s", w2.Code, w2.Body.String())
	}

	// 管理面取票端点不在模型别名内：不能被 HandleMessages 吞掉（404/401 皆可，唯独不能进推理管线）
	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/off-peak/ticket", strings.NewReader(`{"task_id":"t1"}`))
	req3.Header.Set("x-api-key", "root-test-key")
	handler.ServeHTTP(w3, req3)
	if w3.Code == http.StatusBadRequest && strings.Contains(w3.Body.String(), "messages") {
		t.Fatalf("ticket control endpoint must not be treated as inference, got %d %s", w3.Code, w3.Body.String())
	}

	// count_tokens 变体（别名子树）→ 本地估算 200，绝不能当完整生成计费
	for _, path := range []string{
		"/api/v1/off-peak/anthropic/v1/messages/count_tokens",
		"/api/v1/ultra/anthropic/v1/messages/count_tokens",
		"/api/v1/highspeed/anthropic/v1/messages/count_tokens",
	} {
		w4 := httptest.NewRecorder()
		req4 := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"model":"GLM-5.3","messages":[{"role":"user","content":"hello world"}]}`))
		req4.Header.Set("x-api-key", "root-test-key")
		handler.ServeHTTP(w4, req4)
		if w4.Code != http.StatusOK {
			t.Fatalf("%s = %d, want 200 (local estimate); body=%s", path, w4.Code, w4.Body.String())
		}
		if !strings.Contains(w4.Body.String(), "input_tokens") {
			t.Fatalf("%s response missing input_tokens estimate: %s", path, w4.Body.String())
		}
	}
}
