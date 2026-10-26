package main

// 2026-10-26 comprehensive-review 回归测试（三轮评审：数据面 / 安全 / 并发）。
// 每条对应一个已分类并修复的发现；修复方不得删除，只允许改生产代码让它们变绿。

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---- M1：streamResponses 的 sawStop 死代码（start→stop 零内容块被洗成
// response.completed）----

func TestStreamResponsesEmptyContentBlocksFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"model\":\"GLM-5.3\",\"usage\":{\"input_tokens\":5}}}\n\n")
		io.WriteString(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":0}}\n\n")
		io.WriteString(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	}))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("upstream get: %v", err)
	}
	defer resp.Body.Close()

	db := newCompletionsTestDB(t)
	z := &ZCodeAPI{db: db}
	w := httptest.NewRecorder()
	z.streamResponses(w, nil, resp, "my-model", &Account{}, httptest.NewRequest(http.MethodPost, "/v1/responses", nil), []byte(`{}`), time.Now())

	out := w.Body.String()
	if strings.Contains(out, "response.completed") {
		t.Fatalf("start→stop empty-content stream must not synthesize a completed response: %q", out)
	}
	if !strings.Contains(out, "event: response.failed") {
		t.Fatalf("empty-content stream must emit response.failed, got: %q", out)
	}
}

// ---- F2：aggregateAnthropicStream 的 toolTruncated 死分支（截断参数被洗成
// {} 空参成功）----

func truncatedToolStream(t *testing.T) ([]byte, *StreamUsage, error) {
	sse := strings.Join([]string{
		"event: message_start",
		`data: {"type":"message_start","message":{"id":"m","model":"GLM-5.3","usage":{"input_tokens":9}}}`,
		"",
		"event: content_block_start",
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"tu_1","name":"edit_file","input":{}}}`,
		"",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"file\": \"/tmp/x\""}}`,
		"",
		"event: content_block_stop",
		`data: {"type":"content_block_stop","index":0}`,
		"",
		"event: message_delta",
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":4}}`,
		"",
		"event: message_stop",
		`data: {"type":"message_stop"}`,
		"",
	}, "\n")
	return aggregateAnthropicStream(strings.NewReader(sse))
}

func TestAggregateTruncatedToolArgsFail(t *testing.T) {
	raw, _, err := truncatedToolStream(t)
	if err == nil {
		t.Fatalf("truncated tool args must fail the aggregate, got success: %s", raw)
	}
	if !strings.Contains(err.Error(), "tool arguments truncated") {
		t.Fatalf("error = %v, want tool-arguments-truncated", err)
	}
}

func TestAggregateNullToolArgsTolerated(t *testing.T) {
	// 字面量 null（合法 JSON）：仍容忍为空对象，不得误报截断
	sse := strings.Join([]string{
		"event: message_start",
		`data: {"type":"message_start","message":{"id":"m","model":"GLM-5.3","usage":{"input_tokens":9}}}`,
		"",
		"event: content_block_start",
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"tu_1","name":"ping","input":{}}}`,
		"",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"null"}}`,
		"",
		"event: content_block_stop",
		`data: {"type":"content_block_stop","index":0}`,
		"",
		"event: message_delta",
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":1}}`,
		"",
		"event: message_stop",
		`data: {"type":"message_stop"}`,
		"",
	}, "\n")
	raw, _, err := aggregateAnthropicStream(strings.NewReader(sse))
	if err != nil {
		t.Fatalf("null tool args must stay tolerated, got: %v", err)
	}
	var msg map[string]interface{}
	if json.Unmarshal(raw, &msg) != nil {
		t.Fatalf("aggregated body not JSON")
	}
}

// ---- L3：错误信封先于空体判定（{"code":1302} 不再冷却健康账号）----

func TestErrorEnvelopeBeatsEmptyBody(t *testing.T) {
	if !isErrorEnvelope([]byte(`{"code":1302,"msg":"rate"}`)) {
		t.Fatalf("1302 envelope must classify as error envelope")
	}
	if isEmptyMessageBody([]byte(`{"code":1302,"msg":"rate"}`)) {
		t.Fatalf("error envelope must not be classified as empty message body")
	}
	// 真·空 message 不受换序影响
	if !isEmptyMessageBody([]byte(`{"type":"message","content":[]}`)) {
		t.Fatalf("genuinely empty message must still classify as empty")
	}
	if isErrorEnvelope([]byte(`{"type":"message","content":[]}`)) {
		t.Fatalf("empty message must not classify as error envelope")
	}
}

// 1005 耗尽信封（2xx + code:1005）：走耗尽分级 + 换号，绝不能写终态错误——
// 部署后实测回归：终态化会砍断 free 侧耗尽的付费回退链，客户端直接吃 502
func TestQuotaExhaustedEnvelopeFailsOver(t *testing.T) {
	z, _, id, hits := newSpecialProtoTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"code":1005,"msg":"exceed quota limit","type":"error"}`)
	})
	w := httptest.NewRecorder()
	z.relay(w, httptest.NewRequest(http.MethodPost, "/v1/messages", nil), &relayCtx{
		provider: "zai", proto: protocolAnthropic,
		body: map[string]interface{}{"model": "GLM-5.3", "messages": []interface{}{map[string]interface{}{"role": "user", "content": "hello"}}},
	})
	fresh, err := z.db.GetAccount(id)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Status != StatusExhausted {
		t.Fatalf("account status = %s, want exhausted (quota envelope must feed the exhaustion ladder)", fresh.Status)
	}
	if strings.Contains(w.Body.String(), "1005") {
		t.Fatalf("envelope must not be written terminally to the client: %s", w.Body.String())
	}
	if n := hits.Load(); n != 2 {
		t.Fatalf("upstream hits = %d, want 2 (free attempt + paid fallback on the same mock)", n)
	}
	if !isExhaustedError(200, `{"code":1005,"msg":"exceed quota limit"}`) {
		t.Fatalf("1005 exceed-quota-limit body must classify as exhaustion")
	}
}

// ---- M1(security)：同站 CSRF 闸（同 host 异端口 Origin 拒绝；无 Origin 客户端不受影响）----

func TestAdminCSRFOriginGate(t *testing.T) {
	am, db := newAuthFixtures(t)
	hash, err := hashPassword("pw-csrf")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetPasswordHash(hash); err != nil {
		t.Fatal(err)
	}
	reached := false
	handler := am.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	token, _, wait := am.Login("admin", "pw-csrf", "10.0.0.9")
	if wait != 0 || token == "" {
		t.Fatalf("login failed: token=%q wait=%v", token, wait)
	}

	post := func(origin string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(`{"prompt_cache_breakpoint":"1"}`))
		r.Host = "127.0.0.1:8687" // httptest 默认 example.com；同源判定按 Host 比
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		handler.ServeHTTP(w, r)
		return w
	}

	// 同 host 异端口（SameSite 不隔离的攻击面）：403，handler 不得执行
	if w := post("http://127.0.0.1:9999"); w.Code != http.StatusForbidden || reached {
		t.Fatalf("cross-port same-site Origin must be rejected 403, got %d reached=%v", w.Code, reached)
	}
	// 同源（含端口一致）：放行
	if w := post("http://127.0.0.1:8687"); w.Code != http.StatusOK || !reached {
		t.Fatalf("same-origin request must pass, got %d reached=%v", w.Code, reached)
	}
	// 无 Origin（curl/SDK 等非浏览器客户端）：放行
	reached = false
	if w := post(""); w.Code != http.StatusOK || !reached {
		t.Fatalf("origin-less non-browser request must pass, got %d reached=%v", w.Code, reached)
	}
	// 畸形 Origin：拒绝
	if w := post("http://[bad"); w.Code != http.StatusForbidden {
		t.Fatalf("malformed Origin must be rejected, got %d", w.Code)
	}
}

// ---- L5：客户端断开打断取卡不得设置 lane 静默期 ----

func TestHighspeedDrawCancelNoBlock(t *testing.T) {
	z, id, draws, _, _ := newHighspeedLaneAPI(t, okDraw("hsc_cancel"), sseMessages(nil), relayOK)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 模拟取卡中途客户端断开
	if _, ok := z.highspeedCardFor(ctx, mustAccount(t, z, id), "GLM-5.1-Highspeed"); ok {
		t.Fatalf("canceled draw must not return a card")
	}
	z.hsMu.Lock()
	blocked := z.hsDrawBlockUntil[id].After(time.Now())
	z.hsMu.Unlock()
	if blocked {
		t.Fatalf("client-cancel during draw must not set the lane silence window")
	}
	if n := draws.Load(); n != 0 {
		// 已取消的 ctx 在请求发出前就会失败：服务端 0 命中即正确路径
		t.Fatalf("draw hits = %d, want 0 (canceled ctx fails pre-flight)", n)
	}
}

func mustAccount(t *testing.T, z *ZCodeAPI, id int64) *Account {
	t.Helper()
	a, err := z.db.GetAccount(id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// ---- L7：count_tokens 图片按真实像素尺寸计 ----

func TestCountTokensImageDimensions(t *testing.T) {
	// PNG IHDR：4K 截图 3840x2160 → 长边压 1568 → (1568*882)/750 ≈ 1844，
	// 远超旧 flat 1500（低估方向即本修复目标）
	png := append([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A},
		make([]byte, 8)...) // IHDR 前的 length/type
	png = append(png, 0, 0, 15, 0, 0, 0, 8, 112) // w=3840 h=2160 大端高字节
	w, h := imagePixelDimensions(png)
	if w != 3840 || h != 2160 {
		t.Fatalf("png dims = %dx%d, want 3840x2160", w, h)
	}
	tok := imageTokensFromDimensions(w, h)
	if tok < 1500 {
		t.Fatalf("4K image tokens = %d, must exceed the flat floor", tok)
	}
	// 非 PNG/JPEG 头：回落 0,0 → 调用方走固定估值
	if w, h := imagePixelDimensions([]byte("not an image")); w != 0 || h != 0 {
		t.Fatalf("garbage header must return 0,0, got %dx%d", w, h)
	}
}

// ---- response_format（JSON mode）映射 ----

func TestOpenAIResponseFormatMapping(t *testing.T) {
	out, err := openaiToAnthropic(map[string]interface{}{
		"model": "GLM-5.3",
		"response_format": map[string]interface{}{
			"type": "json_schema",
			"json_schema": map[string]interface{}{
				"schema": map[string]interface{}{"type": "object"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	oc, _ := out["output_config"].(map[string]interface{})
	if oc == nil {
		t.Fatalf("json_schema response_format must map to output_config, got %v", out)
	}
	if f, _ := oc["format"].(map[string]interface{}); f == nil || f["type"] != "json_schema" {
		t.Fatalf("format = %v, want json_schema shape", oc["format"])
	}
	out2, _ := openaiToAnthropic(map[string]interface{}{
		"model":           "GLM-5.3",
		"response_format": map[string]interface{}{"type": "json_object"},
	})
	oc2, _ := out2["output_config"].(map[string]interface{})
	if oc2 == nil {
		t.Fatalf("json_object response_format must map to output_config")
	}
	// 文本模式（默认）不得凭空挂 output_config
	out3, _ := openaiToAnthropic(map[string]interface{}{"model": "GLM-5.3"})
	if _, has := out3["output_config"]; has {
		t.Fatalf("no response_format must not produce output_config")
	}
}
