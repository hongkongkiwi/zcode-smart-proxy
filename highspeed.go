package main

// ---- 高速卡通道（Highspeed card lane，v3.16 官方客户端协议，对照 offpeak.go）----
//
// 官方协议（app.asar 3.16.3 out/host 逆向）：
//   控制面（编码计划鉴权头 = buildHighspeedCodingPlanAuthHeaders，非路径签名）：
//     POST {origin}/api/v1/highspeed/draw   body {task_id,provider,model}
//          → {code,msg,data:{card:{card_id,task_id,provider,model,issued_at,expires_at},next_draw_at}}
//          （issued_at/expires_at/next_draw_at 均为 ms epoch）
//     GET  {origin}/api/v1/highspeed/{card_id}/healthy → {card_id,prompt_tokens,...}
//   推理面：POST {origin}/api/v1/highspeed/anthropic/v1/messages
//          头 = 同控制面鉴权 + X-Highspeed-Card-ID；body.model 用卡面模型
//          （官方 modelSelection 即 modelId: card.model，网关可换发高速卡模型）
//   卡过期：provider_code 3402（hasProviderCode）→ 官方按 selection fallback 降级
//
// 本网关语义（官方 SingleAttempt → degrade 对齐）：
//   highspeed_lane_enabled=1 时，打到 /api/v1/highspeed/* 形状的请求先走真实
//   高速卡上游（取卡→带卡转发），任何未写字节的失败原样落回常规通道别名转发
//   （relay 不动账号状态的分支）。lane 失败描述计划侧卡片/资格状态，与账号
//   凭证健康无关——除真实 401/403（先 refresh 后判死，与主路径同规）外一律
//   不惩罚账号。默认关闭：取卡消耗计划侧高速卡资源，与 auto_reset/auto_claim
//   同属资源开关。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// URL 用 var：测试注入 httptest 上游（offPeak* 为 const 无测试面，此处不留同样遗憾）
var (
	highspeedOrigin      = "https://zcode.z.ai"
	highspeedDrawURL     = highspeedOrigin + "/api/v1/highspeed/draw"
	highspeedMessagesURL = highspeedOrigin + "/api/v1/highspeed/anthropic/v1/messages"
)

const (
	highspeedControlTo  = 20 * time.Second // draw 可含服务端排队（hit-after-timeout 场景），比照官方 20s
	highspeedCardMaxTTL = 4 * time.Minute  // 缓存卡面最长持有；expires_at 更早到期时以其为准
	highspeedDrawBlock  = 10 * time.Minute // draw 业务失败（资格/配额）后本 lane 对该账号的静默期
)

// hsBusinessError draw/healthy 的业务码失败（信封 code!=0）：计划侧状态，
// 不是账号凭证问题——调用方只做 lane 级退避，绝不清账号。
// NextDrawAtMs 为上游建议的取卡冷却（ms epoch，0=未给）
type hsBusinessError struct {
	Code         int
	Msg          string
	NextDrawAtMs int64
}

func (e *hsBusinessError) Error() string {
	return fmt.Sprintf("高速卡业务码 %d: %s", e.Code, e.Msg)
}

// highspeedCard 在手卡面（缓存 + 卡内到期时间双约束）
type highspeedCard struct {
	ID          string
	Model       string
	ExpiresAtMs int64
	DrawnAt     time.Time
}

func (c *highspeedCard) valid(now time.Time) bool {
	if c == nil || c.ID == "" {
		return false
	}
	if now.Sub(c.DrawnAt) > highspeedCardMaxTTL {
		return false
	}
	// expires_at<=0（上游未给）按 DrawnAt+TTL 兜底，不视为永不过期
	return c.ExpiresAtMs <= 0 || now.UnixMilli() < c.ExpiresAtMs
}

func (z *ZCodeAPI) highspeedLaneEnabled() bool {
	v, _ := z.db.GetSetting("highspeed_lane_enabled")
	return v == "1" || v == "true"
}

// ---- 控制面：draw ----

// highspeedPlanAuthHeaders 官方 buildHighspeedCodingPlanAuthHeaders 的池凭证版：
// zcodeJwt ← ZCodeJWT，codingPlanAuthorization ← AccessToken（chat.z.ai OAuth
// access token——官方从 oauth:{family}:access_token 装载，即本字段；APIKey 是
// x-coding-plan-api-key 的凭证，官方高速卡形状不带它）。zai 个人版 targetType
// 恒 PERSONAL（TEAM 需 org/project，池账号暂不支持）。
func (z *ZCodeAPI) highspeedPlanAuthHeaders(a *Account, h map[string]string) {
	id := NewClientIdentity(z.appVersion, a.DeviceMid)
	for k, v := range ZaiClientHeaders(id) {
		h[k] = v
	}
	h["Authorization"] = "Bearer " + a.ZCodeJWT
	if planAuth := firstNonEmpty(a.AccessToken, a.APIKey); planAuth != "" {
		h["X-Bigmodel-Authorization"] = "Bearer " + planAuth
	}
	h["Bigmodel-Target-Type"] = "PERSONAL"
}

// highspeedDraw 取卡。业务码失败按 hsBusinessError 返回（携带上游 next_draw_at
// 冷却，lane 级退避，账号分毫不动）。401/403 先过风控/挑战页预分类（relay.go
// 主路径同序——上游曾以 401/403 壳携带 3012 体，落进凭证分支会把临时风控
// 判成 invalid），真实凭证失败才走 refresh-first → MarkInvalid。
func (z *ZCodeAPI) highspeedDraw(ctx context.Context, a *Account, model string) (*highspeedCard, error) {
	payload, _ := json.Marshal(map[string]interface{}{
		"task_id": uuid.NewString(),
		// provider = 编码计划 provider 凭证 id（官方 resolveHighspeedDrawProviderId：
		// {zai,bigmodel}-{individual,team}-coding-plan → "builtin:{family}-coding-plan"），
		// 不是家族名——实测 "zai" 被上游 3001 parameter error 拒绝
		"provider": "builtin:zai-coding-plan",
		"model":    model,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, highspeedDrawURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	h := map[string]string{"Content-Type": "application/json"}
	z.highspeedPlanAuthHeaders(a, h)
	for k, v := range h {
		req.Header.Set(k, v)
	}
	client := ClientForURL(z.egress.ProxyURLForAccount(a), highspeedDrawURL, highspeedControlTo)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		if z.highspeedAuthFailSoft(a, "取卡", resp, raw) {
			return nil, fmt.Errorf("draw HTTP %d (transient auth-shell failure)", resp.StatusCode)
		}
		if ok, inflight := z.tryRefreshAccount(a); ok || inflight {
			return nil, fmt.Errorf("draw HTTP %d (credentials refreshed; retry next request)", resp.StatusCode)
		}
		if z.credentialsAlreadyRotated(a) {
			return nil, fmt.Errorf("draw HTTP %d (credentials rotated)", resp.StatusCode)
		}
		z.pool.MarkInvalid(a, fmt.Sprintf("高速卡取卡鉴权失败 HTTP %d", resp.StatusCode))
		return nil, fmt.Errorf("draw HTTP %d", resp.StatusCode)
	case resp.StatusCode == 429:
		// 取卡限频 = 计划侧配额节奏（对齐官方 next_draw_at 语义），非账号健康
		return nil, &hsBusinessError{Code: 429, Msg: "draw rate-limited", NextDrawAtMs: envelopeNextDrawAt(raw)}
	case resp.StatusCode >= 400:
		return nil, fmt.Errorf("draw HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var v map[string]interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("draw 响应非 JSON: %s", truncate(string(raw), 120))
	}
	nextDrawAtMs := envelopeNextDrawAt(raw)
	if _, has := v["code"]; has {
		if n := jsonInt(v, "code"); n != 0 {
			return nil, &hsBusinessError{Code: n, Msg: firstNonEmpty(jsonStr(v, "msg"), jsonStr(v, "message")), NextDrawAtMs: nextDrawAtMs}
		}
	}
	data, _ := v["data"].(map[string]interface{})
	if data == nil {
		return nil, fmt.Errorf("draw 响应缺少 data")
	}
	cm, _ := data["card"].(map[string]interface{})
	if cm == nil {
		// code=0 但无卡面：官方 draw-miss 形状（如仅 next_draw_at 的排队/冷却
		// 应答）。带 next_draw_at 时按其退避（钳制同业务码路径），否则取证日志
		// + 默认静默。响应体只落日志（可能含非敏感排队元数据，截断）
		log.Printf("[highspeed] account %s draw accepted without card, body: %s",
			a.DisplayNameOrEmail(), truncate(string(raw), 300))
		if nextDrawAtMs > time.Now().UnixMilli() {
			return nil, &hsBusinessError{Code: -1, Msg: "draw queued (no card yet)", NextDrawAtMs: nextDrawAtMs}
		}
		return nil, fmt.Errorf("draw 响应缺少 card")
	}
	id, _ := cm["card_id"].(string)
	if id == "" {
		return nil, fmt.Errorf("draw 响应缺少 card_id")
	}
	cardModel, _ := cm["model"].(string)
	card := &highspeedCard{ID: id, Model: cardModel, ExpiresAtMs: jsonInt64(cm, "expires_at"), DrawnAt: time.Now()}
	log.Printf("[highspeed] account %s drew card %s… model=%s expires_in=%ds",
		a.DisplayNameOrEmail(), safePrefixLog(card.ID, 10), card.Model,
		max64(0, (card.ExpiresAtMs-time.Now().UnixMilli())/1000))
	return card, nil
}

// envelopeNextDrawAt 从 draw 响应体提取 next_draw_at（ms epoch；缺失/非 JSON 返回 0）。
// 业务码失败路径也要先取它——{code:3103,data:{next_draw_at:...}} 是官方冷却的
// 正常携带形状，晚解析会让 lane 冷却退化为固定 10 分钟（评审 Medium 1）
func envelopeNextDrawAt(raw []byte) int64 {
	var v struct {
		Data struct {
			NextDrawAt int64 `json:"next_draw_at"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &v) == nil {
		return v.Data.NextDrawAt
	}
	return 0
}

// highspeedAuthFailSoft 401/403 壳的软失败预分类（取卡/推理两处共用）。
// 命中挑战/风控/验证码/HTML 拦截时冷却账号（临时状态）并返回 true——调用方
// 不得再走 MarkInvalid。这些壳体在兄弟端点上出现过（relay.go:660-696 注释），
// 高速卡端点是否复现未实证，防御成本为零而误杀成本是人工恢复。
func (z *ZCodeAPI) highspeedAuthFailSoft(a *Account, op string, resp *http.Response, body []byte) bool {
	low := strings.ToLower(string(body))
	mark := func(msg string) {
		z.pool.MarkCooling(a, fmt.Sprintf("%s（高速卡%s）", msg, op), 300)
	}
	switch {
	case isCloudflareChallenge(resp.Header, string(body)):
		mark(fmt.Sprintf("Cloudflare/WAF 挑战 HTTP %d", resp.StatusCode))
	case strings.Contains(resp.Header.Get("Content-Type"), "text/html"):
		mark(fmt.Sprintf("上游返回 HTML 拦截/错误页 HTTP %d", resp.StatusCode))
	case isCaptchaError(low):
		mark(fmt.Sprintf("验证码被拒 HTTP %d", resp.StatusCode))
	case isRiskBlocked(low):
		mark(fmt.Sprintf("风控拦截 HTTP %d", resp.StatusCode))
	default:
		return false
	}
	return true
}

// ensureHsMaps 惰性初始化 lane 状态表（测试/未来构造路径可能绕过 NewZCodeAPI，
// 直接构造的零值结构体不得在 map 写入时 panic）
func (z *ZCodeAPI) ensureHsMaps() {
	z.hsMu.Lock()
	defer z.hsMu.Unlock()
	if z.hsCards == nil {
		z.hsCards = make(map[int64]*highspeedCard)
	}
	if z.hsDrawBlockUntil == nil {
		z.hsDrawBlockUntil = make(map[int64]time.Time)
	}
	if z.hsDrawing == nil {
		z.hsDrawing = make(map[int64]bool)
	}
}

// highspeedCardFor 取在手卡面，过期/缺失时重取（单账号内防并发双取）。
// ok=false 表示 lane 本轮不可用（资格/限频/网络），调用方落回常规通道。
// 注：卡面按账号缓存（不按 model 细分）——同一张高速卡在其有效期内服务不同
// 请求模型，draw 的 model 入参取首次触发者的请求值。官方网关按计划发放高速
// 卡（现行仅 GLM-5.1-Highspeed 一档），按模型细分只会成倍消耗取卡配额。
func (z *ZCodeAPI) highspeedCardFor(ctx context.Context, a *Account, model string) (*highspeedCard, bool) {
	z.ensureHsMaps()
	now := time.Now()
	z.hsMu.Lock()
	if z.hsDrawBlockUntil[a.ID].After(now) {
		z.hsMu.Unlock()
		return nil, false
	}
	if c := z.hsCards[a.ID]; c.valid(now) {
		z.hsMu.Unlock()
		return c, true
	}
	if z.hsDrawing[a.ID] {
		// 并发请求撞上在途取卡：本请求直接落回，不等（draw 最长 20s，常规通道更快）
		z.hsMu.Unlock()
		return nil, false
	}
	z.hsDrawing[a.ID] = true
	z.hsMu.Unlock()
	defer func() {
		z.hsMu.Lock()
		delete(z.hsDrawing, a.ID)
		z.hsMu.Unlock()
	}()

	card, err := z.highspeedDraw(ctx, a, model)

	now = time.Now()
	z.hsMu.Lock()
	defer z.hsMu.Unlock()
	if err != nil {
		// 业务码/限频/网络失败：lane 级静默，账号不惩罚；上游给了 next_draw_at
		// 则以其为准（钳制到 [1min, 1h]），否则默认 10min
		block := highspeedDrawBlock
		var be *hsBusinessError
		if errors.As(err, &be) && be.NextDrawAtMs > now.UnixMilli() {
			block = time.Duration(be.NextDrawAtMs-now.UnixMilli()) * time.Millisecond
			if block < time.Minute {
				block = time.Minute
			}
			if block > time.Hour {
				block = time.Hour
			}
		}
		// 客户端断开导致的取卡中断不是取卡失败：不设静默期（否则用户取消一个
		// 请求会把该账号的高速卡 lane 压暗 10 分钟——与 takeFailed 的 ctx 豁免
		// 同规，评审 2026-10-26 L5）
		if ctx.Err() != nil {
			return nil, false
		}
		z.hsDrawBlockUntil[a.ID] = now.Add(block)
		log.Printf("[highspeed] account %s draw failed, lane fallback %s: %v",
			a.DisplayNameOrEmail(), block.Truncate(time.Second), err)
		return nil, false
	}
	z.hsCards[a.ID] = card
	delete(z.hsDrawBlockUntil, a.ID)
	return card, true
}

// invalidateHighspeedCard 3402（卡过期）后调用：仅清自己抽到的那张（并发换卡
// 场景下可能已是他卡，误清只是多取一次，无害）
func (z *ZCodeAPI) invalidateHighspeedCard(a *Account, card *highspeedCard) {
	z.hsMu.Lock()
	defer z.hsMu.Unlock()
	if cur := z.hsCards[a.ID]; cur == card {
		delete(z.hsCards, a.ID)
	}
}

// ---- 选号 ----

// pickHighspeedAccount 高速卡 lane 选号：启用 + zai + 有 JWT（与 runOffPeak 同门槛，
// exhausted/cooling 不拦——高速卡是独立计划资源，主通道状态不约束卡面资格）。
// 轮转起点分摊并发，单账号直接命中。
func (z *ZCodeAPI) pickHighspeedAccount(group string) *Account {
	all, err := z.db.ListAccounts("")
	if err != nil {
		log.Printf("[highspeed] list accounts: %v", err)
		return nil
	}
	accounts := all
	if group != "" {
		accounts = nil
		for _, a := range all {
			if matchAccountGroup(a, group) {
				accounts = append(accounts, a)
			}
		}
	}
	eligible := make([]*Account, 0, len(accounts))
	for _, a := range accounts {
		if a.Enabled && a.Provider == "zai" && a.ZCodeJWT != "" {
			eligible = append(eligible, a)
		}
	}
	if len(eligible) == 0 {
		return nil
	}
	if n := len(eligible); n > 1 {
		start := int(z.asyncRotation.Add(1)) % n
		eligible = append(eligible[start:], eligible[:start]...)
	}
	return eligible[0]
}

// ---- lane 入口 ----

// highspeedCoveredModel 请求模型是否在高速卡覆盖面（官方 isModelCovered 闸）。
// 覆盖面 = *-highspeed 模型族（内置目录：GLM-5.1-Highspeed / MiniMax-*-highspeed）。
// 非覆盖模型不取卡（官方客户端对未覆盖模型根本不提供高速模式；实测对未覆盖
// 模型 draw 会被上游 3001 parameter error 拒绝——2026-10-25 prod logid
// 202610251430581f087cfabec7f154c1af）。返回规范官方名供 draw body 使用。
func highspeedCoveredModel(model string) (string, bool) {
	name := strings.TrimSpace(model)
	if official, ok := modelNameMap[strings.ToLower(name)]; ok {
		name = official
	}
	if name == "" || !strings.HasSuffix(strings.ToLower(name), "-highspeed") {
		return "", false
	}
	return name, true
}

// highspeedLane 高速卡 lane 尝试。返回 true = 响应已写完（成功或已按协议写终态
// 错误帧）；false = 未写任何字节，调用方必须落回常规 relay（官方 degrade 语义）。
func (z *ZCodeAPI) highspeedLane(w http.ResponseWriter, r *http.Request, rc *relayCtx) bool {
	// 与 relay 同闸：暂停开关 + 命名 Key 模型白名单/token 配额（lane 绕开 relay，
	// 这两道闸必须在此补齐，否则受限 Key 借高速卡形状绕过限流）
	if z.gatewayPaused() {
		log.Printf("[highspeed] request rejected: gateway is paused (panic stop)")
		writeAPIError(w, http.StatusServiceUnavailable, "网关已全局暂停（panic stop），请在管理面板恢复")
		return true
	}
	if gk := gatewayKeyFromCtx(r.Context()); gk != nil {
		if errResp := checkGatewayKeyRequest(gk, relayModelName(rc)); errResp != nil {
			errResp.Write(w)
			return true
		}
	}
	// 覆盖面闸（官方 isModelCovered）：非高速卡模型不取卡，直接落回常规通道
	drawModel, covered := highspeedCoveredModel(rc.clientModel)
	if !covered {
		return false
	}
	a := z.pickHighspeedAccount(rc.group)
	if a == nil {
		return false
	}
	if r.Context().Err() != nil {
		// 客户端已断开：取卡是计费侧资源消耗，断连后不得再触发
		return false
	}
	card, ok := z.highspeedCardFor(r.Context(), a, drawModel)
	if !ok {
		return false
	}
	return z.highspeedForward(w, r, a, card, rc, 0)
}

// ---- 推理面 ----

// highspeedForward 带卡调用上游高速卡消息端点。redrawn>0 表示本次已是 3402 重取
// 后的重试（最多一次，再败落回常规通道）。返回值语义同 highspeedLane。
func (z *ZCodeAPI) highspeedForward(w http.ResponseWriter, r *http.Request, a *Account, card *highspeedCard, rc *relayCtx, redrawn int) bool {
	start := time.Now()
	// 卡面模型换发（官方 modelSelection: modelId = card.model）+ metadata.user_id
	//（闲时端点同款参数校验防御）+ 强制流式（闲时端点对 stream:false 回 3001，
	// 高速卡端点未实证，统一流式 + 网关聚合，客户端语义不变）
	body := make(map[string]interface{}, len(rc.body)+2)
	for k, v := range rc.body {
		body[k] = v
	}
	if card.Model != "" {
		body["model"] = card.Model
	}
	if _, has := body["metadata"]; !has {
		body["metadata"] = map[string]interface{}{
			"user_id": fmt.Sprintf(`{"device_id":%q,"account_uuid":"","session_id":""}`, a.DeviceMid),
		}
	}
	body["stream"] = true
	payload, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, highspeedMessagesURL, bytes.NewReader(payload))
	if err != nil {
		log.Printf("[highspeed] build request failed: %v", err)
		return false
	}
	// 推理面头 = sN 鉴权（Authorization JWT + X-Bigmodel-Authorization + Target-Type）
	// + X-Highspeed-Card-ID。官方高速卡推理不带 x-coding-plan-api-key
	//（那是闲时形状的 preferred apiKey，见 wave-3 凭证分类）——多发的凭证头
	// 会改上游用量归因，绝不添发
	h := map[string]string{
		"Content-Type":        "application/json",
		"anthropic-version":   anthropicVersionH,
		"X-ZCode-Agent":       "glm",
		"X-Highspeed-Card-ID": card.ID,
		"Accept":              "text/event-stream",
	}
	z.highspeedPlanAuthHeaders(a, h)
	for k, v := range h {
		req.Header.Set(k, v)
	}
	// 客户端白名单头透传（卡号除外——服务端权威，见 relay.go laneForwardSet）
	forwardLaneClientHeaders(r, req.Header)
	client := ClientForURL(z.egress.ProxyURLForAccount(a), highspeedMessagesURL, 0)
	resp, err := client.Do(req)
	if err != nil {
		if r.Context().Err() != nil {
			// 客户端已断开：响应无人接收，也不得再落回常规通道重放整单
			return true
		}
		log.Printf("[highspeed] account %s connect failed: %v", a.DisplayNameOrEmail(), err)
		return false
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		authBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if z.highspeedAuthFailSoft(a, "推理", resp, authBody) {
			return false
		}
		if ok, inflight := z.tryRefreshAccount(a); ok || inflight {
			return false
		}
		if z.credentialsAlreadyRotated(a) {
			return false
		}
		z.pool.MarkInvalid(a, fmt.Sprintf("高速卡推理鉴权失败 HTTP %d", resp.StatusCode))
		return false
	case resp.StatusCode == 429:
		// 高速卡端点 429 = 卡/端点饱和（官方按 selection fallback 降级），不冷却
		// 账号；不落 recordUsage——落回的常规通道才是本请求的终态写入，此处
		// 记一条会把请求数/时延分布算重（评审 Low 3）
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		log.Printf("[highspeed] account %s upstream 429, fallback: %s", a.DisplayNameOrEmail(), truncate(string(body), 200))
		return false
	case resp.StatusCode >= 400:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if hasProviderCode(strings.ToLower(string(body)), "3402") {
			// 官方契约：3402 = 卡过期 → 重取一次重试；再败落回常规通道
			log.Printf("[highspeed] 3402 card expired on attempt #%d, redrawing", redrawn+1)
			z.invalidateHighspeedCard(a, card)
			if redrawn == 0 {
				if next, ok := z.highspeedCardFor(r.Context(), a, rc.clientModel); ok {
					return z.highspeedForward(w, r, a, next, rc, 1)
				}
			}
			return false
		}
		// 其余上游错误：lane 专属故障（卡面/端点侧），落回常规通道，账号不惩罚
		//（同 429：不落 recordUsage，终态由常规通道记录）
		log.Printf("[highspeed] account %s upstream HTTP %d, fallback: %s",
			a.DisplayNameOrEmail(), resp.StatusCode, truncate(string(body), 200))
		return false
	}

	// 2xx 但非 SSE（WAF 挑战页/登录页 HTML，主/闲时路径同守卫）：未写字节，落回
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		log.Printf("[highspeed] upstream returned non-SSE content (%s), fallback: %s",
			truncate(ct, 60), truncate(string(body), 200))
		return false
	}

	z.pool.MarkUsed(a)
	if rc.clientStream {
		// 上游 request-id 透传给客户端（与 relay 透传路径同规，遥测对账用）
		if rid := resp.Header.Get("x-request-id"); rid != "" {
			w.Header().Set("x-request-id", rid)
		}
		sniff := newUsageSniffReader(resp.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flushWriter(w)
		buf := make([]byte, 32<<10)
		truncated := false
		ttft := 0
		for {
			n, rerr := sniff.Read(buf)
			if n > 0 {
				if ttft == 0 {
					ttft = int(time.Since(start).Milliseconds())
				}
				if _, werr := w.Write(buf[:n]); werr != nil {
					z.recordUsage(a, r, payload, clientGoneStatus(r), start, ttft, sniff.usage(), true)
					return true
				}
				flushWriter(w)
			}
			if rerr != nil {
				truncated = !errors.Is(rerr, io.EOF)
				break
			}
		}
		recStatus := resp.StatusCode
		sniffed := sniff.usage()
		inlineErr := sniffed != nil && strings.HasPrefix(sniffed.StopReason, "ERR:")
		if truncated || inlineErr {
			msg := "upstream stream interrupted"
			if inlineErr {
				msg = strings.TrimPrefix(sniffed.StopReason, "ERR:")
			}
			writeSSEErrorEvent(w, msg)
			recStatus = http.StatusBadGateway
		}
		// 空流守卫（评审 M2，与闲时透传同不变量）：零事件或零内容块的 2xx SSE
		// 不得透传成干净成功
		if !truncated && !inlineErr && !sniff.sawContentBlock {
			writeSSEErrorEvent(w, "upstream returned an empty response (no content blocks)")
			recStatus = http.StatusBadGateway
		}
		z.recordUsage(a, r, payload, recStatus, start, ttft, sniffed, true)
		return true
	}
	// 非流式客户端：聚合为完整 Anthropic message（与闲时通道同规 64MB 上限）
	aggregated, usage, aerr := aggregateAnthropicStream(io.LimitReader(resp.Body, (64<<20)+1))
	if aerr == nil && len(aggregated) > 64<<20 {
		aerr = fmt.Errorf("上游响应超过 64MB 上限")
	}
	if aerr != nil {
		// 聚合失败仍按终态 502 回客户端、不落回常规通道：上游已消费这次生成
		//（计费已发生），重放会给计划烧第二次 token——与闲时通道 offPeakForward
		// 同一裁决。此处虽未向客户端写过字节，但"已写"的判定按上游消费算
		z.recordUsage(a, r, payload, http.StatusBadGateway, start, 0, usage, false)
		log.Printf("[highspeed] aggregate failed, client gets 502: %v", aerr)
		writeJSON(w, http.StatusBadGateway, map[string]interface{}{
			"type": "error", "error": map[string]string{"message": "高速卡通道响应聚合失败: " + truncate(aerr.Error(), 200), "type": "api_error"},
		})
		return true
	}
	z.recordUsage(a, r, payload, resp.StatusCode, start, 0, usage, false)
	if rid := resp.Header.Get("x-request-id"); rid != "" {
		w.Header().Set("x-request-id", rid)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(resp.StatusCode)
	w.Write(aggregated)
	return true
}

// ---- 管理端状态视图 ----

// highspeedLaneStatus 管理端只读视图（不取卡、不触发 draw）
type highspeedLaneStatus struct {
	Enabled  bool                     `json:"enabled"`
	Accounts []map[string]interface{} `json:"accounts"`
}

func (z *ZCodeAPI) highspeedLaneStatus() highspeedLaneStatus {
	st := highspeedLaneStatus{Enabled: z.highspeedLaneEnabled(), Accounts: []map[string]interface{}{}}
	now := time.Now()
	// ListAccounts 先于 hsMu（逐行 vault 解密是最重的一步，不得占着 lane 锁）
	accounts, err := z.db.ListAccounts("")
	if err != nil {
		return st
	}
	z.ensureHsMaps()
	z.hsMu.Lock()
	defer z.hsMu.Unlock()
	for _, a := range accounts {
		if a.Provider != "zai" {
			continue
		}
		m := map[string]interface{}{
			"id": a.ID, "email": a.Email, "enabled": a.Enabled, "status": a.Status,
		}
		if c := z.hsCards[a.ID]; c != nil && c.ID != "" {
			m["card_id"] = c.ID
			m["card_model"] = c.Model
			m["card_valid"] = c.valid(now)
			if c.ExpiresAtMs > 0 {
				m["card_expires_in_sec"] = max64(0, (c.ExpiresAtMs-now.UnixMilli())/1000)
			}
		}
		if until := z.hsDrawBlockUntil[a.ID]; until.After(now) {
			m["draw_blocked_for_sec"] = int64(until.Sub(now) / time.Second)
		}
		st.Accounts = append(st.Accounts, m)
	}
	return st
}

// jsonInt64 JSON 数值字段取 int64（缺失/非数值返回 0）
func jsonInt64(m map[string]interface{}, key string) int64 {
	if m == nil {
		return 0
	}
	if n, ok := m[key].(float64); ok {
		return int64(n)
	}
	return 0
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
