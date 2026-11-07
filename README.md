<div align="center">

# ZCode Proxy

**ZCode（Z.AI / GLM Coding Plan）多账号管理、OAuth 登录、活动领取与配额重置，以及 Anthropic / OpenAI 兼容的 2API 网关。**

Go 单二进制，内嵌管理界面与纯 Go SQLite，无 CGO。验证码求解使用本机 Chrome/Edge，Docker 镜像内置 Chromium。

[![CI](https://github.com/hongkongkiwi/zcode-smart-proxy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hongkongkiwi/zcode-smart-proxy/actions/workflows/ci.yml)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=flat-square)](go.mod)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square)](docker-compose.yml)
[![Single binary](https://img.shields.io/badge/deploy-single%20binary-2ea44f?style=flat-square)](#快速开始)

</div>

> 仅供个人学习、研究和技术交流使用。使用前请阅读文末免责条款。

[核心能力](#核心能力) · [界面](#界面) · [快速开始](#快速开始) · [功能详解](#功能详解) · [配置参考](#配置参考) · [技术细节](#技术细节) · [已知限制](#已知限制) · [免责条款](#免责条款)

## 核心能力

| 模块 | 能力 |
| --- | --- |
| 账号池 | 本地一键导入、OAuth 轮询登录、JWT/API Key 粘贴、分组、`random` / `round_robin` / `best_quota` / `priority` 四种策略、免费/付费双通道、会话粘滞、状态机恢复 |
| 2API 网关 | Anthropic `/v1/messages`、OpenAI `/v1/chat/completions`、`/v1/completions`、`/v1/responses`、`/v1/models`；SSE、工具调用、思考链、用量与 TTFT 记录 |
| 网关 Key | 命名 `sk-` Key，独立 RPM、总配额、模型白名单；库内仅存 SHA-256 |
| 活动与配额 | 活动检测、领取、激活、Coding Plan 配额重置；自动领取、自动重置、到期即花 |
| 人机验证 | go-rod 驱动本机 Chrome/Edge，无头优先、有头兜底，按出口代理分组缓存 |
| 传输与反检测 | utls 20+ 指纹、按主机选择 HTTP/1.1 或 HTTP/2、设备指纹保持、分组出口代理 |
| 本地联动 | 提取本机登录态、一键切回、快照还原、`zcb1:` 加密账号包 |
| 部署与观测 | 单二进制、embed UI、纯 Go SQLite、仪表盘、LLM 测试页、`-doctor` 只读体检 |

## 界面

<p align="center">
  <img src="screenshots/01-dashboard.png" alt="仪表盘" width="880">
</p>

<details>
<summary>更多截图</summary>

| 账号管理 | 账号操作 |
| --- | --- |
| <img src="screenshots/02-accounts.png" alt="账号管理" width="430"> | <img src="screenshots/03-account-actions.png" alt="账号操作" width="430"> |

| 活动任务 | LLM 测试 |
| --- | --- |
| <img src="screenshots/04-activity.png" alt="活动任务" width="430"> | <img src="screenshots/05-llm-test.png" alt="LLM 测试" width="430"> |

</details>

管理台采用顶部 pill 导航、卡片与模态布局。

## 快速开始

### 二进制

```bash
go build -o zcode-proxy .
./zcode-proxy -config config -db data/zcode.db
```

打开 <http://127.0.0.1:8687>。首次启动会生成随机管理员口令并写入 `data/initial_admin_password`（0600）；也可以用 `ZCODE_WEB_PASS` 指定口令。

`-doctor` 执行只读体检后退出：

```bash
./zcode-proxy -doctor
```

体检覆盖 SQLite `quick_check`、vault 往返、验证码浏览器、账号/代理/Key 状态与记录表行数，不建表、不迁移、不访问上游。

### Docker

```bash
mkdir -p ./data
chown -R 10001:10001 ./data
docker compose up -d --build
```

默认只绑定 `127.0.0.1:8687`。容器内 `config/config.json` 的 `listen_addr` 必须是 `0.0.0.0:8687`，`config/` 以只读方式挂载。首次启动后读取管理员口令：

```bash
docker compose exec zcode-proxy cat /app/data/initial_admin_password
```

在 TLS 反向代理后部署时设置 `ZCODE_COOKIE_SECURE=1`。compose 使用 `/health` 做容器健康检查。其他常用环境变量见[配置参考](#配置参考)。

## 功能详解

### 账号与凭证

#### 本地提取账号

无需重新登录，直接从本机 ZCode 客户端提取已登录账号：

- 读取 `~/.zcode/v2/credentials.json`（`enc:v1:` AES-256-GCM 密文），使用与官方一致的密钥派生公式（`SHA-256(zcode-credential-fallback:{平台}:{home}:{用户})`，可用 `ZCODE_CREDENTIAL_SECRET` 覆盖）解密；
- 提取 `zcodejwttoken`（Coding Plan JWT，免费通道凭证）、`oauth:*:access_token`（含 api_key 声明）、`oauth:*:user_info`（邮箱/昵称/user_id）；
- 读取 `~/.zcode/v2/config.json` 中 `builtin:*-coding-plan` 的明文 API Key（`{id}.{secret}` 完整格式）作为 Key 通道凭证；
- 读取 `telemetry-state.json` 的 `deviceMid` 作为设备指纹，同时保存原始凭证快照，供后续还原；
- 以 `user_id` 为自然键 upsert 入库：重复导入不会覆盖设备指纹与快照；导入后自动刷新额度确认套餐状态。

#### 一键切回与快照还原

把网关里的任意账号写回本机 ZCode 客户端，使其成为客户端当前登录账号：

- 切回：先备份 `credentials.json` 和 `config.json` 到 `data/backups/`（带时间戳），再将账号的 JWT/access_token/user_info 重新 `enc:v1:` 加密，更新 `config.json` 的 start-plan/coding-plan apiKey 与 enabled，最后用临时文件加 rename 原子写回；可选结束 `ZCode.exe` 进程使改动生效；
- 还原：用导入时保存的原始快照一键撤销切回，恢复客户端原登录态；
- 全程只替换登录态相关键，不破坏客户端其他配置项。

#### 加密账号包迁移

- 导出：选中账号，输入管理员密码确认身份，再设置包密码，生成 `zcb1:` 前缀的加密串（`base64(salt16‖nonce12‖ct)`，PBKDF2-SHA256 60 万轮 + AES-256-GCM，旧 12 万轮包仍可导入），包含 JWT、Key、设备指纹和快照；
- 导入：在另一台机器粘贴加密串和包密码解密入库；密码错误直接拒绝，不落地明文。

#### OAuth 登录

- 免回调轮询登录（默认，推荐）：与官方桌面端相同的 CLI 轮询流程。`POST /api/v1/oauth/cli/init` 取授权 URL（附加桌面中转参数），浏览器在任意设备打开并授权，中转页在服务端记录结果，不回连本机，无需注册 redirect_uri；网关轮询 `/oauth/cli/poll/{flow_id}` 自动入库；
- 手动粘贴（备用）：复制授权后地址栏 `zcode.z.ai/login?code=…` 完整 URL 贴回网关兑换；
- 环回模式（`127.0.0.1:8687/oauth/callback`）保留为实验项，当前会报 `Redirect URI not registered`；
- 兑换链：`code/poll → Coding Plan JWT + access_token` → 自动提取 API Key（z/login → customer → api_keys → copy）→ 补查 userinfo → 入库并刷新额度。

### 路由、额度与自动化

#### 多账号路由

- 免费/付费双通道（`paid_fallback_mode`，默认 `free_first`）：转发分两阶段，先跨全部可选账号尝试免费通道，全部失败后才进入付费回退阶段。账号级 `paid_fallback` 开关与独立付费冷却列，不触碰免费侧状态；`balanced` 模式下软失败（风控/验证码）立刻级联同账号付费路径；`never` 模式不启用付费阶段（纯 API-Key 无 JWT 账号仍可服务）。`paid_daily_token_cap` 为付费通道每日 token 总量上限，0 表示不限，读取失败按阻断处理。
- 单账号并发上限（`max_concurrent_per_account`，默认 3，范围 1-32）：在途请求按账号 × 通道隔离排队，免费侧打满不堵付费回退；客户端断开与超时同路释放。
- 负载均衡：`round_robin`（默认）在所有可选账号间均匀轮转；`random` 随机；`best_quota` 永远挑剩余额度最大的账号。
- 优先级级联（`priority`）：账号按 priority 数值升序分层，数值小者先用，层内轮转。某层耗尽、冷却或失效时被状态机自动过滤，请求落到下一层，额度恢复后自动回归高层。促销/试用账号可设 50，自费账号保持 100；导入后首次额度刷新发现 Start/体验档会自动降为 50，仅首次生效，不覆盖手动调整。
- 会话粘滞（`sticky_sessions`，默认开）：同一会话（`metadata.user_id`，缺省按 system 块摘要）固定到同一账号，保住上游 prompt 缓存。粘滞账号进入不可选状态时自动让位，恢复后回归。TTL 1 小时。
- 耗尽重置提示：monitor 通道的重置时间落库后，全部账号耗尽的 503 会附「额度窗口约 N 分钟后重置」；额度构成弹窗展示双通道（Start Plan 计费与 coding plan monitor）并排视图。

#### 额度监控

- 后台按 `quota_refresh_interval` 周期刷新，0 表示关闭；成功后节流 30s 防惊群；
- JWT 通道（Start Plan 计费）报耗尽而账号带 API Key 时，自动交叉核对 monitor 通道（individual coding plan 额度），有余量则以 monitor 为准；
- 账号页额度条可点击：弹窗展示分套餐槽位（plan_id/档位/状态/到期/进度）与逐模型明细（总额/已用/剩余/占比/周期）；
- 额度驱动状态机：耗尽转 `exhausted`，限流转 `cooling`，鉴权失败转 `invalid`（后台按退避自动重试，鉴权恢复即自动复活），无订阅转 `inactive`。

#### 活动检测、领取、激活与配额重置

- 检测：`billing/preview` 列出可领活动（plan_id/优先级/entitlements 赠送明细，含 capabilities 与生效时间）；
- 领取：`billing/claim {plan_id}` 加阿里云无痕验证码头；错误码语义化处理（1003 已领过视为幂等成功，1005 名额用完读 next_at）；账号级互斥锁保证 UI 手动与 cron 计划并发不双领；
- 激活：上报 `event/report`（app_launch + app_daily_active，含 device_mid/user_id）触发服务端授予 Start Plan；
- 配额重置：`coding-plan/reset/status` 查 five_hour/week 重置机会，`reset/use {idempotency_key, reset_type}` 消耗机会恢复配额；
- 调度：cron 计划（分钟级去重、per-plan 互斥、账号间随机延迟防风控），任务类型 detect/claim/activate，运行记录可查；配额重置仅支持账号页手动执行，旧 reset 计划不可运行。

#### 自动领取与自动重置

- 自动领取活动（`auto_claim_promos`，默认开）：后台常驻循环，每轮对全部账号领取最高优先级的可领活动；`auto_claim_interval_minutes` 默认 30 分钟（5-1440，0 表示仅手动），账号间 `auto_claim_delay_seconds` 默认 10s ± 40% 抖动；只领活动，不触碰额度重置；
- 自动重置（`auto_reset_enabled`，默认关）：额度耗尽且重置机会等待达门槛时自动消耗机会恢复配额（five_hour ≥ `auto_reset_min_wait_minutes` 默认 60 分钟；week ≥ `auto_reset_min_wait_week_hours` 默认 24 小时；等待时间未知按可花费处理）；
- 到期即花（`auto_reset_expiry_enabled`，默认关，独立于总开关）：机会临近到期（`auto_reset_expiry_spend_minutes` 默认 60 分钟，0 表示关闭）时即使未耗尽也先花掉；槽位间隔 30 分钟，同槽去重防双花，印记重启后从账本还原；
- 自动与手动重置共用账号级互斥锁与防双花印记；冷却中的账号由调度器心跳补上临期评估（refreshAll 会跳过它们）；临期消耗携带确定性幂等键，响应丢失时账本如实标注「槽位可能已被上游消耗」。

### 网关与客户端

#### 2API 网关与协议转换

- 三入口：Anthropic `/v1/messages`、OpenAI `/v1/chat/completions`、`/v1/responses`，外加 `/v1/models`、`/v1/messages/count_tokens`；
- 请求/响应双向转换（system/tool/image/thinking/tool_choice 全映射），SSE 流式逐帧转换并嗅探 usage/TTFT 落库；
- 上游错误不伪装成功：流内 `error` 事件与中途断流均按失败处理（OpenAI 发错误 chunk，Responses 发 `response.failed`）。
- 官方编码计划网关别名：`/api/v1/ultra[|-zai]/anthropic/v1/messages`，客户端把 `ZCODE_BASE_URL` 指向本代理即可承接 OAuth 编码计划流量；上游端点按服务端 `agent/configs` 路由表自动重写（fail-open）。

#### 网关 Key

除根 Key（`settings.api_key`，不受限制）外，可为每个客户端签发独立命名 `sk-` Key：

- 每把 Key 可设启用开关、RPM 上限（0 表示不限，进程内 60s 滑动窗口，超限 429 + `Retry-After: 10`）、总 token 配额（耗尽 429）、模型白名单（逗号分隔小写；命中外 403，并同步过滤 `GET /v1/models` 列表）；
- 配额计费缓存感知：按 `input + output + cache_creation + cache_read/10` 记账；
- 库内仅存 SHA-256 哈希，明文仅在创建时展示一次；签发需管理员密码步升，按 IP 独立退避；
- 管理 API：`/api/keys`（GET/POST/PUT/DELETE）。

#### 闲时通道

`/async/v1/messages`（Anthropic 原生）经上游 off-peak 免费算力队列：取票排队、SSE 注释帧保活、`X-Off-Peak-Ticket-ID` 调用、幂等关票、票回收自动重取。设置 `async_enabled` 开启（默认关）。

该通道为一次性应答，无会话记忆；多轮对话请在请求内携带历史。请求一律强制 `stream=true`，`stream:false` 会被上游以 `3001 parameter error` 拒绝。消息转发遇 3001 按票过期语义自动同票重试，上游对全部账号状态是否可用仍待行为明确。

#### 人机验证、指纹与出口代理

- 验证码：go-rod 驱动本机真实 Chrome/Edge 无头求解阿里云无痕验证（持久化 profile 保留风控 cookie），连败自动升级有头手动（手动模式 10 分钟无操作回落无头）；求解预算前台 45s、后台 120s；参数按出口代理分组缓存 45s + 300s 宽限；`captcha_prewarm=0` 关闭预热；挑战页/WAF 拦截 HTML 由 relay 层识别并按通道冷却 300s，不误伤凭证；
- 指纹：utls 20+ 预置加自定义 JA3；`zcode.z.ai` 走指纹加 HTTP/1.1（ESA WAF），`api.z.ai` 走标准库加 HTTP/2（ALPN 仅 h2）；
- 代理：分组绑定节点（SOCKS5/HTTP CONNECT）、默认节点、全局代理；系统代理探测、本机端口探测、出口 IP 测试。

#### LLM 测试页

三协议 × 流式/非流式在线测试，实时显示状态、总延迟、TTFT、tokens、SSE 事件数、响应内容与会话历史；界面中英双语，跟随系统并支持手动覆盖。

### 安全模型

| 领域 | 实现 |
| --- | --- |
| 管理员口令 | 首次启动随机生成 20 位，写入 `data/initial_admin_password`（0600），可用 `ZCODE_WEB_PASS` 覆盖；无默认口令，不落日志；bcrypt 存储 |
| 登录保护 | 按 IP + 用户名，5 次失败起步 60s 指数退避，封顶 30 分钟；正确管理员口令可治疗性通过，30s 限频 |
| 敏感操作 | 根 Key 生成/揭示、网关 Key 签发、账号包导出、修改密码一律要求密码步升，各自独立按 IP 退避；账号包导出另需管理员密码二次确认 |
| 网关 Key | `sk-` Key 常数时间比较，库内仅存 SHA-256 |
| 会话 | HttpOnly + SameSite=Strict；TLS 下 Secure，`ZCODE_COOKIE_SECURE` 可强制；24h 过期 |
| 凭证存储 | 账号凭证与代理密码 `vault1:` AES-256-GCM 静态加密；降级态拒绝写入新凭证；解密失败节点标记 `password_broken` 并跳过拨号 |
| 日志 | 凭证与 token 从不落日志；未知 `/api/*`、`/v1/*` 返回 404 防探测混淆 |

## 配置参考

`config/config.json`（首次运行生成）：`listen_addr`、`app_version`（空表示从注册表探测）、`models[]`、`upstream{zai,zai_fallback,bigmodel}`。

<details>
<summary>展开 settings 配置项</summary>

| 配置项 | 说明 |
| --- | --- |
| `selection_strategy` | 账号选择：`round_robin` / `random` / `best_quota` / `priority` |
| `quota_refresh_interval` | 额度刷新周期，0 表示关闭 |
| `sticky_sessions` | 会话粘滞，默认开 |
| `paid_fallback_mode` | `free_first` / `balanced` / `never`，默认 `free_first` |
| `paid_daily_token_cap` | 付费通道每日 token 上限，0 表示不限 |
| `max_concurrent_per_account` | 单账号并发上限，1-32，默认 3 |
| `upstream_proxy` | 全局上游代理 |
| `fingerprint` | utls 指纹预设 |
| `custom_ja3` | 自定义 JA3，5 段格式，设置页服务端预校验 |
| `captcha_mode` | `auto` / `manual` / `off` |
| `captcha_prewarm` | 0 表示关闭预热 |
| `gateway_models` | 对外模型清单 |
| `model_catalog` | `client/configs` 目录缓存 |
| `api_key` | 根 Key |
| `password_hash` | 管理员口令 bcrypt 哈希 |
| `prompt_cache_breakpoint` | 1 表示在 system 末块加 ephemeral 缓存断点，默认关 |
| `usage_retention_days` | 用量记录保留天数，默认 90，0 表示永久 |
| `async_enabled` | 闲时通道开关，默认关 |
| `async_poll_interval_ms` | 闲时通道轮询间隔，默认 1000 |
| `async_keepalive_ms` | 闲时通道保活间隔，默认 15000 |
| `async_max_retries` | 闲时通道最大重试，默认 3 |
| `async_max_wait_sec` | 闲时通道最长等待，默认 1800 |
| `auto_claim_promos` | 自动领取活动，默认开 |
| `auto_claim_interval_minutes` | 自动领取间隔，默认 30，0 表示仅手动 |
| `auto_claim_delay_seconds` | 账号间延迟，默认 10 |
| `auto_reset_enabled` | 自动重置，默认关 |
| `auto_reset_min_wait_minutes` | five_hour 重置等待门槛，默认 60 |
| `auto_reset_min_wait_week_hours` | week 重置等待门槛，默认 24 |
| `auto_reset_expiry_enabled` | 到期即花，默认关 |
| `auto_reset_expiry_spend_minutes` | 到期即花提前量，默认 60 |

</details>

### 环境变量

| 变量 | 用途 |
| --- | --- |
| `ZCODE_WEB_PASS` | 覆盖首次启动生成的管理员口令 |
| `ZCODE_PROXY_VAULT_SECRET` | vault 种子；不设置时使用 `data/vault.key` |
| `ZCODE_CREDENTIAL_SECRET` | 本机凭证解密密钥派生覆盖 |
| `ZCODE_SWITCH_HOME` | 切回时的 home 覆盖 |
| `ZCODE_COOKIE_SECURE` | 强制会话 Cookie 的 Secure 标志，TLS 反向代理后设置 |

账号 `priority` 字段：`priority` 策略下数值小者先用（1-9999，默认 100；导入后首次额度刷新发现促销档自动降为 50）。

## 技术细节

<details>
<summary>展开架构、请求生命周期、并发、数据库与上游协议</summary>

### 1. 总体架构

```
                        ┌──────────────────────────────────────────────┐
 客户端(Claude/Cursor) │  HTTP mux (auth.Middleware)                  │
   /v1/*  (sk- Key) ──▶│  ├─ handler: messages / chat / responses     │
 管理浏览器            │  ├─ /api/*  管理 REST (session)              │
   /web, /api/* ──────▶│  └─ /web    embed SPA                       │
                        │                                            │
                        │  relay(转发核心)                            │
                        │   ├─ AccountPool.Select (策略+状态机过滤)    │
                        │   ├─ 两阶段: 免费通道(全账号) → 付费回退模式  │
                        │   ├─ CaptchaService (rod, 按代理分组缓存)    │
                        │   ├─ ClientForURL (utls|h2 按主机, 连接池缓存)│
                        │   └─ SSE 嗅探 → usage_records              │
                        │                                            │
                        │  后台: 额度刷新 / cron 调度 / 自动领取·重置   │
                        │  存储: SQLite(WAL, 单写连接) embed 于二进制   │
                        └──────────────────────────────────────────────┘
                          │                        │
              zcode.z.ai (ESA WAF, h1+utls)   api.z.ai (h2, 标准库)
```

单二进制 = Go + `//go:embed web` + `modernc.org/sqlite`（纯 Go，无 CGO）。依赖：`utls`（TLS 指纹）、`go-rod`（验证码）、`x/net`（SOCKS5）、`x/crypto`（bcrypt/PBKDF2）、`google/uuid`、`ysmood/gson`（rod JSON）。

### 2. `/v1/messages` 请求生命周期

1. 鉴权：`x-api-key` 或 `Authorization: Bearer` 匹配根 Key `settings.api_key`（`subtle.ConstantTimeCompare`），或按 SHA-256 查网关 Key 表，随后施加 RPM、配额、模型白名单拦截。
2. 规范化：模型名大小写/前缀映射（`glm-5.3`→`GLM-5.3`、`bigmodel/x`→provider 路由）；GLM-5.3 思考归一化为上游现行格式（对齐 zai-org/ZCode 3.14.x）：思考开启 → `{thinking:{type:adaptive},output_config:{effort:low|high|max}}`（由 budget_tokens/reasoning_effort 映射，缺省 high，minimal→low），未请求思考 → `{thinking:{type:disabled}}`；string content 桥接为 `[{type:text}]`；body 上限 8MB。
3. 选号：按策略（round_robin 游标 / random / best_quota / priority 级联）过滤 `enabled && 状态可选 && 有凭证`；冷却中账号到期自动可选；通过账号 × 通道并发闸门后进入转发。
4. 两阶段转发：阶段 1 免费通道跨全部可选账号（粘滞优先），阶段 2 按 `paid_fallback_mode`（free_first 默认 / balanced / never）与 `paid_daily_token_cap` 决定付费回退。
   - 免费路径：`JWT + X-Aliyun-Captcha-Verify-Param` → `zcode.z.ai/.../anthropic/v1/messages`（验证码被拒则失效缓存重解，最多 3 次；mode=off 或求解失败时跳过验证码头）→ JWT 直连（风控拦截后跳过）；
   - 付费路径：`x-api-key` → `api.z.ai/api/anthropic/v1/messages`（无需验证码；balanced 模式下软失败立即级联同账号付费）。
5. 上游错误分类：`401/403→invalid`（先试 refresh_token 刷新；付费通道仅冷却付费 1h，不判死账号）；`429→请求内退避重试一次`（尊重 Retry-After 1-5s，缺省 2s），仍失败按梯度 cooling 30s→120s→300s（免费/付费独立记忆，成功清零；业务码 1302/1303 同按限流）；`402/余额短语→exhausted`（付费侧冷却 6h）；`3012 unusual activity→风控`（优先于 401/403 判定），试其余路径，全败按风控梯度 120s→30min→24h（24h 窗口内累进）；`3xx→cooling 120s`（WAF 挑战）；`2xx 但非 json/sse→cooling 120s`；HTML 挑战/拦截页→通道冷却 300s；`2xx JSON 错误信封→502 并解除会话粘滞`；其余原样回传。挑战页（3xx 或 2xx 非 JSON/SSE）返回客户端时统一为 `502`，不伪装 200。
6. 成功：`MarkUsed`（记录使用；cooling 到期后自动重新可选，exhausted 仅由额度刷新确认有余量后恢复）+ 节流额度刷新（30s，进程内单飞）+ 流式透传/转换 + SSE 嗅探写 `usage_records`（含 TTFT 与缓存 token，网关 Key 配额同步记账）；客户端中途取消按 499 落库。
7. 全败：返回 Anthropic 错误信封 `{"type":"error","error":{type,message}}`。全部账号均为限流冷却时回 **529 `overloaded_error` + Retry-After**（客户端有专门过载分类与精确退避）；混合故障（限流+鉴权失效/耗尽/风控等）或付费闸拦截时回 503 `no_available_account`，若因冷却则附「约 N 秒后自动恢复」与最近失败原因链（经出口代理的连接失败只写「代理不可达」，不泄露代理地址）。

### 3. 并发与锁模型

| 锁/原语 | 位置 | 语义 |
| --- | --- | --- |
| `pool.rotation` (mutex) | 选号游标 | round_robin 按 `group\|provider` 递增 |
| `claimLocks[id]` (per-account mutex, TryLock) | 领取/重置 | UI 手动与 cron 并发不双领/双重置 |
| `groupSem` (per-proxy-group cap-1 chan) | 验证码 | 按出口代理分组唯一求解，前台等待 45s 上限；后台刷新用非阻塞 TryAcquire，无锁泄漏路径 |
| `accountSlots[id×channel]` (cap chan, 默认 3, 1-32) | 在途并发 | 账号 × 通道隔离闸门；客户端断开/超时同路释放 |
| `execLocks[planId]` (per-plan mutex, TryLock) | cron | 长计划不排队堆积，cron 拿不到锁跳过本 tick；手动运行拿不到锁报「计划正在执行中」 |
| `clientCache` (sync.Map) | HTTP 客户端 | 键 `(proxy, 指纹, JA3, timeout, 是否 zcode)`；设置变更 `CloseIdleClients()` |
| SQLite `MaxOpenConns(1)` + WAL | 存储 | 单写串行，busy_timeout 5s |

### 4. 数据库 Schema（SQLite, WAL）

| 表 | 关键列 | 用途 |
| --- | --- | --- |
| `accounts` | `user_id`（自然键，UNIQUE）、`auth_type`、`zcode_jwt`、`api_key`、`access_token`、`device_mid`、`creds_raw`、`status`、`enabled`、`account_group`、`quota_json`、`plan_tier/expire`、`total/used/remaining`、`cooling_until`、`use/fail_count`、`priority`（默认 100）、`paid_fallback`、`paid_cooling_until` | 账号、凭证、额度快照；upsert 用 `COALESCE(NULLIF(excluded.x,''), x)` 保留 device_mid/creds_raw |
| `settings` | KV | 策略、刷新间隔、代理、指纹、验证码模式、模型清单、口令哈希、api_key |
| `claim_plans` | cron_expr、task_type（detect/claim/activate）、target_type、delay_seconds、last_run_* | 活动计划（旧 reset 计划仅可删除） |
| `claim_records` | account_id、task_type、plan_id、success、code、next_at、used_at | 领取/检测/重置历史 |
| `usage_records` | account_id、model、in/out/total tokens、cache_read/creation_tokens、channel、gateway_key_id/key_name、stream、status_code、duration_ms、ttft_ms | 用量、延迟、通道路由、网关 Key 记账 |
| `proxy_nodes` | type/host/port/auth、is_default、group_name、check_* | 分组出口代理 |
| `plan_run_records` | plan_id、status、success/fail_count、duration_ms | 计划运行历史 |
| `gateway_keys` | name、key_hash（UNIQUE）、key_prefix、enabled、rpm_limit、quota_total/used、models | 网关子 Key（明文不落库，仅哈希） |

### 5. 上游协议细节

#### 5.1 端点

| 用途 | 端点 | 认证 |
| --- | --- | --- |
| 消息（免费通道） | `POST zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages` | Bearer JWT + 验证码头 |
| 消息（Key 通道） | `POST api.z.ai/api/anthropic/v1/messages` | `x-api-key` |
| 额度 | `GET zcode.z.ai/api/v1/zcode-plan/billing/balance?app_version=`（现行端点；`billing/current` 已废弃，仅兜底） | Bearer JWT |
| Key 通道额度 | `GET api.z.ai/api/monitor/usage/quota/limit` + `/api/biz/subscription/list` | Authorization 直传 Key（无 Bearer 前缀，对齐官方客户端） |
| 活动预览 | `GET zcode.z.ai/api/v1/zcode-plan/billing/preview?app_version&platform` | Bearer JWT |
| 领取 | `POST zcode.z.ai/api/v1/zcode-plan/billing/claim` `{plan_id}` | Bearer JWT + 验证码头 |
| 激活 | `POST zcode.z.ai/api/v1/event/report`（app_launch + app_daily_active） | Bearer JWT |
| 配额重置 | `GET/POST zcode.z.ai/api/v1/coding-plan/reset/{status,use}`（重置历史由 status 响应内 `latest_*_reset_history` 派生） | Bearer JWT + `X-Bigmodel-Authorization` + `Bigmodel-Target-Type` |
| OAuth | `chat.z.ai/api/oauth/authorize` → `zcode.z.ai/api/v1/oauth/token` → `api.z.ai/api/auth/z/login` → `biz/customer/getCustomerInfo` → `biz/v1/organization/{org}/projects/{proj}/api_keys` → `.../copy/{key}` | 无 |
| 验证码配置 | `GET zcode.z.ai/api/v1/client/configs?version&os` → `data.configs.captcha{enabled,prefix,region,sceneId}` | 无 |
| 模型目录 | 同上 → `data.builtinModels[] / providers[]` | 无 |

#### 5.2 请求头

身份头：`User-Agent: ZCode/{ver}`、`X-ZCode-App-Version`、`X-Title: Z Code@electron`、`X-Platform: win32-x64`、`X-Release-Channel: stable`、`X-Client-Language`（Intl locale）、`X-Client-Timezone`（Intl tz）、`X-Os-Category`（win32→windows）、`X-Os-Version`（10.0.build）、`X-Device-Mid`（telemetry-state.json）、`x-request-id`（uuid）。

消息通道追加：`anthropic-version: 2023-06-01`、`X-ZCode-Agent: glm`、`HTTP-Referer: https://zcode.z.ai`、`X-Aliyun-Captcha-Verify-Param`（+Region）。官方客户端 3.14.x 已移除模型请求验证码，该头仅在 `client/configs` 报告 `captcha.enabled` 时发送。

#### 5.3 错误码语义

| code | 含义 | 网关动作 |
| --- | --- | --- |
| 1001/1002 | 套餐不存在 / 活动已结束 | 提示 |
| 1003 | 已领取过 | 视为成功空跑（幂等） |
| 1004 | 不符合条件 | 提示 |
| 1005 | 今日名额用完 | 读 `data.plan.ends_at` → next_at |
| 3001 / 3007 | 参数错 / 验证码失败 | 重解验证码重试 |
| 3101 | coding plan is required | 重置门槛不满足 |
| 3301 | 重置机会授予 | 成功 |
| HTTP 3012 | unusual activity（风控） | 试其余路径，全败 cooling |
| HTTP 429 | 限流 | 退避重试 → cooling 30s |

### 6. SSE / 协议转换

- Anthropic→OpenAI chat：`message_start→首 chunk(role)`、`content_block_delta.text_delta→delta.content`、`thinking_delta→delta.reasoning_content`、`tool_use→delta.tool_calls[index]`、`message_delta→finish_reason`、末尾 `usage chunk(include_usage)` + `[DONE]`。
- Anthropic→Responses：`response.created/output_item.added/reasoning_summary_part.added/reasoning_summary_text.delta/reasoning_summary_text.done/reasoning_summary_part.done/content_part.added/output_text.delta/function_call_arguments.delta/output_text.done/output_item.done/response.completed`（思考以 `type:reasoning` 输出项流式发出，`response.completed.output` 与事件序列一致）；错误/断流发 `response.failed`。
- OpenAI→Anthropic 请求：system/developer→`system` 串；tool→`tool_result`；assistant.tool_calls→`tool_use`；image_url 仅接受 data: base64（其余形态返回 400，不静默丢弃）；tool_choice auto/required/name 映射。reasoning_effort 透传至 GLM-5.3 思考档位，非 5.3 模型丢弃。不按助手输出从全局缓存回填签名思考块，避免跨用户/会话泄露；需重放签名思考块的客户端应使用 Anthropic 原生接口并显式携带原始块。
- Responses→Anthropic：instructions→system；input[] 的 message/function_call/function_call_output 映射；reasoning.effort→reasoning_effort。
- 健壮性：SSE 解析缓冲上限 16MB（超限按流失败处理，不静默清空）、跨 chunk 断帧兼容 LF/CRLF；命名 `event:error`、匿名 `data:` 错误帧（顶层 `error` 字段或 `type=error`）与 `err!=io.EOF` 均按失败处理（不伪装成功）；非流式响应聚合读取上限 64MB（超限按失败）；工具调用参数中途截断按流失败处理（不静默截断）；上游零事件干净 EOF 按 502 返回；客户端取消按 499 落库；非流式响应体总读取时限 15 分钟（超时/中断按 502 + 账号冷却 60s，截断 body 不下传；流式由客户端 600s 空闲超时兜底，静默期注入协议合法 `ping` 帧）；url 形态图片受控抓取内联（SSRF 连接前 IP 校验、直连不走代理、5MB/张、单请求 24 张/32MB base64 上限、URL 去重，失败 fail-closed 400）。

### 7. 验证码子系统（阿里云无痕）

> 官方客户端自 3.14.3 起源码中已无任何验证码逻辑（模型请求免验证），本子系统仅在 `client/configs` 报告 `captcha.enabled` 时参与请求，否则自动跳过；保留用于领取等仍可能触发的场景。

- 配置：`client/configs` → `{enabled,prefix,region,sceneId}`，缓存 10min。
- 求解：rod 启动本机真实 Chrome/Edge（捆绑 Chromium 会被风控识别），先访问 `zcode.z.ai` 建立同源，注入 SDK HTML（配置值经 JSON 转义防注入），`startTracelessVerification` → `__onCaptcha` 回调捕获 param；持久化 user-data-dir 保留风控 cookie。
- 缓存：按出口代理分组，TTL 45s；过期后 300s 宽限期内返回旧值并后台刷新；失败缓存 60s 防风暴；无头连败 2 次升级有头手动（手动模式 10 分钟无操作回落无头）；求解预算前台 45s、后台 120s；`captcha_prewarm=0` 关闭预热。
- 容器：Docker 镜像内置 Alpine chromium 可直接求解（容器内仅无头，有头手动兜底不可用）；Cloudflare/WAF/通用拦截页由 relay 层识别，按通道冷却 300s，不误伤凭证。
- 风控：数据中心 IP 触发 F001；参数单次/短时有效，被拒即失效重解。

### 8. TLS 指纹与传输策略

- 官方栈：Electron 41 / Chromium 146（BoringSSL、TLS1.3、PQ 曲线 X25519MLKEM768=4588、ECH=65037、ALPS=17613）。
- 实测：zcode.z.ai 的 ESA WAF 不做严格 JA3 白名单（stdlib/utls/浏览器均放行），风控基于行为/验证码/频率；api.z.ai 的 ALPN 仅 h2。
- 策略：`zcode.z.ai` → utls 预设（默认 Chrome 族）+ HTTP/1.1；其余 → 标准库 + HTTP/2；客户端按 `(proxy,指纹,JA3,timeout,主机)` 缓存。
- 自定义 JA3：5 段（版本、套件、扩展、曲线、点格式）→ `utls.ClientHelloSpec`；设置页服务端预校验。

### 9. 本地凭证与切回

- `~/.zcode/v2/credentials.json`：`enc:v1:` + b64url(nonce12).b64url(tag16).b64url(ct)，AES-256-GCM；key = SHA-256(`zcode-credential-fallback:{win32}:{home}:{user}`) 或 `ZCODE_CREDENTIAL_SECRET`。与官方/参考实现逐字节兼容（含跨语言测试向量）。
- 切回：备份 `credentials.json` + `config.json` 到 `data/backups/` → 重新加密写回（临时文件 + rename 原子）→ 可选结束 `ZCode.exe`；快照还原可撤销。
- 账号包：`zcb1:` + base64(salt16‖nonce12‖ct)，PBKDF2-SHA256 60 万轮 + AES-256-GCM（旧 12 万轮包仅可导入）。

### 10. 管理 API（节选，session 鉴权）

`/api/login|logout|auth/check|auth/password`；`/api/dashboard`；`/api/accounts`（GET/PUT/DELETE）+ `/import/local|paste|bundle` + `/export` + `/{id}/refresh|claim|detect|activate|reset|reset-status|switch-back|restore-local`；`/api/groups`；`/api/plans`（CRUD + `/{id}/run` + `/running`）+ `/plan-runs` + `/claim-records`；`/api/usage-records` + `/stats`；`/api/settings` + `/settings/api-key[/generate|/reveal]`（生成/揭示需密码步升）；`/api/keys`（GET/POST/PUT/DELETE，网关 Key 管理，签发需密码步升）；`/api/proxies`（CRUD + `/{id}/test` + `/test-url` + `/system` + `/probe-ports`）；`/api/captcha/status|invalidate|solve`；`/api/fingerprints`；`/api/models[/sync|/catalog]`；`/api/offpeak/availability`；`/api/accounts/oauth/start|manual|status`。

</details>

## 已知限制

- utls v1.8.2 无法表达 PQ 曲线 4588 与新 ALPS id（17613），自定义 JA3 的 key_share 仅 X25519。
- OAuth 环回 `redirect_uri` 未被 Z.AI 注册（`Redirect URI not registered`），默认使用免回调轮询或手动粘贴。
- 多出口代理下验证码参数按代理分组缓存，跨组不共享。
- `/v1/messages/count_tokens` 为启发式估算而非官方 tokenizer：ASCII 约 1/4 字、CJK 1 字 1 token、其他约 1/2，另加 5% 余量、每消息/结构开销，图片/文档块按 1500 tokens 估值。官方客户端 3.14.x 已不调用该端点，仅为兼容保留。
- GLM-5.3 思考参数按官方 3.14.x wire 格式发送（`thinking:{type:adaptive}` + `output_config.effort`）；上游若回退旧版可能需重新调整。
- 账号包导出使用 PBKDF2 60 万轮；旧 12 万轮加密包仅支持导入（自动回退），不再生成。
- 库内凭证已静态加密（`vault1:` AES-256-GCM），密钥默认为随机生成的 `data/vault.key`（0600，首次启动创建）。`vault.key` 必须与 `data/` 一同备份，丢失即库内凭证永久不可读；跨机器迁移可改用 `ZCODE_PROXY_VAULT_SECRET` 指定种子（同样需妥善保管，env 模式不在磁盘留钥）。启动时自动迁移存量明文；迁移前的明文可能残留在 WAL/空闲页，敏感场景请在迁移后执行 `VACUUM`。代理节点密码同被加密；钥匙不可用时进入降级态，拒绝写入新凭证，解密失败的节点标记 `password_broken` 并跳过拨号。
- `/async/v1/messages` 闲时通道为一次性应答、无会话记忆（上游语义）；多轮对话请在请求内携带历史。
- 闲时通道取票/排队/就绪全链路已打通，请求强制 `stream=true`；消息转发遇 `3001` 按票过期语义自动同票重试，但上游转发是否对全部账号状态可用仍待上游行为明确。

## 仓库与数据边界

`data/`（SQLite、备份、浏览器 profile）、`*.log`、`*.exe`、`config/config.json`、`refs/` 均在 `.gitignore`，不会提交。`data/` 含真实账号凭证，请勿外传。克隆后首次运行会自动生成配置与空库。

## 参考项目（致谢）

本项目的协议与网关设计参考并整合自以下开源工作：

- [liu5269/zcode2api](https://github.com/liu5269/zcode2api)：Z.AI 2API 网关的核心参考，上游端点、请求头、验证码绑定、额度归一化与状态机语义大量借鉴其实现；
- [pjpv/zcode-switch](https://github.com/pjpv/zcode-switch)：多账号切换、活动领取、本地凭证加解密（Rust）参考；
- [vibe-coding-labs/zcode-reverse-engineer](https://github.com/vibe-coding-labs/zcode-reverse-engineer)：协议逆向文档参考。

## 开发

```bash
go build ./...
go vet ./...
go test ./...
go test -race ./...
```

CI 使用 `go.mod` 中的 Go 版本（1.26），执行 build、vet、test 与 race test。Docker 构建阶段为 `golang:1.26-alpine`，运行阶段为 `alpine:3.20` 加 Chromium，非 root（uid 10001）。

## 免责条款

1. **学习交流目的**：本项目仅供个人学习、研究和技术交流使用，旨在帮助理解 OAuth 授权流程、API 网关设计、TLS 指纹与客户端凭证存储等通用技术原理；不得用于任何商业盈利、对外售卖服务或任何形式的违法用途。
2. **遵守服务条款**：使用本项目即表示你承诺遵守 Z.AI / ZCode 的服务条款、用户协议与相关法律法规；本项目不鼓励、不协助任何违反服务条款的行为（包括但不限于滥用免费额度、绕过付费、批量注册、转租账号）。
3. **风险自担**：因使用本项目导致的账号限流（429）、风控拦截（3012）、套餐冻结、账号封禁、额度损失等后果，均由使用者自行承担；作者不提供任何形式的补偿或恢复保证。
4. **凭证安全自负**：本项目会在本地存储账号凭证（JWT / API Key / 凭证快照）。使用者应自行保管好本机与 `data/` 目录、加密账号包与网关 `sk-` Key；因保管不当导致的凭证泄露、账号被盗用、财产损失，作者不承担责任。
5. **无担保**：本项目按「现状」提供，不作任何明示或暗示的担保（包括可用性、稳定性、准确性、不侵权）；上游接口可能随时变更、限流或下线，本项目不保证持续可用。
6. **合规使用网络与代理**：使用者应确保所用出口代理、网络环境合法合规；因代理或网络行为引发的法律责任由使用者承担。
7. **侵权处理**：若本项目内容侵犯了你的合法权益（含商标、版权），请联系作者，将在核实后第一时间删除相关内容。
8. **法律适用**：因使用本项目产生的任何争议，适用使用者所在地法律法规；继续使用即视为已阅读并同意本免责条款全部内容。

> 简而言之：仅供学习交流，商用与违法用途禁止；账号与凭证风险自负；上游规则变化不保证兼容。
