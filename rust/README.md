# zcode-proxy Rust port

Test-port-first migration of the Go proxy (~45k LOC) to Rust. The Go
deployment on the DO droplet stays the system of record; nothing here ships
until the ported core passes the same traffic behind the live service.

## Phase status

| Phase | Scope | State |
|-------|-------|-------|
| 1 | Protocol core, pure functions: model table, biz-code matchers, SSE parser, Anthropic aggregator, count_tokens estimator | **done, 32 acceptance vectors green** |
| 2a | Failure-classification ladder (the >=400 order + 2xx envelope path), account selectability, cooldown/risk ladders, gateway-key windows (168-slot ring) + RPM + quota charge | **done, 15 more vectors green (47 total)** |
| 2b | Channel selection (free-first/balanced/never strategies, sticky sessions, per-phase skip maps), auto-reset decision logic, egress seams | **done, 12 more vectors green (59 total)** |
| 3 | Egress seams: FingerprintDialer (target rquest) + CaptchaSolver (target chromiumoxide) traits with fail-closed defaults | **seams done; live WAF/browser validation pending** |
| 4 | Data-plane HTTP surface: axum binary — /v1/messages + shape aliases, count_tokens, models, key auth, free-first ladder with balanced cascade | **done, 6 E2E tests green** |
| 5 | Persistence + admin: sqlite (WAL) store, AppState::from_db, session auth (CSPRNG, restart-revokes), bcrypt login, settings whitelist, accounts/usage/stats, /web panel | **done, 3 store + 2 admin E2E green (70 total)** |

Remaining vs the Go service (deploy-time, not portable here): captcha/
fingerprint live validation against the real WAF, the full 2FA machinery,
promo auto-claim + reset cron jobs, and the docker image swap on the DO
droplet.

## Port contract

- Byte-faithful semantics: every module doc comment names its Go origin file
  and the invariants that must not drift (the 2026-10-26 dead-branch fix, the
  1005 exhaustion family, the 3104/3106 ticket-death codes, F2 truncation).
- The Go test tables are the acceptance gate; each ported vector is marked
  with its Go test name. Behavior differences found while porting are ported
  as-is with a comment (e.g. `strings.Contains` phrase matching in
  `is_exhausted_error`), never silently fixed.
- Phase 1 is pure functions only: no async, no I/O, deps limited to serde
  and base64.

## Running

```bash
cd rust && cargo test
```
