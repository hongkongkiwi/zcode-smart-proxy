# zcode-proxy Rust port

Test-port-first migration of the Go proxy (~45k LOC) to Rust. The Go
deployment on the DO droplet stays the system of record; nothing here ships
until the ported core passes the same traffic behind the live service.

## Phase status

| Phase | Scope | State |
|-------|-------|-------|
| 1 | Protocol core, pure functions: model table, biz-code matchers, SSE parser, Anthropic aggregator, count_tokens estimator | **this crate, 32/32 acceptance vectors green** |
| 2 | Relay state machine: account pool, penalty ladders, sticky routing | not started |
| 3 | Egress: utls fingerprinting -> `rquest`, rod captcha -> `chromiumoxide` | not started; the two hard dependency ports |
| 4 | HTTP surface: axum handlers for `/v1/*`, `/api/v1/*` aliases, admin panel | not started |

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
