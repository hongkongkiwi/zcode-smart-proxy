# Rust migration status

The Rust implementation is incomplete. The Go service remains the production
implementation. Do not replace it with the Rust binary or point Rust at the
production Go database.

## Verified increments

- Protocol helpers, model aliases, response aggregation, and failure classifiers
  have Rust tests. These are selected cases, not a port of the full Go suite.
- Account selection and admission controls have router-level regressions.
  Disabled accounts are excluded, paid opt-out and cooldowns are enforced,
  pause blocks generation, and settings reads exclude private values.
- Supported control settings are validated before writes. Selection changes
  apply without restarting, and balanced fallback avoids repeated paid calls.
- True incremental streaming with bounded SSE sniffing, empty-stream error
  frames, and disconnect-aware usage accounting.
- Account management: add/delete/enable routes, password change, login lockout
  (5 failures / 15-minute window), CSRF origin gate, TOTP 2FA with recovery
  codes.
- Vault: AES-256-GCM with Go's vault1 envelope, validated against 14
  Go-generated fixture cases.

At the current tip, workspace tests report 128 passed and strict Clippy is
clean. Those checks do not establish feature parity with the Go service.

## Remaining work

1. Compatible encrypted storage and schema migration (the Rust store schema is
   reduced and does not read the Go vault1 envelope).
2. Account CRUD beyond add/delete/enable: update, import/export, OAuth,
   credential refresh, quota refresh.
3. Admin lockout on named-key management, password step-up, enrollment expiry,
   passkeys.
4. OpenAI streaming chunk relay (Anthropic SSE -> chat.completion.chunk),
   async ticket and highspeed-card workflows.
5. Actual billing claim/reset execution and scheduled automation. Request
   builders and pure decision helpers are not running cron jobs.
6. Browser CAPTCHA solving and fingerprinted TLS transport. The current traits
   and no-op implementations are placeholders, not completed integrations.
7. Release packaging, rollback-safe migration, side-by-side traffic validation,
   and a production cutover only after parity checks pass.

## Local checks

```sh
cargo test --manifest-path rust/Cargo.toml --workspace
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets -- -D warnings
cargo fmt --manifest-path rust/Cargo.toml --all --check
```
