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
- Account and authentication handlers exist, but their security and persistence
  behavior is not yet verified for cutover. Account writes currently store
  credentials without vault encryption. Router regressions now cover password
  and second-factor lockout plus mutation Origin rejection. Lockout currently
  uses the socket peer IP, not untrusted forwarded headers. Clients behind one
  reverse proxy still share its bucket; explicit trusted-proxy handling remains
  unfinished.
- Vault: AES-256-GCM with Go's vault1 envelope, validated against 14
  Go-generated fixture cases.
- Read-only Go account loading passes ten synthetic storage regressions,
  including encrypted credentials, paid-fallback preservation, wrong-key
  rejection, and unchanged source data. This is not a runtime migration.

The current workspace test run passes 154 tests across 14 suites, and strict
Clippy passes. Changed-file formatting passes. The workspace formatting check
still fails on existing formatting in the frozen safety regression file, which
was left unchanged. These checks do not establish Go feature parity.

## Remaining work

1. Compatible encrypted storage and schema migration. The Rust runtime store
   still uses a reduced schema and is not wired to vault encryption. Read-only
   Go account helpers are separate from runtime startup and do not migrate data.
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
