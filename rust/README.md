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
  behavior is not yet verified for cutover. Account credentials and private
  settings now use vault encryption. Eighteen persistence regressions cover
  encrypted writes, secure reloads, and rollback on database failures.
  Router regressions cover password
  and second-factor lockout plus mutation Origin rejection. Lockout currently
  uses the socket peer IP, not untrusted forwarded headers. Clients behind one
  reverse proxy still share its bucket; explicit trusted-proxy handling remains
  unfinished.
- Vault: AES-256-GCM with Go's vault1 envelope, validated against 14
  Go-generated fixture cases.
- Read-only Go account loading passes ten synthetic storage regressions,
  including encrypted credentials, paid-fallback preservation, wrong-key
  rejection, and unchanged source data. This is not a runtime migration.

The current workspace run passes 207 tests across 25 suites, and strict Clippy
passes. This includes encrypted storage, startup key handling, and OpenAI
streaming regressions. Stream failures record one durable error status, malformed
frames cannot finish successfully, and generated heartbeats do not postpone the
upstream silence deadline. The scoped stream repair review found the reported
blocking defects resolved. Numeric account deletion and enable/disable routes
have regression coverage for successful writes, missing IDs, and database
failures. The workspace formatting check has existing failures in the frozen
safety regression file, which remains unchanged. These checks do not establish
Go feature parity.

## Remaining work

1. Full Go runtime data migration. The explicit offline import library now
   preserves a complete Go database archive and creates a separate encrypted
   runtime projection for accounts, settings, and gateway keys. Historical usage,
   claim schedules, proxy records, and unknown metadata remain in the archive;
   those features are not activated in Rust. The explicit command is
   `zcode-proxy-rs import-go <source-db> <destination-dir>`, with the source vault
   secret supplied through `ZCODE_PROXY_VAULT_SECRET`, never a command argument.
   It exits after import without starting HTTP or applying bootstrap settings.
   Stop every source writer before import. A forcibly terminated import can
   leave a private `.zcode-import-*` directory; inspect it and confirm no import
   is running before removing it. Normal startup still refuses Go databases.
2. Account CRUD beyond add/delete/enable: update, import/export, OAuth,
   credential refresh, quota refresh.
3. Admin lockout on named-key management, password step-up, enrollment expiry,
   passkeys.
4. Broader OpenAI compatibility coverage beyond the current streaming tests,
   plus async ticket and highspeed-card workflows.
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
