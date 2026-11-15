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
- The experimental service has a separate SQLite schema, a basic admin API,
  and TOTP enrollment. These do not yet provide Go storage or authentication
  compatibility.

At commit `5c8a252`, workspace tests reported 95 passed and strict Clippy
completed without warnings. Those checks do not establish feature parity.

## Remaining work

1. Incremental streaming, bounded response handling, and durable token-based
   gateway-key accounting for every response path.
2. Authentication parity: login lockout, CSRF protection, password step-up,
   enrollment expiry, atomic recovery-code consumption, passkeys, secure-cookie
   policy, and safe panel rendering.
3. Compatible encrypted storage, explicit schema migration, error propagation,
   and recovery tested against synthetic Go database and vault fixtures.
4. Account CRUD, import/export, OAuth, credential refresh, gateway-key management,
   quota refresh, and the existing admin UI contracts.
5. OpenAI chat/completions/responses protocols, async ticket and highspeed-card
   workflows, model retrieval, and the full upstream-header policy.
6. Actual billing claim/reset execution and scheduled automation. Request
   constructors and pure decision helpers are not running cron jobs.
7. Browser CAPTCHA solving and fingerprinted TLS transport. The current traits
   and no-op implementations are placeholders, not completed integrations.
8. Release packaging, rollback-safe migration, side-by-side traffic validation,
   and a production cutover only after parity checks pass.

## Local checks

```sh
cargo test --manifest-path rust/Cargo.toml --workspace
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets -- -D warnings
cargo fmt --manifest-path rust/Cargo.toml --all --check
```
