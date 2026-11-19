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

The current workspace run passes 506 tests across 69 suites, and strict Clippy
passes. This includes encrypted storage, startup key handling, and OpenAI
streaming regressions. Stream failures record one durable error status, malformed
frames cannot finish successfully, and generated heartbeats do not postpone the
upstream silence deadline. The scoped stream repair review found the reported
blocking defects resolved. Numeric account deletion and enable/disable routes
have regression coverage for successful writes, missing IDs, and database
failures. The workspace formatting check now passes after formatting the safety
and encrypted-store regression files without changing their assertions or
fixtures. These checks do not establish Go feature parity.

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
2. Background account lifecycle and multi-instance discovery. Local import reads
   plaintext and desktop `enc:v1:` credentials plus sibling config/telemetry,
   preserves identity and metadata, and stores credentials under the runtime
   vault. Desktop secret derivation follows Go's environment and machine
   fallback rules, including Node's `darwin` platform name on macOS. Selected
   corrupt ciphertext fails closed without changing account state. Manual,
   public-callback, and polling OAuth enrollment retrieve identity and API-key
   metadata and persist encrypted accounts. Poll workers have bounded retry,
   expiry, cancellation, and deadline-aware storage admission. Flows have strict expiry, replay
   protection, bounded retries, and redirect refusal. OAuth wire tests pin Go's
   source contract, not live-provider acceptance. Manual quota refresh uses JWT
   billing and raw API-key monitor endpoints, with bounded requests, client
   identity headers, quota persistence, and per-account singleflight. Rejected
   credentials can now trigger stored refresh-token exchange with atomic encrypted
   persistence, rotation preservation, backoff, and stale-import protection.
   The exchange request shape follows Go's inferred contract, not a live-provider
   capture.
   Paste import parses and stores JWT/API-key credentials with stable identities
   and encrypted persistence. Paste, local, and OAuth imports schedule delayed
   quota refresh through a bounded manager. It deduplicates pending accounts,
   serializes follow-ups, skips deleted/disabled accounts, and retains in-flight
   handles when shutdown exceeds its deadline. Bundle and plain-add routes do
   not schedule refresh, matching Go. Default local import discovers up to 64
   desktop instances with per-instance credential secrets, deterministic order,
   bounded files, and static symlink checks. An explicit credential path disables
   discovery. Responses retain the first account and add imported accounts plus
   sanitized per-instance errors; storage failures report committed counts.
   Directory names remain user-supplied labels in remarks/errors. Concurrent
   filesystem replacement is not protected by descriptor-relative traversal.
   Production enrollment jobs send a best-effort installation sequence before
   quota refresh: unauthenticated client config, then two authenticated activity
   events. Requests have per-step bounds, redirect refusal, and credential/stop
   checks between steps. Reports use the actual host OS, without randomized
   desktop fingerprints. Isolated state constructors leave reporting off.
   These wire contracts are source-derived, not live-provider validation.
   Per-account device identities persist as UUIDv4
   values before quota and billing requests. Startup backfills empty identities
   atomically; existing identities remain unchanged.
   Encrypted account bundle export/import now supports Go's current and legacy
   `zcb1:` formats, stable account identities, all bundle metadata, and atomic
   import rollback. Export requires password step-up and checks every stored
   credential, including unselected accounts. The offline database importer now
   projects all account bundle metadata and re-encrypts all six credential
   fields while preserving account IDs, cooldowns, balances, and routing state.
3. Remaining admin step-up surfaces and passkeys. Named gateway keys now have
   session-protected CRUD, create-time password step-up, one-time plaintext
   display, hashed storage, policy validation, and immediate authentication
   updates without clearing rate history. Key creation currently holds the DB
   writer lock during password verification to keep the checked password stable
   through commit; this can delay concurrent usage commits. TOTP
   confirmation now requires the current password and a pending setup less than
   ten minutes old. Confirmation and disable have separate peer/action throttles;
   disable requires both password and an active factor or recovery proof.
4. Broader OpenAI compatibility coverage beyond the current streaming tests,
   plus async ticket and highspeed-card workflows.
5. Manual billing routes cover preview and claim, Start Plan activation events
   with billing confirmation, and reset status/use. Synthetic HTTP tests cover
   the wire requests, audit retention after account deletion, activation state
   recovery, and rollback on ledger failures. Detect writes audit records without
   changing claim summaries. Activation can use a stored imported identity after
   profile/JWT lookup, but rejects known synthetic identity formats. Successful
   claims and resets commit their audit before optional billing confirmation;
   cancellation during confirmation preserves the remote acknowledgement.
   Plan CRUD, five-field cron validation, next-run display, and claim/run history
   readers exist with session protection and bounded queries. The scheduler runs
   detect and activation plans, supports run-once execution, deduplicates trigger
   minutes durably, and records interrupted runs at startup. Shutdown stops new
   work and reports tasks that outlast its drain deadline without dropping their
   join handles. Scheduled claims are blocked without documented free-grant
   eligibility; reset plans are refused. Explicit POST reset-history sync imports
   upstream reset records with per-kind deduplication, atomic anchors, and
   success-only throttling. GET reset-status remains read-only and never spends
   a reset slot. Natural-wait decisions and slot-attributed replay guard helpers
   have independent boundary tests. A bounded automatic reset manager now
   evaluates opt-in threshold and expiry jobs, shares manual spend stamps,
   checks cold reset history, and audits acknowledged spends before quota-only
   refresh. It rechecks credentials, administrator state, and stop state before
   requests. Free-channel exhaustion persists account state before relay
   enqueue; confirmed exhausted quota refreshes enqueue only after releasing
   their write locks and singleflight guard. Scheduler ticks sweep expiring
   slots separately from plans. Paid-channel failures and protocol passthrough
   never trigger reset spending. Both switches stay off unless explicitly set.
   The admin API validates all five settings and persists batches atomically.
   The legacy slot-lifetime helper is retained for API
   compatibility and is not suitable for the automatic reset service.
   The default CAPTCHA solver fails closed;
   manual claims need a real solver before operational use. Highspeed
   consumption remains opt-in. Scheduler signal handling has source review but
   no process-level signal test yet.
6. Global egress configuration now reaches inference, quota, token refresh,
   OAuth, billing/reset, and installation clients. Proxy secrets persist encrypted;
   settings reads omit userinfo. Invalid configuration fails closed, including
   invalid proxy settings during offline Go import. Explicit direct mode ignores
   ambient proxy environment variables. Loopback HTTP proxy tests cover routing
   and authentication. Local CONNECT, trusted/untrusted HTTPS-proxy, and SOCKS
   tests now exercise certificate verification and scoped proxy credentials.
   Those tests require OpenSSL and Python 3. Group/default proxy nodes have
   session-protected CRUD, encrypted password preservation, immediate routing,
   and offline Go projection with IDs and metadata preserved. Selected broken
   node credentials fail closed. Node hosts must be IP literals or RFC1123
   hostnames; legacy underscore/Unicode hosts need correction before import.
   Inference uses the captured request-start account group so account deletion
   does not break an in-flight fallback. Proxy probes/system discovery, browser
   CAPTCHA solving, and fingerprinted TLS remain unfinished.
7. Release packaging, rollback-safe migration, side-by-side traffic validation,
   and a production cutover only after parity checks pass.

## Local checks

```sh
cargo test --manifest-path rust/Cargo.toml --workspace
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets -- -D warnings
cargo fmt --manifest-path rust/Cargo.toml --all --check
```
