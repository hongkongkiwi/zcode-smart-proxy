# Rust cutover checklist

Go remains the production service. A green build or an offline import does not authorize changing the HAProxy backend. Use this checklist with the [existing deployment runbook](README.md).

## Before routing traffic

- Verify the exact candidate commit on Linux/amd64. Start its release image against an isolated Rust volume on a separate private port. Keep the Go image, Compose configuration, HAProxy configuration, and data available for rollback. Check disk and memory headroom before staging another image or database on the shared host.
- Rehearse the import and rollback with synthetic data. The importer must preserve the source checksum, produce an intact archive and runtime database, and reopen the runtime database with its generated key. Rust must never open the Go database directly or share its data volume.
- Compare ordinary and streaming requests, authentication and key limits, and challenge-required responses. Use approved upstream verification or a human handoff for challenges. Do not count a health check or synthetic upstream response as provider acceptance.
- Keep highspeed draws and automatic spending disabled during parity testing. Do not mirror requests that can charge quota, draw cards, acquire tickets, or spend reset slots. Use synthetic responses or separately approved test accounts for those paths.
- Check imported schedules against the archive before enabling them. The importer carries over plan definitions and run history but pauses every imported plan. Reconcile any interrupted runs and check that Rust supports the task before re-enabling it. Usage history and non-reset claim records remain in the archive. The runtime reset guard can see imported successful resets that have a `used_at` timestamp. Reconcile legacy rows without that timestamp or keep reset automation disabled.
- Confirm the rate limit reset is acceptable. Go keeps rolling request counts in process memory, so a restart or switch loses current counts. Existing gateway key limits and cumulative quota balances are imported. Do not infer rolling counts from usage history; completed requests are not the admission ledger.

## Switch and rollback

1. Drain Go traffic and stop all writers before copying the source. Retain the database, any SQLite sidecars, the matching vault key, and the original configuration in a private backup. Validate the backup before starting Rust.
2. Import the stopped snapshot into a fresh destination using `zcode-proxy-rs import-go`. Start Rust against its own `zcode-rs.db` and adjacent `vault.key`. Do not pass the source vault override to the runtime. Verify the actual path and mount before startup.
3. Verify private health, admin sign-in, gateway authentication, and test streaming before changing HAProxy. Validate the HAProxy configuration before reloading. Keep only one service receiving production requests. Verify the public hostname after the switch.
4. If smoke checks fail, drain and stop Rust, restore the old HAProxy backend, and restart Go against its original database and matching key. Verify public health, authentication and streaming again. Keep the Rust volume and logs for investigation. An old Go snapshot cannot recover usage or spending that happened on Rust after the switch; reconcile those effects before re-enabling automation or repeating a chargeable action.
