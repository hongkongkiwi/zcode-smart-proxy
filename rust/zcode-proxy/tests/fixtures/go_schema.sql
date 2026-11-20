-- Synthetic schema copied from database.go:initSchema and NewDBWithOptions migrations.
-- No Rust-only aliases (total, used, prefix, input_tokens, output_tokens).
CREATE TABLE accounts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          TEXT NOT NULL UNIQUE,
    email            TEXT DEFAULT '',
    display_name     TEXT DEFAULT '',
    provider         TEXT DEFAULT 'zai',
    auth_type        TEXT DEFAULT 'jwt',
    access_token     TEXT DEFAULT '',
    refresh_token    TEXT DEFAULT '',
    zcode_jwt        TEXT DEFAULT '',
    api_key          TEXT DEFAULT '',
    user_info        TEXT DEFAULT '',
    device_mid       TEXT DEFAULT '',
    creds_raw        TEXT DEFAULT '',
    status           TEXT DEFAULT 'active',
    enabled          INTEGER DEFAULT 1,
    account_group    TEXT DEFAULT '',
    quota_json       TEXT DEFAULT '',
    plan_tier        TEXT DEFAULT '',
    plan_expire      TEXT DEFAULT '',
    total_units      REAL DEFAULT 0,
    used_units       REAL DEFAULT 0,
    remaining        REAL DEFAULT 0,
    use_count        INTEGER DEFAULT 0,
    fail_count       INTEGER DEFAULT 0,
    last_used_at     INTEGER DEFAULT 0,
    last_checked_at  INTEGER DEFAULT 0,
    cooling_until    INTEGER DEFAULT 0,
    last_error       TEXT DEFAULT '',
    last_claim_at    TEXT DEFAULT '',
    last_claim_plan  TEXT DEFAULT '',
    last_claim_msg   TEXT DEFAULT '',
    remark           TEXT DEFAULT '',
    created_at       TEXT DEFAULT (datetime('now','localtime')),
    updated_at       TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX idx_accounts_enabled ON accounts(enabled);
CREATE INDEX idx_accounts_status ON accounts(status);
CREATE INDEX idx_accounts_group ON accounts(account_group);
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT DEFAULT '',
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE TABLE claim_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_name TEXT DEFAULT '',
    cron_expr TEXT NOT NULL DEFAULT '0 9 * * *',
    is_active INTEGER DEFAULT 1,
    target_type TEXT DEFAULT 'all_accounts',
    account_id INTEGER DEFAULT 0,
    account_group TEXT DEFAULT '',
    task_type TEXT DEFAULT 'claim',
    auto_pick INTEGER DEFAULT 1,
    delay_seconds INTEGER DEFAULT 30,
    last_run_at TEXT DEFAULT '',
    last_run_status TEXT DEFAULT '',
    last_run_msg TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX idx_claim_plans_active ON claim_plans(is_active);
CREATE TABLE claim_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    account_id INTEGER DEFAULT 0,
    email TEXT DEFAULT '',
    task_type TEXT DEFAULT 'claim',
    plan_id TEXT DEFAULT '',
    plan_name TEXT DEFAULT '',
    success INTEGER DEFAULT 0,
    code INTEGER DEFAULT 0,
    message TEXT DEFAULT '',
    next_at INTEGER DEFAULT 0
);
CREATE INDEX idx_claim_records_account ON claim_records(account_id);
CREATE INDEX idx_claim_records_created ON claim_records(created_at);
CREATE TABLE usage_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    account_id INTEGER DEFAULT 0,
    email TEXT DEFAULT '',
    model TEXT DEFAULT '',
    prompt_tokens INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    total_tokens INTEGER DEFAULT 0,
    stream INTEGER DEFAULT 0,
    status_code INTEGER DEFAULT 0,
    duration_ms INTEGER DEFAULT 0,
    ttft_ms INTEGER DEFAULT 0
);
CREATE INDEX idx_usage_records_created ON usage_records(created_at);
CREATE INDEX idx_usage_records_account ON usage_records(account_id);
CREATE INDEX idx_usage_records_model ON usage_records(model);
CREATE TABLE proxy_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT DEFAULT '',
    type TEXT DEFAULT 'socks5',
    host TEXT DEFAULT '',
    port INTEGER DEFAULT 0,
    username TEXT DEFAULT '',
    password TEXT DEFAULT '',
    is_default INTEGER DEFAULT 0,
    group_name TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    check_status TEXT DEFAULT '',
    check_latency INTEGER DEFAULT 0,
    check_ip TEXT DEFAULT '',
    check_msg TEXT DEFAULT '',
    check_at TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE UNIQUE INDEX idx_proxy_nodes_default ON proxy_nodes(is_default) WHERE is_default = 1;
CREATE TABLE plan_run_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id INTEGER DEFAULT 0,
    plan_name TEXT DEFAULT '',
    task_type TEXT DEFAULT '',
    target_type TEXT DEFAULT '',
    account_id INTEGER DEFAULT 0,
    run_at TEXT DEFAULT (datetime('now','localtime')),
    status TEXT DEFAULT '',
    message TEXT DEFAULT '',
    total INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    fail_count INTEGER DEFAULT 0,
    duration_ms INTEGER DEFAULT 0
);
CREATE INDEX idx_plan_run_records_run_at ON plan_run_records(run_at);
CREATE INDEX idx_plan_run_records_plan ON plan_run_records(plan_id);
CREATE TABLE gateway_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT DEFAULT '',
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    rpm_limit INTEGER DEFAULT 0,
    quota_total INTEGER DEFAULT 0,
    quota_used INTEGER DEFAULT 0,
    models TEXT DEFAULT '',
    rate_5h INTEGER DEFAULT 0,
    rate_1d INTEGER DEFAULT 0,
    rate_7d INTEGER DEFAULT 0,
    last_used_at INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
);
ALTER TABLE accounts ADD COLUMN priority INTEGER NOT NULL DEFAULT 100;
ALTER TABLE accounts ADD COLUMN paid_fallback INTEGER NOT NULL DEFAULT 1;
ALTER TABLE accounts ADD COLUMN paid_cooling_until INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN paid_last_error TEXT NOT NULL DEFAULT '';
ALTER TABLE usage_records ADD COLUMN channel TEXT NOT NULL DEFAULT '';
ALTER TABLE usage_records ADD COLUMN cache_read_tokens INTEGER NOT NULL DEFAULT 0;
ALTER TABLE usage_records ADD COLUMN cache_creation_tokens INTEGER NOT NULL DEFAULT 0;
ALTER TABLE usage_records ADD COLUMN gateway_key_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE usage_records ADD COLUMN key_name TEXT NOT NULL DEFAULT '';
ALTER TABLE claim_records ADD COLUMN used_at INTEGER NOT NULL DEFAULT 0;

-- Public synthetic rows. Tests replace credential values using the public Vault.
INSERT INTO accounts (
    id, user_id, email, provider, status, account_group, remaining, priority,
    cooling_until, paid_cooling_until, total_units, used_units, device_mid,
    created_at, updated_at
) VALUES (
    101, 'PUBLIC-user-a', 'a@example.invalid', 'zai', 'cooling', 'one,two', 12.5, 50,
    2000000000, 2000000100, 20, 7.5, 'PUBLIC-device-a',
    '2026-01-01 00:00:00', '2026-01-02 00:00:00'
);
INSERT INTO accounts (
    id, user_id, email, provider, enabled, status, paid_fallback,
    access_token, zcode_jwt, api_key, user_info, created_at, updated_at
) VALUES (
    102, 'PUBLIC-user-b', 'b@example.invalid', 'bigmodel', 0, 'disabled', 0,
    'PUBLIC legacy access', 'PUBLIC legacy jwt', 'PUBLIC legacy api key', '{}',
    '2026-01-01 00:00:00', '2026-01-02 00:00:00'
);
INSERT INTO settings (key, value, updated_at)
VALUES ('PUBLIC-unknown-setting', 'keep verbatim', '2026-01-01 00:00:00');
INSERT INTO gateway_keys (name, key_hash, key_prefix, created_at, updated_at)
VALUES ('PUBLIC named key', 'PUBLIC-not-a-real-hash', 'PUBLIC-prefix',
        '2026-01-01 00:00:00', '2026-01-02 00:00:00');
INSERT INTO usage_records (
    created_at, account_id, model, prompt_tokens, completion_tokens, channel
) VALUES ('2026-01-01 00:00:00', 101, 'PUBLIC-model', 11, 7, 'paid');
