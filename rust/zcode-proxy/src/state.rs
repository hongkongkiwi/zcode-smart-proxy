//! Shared service state for the Rust data plane.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::store;
use zcode_core::{AccountView, GwRpmTracker, GwWindowTracker, Selector, StrategyConfig};

#[derive(Clone)]
pub struct NamedKey {
    pub id: i64,
    pub name: String,
    pub key_hash: String,
    pub enabled: bool,
    pub models: String,
    pub rpm_limit: i64,
    pub rate_5h: i64,
    pub rate_1d: i64,
    pub rate_7d: i64,
    pub quota_total: i64,
    pub quota_used: i64,
}

#[derive(Clone)]
pub struct UpstreamUrls {
    /// JWT channel (free): zcode.z.ai zcode-plan endpoint.
    pub zai: String,
    /// API Key channel (paid): api.z.ai fallback endpoint.
    pub zai_fallback: String,
}

#[derive(Clone)]
pub struct Creds {
    pub zcode_jwt: String,
    pub api_key: String,
}

#[derive(Clone, Copy)]
pub struct StreamTimings {
    pub heartbeat_interval: std::time::Duration,
    pub silence_timeout: std::time::Duration,
}

impl Default for StreamTimings {
    fn default() -> Self {
        Self {
            heartbeat_interval: std::time::Duration::from_secs(15),
            silence_timeout: std::time::Duration::from_secs(120),
        }
    }
}

pub struct AppState {
    /// Root key plaintext (empty = named keys only).
    pub root_key: String,
    pub upstream: UpstreamUrls,
    pub stream_timings: StreamTimings,
    /// SQLite persistence (single connection, Go serialized-writer parity).
    pub db: Mutex<rusqlite::Connection>,
    pub vault: crate::vault::Vault,
    pub accounts: Mutex<Vec<AccountView>>,
    pub creds: Mutex<HashMap<i64, Creds>>,
    pub named_keys: Mutex<Vec<NamedKey>>,
    pub settings: Mutex<HashMap<String, String>>,
    pub selector: Mutex<Selector>,
    pub rpm: Mutex<GwRpmTracker>,
    pub windows: Mutex<GwWindowTracker>,
    /// In-memory admin sessions (Go parity: restart revokes every session).
    pub sessions: Mutex<HashMap<String, i64>>,
    /// Login lockout (bounded per-client failure tracking, admin.rs).
    pub login_guard: Mutex<crate::admin::LoginGuard>,
    /// Rolling in-memory usage log (parity with recordUsage for E2E checks).
    pub usage: Mutex<Vec<UsageRecord>>,
}

pub const MAX_MEMORY_USAGE_RECORDS: usize = 1024;

#[derive(Clone, Debug)]
pub struct UsageRecord {
    pub account_id: i64,
    pub status: u16,
    pub gateway_key_id: i64,
    pub quota_charge: i64,
}

impl UsageRecord {
    /// E2E/dashboard read accessor (fields stay private to the log's growth).
    #[allow(dead_code)]
    pub fn summary(&self) -> (i64, u16, i64, i64) {
        (
            self.account_id,
            self.status,
            self.gateway_key_id,
            self.quota_charge,
        )
    }
}

impl AppState {
    /// Default upstream URLs, overridable via env (service layer wiring).
    pub fn upstream_from_env() -> UpstreamUrls {
        UpstreamUrls {
            zai: std::env::var("ZCODE_RS_UPSTREAM_ZAI").unwrap_or_else(|_| {
                "https://zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages".into()
            }),
            zai_fallback: std::env::var("ZCODE_RS_UPSTREAM_FALLBACK")
                .unwrap_or_else(|_| "https://api.z.ai/api/anthropic/v1/messages".into()),
        }
    }

    /// Legacy fixture constructor with an ephemeral key. Encrypted databases must
    /// use try_from_db_with_vault with their persisted key instead.
    pub fn from_db(root_key: String, upstream: UpstreamUrls, db: rusqlite::Connection) -> Self {
        let vault = crate::vault::Vault::ephemeral().expect("generate ephemeral vault");
        Self::try_from_db_with_vault(root_key, upstream, db, vault)
            .expect("load database: encrypted stores require an explicit persisted vault")
    }

    pub fn try_from_db_with_vault(
        root_key: String,
        upstream: UpstreamUrls,
        db: rusqlite::Connection,
        vault: crate::vault::Vault,
    ) -> Result<Self, store::StoreError> {
        store::check_schema(&db)?;
        let settings = store::load_settings(&db, &vault)?;
        let rows = store::load_accounts(&db, &vault)?;
        let mut accounts = Vec::new();
        let mut creds = HashMap::new();
        for (a, jwt, key) in rows {
            creds.insert(
                a.id,
                Creds {
                    zcode_jwt: jwt.clone(),
                    api_key: key.clone(),
                },
            );
            accounts.push(a);
        }
        let named_keys = store::list_gateway_keys(&db);
        Ok(Self {
            root_key,
            upstream,
            stream_timings: StreamTimings::default(),
            db: Mutex::new(db),
            vault,
            accounts: Mutex::new(accounts),
            creds: Mutex::new(creds),
            named_keys: Mutex::new(named_keys),
            settings: Mutex::new(settings),
            selector: Mutex::new(Selector::new(StrategyConfig::default())),
            rpm: Mutex::new(GwRpmTracker::default()),
            windows: Mutex::new(GwWindowTracker::default()),
            sessions: Mutex::new(HashMap::new()),
            login_guard: Mutex::new(crate::admin::LoginGuard::default()),
            usage: Mutex::new(Vec::new()),
        })
    }

    pub fn new(root_key: String, upstream: UpstreamUrls) -> Self {
        Self::from_db(root_key, upstream, store::open(":memory:"))
    }

    /// Writers hold DB then settings through commit and mirror publication.
    pub fn persist_settings(&self, values: &[(&str, &str)]) -> Result<(), store::StoreError> {
        let mut db = self.db.lock().unwrap();
        let mut settings = self.settings.lock().unwrap();
        self.persist_settings_locked(&mut db, &mut settings, values)
    }

    pub(crate) fn persist_settings_locked(
        &self,
        db: &mut rusqlite::Connection,
        settings: &mut HashMap<String, String>,
        values: &[(&str, &str)],
    ) -> Result<(), store::StoreError> {
        // Normalize supplied envelopes too: mirrors always contain plaintext.
        let plain: Vec<_> = values
            .iter()
            .map(|&(key, value)| {
                let value = if store::sensitive_setting(key) {
                    self.vault.decrypt(value)?
                } else {
                    value.to_owned()
                };
                Ok((key, value))
            })
            .collect::<Result<_, store::StoreError>>()?;
        store::persist_settings(db, &self.vault, values)?;
        for (key, value) in plain {
            settings.insert(key.to_owned(), value);
        }
        Ok(())
    }

    pub fn consume_recovery_code(&self, code: &str) -> Result<bool, store::StoreError> {
        let mut db = self.db.lock().unwrap();
        let mut settings = self.settings.lock().unwrap();
        let hashes = zcode_core::recovery_codes_from_json(
            settings.get("recovery_codes").map(String::as_str),
        );
        let Some(rest) = zcode_core::consume_recovery_code(&hashes, code) else {
            return Ok(false);
        };
        let value = zcode_core::recovery_codes_to_json(&rest);
        self.persist_settings_locked(&mut db, &mut settings, &[("recovery_codes", &value)])?;
        Ok(true)
    }

    pub fn setting(&self, key: &str) -> Option<String> {
        self.settings.lock().unwrap().get(key).cloned()
    }
}
