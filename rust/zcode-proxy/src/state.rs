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

pub struct AppState {
    /// Root key plaintext (empty = named keys only).
    pub root_key: String,
    pub upstream: UpstreamUrls,
    /// SQLite persistence (single connection, Go serialized-writer parity).
    pub db: Mutex<rusqlite::Connection>,
    pub accounts: Mutex<Vec<AccountView>>,
    pub creds: Mutex<HashMap<i64, Creds>>,
    pub named_keys: Mutex<Vec<NamedKey>>,
    pub settings: Mutex<HashMap<String, String>>,
    pub selector: Mutex<Selector>,
    pub rpm: Mutex<GwRpmTracker>,
    pub windows: Mutex<GwWindowTracker>,
    /// In-memory admin sessions (Go parity: restart revokes every session).
    pub sessions: Mutex<HashMap<String, i64>>,
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

    /// Build state from a DB connection: load settings, accounts, keys.
    pub fn from_db(root_key: String, upstream: UpstreamUrls, db: rusqlite::Connection) -> Self {
        let settings: HashMap<String, String> = {
            let mut stmt = db
                .prepare("SELECT key, value FROM settings")
                .expect("settings prepare");
            stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .expect("settings query")
                .filter_map(Result::ok)
                .collect()
        };
        let rows = store::list_accounts(&db);
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
        Self {
            root_key,
            upstream,
            db: Mutex::new(db),
            accounts: Mutex::new(accounts),
            creds: Mutex::new(creds),
            named_keys: Mutex::new(named_keys),
            settings: Mutex::new(settings),
            selector: Mutex::new(Selector::new(StrategyConfig::default())),
            rpm: Mutex::new(GwRpmTracker::default()),
            windows: Mutex::new(GwWindowTracker::default()),
            sessions: Mutex::new(HashMap::new()),
            usage: Mutex::new(Vec::new()),
        }
    }

    pub fn new(root_key: String, upstream: UpstreamUrls) -> Self {
        Self {
            root_key,
            upstream,
            db: Mutex::new(store::open(":memory:")),
            accounts: Mutex::new(Vec::new()),
            creds: Mutex::new(HashMap::new()),
            named_keys: Mutex::new(Vec::new()),
            settings: Mutex::new(HashMap::new()),
            selector: Mutex::new(Selector::new(StrategyConfig::default())),
            rpm: Mutex::new(GwRpmTracker::default()),
            windows: Mutex::new(GwWindowTracker::default()),
            sessions: Mutex::new(HashMap::new()),
            usage: Mutex::new(Vec::new()),
        }
    }

    pub fn setting(&self, key: &str) -> Option<String> {
        self.settings.lock().unwrap().get(key).cloned()
    }
}
