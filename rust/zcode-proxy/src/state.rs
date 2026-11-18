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
pub struct ManagementUrls {
    pub billing_base: String,
    pub quota_limit: String,
    pub subscription: String,
    pub oauth_token: String,
    pub app_version: String,
}

impl Default for ManagementUrls {
    fn default() -> Self {
        Self {
            billing_base: "https://zcode.z.ai/api/v1/zcode-plan".into(),
            quota_limit: "https://api.z.ai/api/monitor/usage/quota/limit".into(),
            subscription: "https://api.z.ai/api/biz/subscription/list".into(),
            oauth_token: "https://zcode.z.ai/api/v1/oauth/token".into(),
            app_version: "3.14.4".into(),
        }
    }
}

#[derive(Clone)]
pub struct AutomationUrls {
    pub billing_preview: String,
    pub billing_claim: String,
    pub event_report: String,
    pub reset_status: String,
    pub reset_use: String,
    pub captcha_scene: String,
    pub captcha_prefix: String,
    pub captcha_region: String,
}

impl Default for AutomationUrls {
    fn default() -> Self {
        Self {
            billing_preview: "https://zcode.z.ai/api/v1/zcode-plan/billing/preview".into(),
            billing_claim: "https://zcode.z.ai/api/v1/zcode-plan/billing/claim".into(),
            event_report: "https://zcode.z.ai/api/v1/event/report".into(),
            reset_status: "https://zcode.z.ai/api/v1/coding-plan/reset/status".into(),
            reset_use: "https://zcode.z.ai/api/v1/coding-plan/reset/use".into(),
            // Go discovers these from client/configs; unknown configuration cannot solve a CAPTCHA.
            captcha_scene: String::new(),
            captcha_prefix: String::new(),
            captcha_region: String::new(),
        }
    }
}

#[derive(Clone)]
pub struct OAuthUrls {
    pub authorize: String,
    pub userinfo: String,
    pub business_login: String,
    pub customer_info: String,
    pub project_keys_base: String,
    pub manual_redirect: String,
    pub callback_url: String,
    pub flow_ttl: std::time::Duration,
}

impl Default for OAuthUrls {
    fn default() -> Self {
        Self {
            authorize: "https://chat.z.ai/api/oauth/authorize".into(),
            userinfo: "https://chat.z.ai/api/oauth/userinfo".into(),
            business_login: "https://api.z.ai/api/auth/z/login".into(),
            customer_info: "https://api.z.ai/api/biz/customer/getCustomerInfo".into(),
            project_keys_base: "https://api.z.ai/api/biz/v1/organization".into(),
            manual_redirect: "https://zcode.z.ai/login".into(),
            callback_url: "http://127.0.0.1:8787/oauth/callback".into(),
            flow_ttl: std::time::Duration::from_secs(600),
        }
    }
}

#[derive(Clone)]
pub struct PollOAuthUrls {
    pub init: String,
    pub poll_base: String,
    pub interval_override: Option<std::time::Duration>,
    pub flow_ttl: std::time::Duration,
}

impl Default for PollOAuthUrls {
    fn default() -> Self {
        Self {
            init: "https://zcode.z.ai/api/v1/oauth/cli/init".into(),
            poll_base: "https://zcode.z.ai/api/v1/oauth/cli/poll".into(),
            interval_override: None,
            flow_ttl: std::time::Duration::from_secs(300),
        }
    }
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
    pub management: ManagementUrls,
    pub install_urls: crate::install_sequence::InstallUrls,
    pub install_reporting_enabled: bool,
    pub automation: AutomationUrls,
    pub automation_solver: std::sync::Arc<dyn zcode_core::egress::CaptchaSolver>,
    pub(crate) automation_inflight: Mutex<std::collections::HashSet<i64>>,
    pub(crate) reset_history_synced_at: Mutex<HashMap<i64, std::time::Instant>>,
    pub(crate) scheduler: Mutex<Option<std::sync::Weak<crate::scheduler::Scheduler>>>,
    background_refresh:
        Mutex<Option<std::sync::Weak<crate::background_refresh::BackgroundRefresh>>>,
    pub oauth: OAuthUrls,
    pub oauth_poll: PollOAuthUrls,
    /// An explicit credential file confines local import to it and its siblings.
    pub local_credentials_path: Option<std::path::PathBuf>,
    pub local_credentials_secret: Option<zeroize::Zeroizing<String>>,
    pub(crate) oauth_flows: Mutex<crate::account_oauth::FlowStore>,
    pub(crate) quota_refresh_inflight: Mutex<std::collections::HashSet<i64>>,
    pub(crate) token_refresh_attempts: Mutex<HashMap<i64, std::time::Instant>>,
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
    /// Step-up failures use peer/action buckets independent of login lockout.
    pub(crate) step_up_guard: Mutex<crate::admin::LoginGuard>,
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
    #[allow(clippy::result_unit_err)] // The public slot contract only distinguishes a live occupant.
    pub fn set_background_refresh(
        &self,
        worker: std::sync::Arc<crate::background_refresh::BackgroundRefresh>,
    ) -> Result<(), ()> {
        let mut slot = self.background_refresh.lock().unwrap();
        if slot.as_ref().and_then(std::sync::Weak::upgrade).is_some() {
            return Err(());
        }
        *slot = Some(std::sync::Arc::downgrade(&worker));
        Ok(())
    }

    pub fn background_refresh(
        &self,
    ) -> Option<std::sync::Arc<crate::background_refresh::BackgroundRefresh>> {
        self.background_refresh
            .lock()
            .unwrap()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
    }

    #[allow(clippy::result_unit_err)] // The public slot contract only distinguishes a live occupant.
    pub fn set_scheduler(
        &self,
        scheduler: std::sync::Arc<crate::scheduler::Scheduler>,
    ) -> Result<(), ()> {
        let mut slot = self.scheduler.lock().unwrap();
        if slot.as_ref().and_then(std::sync::Weak::upgrade).is_some() {
            return Err(());
        }
        *slot = Some(std::sync::Arc::downgrade(&scheduler));
        Ok(())
    }

    pub fn scheduler(&self) -> Option<std::sync::Arc<crate::scheduler::Scheduler>> {
        self.scheduler
            .lock()
            .unwrap()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
    }

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
        let named_keys = store::try_list_gateway_keys(&db)?
            .into_iter()
            .map(|row| row.key)
            .collect();
        Ok(Self {
            root_key,
            upstream,
            management: ManagementUrls::default(),
            install_urls: crate::install_sequence::InstallUrls::default(),
            install_reporting_enabled: false,
            automation: AutomationUrls::default(),
            automation_solver: std::sync::Arc::new(zcode_core::egress::NoopSolver),
            automation_inflight: Mutex::new(std::collections::HashSet::new()),
            reset_history_synced_at: Mutex::new(HashMap::new()),
            scheduler: Mutex::new(None),
            background_refresh: Mutex::new(None),
            oauth: OAuthUrls::default(),
            oauth_poll: PollOAuthUrls::default(),
            local_credentials_path: None,
            local_credentials_secret: None,
            oauth_flows: Mutex::new(crate::account_oauth::FlowStore::default()),
            quota_refresh_inflight: Mutex::new(std::collections::HashSet::new()),
            token_refresh_attempts: Mutex::new(HashMap::new()),
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
            step_up_guard: Mutex::new(crate::admin::LoginGuard::default()),
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
