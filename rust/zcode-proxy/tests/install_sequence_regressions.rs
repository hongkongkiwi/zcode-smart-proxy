//! Independent regressions for the installation reporting packet (design:
//! .agents/state/rust-migration/install-design.md; Go reference identity.go
//! SendInstallSequence). Authored against the documented public surface before
//! implementation: a missing install_sequence module is an honest compile gap,
//! not a behavioral red.
//!
//! Contracts pinned here:
//! - The sequence is exactly three requests in order: GET client/configs with
//!   only the app_version query and no Authorization, then two POST
//!   event/report calls (app_launch before app_daily_active) with Bearer JWT.
//! - Event bodies follow the Go field set, carry the persisted device_mid and
//!   claims user_id, never carry install_id, and use fresh UUID event ids.
//! - Fail-soft: each step failure (HTTP, business code, malformed body,
//!   redirect, oversized body) continues the sequence with truthful counts.
//! - Eligibility skips (JWT-empty, API-key-only, disabled, deleted,
//!   synthetic-only identity) send no HTTP at all; credential decryption
//!   failure is Err with no HTTP.
//! - A configs response completing after a reimport or delete stops the next
//!   steps instead of sending stale credentials.
//! - Automatic manager reporting needs the explicit flag plus injected URLs:
//!   defaults stay offline, paste/local/OAuth run install once before quota
//!   refresh, bundle/plain add carry no hook, and stop during configs
//!   suppresses later events without affecting import success.

use std::{
    collections::{BTreeSet, VecDeque},
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use tokio::sync::Notify;
use tower::ServiceExt;
use zcode_core::AccountView;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    background_refresh::{BackgroundRefresh, BackgroundRefreshConfig},
    build_router,
    install_sequence::{send_install_sequence, InstallReport, InstallUrls},
    state::{AppState, Creds, ManagementUrls, UpstreamUrls},
    store::{self, StoreError},
    vault::Vault,
};

const SESSION: &str = "PUBLIC-install-sequence-session";
const CONFIGS: &str = "/api/v1/client/configs";
const EVENT: &str = "/api/v1/event/report";
const BILLING: &str = "/api/v1/zcode-plan/billing/balance";
const TOKEN: &str = "/api/v1/oauth/token";
const CANARY: &str = "/canary/install-redirect";
const VERSION: &str = "PUBLIC-install-version";
const OAUTH_CODE: &str = "PUBLIC-install-oauth-code";
// A delay no bounded test wait can outlive: jobs admitted under it stay
// deterministically pending unless cancelled or dropped.
const PARKED: Duration = Duration::from_secs(3600);
const DEADLINE: Duration = Duration::from_secs(5);
// Debug-mode bundle import derives PBKDF2 (600k rounds) under spawn_blocking;
// this is a harness deadline for that route alone, not latency acceptance.
const CRYPTO_DEADLINE: Duration = Duration::from_secs(120);

// ---- loopback mock ----

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    query: String,
    authorization: String,
    headers: HeaderMap,
    body: Value,
}

impl Seen {
    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
    }
}

#[derive(Default)]
struct Gate {
    entered: Notify,
    release: Notify,
}

enum Payload {
    Json(Value),
    Raw(Vec<u8>),
}

struct Step {
    status: StatusCode,
    payload: Payload,
    location: Option<String>,
    gate: Option<Arc<Gate>>,
}

impl Step {
    fn ok(body: Value) -> Self {
        Self {
            status: StatusCode::OK,
            payload: Payload::Json(body),
            location: None,
            gate: None,
        }
    }

    fn status(status: StatusCode, body: Value) -> Self {
        Self {
            status,
            payload: Payload::Json(body),
            location: None,
            gate: None,
        }
    }

    fn raw(status: StatusCode, bytes: Vec<u8>) -> Self {
        Self {
            status,
            payload: Payload::Raw(bytes),
            location: None,
            gate: None,
        }
    }

    fn redirect(location: String) -> Self {
        Self {
            status: StatusCode::FOUND,
            payload: Payload::Json(json!({})),
            location: Some(location),
            gate: None,
        }
    }

    fn gated(mut self, gate: Arc<Gate>) -> Self {
        self.gate = Some(gate);
        self
    }
}

#[derive(Default)]
struct Script {
    configs_steps: Mutex<VecDeque<Step>>,
    event_steps: Mutex<VecDeque<Step>>,
    billing_steps: Mutex<VecDeque<Step>>,
    token_steps: Mutex<VecDeque<Step>>,
    seen: Mutex<Vec<Seen>>,
}

struct Mock {
    base: String,
    script: Arc<Script>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Mock {
    async fn start() -> Self {
        async fn serve(State(script): State<Arc<Script>>, request: Request) -> Response {
            let (parts, body) = request.into_parts();
            let bytes = to_bytes(body, 4 << 20).await.unwrap_or_default();
            script.seen.lock().unwrap().push(Seen {
                method: parts.method.to_string(),
                path: parts.uri.path().into(),
                query: parts.uri.query().unwrap_or("").into(),
                authorization: parts
                    .headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("")
                    .into(),
                headers: parts.headers.clone(),
                body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            });
            let step = match parts.uri.path() {
                CONFIGS => script.configs_steps.lock().unwrap().pop_front(),
                EVENT => script.event_steps.lock().unwrap().pop_front(),
                BILLING => script.billing_steps.lock().unwrap().pop_front(),
                TOKEN => script.token_steps.lock().unwrap().pop_front(),
                _ => None,
            };
            let Some(step) = step else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"code":500,"msg":"unexpected mock request"})),
                )
                    .into_response();
            };
            if let Some(gate) = step.gate {
                gate.entered.notify_one();
                gate.release.notified().await;
            }
            let mut builder = axum::http::Response::builder()
                .status(step.status)
                .header("content-type", "application/json");
            if let Some(location) = &step.location {
                builder = builder.header("location", location);
            }
            match step.payload {
                Payload::Json(value) => builder.body(Body::from(value.to_string())),
                Payload::Raw(bytes) => builder.body(Body::from(bytes)),
            }
            .unwrap()
        }
        let script = Arc::new(Script::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(serve).with_state(script.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base, script, task }
    }

    fn push_configs(&self, step: Step) {
        self.script.configs_steps.lock().unwrap().push_back(step);
    }

    fn push_event(&self, step: Step) {
        self.script.event_steps.lock().unwrap().push_back(step);
    }

    fn push_billing(&self, used: f64) {
        self.script.billing_steps.lock().unwrap().push_back(Step::ok(
            json!({"code":0,"success":true,"data":{"result":{
                "plans":[{"plan_id":"pro","name":"Pro","status":"active","expire_time":"2096-01-02 03:04"}],
                "balances":[{"plan_id":"pro","show_name":"PUBLIC quota","total_units":100.0,
                    "used_units":used,"remaining_units":100.0-used}]
            }}}),
        ));
    }

    fn push_token(&self, body: Value) {
        self.script
            .token_steps
            .lock()
            .unwrap()
            .push_back(Step::ok(body));
    }

    fn push_ok_sequence(&self) {
        self.push_configs(Step::ok(json!({"code":0})));
        self.push_event(Step::ok(json!({"code":0})));
        self.push_event(Step::ok(json!({"code":0})));
    }

    fn seen(&self) -> Vec<Seen> {
        self.script.seen.lock().unwrap().clone()
    }

    fn assert_order(&self, expected: &[(&str, &str, &str)]) {
        let actual: Vec<(String, String, String)> = self
            .seen()
            .iter()
            .map(|seen| {
                (
                    seen.method.clone(),
                    seen.path.clone(),
                    seen.authorization.clone(),
                )
            })
            .collect();
        let expected: Vec<(String, String, String)> = expected
            .iter()
            .map(|&(method, path, authorization)| {
                (method.into(), path.into(), authorization.into())
            })
            .collect();
        assert_eq!(
            actual, expected,
            "exact upstream method, endpoint, and credential order"
        );
    }

    fn assert_no_canary(&self) {
        assert!(
            self.seen().iter().all(|seen| seen.path != CANARY),
            "a redirect must never be followed to {CANARY}"
        );
    }

    fn assert_complete(&self) {
        assert!(
            self.script.configs_steps.lock().unwrap().is_empty()
                && self.script.event_steps.lock().unwrap().is_empty()
                && self.script.billing_steps.lock().unwrap().is_empty()
                && self.script.token_steps.lock().unwrap().is_empty(),
            "not all expected upstream responses were consumed"
        );
    }
}

// ---- fixtures ----

struct LocalFiles(PathBuf);

impl LocalFiles {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "zcode-install-sequence-{}-{:032x}",
            std::process::id(),
            rand::random::<u128>()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn credentials(&self) -> PathBuf {
        self.0.join("credentials.json")
    }

    fn write_token(&self, token: &str) {
        fs::write(
            self.credentials(),
            json!({"zcodejwttoken": token}).to_string(),
        )
        .unwrap();
    }
}

impl Drop for LocalFiles {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// Claims are deliberately unsigned: import reads identity, not validity.
fn claims_jwt(claims: &Value, variant: &str) -> String {
    format!(
        "e30.{}.PUBLIC-not-a-real-signature-{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap()),
        variant
    )
}

fn jwt(user: &str, variant: &str) -> String {
    claims_jwt(&json!({"user_id": user, "jti": variant}), variant)
}

fn host_os_category() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    }
}

fn assert_uuid4(id: &str, context: &str) {
    assert_eq!(id.len(), 36, "{context}: canonical UUID length in {id}");
    for (index, byte) in id.bytes().enumerate() {
        match index {
            8 | 13 | 18 | 23 => assert_eq!(byte, b'-', "{context}: dash layout in {id}"),
            _ => assert!(
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
                "{context}: lowercase hex digit in {id}"
            ),
        }
    }
    assert_eq!(&id[14..15], "4", "{context}: version nibble in {id}");
    assert!(
        matches!(&id[19..20], "8" | "9" | "a" | "b"),
        "{context}: variant nibble in {id}"
    );
}

fn assert_report(report: &InstallReport, attempted: usize, succeeded: usize, skipped: bool) {
    assert_eq!(
        (report.attempted, report.succeeded, report.skipped),
        (attempted, succeeded, skipped),
        "truthful attempt, success, and skip counts"
    );
}

struct Fixture {
    state: Arc<AppState>,
}

impl Fixture {
    // The reporting flag is set on the owned state before the Arc wrap:
    // assigning through Arc<AppState> is invalid, and the fixture stays
    // uniquely held here by construction.
    fn new(mock: &Mock, local: Option<PathBuf>, reporting: bool) -> Self {
        let mut state = AppState::try_from_db_with_vault(
            String::new(),
            UpstreamUrls {
                zai: format!("{}/unused-relay", mock.base),
                zai_fallback: format!("{}/unused-relay-fallback", mock.base),
            },
            store::open(":memory:"),
            Vault::from_secret("PUBLIC install sequence fixture seed").unwrap(),
        )
        .unwrap();
        state.management = ManagementUrls {
            billing_base: format!("{}/api/v1/zcode-plan", mock.base),
            quota_limit: format!("{}/api/monitor/usage/quota/limit", mock.base),
            subscription: format!("{}/api/biz/subscription/list", mock.base),
            oauth_token: format!("{}{TOKEN}", mock.base),
            app_version: VERSION.into(),
        };
        state.install_urls = InstallUrls {
            client_configs: format!("{base}{CONFIGS}", base = mock.base),
            event_report: format!("{base}{EVENT}", base = mock.base),
        };
        state.install_reporting_enabled = reporting;
        state.local_credentials_path = local;
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        Self {
            state: Arc::new(state),
        }
    }

    fn install_manager(&self, config: BackgroundRefreshConfig) -> Arc<BackgroundRefresh> {
        let manager = Arc::new(BackgroundRefresh::with_config(self.state.clone(), config));
        self.state
            .set_background_refresh(manager.clone())
            .expect("first manager installation must succeed");
        manager
    }

    fn seed(&self, label: &str, jwt: &str) -> i64 {
        let view = AccountView {
            email: format!("{label}@example.invalid"),
            provider: "zai".into(),
            enabled: true,
            status: "active".into(),
            remaining: 7.0,
            zcode_jwt: jwt.into(),
            ..Default::default()
        };
        let id = {
            let db = self.state.db.lock().unwrap();
            store::insert_account_encrypted(&db, &self.state.vault, &view, jwt, "").unwrap()
        };
        self.state
            .accounts
            .lock()
            .unwrap()
            .push(AccountView { id, ..view });
        self.state.creds.lock().unwrap().insert(
            id,
            Creds {
                zcode_jwt: jwt.into(),
                api_key: String::new(),
            },
        );
        id
    }

    async fn request(&self, method: &str, path: &str, body: &str) -> (StatusCode, Value) {
        self.request_with_timeout(method, path, body, DEADLINE)
            .await
    }

    async fn request_with_timeout(
        &self,
        method: &str,
        path: &str,
        body: &str,
        deadline: Duration,
    ) -> (StatusCode, Value) {
        let request = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost:8080")
            .header("content-type", "application/json")
            .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
            .body(Body::from(body.to_owned()))
            .unwrap();
        let response =
            tokio::time::timeout(deadline, build_router(self.state.clone()).oneshot(request))
                .await
                .expect("loopback admin request deadline")
                .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn paste_import(&self, secret: &str) -> Value {
        let (status, body) = self
            .request(
                "POST",
                "/api/accounts/import/paste",
                &json!({"secret": secret}).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "paste import must succeed: {body}");
        assert_eq!(body["success"], true);
        body["account"].clone()
    }

    async fn local_import(&self) -> Value {
        let (status, body) = self
            .request("POST", "/api/accounts/import/local", "{}")
            .await;
        assert_eq!(status, StatusCode::OK, "local import must succeed: {body}");
        assert_eq!(body["success"], true);
        body["account"].clone()
    }

    async fn delete_account(&self, id: i64) {
        let (status, body) = self
            .request("DELETE", &format!("/api/accounts/{id}"), "")
            .await;
        assert_eq!(status, StatusCode::OK, "delete must succeed: {body}");
    }

    async fn disable_account(&self, id: i64) {
        let (status, body) = self
            .request(
                "PUT",
                &format!("/api/accounts/{id}/enabled"),
                &json!({"enabled": false}).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "disable must succeed: {body}");
    }

    fn stored_mid(&self, id: i64) -> String {
        self.state
            .db
            .lock()
            .unwrap()
            .query_row("SELECT device_mid FROM accounts WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .unwrap()
    }

    fn row_exists(&self, id: i64) -> bool {
        self.state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM accounts WHERE id=?1)",
                [id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
            != 0
    }
}

async fn install(state: &AppState, id: i64) -> Result<InstallReport, StoreError> {
    tokio::time::timeout(DEADLINE, send_install_sequence(state, id))
        .await
        .expect("install sequence must finish within the loopback deadline")
}

fn spawn_install(
    state: &Arc<AppState>,
    id: i64,
) -> tokio::task::JoinHandle<Result<InstallReport, StoreError>> {
    let state = state.clone();
    tokio::spawn(async move {
        tokio::time::timeout(DEADLINE, send_install_sequence(&state, id))
            .await
            .expect("install sequence must finish within the loopback deadline")
    })
}

async fn settle(manager: &BackgroundRefresh) {
    tokio::time::timeout(DEADLINE, manager.wait_idle())
        .await
        .expect("background refresh must settle within the loopback test deadline");
}

async fn enter(gate: &Gate, what: &str) {
    tokio::time::timeout(DEADLINE, gate.entered.notified())
        .await
        .expect(what);
}

fn manager_config(
    import_delay: Duration,
    oauth_delay: Duration,
    capacity: usize,
    shutdown_wait: Duration,
) -> BackgroundRefreshConfig {
    BackgroundRefreshConfig {
        import_delay,
        oauth_delay,
        capacity,
        shutdown_wait,
    }
}

fn assert_event_wire(event: &Seen, element: &str, bearer: &str, mid: &str, user: &str) {
    assert_eq!(event.method, "POST");
    assert_eq!(event.path, EVENT);
    assert_eq!(event.query, "", "event posts carry no query string");
    assert_eq!(event.authorization, bearer);
    assert_eq!(event.header("x-device-mid"), mid);
    assert_eq!(event.body["element_name"].as_str(), Some(element));
    assert_eq!(event.body["user_id"].as_str(), Some(user));
    assert_eq!(event.body["app_version"].as_str(), Some(VERSION));
    assert_eq!(event.body["client_language"].as_str(), Some("zh-CN"));
    assert_eq!(event.body["event_region"].as_str(), Some("app"));
    assert_eq!(event.body["event_type"].as_str(), Some("view"));
    assert_eq!(event.body["event_text"].as_str(), Some(""));
    assert_eq!(event.body["event_extra_detail"], json!({}));
    assert_eq!(event.body["screen_resolution"].as_str(), Some("2560x1440"));
    assert_eq!(
        event.body["device_os_category"].as_str(),
        Some(host_os_category())
    );
    assert_eq!(event.body["device_mid"].as_str(), Some(mid));
    assert_eq!(event.body["mac_id"].as_str(), Some(""));
    assert_eq!(event.body["marketing_params"].as_str(), Some("{}"));
    assert!(
        !event.body["client_timezone"]
            .as_str()
            .unwrap_or("")
            .is_empty(),
        "client_timezone is a real IANA zone"
    );
    if !cfg!(windows) {
        assert_eq!(
            event.body["device_os_version"].as_str(),
            Some(""),
            "unknown host version is reported empty, never fabricated"
        );
    }
    assert!(
        event.body.get("install_id").is_none(),
        "install_id never appears on the wire"
    );
    let event_id = event.body["event_id"].as_str().unwrap_or("");
    assert_uuid4(event_id, "fresh per-event event_id");
}

// ---- direct API: wire contract ----

#[test]
fn install_urls_default_matches_production_endpoints_and_constructors_default_off() {
    let urls = InstallUrls::default();
    assert_eq!(
        urls.client_configs,
        "https://zcode.z.ai/api/v1/client/configs"
    );
    assert_eq!(urls.event_report, "https://zcode.z.ai/api/v1/event/report");
    let state = AppState::new(
        String::new(),
        UpstreamUrls {
            zai: "http://127.0.0.1:1/unused".into(),
            zai_fallback: "http://127.0.0.1:1/unused".into(),
        },
    );
    assert!(
        !state.install_reporting_enabled,
        "constructors default automatic reporting off"
    );
    assert_eq!(state.install_urls.client_configs, urls.client_configs);
    assert_eq!(state.install_urls.event_report, urls.event_report);
}

#[tokio::test]
async fn wire_contract_pins_order_auth_query_headers_bodies_and_identity_reuse() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None, false);
    let user = "PUBLIC-install-wire-user";
    let secret = jwt(user, "v1");
    let id = fixture.paste_import(&secret).await["id"].as_i64().unwrap();
    assert_eq!(
        fixture.stored_mid(id),
        "",
        "paste import must not mint an identity; install persists it first"
    );

    mock.push_ok_sequence();
    // The direct API runs regardless of the automatic-reporting flag.
    let report = install(&fixture.state, id)
        .await
        .expect("eligible account reports Ok");
    assert_report(&report, 3, 3, false);
    mock.assert_order(&[
        ("GET", CONFIGS, ""),
        ("POST", EVENT, format!("Bearer {secret}").as_str()),
        ("POST", EVENT, format!("Bearer {secret}").as_str()),
    ]);
    mock.assert_complete();

    let seen = mock.seen();
    let configs = &seen[0];
    assert_eq!(configs.query, format!("app_version={VERSION}"));
    let mid = fixture.stored_mid(id);
    assert_uuid4(&mid, "install-persisted device_mid");
    for request in &seen {
        assert_eq!(
            request.header("x-device-mid"),
            mid,
            "stable persisted identity"
        );
        assert_eq!(request.header("user-agent"), format!("ZCode/{VERSION}"));
        assert_eq!(request.header("x-zcode-app-version"), VERSION);
        assert_eq!(request.header("x-client-language"), "zh-CN");
    }
    let request_ids: Vec<&str> = seen.iter().map(|s| s.header("x-request-id")).collect();
    assert!(request_ids.iter().all(|id| !id.is_empty()));
    assert_eq!(
        request_ids.iter().copied().collect::<BTreeSet<_>>().len(),
        request_ids.len(),
        "request ids are fresh per request"
    );
    for (index, element) in ["app_launch", "app_daily_active"].iter().enumerate() {
        assert_event_wire(
            &seen[1 + index],
            element,
            &format!("Bearer {secret}"),
            &mid,
            user,
        );
    }

    // A second sequence reuses the persisted identity but mints fresh ids.
    mock.push_ok_sequence();
    let report = install(&fixture.state, id)
        .await
        .expect("second run reports Ok");
    assert_report(&report, 3, 3, false);
    mock.assert_complete();
    assert_eq!(
        fixture.stored_mid(id),
        mid,
        "an existing identity is never rotated"
    );
    let seen = mock.seen();
    assert_eq!(seen.len(), 6);
    for request in &seen[3..] {
        assert_eq!(request.header("x-device-mid"), mid);
    }
    let mut event_ids: Vec<&str> = Vec::new();
    for index in [1usize, 2, 4, 5] {
        assert_uuid4(
            seen[index].body["event_id"].as_str().unwrap_or(""),
            "second-run event_id",
        );
        event_ids.push(seen[index].body["event_id"].as_str().unwrap_or(""));
    }
    assert_eq!(
        event_ids.iter().copied().collect::<BTreeSet<_>>().len(),
        4,
        "every event carries a fresh event_id across runs"
    );
    let request_ids: Vec<&str> = seen.iter().map(|s| s.header("x-request-id")).collect();
    assert_eq!(
        request_ids.iter().copied().collect::<BTreeSet<_>>().len(),
        6,
        "request ids stay fresh across runs"
    );
}

#[tokio::test]
async fn accepted_business_codes_zero_minus_one_and_two_hundred_all_succeed() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None, false);
    let secret = jwt("PUBLIC-install-codes-user", "v1");
    let id = fixture.paste_import(&secret).await["id"].as_i64().unwrap();
    mock.push_configs(Step::ok(json!({"code":0})));
    mock.push_event(Step::ok(json!({"code":-1})));
    mock.push_event(Step::ok(json!({"code":200})));
    let report = install(&fixture.state, id)
        .await
        .expect("accepted codes report Ok");
    assert_report(&report, 3, 3, false);
    mock.assert_complete();
}

#[tokio::test]
async fn malformed_or_rejected_business_codes_fail_each_step_without_aborting() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None, false);
    let secret = jwt("PUBLIC-install-rejected-user", "v1");
    let id = fixture.paste_import(&secret).await["id"].as_i64().unwrap();
    // Missing code, non-JSON body, and explicit success=false are each failures.
    mock.push_configs(Step::ok(json!({"msg":"no code field"})));
    mock.push_event(Step::raw(StatusCode::OK, b"{not json".to_vec()));
    mock.push_event(Step::ok(json!({"code":0,"success":false})));
    let report = install(&fixture.state, id)
        .await
        .expect("failures still report Ok");
    assert_report(&report, 3, 0, false);
    mock.assert_order(&[
        ("GET", CONFIGS, ""),
        ("POST", EVENT, format!("Bearer {secret}").as_str()),
        ("POST", EVENT, format!("Bearer {secret}").as_str()),
    ]);
    mock.assert_complete();
}

#[tokio::test]
async fn configs_http_failure_continues_to_both_events() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None, false);
    let secret = jwt("PUBLIC-install-configs-500-user", "v1");
    let id = fixture.paste_import(&secret).await["id"].as_i64().unwrap();
    mock.push_configs(Step::status(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"code":0}),
    ));
    mock.push_event(Step::ok(json!({"code":0})));
    mock.push_event(Step::ok(json!({"code":0})));
    let report = install(&fixture.state, id)
        .await
        .expect("fail-soft run reports Ok");
    assert_report(&report, 3, 2, false);
    mock.assert_complete();
}

#[tokio::test]
async fn first_event_failure_still_sends_second_event() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None, false);
    let secret = jwt("PUBLIC-install-event1-user", "v1");
    let id = fixture.paste_import(&secret).await["id"].as_i64().unwrap();
    mock.push_configs(Step::ok(json!({"code":0})));
    mock.push_event(Step::status(StatusCode::NOT_FOUND, json!({"code":0})));
    mock.push_event(Step::ok(json!({"code":0})));
    let report = install(&fixture.state, id)
        .await
        .expect("fail-soft run reports Ok");
    assert_report(&report, 3, 2, false);
    mock.assert_order(&[
        ("GET", CONFIGS, ""),
        ("POST", EVENT, format!("Bearer {secret}").as_str()),
        ("POST", EVENT, format!("Bearer {secret}").as_str()),
    ]);
    let seen = mock.seen();
    assert_eq!(
        seen[2].body["element_name"].as_str(),
        Some("app_daily_active"),
        "the second event still fires after the first fails"
    );
    mock.assert_complete();
}

#[tokio::test]
async fn redirect_responses_are_not_followed_and_fail_soft() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None, false);
    let secret = jwt("PUBLIC-install-redirect-user", "v1");
    let id = fixture.paste_import(&secret).await["id"].as_i64().unwrap();
    mock.push_configs(Step::redirect(format!("{}{CANARY}", mock.base)));
    mock.push_event(Step::ok(json!({"code":0})));
    mock.push_event(Step::ok(json!({"code":0})));
    let report = install(&fixture.state, id)
        .await
        .expect("fail-soft run reports Ok");
    assert_report(&report, 3, 2, false);
    mock.assert_no_canary();
    mock.assert_complete();
}

#[tokio::test]
async fn oversized_configs_response_is_rejected_fail_soft() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None, false);
    let secret = jwt("PUBLIC-install-oversized-user", "v1");
    let id = fixture.paste_import(&secret).await["id"].as_i64().unwrap();
    // Valid JSON strictly larger than the 1 MiB response bound: only the size
    // limit can reject it, and the sequence must continue afterwards.
    let oversized = format!(
        "{{\"code\":0,\"pad\":\"{}\"}}",
        "a".repeat((1 << 20) + 4096)
    );
    mock.push_configs(Step::raw(StatusCode::OK, oversized.into_bytes()));
    mock.push_event(Step::ok(json!({"code":0})));
    mock.push_event(Step::ok(json!({"code":0})));
    let report = install(&fixture.state, id)
        .await
        .expect("fail-soft run reports Ok");
    assert_report(&report, 3, 2, false);
    mock.assert_complete();
}

// ---- direct API: eligibility and storage gates ----

#[tokio::test]
async fn ineligible_accounts_skip_without_any_http() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None, false);
    // No steps are scripted: any request would be recorded and fail the test.

    // API-key-only accounts carry no zcode.z.ai login state.
    let apikey = fixture.paste_import("PUBLIC-install-apikey-secret").await;
    let apikey_id = apikey["id"].as_i64().unwrap();
    assert_eq!(apikey["auth_type"], "apikey");

    // JWT-empty seeded account with no credentials at all.
    let empty_id = fixture.seed("install-jwt-empty", "");

    // Disabled account.
    let disabled_id = fixture.seed(
        "install-disabled",
        &jwt("PUBLIC-install-disabled-user", "v1"),
    );
    fixture.disable_account(disabled_id).await;

    // Deleted account: skipped, never recreated.
    let deleted_id = fixture.seed("install-deleted", &jwt("PUBLIC-install-deleted-user", "v1"));
    fixture.delete_account(deleted_id).await;

    // JWT account whose only identity fallback is a synthetic stored id.
    let synthetic_id = fixture.seed(
        "install-synthetic",
        &claims_jwt(&json!({"jti":"no-user-identity"}), "synthetic"),
    );

    for id in [apikey_id, empty_id, disabled_id, deleted_id, synthetic_id] {
        let report = install(&fixture.state, id)
            .await
            .unwrap_or_else(|error| panic!("skip must be reported as Ok for {id}: {error}"));
        assert_report(&report, 0, 0, true);
    }
    assert!(
        !fixture.row_exists(deleted_id),
        "a deleted account must not be resurrected by the install path"
    );
    mock.assert_order(&[]);
    mock.assert_complete();
}

#[tokio::test]
async fn storage_failure_errors_without_any_http() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None, false);
    let id = fixture.seed("install-corrupt", &jwt("PUBLIC-install-corrupt-user", "v1"));
    // Values without the vault1: prefix decrypt as legacy plaintext, so a
    // genuine failure needs broken envelopes: a wrong-key envelope for
    // user_info and a malformed one for access_token.
    let wrong_key = Vault::from_secret("PUBLIC install sequence wrong vault seed").unwrap();
    let wrong_cipher = wrong_key.encrypt("PUBLIC-install-user-info").unwrap();
    assert!(
        wrong_cipher.starts_with("vault1:"),
        "precondition: real envelope"
    );
    fixture
        .state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE accounts SET user_info=?1, access_token='vault1:!!!not-base64' WHERE id=?2",
            rusqlite::params![wrong_cipher, id],
        )
        .unwrap();
    let report = install(&fixture.state, id).await;
    assert!(report.is_err(), "decryption failure must surface Err");
    mock.assert_order(&[]);
    mock.assert_complete();
}

#[tokio::test]
async fn reimport_during_configs_gate_suppresses_stale_next_steps() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None, false);
    let user = "PUBLIC-install-reimport-user";
    let first = jwt(user, "v1");
    let id = fixture.paste_import(&first).await["id"].as_i64().unwrap();

    let gate = Arc::new(Gate::default());
    mock.push_configs(Step::ok(json!({"code":0})).gated(gate.clone()));
    let task = spawn_install(&fixture.state, id);
    enter(&gate, "install reaches the gated configs request").await;
    assert_eq!(mock.seen().len(), 1, "only configs has been sent so far");

    let second = jwt(user, "v2");
    let reimported = fixture.paste_import(&second).await;
    assert_eq!(reimported["id"], id, "reimport upserts the same account");

    gate.release.notify_one();
    let report = task
        .await
        .expect("install task joins")
        .expect("credential change is reported, not errored");
    assert_report(&report, 1, 1, true);
    mock.assert_order(&[("GET", CONFIGS, "")]);
    mock.assert_complete();

    // The next sequence picks up the new credentials: the old JWT never
    // reappears on any later request.
    mock.push_ok_sequence();
    let report = install(&fixture.state, id)
        .await
        .expect("fresh run reports Ok");
    assert_report(&report, 3, 3, false);
    mock.assert_order(&[
        ("GET", CONFIGS, ""),
        ("GET", CONFIGS, ""),
        ("POST", EVENT, format!("Bearer {second}").as_str()),
        ("POST", EVENT, format!("Bearer {second}").as_str()),
    ]);
    let stale = mock
        .seen()
        .iter()
        .any(|seen| seen.authorization == format!("Bearer {first}"));
    assert!(
        !stale,
        "stale credentials must never be sent after a reimport"
    );
    mock.assert_complete();
}

#[tokio::test]
async fn delete_during_configs_gate_stops_without_resurrecting() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None, false);
    let id = fixture.seed(
        "install-mid-delete",
        &jwt("PUBLIC-install-mid-delete-user", "v1"),
    );

    let gate = Arc::new(Gate::default());
    mock.push_configs(Step::ok(json!({"code":0})).gated(gate.clone()));
    let task = spawn_install(&fixture.state, id);
    enter(&gate, "install reaches the gated configs request").await;
    fixture.delete_account(id).await;
    gate.release.notify_one();
    let report = task
        .await
        .expect("install task joins")
        .expect("mid-sequence delete is a skip, not an error");
    assert_report(&report, 1, 1, true);
    mock.assert_order(&[("GET", CONFIGS, "")]);
    mock.assert_complete();
    assert!(!fixture.row_exists(id), "the deleted row stays deleted");
}

// ---- automatic manager integration ----

#[tokio::test]
async fn manager_paste_import_runs_install_once_before_quota_refresh_when_enabled() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None, true);
    let manager = fixture.install_manager(manager_config(
        Duration::from_millis(50),
        PARKED,
        2,
        DEADLINE,
    ));
    let secret = jwt("PUBLIC-install-auto-paste-user", "v1");
    mock.push_ok_sequence();
    mock.push_billing(25.0);
    let id = fixture.paste_import(&secret).await["id"].as_i64().unwrap();
    settle(&manager).await;
    mock.assert_order(&[
        ("GET", CONFIGS, ""),
        ("POST", EVENT, format!("Bearer {secret}").as_str()),
        ("POST", EVENT, format!("Bearer {secret}").as_str()),
        ("GET", BILLING, format!("Bearer {secret}").as_str()),
    ]);
    mock.assert_complete();
    assert_eq!(
        mock.seen().len(),
        4,
        "the install sequence runs exactly once"
    );
    let mid = fixture.stored_mid(id);
    assert_uuid4(&mid, "automatic install persists the identity");
    assert_eq!(mock.seen()[0].header("x-device-mid"), mid);
    let (status, remaining, tier, checked) = fixture
        .state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT status,remaining,plan_tier,last_checked_at FROM accounts WHERE id=?1",
            [id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, f64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        (status.as_str(), remaining, tier.as_str()),
        ("active", 75.0, "Pro")
    );
    assert!(checked > 0, "quota refresh still commits after the install");
}

#[tokio::test]
async fn manager_local_import_runs_install_before_quota_when_enabled() {
    let mock = Mock::start().await;
    let files = LocalFiles::new();
    let token = jwt("PUBLIC-install-auto-local-user", "v1");
    files.write_token(&token);
    let fixture = Fixture::new(&mock, Some(files.credentials()), true);
    let manager = fixture.install_manager(manager_config(
        Duration::from_millis(50),
        PARKED,
        2,
        DEADLINE,
    ));
    mock.push_ok_sequence();
    mock.push_billing(25.0);
    let id = fixture.local_import().await["id"].as_i64().unwrap();
    assert!(id > 0, "local import returns a real account id");
    settle(&manager).await;
    mock.assert_order(&[
        ("GET", CONFIGS, ""),
        ("POST", EVENT, format!("Bearer {token}").as_str()),
        ("POST", EVENT, format!("Bearer {token}").as_str()),
        ("GET", BILLING, format!("Bearer {token}").as_str()),
    ]);
    mock.assert_complete();
    assert!(fixture.row_exists(id), "the imported account is persisted");
}

#[tokio::test]
async fn manager_oauth_import_runs_install_before_quota_when_enabled() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None, true);
    // import_delay stays parked: settling proves the OAuth hook scheduled the
    // combined install-plus-quota job on the OAuth delay.
    let manager = fixture.install_manager(manager_config(
        PARKED,
        Duration::from_millis(50),
        2,
        DEADLINE,
    ));
    let token = jwt("PUBLIC-install-auto-oauth-user", "v1");
    mock.push_token(json!({"code":200,"data":{"token": token.clone()}}));
    mock.push_ok_sequence();
    mock.push_billing(25.0);
    let (status, started) = fixture
        .request(
            "POST",
            "/api/accounts/oauth/start",
            &json!({"manual": true}).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "oauth start: {started}");
    let state = started["state"].as_str().unwrap();
    let (status, completed) = fixture
        .request(
            "POST",
            "/api/accounts/oauth/manual",
            &json!({"state": state, "input": OAUTH_CODE}).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "oauth manual completion: {completed}"
    );
    let (status, ready) = fixture
        .request(
            "GET",
            &format!("/api/accounts/oauth/status?state={state}"),
            "",
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ready["status"], "ready");
    settle(&manager).await;
    mock.assert_order(&[
        ("POST", TOKEN, ""),
        ("GET", CONFIGS, ""),
        ("POST", EVENT, format!("Bearer {token}").as_str()),
        ("POST", EVENT, format!("Bearer {token}").as_str()),
        ("GET", BILLING, format!("Bearer {token}").as_str()),
    ]);
    mock.assert_complete();
}

#[tokio::test]
async fn default_flag_keeps_automatic_reporting_offline_after_paste_import() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None, false);
    assert!(
        !fixture.state.install_reporting_enabled,
        "the fixture constructor leaves automatic reporting off"
    );
    let manager = fixture.install_manager(manager_config(
        Duration::from_millis(50),
        PARKED,
        2,
        DEADLINE,
    ));
    let secret = jwt("PUBLIC-install-offline-user", "v1");
    mock.push_billing(25.0);
    fixture.paste_import(&secret).await;
    settle(&manager).await;
    // URLs point at the mock as a canary: any install traffic would be seen.
    mock.assert_order(&[("GET", BILLING, format!("Bearer {secret}").as_str())]);
    mock.assert_complete();
}

#[tokio::test]
async fn bundle_and_plain_add_carry_no_install_hook_even_when_enabled() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None, true);
    // The manager must outlive the imports so a live hook could have fired.
    let manager = fixture.install_manager(manager_config(
        PARKED,
        PARKED,
        2,
        Duration::from_millis(100),
    ));
    let wire: Value =
        serde_json::from_str(include_str!("fixtures/account_bundle_interop.json")).unwrap();
    let (status, body) = fixture
        .request_with_timeout(
            "POST",
            "/api/accounts/import/bundle",
            &json!({"password": wire["password"], "bundle": wire["current"]}).to_string(),
            CRYPTO_DEADLINE,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "bundle import: {body}");
    assert_eq!(body["imported"], 2);
    let jwt_cipher = fixture
        .state
        .vault
        .encrypt("PUBLIC-install-bundle-jwt")
        .unwrap();
    let key_cipher = fixture
        .state
        .vault
        .encrypt("PUBLIC-install-bundle-key")
        .unwrap();
    let (status, body) = fixture
        .request(
            "POST",
            "/api/accounts/add",
            &json!({
                "email": "plain-add@example.invalid", "provider": "zai",
                "zcode_jwt": jwt_cipher, "api_key": key_cipher
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "plain add: {body}");
    assert_eq!(body["ok"], true);
    assert!(
        manager.pending().is_empty(),
        "bundle and plain-add paths enqueue no install work"
    );
    mock.assert_order(&[]);
    mock.assert_complete();
}

#[tokio::test]
async fn stop_during_configs_suppresses_events_but_import_succeeds() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None, true);
    let manager = fixture.install_manager(manager_config(
        Duration::from_millis(50),
        PARKED,
        1,
        DEADLINE,
    ));
    let secret = jwt("PUBLIC-install-stop-user", "v1");
    let gate = Arc::new(Gate::default());
    mock.push_configs(Step::ok(json!({"code":0})).gated(gate.clone()));
    fixture.paste_import(&secret).await;
    enter(
        &gate,
        "the automatic install reaches the held configs request",
    )
    .await;
    manager.stop();
    gate.release.notify_one();
    settle(&manager).await;
    // The in-flight configs request may complete; no further step may start.
    mock.assert_order(&[("GET", CONFIGS, "")]);
    mock.assert_complete();
    assert!(manager.is_stopped());
    assert!(manager.pending().is_empty());
}
