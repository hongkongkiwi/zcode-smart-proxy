//! Per-account device identity regressions (Go reference: identity.go
//! SetAccountDeviceMid / EnsureDeviceIdentity / EnsurePoolDeviceIdentities).
//!
//! Contracts pinned here:
//! - `identity::ensure_device_identity` mints a persisted UUIDv4 device_mid
//!   for accounts whose fingerprint is empty, keeps it stable across repeated
//!   calls and reloads, and never rotates an existing fingerprint (including
//!   disabled or non-zai accounts). Missing or deleted accounts error without
//!   resurrecting the row, and concurrent ensures converge on one stored
//!   winner.
//! - `identity::backfill_device_identities` reports how many empty identities
//!   it filled, skips existing fingerprints, and commits as one batch: a row
//!   failure rolls back every write.
//! - Storage failures fail closed: `ensure` errors without a memory-only
//!   identity, and quota refresh / manual billing return 500 before any
//!   upstream request when the persist fails.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    Json, Router,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_core::AccountView;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router, identity,
    state::{AppState, AutomationUrls, ManagementUrls, UpstreamUrls},
    store,
    vault::Vault,
};

const SESSION: &str = "PUBLIC-device-identity-session";
const JWT: &str = "PUBLIC-device-identity-jwt";
const KEY: &str = "PUBLIC-device-identity-api-key";
const VERSION: &str = "PUBLIC-device-identity-version";
const SENTINEL: &str = "PUBLIC-device-identity-sentinel-mid";
const SENTINEL_ALT: &str = "PUBLIC-device-identity-sentinel-alt";
const USER: &str = "PUBLIC-device-identity-user";
const EVENT: &str = "/api/v1/event/report";
const BALANCE: &str = "/api/v1/zcode-plan/billing/balance";
const PREVIEW: &str = "/api/v1/zcode-plan/billing/preview";
const UNREACHABLE: &str = "http://127.0.0.1:1";
const ENSURE_THREADS: usize = 8;
const ENSURE_CALLS_PER_THREAD: usize = 3;

// ---- fixtures ----

struct Seed {
    email: String,
    provider: String,
    enabled: bool,
    status: String,
    device_mid: String,
    user_info: Value,
}

impl Seed {
    fn new(email: &str) -> Self {
        Self {
            email: email.into(),
            provider: "zai".into(),
            enabled: true,
            status: "active".into(),
            device_mid: String::new(),
            user_info: Value::Null,
        }
    }

    fn identity(mut self, mid: &str) -> Self {
        self.device_mid = mid.into();
        self
    }

    fn disabled(mut self) -> Self {
        self.enabled = false;
        self.status = "disabled".into();
        self
    }

    fn provider(mut self, provider: &str) -> Self {
        self.provider = provider.into();
        self
    }

    fn profile(mut self, user: &str) -> Self {
        self.user_info = json!({"id": user});
        self
    }
}

fn seed_account(db: &rusqlite::Connection, vault: &Vault, seed: &Seed) -> i64 {
    let id = store::insert_account_encrypted(
        db,
        vault,
        &AccountView {
            email: seed.email.clone(),
            provider: seed.provider.clone(),
            enabled: seed.enabled,
            status: seed.status.clone(),
            ..Default::default()
        },
        JWT,
        KEY,
    )
    .unwrap();
    let user_info = if seed.user_info.is_object() {
        vault.encrypt(&seed.user_info.to_string()).unwrap()
    } else {
        String::new()
    };
    db.execute(
        "UPDATE accounts SET device_mid=?1,user_info=?2 WHERE id=?3",
        rusqlite::params![seed.device_mid, user_info, id],
    )
    .unwrap();
    id
}

fn state_for(base: &str, db: rusqlite::Connection, vault: Vault) -> AppState {
    let mut state = AppState::try_from_db_with_vault(
        String::new(),
        UpstreamUrls {
            zai: format!("{base}/forbidden-relay"),
            zai_fallback: format!("{base}/forbidden-relay-fallback"),
        },
        db,
        vault,
    )
    .unwrap();
    state.management = ManagementUrls {
        billing_base: format!("{base}/api/v1/zcode-plan"),
        quota_limit: format!("{base}/forbidden-monitor"),
        subscription: format!("{base}/forbidden-subscription"),
        oauth_token: format!("{base}/forbidden-oauth"),
        app_version: VERSION.into(),
    };
    state.automation = AutomationUrls {
        billing_preview: format!("{base}{PREVIEW}"),
        billing_claim: format!("{base}/forbidden-claim"),
        event_report: format!("{base}{EVENT}"),
        reset_status: format!("{base}/forbidden-reset-status"),
        reset_use: format!("{base}/forbidden-reset-use"),
        captcha_scene: String::new(),
        captcha_prefix: String::new(),
        captcha_region: String::new(),
    };
    state
        .sessions
        .lock()
        .unwrap()
        .insert(SESSION.into(), now_secs() + 3600);
    state
}

fn sync_fixture(seeds: &[Seed]) -> (Arc<AppState>, Vec<i64>) {
    let db = store::open(":memory:");
    let vault = Vault::from_secret("PUBLIC device identity sync vault seed").unwrap();
    let ids = seeds
        .iter()
        .map(|seed| seed_account(&db, &vault, seed))
        .collect();
    (Arc::new(state_for(UNREACHABLE, db, vault)), ids)
}

fn mock_fixture(mock: &Mock, seed: &Seed) -> (Arc<AppState>, i64) {
    let db = store::open(":memory:");
    let vault = Vault::from_secret("PUBLIC device identity mock vault seed").unwrap();
    let id = seed_account(&db, &vault, seed);
    (Arc::new(state_for(&mock.base, db, vault)), id)
}

/// Rebuild the state from the same database to prove identities are durable,
/// not process-memory artifacts.
fn reload(state: Arc<AppState>) -> Arc<AppState> {
    let state = Arc::try_unwrap(state)
        .ok()
        .expect("fixture state must be uniquely held");
    let management = state.management.clone();
    let automation = state.automation.clone();
    let mut next = AppState::try_from_db_with_vault(
        state.root_key,
        state.upstream,
        state.db.into_inner().unwrap(),
        state.vault,
    )
    .unwrap();
    next.management = management;
    next.automation = automation;
    next.sessions
        .lock()
        .unwrap()
        .insert(SESSION.into(), now_secs() + 3600);
    Arc::new(next)
}

fn stored_mid(state: &AppState, id: i64) -> String {
    state
        .db
        .lock()
        .unwrap()
        .query_row("SELECT device_mid FROM accounts WHERE id=?1", [id], |r| {
            r.get(0)
        })
        .unwrap()
}

fn account_row_exists(state: &AppState, id: i64) -> bool {
    state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE id=?1)",
            [id],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
        != 0
}

fn sql(state: &AppState, statement: &str) {
    state.db.lock().unwrap().execute_batch(statement).unwrap();
}

fn assert_uuid4(mid: &str, context: &str) {
    assert_eq!(mid.len(), 36, "{context}: canonical UUID length in {mid}");
    for (index, byte) in mid.bytes().enumerate() {
        match index {
            8 | 13 | 18 | 23 => {
                assert_eq!(byte, b'-', "{context}: dash layout in {mid}")
            }
            _ => assert!(
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
                "{context}: lowercase hex digit in {mid}"
            ),
        }
    }
    assert_eq!(
        &mid[14..15],
        "4",
        "{context}: RFC 4122 version nibble in {mid}"
    );
    assert!(
        matches!(&mid[19..20], "8" | "9" | "a" | "b"),
        "{context}: RFC 4122 variant nibble in {mid}"
    );
}

// ---- loopback mock ----

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    headers: HeaderMap,
    body: Value,
}

impl Seen {
    fn device_mid(&self) -> &str {
        self.headers
            .get("x-device-mid")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
    }
}

#[derive(Default)]
struct Script {
    steps: Mutex<VecDeque<(StatusCode, Value)>>,
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
        async fn serve(
            State(script): State<Arc<Script>>,
            request: Request,
        ) -> (StatusCode, Json<Value>) {
            let (parts, body) = request.into_parts();
            let bytes = axum::body::to_bytes(body, 1 << 20)
                .await
                .unwrap_or_default();
            let seen = Seen {
                method: parts.method.to_string(),
                path: parts.uri.path().into(),
                headers: parts.headers,
                body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            };
            script.seen.lock().unwrap().push(seen);
            match script.steps.lock().unwrap().pop_front() {
                Some((status, body)) => (status, Json(body)),
                None => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"code":500,"msg":"unexpected mock request"})),
                ),
            }
        }
        let script = Arc::new(Script::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(serve).with_state(script.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base, script, task }
    }

    fn push(&self, status: StatusCode, body: Value) {
        self.script.steps.lock().unwrap().push_back((status, body));
    }

    fn seen(&self) -> Vec<Seen> {
        self.script.seen.lock().unwrap().clone()
    }

    fn assert_complete(&self) {
        assert!(
            self.script.steps.lock().unwrap().is_empty(),
            "unconsumed upstream responses"
        );
    }
}

async fn call(state: &Arc<AppState>, method: &str, uri: String) -> (StatusCode, Value) {
    let request = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "localhost:8080")
        .header("origin", "http://localhost:8080")
        .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
        .body(Body::empty())
        .unwrap();
    let response = tokio::time::timeout(
        Duration::from_secs(8),
        build_router(state.clone()).oneshot(request),
    )
    .await
    .expect("bounded loopback request deadline")
    .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn billing_ok() -> Value {
    json!({"code":0,"success":true,"data":{"result":{
        "plans":[{"plan_id":"pro","name":"Pro","status":"active","expire_time":"2096-01-02 03:04"}],
        "balances":[{"plan_id":"pro","show_name":"PUBLIC identity tokens",
            "total_units":100.0,"used_units":25.0,"remaining_units":75.0}]
    }}})
}

fn event_ok() -> Value {
    json!({"code":0,"success":true})
}

fn push_activate_exchange(mock: &Mock) {
    mock.push(StatusCode::OK, event_ok());
    mock.push(StatusCode::OK, event_ok());
    mock.push(StatusCode::OK, billing_ok());
}

// ---- ensure_device_identity ----

#[test]
fn ensure_generates_persists_and_stabilizes_uuid4_and_preserves_sentinel_identities() {
    let (state, ids) = sync_fixture(&[
        Seed::new("generated@example.invalid"),
        Seed::new("disabled-foreign@example.invalid")
            .identity(SENTINEL)
            .disabled()
            .provider("openai"),
    ]);
    let (generated, sentinel) = (ids[0], ids[1]);

    let mid = identity::ensure_device_identity(&state, generated)
        .expect("empty identity must be generated and persisted");
    assert_uuid4(&mid, "generated device_mid");
    assert_eq!(
        stored_mid(&state, generated),
        mid,
        "identity must be durable"
    );
    assert_eq!(
        identity::ensure_device_identity(&state, generated).unwrap(),
        mid,
        "a second ensure must reuse the stored identity instead of rotating"
    );

    assert_eq!(
        identity::ensure_device_identity(&state, sentinel).unwrap(),
        SENTINEL,
        "existing fingerprints on disabled non-zai accounts must never rotate"
    );
    assert_eq!(stored_mid(&state, sentinel), SENTINEL);

    let state = reload(state);
    assert_eq!(
        identity::ensure_device_identity(&state, generated).unwrap(),
        mid,
        "reload must preserve the generated identity"
    );
    assert_eq!(stored_mid(&state, generated), mid);
    assert_eq!(stored_mid(&state, sentinel), SENTINEL);
}

#[tokio::test]
async fn ensure_on_missing_or_deleted_account_errors_without_resurrection() {
    let (state, ids) = sync_fixture(&[Seed::new("doomed@example.invalid")]);
    let id = ids[0];
    assert_uuid4(
        &identity::ensure_device_identity(&state, id).unwrap(),
        "pre-deletion sanity ensure",
    );

    let (status, body) = call(&state, "DELETE", format!("/api/accounts/{id}")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "account deletion must succeed: {body}"
    );
    assert_eq!(body["ok"], true);

    assert!(
        identity::ensure_device_identity(&state, id).is_err(),
        "a deleted account must not get a new identity"
    );
    assert!(
        !account_row_exists(&state, id),
        "ensure must not resurrect the deleted row"
    );
    assert!(
        state.accounts.lock().unwrap().iter().all(|a| a.id != id),
        "ensure must not resurrect the deleted account in memory"
    );

    assert!(
        identity::ensure_device_identity(&state, 987_654).is_err(),
        "an id that never existed must error"
    );

    assert_eq!(
        identity::backfill_device_identities(&state).unwrap(),
        0,
        "backfill over an empty pool reports zero without recreating rows"
    );
    assert!(!account_row_exists(&state, id));
}

#[test]
fn concurrent_ensure_converges_on_one_persisted_winner() {
    let (state, ids) = sync_fixture(&[Seed::new("raced@example.invalid")]);
    let id = ids[0];

    let state_ref: &AppState = &state;
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..ENSURE_THREADS)
            .map(|_| {
                scope.spawn(move || {
                    (0..ENSURE_CALLS_PER_THREAD)
                        .map(|_| identity::ensure_device_identity(state_ref, id))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut all = Vec::new();
        for handle in handles {
            all.extend(handle.join().expect("ensure thread must not panic"));
        }
        all
    });
    let mids: Vec<String> = results
        .into_iter()
        .map(|result| result.expect("concurrent ensure must succeed"))
        .collect();
    assert_eq!(mids.len(), ENSURE_THREADS * ENSURE_CALLS_PER_THREAD);
    assert!(
        mids.iter().all(|mid| mid == &mids[0]),
        "every racer must observe the single stored winner: {mids:?}"
    );
    assert_uuid4(&mids[0], "winning device_mid");
    assert_eq!(stored_mid(&state, id), mids[0]);
}

// ---- backfill_device_identities ----

#[test]
fn backfill_fills_only_empty_identities_and_reports_the_backfilled_count() {
    let (state, ids) = sync_fixture(&[
        Seed::new("active-empty@example.invalid"),
        Seed::new("disabled-empty@example.invalid")
            .disabled()
            .provider("anthropic"),
        Seed::new("active-filled@example.invalid").identity(SENTINEL),
        Seed::new("disabled-filled@example.invalid")
            .identity(SENTINEL_ALT)
            .disabled(),
    ]);

    assert_eq!(
        identity::backfill_device_identities(&state).unwrap(),
        2,
        "only the two empty identities count as backfilled"
    );
    let first = stored_mid(&state, ids[0]);
    let second = stored_mid(&state, ids[1]);
    assert_uuid4(&first, "backfilled active identity");
    assert_uuid4(&second, "backfilled disabled non-zai identity");
    assert_ne!(first, second, "accounts must not share one device identity");
    assert_eq!(stored_mid(&state, ids[2]), SENTINEL);
    assert_eq!(stored_mid(&state, ids[3]), SENTINEL_ALT);

    let state = reload(state);
    assert_eq!(
        stored_mid(&state, ids[0]),
        first,
        "reload preserves backfill"
    );
    assert_eq!(stored_mid(&state, ids[1]), second);
    assert_eq!(stored_mid(&state, ids[2]), SENTINEL);
    assert_eq!(stored_mid(&state, ids[3]), SENTINEL_ALT);
    assert_eq!(
        identity::backfill_device_identities(&state).unwrap(),
        0,
        "a second backfill is a no-op"
    );
}

#[test]
fn backfill_row_failure_rolls_back_every_identity_write() {
    let (state, ids) = sync_fixture(&[
        Seed::new("would-commit@example.invalid"),
        Seed::new("forced-failure@example.invalid"),
        Seed::new("already-set@example.invalid").identity(SENTINEL),
    ]);
    let (commit_id, fail_id, sentinel_id) = (ids[0], ids[1], ids[2]);
    sql(
        &state,
        &format!(
            "CREATE TRIGGER reject_backfill_row BEFORE UPDATE ON accounts
               WHEN OLD.id = {fail_id}
             BEGIN SELECT RAISE(FAIL, 'PUBLIC forced backfill row failure'); END;"
        ),
    );

    let result = identity::backfill_device_identities(&state);
    assert!(
        matches!(&result, Err(store::StoreError::Database)),
        "a row failure must fail the whole backfill: {result:?}"
    );
    assert_eq!(
        stored_mid(&state, commit_id),
        "",
        "the batch is all-or-none: an earlier row must not stay committed"
    );
    assert_eq!(stored_mid(&state, fail_id), "");
    assert_eq!(stored_mid(&state, sentinel_id), SENTINEL);
    for id in ids {
        assert!(account_row_exists(&state, id));
    }

    sql(&state, "DROP TRIGGER reject_backfill_row");
    assert_eq!(
        identity::backfill_device_identities(&state).unwrap(),
        2,
        "retry after the failure must backfill both empty identities"
    );
    let first = stored_mid(&state, commit_id);
    let second = stored_mid(&state, fail_id);
    assert_uuid4(&first, "retried backfill identity");
    assert_uuid4(&second, "retried backfill identity");
    assert_ne!(first, second);
    assert_eq!(stored_mid(&state, sentinel_id), SENTINEL);
}

// ---- HTTP integration: quota refresh and manual billing ----

#[tokio::test]
async fn quota_refresh_ensures_a_stable_identity_header_across_reloads() {
    let mock = Mock::start().await;
    let (state, id) = mock_fixture(&mock, &Seed::new("refresh-empty@example.invalid"));
    mock.push(StatusCode::OK, billing_ok());
    mock.push(StatusCode::OK, billing_ok());

    for round in 0..2 {
        let (status, body) = call(&state, "POST", format!("/api/accounts/{id}/refresh")).await;
        assert_eq!(status, StatusCode::OK, "refresh round {round}: {body}");
        assert_eq!(body["success"], true);
        assert_eq!(body["account"]["plan_tier"], "Pro");
    }
    let seen = mock.seen();
    assert_eq!(seen.len(), 2, "one billing request per refresh");
    let mid = seen[0].device_mid().to_owned();
    assert_uuid4(&mid, "refresh-generated x-device-mid");
    for request in &seen {
        assert_eq!(
            request.device_mid(),
            mid,
            "every billing request must carry the same generated identity"
        );
        assert_eq!(request.path, BALANCE);
    }
    assert_eq!(
        stored_mid(&state, id),
        mid,
        "refresh must persist the identity"
    );
    mock.assert_complete();

    let state = reload(state);
    mock.push(StatusCode::OK, billing_ok());
    let (status, body) = call(&state, "POST", format!("/api/accounts/{id}/refresh")).await;
    assert_eq!(status, StatusCode::OK, "post-reload refresh: {body}");
    assert_eq!(body["success"], true);
    let seen = mock.seen();
    assert_eq!(seen.len(), 3);
    assert_eq!(
        seen[2].device_mid(),
        mid,
        "reload must keep the same identity"
    );
    assert_eq!(stored_mid(&state, id), mid);
    mock.assert_complete();
}

#[tokio::test]
async fn billing_activate_reports_events_with_the_persisted_identity_across_reloads() {
    let mock = Mock::start().await;
    let (state, id) = mock_fixture(
        &mock,
        &Seed::new("activate-empty@example.invalid").profile(USER),
    );
    push_activate_exchange(&mock);

    let (status, body) = call(&state, "POST", format!("/api/accounts/{id}/activate")).await;
    assert_eq!(status, StatusCode::OK, "activation must succeed: {body}");
    assert_eq!(body["ok"], true);

    let seen = mock.seen();
    assert_eq!(seen.len(), 3, "two events plus one quota confirmation");
    let mid = seen[0].device_mid().to_owned();
    assert_uuid4(&mid, "activation-generated x-device-mid");
    for request in &seen {
        assert_eq!(
            request.device_mid(),
            mid,
            "all upstream calls share the identity"
        );
    }
    let events: Vec<&Seen> = seen.iter().filter(|s| s.path == EVENT).collect();
    assert_eq!(events.len(), 2);
    for (event, element) in events.iter().zip(["app_launch", "app_daily_active"]) {
        assert_eq!(event.method, "POST");
        assert_eq!(event.body["element_name"], element);
        assert_eq!(event.body["device_mid"], mid, "event payload identity");
        assert_eq!(event.body["user_id"], USER);
    }
    assert_eq!(
        seen.iter().filter(|s| s.path == BALANCE).count(),
        1,
        "activation must confirm quota with the same identity"
    );
    assert_eq!(stored_mid(&state, id), mid);
    mock.assert_complete();

    push_activate_exchange(&mock);
    let (status, body) = call(&state, "POST", format!("/api/accounts/{id}/activate")).await;
    assert_eq!(status, StatusCode::OK, "repeat activation: {body}");
    assert_eq!(body["ok"], true);
    let seen = mock.seen();
    assert_eq!(seen.len(), 6);
    for request in &seen[3..] {
        assert_eq!(
            request.device_mid(),
            mid,
            "repeated requests keep the identity"
        );
    }
    mock.assert_complete();

    let state = reload(state);
    push_activate_exchange(&mock);
    let (status, body) = call(&state, "POST", format!("/api/accounts/{id}/activate")).await;
    assert_eq!(status, StatusCode::OK, "post-reload activation: {body}");
    assert_eq!(body["ok"], true);
    let seen = mock.seen();
    assert_eq!(seen.len(), 9);
    for request in &seen[6..] {
        assert_eq!(
            request.device_mid(),
            mid,
            "reload keeps the persisted identity"
        );
    }
    for event in seen.iter().filter(|s| s.path == EVENT).skip(4) {
        assert_eq!(event.body["device_mid"], mid);
    }
    assert_eq!(stored_mid(&state, id), mid);
    mock.assert_complete();
}

#[tokio::test]
async fn identity_persist_failure_fails_closed_before_any_upstream_call() {
    let mock = Mock::start().await;
    let (state, id) = mock_fixture(&mock, &Seed::new("blocked@example.invalid"));
    sql(
        &state,
        "CREATE TRIGGER reject_device_mid_write BEFORE UPDATE OF device_mid ON accounts
           WHEN NEW.device_mid <> OLD.device_mid
         BEGIN SELECT RAISE(FAIL, 'PUBLIC forced device_mid persist failure'); END;",
    );

    let result = identity::ensure_device_identity(&state, id);
    assert!(
        matches!(&result, Err(store::StoreError::Database)),
        "persist failure must fail closed: {result:?}"
    );
    assert_eq!(
        stored_mid(&state, id),
        "",
        "no identity may survive a failed persist"
    );

    let (status, body) = call(&state, "POST", format!("/api/accounts/{id}/refresh")).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "quota refresh must fail closed on identity persist failure: {body}"
    );
    assert_eq!(body["error"]["type"], "api_error");
    assert!(
        mock.seen().is_empty(),
        "no upstream quota call may leave the process when the identity cannot persist"
    );

    let (status, body) = call(&state, "POST", format!("/api/accounts/{id}/detect")).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "manual billing must fail closed on identity persist failure: {body}"
    );
    assert_eq!(body["error"]["type"], "api_error");
    assert!(
        mock.seen().is_empty(),
        "no upstream billing call may leave the process when the identity cannot persist"
    );
    assert_eq!(stored_mid(&state, id), "");

    sql(&state, "DROP TRIGGER reject_device_mid_write");
    mock.push(StatusCode::OK, billing_ok());
    let (status, body) = call(&state, "POST", format!("/api/accounts/{id}/refresh")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "recovered refresh must succeed: {body}"
    );
    assert_eq!(body["success"], true);
    let seen = mock.seen();
    assert_eq!(seen.len(), 1);
    let mid = stored_mid(&state, id);
    assert_uuid4(&mid, "recovered identity");
    assert_eq!(
        seen[0].device_mid(),
        mid,
        "the persisted identity reaches upstream"
    );
    mock.assert_complete();
}
