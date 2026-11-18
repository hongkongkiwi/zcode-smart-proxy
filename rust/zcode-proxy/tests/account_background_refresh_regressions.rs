//! Independent regressions for the managed post-import background quota
//! refresh (design: .agents/state/rust-migration/account-lifecycle-design.md).
//! Authored against the documented public surface before implementation:
//! a missing module is an honest compile gap, not a behavioral red.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::StatusCode,
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
    background_refresh::{BackgroundRefresh, BackgroundRefreshConfig, BackgroundShutdownReport},
    build_router,
    state::{AppState, Creds, ManagementUrls, UpstreamUrls},
    store,
    vault::Vault,
};

const SESSION: &str = "PUBLIC-background-refresh-session";
const BILLING: &str = "/api/v1/zcode-plan/billing/balance";
const TOKEN: &str = "/api/v1/oauth/token";
const OAUTH_JWT: &str = "PUBLIC-background-oauth-jwt";
const OAUTH_CODE: &str = "PUBLIC-background-oauth-code";
const JWT_A: &str = "PUBLIC-background-jwt-a";
const JWT_B: &str = "PUBLIC-background-jwt-b";
const JWT_C: &str = "PUBLIC-background-jwt-c";
// A delay no bounded test wait can outlive: jobs admitted under it stay
// deterministically pending unless cancelled or dropped.
const PARKED: Duration = Duration::from_secs(3600);
const DEADLINE: Duration = Duration::from_secs(5);
// Debug-mode bundle import derives PBKDF2 (600k rounds) under spawn_blocking;
// this is a harness deadline for that route alone, not latency acceptance.
const CRYPTO_DEADLINE: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, PartialEq)]
struct Seen {
    method: String,
    path: String,
    authorization: String,
}

#[derive(Default)]
struct Gate {
    entered: Notify,
    release: Notify,
}

struct Step {
    body: Value,
    gate: Option<Arc<Gate>>,
}

#[derive(Default)]
struct Script {
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
        async fn serve(
            State(script): State<Arc<Script>>,
            request: Request,
        ) -> (StatusCode, Json<Value>) {
            script.seen.lock().unwrap().push(Seen {
                method: request.method().to_string(),
                path: request.uri().path().into(),
                authorization: request
                    .headers()
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("")
                    .into(),
            });
            let step = match request.uri().path() {
                BILLING => script.billing_steps.lock().unwrap().pop_front(),
                TOKEN => script.token_steps.lock().unwrap().pop_front(),
                _ => None,
            };
            let Some(step) = step else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"code":500,"msg":"unexpected mock request"})),
                );
            };
            if let Some(gate) = step.gate {
                gate.entered.notify_one();
                gate.release.notified().await;
            }
            (StatusCode::OK, Json(step.body))
        }
        let script = Arc::new(Script::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(serve).with_state(script.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base, script, task }
    }

    fn push_billing(&self, used: f64) {
        self.script.billing_steps.lock().unwrap().push_back(Step {
            body: billing(used),
            gate: None,
        });
    }

    fn push_gated_billing(&self, used: f64, gate: Arc<Gate>) {
        self.script.billing_steps.lock().unwrap().push_back(Step {
            body: billing(used),
            gate: Some(gate),
        });
    }

    fn push_token(&self, body: Value) {
        self.script
            .token_steps
            .lock()
            .unwrap()
            .push_back(Step { body, gate: None });
    }

    fn count(&self) -> usize {
        self.script.seen.lock().unwrap().len()
    }

    fn authorizations(&self) -> Vec<String> {
        self.script
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|seen| seen.authorization.clone())
            .collect()
    }

    fn assert_seen(&self, expected: &[(&str, &str, String)]) {
        let actual = self.script.seen.lock().unwrap().clone();
        let expected: Vec<_> = expected
            .iter()
            .map(|&(method, path, ref authorization)| Seen {
                method: method.into(),
                path: path.into(),
                authorization: authorization.clone(),
            })
            .collect();
        assert_eq!(
            actual, expected,
            "upstream method, endpoint, and credential contract"
        );
    }

    fn assert_seen_billing_set(&self, authorizations: &[String]) {
        let seen = self.script.seen.lock().unwrap();
        assert_eq!(seen.len(), authorizations.len());
        for request in seen.iter() {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, BILLING);
        }
        let actual: BTreeSet<_> = seen.iter().map(|s| s.authorization.clone()).collect();
        let expected: BTreeSet<_> = authorizations.iter().cloned().collect();
        assert_eq!(actual, expected, "distinct accounts fetched exactly once");
    }

    fn assert_complete(&self) {
        assert!(
            self.script.billing_steps.lock().unwrap().is_empty()
                && self.script.token_steps.lock().unwrap().is_empty(),
            "not all expected upstream responses were consumed"
        );
    }
}

struct LocalFiles(PathBuf);

impl LocalFiles {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "zcode-background-refresh-{}-{:032x}",
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

fn config(
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

fn billing(used: f64) -> Value {
    json!({"code":0,"success":true,"data":{"result":{
        "plans":[{"plan_id":"pro","name":"Pro","status":"active","expire_time":"2096-01-02 03:04"}],
        "balances":[{"plan_id":"pro","show_name":"PUBLIC quota","total_units":100.0,
            "used_units":used,"remaining_units":100.0-used}]
    }}})
}

// Claims are deliberately unsigned: paste import reads identity, not validity.
fn jwt(user_id: &str, variant: &str) -> String {
    format!(
        "e30.{}.PUBLIC-not-a-real-signature-{}",
        URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"user_id": user_id, "jti": variant})).unwrap()),
        variant
    )
}

struct Fixture {
    state: Arc<AppState>,
}

impl Fixture {
    fn new(mock: &Mock, local: Option<PathBuf>) -> Self {
        let mut state = AppState::try_from_db_with_vault(
            String::new(),
            UpstreamUrls {
                zai: format!("{}/unused-relay", mock.base),
                zai_fallback: format!("{}/unused-relay-fallback", mock.base),
            },
            store::open(":memory:"),
            Vault::from_secret("PUBLIC background refresh fixture seed").unwrap(),
        )
        .unwrap();
        state.management = ManagementUrls {
            billing_base: format!("{}/api/v1/zcode-plan", mock.base),
            quota_limit: format!("{}/api/monitor/usage/quota/limit", mock.base),
            subscription: format!("{}/api/biz/subscription/list", mock.base),
            oauth_token: format!("{}{TOKEN}", mock.base),
            app_version: "PUBLIC-background-version".into(),
        };
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

    fn install(&self, config: BackgroundRefreshConfig) -> Arc<BackgroundRefresh> {
        let manager = Arc::new(BackgroundRefresh::with_config(self.state.clone(), config));
        self.state
            .set_background_refresh(manager.clone())
            .expect("first manager installation must succeed");
        manager
    }

    fn account(&self, label: &str, jwt: &str) -> i64 {
        let view = AccountView {
            email: format!("{label}@example.invalid"),
            provider: "zai".into(),
            enabled: true,
            status: "exhausted".into(),
            remaining: 7.0,
            // The refresh core reads credentials from the mirror account, so
            // the seeded view must carry the jwt the DB insert stores.
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

    fn stored(&self, id: i64) -> (String, f64, String, i64) {
        self.state
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
            .unwrap()
    }

    fn mirror_remaining(&self, id: i64) -> f64 {
        self.state
            .accounts
            .lock()
            .unwrap()
            .iter()
            .find(|account| account.id == id)
            .unwrap()
            .remaining
    }

    fn row_exists(&self, id: i64) -> bool {
        self.state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM accounts WHERE id=?1)",
                [id],
                |row| row.get::<_, bool>(0),
            )
            .unwrap()
    }

    fn assert_refreshed(&self, id: i64, remaining: f64) {
        let (status, stored_remaining, tier, checked) = self.stored(id);
        assert_eq!(status, "active");
        assert_eq!(stored_remaining, remaining);
        assert_eq!(tier, "Pro");
        assert!(checked > 0, "quota commit must stamp last_checked_at");
        assert_eq!(
            self.mirror_remaining(id),
            remaining,
            "live mirror must agree with the persisted quota"
        );
    }
}

async fn settle(manager: &BackgroundRefresh) {
    tokio::time::timeout(DEADLINE, manager.wait_idle())
        .await
        .expect("background refresh must settle within the loopback test deadline");
}

async fn stop(manager: &BackgroundRefresh) -> BackgroundShutdownReport {
    tokio::time::timeout(Duration::from_secs(2), manager.shutdown())
        .await
        .expect("shutdown must respect the bounded shutdown_wait")
}

async fn enter(gate: &Gate, what: &str) {
    tokio::time::timeout(DEADLINE, gate.entered.notified())
        .await
        .expect(what);
}

#[test]
fn documented_default_config_is_public_and_exact() {
    let config = BackgroundRefreshConfig::default();
    assert_eq!(config.import_delay, Duration::from_millis(500));
    assert_eq!(config.oauth_delay, Duration::from_secs(1));
    assert_eq!(config.capacity, 2);
    assert_eq!(config.shutdown_wait, Duration::from_secs(5));
    let overridden = BackgroundRefreshConfig {
        import_delay: Duration::from_millis(20),
        ..Default::default()
    };
    assert_eq!(overridden.import_delay, Duration::from_millis(20));
}

#[test]
fn construction_outside_tokio_is_inert_and_refuses_enqueue() {
    let state = AppState::new(
        String::new(),
        UpstreamUrls {
            zai: "http://127.0.0.1:1/unused".into(),
            zai_fallback: "http://127.0.0.1:1/unused".into(),
        },
    );
    let manager = BackgroundRefresh::new(Arc::new(state));
    assert!(
        !manager.refresh_after_import(1),
        "enqueue outside Tokio must refuse, not panic"
    );
    assert!(!manager.refresh_after_oauth(1));
    assert!(manager.pending().is_empty());
    assert!(manager.executing().is_empty());
}

#[tokio::test]
async fn state_slot_holds_one_live_manager_and_a_dead_weak_is_replaceable() {
    let state = Arc::new(AppState::new(
        String::new(),
        UpstreamUrls {
            zai: "http://127.0.0.1:1/unused".into(),
            zai_fallback: "http://127.0.0.1:1/unused".into(),
        },
    ));
    assert!(state.background_refresh().is_none());
    let first = Arc::new(BackgroundRefresh::new(state.clone()));
    state.set_background_refresh(first.clone()).unwrap();
    assert!(Arc::ptr_eq(
        &state.background_refresh().expect("live manager upgrades"),
        &first
    ));
    assert!(
        state
            .set_background_refresh(Arc::new(BackgroundRefresh::new(state.clone())))
            .is_err(),
        "a live manager must not be replaced"
    );
    drop(first);
    assert!(
        state.background_refresh().is_none(),
        "dead Weak degrades to None, never wedges"
    );
    let second = Arc::new(BackgroundRefresh::new(state.clone()));
    state.set_background_refresh(second.clone()).unwrap();
    assert!(Arc::ptr_eq(
        &state.background_refresh().expect("replacement installed"),
        &second
    ));
}

#[tokio::test]
async fn missing_manager_leaves_paste_and_local_import_offline() {
    let mock = Mock::start().await;
    let files = LocalFiles::new();
    files.write_token(&jwt("PUBLIC-background-local-user", "v1"));
    let fixture = Fixture::new(&mock, Some(files.credentials()));
    let pasted = fixture
        .paste_import(&jwt("PUBLIC-background-paste-user", "v1"))
        .await;
    assert!(pasted["id"].as_i64().unwrap() > 0);
    let imported = fixture.local_import().await;
    assert!(imported["id"].as_i64().unwrap() > 0);
    mock.assert_seen(&[]);
    mock.assert_complete();
}

#[tokio::test]
async fn paste_import_refreshes_quota_after_delay_and_persists_it() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None);
    let manager = fixture.install(config(Duration::from_millis(50), PARKED, 2, DEADLINE));
    mock.push_billing(25.0);
    let secret = jwt("PUBLIC-background-paste-user", "v1");
    let pasted = fixture.paste_import(&secret).await;
    let id = pasted["id"].as_i64().unwrap();
    settle(&manager).await;
    mock.assert_seen(&[("GET", BILLING, format!("Bearer {secret}"))]);
    mock.assert_complete();
    fixture.assert_refreshed(id, 75.0);
}

#[tokio::test]
async fn local_import_refreshes_quota_after_delay_and_persists_it() {
    let mock = Mock::start().await;
    let files = LocalFiles::new();
    let token = jwt("PUBLIC-background-local-user", "v1");
    files.write_token(&token);
    let fixture = Fixture::new(&mock, Some(files.credentials()));
    let manager = fixture.install(config(Duration::from_millis(50), PARKED, 2, DEADLINE));
    mock.push_billing(25.0);
    let imported = fixture.local_import().await;
    let id = imported["id"].as_i64().unwrap();
    settle(&manager).await;
    mock.assert_seen(&[("GET", BILLING, format!("Bearer {token}"))]);
    mock.assert_complete();
    fixture.assert_refreshed(id, 75.0);
}

#[tokio::test]
async fn oauth_publish_refreshes_quota_on_the_oauth_delay() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None);
    // import_delay stays parked: settling within the deadline proves the
    // shared OAuth publish hook scheduled on oauth_delay, not import_delay.
    let manager = fixture.install(config(PARKED, Duration::from_millis(50), 2, DEADLINE));
    mock.push_token(json!({"code":200,"data":{"token":OAUTH_JWT}}));
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
    assert_eq!(completed["success"], true);
    let (status, ready) = fixture
        .request(
            "GET",
            &format!("/api/accounts/oauth/status?state={state}"),
            "",
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ready["status"], "ready");
    let id = ready["account_id"].as_i64().unwrap();
    settle(&manager).await;
    mock.assert_seen(&[
        ("POST", TOKEN, String::new()),
        ("GET", BILLING, format!("Bearer {OAUTH_JWT}")),
    ]);
    mock.assert_complete();
    fixture.assert_refreshed(id, 75.0);
}

#[tokio::test]
async fn duplicate_pending_enqueues_are_deduplicated_and_shutdown_cancels_the_delay() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None);
    let manager = fixture.install(config(PARKED, PARKED, 2, Duration::from_millis(100)));
    let id = fixture.account("duplicate", JWT_A);
    assert!(
        manager.refresh_after_import(id),
        "first admission queues the account"
    );
    assert!(
        !manager.refresh_after_import(id),
        "duplicate while pending is refused"
    );
    assert!(
        !manager.refresh_after_oauth(id),
        "cross-trigger dedup applies while pending"
    );
    assert_eq!(manager.pending(), vec![id]);
    assert!(manager.executing().is_empty());
    assert!(!manager.is_stopped());
    let report = stop(&manager).await;
    assert!(report.drained, "nothing was executing at shutdown");
    assert_eq!(report.cancelled, 1, "the delayed job is cancelled");
    assert!(report.abandoned.is_empty());
    assert!(manager.is_stopped());
    assert!(manager.pending().is_empty());
    assert!(
        !manager.refresh_after_import(id),
        "a stopped manager rejects new import triggers"
    );
    assert!(
        !manager.refresh_after_oauth(id),
        "a stopped manager rejects new oauth triggers"
    );
    mock.assert_seen(&[]);
    mock.assert_complete();
}

#[tokio::test]
async fn capacity_two_runs_two_gated_accounts_and_holds_the_third() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None);
    let manager = fixture.install(config(Duration::from_millis(20), PARKED, 2, DEADLINE));
    let a = fixture.account("capacity-a", JWT_A);
    let b = fixture.account("capacity-b", JWT_B);
    let c = fixture.account("capacity-c", JWT_C);
    let by_bearer: BTreeMap<String, i64> = [
        (format!("Bearer {JWT_A}"), a),
        (format!("Bearer {JWT_B}"), b),
        (format!("Bearer {JWT_C}"), c),
    ]
    .into();
    let gates: Vec<Arc<Gate>> = (0..3).map(|_| Arc::new(Gate::default())).collect();
    for gate in gates.iter() {
        mock.push_gated_billing(25.0, gate.clone());
    }
    for id in [a, b, c] {
        assert!(manager.refresh_after_import(id), "admission of {id}");
    }
    // Steps pop in arrival order, so the first two arrivals hold gates 0 and 1.
    enter(
        &gates[0],
        "first executor reaches the gated billing request",
    )
    .await;
    enter(
        &gates[1],
        "second executor reaches the gated billing request",
    )
    .await;
    let executing = manager.executing();
    assert_eq!(executing.len(), 2, "capacity admits exactly two executors");
    let arrived: BTreeSet<i64> = mock
        .authorizations()
        .iter()
        .map(|authorization| by_bearer[authorization.as_str()])
        .collect();
    assert_eq!(
        executing.iter().copied().collect::<BTreeSet<_>>(),
        arrived,
        "executing ids match the in-flight requests"
    );
    let held_back: Vec<i64> = [a, b, c]
        .into_iter()
        .filter(|id| !arrived.contains(id))
        .collect();
    assert_eq!(held_back.len(), 1);
    assert_eq!(manager.pending(), held_back, "the third account waits");
    gates[0].release.notify_one();
    gates[1].release.notify_one();
    enter(&gates[2], "released capacity admits the third account").await;
    assert!(
        manager.executing().contains(&held_back[0]),
        "the third account now executes"
    );
    assert!(manager.pending().is_empty());
    gates[2].release.notify_one();
    settle(&manager).await;
    mock.assert_seen_billing_set(&[
        format!("Bearer {JWT_A}"),
        format!("Bearer {JWT_B}"),
        format!("Bearer {JWT_C}"),
    ]);
    mock.assert_complete();
    for id in [a, b, c] {
        fixture.assert_refreshed(id, 75.0);
    }
}

#[tokio::test]
async fn reimport_during_execution_runs_one_followup_with_latest_credentials() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None);
    let manager = fixture.install(config(Duration::from_millis(20), PARKED, 2, DEADLINE));
    let gate = Arc::new(Gate::default());
    mock.push_gated_billing(25.0, gate.clone());
    let user = "PUBLIC-background-followup-user";
    let first_secret = jwt(user, "v1");
    let id = fixture.paste_import(&first_secret).await["id"]
        .as_i64()
        .unwrap();
    enter(&gate, "first execution reaches the gated billing request").await;
    assert_eq!(
        mock.count(),
        1,
        "no second same-account request may overlap the held execution"
    );
    let second_secret = jwt(user, "v2");
    let reimported = fixture.paste_import(&second_secret).await;
    assert_eq!(reimported["id"], id, "reimport upserts the same account");
    mock.push_billing(10.0);
    gate.release.notify_one();
    settle(&manager).await;
    mock.assert_seen(&[
        ("GET", BILLING, format!("Bearer {first_secret}")),
        ("GET", BILLING, format!("Bearer {second_secret}")),
    ]);
    mock.assert_complete();
    fixture.assert_refreshed(id, 90.0);
}

#[tokio::test]
async fn pending_job_reads_latest_credentials_at_execution_time() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None);
    let manager = fixture.install(config(Duration::from_millis(1200), PARKED, 2, DEADLINE));
    let user = "PUBLIC-background-latest-user";
    let id = fixture.paste_import(&jwt(user, "old")).await["id"]
        .as_i64()
        .unwrap();
    assert!(
        manager.executing().is_empty(),
        "the delay must hold execution while the credential is replaced"
    );
    let replacement = jwt(user, "new");
    let reimported = fixture.paste_import(&replacement).await;
    assert_eq!(reimported["id"], id);
    mock.push_billing(25.0);
    settle(&manager).await;
    mock.assert_seen(&[("GET", BILLING, format!("Bearer {replacement}"))]);
    mock.assert_complete();
    fixture.assert_refreshed(id, 75.0);
}

#[tokio::test]
async fn deleted_and_disabled_accounts_are_skipped_at_execution_without_traffic() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None);
    let manager = fixture.install(config(Duration::from_millis(20), PARKED, 2, DEADLINE));
    let deleted = fixture.account("skipped-deleted", JWT_A);
    let disabled = fixture.account("skipped-disabled", JWT_B);
    let live = fixture.account("skipped-live", JWT_C);
    fixture.delete_account(deleted).await;
    fixture.disable_account(disabled).await;
    mock.push_billing(25.0);
    let _ = manager.refresh_after_import(deleted);
    let _ = manager.refresh_after_import(disabled);
    assert!(
        manager.refresh_after_import(live),
        "a live account still admits"
    );
    settle(&manager).await;
    mock.assert_seen(&[("GET", BILLING, format!("Bearer {JWT_C}"))]);
    mock.assert_complete();
    assert!(!fixture.row_exists(deleted));
    let (status, remaining, tier, checked) = fixture.stored(disabled);
    assert_eq!(
        (status.as_str(), remaining, tier.as_str(), checked),
        ("disabled", 7.0, "", 0),
        "a disabled account keeps its prior snapshot"
    );
    fixture.assert_refreshed(live, 75.0);
}

#[tokio::test]
async fn failed_imports_never_enqueue_a_refresh() {
    let mock = Mock::start().await;
    let files = LocalFiles::new(); // no credentials.json: local import fails
    let fixture = Fixture::new(&mock, Some(files.credentials()));
    let manager = fixture.install(config(PARKED, PARKED, 2, Duration::from_millis(100)));
    let (status, body) = fixture
        .request("POST", "/api/accounts/import/paste", r#"{"secret":"  "}"#)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "paste rejects: {body}");
    let (status, body) = fixture
        .request("POST", "/api/accounts/import/local", "{}")
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "local rejects: {body}");
    assert!(
        manager.pending().is_empty(),
        "failed imports must not enqueue anything"
    );
    assert!(manager.executing().is_empty());
    mock.assert_seen(&[]);
    mock.assert_complete();
    let report = stop(&manager).await;
    assert!(report.drained);
    assert_eq!(report.cancelled, 0);
}

#[tokio::test]
async fn bundle_and_plain_add_do_not_enqueue_refreshes() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None);
    // The manager must outlive the imports so a live hook could have fired.
    let _manager = fixture.install(config(PARKED, PARKED, 2, Duration::from_millis(100)));
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
    let jwt_cipher = fixture.state.vault.encrypt(JWT_A).unwrap();
    let key_cipher = fixture.state.vault.encrypt(JWT_B).unwrap();
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
        _manager.pending().is_empty(),
        "bundle and plain-add paths carry no refresh hook"
    );
    mock.assert_seen(&[]);
    mock.assert_complete();
}

#[tokio::test]
async fn pending_queue_is_bounded_to_256_distinct_accounts() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None);
    let manager = fixture.install(config(PARKED, PARKED, 2, Duration::from_millis(100)));
    for id in 1..=256 {
        assert!(
            manager.refresh_after_import(id),
            "admission within the bound: {id}"
        );
    }
    assert!(
        !manager.refresh_after_import(257),
        "a full queue refuses new accounts"
    );
    assert!(
        !manager.refresh_after_oauth(258),
        "a full queue refuses oauth triggers"
    );
    assert!(
        !manager.refresh_after_import(7),
        "duplicates are still refused at the bound"
    );
    assert_eq!(manager.pending(), (1..=256).collect::<Vec<i64>>());
    assert!(manager.executing().is_empty());
    let report = stop(&manager).await;
    assert!(report.drained);
    assert_eq!(report.cancelled, 256);
    assert!(report.abandoned.is_empty());
    mock.assert_seen(&[]);
    mock.assert_complete();
}

#[tokio::test]
async fn shutdown_timeout_reports_abandoned_and_wait_idle_joins_the_release() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None);
    let manager = fixture.install(config(
        Duration::from_millis(20),
        PARKED,
        1,
        Duration::from_millis(200),
    ));
    let held = fixture.account("shutdown-held", JWT_A);
    let cancelled = fixture.account("shutdown-cancelled", JWT_B);
    let gate = Arc::new(Gate::default());
    mock.push_gated_billing(25.0, gate.clone());
    assert!(manager.refresh_after_import(held));
    enter(&gate, "the executor reaches the held billing request").await;
    assert!(
        manager.refresh_after_import(cancelled),
        "the second account queues behind capacity 1"
    );
    let report = stop(&manager).await;
    assert!(
        !report.drained,
        "a timed-out execution must never be reported drained"
    );
    assert_eq!(report.abandoned, vec![held]);
    assert_eq!(
        report.cancelled, 1,
        "the capacity-waiting job is cancelled, not abandoned"
    );
    assert!(manager.is_stopped());
    assert!(manager.pending().is_empty());
    gate.release.notify_one();
    tokio::time::timeout(DEADLINE, manager.wait_idle())
        .await
        .expect("wait_idle joins the retained execution after the release");
    mock.assert_seen(&[("GET", BILLING, format!("Bearer {JWT_A}"))]);
    mock.assert_complete();
    fixture.assert_refreshed(held, 75.0);
}

#[tokio::test]
async fn capacity_zero_normalizes_to_a_single_executor() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None);
    let manager = fixture.install(config(Duration::from_millis(20), PARKED, 0, DEADLINE));
    let a = fixture.account("normalized-a", JWT_A);
    let b = fixture.account("normalized-b", JWT_B);
    let gates: Vec<Arc<Gate>> = (0..2).map(|_| Arc::new(Gate::default())).collect();
    mock.push_gated_billing(25.0, gates[0].clone());
    mock.push_gated_billing(25.0, gates[1].clone());
    assert!(manager.refresh_after_import(a));
    assert!(manager.refresh_after_import(b));
    enter(&gates[0], "the normalized single executor starts").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        manager.executing().len(),
        1,
        "capacity 0 must normalize to one executor, not zero or two"
    );
    assert_eq!(manager.pending().len(), 1);
    gates[0].release.notify_one();
    enter(
        &gates[1],
        "the second account runs after the first releases",
    )
    .await;
    gates[1].release.notify_one();
    settle(&manager).await;
    mock.assert_seen_billing_set(&[format!("Bearer {JWT_A}"), format!("Bearer {JWT_B}")]);
    mock.assert_complete();
}

#[tokio::test]
async fn dropping_the_manager_cancels_waiting_work() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, None);
    let manager = fixture.install(config(Duration::from_millis(400), PARKED, 2, DEADLINE));
    let id = fixture.account("dropped", JWT_A);
    assert!(manager.refresh_after_import(id));
    drop(manager);
    assert!(
        fixture.state.background_refresh().is_none(),
        "a dropped manager degrades the slot"
    );
    tokio::time::sleep(Duration::from_millis(900)).await;
    mock.assert_seen(&[]);
    mock.assert_complete();
}
