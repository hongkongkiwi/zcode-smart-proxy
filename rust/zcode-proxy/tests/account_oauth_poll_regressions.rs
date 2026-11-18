use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json, Router,
};
use serde_json::{json, Value};
use tokio::sync::Notify;
use tower::ServiceExt;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, PollOAuthUrls, UpstreamUrls},
    store,
    vault::Vault,
};

const SESSION: &str = "PUBLIC-poll-session";
const JWT: &str = "PUBLIC-poll-coding-plan-jwt";
const ACCESS: &str = "PUBLIC-poll-access-token";
const REFRESH: &str = "PUBLIC-poll-refresh-token";
const BIZ: &str = "PUBLIC-poll-business-token";
const KEY_ID: &str = "PUBLIC-poll-key";
const SECRET: &str = "PUBLIC-poll-secret";
const KEY: &str = "PUBLIC-poll-key.PUBLIC-poll-secret";
const FLOW: &str = "PUBLIC-poll-flow";
const INIT: &str = "/api/v1/oauth/cli/init";
const POLL: &str = "/api/v1/oauth/cli/poll/PUBLIC-poll-flow";
const TOKEN: &str = "/api/v1/oauth/token";
const USERINFO: &str = "/api/oauth/userinfo";
const LOGIN: &str = "/api/auth/z/login";
const CUSTOMER: &str = "/api/biz/customer/getCustomerInfo";
const KEYS: &str = "/api/biz/v1/organization/17/projects/23/api_keys";
const COPY: &str = "/api/biz/v1/organization/17/projects/23/api_keys/copy/PUBLIC-poll-key";
const INTERVAL: Duration = Duration::from_millis(20);
const DEADLINE: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    query: Option<String>,
    authorization: String,
    content_type: String,
    body: Value,
}

#[derive(Default)]
struct Gate {
    entered: Notify,
    release: Notify,
}

struct Step {
    status: StatusCode,
    body: String,
    location: Option<String>,
    gate: Option<Arc<Gate>>,
}

impl Step {
    fn json(status: StatusCode, body: Value) -> Self {
        Self {
            status,
            body: body.to_string(),
            location: None,
            gate: None,
        }
    }

    fn pending() -> Self {
        Self::json(
            StatusCode::OK,
            json!({"code":0,"data":{"status":"pending"}}),
        )
    }

    fn ready() -> Self {
        Self::json(
            StatusCode::OK,
            json!({"code":0,"data":{"status":"ready","token":JWT,
                "zai":{"accessToken":ACCESS,"refresh_token":REFRESH}}}),
        )
    }

    async fn response(self) -> Response {
        if let Some(gate) = self.gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        let mut response = (self.status, self.body).into_response();
        response
            .headers_mut()
            .insert("content-type", "application/json".parse().unwrap());
        if let Some(location) = self.location {
            response
                .headers_mut()
                .insert("location", location.parse().unwrap());
        }
        response
    }
}

struct Script {
    init: Mutex<Option<Step>>,
    polls: Mutex<VecDeque<Step>>,
    seen: Mutex<Vec<Seen>>,
    reject_business: bool,
}

struct Mock {
    base: String,
    script: Arc<Script>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn init_data() -> Value {
    json!({"flow_id":FLOW,
        "authorize_url":"https://chat.z.ai/api/oauth/authorize?public=kept",
        "expires_at":now_secs()+60,"poll_interval_sec":2})
}

fn init_step(data: Value) -> Step {
    Step::json(StatusCode::OK, json!({"code":0,"data":data}))
}

impl Mock {
    async fn start(init: Step, polls: Vec<Step>, reject_business: bool) -> Self {
        async fn serve(State(script): State<Arc<Script>>, request: Request) -> Response {
            let (parts, body) = request.into_parts();
            let bytes = to_bytes(body, 1 << 20).await.unwrap();
            let path = parts.uri.path().to_owned();
            script.seen.lock().unwrap().push(Seen {
                method: parts.method.to_string(),
                path: path.clone(),
                query: parts.uri.query().map(str::to_owned),
                authorization: parts
                    .headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("")
                    .into(),
                content_type: parts
                    .headers
                    .get("content-type")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("")
                    .into(),
                body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            });
            let step = match path.as_str() {
                INIT => Some(script.init.lock().unwrap().take().unwrap_or_else(|| {
                    Step::json(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({"error":"extra init"}),
                    )
                })),
                POLL => Some(
                    script
                        .polls
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or_else(Step::pending),
                ),
                _ => None,
            };
            if let Some(step) = step {
                return step.response().await;
            }
            let body = match path.as_str() {
                USERINFO => {
                    json!({"data":{"user_id":"PUBLIC-poll-user","email":"poll@example.invalid","nickName":"Poll fixture"}})
                }
                LOGIN if script.reject_business => {
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(json!({"message":format!("{ACCESS} {BIZ}")})),
                    )
                        .into_response();
                }
                LOGIN => json!({"data":{"access_token":BIZ}}),
                CUSTOMER => {
                    json!({"data":{"organizations":[{"organizationId":17,"organizationName":"默认机构","projects":[{"projectId":23,"projectName":"默认项目"}]}]}})
                }
                KEYS => json!({"data":[{"name":"zcode-api-key","apiKey":KEY_ID}]}),
                COPY => json!({"data":{"secretKey":SECRET}}),
                _ => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error":"unexpected poll upstream path"})),
                    )
                        .into_response()
                }
            };
            Json(body).into_response()
        }
        let script = Arc::new(Script {
            init: Mutex::new(Some(init)),
            polls: Mutex::new(polls.into()),
            seen: Mutex::new(Vec::new()),
            reject_business,
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(serve).with_state(script.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            base,
            script,
            server,
        }
    }

    fn paths(&self) -> Vec<String> {
        self.script
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.path.clone())
            .collect()
    }

    async fn assert_stopped(&self) {
        let before = self.paths();
        tokio::time::sleep(INTERVAL * 4).await;
        assert_eq!(
            self.paths(),
            before,
            "terminal poll flow kept making upstream requests"
        );
    }

    fn assert_poll_wire(&self) {
        let seen = self.script.seen.lock().unwrap();
        let init = &seen[0];
        assert_eq!(init.path, INIT);
        assert_eq!(init.method, "POST");
        assert_eq!(init.body, json!({"provider":"zai"}));
        assert!(init.content_type.starts_with("application/json"));
        let token = init.authorization.strip_prefix("Bearer ").unwrap();
        assert_eq!(
            token.len(),
            64,
            "Go poll bearer is 32 random bytes encoded as hex"
        );
        assert!(token.bytes().all(|b| b.is_ascii_hexdigit()));
        for request in seen.iter() {
            assert_eq!(
                request.query, None,
                "credentials must not enter upstream queries"
            );
            if request.path == POLL {
                assert_eq!(request.method, "GET");
                assert_eq!(request.authorization, init.authorization);
                assert_eq!(request.body, Value::Null);
            }
        }
    }
}

struct Reply {
    status: StatusCode,
    json: Value,
    raw: String,
}

struct Fixture {
    state: Arc<AppState>,
    script: Arc<Script>,
}

impl Fixture {
    fn new(mock: &Mock, ttl: Duration) -> Self {
        let mut state = AppState::try_from_db_with_vault(
            String::new(),
            UpstreamUrls {
                zai: format!("{}/unused-relay", mock.base),
                zai_fallback: format!("{}/unused-fallback", mock.base),
            },
            store::open(":memory:"),
            Vault::from_secret("PUBLIC poll OAuth vault seed").unwrap(),
        )
        .unwrap();
        state.oauth_poll = PollOAuthUrls {
            init: format!("{}{INIT}", mock.base),
            poll_base: format!("{}/api/v1/oauth/cli/poll", mock.base),
            interval_override: Some(INTERVAL),
            flow_ttl: ttl,
        };
        state.oauth.userinfo = format!("{}{USERINFO}", mock.base);
        state.oauth.business_login = format!("{}{LOGIN}", mock.base);
        state.oauth.customer_info = format!("{}{CUSTOMER}", mock.base);
        state.oauth.project_keys_base = format!("{}/api/biz/v1/organization", mock.base);
        state.management.oauth_token = format!("{}{TOKEN}", mock.base);
        state.management.app_version = "PUBLIC-poll-version".into();
        state.management.billing_base = format!("{}/unused-billing", mock.base);
        state.management.quota_limit = format!("{}/unused-quota", mock.base);
        state.management.subscription = format!("{}/unused-subscription", mock.base);
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        Self {
            state: Arc::new(state),
            script: mock.script.clone(),
        }
    }

    async fn request(&self, method: &str, path: &str, body: Value) -> Reply {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost:8787")
            .header("origin", "http://localhost:8787")
            .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response =
            tokio::time::timeout(DEADLINE, build_router(self.state.clone()).oneshot(request))
                .await
                .expect("loopback poll management request deadline")
                .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        let raw = String::from_utf8(bytes.to_vec()).unwrap();
        let mut secrets = vec![
            JWT.to_owned(),
            ACCESS.into(),
            REFRESH.into(),
            BIZ.into(),
            KEY.into(),
            SECRET.into(),
            "vault1:".into(),
        ];
        secrets.extend(
            self.script
                .seen
                .lock()
                .unwrap()
                .iter()
                .filter_map(|s| s.authorization.strip_prefix("Bearer ").map(str::to_owned)),
        );
        for secret in secrets {
            assert!(
                !raw.contains(&secret),
                "poll management response leaked credentials"
            );
            assert!(
                headers
                    .values()
                    .all(|h| !h.to_str().unwrap_or("").contains(&secret)),
                "poll management header leaked credentials"
            );
        }
        Reply {
            status,
            json: serde_json::from_str(&raw).unwrap_or(Value::Null),
            raw,
        }
    }

    async fn start(&self) -> Reply {
        self.request(
            "POST",
            "/api/accounts/oauth/start",
            json!({"poll":true,"group":"Poll group"}),
        )
        .await
    }

    async fn started(&self) -> Value {
        let reply = self.start().await;
        assert_eq!(reply.status, StatusCode::OK, "poll start: {}", reply.raw);
        assert_eq!(reply.json["poll"], true);
        assert_eq!(reply.json["state"], FLOW);
        reply.json
    }

    async fn status(&self) -> Reply {
        self.request(
            "GET",
            &format!("/api/accounts/oauth/status?state={FLOW}"),
            Value::Null,
        )
        .await
    }

    async fn terminal(&self) -> Reply {
        tokio::time::timeout(DEADLINE, async {
            loop {
                let reply = self.status().await;
                if reply.status == StatusCode::NOT_FOUND
                    || matches!(reply.json["status"].as_str(), Some("ready" | "failed"))
                {
                    return reply;
                }
                assert_eq!(reply.status, StatusCode::OK, "status: {}", reply.raw);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("poll flow must reach a terminal result within its injected budget")
    }

    async fn replay(&self) {
        let manual = self
            .request(
                "POST",
                "/api/accounts/oauth/manual",
                json!({"state":FLOW,"input":"PUBLIC-poll-replay-code"}),
            )
            .await;
        assert_eq!(manual.status, StatusCode::BAD_REQUEST);
        let callback = self
            .request(
                "GET",
                &format!("/oauth/callback?state={FLOW}&code=PUBLIC-poll-replay-code"),
                Value::Null,
            )
            .await;
        assert_eq!(callback.status, StatusCode::OK);
    }

    fn assert_empty(&self) {
        assert!(
            store::load_bundle_accounts(&self.state.db.lock().unwrap(), &self.state.vault)
                .unwrap()
                .is_empty()
        );
        assert!(self.state.accounts.lock().unwrap().is_empty());
        assert!(self.state.creds.lock().unwrap().is_empty());
    }

    fn assert_account(&self, id: i64, key: &str) {
        let rows =
            store::load_bundle_accounts(&self.state.db.lock().unwrap(), &self.state.vault).unwrap();
        assert_eq!(rows.len(), 1);
        let (stored_id, account) = &rows[0];
        assert_eq!(*stored_id, id);
        assert_eq!(account.user_id, "PUBLIC-poll-user");
        assert_eq!(account.email, "poll@example.invalid");
        assert_eq!(account.display_name, "Poll fixture");
        assert_eq!(account.provider, "zai");
        assert_eq!(account.auth_type, "jwt");
        assert_eq!(account.account_group, "Poll group");
        assert_eq!(account.zcode_jwt, JWT);
        assert_eq!(account.access_token, ACCESS);
        assert_eq!(account.refresh_token, REFRESH);
        assert_eq!(account.api_key, key);
        let live = self.state.accounts.lock().unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].id, id);
        assert_eq!(live[0].email, account.email);
        assert_eq!(live[0].account_group, "Poll group");
        assert_eq!(live[0].status, "active");
        assert!(live[0].enabled);
        assert_eq!(live[0].zcode_jwt, JWT);
        assert_eq!(live[0].api_key, key);
        let creds = self.state.creds.lock().unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[&id].zcode_jwt, JWT);
        assert_eq!(creds[&id].api_key, key);
        let raw: Vec<String> = self.state.db.lock().unwrap().query_row(
            "SELECT access_token,refresh_token,zcode_jwt,api_key,user_info FROM accounts WHERE id=?1", [id],
            |row| (0..5).map(|i| row.get(i)).collect(),
        ).unwrap();
        for (cipher, plain) in
            raw.iter()
                .zip([ACCESS, REFRESH, JWT, key, account.user_info.as_str()])
        {
            assert_eq!(self.state.vault.decrypt(cipher).unwrap(), plain);
            if !plain.is_empty() {
                assert!(cipher.starts_with("vault1:"));
                assert!(
                    !cipher.contains(plain),
                    "poll credentials must be encrypted at rest"
                );
            }
        }
    }
}

async fn entered(gate: &Gate) {
    tokio::time::timeout(DEADLINE, gate.entered.notified())
        .await
        .expect("poll reached loopback gate");
}

#[tokio::test]
async fn poll_start_uses_go_init_wire_and_validates_https_authorization_envelope() {
    let gate = Arc::new(Gate::default());
    let mut pending = Step::pending();
    pending.gate = Some(gate.clone());
    let mock = Mock::start(
        init_step(init_data()),
        vec![pending, Step::json(StatusCode::BAD_REQUEST, json!({}))],
        false,
    )
    .await;
    let fixture = Fixture::new(&mock, Duration::from_secs(3));
    let started = fixture.started().await;
    entered(&gate).await;
    let authorize = reqwest::Url::parse(started["authorize_url"].as_str().unwrap()).unwrap();
    assert_eq!(authorize.scheme(), "https");
    assert_eq!(authorize.host_str(), Some("chat.z.ai"));
    let query: std::collections::BTreeMap<_, _> = authorize.query_pairs().into_owned().collect();
    assert_eq!(query["public"], "kept");
    let redirect = reqwest::Url::parse(&query["redirect_uri"]).unwrap();
    assert_eq!(
        redirect.as_str().split('?').next().unwrap(),
        "https://zcode.z.ai/app/oauth/login"
    );
    let redirect_query: std::collections::BTreeMap<_, _> =
        redirect.query_pairs().into_owned().collect();
    assert_eq!(redirect_query["redirect"], "zcode://oauth/callback");
    assert_eq!(redirect_query["app_version"], "PUBLIC-poll-version");
    assert_eq!(fixture.status().await.json["status"], "pending");
    fixture.assert_empty();
    gate.release.notify_one();
    assert_eq!(fixture.terminal().await.json["status"], "failed");
    mock.assert_poll_wire();
    mock.assert_stopped().await;

    let mut cases = Vec::new();
    for authorize in [
        "http://chat.z.ai/authorize",
        "javascript:alert(1)",
        "/relative",
        "https:///",
        "",
    ] {
        let mut data = init_data();
        data["authorize_url"] = json!(authorize);
        cases.push((format!("authorize {authorize}"), init_step(data)));
    }
    let mut missing_flow = init_data();
    missing_flow.as_object_mut().unwrap().remove("flow_id");
    cases.push(("missing flow_id".into(), init_step(missing_flow)));
    for code in [json!(200), json!("0"), Value::Null] {
        cases.push((
            format!("invalid init code {code}"),
            Step::json(StatusCode::OK, json!({"code":code,"data":init_data()})),
        ));
    }
    cases.push((
        "missing init code".into(),
        Step::json(StatusCode::OK, json!({"data":init_data()})),
    ));
    cases.push((
        "missing init data".into(),
        Step::json(StatusCode::OK, json!({"code":0})),
    ));
    let mut oversized = init_step(init_data());
    oversized.body = format!("{}{}", " ".repeat(1 << 20), oversized.body);
    cases.push(("init response exceeds Go 1MiB cap".into(), oversized));
    for (label, step) in cases {
        let mock = Mock::start(step, vec![], false).await;
        let fixture = Fixture::new(&mock, Duration::from_secs(3));
        let reply = fixture.start().await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_GATEWAY,
            "{label}: {}",
            reply.raw
        );
        assert_eq!(
            fixture.status().await.status,
            StatusCode::NOT_FOUND,
            "{label}"
        );
        assert_eq!(
            mock.paths(),
            [INIT],
            "invalid init must not start polling: {label}"
        );
        fixture.assert_empty();
        mock.assert_poll_wire();
    }
}

#[tokio::test]
async fn poll_pending_then_ready_uses_shared_ingest_and_publishes_credentials_only_after_commit() {
    for scenario in ["success", "storage failure", "optional key failure"] {
        let gate = Arc::new(Gate::default());
        let mut ready = Step::ready();
        ready.gate = Some(gate.clone());
        let mock = Mock::start(
            init_step(init_data()),
            vec![Step::pending(), ready],
            scenario == "optional key failure",
        )
        .await;
        let fixture = Fixture::new(&mock, Duration::from_secs(3));
        if scenario == "storage failure" {
            fixture.state.db.lock().unwrap().execute_batch(
                "CREATE TRIGGER reject_poll_insert BEFORE INSERT ON accounts BEGIN SELECT RAISE(FAIL, 'PUBLIC forced poll storage failure'); END;",
            ).unwrap();
        }
        fixture.started().await;
        entered(&gate).await;
        assert_eq!(fixture.status().await.json["status"], "pending");
        fixture.assert_empty();
        gate.release.notify_one();
        let terminal = fixture.terminal().await;
        assert_eq!(
            terminal.status,
            StatusCode::OK,
            "{scenario}: {}",
            terminal.raw
        );
        if scenario == "storage failure" {
            assert_eq!(terminal.json["status"], "failed");
            fixture.assert_empty();
        } else {
            assert_eq!(terminal.json["status"], "ready", "{scenario}");
            assert_eq!(terminal.json["email"], "poll@example.invalid");
            let id = terminal.json["account_id"]
                .as_i64()
                .filter(|id| *id > 0)
                .unwrap();
            fixture.assert_account(id, if scenario == "success" { KEY } else { "" });
            let before = mock.paths();
            fixture.replay().await;
            assert_eq!(fixture.status().await.json["status"], "ready");
            assert_eq!(fixture.status().await.json["account_id"], id);
            assert_eq!(
                mock.paths(),
                before,
                "completed poll capability was replayed"
            );
        }
        let expected = if scenario == "optional key failure" {
            vec![INIT, POLL, POLL, USERINFO, LOGIN]
        } else {
            vec![INIT, POLL, POLL, USERINFO, LOGIN, CUSTOMER, KEYS, COPY]
        };
        assert_eq!(
            mock.paths(),
            expected,
            "{scenario}: poll ready must not exchange an authorization code"
        );
        mock.assert_poll_wire();
        for request in mock
            .script
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.path != INIT && s.path != POLL)
        {
            if request.path == LOGIN {
                assert_eq!(request.method, "POST");
                assert_eq!(request.body, json!({"token":ACCESS}));
                assert!(request.authorization.is_empty());
            } else {
                assert_eq!(request.method, "GET");
                assert_eq!(
                    request.authorization,
                    format!(
                        "Bearer {}",
                        if request.path == USERINFO {
                            ACCESS
                        } else {
                            BIZ
                        }
                    )
                );
            }
        }
        mock.assert_stopped().await;
    }
}

#[tokio::test]
async fn poll_retries_408_429_and_5xx_but_stops_on_fatal_http_envelopes_and_redirects() {
    let transient = [
        StatusCode::REQUEST_TIMEOUT,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::BAD_GATEWAY,
        StatusCode::SERVICE_UNAVAILABLE,
    ];
    let mut steps: Vec<_> = transient
        .iter()
        .map(|status| Step::json(*status, json!({"code":99,"message":ACCESS})))
        .collect();
    steps.push(Step::pending());
    steps.push(Step::ready());
    let mock = Mock::start(init_step(init_data()), steps, false).await;
    let fixture = Fixture::new(&mock, Duration::from_secs(3));
    fixture.started().await;
    let ready = fixture.terminal().await;
    assert_eq!(
        ready.json["status"], "ready",
        "transient statuses must not fail a valid flow"
    );
    assert_eq!(
        mock.paths().iter().filter(|path| *path == POLL).count(),
        transient.len() + 2
    );
    fixture.assert_account(ready.json["account_id"].as_i64().unwrap(), KEY);
    mock.assert_stopped().await;

    let mut fatal = Vec::new();
    for status in [
        StatusCode::BAD_REQUEST,
        StatusCode::UNAUTHORIZED,
        StatusCode::FORBIDDEN,
        StatusCode::NOT_FOUND,
        StatusCode::GONE,
    ] {
        fatal.push((
            format!("HTTP {status}"),
            Step::json(
                status,
                json!({"message":format!("{ACCESS} {REFRESH} {BIZ}")}),
            ),
        ));
    }
    for status in [StatusCode::FOUND, StatusCode::TEMPORARY_REDIRECT] {
        let mut redirect = Step::ready();
        redirect.status = status;
        redirect.location = Some("/capture-poll-bearer".into());
        fatal.push((format!("redirect {status}"), redirect));
    }
    for (label, body) in [
        (
            "business failure",
            json!({"code":200,"data":{"status":"pending"},"msg":ACCESS}),
        ),
        ("missing data", json!({"code":0})),
        (
            "unknown status",
            json!({"code":0,"data":{"status":"waiting"}}),
        ),
        (
            "provider failure",
            json!({"code":0,"data":{"status":"failed"}}),
        ),
        (
            "ready without JWT",
            json!({"code":0,"data":{"status":"ready","zai":{"access_token":ACCESS}}}),
        ),
    ] {
        fatal.push((label.into(), Step::json(StatusCode::OK, body)));
    }
    let mut malformed = Step::pending();
    malformed.body = "<html>PUBLIC WAF challenge</html>".into();
    fatal.push(("malformed 200".into(), malformed));
    let mut oversized = Step::pending();
    oversized.body = format!("{}{}", " ".repeat(1 << 20), oversized.body);
    fatal.push(("poll response exceeds Go 1MiB cap".into(), oversized));
    for (label, step) in fatal {
        let mock = Mock::start(init_step(init_data()), vec![step, Step::ready()], false).await;
        let fixture = Fixture::new(&mock, Duration::from_secs(3));
        fixture.started().await;
        let failed = fixture.terminal().await;
        assert_eq!(failed.json["status"], "failed", "{label}: {}", failed.raw);
        fixture.assert_empty();
        assert_eq!(
            mock.paths(),
            [INIT, POLL],
            "fatal result must stop before a later ready response: {label}"
        );
        mock.assert_poll_wire();
        mock.assert_stopped().await;
    }
}

#[tokio::test]
async fn poll_expiry_and_owner_cancellation_bound_workers_and_block_late_ready_or_replay() {
    let ttl = Duration::from_millis(120);
    for inflight_ready in [false, true] {
        let gate = Arc::new(Gate::default());
        let polls = if inflight_ready {
            let mut step = Step::ready();
            step.gate = Some(gate.clone());
            vec![step]
        } else {
            vec![]
        };
        let mock = Mock::start(init_step(init_data()), polls, false).await;
        let fixture = Fixture::new(&mock, ttl);
        fixture.started().await;
        if inflight_ready {
            entered(&gate).await;
        }
        let expired = fixture.terminal().await;
        assert!(
            expired.status == StatusCode::NOT_FOUND || expired.json["status"] == "failed",
            "expired poll flow must not remain active"
        );
        gate.release.notify_one();
        mock.assert_stopped().await;
        fixture.assert_empty();
        let before = mock.paths();
        fixture.replay().await;
        fixture.assert_empty();
        assert_eq!(
            mock.paths(),
            before,
            "expired flow replay made an upstream request"
        );
        let weak = Arc::downgrade(&fixture.state);
        drop(fixture);
        tokio::time::timeout(DEADLINE, async {
            while weak.upgrade().is_some() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("expired worker retained application state");
    }

    let mut data = init_data();
    data["expires_at"] = json!(now_secs() - 1);
    let mock = Mock::start(init_step(data), vec![Step::ready()], false).await;
    let fixture = Fixture::new(&mock, Duration::from_secs(3));
    fixture.started().await;
    let expired = fixture.terminal().await;
    assert!(expired.status == StatusCode::NOT_FOUND || expired.json["status"] == "failed");
    assert_eq!(
        mock.paths(),
        [INIT],
        "upstream expires_at must shorten the local budget before the first poll"
    );
    fixture.assert_empty();
    mock.assert_stopped().await;

    let gate = Arc::new(Gate::default());
    let mut pending = Step::pending();
    pending.gate = Some(gate.clone());
    let mock = Mock::start(init_step(init_data()), vec![pending], false).await;
    let fixture = Fixture::new(&mock, ttl);
    fixture.started().await;
    entered(&gate).await;
    let weak = Arc::downgrade(&fixture.state);
    drop(fixture);
    tokio::time::timeout(DEADLINE, async {
        while weak.upgrade().is_some() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("abandoned poll worker must release state without waiting for a stalled upstream");
    gate.release.notify_one();
    mock.assert_stopped().await;
}
