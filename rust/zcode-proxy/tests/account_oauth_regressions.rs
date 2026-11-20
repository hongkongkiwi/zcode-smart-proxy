use std::{
    collections::VecDeque,
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
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, OAuthUrls, UpstreamUrls},
    store,
    vault::Vault,
};

const SESSION: &str = "PUBLIC-oauth-wire-session";
const CODE: &str = "PUBLIC-oauth-authorization-code";
const JWT: &str = "PUBLIC-oauth-coding-plan-jwt";
const ACCESS: &str = "PUBLIC-oauth-access-token";
const REFRESH: &str = "PUBLIC-oauth-refresh-token";
const BIZ: &str = "PUBLIC-oauth-business-token";
const KEY_ID: &str = "PUBLIC-oauth-api-key";
const KEY_SECRET: &str = "PUBLIC-oauth-secret-key";
const KEY: &str = "PUBLIC-oauth-api-key.PUBLIC-oauth-secret-key";
const START: &str = "/api/accounts/oauth/start";
const MANUAL: &str = "/api/accounts/oauth/manual";
const TOKEN: &str = "/api/v1/oauth/token";
const USERINFO: &str = "/api/oauth/userinfo";
const LOGIN: &str = "/api/auth/z/login";
const CUSTOMER: &str = "/api/biz/customer/getCustomerInfo";
const KEYS: &str = "/api/biz/v1/organization/17/projects/23/api_keys";
const COPY: &str = "/api/biz/v1/organization/17/projects/23/api_keys/copy/PUBLIC-oauth-api-key";

#[derive(Debug)]
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

struct TokenStep {
    status: StatusCode,
    body: Value,
    location: Option<String>,
    gate: Option<Arc<Gate>>,
}

#[derive(Default)]
struct Script {
    token_steps: Mutex<VecDeque<TokenStep>>,
    seen: Mutex<Vec<Seen>>,
    reject_business: Mutex<bool>,
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

impl Mock {
    async fn start() -> Self {
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
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("")
                    .into(),
                content_type: parts
                    .headers
                    .get("content-type")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("")
                    .into(),
                body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            });
            if path == TOKEN {
                let step = script.token_steps.lock().unwrap().pop_front();
                let Some(step) = step else {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error":"unexpected token request"})),
                    )
                        .into_response();
                };
                if let Some(gate) = step.gate {
                    gate.entered.notify_one();
                    gate.release.notified().await;
                }
                let mut response = (step.status, Json(step.body)).into_response();
                if let Some(location) = step.location {
                    response
                        .headers_mut()
                        .insert("location", location.parse().unwrap());
                }
                return response;
            }
            let body = match path.as_str() {
                USERINFO => {
                    json!({"data":{"user_id":"PUBLIC-oauth-user","email":"oauth@example.invalid","nickName":"OAuth fixture"}})
                }
                LOGIN if *script.reject_business.lock().unwrap() => {
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(json!({"message":format!("business denied {ACCESS} {BIZ}")})),
                    )
                        .into_response();
                }
                LOGIN => json!({"data":{"access_token":BIZ}}),
                CUSTOMER => {
                    json!({"data":{"organizations":[{"organizationId":17,"organizationName":"默认机构","projects":[{"projectId":23,"projectName":"默认项目"}]}]}})
                }
                KEYS => json!({"data":[{"name":"zcode-api-key","apiKey":KEY_ID}]}),
                COPY => json!({"data":{"secretKey":KEY_SECRET}}),
                _ => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error":"unexpected OAuth upstream path"})),
                    )
                        .into_response()
                }
            };
            Json(body).into_response()
        }
        let script = Arc::new(Script::default());
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

    fn token(&self, gate: Option<Arc<Gate>>) {
        self.script.token_steps.lock().unwrap().push_back(TokenStep {
            status: StatusCode::OK,
            body: json!({"code":200,"data":{"token":JWT,"zai":{"access_token":ACCESS,"refresh_token":REFRESH}}}),
            location: None,
            gate,
        });
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

    fn assert_wire(&self, state: &str, redirect: &str, with_key: bool) {
        let seen = self.script.seen.lock().unwrap();
        let expected: Vec<_> = if with_key {
            vec![TOKEN, USERINFO, LOGIN, CUSTOMER, KEYS, COPY]
        } else {
            vec![TOKEN, USERINFO, LOGIN]
        };
        assert_eq!(
            seen.iter().map(|s| s.path.as_str()).collect::<Vec<_>>(),
            expected
        );
        for request in seen.iter() {
            assert_eq!(
                request.query, None,
                "credentials stay out of upstream query strings"
            );
            match request.path.as_str() {
                TOKEN => {
                    assert_eq!(request.method, "POST");
                    assert!(request.content_type.starts_with("application/json"));
                    assert!(request.authorization.is_empty());
                    // This is Go's source contract, not a capture from the live provider.
                    assert_eq!(
                        request.body,
                        json!({"provider":"zai","code":CODE,"redirect_uri":redirect,"state":state})
                    );
                }
                LOGIN => {
                    assert_eq!(request.method, "POST");
                    assert!(request.content_type.starts_with("application/json"));
                    assert_eq!(request.body, json!({"token":ACCESS}));
                    assert!(request.authorization.is_empty());
                }
                path => {
                    assert_eq!(request.method, "GET");
                    assert_eq!(request.body, Value::Null);
                    let bearer = if path == USERINFO { ACCESS } else { BIZ };
                    assert_eq!(request.authorization, format!("Bearer {bearer}"));
                }
            }
        }
        assert!(self.script.token_steps.lock().unwrap().is_empty());
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    json: Value,
    raw: String,
}

struct Fixture(Arc<AppState>);

impl Fixture {
    fn new(mock: &Mock, ttl: Duration) -> Self {
        let mut state = AppState::try_from_db_with_vault(
            String::new(),
            UpstreamUrls {
                zai: format!("{}/unused-relay", mock.base),
                zai_fallback: format!("{}/unused-relay-fallback", mock.base),
            },
            store::open(":memory:"),
            Vault::from_secret("PUBLIC OAuth wire fixture vault seed").unwrap(),
        )
        .unwrap();
        state.management.oauth_token = format!("{}{TOKEN}", mock.base);
        state.management.billing_base = format!("{}/unused-billing", mock.base);
        state.management.quota_limit = format!("{}/unused-quota", mock.base);
        state.management.subscription = format!("{}/unused-subscription", mock.base);
        state.oauth = OAuthUrls {
            authorize: format!("{}/authorize", mock.base),
            userinfo: format!("{}{USERINFO}", mock.base),
            business_login: format!("{}{LOGIN}", mock.base),
            customer_info: format!("{}{CUSTOMER}", mock.base),
            project_keys_base: format!("{}/api/biz/v1/organization", mock.base),
            manual_redirect: "https://zcode.z.ai/login".into(),
            callback_url: "http://127.0.0.1:8787/oauth/callback".into(),
            flow_ttl: ttl,
        };
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        Self(Arc::new(state))
    }

    async fn request(&self, method: &str, path: &str, body: Value, authenticated: bool) -> Reply {
        let mut request = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost:8787")
            .header("content-type", "application/json");
        if authenticated {
            request = request
                .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
                .header("origin", "http://localhost:8787");
        }
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            build_router(self.0.clone())
                .oneshot(request.body(Body::from(body.to_string())).unwrap()),
        )
        .await
        .expect("loopback OAuth request deadline")
        .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        let reply = Reply {
            status,
            headers,
            json: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            raw: String::from_utf8(bytes.to_vec()).unwrap(),
        };
        assert_redacted(&reply);
        reply
    }

    async fn start(&self, manual: bool) -> Value {
        let reply = self
            .request(
                "POST",
                START,
                json!({"manual":manual,"group":"OAuth group"}),
                true,
            )
            .await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "OAuth start route: {}",
            reply.raw
        );
        assert_eq!(reply.json["manual"], manual);
        assert!(!reply.json["state"].as_str().unwrap().is_empty());
        reply.json
    }

    async fn manual(&self, state: &str, input: &str) -> Reply {
        self.request("POST", MANUAL, json!({"state":state,"input":input}), true)
            .await
    }

    async fn status(&self, state: &str) -> Reply {
        let mut url =
            reqwest::Url::parse("http://localhost:8787/api/accounts/oauth/status").unwrap();
        url.query_pairs_mut().append_pair("state", state);
        self.request(
            "GET",
            &format!("{}?{}", url.path(), url.query().unwrap()),
            Value::Null,
            true,
        )
        .await
    }

    async fn callback(&self, state: &str, code: Option<&str>, error: Option<&str>) -> Reply {
        let mut url = reqwest::Url::parse("http://localhost:8787/oauth/callback").unwrap();
        url.query_pairs_mut().append_pair("state", state);
        if let Some(code) = code {
            url.query_pairs_mut().append_pair("code", code);
        }
        if let Some(error) = error {
            url.query_pairs_mut()
                .append_pair("error", "access_denied")
                .append_pair("error_description", error);
        }
        let reply = self
            .request(
                "GET",
                &format!("{}?{}", url.path(), url.query().unwrap()),
                Value::Null,
                false,
            )
            .await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "callback renders a result without an admin cookie"
        );
        assert!(reply.headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/html"));
        assert!(!reply.headers.contains_key("location"));
        reply
    }

    fn assert_empty(&self) {
        assert!(
            store::load_bundle_accounts(&self.0.db.lock().unwrap(), &self.0.vault)
                .unwrap()
                .is_empty()
        );
        assert!(self.0.accounts.lock().unwrap().is_empty());
        assert!(self.0.creds.lock().unwrap().is_empty());
    }

    fn assert_account(&self, id: i64, key: &str) {
        let rows = store::load_bundle_accounts(&self.0.db.lock().unwrap(), &self.0.vault).unwrap();
        assert_eq!(rows.len(), 1);
        let (row_id, account) = &rows[0];
        assert_eq!(*row_id, id);
        assert_eq!(account.user_id, "PUBLIC-oauth-user");
        assert_eq!(account.email, "oauth@example.invalid");
        assert_eq!(account.display_name, "OAuth fixture");
        assert_eq!(account.provider, "zai");
        assert_eq!(account.auth_type, "jwt");
        assert_eq!(account.account_group, "OAuth group");
        assert_eq!(account.zcode_jwt, JWT);
        assert_eq!(account.access_token, ACCESS);
        assert_eq!(account.refresh_token, REFRESH);
        assert_eq!(account.api_key, key);
        assert_eq!(
            serde_json::from_str::<Value>(&account.user_info).unwrap(),
            json!({"user_id":"PUBLIC-oauth-user","email":"oauth@example.invalid","nickName":"OAuth fixture"})
        );
        let live = self.0.accounts.lock().unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].id, id);
        assert_eq!(live[0].provider, "zai");
        assert_eq!(live[0].email, account.email);
        assert_eq!(live[0].account_group, "OAuth group");
        assert_eq!(live[0].status, "active");
        assert!(live[0].enabled);
        assert_eq!(live[0].zcode_jwt, JWT);
        assert_eq!(live[0].api_key, key);
        let creds = self.0.creds.lock().unwrap();
        assert_eq!(creds[&id].zcode_jwt, JWT);
        assert_eq!(creds[&id].api_key, key);
        let raw: Vec<String> = self.0.db.lock().unwrap().query_row(
            "SELECT access_token,refresh_token,zcode_jwt,api_key,user_info FROM accounts WHERE id=?1", [id],
            |row| (0..5).map(|i| row.get(i)).collect(),
        ).unwrap();
        for (cipher, plain) in
            raw.iter()
                .zip([ACCESS, REFRESH, JWT, key, account.user_info.as_str()])
        {
            assert_eq!(self.0.vault.decrypt(cipher).unwrap(), plain);
            if !plain.is_empty() {
                assert!(
                    cipher.starts_with("vault1:"),
                    "OAuth credentials must be encrypted at rest"
                );
                assert!(!cipher.contains(plain));
            }
        }
    }

    fn reload(self) -> Self {
        let state = Arc::try_unwrap(self.0)
            .ok()
            .expect("all OAuth requests have completed");
        Self(Arc::new(
            AppState::try_from_db_with_vault(
                state.root_key,
                state.upstream,
                state.db.into_inner().unwrap(),
                state.vault,
            )
            .unwrap(),
        ))
    }
}

fn assert_redacted(reply: &Reply) {
    for secret in [CODE, JWT, ACCESS, REFRESH, BIZ, KEY, KEY_SECRET] {
        assert!(
            !reply.raw.contains(secret),
            "OAuth response leaked a credential"
        );
        for header in reply.headers.values() {
            assert!(
                !header.to_str().unwrap_or("").contains(secret),
                "OAuth header leaked a credential"
            );
        }
    }
    assert!(
        !reply.raw.contains("vault1:"),
        "OAuth response leaked ciphertext"
    );
    fn visit(value: &Value) {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    assert!(
                        ![
                            "access_token",
                            "refresh_token",
                            "zcode_jwt",
                            "api_key",
                            "secretKey",
                            "creds_raw",
                            "user_info"
                        ]
                        .contains(&key.as_str()),
                        "OAuth response exposed credential field {key}"
                    );
                    visit(value);
                }
            }
            Value::Array(array) => array.iter().for_each(visit),
            _ => {}
        }
    }
    visit(&reply.json);
}

#[tokio::test]
async fn manual_oauth_uses_go_authcode_wire_and_persists_typed_encrypted_account() {
    let mock = Mock::start().await;
    mock.token(None);
    let fixture = Fixture::new(&mock, Duration::from_secs(600));
    let started = fixture.start(true).await;
    let state = started["state"].as_str().unwrap();
    let other = fixture.start(true).await;
    assert_ne!(
        other["state"], started["state"],
        "each flow needs an independent CSRF nonce"
    );
    let state_json: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(state).unwrap()).unwrap();
    assert!(!state_json["nonce"].as_str().unwrap().is_empty());
    assert_eq!(state_json["app_return_to"], "https://zcode.z.ai/login");
    assert_eq!(state_json["redirect_uri"], "https://zcode.z.ai/login");
    let authorize = reqwest::Url::parse(started["authorize_url"].as_str().unwrap()).unwrap();
    assert_eq!(
        authorize.as_str().split('?').next().unwrap(),
        format!("{}/authorize", mock.base)
    );
    let query: std::collections::BTreeMap<_, _> = authorize.query_pairs().into_owned().collect();
    assert_eq!(query.len(), 4);
    assert_eq!(query["state"], state);
    assert_eq!(query["redirect_uri"], "https://zcode.z.ai/login");
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["client_id"], "client_P8X5CMWmlaRO9gyO-KSqtg");
    let pending = fixture.status(state).await;
    assert_eq!(pending.status, StatusCode::OK);
    assert_eq!(pending.json["status"], "pending");
    let mut pasted = reqwest::Url::parse("https://zcode.z.ai/login").unwrap();
    pasted
        .query_pairs_mut()
        .append_pair("code", CODE)
        .append_pair("state", state);
    let reply = fixture.manual(state, pasted.as_str()).await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "manual completion: {}",
        reply.raw
    );
    assert_eq!(reply.json["success"], true);
    let ready = fixture.status(state).await;
    assert_eq!(ready.status, StatusCode::OK);
    assert_eq!(ready.json["status"], "ready");
    assert_eq!(ready.json["email"], "oauth@example.invalid");
    assert_eq!(ready.json["state"], state);
    let id = ready.json["account_id"]
        .as_i64()
        .filter(|id| *id > 0)
        .unwrap();
    mock.assert_wire(state, "https://zcode.z.ai/login", true);
    fixture.assert_account(id, KEY);
    fixture.reload().assert_account(id, KEY);
}

#[tokio::test]
async fn oauth_state_validation_and_callback_errors_do_not_authorize_an_account() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, Duration::from_secs(600));
    let started = fixture.start(true).await;
    let state = started["state"].as_str().unwrap();
    fixture
        .callback("PUBLIC-forged-state", Some(CODE), None)
        .await;
    let rejected = fixture
        .manual(
            state,
            &format!("https://zcode.z.ai/login?code={CODE}&state=PUBLIC-forged-state"),
        )
        .await;
    assert_eq!(
        rejected.status,
        StatusCode::BAD_REQUEST,
        "pasted callback state must match the flow"
    );
    fixture.callback(state, None, None).await;
    assert_eq!(fixture.status(state).await.json["status"], "pending");
    let html = fixture
        .callback(state, None, Some("<script>PUBLIC-denied</script>"))
        .await;
    assert!(
        !html.raw.contains("<script>PUBLIC-denied</script>"),
        "provider error text must be HTML escaped"
    );
    assert_eq!(fixture.status(state).await.json["status"], "failed");
    assert!(
        mock.paths().is_empty(),
        "invalid states, missing code and denial never exchange tokens"
    );
    fixture.assert_empty();

    mock.token(None);
    let loopback = fixture.start(false).await;
    let loopback_state = loopback["state"].as_str().unwrap();
    let authorize = reqwest::Url::parse(loopback["authorize_url"].as_str().unwrap()).unwrap();
    assert_eq!(
        authorize
            .query_pairs()
            .find(|(key, _)| key == "redirect_uri")
            .unwrap()
            .1,
        "http://127.0.0.1:8787/oauth/callback"
    );
    fixture.callback(loopback_state, Some(CODE), None).await;
    let ready = fixture.status(loopback_state).await;
    assert_eq!(ready.json["status"], "ready");
    fixture.assert_account(ready.json["account_id"].as_i64().unwrap(), KEY);
    mock.assert_wire(loopback_state, "http://127.0.0.1:8787/oauth/callback", true);
}

#[tokio::test]
async fn oauth_exchange_is_single_use_and_error_callbacks_cannot_regress_inflight_or_ready() {
    let mock = Mock::start().await;
    let gate = Arc::new(Gate::default());
    mock.token(Some(gate.clone()));
    let fixture = Fixture::new(&mock, Duration::from_secs(600));
    let started = fixture.start(true).await;
    let state = started["state"].as_str().unwrap().to_owned();
    let first_fixture = Fixture(fixture.0.clone());
    let first_state = state.clone();
    let first = tokio::spawn(async move { first_fixture.manual(&first_state, CODE).await });
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .expect("token request entered loopback gate");
    assert_eq!(fixture.status(&state).await.json["status"], "exchanging");
    assert_eq!(
        fixture.manual(&state, CODE).await.status,
        StatusCode::BAD_REQUEST
    );
    fixture.callback(&state, Some(CODE), None).await;
    fixture.callback(&state, None, Some("late denial")).await;
    assert_eq!(fixture.status(&state).await.json["status"], "exchanging");
    assert_eq!(mock.paths(), [TOKEN]);
    fixture.assert_empty();
    gate.release.notify_one();
    let complete = first.await.unwrap();
    assert_eq!(complete.status, StatusCode::OK);
    let ready = fixture.status(&state).await;
    assert_eq!(ready.json["status"], "ready");
    let id = ready.json["account_id"].as_i64().unwrap();
    assert_eq!(
        fixture.manual(&state, CODE).await.status,
        StatusCode::BAD_REQUEST
    );
    fixture.callback(&state, Some(CODE), None).await;
    fixture.callback(&state, None, Some("late denial")).await;
    let after = fixture.status(&state).await;
    assert_eq!(after.json["status"], "ready");
    assert_eq!(after.json["account_id"], id);
    assert_eq!(after.json["email"], "oauth@example.invalid");
    fixture.assert_account(id, KEY);
    mock.assert_wire(&state, "https://zcode.z.ai/login", true);
}

#[tokio::test]
async fn expired_oauth_state_is_rejected_on_every_use_without_another_start() {
    let mock = Mock::start().await;
    let fixture = Fixture::new(&mock, Duration::ZERO);
    let started = fixture.start(true).await;
    let state = started["state"].as_str().unwrap();
    assert_eq!(fixture.status(state).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        fixture.manual(state, CODE).await.status,
        StatusCode::BAD_REQUEST
    );
    fixture.callback(state, Some(CODE), None).await;
    assert_eq!(fixture.status(state).await.status, StatusCode::NOT_FOUND);
    assert!(
        mock.paths().is_empty(),
        "expired capability cannot exchange tokens"
    );
    fixture.assert_empty();
}

#[tokio::test]
async fn oauth_refuses_token_redirects_redacts_provider_secrets_and_allows_failed_flow_retry() {
    let mock = Mock::start().await;
    mock.script.token_steps.lock().unwrap().push_back(TokenStep {
        status: StatusCode::TEMPORARY_REDIRECT,
        body: json!({"code":200,"data":{"token":JWT,"zai":{"access_token":ACCESS,"refresh_token":REFRESH}},"message":format!("denied {CODE} {BIZ} {KEY_SECRET}")}),
        location: Some(format!("{}/capture?code={CODE}&token={ACCESS}", mock.base)),
        gate: None,
    });
    let fixture = Fixture::new(&mock, Duration::from_secs(600));
    let started = fixture.start(true).await;
    let state = started["state"].as_str().unwrap();
    let reply = fixture.manual(state, CODE).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let failed = fixture.status(state).await;
    assert_eq!(failed.json["status"], "failed");
    assert_eq!(
        mock.paths(),
        [TOKEN],
        "307 must not forward authorization code or body to Location"
    );
    fixture.assert_empty();

    mock.script.seen.lock().unwrap().clear();
    *mock.script.reject_business.lock().unwrap() = true;
    mock.token(None);
    let retry = fixture.manual(state, CODE).await;
    assert_eq!(
        retry.status,
        StatusCode::OK,
        "failed exchange can retry; optional API-key failure must not discard valid JWT"
    );
    assert_eq!(retry.json["success"], true);
    let ready = fixture.status(state).await;
    assert_eq!(ready.json["status"], "ready");
    fixture.assert_account(ready.json["account_id"].as_i64().unwrap(), "");
    mock.assert_wire(state, "https://zcode.z.ai/login", false);
}
