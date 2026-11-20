use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::StatusCode,
    Json, Router,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, OAuthUrls, UpstreamUrls},
    store,
};

const SESSION: &str = "PUBLIC-oauth-business-session";
const JWT: &str = "PUBLIC-oauth-business-jwt";
const ACCESS: &str = "PUBLIC-oauth-business-access";
const KEY: &str = "PUBLIC-business-key.PUBLIC-business-secret";
const TOKEN: &str = "/token";
const LOGIN: &str = "/business/login";
const CUSTOMER: &str = "/business/customer";
const KEYS: &str = "/business/organization/17/projects/23/api_keys";
const COPY: &str = "/business/organization/17/projects/23/api_keys/copy/PUBLIC-business-key";

struct Script {
    unusual_code: Option<(&'static str, Value)>,
    token_code: i64,
    seen: Mutex<Vec<String>>,
}

struct Fixture {
    state: Arc<AppState>,
    script: Arc<Script>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn new(unusual_code: Option<(&'static str, Value)>, token_code: i64) -> Self {
        async fn serve(
            State(script): State<Arc<Script>>,
            request: Request,
        ) -> (StatusCode, Json<Value>) {
            let path = request.uri().path();
            script.seen.lock().unwrap().push(path.to_owned());
            let data = match path {
                TOKEN => {
                    json!({"token":JWT,"zai":{"access_token":ACCESS},"user":{"user_id":"PUBLIC-business-user","email":"business@example.invalid"}})
                }
                LOGIN => json!({"access_token":"PUBLIC-business-bearer"}),
                CUSTOMER => {
                    json!({"organizations":[{"organizationId":17,"projects":[{"projectId":23}]}]})
                }
                KEYS => json!([{"name":"zcode-api-key","apiKey":"PUBLIC-business-key"}]),
                COPY => json!({"secretKey":"PUBLIC-business-secret"}),
                _ => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error":"unexpected business fixture request"})),
                    )
                }
            };
            let code = if path == TOKEN {
                json!(script.token_code)
            } else {
                script
                    .unusual_code
                    .as_ref()
                    .filter(|(target, _)| *target == path)
                    .map(|(_, code)| code.clone())
                    .unwrap_or(json!(0))
            };
            (StatusCode::OK, Json(json!({"code":code,"data":data})))
        }
        let script = Arc::new(Script {
            unusual_code,
            token_code,
            seen: Mutex::new(Vec::new()),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(serve).with_state(script.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut state = AppState::new(
            String::new(),
            UpstreamUrls {
                zai: format!("{base}/unused-relay"),
                zai_fallback: format!("{base}/unused-relay-fallback"),
            },
        );
        state.management.oauth_token = format!("{base}{TOKEN}");
        state.management.billing_base = format!("{base}/unused-billing");
        state.management.quota_limit = format!("{base}/unused-quota");
        state.management.subscription = format!("{base}/unused-subscription");
        state.oauth = OAuthUrls {
            authorize: format!("{base}/authorize"),
            userinfo: format!("{base}/unused-userinfo"),
            business_login: format!("{base}{LOGIN}"),
            customer_info: format!("{base}{CUSTOMER}"),
            project_keys_base: format!("{base}/business/organization"),
            manual_redirect: "https://zcode.z.ai/login".into(),
            callback_url: "http://127.0.0.1:8787/oauth/callback".into(),
            flow_ttl: Duration::from_secs(600),
        };
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        Self {
            state: Arc::new(state),
            script,
            server,
        }
    }

    async fn request(&self, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
        let request = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost:8787")
            .header("origin", "http://localhost:8787")
            .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            build_router(self.state.clone()).oneshot(request),
        )
        .await
        .expect("OAuth business fixture deadline")
        .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn start(&self) -> String {
        let (status, started) = self
            .request("POST", "/api/accounts/oauth/start", json!({"manual":true}))
            .await;
        assert_eq!(status, StatusCode::OK);
        started["state"].as_str().unwrap().to_owned()
    }

    async fn submit(&self, state: &str) -> (StatusCode, Value) {
        self.request(
            "POST",
            "/api/accounts/oauth/manual",
            json!({"state":state,"input":"PUBLIC-business-code"}),
        )
        .await
    }

    async fn status(&self, state: &str) -> Value {
        let mut url =
            reqwest::Url::parse("http://localhost:8787/api/accounts/oauth/status").unwrap();
        url.query_pairs_mut().append_pair("state", state);
        let (status, body) = self
            .request(
                "GET",
                &format!("{}?{}", url.path(), url.query().unwrap()),
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        body
    }
}

#[tokio::test]
async fn oauth_business_data_remains_usable_with_nonstandard_envelope_codes() {
    // Go's business chain reads usable data; only the OAuth token exchange classifies code.
    for (path, code) in [
        (LOGIN, json!(731)),
        (CUSTOMER, json!("customer-data")),
        (KEYS, json!(733)),
        (COPY, json!("copied")),
    ] {
        let fixture = Fixture::new(Some((path, code)), 0).await;
        let state = fixture.start().await;
        let (status, body) = fixture.submit(&state).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "valid token exchange must complete despite {path} envelope code"
        );
        assert_eq!(body["success"], true);
        let ready = fixture.status(&state).await;
        assert_eq!(ready["status"], "ready");
        let id = ready["account_id"].as_i64().unwrap();
        let rows =
            store::load_bundle_accounts(&fixture.state.db.lock().unwrap(), &fixture.state.vault)
                .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, id);
        assert_eq!(
            rows[0].1.api_key, KEY,
            "usable {path} data must not silently lose the paid API key"
        );
        assert_eq!(rows[0].1.zcode_jwt, JWT);
        assert_eq!(fixture.state.creds.lock().unwrap()[&id].api_key, KEY);
        assert_eq!(fixture.state.accounts.lock().unwrap()[0].api_key, KEY);
        assert_eq!(
            *fixture.script.seen.lock().unwrap(),
            [TOKEN, LOGIN, CUSTOMER, KEYS, COPY]
        );
    }
}

#[tokio::test]
async fn oauth_token_business_error_still_rejects_usable_token_data_without_persistence() {
    let fixture = Fixture::new(None, 731).await;
    let state = fixture.start().await;
    let (status, _) = fixture.submit(&state).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "token exchange must still enforce its business-code contract"
    );
    assert_eq!(fixture.status(&state).await["status"], "failed");
    assert!(
        store::load_bundle_accounts(&fixture.state.db.lock().unwrap(), &fixture.state.vault)
            .unwrap()
            .is_empty()
    );
    assert!(fixture.state.accounts.lock().unwrap().is_empty());
    assert!(fixture.state.creds.lock().unwrap().is_empty());
    assert_eq!(
        *fixture.script.seen.lock().unwrap(),
        [TOKEN],
        "rejected token cannot enter business key extraction"
    );
}
