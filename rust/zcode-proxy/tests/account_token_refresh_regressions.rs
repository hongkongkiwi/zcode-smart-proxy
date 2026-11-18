use std::{
    collections::VecDeque,
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
    build_router,
    state::{AppState, ManagementUrls, UpstreamUrls},
    store,
    vault::Vault,
};

const SESSION: &str = "PUBLIC-token-refresh-session";
const USER: &str = "PUBLIC-token-refresh-user";
const OLD_JWT: &str = "PUBLIC-token-refresh-old-jwt";
const NEW_JWT: &str = "PUBLIC-token-refresh-new-jwt";
const OLD_ACCESS: &str = "PUBLIC-token-refresh-old-access";
const NEW_ACCESS: &str = "PUBLIC-token-refresh-new-access";
const OLD_REFRESH: &str = "PUBLIC-token-refresh-old-refresh";
const NEW_REFRESH: &str = "PUBLIC-token-refresh-new-refresh";
const KEY: &str = "PUBLIC-token-refresh-api-key";
const USER_INFO: &str = "PUBLIC-token-refresh-user-info";
const CREDS_RAW: &str = "PUBLIC-token-refresh-credential-snapshot";
const BILLING: &str = "/api/v1/zcode-plan/billing/balance";
const LIMIT: &str = "/api/monitor/usage/quota/limit";
const TOKEN: &str = "/api/v1/oauth/token";
const VERSION: &str = "PUBLIC-token-test-version";

#[derive(Debug, PartialEq)]
struct Seen {
    method: String,
    path: String,
    query: Option<String>,
    authorization: String,
    content_type: String,
    body: Value,
}

struct Step {
    status: StatusCode,
    body: Value,
    gate: Option<Arc<Gate>>,
}
#[derive(Default)]
struct Gate {
    entered: Notify,
    release: Notify,
}
#[derive(Default)]
struct Script {
    steps: Mutex<VecDeque<Step>>,
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
            let body = to_bytes(body, 1 << 20).await.unwrap();
            script.seen.lock().unwrap().push(Seen {
                method: parts.method.to_string(),
                path: parts.uri.path().into(),
                query: parts.uri.query().map(str::to_owned),
                authorization: parts
                    .headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .into(),
                content_type: parts
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .into(),
                body: serde_json::from_slice(&body).unwrap_or(Value::Null),
            });
            let step = script.steps.lock().unwrap().pop_front();
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
            (step.status, Json(step.body))
        }
        let script = Arc::new(Script::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(serve).with_state(script.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { base, script, task }
    }

    fn push(&self, status: StatusCode, body: Value) {
        self.script.steps.lock().unwrap().push_back(Step {
            status,
            body,
            gate: None,
        });
    }

    fn denied_quota(&self) {
        self.push(StatusCode::UNAUTHORIZED, json!({"code":401}));
        self.push(StatusCode::UNAUTHORIZED, json!({"code":401}));
    }

    fn exchange(&self, rotated: bool) -> Value {
        let mut zai = json!({"access_token":NEW_ACCESS});
        if rotated {
            zai["refresh_token"] = json!(NEW_REFRESH);
        }
        json!({"code":200,"data":{"token":NEW_JWT,"zai":zai}})
    }

    fn assert_calls(&self, expected: &[(&str, &str)]) {
        let seen = self.script.seen.lock().unwrap();
        let actual: Vec<_> = seen
            .iter()
            .map(|s| (s.path.as_str(), s.authorization.as_str()))
            .collect();
        assert_eq!(
            actual, expected,
            "billing, monitor and automatic exchange request sequence"
        );
        for request in seen.iter() {
            if request.path == TOKEN {
                assert_eq!(request.method, "POST");
                assert!(request.content_type.starts_with("application/json"));
                assert_eq!(
                    request.body,
                    json!({"provider":"zai","refresh_token":OLD_REFRESH})
                );
                assert_eq!(request.query, None);
            } else {
                assert_eq!(request.method, "GET");
                assert_eq!(request.body, Value::Null);
                assert_eq!(
                    request.query,
                    (request.path == BILLING).then(|| format!("app_version={VERSION}"))
                );
            }
        }
        assert!(
            self.script.steps.lock().unwrap().is_empty(),
            "automatic token exchange must consume its response"
        );
    }
}

struct Fixture {
    state: Arc<AppState>,
    id: i64,
}
impl Fixture {
    fn new(mock: &Mock, status: &str) -> Self {
        let db = store::open(":memory:");
        let vault = Vault::from_secret("PUBLIC token refresh vault seed").unwrap();
        let id = store::insert_account_encrypted(
            &db,
            &vault,
            &AccountView {
                email: "token-refresh@example.invalid".into(),
                provider: "zai".into(),
                enabled: true,
                status: status.into(),
                remaining: 7.0,
                priority: 37,
                paid_fallback: true,
                ..Default::default()
            },
            OLD_JWT,
            KEY,
        )
        .unwrap();
        db.execute("UPDATE accounts SET user_id=?1,access_token=?2,refresh_token=?3,user_info=?4,creds_raw=?5 WHERE id=?6",
            rusqlite::params![USER, vault.encrypt(OLD_ACCESS).unwrap(), vault.encrypt(OLD_REFRESH).unwrap(),
                vault.encrypt(USER_INFO).unwrap(), vault.encrypt(CREDS_RAW).unwrap(), id]).unwrap();
        let mut state = AppState::try_from_db_with_vault(
            String::new(),
            UpstreamUrls {
                zai: format!("{}/unused-relay", mock.base),
                zai_fallback: format!("{}/unused-relay-fallback", mock.base),
            },
            db,
            vault,
        )
        .unwrap();
        state.management = ManagementUrls {
            billing_base: format!("{}/api/v1/zcode-plan", mock.base),
            quota_limit: format!("{}{LIMIT}", mock.base),
            subscription: format!("{}/api/biz/subscription/list", mock.base),
            oauth_token: format!("{}{TOKEN}", mock.base),
            app_version: VERSION.into(),
        };
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        Self {
            state: Arc::new(state),
            id,
        }
    }

    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("host", "localhost:8080")
            .header("origin", "http://localhost:8080")
            .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            build_router(self.state.clone()).oneshot(request),
        )
        .await
        .expect("loopback refresh deadline")
        .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert_redacted(&value);
        (status, value)
    }

    async fn refresh(&self) -> Value {
        let (status, body) = self
            .post(&format!("/api/accounts/{}/refresh", self.id), Value::Null)
            .await;
        assert_eq!(status, StatusCode::OK, "automatic refresh response: {body}");
        assert_eq!(body["success"], true);
        assert_eq!(body["account"]["id"], self.id);
        body["account"].clone()
    }

    fn raw(&self) -> [String; 6] {
        self.state.db.lock().unwrap().query_row(
            "SELECT access_token,refresh_token,zcode_jwt,api_key,user_info,creds_raw FROM accounts WHERE id=?1", [self.id],
            |r| Ok([r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?])).unwrap()
    }

    fn live(&self) -> (String, String, String, String) {
        let accounts = self.state.accounts.lock().unwrap();
        let a = accounts.iter().find(|a| a.id == self.id).unwrap();
        let creds = self.state.creds.lock().unwrap();
        let c = creds.get(&self.id).unwrap();
        (
            a.zcode_jwt.clone(),
            a.api_key.clone(),
            c.zcode_jwt.clone(),
            c.api_key.clone(),
        )
    }

    fn assert_credentials(&self, jwt: &str, access: &str, refresh: &str) {
        let expected = [access, refresh, jwt, KEY, USER_INFO, CREDS_RAW];
        let raw = self.raw();
        for (cipher, plain) in raw.iter().zip(expected) {
            assert!(
                cipher.starts_with("vault1:"),
                "each nonempty credential column must stay encrypted"
            );
            assert_eq!(self.state.vault.decrypt(cipher).unwrap(), plain);
        }
        assert_eq!(
            self.live(),
            (jwt.into(), KEY.into(), jwt.into(), KEY.into())
        );
        let loaded =
            store::load_bundle_accounts(&self.state.db.lock().unwrap(), &self.state.vault).unwrap();
        let (_, a) = loaded.iter().find(|(id, _)| *id == self.id).unwrap();
        assert_eq!(
            (
                &a.access_token,
                &a.refresh_token,
                &a.zcode_jwt,
                &a.api_key,
                &a.user_info,
                &a.creds_raw
            ),
            (
                &access.to_owned(),
                &refresh.to_owned(),
                &jwt.to_owned(),
                &KEY.to_owned(),
                &USER_INFO.to_owned(),
                &CREDS_RAW.to_owned()
            )
        );
    }

    fn assert_status(&self, expected: &str) {
        let stored: String = self
            .state
            .db
            .lock()
            .unwrap()
            .query_row("SELECT status FROM accounts WHERE id=?1", [self.id], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(stored, expected);
        let accounts = self.state.accounts.lock().unwrap();
        assert_eq!(
            accounts.iter().find(|a| a.id == self.id).unwrap().status,
            expected
        );
    }
}

fn assert_redacted(value: &Value) {
    let text = value.to_string();
    for secret in [
        OLD_JWT,
        NEW_JWT,
        OLD_ACCESS,
        NEW_ACCESS,
        OLD_REFRESH,
        NEW_REFRESH,
        KEY,
        USER_INFO,
        CREDS_RAW,
    ] {
        assert!(
            !text.contains(secret),
            "management response leaked a fixture credential"
        );
    }
    assert!(!text.contains("vault1:"));
    for field in [
        "access_token",
        "refresh_token",
        "zcode_jwt",
        "api_key",
        "user_info",
        "creds_raw",
    ] {
        assert!(
            value["account"].get(field).is_none(),
            "public response exposed {field}"
        );
    }
}

fn quota() -> Value {
    json!({"code":0,"data":{"plans":[{"plan_id":"pro","status":"active"}],
        "balances":[{"plan_id":"pro","total_units":100.0,"used_units":25.0,"remaining_units":75.0}]}})
}

#[tokio::test]
async fn quota_401_exchanges_stored_refresh_persists_encrypted_metadata_and_retries_new_jwt() {
    for rotated in [true, false] {
        let mock = Mock::start().await;
        let f = Fixture::new(&mock, "invalid");
        mock.denied_quota();
        mock.push(StatusCode::OK, mock.exchange(rotated));
        let account = f.refresh().await;
        assert_eq!(
            account["status"], "active",
            "a successful automatic exchange must recover the account"
        );
        f.assert_status("active");
        f.assert_credentials(
            NEW_JWT,
            NEW_ACCESS,
            if rotated { NEW_REFRESH } else { OLD_REFRESH },
        );
        let old_bearer = format!("Bearer {OLD_JWT}");
        mock.assert_calls(&[(BILLING, &old_bearer), (LIMIT, KEY), (TOKEN, "")]);
        // Go applies the new credentials now; its next quota refresh confirms them.
        mock.push(StatusCode::OK, quota());
        let account = f.refresh().await;
        assert_eq!(account["status"], "active");
        assert_eq!(account["remaining"], 75.0);
        let stored: f64 = f
            .state
            .db
            .lock()
            .unwrap()
            .query_row("SELECT remaining FROM accounts WHERE id=?1", [f.id], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(stored, 75.0);
        assert_eq!(
            f.state
                .accounts
                .lock()
                .unwrap()
                .iter()
                .find(|a| a.id == f.id)
                .unwrap()
                .remaining,
            75.0
        );
        let new_bearer = format!("Bearer {NEW_JWT}");
        mock.assert_calls(&[
            (BILLING, &old_bearer),
            (LIMIT, KEY),
            (TOKEN, ""),
            (BILLING, &new_bearer),
        ]);
    }
}

#[tokio::test]
async fn failed_token_write_preserves_all_durable_and_live_credentials() {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock, "invalid");
    let before_raw = f.raw();
    let before_live = f.live();
    f.state.db.lock().unwrap().execute_batch(
        "CREATE TRIGGER reject_token_update BEFORE UPDATE OF access_token,refresh_token,zcode_jwt ON accounts
         BEGIN SELECT RAISE(ABORT,'PUBLIC rejected token write'); END;").unwrap();
    mock.denied_quota();
    mock.push(StatusCode::OK, mock.exchange(true));
    let account = f.refresh().await;
    assert_eq!(account["status"], "invalid");
    assert_eq!(
        f.raw(),
        before_raw,
        "failed token persistence cannot partially replace stored credentials"
    );
    assert_eq!(
        f.live(),
        before_live,
        "failed token persistence cannot publish new live credentials"
    );
    f.assert_credentials(OLD_JWT, OLD_ACCESS, OLD_REFRESH);
    f.assert_status("invalid");
    let bearer = format!("Bearer {OLD_JWT}");
    mock.assert_calls(&[(BILLING, &bearer), (LIMIT, KEY), (TOKEN, "")]);
}

#[tokio::test]
async fn rejected_or_tokenless_exchange_marks_invalid_preserves_credentials_and_redacts_errors() {
    for (status, exchange) in [
        (
            StatusCode::UNAUTHORIZED,
            json!({"code":401,"msg":format!("rejected {OLD_REFRESH} {OLD_ACCESS} {KEY}")}),
        ),
        (
            StatusCode::OK,
            json!({"code":200,"data":{"zai":{"access_token":NEW_ACCESS,"refresh_token":NEW_REFRESH}}}),
        ),
    ] {
        let mock = Mock::start().await;
        let f = Fixture::new(&mock, "active");
        let before = f.raw();
        mock.denied_quota();
        mock.push(status, exchange);
        let account = f.refresh().await;
        assert_eq!(account["status"], "invalid");
        assert_eq!(account["remaining"], 7.0);
        f.assert_status("invalid");
        assert_eq!(f.raw(), before);
        f.assert_credentials(OLD_JWT, OLD_ACCESS, OLD_REFRESH);
        let last_error: String = f
            .state
            .db
            .lock()
            .unwrap()
            .query_row("SELECT last_error FROM accounts WHERE id=?1", [f.id], |r| {
                r.get(0)
            })
            .unwrap();
        assert_redacted(&json!({"last_error":last_error}));
        let bearer = format!("Bearer {OLD_JWT}");
        mock.assert_calls(&[(BILLING, &bearer), (LIMIT, KEY), (TOKEN, "")]);
    }
}

#[tokio::test]
async fn concurrent_refresh_exchanges_once_and_does_not_overwrite_newer_imported_credentials() {
    for import_newer in [false, true] {
        let mock = Mock::start().await;
        let f = Arc::new(Fixture::new(&mock, "invalid"));
        let gate = Arc::new(Gate::default());
        mock.denied_quota();
        mock.script.steps.lock().unwrap().push_back(Step {
            status: StatusCode::OK,
            body: mock.exchange(true),
            gate: Some(gate.clone()),
        });
        let mut first = tokio::spawn({
            let f = f.clone();
            async move { f.refresh().await }
        });
        tokio::select! {
            _ = gate.entered.notified() => {},
            result = &mut first => panic!("quota authentication failure completed without reaching automatic token exchange: {:?}", result.unwrap()),
            _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("automatic token exchange did not reach loopback mock"),
        }
        let concurrent = f.refresh().await;
        assert_eq!(
            concurrent["status"], "invalid",
            "inflight exchange must not prematurely publish active status"
        );
        f.assert_credentials(OLD_JWT, OLD_ACCESS, OLD_REFRESH);
        let imported = format!(
            "e30.{}.PUBLIC-import-signature",
            URL_SAFE_NO_PAD.encode(json!({"user_id":USER}).to_string())
        );
        if import_newer {
            let (status, body) = f
                .post(
                    "/api/accounts/import/paste",
                    json!({"provider":"zai","secret":imported}),
                )
                .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "concurrent credential import: {body}"
            );
        }
        gate.release.notify_one();
        let account = first.await.unwrap();
        assert_eq!(account["status"], "active");
        let jwt = if import_newer {
            imported.as_str()
        } else {
            NEW_JWT
        };
        if import_newer {
            f.assert_credentials(jwt, OLD_ACCESS, OLD_REFRESH);
        } else {
            f.assert_credentials(jwt, NEW_ACCESS, NEW_REFRESH);
        }
        f.assert_status("active");
        let old_bearer = format!("Bearer {OLD_JWT}");
        mock.assert_calls(&[(BILLING, &old_bearer), (LIMIT, KEY), (TOKEN, "")]);
        mock.push(StatusCode::OK, quota());
        let account = f.refresh().await;
        assert_eq!(account["remaining"], 75.0);
        let bearer = format!("Bearer {jwt}");
        mock.assert_calls(&[
            (BILLING, &old_bearer),
            (LIMIT, KEY),
            (TOKEN, ""),
            (BILLING, &bearer),
        ]);
    }
}
