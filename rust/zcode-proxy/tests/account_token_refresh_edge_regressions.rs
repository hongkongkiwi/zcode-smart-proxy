use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::StatusCode,
    Json, Router,
};
use serde_json::{json, Value};
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

const SESSION: &str = "PUBLIC-token-refresh-edge-session";
const OLD_JWT: &str = "PUBLIC-edge-old-jwt";
const NEW_JWT: &str = "PUBLIC-edge-new-jwt";
const OLD_ACCESS: &str = "PUBLIC-edge-old-access";
const NEW_ACCESS: &str = "PUBLIC-edge-new-access";
const OLD_REFRESH: &str = "PUBLIC-edge-old-refresh";
const NEW_REFRESH: &str = "PUBLIC-edge-new-refresh";
const USER_INFO: &str = r#"{ "id": "PUBLIC-edge-user", "email": "edge@example.invalid", "name": "PUBLIC preserved name", "roles": ["PUBLIC-role"] }"#;
const BILLING: &str = "/api/v1/zcode-plan/billing/balance";
const TOKEN: &str = "/api/v1/oauth/token";

#[derive(Debug, PartialEq)]
struct Seen {
    method: String,
    path: String,
    authorization: String,
    body: Value,
}

#[derive(Default)]
struct Script {
    replies: Mutex<VecDeque<(StatusCode, Value)>>,
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
                authorization: parts
                    .headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .into(),
                body: serde_json::from_slice(&body).unwrap_or(Value::Null),
            });
            let (status, body) = script
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({"code":500,"msg":"unexpected mock request"}),
                    )
                });
            (status, Json(body))
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

    fn denied_billing(&self) {
        self.script
            .replies
            .lock()
            .unwrap()
            .push_back((StatusCode::UNAUTHORIZED, json!({"code":401})));
    }

    fn exchange(&self, user: Option<Value>) {
        let mut data =
            json!({"token":NEW_JWT,"zai":{"access_token":NEW_ACCESS,"refresh_token":NEW_REFRESH}});
        if let Some(user) = user {
            data["user"] = user;
        }
        self.script
            .replies
            .lock()
            .unwrap()
            .push_back((StatusCode::OK, json!({"code":200,"data":data})));
    }

    fn assert_calls(&self, second_quota: bool) {
        let mut expected = vec![
            Seen {
                method: "GET".into(),
                path: BILLING.into(),
                authorization: format!("Bearer {OLD_JWT}"),
                body: Value::Null,
            },
            Seen {
                method: "POST".into(),
                path: TOKEN.into(),
                authorization: String::new(),
                body: json!({"provider":"zai","refresh_token":OLD_REFRESH}),
            },
        ];
        if second_quota {
            expected.push(Seen {
                method: "GET".into(),
                path: BILLING.into(),
                authorization: format!("Bearer {NEW_JWT}"),
                body: Value::Null,
            });
        }
        assert_eq!(*self.script.seen.lock().unwrap(), expected);
        assert!(self.script.replies.lock().unwrap().is_empty());
    }
}

struct Fixture {
    state: Arc<AppState>,
    id: i64,
}

impl Fixture {
    fn new(mock: &Mock) -> Self {
        let db = store::open(":memory:");
        let vault = Vault::from_secret("PUBLIC edge token refresh vault seed").unwrap();
        let id = store::insert_account_encrypted(
            &db,
            &vault,
            &AccountView {
                email: "edge@example.invalid".into(),
                provider: "zai".into(),
                enabled: true,
                status: "invalid".into(),
                remaining: 7.0,
                priority: 37,
                ..Default::default()
            },
            OLD_JWT,
            "",
        )
        .unwrap();
        db.execute(
            "UPDATE accounts SET access_token=?1,refresh_token=?2,user_info=?3 WHERE id=?4",
            rusqlite::params![
                vault.encrypt(OLD_ACCESS).unwrap(),
                vault.encrypt(OLD_REFRESH).unwrap(),
                vault.encrypt(USER_INFO).unwrap(),
                id
            ],
        )
        .unwrap();
        let mut state = AppState::try_from_db_with_vault(
            String::new(),
            UpstreamUrls {
                zai: format!("{}/unused-relay", mock.base),
                zai_fallback: format!("{}/unused-fallback", mock.base),
            },
            db,
            vault,
        )
        .unwrap();
        state.management = ManagementUrls {
            billing_base: format!("{}/api/v1/zcode-plan", mock.base),
            quota_limit: format!("{}/unused-monitor", mock.base),
            subscription: format!("{}/unused-subscription", mock.base),
            oauth_token: format!("{}{TOKEN}", mock.base),
            app_version: "PUBLIC-edge-test-version".into(),
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

    async fn refresh(&self) -> Value {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/api/accounts/{}/refresh", self.id))
            .header("host", "localhost:8080")
            .header("origin", "http://localhost:8080")
            .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
            .body(Body::empty())
            .unwrap();
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            build_router(self.state.clone()).oneshot(request),
        )
        .await
        .expect("loopback refresh deadline")
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["success"], true);
        let text = body.to_string();
        for secret in [
            OLD_JWT,
            NEW_JWT,
            OLD_ACCESS,
            NEW_ACCESS,
            OLD_REFRESH,
            NEW_REFRESH,
            USER_INFO,
        ] {
            assert!(
                !text.contains(secret),
                "response exposed credential metadata"
            );
        }
        assert!(!text.contains("vault1:"));
        body["account"].clone()
    }

    fn raw(&self) -> [String; 4] {
        self.state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT access_token,refresh_token,zcode_jwt,user_info FROM accounts WHERE id=?1",
                [self.id],
                |r| Ok([r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?]),
            )
            .unwrap()
    }

    fn assert_rotated(&self, status: &str) {
        let raw = self.raw();
        for (cipher, expected) in raw
            .iter()
            .zip([NEW_ACCESS, NEW_REFRESH, NEW_JWT, USER_INFO])
        {
            assert!(cipher.starts_with("vault1:"));
            assert_eq!(self.state.vault.decrypt(cipher).unwrap(), expected);
        }
        let accounts = self.state.accounts.lock().unwrap();
        let account = accounts.iter().find(|a| a.id == self.id).unwrap();
        assert_eq!(account.zcode_jwt, NEW_JWT);
        assert_eq!(account.status, status);
        let creds = self.state.creds.lock().unwrap();
        assert_eq!(creds.get(&self.id).unwrap().zcode_jwt, NEW_JWT);
        drop(creds);
        drop(accounts);
        let db = self.state.db.lock().unwrap();
        let stored: String = db
            .query_row("SELECT status FROM accounts WHERE id=?1", [self.id], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(stored, status);
        let loaded = store::load_bundle_accounts(&db, &self.state.vault).unwrap();
        let (_, account) = loaded.iter().find(|(id, _)| *id == self.id).unwrap();
        assert_eq!(account.user_info, USER_INFO);
        assert_eq!(account.refresh_token, NEW_REFRESH);
    }
}

#[tokio::test]
async fn empty_or_partial_exchange_user_preserves_exact_stored_profile_while_tokens_rotate() {
    for user in [
        json!({}),
        json!({"id":"PUBLIC-edge-user","name":"PUBLIC partial replacement"}),
    ] {
        let mock = Mock::start().await;
        let f = Fixture::new(&mock);
        let before = f.raw();
        mock.denied_billing();
        mock.exchange(Some(user.clone()));
        let account = f.refresh().await;
        assert_eq!(account["status"], "active");
        let after = f.raw();
        assert_eq!(
            after[3], before[3],
            "refresh response user={user} must not replace or re-encrypt stored user_info"
        );
        f.assert_rotated("active");
        mock.assert_calls(false);
    }
}

#[tokio::test]
async fn repeated_quota_401_within_backoff_exchanges_once_then_marks_invalid_without_credential_changes(
) {
    let mock = Mock::start().await;
    let f = Fixture::new(&mock);
    mock.denied_billing();
    mock.exchange(None);
    let started = Instant::now();
    assert_eq!(f.refresh().await["status"], "active");
    f.assert_rotated("active");
    let after_exchange = f.raw();
    mock.denied_billing();
    let account = f.refresh().await;
    assert!(
        started.elapsed() < Duration::from_secs(90),
        "requests must exercise the refresh-attempt cooldown window"
    );
    assert_eq!(account["status"], "invalid");
    assert_eq!(account["remaining"], 7.0);
    assert_eq!(
        f.raw(),
        after_exchange,
        "cooldown must preserve the successfully rotated credentials"
    );
    f.assert_rotated("invalid");
    mock.assert_calls(true);
}
