use std::{sync::Arc, time::Duration};

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_core::AccountView;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
    store,
};

const STATUS: &str = "/api/highspeed/status";
const SESSION: &str = "PUBLIC-highspeed-session";
const ROOT: &str = "PUBLIC-highspeed-root-key";
const DEADLINE: Duration = Duration::from_secs(5);
const CARD_FIELDS: [&str; 5] = [
    "card_id",
    "card_model",
    "card_valid",
    "card_expires_in_sec",
    "draw_blocked_for_sec",
];

struct Reply {
    status: StatusCode,
    body: String,
}

impl Reply {
    fn expect_json(&self, status: StatusCode, expected: Value) {
        assert_eq!(self.status, status, "body={}", self.body);
        let body: Value = serde_json::from_str(&self.body).expect("response must be JSON");
        assert_no_card_fields(&body);
        assert_eq!(body, expected);
    }
}

fn assert_no_card_fields(body: &Value) {
    match body {
        Value::Object(object) => {
            for field in CARD_FIELDS {
                assert!(
                    !object.contains_key(field),
                    "status response must omit {field}"
                );
            }
            for value in object.values() {
                assert_no_card_fields(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                assert_no_card_fields(value);
            }
        }
        _ => {}
    }
}

struct Fixture {
    state: Arc<AppState>,
    app: Router,
    account_ids: Vec<i64>,
}

impl Fixture {
    fn new(accounts: &[AccountView]) -> Self {
        let db = store::open(":memory:");
        let mut account_ids = Vec::new();
        for account in accounts {
            account_ids.push(store::upsert_account(
                &db,
                account,
                &account.zcode_jwt,
                &account.api_key,
            ));
        }
        let state = AppState::from_db(
            ROOT.into(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
            db,
        );
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        let state = Arc::new(state);
        Self {
            app: build_router(state.clone()),
            state,
            account_ids,
        }
    }

    async fn status(&self, session: Option<&str>) -> Reply {
        let mut request = Request::builder()
            .method("GET")
            .uri(STATUS)
            .header("host", "localhost:8787")
            .header("authorization", format!("Bearer {ROOT}"))
            .header("x-api-key", ROOT);
        if let Some(session) = session {
            request = request.header("cookie", format!("{SESSION_COOKIE}={session}"));
        }
        tokio::time::timeout(DEADLINE, async {
            let response = self
                .app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
            Reply {
                status,
                body: String::from_utf8(bytes.to_vec()).unwrap(),
            }
        })
        .await
        .expect("highspeed status request exceeded the test deadline")
    }
}

fn account(email: &str, provider: &str, enabled: bool, status: &str) -> AccountView {
    AccountView {
        email: email.into(),
        provider: provider.into(),
        enabled,
        status: status.into(),
        zcode_jwt: "PUBLIC-highspeed-account-jwt".into(),
        api_key: "PUBLIC-highspeed-account-api-key".into(),
        ..AccountView::default()
    }
}

#[tokio::test]
async fn missing_session_returns_exact_unauthorized_json_even_with_api_keys() {
    let f = Fixture::new(&[]);
    f.status(None).await.expect_json(
        StatusCode::UNAUTHORIZED,
        json!({"error": {"message": "unauthorized", "type": "api_error"}}),
    );
}

#[tokio::test]
async fn no_accounts_and_no_setting_returns_disabled_with_empty_accounts() {
    let f = Fixture::new(&[]);
    f.status(Some(SESSION))
        .await
        .expect_json(StatusCode::OK, json!({"enabled": false, "accounts": []}));
}

#[tokio::test]
async fn only_one_and_true_settings_enable_highspeed_status() {
    let f = Fixture::new(&[]);
    for (value, enabled) in [
        ("1", true),
        ("0", false),
        ("true", true),
        ("false", false),
        ("yes", false),
        ("", false),
    ] {
        f.state
            .persist_settings(&[("highspeed_lane_enabled", value)])
            .unwrap();
        f.status(Some(SESSION))
            .await
            .expect_json(StatusCode::OK, json!({"enabled": enabled, "accounts": []}));
    }
}

#[tokio::test]
async fn lists_only_zai_accounts_in_stored_order_including_disabled_without_card_fields() {
    let f = Fixture::new(&[
        account("z-first@example.test", "zai", true, "active"),
        account("a-second@example.test", "zai", false, "inactive"),
        account("other@example.test", "openai", true, "active"),
    ]);
    f.status(Some(SESSION)).await.expect_json(
        StatusCode::OK,
        json!({
            "enabled": false,
            "accounts": [
                {
                    "id": f.account_ids[0],
                    "email": "z-first@example.test",
                    "enabled": true,
                    "status": "active"
                },
                {
                    "id": f.account_ids[1],
                    "email": "a-second@example.test",
                    "enabled": false,
                    "status": "inactive"
                }
            ]
        }),
    );
}
