use std::{collections::BTreeMap, sync::Arc};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_core::{SelectionQuery, CHANNEL_FREE, CHANNEL_PAID};
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
};

const SESSION: &str = "PUBLIC-account-mutation-test-session";

struct Fixture {
    state: Arc<AppState>,
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    stored: Vec<Vec<rusqlite::types::Value>>,
    accounts: Vec<Value>,
    creds: BTreeMap<i64, (String, String)>,
}

impl Fixture {
    fn new() -> Self {
        let state = Arc::new(AppState::new(
            String::new(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
        ));
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        Self { state }
    }

    async fn request(&self, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
        let response = build_router(self.state.clone())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("content-type", "application/json")
                    .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
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

    async fn add(&self, email: &str) -> i64 {
        let jwt = format!("PUBLIC-jwt-{email}");
        let key = format!("PUBLIC-api-key-{email}");
        let (status, reply) = self
            .request(
                "POST",
                "/api/accounts/add",
                json!({"email":email, "zcode_jwt":jwt, "api_key":key}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "account creation failed");
        let id = reply["id"].as_i64().unwrap();
        let stored: (String, String) = self
            .state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT zcode_jwt, api_key FROM accounts WHERE id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(stored.0.starts_with("vault1:"));
        assert!(stored.1.starts_with("vault1:"));
        assert_eq!(self.state.vault.decrypt(&stored.0).unwrap(), jwt);
        assert_eq!(self.state.vault.decrypt(&stored.1).unwrap(), key);
        id
    }

    fn snapshot(&self) -> Snapshot {
        let db = self.state.db.lock().unwrap();
        let mut stmt = db.prepare("SELECT * FROM accounts ORDER BY id").unwrap();
        let columns = stmt.column_count();
        let stored = stmt
            .query_map([], |row| {
                (0..columns)
                    .map(|column| row.get::<_, rusqlite::types::Value>(column))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let accounts = self
            .state
            .accounts
            .lock()
            .unwrap()
            .iter()
            .map(|a| {
                json!({
                    "id":a.id, "email":a.email, "provider":a.provider,
                    "enabled":a.enabled, "status":a.status,
                    "cooling_until":a.cooling_until, "paid_cooling_until":a.paid_cooling_until,
                    "paid_fallback":a.paid_fallback, "zcode_jwt":a.zcode_jwt, "api_key":a.api_key,
                    "account_group":a.account_group, "remaining":a.remaining, "priority":a.priority,
                })
            })
            .collect();
        let creds = self
            .state
            .creds
            .lock()
            .unwrap()
            .iter()
            .map(|(&id, creds)| (id, (creds.zcode_jwt.clone(), creds.api_key.clone())))
            .collect();
        Snapshot {
            stored,
            accounts,
            creds,
        }
    }

    fn assert_enabled(&self, id: i64, expected: bool) {
        let enabled: bool = self
            .state
            .db
            .lock()
            .unwrap()
            .query_row("SELECT enabled FROM accounts WHERE id = ?1", [id], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(enabled, expected, "persisted enabled state");
        let accounts = self.state.accounts.lock().unwrap();
        let account = accounts.iter().find(|a| a.id == id).unwrap();
        assert_eq!(account.enabled, expected, "live enabled state");
    }

    fn assert_selected(&self, expected: Option<i64>) {
        let accounts = self.state.accounts.lock().unwrap();
        let mut selector = self.state.selector.lock().unwrap();
        let skip = Default::default();
        for channel in [CHANNEL_FREE, CHANNEL_PAID] {
            let selected = selector.select_sticky_channel(
                &accounts,
                &SelectionQuery {
                    provider: "zai",
                    group: "",
                    skip: &skip,
                    channel,
                    now_unix: now_secs(),
                },
                "PUBLIC-account-mutation-sticky-session",
            );
            assert_eq!(selected.account.map(|a| a.id), expected, "{channel}");
        }
    }

    fn sql(&self, sql: &str) {
        self.state.db.lock().unwrap().execute_batch(sql).unwrap();
    }
}

#[tokio::test]
async fn deleting_a_numeric_account_id_removes_only_that_account_and_its_credentials() {
    let f = Fixture::new();
    let survivor = f.add("survivor@example.invalid").await;
    let before = f.snapshot();
    let removed = f.add("removed@example.invalid").await;
    let (status, _) = f
        .request("DELETE", &format!("/api/accounts/{removed}"), Value::Null)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "numeric delete route must be reachable"
    );
    assert_eq!(f.snapshot(), before, "delete changed the surviving account");
    let (status, listed) = f.request("GET", "/api/accounts", Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    let accounts = listed["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0]["id"], survivor);
}

#[tokio::test]
async fn enabled_toggle_persists_and_revalidates_free_paid_and_sticky_selection() {
    let f = Fixture::new();
    let id = f.add("toggle@example.invalid").await;
    let before = f.snapshot();
    f.assert_enabled(id, true);
    f.assert_selected(Some(id));
    for enabled in [false, true] {
        let (status, _) = f
            .request(
                "PUT",
                &format!("/api/accounts/{id}/enabled"),
                json!({"enabled":enabled}),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "numeric enabled route must be reachable"
        );
        f.assert_enabled(id, enabled);
        f.assert_selected(if enabled { Some(id) } else { None });
        let after = f.snapshot();
        assert_eq!(after.creds, before.creds, "toggle changed live credentials");
        if enabled {
            assert_eq!(after, before, "re-enabling changed other account fields");
        }
    }
}

#[tokio::test]
async fn missing_ids_return_404_and_malformed_ids_return_400_without_mutation() {
    let f = Fixture::new();
    let id = f.add("unchanged@example.invalid").await;
    let before = f.snapshot();
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for (input, status) in [
        ((id + 1000).to_string(), StatusCode::NOT_FOUND),
        ("not-an-id".into(), StatusCode::BAD_REQUEST),
        ("9223372036854775808".into(), StatusCode::BAD_REQUEST),
    ] {
        for (method, suffix, body) in [
            ("DELETE", "", Value::Null),
            ("PUT", "/enabled", json!({"enabled":false})),
        ] {
            let path = format!("/api/accounts/{input}{suffix}");
            let (got, _) = f.request(method, &path, body).await;
            actual.push((method, path.clone(), got));
            expected.push((method, path, status));
            assert_eq!(f.snapshot(), before, "invalid target changed account state");
        }
    }
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn failed_delete_returns_500_and_keeps_database_memory_and_credentials() {
    let f = Fixture::new();
    let id = f.add("delete-failure@example.invalid").await;
    let before = f.snapshot();
    f.sql(
        "CREATE TRIGGER fail_account_delete BEFORE DELETE ON accounts
         BEGIN SELECT RAISE(FAIL, 'PUBLIC injected delete failure'); END;",
    );
    let (status, _) = f
        .request("DELETE", &format!("/api/accounts/{id}"), Value::Null)
        .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(f.snapshot(), before);
}

#[tokio::test]
async fn failed_enabled_update_returns_500_and_keeps_database_memory_and_credentials() {
    let f = Fixture::new();
    let id = f.add("update-failure@example.invalid").await;
    let before = f.snapshot();
    f.sql(
        "CREATE TRIGGER fail_account_enabled BEFORE UPDATE OF enabled ON accounts
         BEGIN SELECT RAISE(FAIL, 'PUBLIC injected enabled failure'); END;",
    );
    let (status, _) = f
        .request(
            "PUT",
            &format!("/api/accounts/{id}/enabled"),
            json!({"enabled":false}),
        )
        .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(f.snapshot(), before);
    f.assert_selected(Some(id));
}
