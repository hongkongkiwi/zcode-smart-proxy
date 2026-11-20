use std::{collections::BTreeMap, sync::Arc};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use rusqlite::types::Value as SqlValue;
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_core::AccountView;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
    store,
    vault::Vault,
};

const SESSION: &str = "PUBLIC-account-update-test-session";

struct Fixture {
    state: Arc<AppState>,
    id: i64,
}

#[derive(Clone, Debug, PartialEq)]
struct Snapshot {
    stored: Vec<BTreeMap<String, SqlValue>>,
    accounts: Vec<Value>,
    creds: BTreeMap<i64, (String, String)>,
}

impl Fixture {
    fn new() -> Self {
        let db = store::open(":memory:");
        let vault = Vault::from_secret("PUBLIC account update fixture seed").unwrap();
        let mut id = 0;
        for email in ["updated@example.invalid", "survivor@example.invalid"] {
            let jwt = format!("PUBLIC-jwt-{email}");
            let key = format!("PUBLIC-api-key-{email}");
            let account = AccountView {
                email: email.into(),
                provider: "zai".into(),
                enabled: true,
                status: "cooling".into(),
                cooling_until: 4_000_000_000,
                paid_cooling_until: 4_000_000_001,
                paid_fallback: true,
                account_group: "original".into(),
                remaining: 42.5,
                priority: 37,
                ..Default::default()
            };
            let inserted =
                store::insert_account_encrypted(&db, &vault, &account, &jwt, &key).unwrap();
            if id == 0 {
                id = inserted;
            }
        }
        let state = AppState::try_from_db_with_vault(
            String::new(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
            db,
            vault,
        )
        .unwrap();
        Self::from_state(state, id)
    }

    fn from_state(state: AppState, id: i64) -> Self {
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

    fn reload(self) -> Self {
        let state = Arc::try_unwrap(self.state).ok().unwrap();
        let state = AppState::try_from_db_with_vault(
            state.root_key,
            state.upstream,
            state.db.into_inner().unwrap(),
            state.vault,
        )
        .unwrap();
        Self::from_state(state, self.id)
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Value,
        authenticated: bool,
        origin: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost:8080")
            .header("content-type", "application/json");
        if authenticated {
            request = request.header("cookie", format!("{SESSION_COOKIE}={SESSION}"));
        }
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        let response = build_router(self.state.clone())
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
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

    async fn put(&self, body: Value) -> (StatusCode, Value) {
        self.request(
            "PUT",
            &format!("/api/accounts/{}", self.id),
            body,
            true,
            None,
        )
        .await
    }

    async fn save(&self, body: Value) {
        let (status, reply) = self.put(body).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "PUT account update must be reachable"
        );
        assert_eq!(reply, json!({"success":true}));
    }

    fn snapshot(&self) -> Snapshot {
        let db = self.state.db.lock().unwrap();
        let mut stmt = db.prepare("SELECT * FROM accounts ORDER BY id").unwrap();
        let columns: Vec<_> = stmt
            .column_names()
            .iter()
            .map(|name| name.to_string())
            .collect();
        let stored = stmt
            .query_map([], |row| {
                columns
                    .iter()
                    .enumerate()
                    .map(|(i, name)| Ok((name.clone(), row.get::<_, SqlValue>(i)?)))
                    .collect::<rusqlite::Result<BTreeMap<_, _>>>()
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

    async fn assert_updated(&self, before: &Snapshot, fields: Value) {
        let mut expected = before.clone();
        let row = expected
            .stored
            .iter_mut()
            .find(|row| row.get("id") == Some(&SqlValue::Integer(self.id)))
            .unwrap();
        let account = expected
            .accounts
            .iter_mut()
            .find(|a| a["id"] == self.id)
            .unwrap();
        for (key, value) in fields.as_object().unwrap() {
            let stored_key = if key == "group" {
                "account_group"
            } else {
                key.as_str()
            };
            let sql_value = match value {
                Value::String(value) => SqlValue::Text(value.clone()),
                Value::Bool(value) => SqlValue::Integer(i64::from(*value)),
                Value::Number(value) => SqlValue::Integer(value.as_i64().unwrap()),
                _ => panic!("unexpected fixture field type"),
            };
            row.insert(stored_key.into(), sql_value);
            if key != "remark" {
                account[stored_key] = value.clone();
            }
        }
        assert_eq!(
            self.snapshot(),
            expected,
            "update must preserve all unrelated state"
        );
        let (status, listed) = self
            .request("GET", "/api/accounts", Value::Null, true, None)
            .await;
        assert_eq!(status, StatusCode::OK);
        let accounts = listed["accounts"].as_array().unwrap();
        assert_eq!(accounts.len(), 2);
        let account = accounts.iter().find(|a| a["id"] == self.id).unwrap();
        for key in ["group", "remark", "enabled", "priority", "paid_fallback"] {
            assert_eq!(account[key], fields[key], "listed {key}");
        }
        for account in accounts {
            assert!(account.get("zcode_jwt").is_none());
            assert!(account.get("api_key").is_none());
        }
        let serialized = listed.to_string();
        for (jwt, key) in before.creds.values() {
            assert!(!serialized.contains(jwt), "list leaked a JWT");
            assert!(!serialized.contains(key), "list leaked an API key");
        }
        assert!(
            !serialized.contains("vault1:"),
            "list leaked stored ciphertext"
        );
    }
}

#[tokio::test]
async fn update_persists_all_fields_preserves_omitted_state_and_reloads_redacted_metadata() {
    let f = Fixture::new();
    let before = f.snapshot();
    let mut fields = json!({
        "group":"eu,failover", "remark":"PUBLIC note: 测试", "enabled":true,
        "priority":1, "paid_fallback":false, "status":"cooling",
    });
    f.save(json!({
        "group":"eu,failover", "remark":"PUBLIC note: 测试", "enabled":true,
        "priority":1, "paid_fallback":false,
    }))
    .await;
    f.assert_updated(&before, fields.clone()).await;
    let f = f.reload();
    f.assert_updated(&before, fields.clone()).await;
    for (enabled, status) in [(false, "disabled"), (true, "active")] {
        f.save(json!({"enabled":enabled})).await;
        fields["enabled"] = json!(enabled);
        fields["status"] = json!(status);
        f.assert_updated(&before, fields.clone()).await;
    }
    f.save(json!({"group":"", "remark":"", "priority":9999}))
        .await;
    fields["group"] = json!("");
    fields["remark"] = json!("");
    fields["priority"] = json!(9999);
    f.assert_updated(&before, fields.clone()).await;
    let unchanged = f.snapshot();
    for body in [
        json!({}),
        json!({
            "group":null, "remark":null, "enabled":null, "priority":null, "paid_fallback":null,
        }),
    ] {
        f.save(body).await;
        assert_eq!(
            f.snapshot(),
            unchanged,
            "omitted or null fields must be preserved"
        );
    }
    let f = f.reload();
    f.assert_updated(&before, fields).await;
}

#[tokio::test]
async fn invalid_priority_or_field_type_rejects_the_entire_update() {
    let f = Fixture::new();
    let before = f.snapshot();
    for (key, invalid) in [
        ("priority", json!(0)),
        ("priority", json!(-1)),
        ("priority", json!(10000)),
        ("priority", json!(1.5)),
        ("priority", json!("2")),
        ("priority", json!(true)),
        ("group", json!(42)),
        ("remark", json!(false)),
        ("enabled", json!("false")),
        ("paid_fallback", json!(0)),
    ] {
        let mut body = json!({
            "group":"changed", "remark":"PUBLIC invalid batch note", "enabled":false,
            "priority":2, "paid_fallback":false,
        });
        body[key] = invalid;
        let (status, _) = f.put(body.clone()).await;
        assert_eq!(f.snapshot(), before, "invalid batch changed state: {body}");
        assert_eq!(status, StatusCode::BAD_REQUEST, "invalid batch: {body}");
    }
}

#[tokio::test]
async fn missing_and_malformed_account_ids_return_404_and_400_without_mutation() {
    let f = Fixture::new();
    let before = f.snapshot();
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for (id, status) in [
        ((f.id + 1000).to_string(), StatusCode::NOT_FOUND),
        ("not-an-id".into(), StatusCode::BAD_REQUEST),
        ("9223372036854775808".into(), StatusCode::BAD_REQUEST),
    ] {
        let (got, _) = f
            .request(
                "PUT",
                &format!("/api/accounts/{id}"),
                json!({"group":"changed"}),
                true,
                None,
            )
            .await;
        actual.push((id.clone(), got));
        expected.push((id, status));
        assert_eq!(f.snapshot(), before, "invalid target changed state");
    }
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn sql_failure_returns_500_and_rolls_back_metadata_priority_and_live_state() {
    let f = Fixture::new();
    let before = f.snapshot();
    f.state
        .db
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_account_priority BEFORE UPDATE OF priority ON accounts
         BEGIN SELECT RAISE(FAIL, 'PUBLIC injected priority update failure'); END;",
        )
        .unwrap();
    let (status, _) = f
        .put(json!({
            "group":"changed", "remark":"PUBLIC rollback note", "enabled":false,
            "priority":2, "paid_fallback":false,
        }))
        .await;
    assert_eq!(
        f.snapshot(),
        before,
        "failed update was partially published or persisted"
    );
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn account_updates_require_a_session_and_reject_wrong_origin_without_mutation() {
    let f = Fixture::new();
    let before = f.snapshot();
    for (authenticated, origin, expected) in [
        (false, None, StatusCode::UNAUTHORIZED),
        (true, Some("http://localhost:8081"), StatusCode::FORBIDDEN),
    ] {
        let (status, _) = f
            .request(
                "PUT",
                &format!("/api/accounts/{}", f.id),
                json!({
                    "group":"changed", "remark":"PUBLIC rejected note", "enabled":false,
                    "priority":2, "paid_fallback":false,
                }),
                authenticated,
                origin,
            )
            .await;
        assert_eq!(f.snapshot(), before, "rejected update changed state");
        assert_eq!(status, expected);
    }
}
