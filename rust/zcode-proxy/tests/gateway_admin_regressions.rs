use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use rusqlite::types::Value as SqlValue;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use zcode_proxy::{
    admin::{record_usage_db, SESSION_COOKIE},
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls, UsageRecord},
};

const SESSION: &str = "PUBLIC-gateway-admin-session";
const PASSWORD: &str = "PUBLIC-gateway-admin-password";
const ROOT: &str = "PUBLIC-gateway-admin-root";
const HOST: &str = "localhost:8080";

struct Fixture(Arc<AppState>);

type Snapshot = (Vec<Vec<SqlValue>>, Vec<Value>);

fn digest(secret: &str) -> String {
    format!("{:x}", Sha256::digest(secret.as_bytes()))
}

fn create_body(name: &str) -> Value {
    json!({"name":name, "verify_password":PASSWORD})
}

impl Fixture {
    fn new() -> Self {
        let state = AppState::new(
            ROOT.into(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
        );
        state
            .persist_settings(&[("admin_password_hash", &bcrypt::hash(PASSWORD, 4).unwrap())])
            .unwrap();
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        Self(Arc::new(state))
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Value,
        session: bool,
        origin: Option<&str>,
        key: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", HOST)
            .header("content-type", "application/json");
        if session {
            builder = builder.header("cookie", format!("{SESSION_COOKIE}={SESSION}"));
        }
        if let Some(origin) = origin {
            builder = builder.header("origin", origin);
        }
        if let Some(key) = key {
            builder = builder.header("authorization", format!("Bearer {key}"));
        }
        let mut request = builder.body(Body::from(body.to_string())).unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "192.0.2.10:41000".parse::<SocketAddr>().unwrap(),
        ));
        let response = build_router(self.0.clone()).oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn admin(&self, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
        self.send(method, path, body, true, None, None).await
    }

    async fn data(&self, key: &str, model: Option<&str>) -> (StatusCode, Value) {
        let (method, path, body) = match model {
            Some(model) => (
                "POST",
                "/v1/messages",
                json!({"model":model, "max_tokens":1, "messages":[]}),
            ),
            None => ("GET", "/v1/models", Value::Null),
        };
        self.send(method, path, body, false, None, Some(key)).await
    }

    async fn create(&self, body: Value) -> (i64, String, Value) {
        let (status, reply) = self.admin("POST", "/api/keys", body).await;
        assert_eq!(status, StatusCode::OK, "POST /api/keys must create a key");
        let id = reply["key"]["id"].as_i64().unwrap();
        assert!(id > 0);
        let secret = reply["key"]["key"].as_str().unwrap().to_owned();
        assert!(secret.starts_with("sk-") && secret.len() > 20);
        assert!(reply["key"].get("key_hash").is_none());
        (id, secret, reply["key"].clone())
    }

    async fn update(&self, id: i64, body: Value) -> Value {
        let (status, reply) = self.admin("PUT", &format!("/api/keys/{id}"), body).await;
        assert_eq!(status, StatusCode::OK, "PUT /api/keys/{{id}} must update");
        reply["key"].clone()
    }

    async fn list(&self) -> Vec<Value> {
        let (status, reply) = self.admin("GET", "/api/keys", Value::Null).await;
        assert_eq!(status, StatusCode::OK, "GET /api/keys must list keys");
        reply["keys"].as_array().unwrap().clone()
    }

    fn sql(&self, sql: &str) {
        self.0.db.lock().unwrap().execute_batch(sql).unwrap();
    }

    fn snapshot(&self) -> Snapshot {
        let db = self.0.db.lock().unwrap();
        let mut stmt = db
            .prepare("SELECT * FROM gateway_keys ORDER BY id")
            .unwrap();
        let columns = stmt.column_count();
        let stored = stmt
            .query_map([], |row| {
                (0..columns)
                    .map(|i| row.get(i))
                    .collect::<rusqlite::Result<Vec<SqlValue>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let live = self
            .0
            .named_keys
            .lock()
            .unwrap()
            .iter()
            .map(|key| {
                json!({
                    "id":key.id, "name":key.name, "key_hash":key.key_hash,
                    "enabled":key.enabled, "models":key.models, "rpm_limit":key.rpm_limit,
                    "rate_5h":key.rate_5h, "rate_1d":key.rate_1d, "rate_7d":key.rate_7d,
                    "quota_total":key.quota_total, "quota_used":key.quota_used,
                })
            })
            .collect();
        (stored, live)
    }

    fn charge(&self, id: i64, amount: i64) {
        record_usage_db(
            &self.0,
            UsageRecord {
                account_id: 0,
                status: 200,
                gateway_key_id: id,
                quota_charge: amount,
            },
        )
        .unwrap();
    }

    fn reload(self) -> Self {
        let state = Arc::try_unwrap(self.0).ok().unwrap();
        let loaded = AppState::try_from_db_with_vault(
            state.root_key,
            state.upstream,
            state.db.into_inner().unwrap(),
            state.vault,
        )
        .unwrap();
        loaded
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        Self(Arc::new(loaded))
    }
}

fn assert_fields(actual: &Value, expected: Value) {
    for (field, value) in expected.as_object().unwrap() {
        assert_eq!(&actual[field], value, "gateway key field {field}");
    }
}

fn assert_redacted(value: &Value, secret: &str) {
    assert!(
        value.get("key").is_none(),
        "plaintext must be shown only on creation"
    );
    assert!(
        value.get("key_hash").is_none(),
        "hash must not be serialized"
    );
    assert!(
        !value.to_string().contains(secret),
        "plaintext leaked into metadata"
    );
    assert!(value["key_prefix"].as_str().is_some_and(|s| !s.is_empty()));
}

#[tokio::test]
async fn key_crud_persists_policy_and_shows_plaintext_only_once() {
    let f = Fixture::new();
    assert!(f.list().await.is_empty());
    let mut body = create_body("  client one  ");
    body["models"] = json!(" zai/GLM-5.3, GLM-5.2,,glm-5.3 ");
    body["rpm_limit"] = json!(11);
    body["rate_5h"] = json!(12);
    body["rate_1d"] = json!(13);
    body["rate_7d"] = json!(14);
    body["quota_total"] = json!(900);
    let (id, secret, created) = f.create(body).await;
    let policy = json!({
        "id":id, "name":"client one", "enabled":true, "models":"glm-5.3,glm-5.2",
        "rpm_limit":11, "rate_5h":12, "rate_1d":13, "rate_7d":14,
        "quota_total":900, "quota_used":0,
    });
    assert_fields(&created, policy.clone());
    let hash: String =
        f.0.db
            .lock()
            .unwrap()
            .query_row(
                "SELECT key_hash FROM gateway_keys WHERE id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
    assert!(
        hash == digest(&secret),
        "database must store the SHA-256 key digest"
    );
    let (stored, _) = f.snapshot();
    assert!(
        !format!("{stored:?}").contains(&secret),
        "plaintext stored in gateway row"
    );
    let prefix = created["key_prefix"].as_str().unwrap();
    assert!(prefix.starts_with(&secret[..10]) && !prefix.contains(&secret));
    let listed = f.list().await;
    assert_eq!(listed.len(), 1);
    assert_fields(&listed[0], policy.clone());
    assert_redacted(&listed[0], &secret);
    assert_eq!(listed[0]["key_prefix"], created["key_prefix"]);

    let updated = f
        .update(
            id,
            json!({
                "name":"renamed", "enabled":false, "models":" GLM-5.2, zai/GLM-5.2 ",
                "rpm_limit":21, "rate_5h":22, "rate_1d":23, "rate_7d":24, "quota_total":700,
            }),
        )
        .await;
    let edited = json!({
        "id":id, "name":"renamed", "enabled":false, "models":"glm-5.2",
        "rpm_limit":21, "rate_5h":22, "rate_1d":23, "rate_7d":24,
        "quota_total":700, "quota_used":0,
    });
    assert_fields(&updated, edited.clone());
    assert_redacted(&updated, &secret);
    assert_eq!(updated["key_prefix"], created["key_prefix"]);
    let partial = f.update(id, json!({"name":"renamed"})).await;
    assert_fields(&partial, edited.clone());
    let f = f.reload();
    let listed = f.list().await;
    assert_eq!(listed.len(), 1);
    assert_fields(&listed[0], edited);
    assert_redacted(&listed[0], &secret);
    assert_eq!(listed[0]["key_prefix"], created["key_prefix"]);
    let (status, reply) = f
        .admin("DELETE", &format!("/api/keys/{id}"), Value::Null)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reply["success"], true);
    assert!(f.list().await.is_empty());
    assert!(f.snapshot().0.is_empty());
    assert!(f.snapshot().1.is_empty());
    assert_eq!(f.data(&secret, None).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_key_policies_and_targets_leave_existing_keys_unchanged() {
    let f = Fixture::new();
    let (id, secret, _) = f.create(create_body("unchanged")).await;
    let (other, _, _) = f.create(create_body("other")).await;
    let before = f.snapshot();
    let invalid = [
        json!({"name":"  "}),
        json!({"name":"x".repeat(65)}),
        json!({"rpm_limit":-1}),
        json!({"rpm_limit":100001}),
        json!({"rate_5h":-1}),
        json!({"rate_5h":10000001}),
        json!({"rate_1d":-1}),
        json!({"rate_1d":10000001}),
        json!({"rate_7d":-1}),
        json!({"rate_7d":10000001}),
        json!({"quota_total":-1}),
    ];
    for patch in invalid {
        let mut body = create_body("invalid");
        for (field, value) in patch.as_object().unwrap() {
            body[field] = value.clone();
        }
        for (method, path, body) in [
            ("POST", "/api/keys".to_owned(), body),
            ("PUT", format!("/api/keys/{id}"), patch.clone()),
        ] {
            let (status, _) = f.admin(method, &path, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {path}: {patch}");
            assert_eq!(f.snapshot(), before);
        }
    }
    for (method, path, body) in [
        ("POST", "/api/keys".to_owned(), create_body(" unchanged ")),
        (
            "PUT",
            format!("/api/keys/{other}"),
            json!({"name":" unchanged "}),
        ),
    ] {
        assert_eq!(f.admin(method, &path, body).await.0, StatusCode::CONFLICT);
        assert_eq!(f.snapshot(), before);
    }
    for (target, expected) in [
        ("not-an-id".to_owned(), StatusCode::BAD_REQUEST),
        ("9223372036854775808".to_owned(), StatusCode::BAD_REQUEST),
        ((other + 1000).to_string(), StatusCode::NOT_FOUND),
    ] {
        // Go deletion is idempotent for absent numeric IDs; update requires an existing row.
        assert_eq!(
            f.admin(
                "PUT",
                &format!("/api/keys/{target}"),
                json!({"enabled":false})
            )
            .await
            .0,
            expected,
        );
        if expected == StatusCode::BAD_REQUEST {
            assert_eq!(
                f.admin("DELETE", &format!("/api/keys/{target}"), Value::Null)
                    .await
                    .0,
                expected,
            );
        }
        assert_eq!(f.snapshot(), before);
    }
    let updated = f
        .update(
            id,
            json!({
                "rpm_limit":100000, "rate_5h":10000000, "rate_1d":10000000,
                "rate_7d":10000000, "quota_total":0, "models":"",
            }),
        )
        .await;
    assert_fields(
        &updated,
        json!({
            "rpm_limit":100000, "rate_5h":10000000, "rate_1d":10000000,
            "rate_7d":10000000, "quota_total":0, "models":"",
        }),
    );
    assert_eq!(f.data(&secret, None).await.0, StatusCode::OK);
}

#[tokio::test]
async fn key_admin_requires_session_origin_and_current_password_for_creation_only() {
    let f = Fixture::new();
    let empty = f.snapshot();
    for (method, path, body) in [
        ("GET", "/api/keys", Value::Null),
        ("POST", "/api/keys", create_body("unauthenticated")),
        ("PUT", "/api/keys/1", json!({"enabled":false})),
        ("DELETE", "/api/keys/1", Value::Null),
    ] {
        assert_eq!(
            f.send(method, path, body, false, None, Some(ROOT)).await.0,
            StatusCode::UNAUTHORIZED,
            "root API key must not authorize {method} {path}",
        );
    }
    for body in [
        json!({"name":"no-password"}),
        json!({"name":"wrong-password", "verify_password":"PUBLIC-wrong"}),
        json!({"name":"wrong-field", "password":PASSWORD, "admin_password":PASSWORD}),
    ] {
        assert_eq!(
            f.admin("POST", "/api/keys", body).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(f.snapshot(), empty);
    }
    for origin in ["http://localhost:8081", "https://evil.invalid", "null"] {
        assert_eq!(
            f.send(
                "POST",
                "/api/keys",
                create_body("cross-origin"),
                true,
                Some(origin),
                None
            )
            .await
            .0,
            StatusCode::FORBIDDEN,
        );
        assert_eq!(f.snapshot(), empty);
    }
    let (status, reply) = f
        .send(
            "POST",
            "/api/keys",
            create_body("same-host"),
            true,
            Some("https://localhost:8080"),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Origin scheme may differ behind TLS termination"
    );
    let id = reply["key"]["id"].as_i64().unwrap();
    let before = f.snapshot();
    for (method, path, body) in [
        ("PUT", format!("/api/keys/{id}"), json!({"enabled":false})),
        ("DELETE", format!("/api/keys/{id}"), Value::Null),
    ] {
        assert_eq!(
            f.send(
                method,
                &path,
                body,
                true,
                Some("http://localhost:8081"),
                None
            )
            .await
            .0,
            StatusCode::FORBIDDEN,
        );
        assert_eq!(f.snapshot(), before);
    }
    let current_password = "PUBLIC-rotated-gateway-admin-password";
    f.0.persist_settings(&[(
        "admin_password_hash",
        &bcrypt::hash(current_password, 4).unwrap(),
    )])
    .unwrap();
    assert_eq!(
        f.admin("POST", "/api/keys", create_body("stale-password"))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, _) = f
        .admin(
            "POST",
            "/api/keys",
            json!({
                "name":"current-password", "verify_password":current_password,
            }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "step-up must use the current administrator hash"
    );
    // Go requires password step-up only when minting the one-time plaintext key.
    f.update(id, json!({"enabled":false})).await;
    assert_eq!(
        f.admin("DELETE", &format!("/api/keys/{id}"), Value::Null)
            .await
            .0,
        StatusCode::OK
    );
    f.0.sessions
        .lock()
        .unwrap()
        .insert(SESSION.into(), now_secs() - 1);
    assert_eq!(
        f.admin("GET", "/api/keys", Value::Null).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn key_sql_failures_return_500_without_publishing_partial_database_or_live_policy() {
    let f = Fixture::new();
    let (id, secret, _) = f.create(create_body("durable")).await;
    f.charge(id, 9);
    let before = f.snapshot();
    for (event, method, path, body) in [
        (
            "INSERT",
            "POST",
            "/api/keys".to_owned(),
            create_body("failed-create"),
        ),
        (
            "UPDATE",
            "PUT",
            format!("/api/keys/{id}"),
            json!({"enabled":false, "name":"lost"}),
        ),
        ("DELETE", "DELETE", format!("/api/keys/{id}"), Value::Null),
    ] {
        f.sql(&format!(
            "CREATE TRIGGER fail_gateway_write BEFORE {event} ON gateway_keys
             BEGIN SELECT RAISE(FAIL, 'PUBLIC injected gateway write failure'); END;"
        ));
        let (status, reply) = f.admin(method, &path, body).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{method} {path}");
        assert!(
            reply.get("key").is_none(),
            "failed write must not return a new key"
        );
        assert_eq!(
            f.snapshot(),
            before,
            "failed {method} {path} changed DB or live keys"
        );
        assert_eq!(f.data(&secret, None).await.0, StatusCode::OK);
        f.sql("DROP TRIGGER fail_gateway_write");
    }
    f.sql("ALTER TABLE gateway_keys RENAME TO unavailable_gateway_keys");
    let (status, _) = f.admin("GET", "/api/keys", Value::Null).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "failed list must not masquerade as empty success"
    );
    f.sql("ALTER TABLE unavailable_gateway_keys RENAME TO gateway_keys");
    assert_eq!(f.snapshot(), before);
    assert_eq!(f.list().await[0]["quota_used"], 9);
}

#[tokio::test]
async fn created_keys_immediately_obey_auth_gates_and_policy_edits_preserve_rate_history() {
    let f = Fixture::new();
    let mut body = create_body("live-policy");
    body["models"] = json!("zai/GLM-5.3");
    body["quota_total"] = json!(5);
    let (id, secret, _) = f.create(body).await;
    assert_eq!(
        f.data(&secret, None).await.0,
        StatusCode::OK,
        "created key must authenticate immediately"
    );
    assert_eq!(
        f.data("PUBLIC-not-a-created-key", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, error) = f.data(&secret, Some("glm-5.2")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("model not allowed"));
    f.update(id, json!({"models":"glm-5.2"})).await;
    assert_eq!(
        f.data(&secret, Some("glm-5.3")).await.0,
        StatusCode::FORBIDDEN
    );
    f.charge(id, 5);
    let (status, error) = f.data(&secret, Some("glm-5.2")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("quota exhausted"));
    let updated = f.update(id, json!({"quota_total":0})).await;
    assert_eq!(
        updated["quota_used"], 5,
        "policy edit must retain accounted usage"
    );
    assert_eq!(f.snapshot().1[0]["quota_used"], 5);
    let stored_usage: i64 =
        f.0.db
            .lock()
            .unwrap()
            .query_row(
                "SELECT quota_used FROM gateway_keys WHERE id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
    assert_eq!(stored_usage, 5);
    assert_eq!(
        f.data(&secret, Some("glm-5.3")).await.0,
        StatusCode::FORBIDDEN,
        "zero quota is unlimited but must retain whitelist enforcement"
    );
    f.update(id, json!({"enabled":false})).await;
    assert_eq!(f.data(&secret, None).await.0, StatusCode::UNAUTHORIZED);
    f.update(id, json!({"enabled":true})).await;
    assert_eq!(f.data(&secret, None).await.0, StatusCode::OK);

    for (field, label) in [
        ("rpm_limit", "rpm"),
        ("rate_5h", "5h"),
        ("rate_1d", "24h"),
        ("rate_7d", "7d"),
    ] {
        let mut body = create_body(field);
        body[field] = json!(1);
        let (limited_id, limited_secret, _) = f.create(body).await;
        assert_eq!(f.data(&limited_secret, None).await.0, StatusCode::OK);
        let (status, error) = f.data(&limited_secret, None).await;
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "{field} must gate created keys"
        );
        assert!(error["error"]["message"].as_str().unwrap().contains(label));
        f.update(limited_id, json!({"name":format!("renamed-{field}")}))
            .await;
        assert_eq!(
            f.data(&limited_secret, None).await.0,
            StatusCode::TOO_MANY_REQUESTS,
            "metadata update must retain {field} history"
        );
        f.update(limited_id, json!({field:0})).await;
        assert_eq!(
            f.data(&limited_secret, None).await.0,
            StatusCode::OK,
            "zero {field} is unlimited immediately"
        );
        assert_eq!(
            f.data(ROOT, None).await.0,
            StatusCode::OK,
            "root key bypass must remain intact"
        );
    }
}
