// Regression tests for the auto_reset_* settings whitelist on PUT/GET
// /api/settings: exact-string flags, bounded integer strings, atomic
// batch rejection, no default seeding, storage rollback, auth gates.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
};

const HOST: &str = "localhost:8080";
const SESSION: &str = "PUBLIC-autoreset-settings-session";
const AUTO_RESET_KEYS: [&str; 5] = [
    "auto_reset_enabled",
    "auto_reset_expiry_enabled",
    "auto_reset_min_wait_minutes",
    "auto_reset_expiry_spend_minutes",
    "auto_reset_min_wait_week_hours",
];

struct Fixture {
    state: Arc<AppState>,
}

impl Fixture {
    fn new() -> Self {
        Self::with_upstream("http://127.0.0.1:1/unused")
    }

    fn with_upstream(upstream: &str) -> Self {
        let state = Arc::new(AppState::new(
            String::new(),
            UpstreamUrls {
                zai: upstream.into(),
                zai_fallback: upstream.into(),
            },
        ));
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        Self { state }
    }

    async fn request(
        &self,
        method: &str,
        body: Option<Value>,
        session: bool,
        origin: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri("/api/settings")
            .header("host", HOST)
            .header("content-type", "application/json");
        if session {
            builder = builder.header("cookie", format!("{SESSION_COOKIE}={SESSION}"));
        }
        if let Some(origin) = origin {
            builder = builder.header("origin", origin);
        }
        let body = match body {
            Some(body) => Body::from(body.to_string()),
            None => Body::empty(),
        };
        let response = build_router(self.state.clone())
            .oneshot(builder.body(body).unwrap())
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
        self.request("PUT", Some(body), true, None).await
    }

    async fn get(&self) -> Value {
        let (status, body) = self.request("GET", None, true, None).await;
        assert_eq!(status, StatusCode::OK, "GET /api/settings body={body}");
        body
    }

    fn sql(&self, sql: &str) {
        self.state.db.lock().unwrap().execute_batch(sql).unwrap();
    }

    // Seed legacy plaintext directly so assertions do not depend on secret writes.
    fn seed_setting(&self, key: &str, value: &str) {
        self.state
            .db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO settings(key, value) VALUES(?1, ?2)",
                [key, value],
            )
            .unwrap();
        self.state
            .settings
            .lock()
            .unwrap()
            .insert(key.into(), value.into());
    }

    fn stored_settings(&self) -> BTreeMap<String, String> {
        let db = self.state.db.lock().unwrap();
        let mut stmt = db
            .prepare("SELECT key, value FROM settings ORDER BY key")
            .unwrap();
        let settings = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        settings
    }

    fn memory_settings(&self) -> BTreeMap<String, String> {
        self.state
            .settings
            .lock()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    fn assert_persisted(&self, key: &str, value: &str) {
        assert_eq!(
            self.state.setting(key).as_deref(),
            Some(value),
            "memory mirror for {key}"
        );
        assert_eq!(
            self.stored_settings().get(key).map(String::as_str),
            Some(value),
            "SQLite row for {key}"
        );
    }

    fn assert_absent(&self, key: &str) {
        assert_eq!(self.state.setting(key), None, "memory mirror for {key}");
        assert_eq!(
            self.stored_settings().get(key),
            None,
            "SQLite row for {key}"
        );
    }
}

fn valid_batch() -> Value {
    json!({
        "auto_reset_enabled": "1",
        "auto_reset_expiry_enabled": "0",
        "auto_reset_min_wait_minutes": "45",
        "auto_reset_expiry_spend_minutes": "60",
        "auto_reset_min_wait_week_hours": "24",
    })
}

async fn counting_upstream() -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let server = tokio::spawn(async move {
        loop {
            if listener.accept().await.is_ok() {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    (format!("http://{addr}"), hits, server)
}

#[tokio::test]
async fn auto_reset_settings_roundtrip_through_get_and_storage() {
    let f = Fixture::new();
    let (status, body) = f
        .put(json!({
            "auto_reset_enabled": "1",
            "auto_reset_expiry_enabled": "0",
            "auto_reset_min_wait_minutes": "1440",
            "auto_reset_expiry_spend_minutes": "60",
            "auto_reset_min_wait_week_hours": "168",
        }))
        .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    let mut updated: Vec<String> = body["updated"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    updated.sort();
    let mut expected: Vec<String> = AUTO_RESET_KEYS.iter().map(|k| k.to_string()).collect();
    expected.sort();
    assert_eq!(updated, expected, "updated must name exactly the five keys");
    let body = f.get().await;
    assert_eq!(
        body.as_object().unwrap().len(),
        5,
        "GET must return exactly the five persisted keys: {body}"
    );
    for (key, value) in [
        ("auto_reset_enabled", "1"),
        ("auto_reset_expiry_enabled", "0"),
        ("auto_reset_min_wait_minutes", "1440"),
        ("auto_reset_expiry_spend_minutes", "60"),
        ("auto_reset_min_wait_week_hours", "168"),
    ] {
        assert_eq!(body[key], json!(value), "GET value for {key}");
        f.assert_persisted(key, value);
    }
}

#[tokio::test]
async fn auto_reset_zero_boundary_values_roundtrip() {
    let f = Fixture::new();
    let (status, body) = f
        .put(json!({
            "auto_reset_enabled": "0",
            "auto_reset_expiry_enabled": "1",
            "auto_reset_min_wait_minutes": "0",
            "auto_reset_expiry_spend_minutes": "0",
            "auto_reset_min_wait_week_hours": "0",
        }))
        .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    let body = f.get().await;
    for (key, value) in [
        ("auto_reset_enabled", "0"),
        ("auto_reset_expiry_enabled", "1"),
        ("auto_reset_min_wait_minutes", "0"),
        ("auto_reset_expiry_spend_minutes", "0"),
        ("auto_reset_min_wait_week_hours", "0"),
    ] {
        assert_eq!(body[key], json!(value), "GET value for {key}");
        f.assert_persisted(key, value);
    }
}

#[tokio::test]
async fn absent_auto_reset_keys_gain_no_defaults() {
    let f = Fixture::new();
    let body = f.get().await;
    for key in AUTO_RESET_KEYS {
        assert!(
            body.get(key).is_none(),
            "fresh GET must not synthesize {key}: {body}"
        );
        f.assert_absent(key);
    }
    let (status, body) = f.put(json!({"auto_reset_enabled": "0"})).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(
        f.get().await["auto_reset_enabled"],
        json!("0"),
        "single-key write must persist"
    );
    f.assert_persisted("auto_reset_enabled", "0");
    for key in AUTO_RESET_KEYS
        .iter()
        .filter(|k| **k != "auto_reset_enabled")
    {
        f.assert_absent(key);
        assert!(
            f.get().await.get(key).is_none(),
            "partial write must not seed {key}"
        );
    }
}

#[tokio::test]
async fn invalid_auto_reset_values_reject_whole_batch() {
    let f = Fixture::new();
    f.seed_setting("gateway_paused", "0");
    let (status, body) = f
        .put(json!({"auto_reset_enabled": "1", "auto_reset_min_wait_minutes": "30"}))
        .await;
    assert_eq!(status, StatusCode::OK, "baseline write, body={body}");
    let cases: Vec<(&str, Value)> = vec![
        ("auto_reset_enabled", json!(true)),
        ("auto_reset_enabled", json!("true")),
        ("auto_reset_enabled", json!("2")),
        ("auto_reset_enabled", json!("")),
        ("auto_reset_enabled", json!(1)),
        ("auto_reset_enabled", json!(null)),
        ("auto_reset_expiry_enabled", json!(true)),
        ("auto_reset_expiry_enabled", json!("on")),
        ("auto_reset_min_wait_minutes", json!("-1")),
        ("auto_reset_min_wait_minutes", json!("1441")),
        ("auto_reset_min_wait_minutes", json!("abc")),
        ("auto_reset_min_wait_minutes", json!("1.5")),
        ("auto_reset_min_wait_minutes", json!(" 10")),
        ("auto_reset_min_wait_minutes", json!(60)),
        ("auto_reset_expiry_spend_minutes", json!("-5")),
        ("auto_reset_expiry_spend_minutes", json!("1441")),
        ("auto_reset_expiry_spend_minutes", json!("0x10")),
        ("auto_reset_min_wait_week_hours", json!("-1")),
        ("auto_reset_min_wait_week_hours", json!("169")),
        ("auto_reset_min_wait_week_hours", json!(null)),
        ("auto_reset_min_wait_week_hours", json!(24)),
    ];
    for (key, value) in cases {
        let mut body = json!({"gateway_paused": "1"});
        body[key] = value.clone();
        let before_db = f.stored_settings();
        let before_memory = f.memory_settings();
        let (status, reply) = f.put(body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{key}={value} must be rejected, reply={reply}"
        );
        assert_eq!(
            f.stored_settings(),
            before_db,
            "rejected batch must not touch SQLite: {key}={value}"
        );
        assert_eq!(
            f.memory_settings(),
            before_memory,
            "rejected batch must not touch the mirror: {key}={value}"
        );
    }
}

#[tokio::test]
async fn auto_reset_db_write_failure_returns_500_and_rolls_back() {
    let f = Fixture::new();
    f.seed_setting("gateway_paused", "0");
    f.sql(
        "CREATE TRIGGER fail_autoreset_insert BEFORE INSERT ON settings
         WHEN NEW.key LIKE 'auto_reset_%'
         BEGIN SELECT RAISE(FAIL, 'PUBLIC injected autoreset failure'); END;
         CREATE TRIGGER fail_autoreset_update BEFORE UPDATE ON settings
         WHEN NEW.key LIKE 'auto_reset_%'
         BEGIN SELECT RAISE(FAIL, 'PUBLIC injected autoreset failure'); END;",
    );
    let before_db = f.stored_settings();
    let before_memory = f.memory_settings();
    let (status, body) = f.put(valid_batch()).await;
    assert!(
        status.is_server_error(),
        "trigger failure must surface as 5xx, got {status} body={body}"
    );
    assert_eq!(
        f.stored_settings(),
        before_db,
        "failed write must roll back SQLite"
    );
    assert_eq!(
        f.memory_settings(),
        before_memory,
        "failed write must not publish to the mirror"
    );
}

#[tokio::test]
async fn auto_reset_settings_keep_session_and_origin_gates() {
    let f = Fixture::new();
    let body = valid_batch();
    let before_db = f.stored_settings();
    let before_memory = f.memory_settings();
    let (status, reply) = f.request("PUT", Some(body.clone()), false, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "reply={reply}");
    let (status, reply) = f
        .request("PUT", Some(body), true, Some("http://evil.example"))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "reply={reply}");
    assert_eq!(f.stored_settings(), before_db, "gated PUT reached SQLite");
    assert_eq!(
        f.memory_settings(),
        before_memory,
        "gated PUT reached mirror"
    );
}

#[tokio::test]
async fn unknown_keys_ignored_and_secrets_absent_from_get() {
    let f = Fixture::new();
    f.seed_setting("admin_password_hash", "PUBLIC bcrypt hash fixture");
    f.seed_setting("totp_secret", "PUBLIC base32 secret fixture");
    let before_db = f.stored_settings();
    let before_memory = f.memory_settings();
    let (status, body) = f
        .put(json!({"totally_new_setting": "1", "auto_reset_enabled": "1"}))
        .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    let updated: Vec<&str> = body["updated"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        !updated.contains(&"totally_new_setting"),
        "unknown keys must stay ignored: {body}"
    );
    f.assert_absent("totally_new_setting");
    // Expected end state: the one whitelisted key persists while the unknown
    // key and the seeded secrets stay untouched.
    let mut expected_db = before_db;
    expected_db.insert("auto_reset_enabled".into(), "1".into());
    let mut expected_memory = before_memory;
    expected_memory.insert("auto_reset_enabled".into(), "1".into());
    assert_eq!(
        f.stored_settings(),
        expected_db,
        "only the whitelisted key may persist"
    );
    assert_eq!(
        f.memory_settings(),
        expected_memory,
        "only the whitelisted key may reach the mirror"
    );
    let body = f.get().await;
    assert_eq!(
        body["auto_reset_enabled"],
        json!("1"),
        "persisted key must be readable through GET: {body}"
    );
    for secret in [
        "admin_password_hash",
        "totp_secret",
        "password_hash",
        "api_key",
        "upstream_proxy",
        "recovery_codes",
        "totp_recovery",
        "totally_new_setting",
    ] {
        assert!(
            body.get(secret).is_none(),
            "GET /api/settings leaked {secret}: {body}"
        );
    }
}

#[tokio::test]
async fn saving_auto_reset_settings_makes_no_upstream_requests() {
    let (upstream, hits, server) = counting_upstream().await;
    let f = Fixture::with_upstream(&upstream);
    let (status, body) = f.put(valid_batch()).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "saving settings must not trigger remote HTTP"
    );
    server.abort();
}
