use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use rusqlite::types::Value as SqlValue;
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
    store,
    vault::Vault,
};

const IMPORT: &str = "/api/accounts/import/bundle";
const EXPORT: &str = "/api/accounts/export";
const SESSION: &str = "PUBLIC-atomic-bundle-session";
const ADMIN_PASSWORD: &str = "PUBLIC-atomic-bundle-admin";

type Snapshot = (
    Vec<Vec<SqlValue>>,
    Vec<Value>,
    BTreeMap<i64, (String, String)>,
);

fn wire() -> Value {
    serde_json::from_str(include_str!("fixtures/account_bundle_interop.json")).unwrap()
}

fn import_body() -> Value {
    let fixture = wire();
    json!({"password":fixture["password"], "bundle":fixture["current"]})
}

struct Fixture(Arc<AppState>);

impl Fixture {
    fn new() -> Self {
        let state = AppState::try_from_db_with_vault(
            "PUBLIC-atomic-bundle-root".into(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
            store::open(":memory:"),
            Vault::from_secret("PUBLIC atomic bundle vault seed").unwrap(),
        )
        .unwrap();
        state
            .persist_settings(&[(
                "admin_password_hash",
                &bcrypt::hash(ADMIN_PASSWORD, 4).unwrap(),
            )])
            .unwrap();
        Self::from_state(state)
    }

    fn from_state(state: AppState) -> Self {
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        Self(Arc::new(state))
    }

    fn reload(self) -> Self {
        let state = Arc::try_unwrap(self.0).ok().unwrap();
        Self::from_state(
            AppState::try_from_db_with_vault(
                state.root_key,
                state.upstream,
                state.db.into_inner().unwrap(),
                state.vault,
            )
            .unwrap(),
        )
    }

    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .header("host", "localhost:8080")
            .header("content-type", "application/json")
            .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
            .body(Body::from(body.to_string()))
            .unwrap();
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

    async fn import(&self) {
        let (status, reply) = self.post(IMPORT, import_body()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "canonical bundle import must be reachable"
        );
        assert_eq!(reply, json!({"success":true, "imported":2}));
    }

    fn id(&self, group: &str) -> i64 {
        self.0
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT id FROM accounts WHERE account_group=?1",
                [group],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn snapshot(&self) -> Snapshot {
        let db = self.0.db.lock().unwrap();
        let mut stmt = db.prepare("SELECT * FROM accounts ORDER BY id").unwrap();
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
        let accounts = self
            .0
            .accounts
            .lock()
            .unwrap()
            .iter()
            .map(|a| {
                json!({
                    "id":a.id, "email":a.email, "provider":a.provider, "enabled":a.enabled,
                    "status":a.status, "cooling_until":a.cooling_until,
                    "paid_cooling_until":a.paid_cooling_until, "paid_fallback":a.paid_fallback,
                    "zcode_jwt":a.zcode_jwt, "api_key":a.api_key, "account_group":a.account_group,
                    "remaining":a.remaining, "priority":a.priority,
                })
            })
            .collect();
        let creds = self
            .0
            .creds
            .lock()
            .unwrap()
            .iter()
            .map(|(&id, c)| (id, (c.zcode_jwt.clone(), c.api_key.clone())))
            .collect();
        (stored, accounts, creds)
    }

    fn sql(&self, sql: &str) {
        self.0.db.lock().unwrap().execute_batch(sql).unwrap();
    }

    fn assert_failed_import(status: StatusCode, reply: &Value) {
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "canonical bundle import route is missing"
        );
        assert!(status.is_client_error() || status.is_server_error());
        assert_eq!(reply["success"], false);
        assert_eq!(
            reply["imported"], 0,
            "rolled-back imports must report zero imported accounts"
        );
    }
}

#[tokio::test]
async fn second_account_insert_failure_rolls_back_database_live_accounts_and_credentials() {
    let f = Fixture::new();
    let before = f.snapshot();
    f.sql(
        "CREATE TRIGGER reject_second_bundle_insert BEFORE INSERT ON accounts
           WHEN NEW.account_group='backup' BEGIN SELECT RAISE(FAIL, 'PUBLIC forced insert failure'); END;",
    );
    let (status, reply) = f.post(IMPORT, import_body()).await;
    Fixture::assert_failed_import(status, &reply);
    assert_eq!(
        f.snapshot(),
        before,
        "failed second insert left a partial import"
    );
    f.sql("DROP TRIGGER reject_second_bundle_insert");
    f.import().await;
    assert_eq!(
        f.snapshot().0.len(),
        2,
        "retry must import both valid fixture users"
    );
}

#[tokio::test]
async fn second_account_update_failure_preserves_existing_state_and_exact_ciphertext() {
    let f = Fixture::new();
    f.import().await;
    let first = f.id("eu,failover");
    let second = f.id("backup");
    let old_jwt = f.0.vault.encrypt("PUBLIC prior JWT").unwrap();
    let old_key = f.0.vault.encrypt("PUBLIC prior API key").unwrap();
    f.0.db
        .lock()
        .unwrap()
        .execute(
            "UPDATE accounts SET zcode_jwt=?1, api_key=?2, email='prior@example.invalid',
         remark='PUBLIC prior remark', enabled=0, status='disabled', priority=17 WHERE id=?3",
            rusqlite::params![old_jwt, old_key, first],
        )
        .unwrap();
    let f = f.reload();
    let before = f.snapshot();
    f.sql(&format!(
        "CREATE TRIGGER reject_second_bundle_update BEFORE UPDATE ON accounts
                   WHEN OLD.id={second} BEGIN SELECT RAISE(FAIL, 'PUBLIC forced update failure'); END;"
    ));
    let (status, reply) = f.post(IMPORT, import_body()).await;
    Fixture::assert_failed_import(status, &reply);
    assert_eq!(
        f.snapshot(),
        before,
        "rollback must preserve old values and ciphertext bytes"
    );
    f.sql("DROP TRIGGER reject_second_bundle_update");
    f.import().await;
    assert_eq!(
        f.id("eu,failover"),
        first,
        "retry must preserve the first user's local ID"
    );
    assert_eq!(
        f.id("backup"),
        second,
        "retry must preserve the second user's local ID"
    );
    assert_eq!(
        f.snapshot().0.len(),
        2,
        "retry must update rather than duplicate users"
    );
    assert_eq!(
        f.0.creds.lock().unwrap()[&first].zcode_jwt,
        wire()["payload"]["accounts"][0]["zcode_jwt"]
            .as_str()
            .unwrap()
    );
}

#[tokio::test]
async fn selected_export_rejects_corrupt_ciphertext_on_an_unselected_account() {
    let f = Fixture::new();
    f.import().await;
    let selected = f.id("eu,failover");
    let unselected = f.id("backup");
    let body =
        json!({"password":wire()["password"], "admin_password":ADMIN_PASSWORD, "ids":[selected]});
    let (status, reply) = f.post(EXPORT, body.clone()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "healthy selected export must succeed"
    );
    assert!(reply["bundle"].as_str().unwrap().starts_with("zcb1:"));
    let foreign = Vault::from_secret("PUBLIC deliberately different bundle vault").unwrap();
    for (column, bad) in [
        ("zcode_jwt", "vault1:PUBLIC malformed ciphertext".to_owned()),
        (
            "api_key",
            foreign.encrypt("PUBLIC foreign API key").unwrap(),
        ),
    ] {
        let original: String =
            f.0.db
                .lock()
                .unwrap()
                .query_row(
                    &format!("SELECT {column} FROM accounts WHERE id=?1"),
                    [unselected],
                    |row| row.get(0),
                )
                .unwrap();
        f.0.db
            .lock()
            .unwrap()
            .execute(
                &format!("UPDATE accounts SET {column}=?1 WHERE id=?2"),
                rusqlite::params![bad, unselected],
            )
            .unwrap();
        let before = f.snapshot();
        let (status, reply) = f.post(EXPORT, body.clone()).await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "canonical bundle export route is missing"
        );
        assert!(
            status.is_client_error() || status.is_server_error(),
            "unselected corrupt credentials must block export"
        );
        assert!(
            reply.get("bundle").is_none(),
            "failed export must return no bundle"
        );
        assert_eq!(
            f.snapshot(),
            before,
            "integrity failure must not mutate account state"
        );
        f.0.db
            .lock()
            .unwrap()
            .execute(
                &format!("UPDATE accounts SET {column}=?1 WHERE id=?2"),
                rusqlite::params![original, unselected],
            )
            .unwrap();
    }
}
