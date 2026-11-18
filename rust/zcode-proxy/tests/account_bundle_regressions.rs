use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::types::Value as SqlValue;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
    store,
    vault::Vault,
};

const EXPORT: &str = "/api/accounts/export";
const IMPORT: &str = "/api/accounts/import/bundle";
const ADMIN_PASSWORD: &str = "PUBLIC-bundle-admin-password";
const SESSION: &str = "PUBLIC-bundle-test-session";
const PEER: &str = "192.0.2.10:41000";
const JWT_A: &str = "PUBLIC-go-bundle-jwt-a";
const KEY_A: &str = "PUBLIC-go-bundle-key-a";
const JWT_B: &str = "PUBLIC-go-bundle-jwt-b";
const KEY_B: &str = "PUBLIC-go-bundle-key-b";

fn wire_fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/account_bundle_interop.json")).unwrap()
}

struct Reply {
    status: StatusCode,
    json: Value,
    raw: String,
}

struct Fixture {
    state: Arc<AppState>,
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    stored: Vec<BTreeMap<String, SqlValue>>,
    listed: Value,
    credentials: BTreeMap<i64, (String, String)>,
}

impl Fixture {
    fn new() -> Self {
        let state = AppState::try_from_db_with_vault(
            "PUBLIC-bundle-root-api-key".into(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
            store::open(":memory:"),
            Vault::from_secret("PUBLIC destination bundle vault seed").unwrap(),
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
        Self {
            state: Arc::new(state),
        }
    }

    fn reload(self) -> Self {
        let state = Arc::try_unwrap(self.state).ok().unwrap();
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

    async fn request(
        &self,
        endpoint: (&str, &str),
        body: &str,
        authenticated: bool,
        origin: Option<&str>,
        peer: &str,
        forwarded: Option<&str>,
    ) -> Reply {
        let mut builder = Request::builder()
            .method(endpoint.0)
            .uri(endpoint.1)
            .header("host", "localhost:8080")
            .header("content-type", "application/json");
        if authenticated {
            builder = builder.header("cookie", format!("{SESSION_COOKIE}={SESSION}"));
        }
        if let Some(origin) = origin {
            builder = builder.header("origin", origin);
        }
        if let Some(forwarded) = forwarded {
            builder = builder.header("x-forwarded-for", forwarded);
        }
        let mut request = builder.body(Body::from(body.to_owned())).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        let response = build_router(self.state.clone())
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        Reply {
            status,
            json: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            raw: String::from_utf8(bytes.to_vec()).unwrap(),
        }
    }

    async fn post(&self, path: &str, body: Value) -> Reply {
        self.request(("POST", path), &body.to_string(), true, None, PEER, None)
            .await
    }

    async fn import(&self, case: &str) {
        let wire = wire_fixture();
        let reply = self
            .post(
                IMPORT,
                json!({"password":wire["password"], "bundle":wire[case]}),
            )
            .await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "Go-compatible bundle import route must be reachable"
        );
        assert_eq!(reply.json, json!({"success":true,"imported":2}));
        assert_redacted(&reply.raw);
    }

    async fn export(&self, ids: Option<Value>) -> Reply {
        let mut body = json!({
            "password":wire_fixture()["password"], "admin_password":ADMIN_PASSWORD,
        });
        if let Some(ids) = ids {
            body["ids"] = ids;
        }
        self.post(EXPORT, body).await
    }

    async fn listed(&self) -> Value {
        let reply = self
            .request(("GET", "/api/accounts"), "", true, None, PEER, None)
            .await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_redacted(&reply.raw);
        reply.json
    }

    async fn snapshot(&self) -> Snapshot {
        let listed = self.listed().await;
        let db = self.state.db.lock().unwrap();
        let mut stmt = db.prepare("SELECT * FROM accounts ORDER BY id").unwrap();
        let names: Vec<_> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let stored = stmt
            .query_map([], |row| {
                names
                    .iter()
                    .enumerate()
                    .map(|(i, name)| Ok((name.clone(), row.get::<_, SqlValue>(i)?)))
                    .collect::<rusqlite::Result<BTreeMap<_, _>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let credentials = self
            .state
            .creds
            .lock()
            .unwrap()
            .iter()
            .map(|(&id, c)| (id, (c.zcode_jwt.clone(), c.api_key.clone())))
            .collect();
        Snapshot {
            stored,
            listed,
            credentials,
        }
    }

    async fn assert_imported(&self) -> BTreeMap<String, i64> {
        let listed = self.listed().await;
        let accounts = listed["accounts"].as_array().unwrap();
        assert_eq!(
            accounts.len(),
            2,
            "same email must not merge distinct Go user_ids"
        );
        let db = self.state.db.lock().unwrap();
        let rows = store::load_accounts(&db, &self.state.vault).unwrap();
        let mut ids = BTreeMap::new();
        let wrong_vault = Vault::from_secret("PUBLIC different destination vault").unwrap();
        for (jwt, key, group, remark) in [
            (JWT_A, KEY_A, "eu,failover", "PUBLIC note: 测试"),
            (JWT_B, KEY_B, "backup", "PUBLIC second note"),
        ] {
            let (a, actual_jwt, actual_key) = rows.iter().find(|(_, j, _)| j == jwt).unwrap();
            assert_eq!(actual_jwt, jwt);
            assert_eq!(actual_key, key);
            assert_eq!(a.email, "shared@example.invalid");
            assert_eq!(a.provider, "zai");
            assert_eq!(a.account_group, group);
            assert!(a.enabled);
            assert_eq!(a.status, "active");
            let public = accounts.iter().find(|v| v["id"] == a.id).unwrap();
            assert_eq!(public["group"], group);
            assert_eq!(public["remark"], remark);
            let live = self.state.accounts.lock().unwrap();
            let live = live.iter().find(|v| v.id == a.id).unwrap();
            assert_eq!(live.zcode_jwt, jwt);
            assert_eq!(live.api_key, key);
            let creds = self.state.creds.lock().unwrap();
            assert_eq!(creds[&a.id].zcode_jwt, jwt);
            assert_eq!(creds[&a.id].api_key, key);
            let (stored_jwt, stored_key): (String, String) = db
                .query_row(
                    "SELECT zcode_jwt, api_key FROM accounts WHERE id=?1",
                    [a.id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            for (stored, plain) in [(&stored_jwt, jwt), (&stored_key, key)] {
                assert!(stored.starts_with("vault1:"), "import must encrypt at rest");
                assert!(!stored.contains(plain));
                assert_eq!(self.state.vault.decrypt(stored).unwrap(), plain);
                assert!(wrong_vault.decrypt(stored).is_err());
            }
            ids.insert(jwt.to_string(), a.id);
        }
        ids
    }
}

fn assert_redacted(raw: &str) {
    for secret in [
        JWT_A,
        KEY_A,
        JWT_B,
        KEY_B,
        "PUBLIC-go-access-a",
        "PUBLIC-go-refresh-a",
        "PUBLIC-snapshot-a",
        "PUBLIC-device-a",
    ] {
        assert!(
            !raw.contains(secret),
            "HTTP response exposed a raw bundle credential"
        );
    }
    assert!(
        !raw.contains("vault1:"),
        "HTTP response exposed vault ciphertext"
    );
}

// Independent single-block PBKDF2-HMAC-SHA256 oracle; no production bundle helper.
fn bundle_key(password: &str, salt: &[u8], rounds: u32) -> [u8; 32] {
    let mut key = [0u8; 64];
    if password.len() > key.len() {
        key[..32].copy_from_slice(&Sha256::digest(password.as_bytes()));
    } else {
        key[..password.len()].copy_from_slice(password.as_bytes());
    }
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for i in 0..64 {
        inner[i] ^= key[i];
        outer[i] ^= key[i];
    }
    let mut inner_hash = Sha256::new();
    inner_hash.update(inner);
    let mut outer_hash = Sha256::new();
    outer_hash.update(outer);
    let hmac = |data: &[u8]| -> [u8; 32] {
        let mut i = inner_hash.clone();
        i.update(data);
        let mut o = outer_hash.clone();
        o.update(i.finalize());
        o.finalize().into()
    };
    let mut first = salt.to_vec();
    first.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac(&first);
    let mut result = u;
    for _ in 1..rounds {
        u = hmac(&u);
        for i in 0..32 {
            result[i] ^= u[i];
        }
    }
    result
}

fn decrypt_bundle(bundle: &str, rounds: u32) -> Value {
    let raw = STANDARD
        .decode(bundle.strip_prefix("zcb1:").unwrap())
        .unwrap();
    assert!(raw.len() >= 44);
    let key = bundle_key(
        wire_fixture()["password"].as_str().unwrap(),
        &raw[..16],
        rounds,
    );
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let plain = cipher
        .decrypt(Nonce::from_slice(&raw[16..28]), &raw[28..])
        .expect("bundle must use Go AES256GCM/PBKDF2SHA256 wire format");
    let payload: Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(payload["version"], 1);
    payload
}

fn decrypt_export(reply: &Reply) -> Value {
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "bundle export route must be reachable"
    );
    assert_redacted(&reply.raw);
    assert_eq!(reply.json.as_object().unwrap().len(), 1);
    decrypt_bundle(
        reply.json["bundle"]
            .as_str()
            .expect("export must return bundle"),
        600_000,
    )
}

#[tokio::test]
async fn bundle_routes_require_session_origin_and_export_password_stepup() {
    let f = Fixture::new();
    let wire = wire_fixture();
    let export = json!({"password":wire["password"],"admin_password":ADMIN_PASSWORD});
    let import = json!({"password":wire["password"],"bundle":wire["current"]});
    let before = f.snapshot().await;
    for (path, body) in [(EXPORT, &export), (IMPORT, &import)] {
        let reply = f
            .request(("POST", path), &body.to_string(), false, None, PEER, None)
            .await;
        assert_eq!(
            reply.status,
            StatusCode::UNAUTHORIZED,
            "bundle route must require session"
        );
        assert_redacted(&reply.raw);
        for origin in [
            "http://localhost:8081",
            "http://other.example.invalid",
            "null",
        ] {
            let reply = f
                .request(
                    ("POST", path),
                    &body.to_string(),
                    true,
                    Some(origin),
                    PEER,
                    None,
                )
                .await;
            assert_eq!(
                reply.status,
                StatusCode::FORBIDDEN,
                "bundle route must reject foreign Origin"
            );
            assert!(reply.json.get("bundle").is_none());
        }
    }
    for body in [
        json!({"password":wire["password"]}),
        json!({"password":wire["password"],"admin_password":"PUBLIC-wrong-admin"}),
    ] {
        let reply = f.post(EXPORT, body).await;
        assert_eq!(
            reply.status,
            StatusCode::UNAUTHORIZED,
            "session cannot replace export password step-up"
        );
        assert!(reply.json.get("bundle").is_none());
        assert_redacted(&reply.raw);
    }
    assert_eq!(f.snapshot().await, before);
    f.state
        .persist_settings(&[("admin_password_hash", "")])
        .unwrap();
    let reply = f
        .post(
            EXPORT,
            json!({"password":wire["password"],"admin_password":""}),
        )
        .await;
    assert_eq!(
        reply.status,
        StatusCode::UNAUTHORIZED,
        "unconfigured admin hash must fail closed"
    );
    f.state
        .persist_settings(&[(
            "admin_password_hash",
            &bcrypt::hash(ADMIN_PASSWORD, 4).unwrap(),
        )])
        .unwrap();
    let reply = f
        .request(
            ("POST", IMPORT),
            &import.to_string(),
            true,
            Some("https://localhost:8080"),
            PEER,
            None,
        )
        .await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "same-host import needs session, not export step-up"
    );
    assert_eq!(reply.json, json!({"success":true,"imported":2}));
    assert_eq!(
        f.export(None).await.status,
        StatusCode::OK,
        "non-browser no-Origin export remains supported"
    );
}

#[tokio::test]
async fn export_encrypts_go_wire_payload_and_filters_local_ids_without_leaking_credentials() {
    let wire = wire_fixture();
    for (case, rounds) in [("current", 600_000), ("legacy", 120_000)] {
        assert_eq!(
            decrypt_bundle(wire[case].as_str().unwrap(), rounds),
            wire["payload"],
            "independent oracle must agree with exact Go fixture"
        );
    }
    let f = Fixture::new();
    let empty = f.export(None).await;
    assert_eq!(
        empty.status,
        StatusCode::BAD_REQUEST,
        "empty store has no exportable accounts"
    );
    f.import("current").await;
    let ids = f.assert_imported().await;
    let selected = decrypt_export(
        &f.export(Some(json!([ids[JWT_A], ids[JWT_A], 999999])))
            .await,
    );
    let accounts = selected["accounts"].as_array().unwrap();
    assert_eq!(
        accounts.len(),
        1,
        "duplicate/unknown IDs must not duplicate or widen selection"
    );
    let a = &accounts[0];
    assert_eq!(
        a,
        &wire_fixture()["payload"]["accounts"][0],
        "all Go bundle fields must survive import and re-export"
    );
    assert!(
        a.get("id").is_none(),
        "bundle must not transport machine-local account IDs"
    );
    let all = decrypt_export(&f.export(Some(json!([]))).await);
    assert_eq!(
        all["accounts"].as_array().unwrap().len(),
        2,
        "empty IDs means all accounts"
    );
    let first_bundle = f.export(None).await;
    let second_bundle = f.export(None).await;
    let omitted = decrypt_export(&first_bundle);
    assert_eq!(
        omitted["accounts"].as_array().unwrap().len(),
        2,
        "omitted IDs means all accounts"
    );
    assert_eq!(
        decrypt_export(&second_bundle),
        omitted,
        "fresh encryption must preserve payload"
    );
    assert_ne!(
        first_bundle.json["bundle"], second_bundle.json["bundle"],
        "exports must use fresh salt and nonce"
    );
    assert_eq!(
        f.export(Some(json!([999999]))).await.status,
        StatusCode::BAD_REQUEST
    );
    let reply = f
        .post(
            EXPORT,
            json!({"password":"","admin_password":ADMIN_PASSWORD}),
        )
        .await;
    assert_eq!(
        reply.status,
        StatusCode::BAD_REQUEST,
        "empty bundle password must not export"
    );
}

#[tokio::test]
async fn go_current_and_legacy_imports_preserve_distinct_user_ids_and_reencrypt_for_destination() {
    // Re-export checks all wire fields; live Rust assertions cover JWT/key/group/remark.
    let f = Fixture::new();
    f.import("current").await;
    let ids = f.assert_imported().await;
    assert_ne!(ids[JWT_A], ids[JWT_B]);
    f.import("legacy").await;
    assert_eq!(
        f.assert_imported().await,
        ids,
        "repeat import must upsert by user_id, preserving destination IDs"
    );
    let f = f.reload();
    assert_eq!(
        f.assert_imported().await,
        ids,
        "imported identities and vault credentials must survive reload"
    );
    let wire = wire_fixture();
    let reply = f.post(IMPORT, json!({"password":wire["password"],"bundle":format!(" \n{}\t",wire["current"].as_str().unwrap())})).await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "Go accepts surrounding bundle whitespace"
    );
    assert_eq!(reply.json["imported"], 2);
    assert_eq!(f.assert_imported().await, ids);
}

#[tokio::test]
async fn malformed_or_wrong_password_bundle_requests_leave_database_and_live_accounts_unchanged() {
    let f = Fixture::new();
    f.import("current").await;
    let before = f.snapshot().await;
    let wire = wire_fixture();
    let raw = STANDARD
        .decode(
            wire["current"]
                .as_str()
                .unwrap()
                .strip_prefix("zcb1:")
                .unwrap(),
        )
        .unwrap();
    let mut corrupt = raw;
    *corrupt.last_mut().unwrap() ^= 1;
    for body in [
        json!({"password":"PUBLIC-wrong-bundle-password","bundle":wire["current"]}),
        json!({"password":wire["password"],"bundle":"not-a-bundle"}),
        json!({"password":wire["password"],"bundle":"zcb1:%%%"}),
        json!({"password":wire["password"],"bundle":"zcb1:AA=="}),
        json!({"password":wire["password"],"bundle":format!("zcb1:{}",STANDARD.encode(corrupt))}),
        json!({"password":wire["password"],"bundle":wire["future_version"]}),
        json!({"password":wire["password"],"bundle":wire["invalid_json"]}),
    ] {
        let reply = f.post(IMPORT, body).await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "invalid bundle must be a client error"
        );
        assert_eq!(reply.json["success"], false);
        assert_eq!(reply.json["imported"], 0);
        assert_redacted(&reply.raw);
        assert_eq!(
            f.snapshot().await,
            before,
            "failed import must not partially mutate state"
        );
    }
    for path in [EXPORT, IMPORT] {
        let reply = f.request(("POST", path), "{", true, None, PEER, None).await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "malformed request JSON must reject"
        );
        assert_eq!(f.snapshot().await, before);
    }
}

#[tokio::test]
async fn export_stepup_throttle_is_peer_scoped_ignores_forwarded_headers_and_isolates_login() {
    let f = Fixture::new();
    f.import("current").await;
    let wire = wire_fixture();
    let wrong = json!({"password":wire["password"],"admin_password":"PUBLIC-wrong-admin"});
    let correct = json!({"password":wire["password"],"admin_password":ADMIN_PASSWORD});
    for _ in 0..5 {
        let reply = f.post(EXPORT, wrong.clone()).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert!(reply.json.get("bundle").is_none());
    }
    let reply = f
        .request(
            ("POST", EXPORT),
            &correct.to_string(),
            true,
            None,
            "192.0.2.10:41999",
            Some("192.0.2.11"),
        )
        .await;
    assert_eq!(
        reply.status,
        StatusCode::TOO_MANY_REQUESTS,
        "source-port/forwarded-header changes must not bypass export lockout"
    );
    assert!(reply.json.get("bundle").is_none());
    assert_redacted(&reply.raw);
    let reply = f
        .request(
            ("POST", EXPORT),
            &correct.to_string(),
            true,
            None,
            "192.0.2.11:41000",
            None,
        )
        .await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "another peer must retain export access"
    );
    let reply = f
        .request(
            ("POST", "/api/login"),
            &json!({"password":ADMIN_PASSWORD}).to_string(),
            false,
            None,
            PEER,
            None,
        )
        .await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "export failures must not poison login"
    );
    for _ in 0..5 {
        let reply = f
            .request(
                ("POST", "/api/login"),
                &json!({"password":"PUBLIC-wrong-admin"}).to_string(),
                false,
                None,
                "192.0.2.11:41000",
                None,
            )
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }
    let reply = f
        .request(
            ("POST", EXPORT),
            &correct.to_string(),
            true,
            None,
            "192.0.2.11:41000",
            None,
        )
        .await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "login lockout must not poison authenticated export step-up"
    );
}
