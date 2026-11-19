/*
The fixed packet contract overrides Go where Rust intentionally differs:
all console responses, including /web, revalidate; bootstrap-password state
uses admin_password_default; step-up lockouts use five failures in 900s;
usage_7d and models use existing Rust sources; captcha and app_version report
unported telemetry honestly. Groups are sorted, unlike Go's unsorted union.
Username success includes Go's message field, not just username.
Bad /totp/enable codes return 400, matching the existing Rust confirm handler.
*/

use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode},
    Router,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_core::AccountView;
use zcode_proxy::{
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
    store,
};

const PASSWORD: &str = "PUBLIC-console-panel-password";
const NEW_PASSWORD: &str = "PUBLIC-console-panel-new-password";
const ROOT_KEY: &str = "ROOTKEY-seed-0123456789abcdef";
const HOST: &str = "localhost:8787";
const PEER: &str = "192.0.2.31:41000";
const OTHER_PEER: &str = "192.0.2.32:41000";
const INDEX_MARKER: &str = "<title>ZCode Proxy</title>";

#[derive(Default)]
struct Options<'a> {
    cookie: Option<&'a str>,
    api_key: Option<&'a str>,
    peer: Option<SocketAddr>,
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn expect_status(&self, expected: StatusCode) {
        assert_eq!(self.status, expected, "body={}", self.body);
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).expect("response must contain valid JSON")
    }

    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .unwrap_or_else(|| panic!("missing {name}"))
            .to_str()
            .unwrap()
    }
}

struct Fixture {
    state: Arc<AppState>,
    app: Router,
}

impl Fixture {
    fn new(root_key: &str) -> Self {
        Self::with_data(root_key, &[], None)
    }

    fn with_data(root_key: &str, accounts: &[AccountView], proxy_group: Option<&str>) -> Self {
        let db = store::open(":memory:");
        store::set_setting(
            &db,
            "admin_password_hash",
            &bcrypt::hash(PASSWORD, 4).unwrap(),
        );
        store::set_setting(&db, "admin_password_default", "1");
        store::set_setting(&db, "admin_username", "admin");
        if !root_key.is_empty() {
            store::set_setting(&db, "api_key", root_key);
        }
        for account in accounts {
            store::upsert_account(&db, account, &account.zcode_jwt, &account.api_key);
        }
        if let Some(group) = proxy_group {
            db.execute(
                "INSERT INTO proxy_nodes(name, type, host, port, group_name)
                 VALUES('PUBLIC-console-proxy', 'socks5', '127.0.0.1', 1080, ?1)",
                [group],
            )
            .unwrap();
        }
        let state = Arc::new(AppState::from_db(
            root_key.into(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
            db,
        ));
        assert_eq!(
            state.setting("admin_password_default").as_deref(),
            Some("1")
        );
        assert!(bcrypt::verify(PASSWORD, &state.setting("admin_password_hash").unwrap()).unwrap());
        Self {
            app: build_router(state.clone()),
            state,
        }
    }

    async fn send(&self, method: &str, path: &str, body: Value, opts: Options<'_>) -> Reply {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", HOST)
            .header("content-type", "application/json");
        if let Some(cookie) = opts.cookie {
            builder = builder.header("cookie", cookie);
        }
        if let Some(key) = opts.api_key {
            builder = builder.header("x-api-key", key);
        }
        let mut request = builder.body(Body::from(body.to_string())).unwrap();
        request.extensions_mut().insert(ConnectInfo(
            opts.peer.unwrap_or_else(|| PEER.parse().unwrap()),
        ));
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 4 << 20)
            .await
            .unwrap();
        Reply {
            status,
            headers,
            body: String::from_utf8(bytes.to_vec()).unwrap(),
        }
    }

    async fn session(&self) -> String {
        let reply = self
            .send(
                "POST",
                "/api/login",
                json!({"password": PASSWORD}),
                Options::default(),
            )
            .await;
        reply.expect_status(StatusCode::OK);
        assert_eq!(reply.json(), json!({"success": true, "username": "admin"}));
        reply.header("set-cookie").split(';').next().unwrap().into()
    }

    async fn get(&self, path: &str, cookie: &str) -> Reply {
        self.send(
            "GET",
            path,
            Value::Null,
            Options {
                cookie: Some(cookie),
                ..Options::default()
            },
        )
        .await
    }

    async fn post(&self, path: &str, cookie: &str, body: Value) -> Reply {
        self.send(
            "POST",
            path,
            body,
            Options {
                cookie: Some(cookie),
                ..Options::default()
            },
        )
        .await
    }

    async fn models_with_key(&self, key: &str) -> Reply {
        self.send(
            "GET",
            "/v1/models",
            Value::Null,
            Options {
                api_key: Some(key),
                ..Options::default()
            },
        )
        .await
    }

    fn assert_persisted(&self, key: &str, expected: &str) {
        assert_eq!(self.state.setting(key).as_deref(), Some(expected));
        let db = self.state.db.lock().unwrap();
        let persisted = store::load_settings(&db, &self.state.vault).unwrap();
        assert_eq!(persisted.get(key).map(String::as_str), Some(expected));
    }

    async fn setup_totp(&self, cookie: &str) -> String {
        let reply = self
            .post(
                "/api/auth/totp/setup",
                cookie,
                json!({"current_password": PASSWORD}),
            )
            .await;
        reply.expect_status(StatusCode::OK);
        let body = reply.json();
        let secret = body["secret"].as_str().unwrap();
        assert!(!secret.is_empty());
        assert!(body["otpauth_url"].as_str().unwrap().contains(secret));
        secret.into()
    }
}

fn account(email: &str, group: &str, enabled: bool, status: &str, remaining: f64) -> AccountView {
    AccountView {
        email: email.into(),
        provider: "zai".into(),
        enabled,
        status: status.into(),
        account_group: group.into(),
        remaining,
        zcode_jwt: "PUBLIC-console-account-jwt".into(),
        ..AccountView::default()
    }
}

async fn current_totp_code(secret: &str) -> String {
    // Keep password verification away from a TOTP rollover boundary.
    let seconds_into_step = now_secs().rem_euclid(30);
    if seconds_into_step >= 28 {
        tokio::time::sleep(std::time::Duration::from_secs(
            (31 - seconds_into_step) as u64,
        ))
        .await;
    }
    zcode_core::totp_now(&zcode_core::base32_decode(secret).unwrap(), now_secs())
}

fn assert_recovery_codes(body: &Value) -> usize {
    let object = body.as_object().unwrap();
    assert_eq!(object.len(), 2, "body={body}");
    assert_eq!(body["enabled"], json!(true));
    let codes = body["recovery_codes"].as_array().unwrap();
    assert!(!codes.is_empty());
    for code in codes {
        assert!(!code.as_str().unwrap().is_empty());
    }
    codes.len()
}

#[tokio::test]
async fn console_index_aliases_and_fallback_serve_the_same_uncached_html() {
    let f = Fixture::new("");
    let mut index = None;
    for path in ["/web", "/web/", "/web/does-not-exist"] {
        let reply = f.send("GET", path, Value::Null, Options::default()).await;
        reply.expect_status(StatusCode::OK);
        assert_eq!(reply.header("content-type"), "text/html; charset=utf-8");
        assert_eq!(reply.header("cache-control"), "no-cache, must-revalidate");
        assert!(reply.body.contains(INDEX_MARKER), "path={path}");
        if let Some(expected) = &index {
            assert_eq!(&reply.body, expected, "path={path}");
        } else {
            index = Some(reply.body);
        }
    }
}

#[tokio::test]
async fn console_static_assets_have_exact_types_and_reject_missing_or_traversal_paths() {
    let f = Fixture::new("");
    for (path, content_type) in [
        ("/web/static/app.js", "text/javascript; charset=utf-8"),
        ("/web/static/style.css", "text/css; charset=utf-8"),
    ] {
        let reply = f.send("GET", path, Value::Null, Options::default()).await;
        reply.expect_status(StatusCode::OK);
        assert_eq!(reply.header("content-type"), content_type);
        assert_eq!(reply.header("cache-control"), "no-cache, must-revalidate");
        if path.ends_with("app.js") {
            assert!(reply.body.starts_with("/* ZCode Proxy"));
        } else {
            assert!(!reply.body.is_empty());
        }
    }
    for path in ["/web/static/missing.js", "/web/static/../index.html"] {
        let reply = f.send("GET", path, Value::Null, Options::default()).await;
        reply.expect_status(StatusCode::NOT_FOUND);
        assert_eq!(reply.header("cache-control"), "no-cache, must-revalidate");
        assert!(!reply.body.contains(INDEX_MARKER), "path={path}");
    }
}

#[tokio::test]
async fn login_info_is_open_and_password_change_clears_the_bootstrap_marker() {
    let f = Fixture::new("");
    let reply = f
        .send(
            "GET",
            "/api/auth/login-info",
            Value::Null,
            Options::default(),
        )
        .await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({"initial_password": true, "totp_enabled": false})
    );
    let cookie = f.session().await;
    let reply = f
        .post(
            "/api/auth/password",
            &cookie,
            json!({"current_password": PASSWORD, "new_password": NEW_PASSWORD}),
        )
        .await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(reply.json(), json!({"ok": true}));
    let reply = f
        .send(
            "GET",
            "/api/auth/login-info",
            Value::Null,
            Options::default(),
        )
        .await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({"initial_password": false, "totp_enabled": false})
    );
    // Clearing may remove the marker or persist a non-default value.
    assert_ne!(
        f.state.setting("admin_password_default").as_deref(),
        Some("1")
    );
    let db = f.state.db.lock().unwrap();
    let settings = store::load_settings(&db, &f.state.vault).unwrap();
    assert_ne!(
        settings.get("admin_password_default").map(String::as_str),
        Some("1")
    );
}

#[tokio::test]
async fn totp_status_tracks_existing_setup_confirm_and_recovery_codes() {
    let f = Fixture::new("");
    let cookie = f.session().await;
    let reply = f.get("/api/auth/totp/status", &cookie).await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({"enabled": false, "recovery_remaining": 0})
    );
    let secret = f.setup_totp(&cookie).await;
    let code = current_totp_code(&secret).await;
    let reply = f
        .post(
            "/api/auth/totp/confirm",
            &cookie,
            json!({"current_password": PASSWORD, "code": code}),
        )
        .await;
    reply.expect_status(StatusCode::OK);
    let count = assert_recovery_codes(&reply.json());
    let reply = f.get("/api/auth/totp/status", &cookie).await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({"enabled": true, "recovery_remaining": count})
    );
}

#[tokio::test]
async fn totp_enable_alias_rejects_bad_codes_without_enabling_then_confirms() {
    let f = Fixture::new("");
    let cookie = f.session().await;
    let secret = f.setup_totp(&cookie).await;
    let reply = f
        .post(
            "/api/auth/totp/enable",
            &cookie,
            json!({"current_password": PASSWORD, "code": "not-a-totp-code"}),
        )
        .await;
    reply.expect_status(StatusCode::BAD_REQUEST);
    assert_eq!(reply.json(), json!({"message": "code did not verify"}));
    let reply = f.get("/api/auth/totp/status", &cookie).await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({"enabled": false, "recovery_remaining": 0})
    );
    let code = current_totp_code(&secret).await;
    let reply = f
        .post(
            "/api/auth/totp/enable",
            &cookie,
            json!({"current_password": PASSWORD, "code": code}),
        )
        .await;
    reply.expect_status(StatusCode::OK);
    let count = assert_recovery_codes(&reply.json());
    let reply = f.get("/api/auth/totp/status", &cookie).await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({"enabled": true, "recovery_remaining": count})
    );
    let reply = f
        .send(
            "GET",
            "/api/auth/login-info",
            Value::Null,
            Options::default(),
        )
        .await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({"initial_password": true, "totp_enabled": true})
    );
}

#[tokio::test]
async fn username_change_validates_password_persists_and_keeps_the_session() {
    let f = Fixture::new("");
    let cookie = f.session().await;
    for username in ["ab", "bad name!"] {
        let reply = f
            .post(
                "/api/auth/username",
                &cookie,
                json!({"new_username": username, "current_password": PASSWORD}),
            )
            .await;
        reply.expect_status(StatusCode::BAD_REQUEST);
        f.assert_persisted("admin_username", "admin");
    }
    let reply = f
        .post(
            "/api/auth/username",
            &cookie,
            json!({"new_username": "ops.admin-2", "current_password": "PUBLIC-wrong-password"}),
        )
        .await;
    reply.expect_status(StatusCode::FORBIDDEN);
    f.assert_persisted("admin_username", "admin");
    let reply = f
        .post(
            "/api/auth/username",
            &cookie,
            json!({"new_username": "ops.admin-2", "current_password": PASSWORD}),
        )
        .await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({"username": "ops.admin-2", "message": "username updated"})
    );
    f.assert_persisted("admin_username", "ops.admin-2");
    let reply = f.get("/api/auth/check", &cookie).await;
    reply.expect_status(StatusCode::OK);
    // Go auth.go:676-688 reports the configured username and bootstrap-password flag.
    assert_eq!(
        reply.json(),
        json!({"authenticated": true, "username": "ops.admin-2", "is_default_password": true})
    );
}

#[tokio::test]
async fn username_change_locks_the_sixth_attempt_by_peer_ip_not_port() {
    let f = Fixture::new("");
    let cookie = f.session().await;
    for _ in 0..5 {
        let reply = f
            .post(
                "/api/auth/username",
                &cookie,
                json!({"new_username": "ops.admin-2", "current_password": "PUBLIC-wrong-password"}),
            )
            .await;
        reply.expect_status(StatusCode::FORBIDDEN);
    }
    let reply = f
        .send(
            "POST",
            "/api/auth/username",
            json!({"new_username": "ops.admin-2", "current_password": PASSWORD}),
            Options {
                cookie: Some(&cookie),
                peer: Some("192.0.2.31:41001".parse().unwrap()),
                ..Options::default()
            },
        )
        .await;
    reply.expect_status(StatusCode::TOO_MANY_REQUESTS);
    f.assert_persisted("admin_username", "admin");
    let reply = f
        .send(
            "POST",
            "/api/auth/username",
            json!({"new_username": "ops.admin-2", "current_password": PASSWORD}),
            Options {
                cookie: Some(&cookie),
                peer: Some(OTHER_PEER.parse().unwrap()),
                ..Options::default()
            },
        )
        .await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({"username": "ops.admin-2", "message": "username updated"})
    );
}

#[tokio::test]
async fn root_key_get_masks_long_and_short_keys_and_omits_an_absent_mask() {
    for (key, expected) in [
        (
            ROOT_KEY,
            json!({"has_api_key": true, "api_key_masked": "ROOTKEY-…cdef"}),
        ),
        (
            "PUBLIC-short",
            json!({"has_api_key": true, "api_key_masked": "****"}),
        ),
        ("", json!({"has_api_key": false})),
    ] {
        let f = Fixture::new(key);
        let cookie = f.session().await;
        let reply = f.get("/api/settings/api-key", &cookie).await;
        reply.expect_status(StatusCode::OK);
        assert_eq!(reply.json(), expected);
        if !key.is_empty() {
            assert!(!reply.body.contains(key), "GET must not disclose plaintext");
        }
    }
}

#[tokio::test]
async fn root_key_reveal_requires_password_and_returns_the_exact_key() {
    let f = Fixture::new(ROOT_KEY);
    let cookie = f.session().await;
    let reply = f
        .post(
            "/api/settings/api-key/reveal",
            &cookie,
            json!({"verify_password": "PUBLIC-wrong-password"}),
        )
        .await;
    reply.expect_status(StatusCode::UNAUTHORIZED);
    assert!(!reply.body.contains(ROOT_KEY));
    let reply = f
        .post(
            "/api/settings/api-key/reveal",
            &cookie,
            json!({"verify_password": PASSWORD}),
        )
        .await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({"has_api_key": true, "api_key": ROOT_KEY})
    );
}

#[tokio::test]
async fn root_key_generation_requires_password_and_rotates_storage_and_live_auth() {
    let f = Fixture::new(ROOT_KEY);
    let cookie = f.session().await;
    f.models_with_key(ROOT_KEY)
        .await
        .expect_status(StatusCode::OK);
    let reply = f
        .post(
            "/api/settings/api-key/generate",
            &cookie,
            json!({"verify_password": "PUBLIC-wrong-password"}),
        )
        .await;
    reply.expect_status(StatusCode::UNAUTHORIZED);
    f.assert_persisted("api_key", ROOT_KEY);
    f.models_with_key(ROOT_KEY)
        .await
        .expect_status(StatusCode::OK);
    let reply = f
        .post(
            "/api/settings/api-key/generate",
            &cookie,
            json!({"verify_password": PASSWORD}),
        )
        .await;
    reply.expect_status(StatusCode::OK);
    let body = reply.json();
    let key = body["api_key"].as_str().unwrap();
    assert!(!key.is_empty());
    assert_ne!(key, ROOT_KEY);
    assert_eq!(
        body,
        json!({"api_key": key, "message": "API key generated"})
    );
    f.assert_persisted("api_key", key);
    f.models_with_key(ROOT_KEY)
        .await
        .expect_status(StatusCode::UNAUTHORIZED);
    // /v1/models is local, so accepted auth deterministically returns 200.
    f.models_with_key(key).await.expect_status(StatusCode::OK);
    let masked = if key.len() > 12 {
        format!("{}…{}", &key[..8], &key[key.len() - 4..])
    } else {
        "****".into()
    };
    let reply = f.get("/api/settings/api-key", &cookie).await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({"has_api_key": true, "api_key_masked": masked})
    );
    assert!(!reply.body.contains(key));
}

#[tokio::test]
async fn root_key_generation_storage_failure_keeps_the_previous_key_active() {
    let f = Fixture::new(ROOT_KEY);
    let cookie = f.session().await;
    f.state
        .db
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_root_key_insert BEFORE INSERT ON settings
             WHEN NEW.key = 'api_key'
             BEGIN SELECT RAISE(FAIL, 'PUBLIC injected root key failure'); END;
             CREATE TRIGGER fail_root_key_update BEFORE UPDATE ON settings
             WHEN NEW.key = 'api_key'
             BEGIN SELECT RAISE(FAIL, 'PUBLIC injected root key failure'); END;",
        )
        .unwrap();
    let reply = f
        .post(
            "/api/settings/api-key/generate",
            &cookie,
            json!({"verify_password": PASSWORD}),
        )
        .await;
    reply.expect_status(StatusCode::INTERNAL_SERVER_ERROR);
    f.assert_persisted("api_key", ROOT_KEY);
    f.models_with_key(ROOT_KEY)
        .await
        .expect_status(StatusCode::OK);
    let reply = f.get("/api/settings/api-key", &cookie).await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({"has_api_key": true, "api_key_masked": "ROOTKEY-…cdef"})
    );
}

#[tokio::test]
async fn root_key_reveal_and_generate_have_independent_peer_action_lockouts() {
    let f = Fixture::new(ROOT_KEY);
    let cookie = f.session().await;
    for _ in 0..5 {
        let reply = f
            .post(
                "/api/settings/api-key/reveal",
                &cookie,
                json!({"verify_password": "PUBLIC-wrong-password"}),
            )
            .await;
        reply.expect_status(StatusCode::UNAUTHORIZED);
    }
    let reply = f
        .post(
            "/api/settings/api-key/reveal",
            &cookie,
            json!({"verify_password": PASSWORD}),
        )
        .await;
    reply.expect_status(StatusCode::TOO_MANY_REQUESTS);
    let reply = f
        .post(
            "/api/settings/api-key/generate",
            &cookie,
            json!({"verify_password": PASSWORD}),
        )
        .await;
    reply.expect_status(StatusCode::OK);
    let generated = reply.json();
    let key = generated["api_key"].as_str().unwrap();
    assert!(!key.is_empty());
    assert_ne!(key, ROOT_KEY);
    for _ in 0..5 {
        let reply = f
            .post(
                "/api/settings/api-key/generate",
                &cookie,
                json!({"verify_password": "PUBLIC-wrong-password"}),
            )
            .await;
        reply.expect_status(StatusCode::UNAUTHORIZED);
    }
    let reply = f
        .post(
            "/api/settings/api-key/generate",
            &cookie,
            json!({"verify_password": PASSWORD}),
        )
        .await;
    reply.expect_status(StatusCode::TOO_MANY_REQUESTS);
    f.assert_persisted("api_key", key);
    f.models_with_key(key).await.expect_status(StatusCode::OK);
    let reply = f
        .send(
            "POST",
            "/api/settings/api-key/reveal",
            json!({"verify_password": PASSWORD}),
            Options {
                cookie: Some(&cookie),
                peer: Some(OTHER_PEER.parse().unwrap()),
                ..Options::default()
            },
        )
        .await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(reply.json(), json!({"has_api_key": true, "api_key": key}));
}

#[tokio::test]
async fn dashboard_counts_selectable_effective_statuses_and_reports_honest_telemetry() {
    for status in ["active", "cooling"] {
        // Zero cooling_until is expired, so both fixtures have one effective active account.
        let accounts = [
            account("active@example.test", "", true, status, 12.5),
            account("disabled@example.test", "eu", false, "disabled", 7.25),
        ];
        let f = Fixture::with_data("", &accounts, None);
        let cookie = f.session().await;
        let stats = f.get("/api/stats", &cookie).await;
        stats.expect_status(StatusCode::OK);
        let reply = f.get("/api/dashboard", &cookie).await;
        reply.expect_status(StatusCode::OK);
        assert_eq!(
            reply.json(),
            json!({
                "account_total": 2,
                "account_selectable": 1,
                "status_count": {"active": 1, "disabled": 1},
                "group_count": {"未分组": 1, "eu": 1},
                "total_remaining": 19.75,
                "usage_7d": stats.json(),
                "gateway_paused": false,
                "captcha": {"available": false, "reason": "not ported"},
                "app_version": "",
            }),
            "raw account status={status}"
        );
    }
}

#[tokio::test]
async fn groups_merge_split_sort_and_deduplicate_accounts_and_proxy_nodes() {
    let accounts = [
        account("eu@example.test", "eu", true, "active", 0.0),
        account("multi@example.test", "eu,us", true, "active", 0.0),
    ];
    let f = Fixture::with_data("", &accounts, Some("eu,ops"));
    let cookie = f.session().await;
    let reply = f.get("/api/groups", &cookie).await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(reply.json(), json!({"groups": ["eu", "ops", "us"]}));
    let empty = Fixture::new("");
    let cookie = empty.session().await;
    let reply = empty.get("/api/groups", &cookie).await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(reply.json(), json!({"groups": []}));
}

#[tokio::test]
async fn fingerprints_return_the_go_preset_ids_labels_and_groups() {
    let f = Fixture::new("");
    let cookie = f.session().await;
    let reply = f.get("/api/fingerprints", &cookie).await;
    reply.expect_status(StatusCode::OK);
    let presets = [
        ("off", "关闭（Go 默认指纹）", "基础"),
        ("randomized", "随机化指纹", "基础"),
        ("chrome", "Chrome 浏览器（自动最新）", "浏览器"),
        ("chrome_100", "Chrome 100", "浏览器"),
        ("chrome_83", "Chrome 83（旧版 Electron 常见）", "浏览器"),
        ("firefox", "Firefox 浏览器（120）", "浏览器"),
        ("safari", "Safari 浏览器（16.0）", "浏览器"),
        ("edge", "Edge 浏览器（85）", "浏览器"),
        ("qq", "QQ 浏览器（11.1）", "浏览器"),
        ("q360", "360 浏览器（7.5）", "浏览器"),
        ("bun", "Bun.js（BoringSSL）", "运行时与工具"),
        ("node", "Node.js（OpenSSL）", "运行时与工具"),
        ("deno", "Deno（rustls）", "运行时与工具"),
        ("curl", "curl（OpenSSL）", "运行时与工具"),
        ("python", "Python requests（OpenSSL）", "运行时与工具"),
        ("okhttp", "OkHttp 3（Android）", "运行时与工具"),
        ("golang", "Go 标准库（crypto/tls）", "运行时与工具"),
        ("ios", "iOS Safari（14）", "移动端"),
        ("android", "Android OkHttp（11）", "移动端"),
        ("custom", "自定义 JA3 指纹", "自定义"),
    ];
    let expected: Vec<Value> = presets
        .iter()
        .map(|(id, label, group)| json!({"id": id, "label": label, "group": group}))
        .collect();
    assert_eq!(reply.json(), json!({"fingerprints": expected}));
}

#[tokio::test]
async fn panel_models_return_a_nonempty_string_catalog_matching_the_data_plane() {
    let f = Fixture::new(ROOT_KEY);
    let cookie = f.session().await;
    let data_plane = f.models_with_key(ROOT_KEY).await;
    data_plane.expect_status(StatusCode::OK);
    let catalog = data_plane.json();
    let models: Vec<&str> = catalog["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|model| model["id"].as_str().unwrap())
        .collect();
    assert!(!models.is_empty());
    assert!(models.iter().all(|model| !model.is_empty()));
    let reply = f.get("/api/models", &cookie).await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(reply.json(), json!({"models": models}));
}

#[tokio::test]
async fn persisted_root_key_overrides_the_constructor_seed_for_live_auth_and_masking() {
    const PERSISTED_KEY: &str = "PERSISTED-key-0123456789abcdef";
    const SEED_KEY: &str = "SEED-key-0123456789abcdef";
    let db = store::open(":memory:");
    store::set_setting(&db, "api_key", PERSISTED_KEY);
    store::set_setting(
        &db,
        "admin_password_hash",
        &bcrypt::hash(PASSWORD, 4).unwrap(),
    );
    let state = Arc::new(AppState::from_db(
        SEED_KEY.into(),
        UpstreamUrls {
            zai: "http://127.0.0.1:1/unused".into(),
            zai_fallback: "http://127.0.0.1:1/unused".into(),
        },
        db,
    ));
    let f = Fixture {
        app: build_router(state.clone()),
        state,
    };
    // Go auth.go:487-496 validates the persisted key rather than a startup seed.
    f.models_with_key(PERSISTED_KEY)
        .await
        .expect_status(StatusCode::OK);
    f.models_with_key(SEED_KEY)
        .await
        .expect_status(StatusCode::UNAUTHORIZED);
    let cookie = f.session().await;
    let reply = f.get("/api/settings/api-key", &cookie).await;
    reply.expect_status(StatusCode::OK);
    // Go auth.go:826-840 masks the first eight and last four bytes of the stored key.
    assert_eq!(
        reply.json(),
        json!({"has_api_key": true, "api_key_masked": "PERSISTE…cdef"})
    );
    assert!(!reply.body.contains(PERSISTED_KEY));
    assert!(!reply.body.contains(SEED_KEY));
    f.assert_persisted("api_key", PERSISTED_KEY);
}

#[tokio::test]
async fn stored_root_key_rotation_reaches_an_already_running_state_within_one_second() {
    const ROTATED_KEY: &str = "ROTATED-key-0123456789abcdef";
    let f = Fixture::new(ROOT_KEY);
    let cookie = f.session().await;
    f.models_with_key(ROOT_KEY)
        .await
        .expect_status(StatusCode::OK);
    f.models_with_key(ROTATED_KEY)
        .await
        .expect_status(StatusCode::UNAUTHORIZED);
    let updated = f
        .state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE settings SET value = ?1 WHERE key = 'api_key'",
            [ROTATED_KEY],
        )
        .unwrap();
    assert_eq!(updated, 1);
    // Inside the refresh window the old key remains valid; omit a new-key probe that could cross it.
    f.models_with_key(ROOT_KEY)
        .await
        .expect_status(StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    // Go auth.go:487-496 reads the stored key; this packet permits at most one second of staleness.
    f.models_with_key(ROTATED_KEY)
        .await
        .expect_status(StatusCode::OK);
    f.models_with_key(ROOT_KEY)
        .await
        .expect_status(StatusCode::UNAUTHORIZED);
    let reply = f.get("/api/settings/api-key", &cookie).await;
    reply.expect_status(StatusCode::OK);
    // Go auth.go:826-840 masks the current stored key without returning plaintext.
    assert_eq!(
        reply.json(),
        json!({"has_api_key": true, "api_key_masked": "ROTATED-…cdef"})
    );
    assert!(!reply.body.contains(ROTATED_KEY));
    assert!(!reply.body.contains(ROOT_KEY));
}

#[tokio::test]
async fn unreadable_stored_root_key_fails_closed_after_the_refresh_window() {
    let f = Fixture::new(ROOT_KEY);
    f.models_with_key(ROOT_KEY)
        .await
        .expect_status(StatusCode::OK);
    let updated = f
        .state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE settings SET value = 'vault1:invalid-envelope' WHERE key = 'api_key'",
            [],
        )
        .unwrap();
    assert_eq!(updated, 1);
    // The packet permits the cached key only until the one-second refresh window expires.
    f.models_with_key(ROOT_KEY)
        .await
        .expect_status(StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    // Go auth.go:487-496 rejects root authentication when the stored authority cannot be read.
    f.models_with_key(ROOT_KEY)
        .await
        .expect_status(StatusCode::UNAUTHORIZED);
    f.models_with_key("PUBLIC-garbage-root-key")
        .await
        .expect_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn password_change_accepts_old_password_and_replaces_login_credentials() {
    let f = Fixture::new("");
    let cookie = f.session().await;
    // Go auth.go:690-702 names the password-change fields old_password and new_password.
    let reply = f
        .post(
            "/api/auth/password",
            &cookie,
            json!({"old_password": PASSWORD, "new_password": NEW_PASSWORD}),
        )
        .await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(reply.json(), json!({"ok": true}));
    assert_ne!(
        f.state.setting("admin_password_default").as_deref(),
        Some("1")
    );
    {
        let db = f.state.db.lock().unwrap();
        let settings = store::load_settings(&db, &f.state.vault).unwrap();
        assert_ne!(
            settings.get("admin_password_default").map(String::as_str),
            Some("1")
        );
    }
    let reply = f
        .send(
            "POST",
            "/api/login",
            json!({"password": NEW_PASSWORD}),
            Options::default(),
        )
        .await;
    reply.expect_status(StatusCode::OK);
    assert_eq!(reply.json(), json!({"success": true, "username": "admin"}));
    let new_cookie = reply.header("set-cookie").split(';').next().unwrap();
    let check = f.get("/api/auth/check", new_cookie).await;
    check.expect_status(StatusCode::OK);
    // Go auth.go:676-688 exposes the cleared default-password flag on the new session.
    assert_eq!(
        check.json(),
        json!({"authenticated": true, "username": "admin", "is_default_password": false})
    );
    let reply = f
        .send(
            "POST",
            "/api/login",
            json!({"password": PASSWORD}),
            Options::default(),
        )
        .await;
    reply.expect_status(StatusCode::UNAUTHORIZED);
    assert!(!reply.headers.contains_key("set-cookie"));
}

#[tokio::test]
async fn totp_only_login_stages_a_challenge_and_preserves_inline_code_login() {
    let f = Fixture::new("");
    let cookie = f.session().await;
    let secret = f.setup_totp(&cookie).await;
    let code = current_totp_code(&secret).await;
    let enabled = f
        .post(
            "/api/auth/totp/enable",
            &cookie,
            json!({"current_password": PASSWORD, "code": code}),
        )
        .await;
    enabled.expect_status(StatusCode::OK);
    assert_recovery_codes(&enabled.json());
    // Go auth.go:640-654 stages enabled second factors without issuing a session.
    let staged = f
        .send(
            "POST",
            "/api/login",
            json!({"password": PASSWORD}),
            Options::default(),
        )
        .await;
    staged.expect_status(StatusCode::OK);
    assert!(!staged.headers.contains_key("set-cookie"));
    let body = staged.json();
    assert_eq!(body.as_object().unwrap().len(), 3);
    assert_eq!(body["two_factor_required"], json!(true));
    let challenge = body["challenge"].as_str().unwrap();
    assert!(!challenge.is_empty());
    let mut methods: Vec<&str> = body["methods"]
        .as_array()
        .unwrap()
        .iter()
        .map(|method| method.as_str().unwrap())
        .collect();
    methods.sort_unstable();
    assert_eq!(methods, vec!["recovery", "totp"]);
    let code = current_totp_code(&secret).await;
    // Go auth_totp.go:269-314 exchanges the challenge and TOTP proof for a session.
    let verified = f
        .send(
            "POST",
            "/api/login/totp",
            json!({"challenge": challenge, "code": code}),
            Options::default(),
        )
        .await;
    verified.expect_status(StatusCode::OK);
    assert_eq!(
        verified.json(),
        json!({"success": true, "username": "admin"})
    );
    let verified_cookie = verified.header("set-cookie").split(';').next().unwrap();
    let check = f.get("/api/auth/check", verified_cookie).await;
    check.expect_status(StatusCode::OK);
    // Go auth.go:676-688 returns identity and bootstrap state for an authenticated session.
    assert_eq!(
        check.json(),
        json!({"authenticated": true, "username": "admin", "is_default_password": true})
    );
    let code = current_totp_code(&secret).await;
    let inline = f
        .send(
            "POST",
            "/api/login",
            json!({"password": PASSWORD, "code": code}),
            Options::default(),
        )
        .await;
    inline.expect_status(StatusCode::OK);
    assert_eq!(inline.json(), json!({"success": true, "username": "admin"}));
    let inline_cookie = inline.header("set-cookie").split(';').next().unwrap();
    let check = f.get("/api/auth/check", inline_cookie).await;
    check.expect_status(StatusCode::OK);
    assert_eq!(
        check.json(),
        json!({"authenticated": true, "username": "admin", "is_default_password": true})
    );
}

#[tokio::test]
async fn login_validates_supplied_username_and_check_reports_the_configured_identity() {
    let f = Fixture::new("");
    let cookie = f.session().await;
    let renamed = f
        .post(
            "/api/auth/username",
            &cookie,
            json!({"new_username": "ops.admin-2", "current_password": PASSWORD}),
        )
        .await;
    renamed.expect_status(StatusCode::OK);
    assert_eq!(
        renamed.json(),
        json!({"username": "ops.admin-2", "message": "username updated"})
    );
    // Go auth.go:373-405 rejects a supplied username that differs from adminUser().
    let wrong = f
        .send(
            "POST",
            "/api/login",
            json!({"username": "wrong", "password": PASSWORD}),
            Options::default(),
        )
        .await;
    wrong.expect_status(StatusCode::UNAUTHORIZED);
    assert!(!wrong.headers.contains_key("set-cookie"));
    for credentials in [
        json!({"username": "ops.admin-2", "password": PASSWORD}),
        json!({"password": PASSWORD}),
    ] {
        let login = f
            .send("POST", "/api/login", credentials, Options::default())
            .await;
        login.expect_status(StatusCode::OK);
        assert_eq!(
            login.json(),
            json!({"success": true, "username": "ops.admin-2"})
        );
        let session_cookie = login.header("set-cookie").split(';').next().unwrap();
        let check = f.get("/api/auth/check", session_cookie).await;
        check.expect_status(StatusCode::OK);
        // Go auth.go:676-688 reports the current administrator name and a boolean default flag.
        assert_eq!(
            check.json(),
            json!({"authenticated": true, "username": "ops.admin-2", "is_default_password": true})
        );
    }
}

#[tokio::test]
async fn api_json_responses_use_no_store_without_changing_console_asset_caching() {
    let f = Fixture::new(ROOT_KEY);
    let cookie = f.session().await;
    // Go auth.go:912-918 sets no-store on management JSON responses.
    let key = f.get("/api/settings/api-key", &cookie).await;
    key.expect_status(StatusCode::OK);
    assert_eq!(key.header("cache-control"), "no-store");
    assert_eq!(
        key.json(),
        json!({"has_api_key": true, "api_key_masked": "ROOTKEY-…cdef"})
    );
    let dashboard = f.get("/api/dashboard", &cookie).await;
    dashboard.expect_status(StatusCode::OK);
    assert_eq!(dashboard.header("cache-control"), "no-store");
    let revealed = f
        .post(
            "/api/settings/api-key/reveal",
            &cookie,
            json!({"verify_password": PASSWORD}),
        )
        .await;
    revealed.expect_status(StatusCode::OK);
    assert_eq!(revealed.header("cache-control"), "no-store");
    assert_eq!(
        revealed.json(),
        json!({"api_key": ROOT_KEY, "has_api_key": true})
    );
    // Unlike Go auth.go:912-918, current Rust session middleware emits 401 without a cache header.
    let unauthorized = f
        .send("GET", "/api/dashboard", Value::Null, Options::default())
        .await;
    unauthorized.expect_status(StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauthorized.json(),
        json!({"error": {"message": "unauthorized", "type": "api_error"}})
    );
    // Go main.go:214-218 keeps asset revalidation separate from JSON's no-store policy.
    let asset = f
        .send("GET", "/web/static/app.js", Value::Null, Options::default())
        .await;
    asset.expect_status(StatusCode::OK);
    assert_eq!(asset.header("cache-control"), "no-cache, must-revalidate");
    assert_eq!(
        asset.header("content-type"),
        "text/javascript; charset=utf-8"
    );
    assert!(asset.body.starts_with("/* ZCode Proxy"));
}

#[tokio::test]
async fn panel_management_routes_require_a_session_even_with_the_root_api_key() {
    let f = Fixture::new(ROOT_KEY);
    for (method, path, body) in [
        ("GET", "/api/auth/totp/status", Value::Null),
        (
            "POST",
            "/api/auth/totp/enable",
            json!({"current_password": PASSWORD, "code": "000000"}),
        ),
        (
            "POST",
            "/api/auth/username",
            json!({"new_username": "ops.admin-2", "current_password": PASSWORD}),
        ),
        ("GET", "/api/settings/api-key", Value::Null),
        (
            "POST",
            "/api/settings/api-key/reveal",
            json!({"verify_password": PASSWORD}),
        ),
        (
            "POST",
            "/api/settings/api-key/generate",
            json!({"verify_password": PASSWORD}),
        ),
        ("GET", "/api/dashboard", Value::Null),
        ("GET", "/api/groups", Value::Null),
        ("GET", "/api/fingerprints", Value::Null),
        ("GET", "/api/models", Value::Null),
    ] {
        let reply = f
            .send(
                method,
                path,
                body,
                Options {
                    api_key: Some(ROOT_KEY),
                    ..Options::default()
                },
            )
            .await;
        reply.expect_status(StatusCode::UNAUTHORIZED);
        assert_eq!(
            reply.json(),
            json!({"error": {"message": "unauthorized", "type": "api_error"}}),
            "{method} {path}"
        );
    }
    f.assert_persisted("api_key", ROOT_KEY);
    f.assert_persisted("admin_username", "admin");
}
