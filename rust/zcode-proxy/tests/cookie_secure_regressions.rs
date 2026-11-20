use std::ffi::OsString;
use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use serde_json::json;
use tower::ServiceExt;
use zcode_proxy::{
    admin::cookie_secure_from,
    build_router,
    state::{AppState, UpstreamUrls},
    store,
};

const COOKIE_SECURE_ENV: &str = "ZCODE_COOKIE_SECURE";
const PASSWORD: &str = "PUBLIC-cookie-regression-password";

// Env-mutating tests must stay in this file: this mutex cannot protect other files.
static COOKIE_SECURE_LOCK: Mutex<()> = Mutex::new(());

struct RestoreCookieSecure(Option<OsString>);

impl Drop for RestoreCookieSecure {
    fn drop(&mut self) {
        match &self.0 {
            Some(value) => std::env::set_var(COOKIE_SECURE_ENV, value),
            None => std::env::remove_var(COOKIE_SECURE_ENV),
        }
    }
}

fn with_cookie_secure<T>(value: Option<&str>, test: impl FnOnce() -> T) -> T {
    let _lock = COOKIE_SECURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = RestoreCookieSecure(std::env::var_os(COOKIE_SECURE_ENV));
    match value {
        Some(value) => std::env::set_var(COOKIE_SECURE_ENV, value),
        None => std::env::remove_var(COOKIE_SECURE_ENV),
    }
    test()
}

fn app() -> Router {
    let db = store::open(":memory:");
    store::set_setting(
        &db,
        "admin_password_hash",
        &bcrypt::hash(PASSWORD, 4).unwrap(),
    );
    let state = AppState::from_db(
        String::new(),
        UpstreamUrls {
            zai: "http://127.0.0.1:1/unused".into(),
            zai_fallback: "http://127.0.0.1:1/unused".into(),
        },
        db,
    );
    build_router(Arc::new(state))
}

async fn response_cookie(
    app: &Router,
    path: &str,
    session: Option<&str>,
    forwarded_proto: Option<&str>,
) -> String {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(session) = session {
        request = request.header("cookie", session);
    }
    if let Some(proto) = forwarded_proto {
        request = request.header("x-forwarded-proto", proto);
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(Body::from(json!({"password": PASSWORD}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "request to {path}");
    response
        .headers()
        .get("set-cookie")
        .expect("successful auth response sets a cookie")
        .to_str()
        .unwrap()
        .to_string()
}

fn assert_session_attrs(cookie: &str) {
    assert!(cookie.starts_with("zcode_rs_session="));
    let attrs: Vec<_> = cookie.split(';').skip(1).map(str::trim).collect();
    for attr in ["Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=86400"] {
        assert!(attrs.contains(&attr), "session cookie must retain {attr}");
    }
}

fn login_cookie(value: Option<&str>, forwarded_proto: Option<&str>) -> String {
    with_cookie_secure(value, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let cookie = response_cookie(&app(), "/api/login", None, forwarded_proto).await;
                assert_session_attrs(&cookie);
                cookie
            })
    })
}

#[test]
fn cookie_secure_from_matches_go_override_values() {
    for (value, expected) in [
        (None, false),
        (Some(""), false),
        (Some(" \t\r\n"), false),
        (Some("1"), true),
        (Some("true"), true),
        (Some("YES"), true),
        (Some("on"), true),
        (Some(" TrUe "), true),
        (Some("\tyEs\r\n"), true),
        (Some(" ON "), true),
        (Some(" 1 "), true),
        (Some("0"), false),
        (Some("off"), false),
        (Some("false"), false),
        (Some("enabled"), false),
        (Some("true-ish"), false),
        (Some("2"), false),
    ] {
        assert_eq!(cookie_secure_from(value), expected, "override {value:?}");
    }
}

#[test]
fn login_default_cookie_retains_attrs_without_secure() {
    let cookie = login_cookie(None, None);
    assert!(!cookie.contains("Secure"));
}

#[test]
fn login_cookie_is_secure_for_one() {
    assert!(login_cookie(Some("1"), None).contains("; Secure"));
}

#[test]
fn login_cookie_is_secure_for_true() {
    assert!(login_cookie(Some("true"), None).contains("; Secure"));
}

#[test]
fn login_cookie_is_secure_for_uppercase_yes() {
    assert!(login_cookie(Some("YES"), None).contains("; Secure"));
}

#[test]
fn login_cookie_is_secure_for_on() {
    assert!(login_cookie(Some("on"), None).contains("; Secure"));
}

#[test]
fn login_cookie_trims_and_normalizes_override() {
    assert!(login_cookie(Some(" \tTrUe\r\n"), None).contains("; Secure"));
}

#[test]
fn login_cookie_is_not_secure_for_disabled_or_unknown_overrides() {
    for value in ["0", "off", "", "enabled"] {
        let cookie = login_cookie(Some(value), None);
        assert!(!cookie.contains("Secure"), "override {value:?}");
    }
}

#[test]
fn login_cookie_does_not_trust_forwarded_https() {
    let cookie = login_cookie(None, Some("https"));
    assert!(!cookie.contains("Secure"));
}

#[test]
fn logout_cookie_still_clears_with_and_without_secure_override() {
    for value in [None, Some("1")] {
        with_cookie_secure(value, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let app = app();
                    let login = response_cookie(&app, "/api/login", None, None).await;
                    let session = login.split(';').next().unwrap();
                    let logout = response_cookie(&app, "/api/logout", Some(session), None).await;
                    assert!(logout.contains("; Max-Age=-1"));
                    assert!(logout.contains("; HttpOnly"));
                });
        });
    }
}
