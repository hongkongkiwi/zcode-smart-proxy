use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    Router,
};
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceExt;
use zcode_proxy::{
    build_router,
    state::{AppState, UpstreamUrls},
    store,
};

struct Fixture {
    app: Router,
    password: String,
}

struct LoginReply {
    status: StatusCode,
    body: Value,
    has_session_cookie: bool,
}

impl Fixture {
    fn new() -> Self {
        let password = format!("admin-peer-test-{:032x}", rand::random::<u128>());
        let db = store::open(":memory:");
        store::set_setting(
            &db,
            "admin_password_hash",
            &bcrypt::hash(&password, 4).unwrap(),
        );
        let state = Arc::new(AppState::from_db(
            String::new(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
            db,
        ));
        Self {
            app: build_router(state),
            password,
        }
    }

    async fn login(&self, peer: SocketAddr, password: &str, xff: Option<&str>) -> LoginReply {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/api/login")
            .header("host", "localhost:8080")
            .header("content-type", "application/json");
        if let Some(xff) = xff {
            builder = builder.header("x-forwarded-for", xff);
        }
        let mut request = builder
            .body(Body::from(json!({"password": password}).to_string()))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let has_session_cookie = response.headers().contains_key("set-cookie");
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        LoginReply {
            status,
            body: serde_json::from_slice(&bytes).unwrap(),
            has_session_cookie,
        }
    }

    async fn lock_out(&self, peer: SocketAddr) {
        for _ in 0..5 {
            assert_denied(&self.login(peer, "incorrect-password", None).await);
        }
    }
}

fn assert_denied(reply: &LoginReply) {
    assert!(
        matches!(
            reply.status,
            StatusCode::UNAUTHORIZED | StatusCode::TOO_MANY_REQUESTS
        ),
        "login must be denied, status={}, body={}",
        reply.status,
        reply.body
    );
    assert_eq!(reply.body["success"], false);
    assert!(
        !reply.has_session_cookie,
        "denied login must not issue a session"
    );
}

#[tokio::test]
async fn failed_peer_does_not_lock_out_a_different_peer_ip() {
    let f = Fixture::new();
    f.lock_out("192.0.2.1:40000".parse().unwrap()).await;

    let reply = f
        .login("192.0.2.2:40000".parse().unwrap(), &f.password, None)
        .await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "another peer's failures must not block valid credentials, body={}",
        reply.body
    );
    assert_eq!(reply.body["success"], true);
    assert!(
        reply.has_session_cookie,
        "successful login must issue a session"
    );

    assert_denied(
        &f.login("192.0.2.1:40000".parse().unwrap(), &f.password, None)
            .await,
    );
}

#[tokio::test]
async fn changing_source_port_does_not_bypass_peer_ip_lockout() {
    let f = Fixture::new();
    f.lock_out("192.0.2.1:40000".parse().unwrap()).await;
    assert_denied(
        &f.login("192.0.2.1:40001".parse().unwrap(), &f.password, None)
            .await,
    );
}

#[tokio::test]
async fn spoofed_forwarded_for_does_not_bypass_peer_ip_lockout() {
    let f = Fixture::new();
    f.lock_out("192.0.2.1:40000".parse().unwrap()).await;
    assert_denied(
        &f.login(
            "192.0.2.1:40000".parse().unwrap(),
            &f.password,
            Some("192.0.2.2"),
        )
        .await,
    );
}
