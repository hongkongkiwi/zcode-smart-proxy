use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_cbor_2::Value as Cbor;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use webauthn_rs_core::proto::{COSEAlgorithm, COSEKey};
use zcode_proxy::{
    auth::now_secs,
    build_router,
    passkey::RpConfig,
    state::{AppState, UpstreamUrls},
    store,
};

const PASSWORD: &str = "PUBLIC-passkey-review-password";
const RP_ID: &str = "panel.example";
const HOST: &str = "panel.example:8443";
const ORIGIN: &str = "https://panel.example:8443";
const CREDENTIAL_ID: &[u8] = b"PUBLIC-passkey-review-credential";
const UP: u8 = 0x01;
const UV: u8 = 0x04;

struct Authenticator {
    signing: SigningKey,
}

impl Authenticator {
    fn new() -> Self {
        Self {
            signing: SigningKey::from_slice(&[7u8; 32]).unwrap(),
        }
    }

    fn cose_key(&self) -> Vec<u8> {
        let point = self.signing.verifying_key().to_encoded_point(false);
        let map = BTreeMap::from([
            (Cbor::Integer(1), Cbor::Integer(2)),
            (Cbor::Integer(3), Cbor::Integer(-7)),
            (Cbor::Integer(-1), Cbor::Integer(1)),
            (Cbor::Integer(-2), Cbor::Bytes(point.x().unwrap().to_vec())),
            (Cbor::Integer(-3), Cbor::Bytes(point.y().unwrap().to_vec())),
        ]);
        serde_cbor_2::to_vec(&Cbor::Map(map)).unwrap()
    }

    fn stored_credential(&self, counter: Option<u32>, user_verified: bool) -> Value {
        let mut authenticator = json!({"AAGUID": STANDARD.encode([0u8; 16])});
        if let Some(counter) = counter {
            authenticator["signCount"] = json!(counter);
        }
        json!([{
            "credential": {
                "id": STANDARD.encode(CREDENTIAL_ID),
                "publicKey": STANDARD.encode(self.cose_key()),
                "attestationType": "none",
                "flags": {
                    "userPresent": true,
                    "userVerified": user_verified,
                    "backupEligible": false,
                    "backupState": false,
                },
                "authenticator": authenticator,
            },
            "label": "PUBLIC-review-key",
            "created_at": "2026-11-01T12:00:00Z",
        }])
    }

    fn assertion(&self, challenge: &str, counter: u32, flags: u8) -> Value {
        let client_data = serde_json::to_vec(&json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": ORIGIN,
            "crossOrigin": false,
        }))
        .unwrap();
        let mut auth_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        auth_data.push(flags);
        auth_data.extend_from_slice(&counter.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let signature: Signature = self.signing.sign(&signed);
        json!({
            "id": URL_SAFE_NO_PAD.encode(CREDENTIAL_ID),
            "rawId": URL_SAFE_NO_PAD.encode(CREDENTIAL_ID),
            "type": "public-key",
            "response": {
                "authenticatorData": URL_SAFE_NO_PAD.encode(auth_data),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data),
                "signature": URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
            },
        })
    }
}

#[derive(Default)]
struct Options<'a> {
    cookie: Option<&'a str>,
    host: Option<&'a str>,
    origin: Option<&'a str>,
    peer: Option<SocketAddr>,
}

struct Reply {
    status: StatusCode,
    body: Value,
    cookie: Option<String>,
}

impl Reply {
    fn success(&self) {
        assert_eq!(self.status, StatusCode::OK, "body={}", self.body);
    }

    fn denied(&self) {
        assert!(self.status.is_client_error(), "body={}", self.body);
        assert!(self.cookie.is_none(), "a denial must not issue a session");
    }
}

struct Fixture {
    state: Arc<AppState>,
    app: Router,
}

impl Fixture {
    fn new() -> Self {
        let db = store::open(":memory:");
        store::set_setting(
            &db,
            "admin_password_hash",
            &bcrypt::hash(PASSWORD, 4).unwrap(),
        );
        let state = Arc::new(AppState::from_db(
            String::new(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
            db,
        ));
        state
            .set_webauthn_rp(RpConfig {
                rp_id: RP_ID.into(),
                origins: vec![ORIGIN.into()],
            })
            .unwrap();
        Self {
            app: build_router(state.clone()),
            state,
        }
    }

    async fn send(&self, method: &str, path: &str, body: Value, opts: Options<'_>) -> Reply {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", opts.host.unwrap_or(HOST))
            .header("content-type", "application/json");
        if let Some(cookie) = opts.cookie {
            builder = builder.header("cookie", cookie);
        }
        if let Some(origin) = opts.origin {
            builder = builder.header("origin", origin);
        }
        let mut request = builder.body(Body::from(body.to_string())).unwrap();
        if let Some(peer) = opts.peer {
            request.extensions_mut().insert(ConnectInfo(peer));
        }
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let cookie = response.headers().get("set-cookie").map(|value| {
            value
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_string()
        });
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        Reply {
            status,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            cookie,
        }
    }

    async fn login(&self, code: Option<&str>) -> Reply {
        let mut body = json!({"password": PASSWORD});
        if let Some(code) = code {
            body["code"] = json!(code);
        }
        self.send("POST", "/api/login", body, Options::default())
            .await
    }

    async fn session(&self) -> String {
        let reply = self.login(None).await;
        reply.success();
        reply
            .cookie
            .expect("password-only login issues a cookie pair")
    }

    fn seed_credential(&self, authenticator: &Authenticator, counter: Option<u32>, uv: bool) {
        self.state
            .persist_settings(&[(
                "passkey_credentials",
                &authenticator.stored_credential(counter, uv).to_string(),
            )])
            .unwrap();
    }

    fn credentials(&self) -> Value {
        serde_json::from_str(&self.state.setting("passkey_credentials").unwrap()).unwrap()
    }

    fn seed_totp(&self, secret: &str) -> Vec<String> {
        let (plain, hashes) = zcode_core::generate_recovery_codes(3);
        self.state
            .persist_settings(&[
                ("totp_enabled", "1"),
                ("totp_secret", secret),
                (
                    "recovery_codes",
                    &zcode_core::recovery_codes_to_json(&hashes),
                ),
            ])
            .unwrap();
        plain
    }

    async fn stage(&self) -> String {
        let reply = self.login(None).await;
        reply.success();
        assert_eq!(reply.body["two_factor_required"], true);
        assert!(
            reply.cookie.is_none(),
            "password stage must not issue a session"
        );
        reply.body["challenge"].as_str().unwrap().to_string()
    }

    async fn assert_passkey(
        &self,
        authenticator: &Authenticator,
        counter: u32,
        flags: u8,
    ) -> Reply {
        let challenge = self.stage().await;
        let begin = self
            .send(
                "POST",
                "/api/login/passkey/begin",
                json!({"challenge": challenge}),
                Options::default(),
            )
            .await;
        begin.success();
        let options = begin.body["options"]
            .get("publicKey")
            .unwrap_or(&begin.body["options"]);
        let credential =
            authenticator.assertion(options["challenge"].as_str().unwrap(), counter, flags);
        self.send(
            "POST",
            &format!(
                "/api/login/passkey/finish?ticket={}",
                begin.body["ticket"].as_str().unwrap()
            ),
            credential,
            Options::default(),
        )
        .await
    }

    async fn recover(&self, code: &str) -> Reply {
        let challenge = self.stage().await;
        self.send(
            "POST",
            "/api/login/totp",
            json!({"challenge": challenge, "code": code}),
            Options::default(),
        )
        .await
    }
}

#[test]
fn review_authenticator_fixture_has_valid_cose_and_der_signature() {
    let authenticator = Authenticator::new();
    let value: Cbor = serde_cbor_2::from_slice(&authenticator.cose_key()).unwrap();
    let Cbor::Map(ref map) = value else {
        panic!("COSE public key must be a map");
    };
    assert_eq!(map.get(&Cbor::Integer(3)), Some(&Cbor::Integer(-7)));
    assert_eq!(
        serde_cbor_2::to_vec(&Cbor::Integer(-7)).unwrap(),
        vec![0x26]
    );
    let key = COSEKey::try_from(&value).expect("fixture must be a valid COSE key");
    assert_eq!(key.type_, COSEAlgorithm::ES256);
    let assertion = authenticator.assertion("PUBLIC-fixture-challenge", 0, UP);
    let response = &assertion["response"];
    let mut signed = URL_SAFE_NO_PAD
        .decode(response["authenticatorData"].as_str().unwrap())
        .unwrap();
    let client = URL_SAFE_NO_PAD
        .decode(response["clientDataJSON"].as_str().unwrap())
        .unwrap();
    signed.extend_from_slice(&Sha256::digest(client));
    let signature = URL_SAFE_NO_PAD
        .decode(response["signature"].as_str().unwrap())
        .unwrap();
    assert!(Signature::from_der(&signature).is_ok());
    assert!(key.verify_signature(&signature, &signed).unwrap());
    signed[0] ^= 1;
    assert!(!key.verify_signature(&signature, &signed).unwrap());
}

#[tokio::test]
async fn go_omitted_zero_counter_import_accepts_genuine_zero_counter_assertions() {
    let f = Fixture::new();
    let authenticator = Authenticator::new();
    f.seed_credential(&authenticator, None, false);
    assert!(f.credentials()[0]["credential"]["authenticator"]
        .get("signCount")
        .is_none());
    for _ in 0..2 {
        let reply = f.assert_passkey(&authenticator, 0, UP).await;
        reply.success();
        assert!(
            reply.cookie.is_some(),
            "zero-only Go authenticator must log in"
        );
    }
}

#[tokio::test]
async fn disabling_totp_preserves_passkey_recovery_codes_and_consumes_only_the_proof() {
    for use_recovery in [false, true] {
        let f = Fixture::new();
        let cookie = f.session().await;
        f.seed_credential(&Authenticator::new(), Some(0), false);
        let secret = zcode_core::new_totp_secret();
        let recovery = f.seed_totp(&secret);
        let hashes =
            zcode_core::recovery_codes_from_json(f.state.setting("recovery_codes").as_deref());
        let proof = if use_recovery {
            recovery[0].clone()
        } else {
            zcode_core::totp_now(&zcode_core::base32_decode(&secret).unwrap(), now_secs())
        };
        let disabled = f
            .send(
                "POST",
                "/api/auth/totp/disable",
                json!({"current_password": PASSWORD, "code": proof}),
                Options {
                    cookie: Some(&cookie),
                    ..Options::default()
                },
            )
            .await;
        disabled.success();
        assert_eq!(disabled.body["enabled"], false);
        let remaining =
            zcode_core::recovery_codes_from_json(f.state.setting("recovery_codes").as_deref());
        let expected = if use_recovery {
            &hashes[1..]
        } else {
            &hashes[..]
        };
        assert_eq!(
            remaining, expected,
            "passkey fallback codes survive TOTP disable"
        );
        if use_recovery {
            f.recover(&recovery[0]).await.denied();
        }
        for code in recovery.iter().skip(usize::from(use_recovery)) {
            let reply = f.recover(code).await;
            reply.success();
            assert!(
                reply.cookie.is_some(),
                "remaining fallback code completes login"
            );
        }
    }
}

#[tokio::test]
async fn successful_user_verification_latches_and_rejects_a_later_uv_downgrade() {
    let f = Fixture::new();
    let authenticator = Authenticator::new();
    f.seed_credential(&authenticator, Some(0), false);
    let initially_unverified = f.assert_passkey(&authenticator, 1, UP).await;
    initially_unverified.success();
    assert!(initially_unverified.cookie.is_some());
    let verified = f.assert_passkey(&authenticator, 2, UP | UV).await;
    verified.success();
    assert!(verified.cookie.is_some());
    assert_eq!(
        f.credentials()[0]["credential"]["flags"]["userVerified"],
        true,
        "a successful UV assertion must persist the verification latch"
    );
    let downgrade = f.assert_passkey(&authenticator, 3, UP).await;
    assert_eq!(
        downgrade.status,
        StatusCode::UNAUTHORIZED,
        "body={}",
        downgrade.body
    );
    downgrade.denied();
}

#[tokio::test]
async fn configured_rp_keeps_ordinary_same_origin_admin_routes_and_strict_ceremonies() {
    let f = Fixture::new();
    let login = f
        .send(
            "POST",
            "/api/login",
            json!({"password": PASSWORD}),
            Options {
                host: Some("localhost:8080"),
                origin: Some("http://localhost:8080"),
                ..Options::default()
            },
        )
        .await;
    login.success();
    let cookie = login
        .cookie
        .expect("ordinary same-origin login remains available");
    let settings = f
        .send(
            "PUT",
            "/api/settings",
            json!({"gateway_paused": "1"}),
            Options {
                cookie: Some(&cookie),
                host: Some("localhost:8080"),
                origin: Some("http://localhost:8080"),
                ..Options::default()
            },
        )
        .await;
    settings.success();
    assert_eq!(f.state.setting("gateway_paused").as_deref(), Some("1"));
    let cross_origin = f
        .send(
            "PUT",
            "/api/settings",
            json!({"gateway_paused": "0"}),
            Options {
                cookie: Some(&cookie),
                host: Some("localhost:8080"),
                origin: Some("https://attacker.example"),
                ..Options::default()
            },
        )
        .await;
    assert_eq!(cross_origin.status, StatusCode::FORBIDDEN);
    assert_eq!(f.state.setting("gateway_paused").as_deref(), Some("1"));
    let ceremony = f
        .send(
            "POST",
            "/api/auth/passkey/register/begin",
            json!({"current_password": PASSWORD}),
            Options {
                cookie: Some(&cookie),
                host: Some("localhost:8080"),
                origin: Some("http://localhost:8080"),
                ..Options::default()
            },
        )
        .await;
    assert_eq!(
        ceremony.status,
        StatusCode::FORBIDDEN,
        "a ceremony still requires a configured RP origin"
    );
    let allowed = f
        .send(
            "POST",
            "/api/auth/passkey/register/begin",
            json!({"current_password": PASSWORD}),
            Options {
                cookie: Some(&cookie),
                origin: Some(ORIGIN),
                ..Options::default()
            },
        )
        .await;
    allowed.success();
}

#[tokio::test]
async fn enabled_empty_or_malformed_totp_never_accepts_an_empty_key_code() {
    for secret in ["", "A", "PUBLIC-not-base32"] {
        for staged in [false, true] {
            let f = Fixture::new();
            if staged {
                f.seed_credential(&Authenticator::new(), Some(0), false);
            }
            let recovery = f.seed_totp(secret);
            let empty_key_code = zcode_core::totp_now(&[], now_secs());
            let reply = if staged {
                f.recover(&empty_key_code).await
            } else {
                f.login(Some(&empty_key_code)).await
            };
            assert_eq!(
                reply.status,
                StatusCode::UNAUTHORIZED,
                "invalid enrolled secret {secret:?}, staged={staged}: body={}",
                reply.body
            );
            reply.denied();
            let fallback = if staged {
                f.recover(&recovery[0]).await
            } else {
                f.login(Some(&recovery[0])).await
            };
            fallback.success();
            assert!(
                fallback.cookie.is_some(),
                "malformed TOTP must not disable valid recovery proof"
            );
        }
    }
}

#[tokio::test]
async fn password_change_step_up_locks_after_five_failures_per_peer() {
    let f = Fixture::new();
    let cookie = f.session().await;
    let peer: SocketAddr = "192.0.2.60:40000".parse().unwrap();
    let original_hash = f.state.setting("admin_password_hash");
    for _ in 0..5 {
        let reply = f
            .send(
                "POST",
                "/api/auth/password",
                json!({"current_password": "PUBLIC-wrong", "new_password": "PUBLIC-new-password"}),
                Options {
                    cookie: Some(&cookie),
                    peer: Some(peer),
                    ..Options::default()
                },
            )
            .await;
        reply.denied();
    }
    for password in ["PUBLIC-wrong", PASSWORD] {
        let blocked = f
            .send(
                "POST",
                "/api/auth/password",
                json!({"current_password": password, "new_password": "PUBLIC-new-password"}),
                Options {
                    cookie: Some(&cookie),
                    peer: Some("192.0.2.60:40001".parse().unwrap()),
                    ..Options::default()
                },
            )
            .await;
        assert_eq!(
            blocked.status,
            StatusCode::TOO_MANY_REQUESTS,
            "body={}",
            blocked.body
        );
        blocked.denied();
        assert_eq!(f.state.setting("admin_password_hash"), original_hash);
    }
    let other_peer = f
        .send(
            "POST",
            "/api/auth/password",
            json!({"current_password": "PUBLIC-wrong", "new_password": "PUBLIC-new-password"}),
            Options {
                cookie: Some(&cookie),
                peer: Some("192.0.2.61:40000".parse().unwrap()),
                ..Options::default()
            },
        )
        .await;
    other_peer.denied();
    assert_ne!(
        other_peer.status,
        StatusCode::TOO_MANY_REQUESTS,
        "another peer has its own attempt budget"
    );
}
