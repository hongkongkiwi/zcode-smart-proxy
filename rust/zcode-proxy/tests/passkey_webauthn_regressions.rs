//! Passkey/WebAuthn 2FA regressions. A soft authenticator holding a real
//! P-256 ES256 key drives the full ceremony pair (registration with fmt
//! "none", then staged-login assertions). No signature is ever faked: an
//! accepted response means the server verified a genuine ECDSA signature
//! over authenticator data it partly chose itself, and every tampered
//! variant (signature, origin, RP hash, user presence, challenge, counter)
//! must be rejected without issuing a session.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    Router,
};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    passkey::RpConfig,
    state::{AppState, UpstreamUrls},
    store,
};

const HOST: &str = "panel.example:8443";
const ORIGIN: &str = "https://panel.example:8443";
const RP_ID: &str = "panel.example";
const OTHER_RP_ID: &str = "other.example";
const OTHER_ORIGIN: &str = "https://other.example";
const PEER_A: &str = "192.0.2.10:40000";
const PEER_B: &str = "192.0.2.11:40000";

// WebAuthn authenticator-data flags.
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn unused_upstream() -> UpstreamUrls {
    UpstreamUrls {
        zai: "http://127.0.0.1:1/unused".into(),
        zai_fallback: "http://127.0.0.1:1/unused".into(),
    }
}

fn rp_config() -> RpConfig {
    RpConfig {
        rp_id: RP_ID.into(),
        origins: vec![ORIGIN.into()],
    }
}

// ---- Minimal CBOR writer (only the shapes a COSE EC2 key and a fmt "none"
// attestation object need). ----

fn cbor_uint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=23 => out.push(value as u8),
        24..=0xff => {
            out.push(0x18);
            out.push(value as u8);
        }
        0x100..=0xffff => {
            out.push(0x19);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        _ => {
            out.push(0x1a);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
    }
}

/// Major type 1: encodes a negative integer -`value` (value >= 1).
fn cbor_neg(out: &mut Vec<u8>, value: u64) {
    let first = out.len();
    cbor_uint(out, value - 1);
    out[first] |= 0x20;
}

fn cbor_text(out: &mut Vec<u8>, text: &str) {
    let bytes = text.as_bytes();
    if bytes.len() < 24 {
        out.push(0x60 | bytes.len() as u8);
    } else {
        out.push(0x78);
        out.push(bytes.len() as u8);
    }
    out.extend_from_slice(bytes);
}

fn cbor_bstr(out: &mut Vec<u8>, data: &[u8]) {
    if data.len() < 24 {
        out.push(0x40 | data.len() as u8);
    } else if data.len() <= 0xff {
        out.push(0x58);
        out.push(data.len() as u8);
    } else {
        out.push(0x59);
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(data);
}

/// COSE_Key for an ES256 (P-256, EC2, alg -7) public key.
/// `uncompressed` is the 65-byte SEC1 point (0x04 || x || y).
fn cose_es256_key(uncompressed: &[u8]) -> Vec<u8> {
    assert_eq!(uncompressed.len(), 65, "uncompressed SEC1 point expected");
    let mut out = Vec::with_capacity(80);
    out.push(0xa5); // map(5)
    cbor_uint(&mut out, 1);
    cbor_uint(&mut out, 2); // 1: kty = EC2
    cbor_uint(&mut out, 3);
    cbor_neg(&mut out, 7); // 3: alg = ES256 (-7)
    cbor_neg(&mut out, 1);
    cbor_uint(&mut out, 1); // -1: crv = P-256
    cbor_neg(&mut out, 2);
    cbor_bstr(&mut out, &uncompressed[1..33]); // -2: x
    cbor_neg(&mut out, 3);
    cbor_bstr(&mut out, &uncompressed[33..65]); // -3: y
    out
}

fn authenticator_data(
    rp_id: &str,
    flags: u8,
    counter: u32,
    attested: Option<(&[u8], &[u8])>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(37 + 18 + 64);
    out.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    out.push(flags);
    out.extend_from_slice(&counter.to_be_bytes());
    if let Some((credential_id, cose_key)) = attested {
        out.extend_from_slice(&[0u8; 16]); // AAGUID
        out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        out.extend_from_slice(credential_id);
        out.extend_from_slice(cose_key);
    }
    out
}

fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "type": kind,
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": false,
    }))
    .unwrap()
}

// ---- Soft authenticator: real ES256 keys, W3C wire format. ----

struct SoftAuthenticator {
    signing: SigningKey,
    credential_id: Vec<u8>,
}

impl SoftAuthenticator {
    fn new() -> Self {
        let mut seed = rand::random::<[u8; 32]>();
        let signing = loop {
            if let Ok(key) = SigningKey::from_slice(&seed) {
                break key;
            }
            seed = rand::random();
        };
        Self {
            signing,
            credential_id: rand::random::<[u8; 32]>().to_vec(),
        }
    }

    fn from_signing_key(signing: SigningKey, credential_id: Vec<u8>) -> Self {
        Self {
            signing,
            credential_id,
        }
    }

    fn uncompressed_public(&self) -> [u8; 65] {
        self.signing
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .expect("uncompressed P-256 point is 65 bytes")
    }

    fn cose_key(&self) -> Vec<u8> {
        cose_es256_key(&self.uncompressed_public())
    }

    /// PublicKeyCredential for registration (attestation format "none").
    fn registration(&self, challenge: &str, rp_id: &str, flags: u8) -> Value {
        self.registration_for(challenge, rp_id, flags, ORIGIN)
    }

    fn registration_for(&self, challenge: &str, rp_id: &str, flags: u8, origin: &str) -> Value {
        let auth_data = authenticator_data(
            rp_id,
            flags | FLAG_AT,
            0,
            Some((&self.credential_id, &self.cose_key())),
        );
        let mut attestation = Vec::with_capacity(auth_data.len() + 32);
        attestation.push(0xa3); // map(3)
        cbor_text(&mut attestation, "fmt");
        cbor_text(&mut attestation, "none");
        cbor_text(&mut attestation, "attStmt");
        attestation.push(0xa0); // map(0)
        cbor_text(&mut attestation, "authData");
        cbor_bstr(&mut attestation, &auth_data);
        let client_data = client_data("webauthn.create", challenge, origin);
        let id = b64url(&self.credential_id);
        json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "response": {
                "attestationObject": b64url(&attestation),
                "clientDataJSON": b64url(&client_data),
            },
        })
    }

    /// PublicKeyCredential for an assertion. The signature covers
    /// authData || SHA-256(clientDataJSON) and is a real ES256 signature.
    fn assertion(
        &self,
        challenge: &str,
        rp_id: &str,
        counter: u32,
        flags: u8,
        origin: &str,
    ) -> Value {
        let auth_data = authenticator_data(rp_id, flags, counter, None);
        let client_data = client_data("webauthn.get", challenge, origin);
        let mut payload = auth_data.clone();
        payload.extend_from_slice(&Sha256::digest(&client_data));
        let signature: Signature = self.signing.sign(&payload);
        let id = b64url(&self.credential_id);
        json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "response": {
                "authenticatorData": b64url(&auth_data),
                "clientDataJSON": b64url(&client_data),
                "signature": b64url(signature.to_der().as_bytes()),
            },
        })
    }

    fn valid_assertion(&self, challenge: &str, counter: u32) -> Value {
        self.assertion(challenge, RP_ID, counter, FLAG_UP | FLAG_UV, ORIGIN)
    }

    /// Same assertion with an all-zero r||s pair: structurally valid 64-byte
    /// ECDSA bytes that can never verify (r = 0 is not a valid scalar).
    fn zero_signature_assertion(&self, challenge: &str, counter: u32) -> Value {
        let mut response = self.valid_assertion(challenge, counter);
        response["response"]["signature"] = json!(b64url(&[0u8; 64]));
        response
    }
}

// ---- Fixture ----

struct Reply {
    status: StatusCode,
    body: Value,
    cookie: Option<String>,
    cookie_attrs: String,
    no_store: bool,
}

impl Reply {
    fn error_message(&self) -> String {
        self.body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    fn denied(&self, context: &str) {
        assert!(
            self.status.is_client_error() || self.status.is_server_error(),
            "{context}: expected a denial, got {} {}",
            self.status,
            self.body
        );
        assert!(
            self.cookie.is_none(),
            "{context}: denied response must not issue a session cookie"
        );
    }
}

#[derive(Default)]
struct Opts {
    cookie: Option<String>,
    peer: Option<SocketAddr>,
    origin: Option<String>,
    host: Option<String>,
    header: Option<(&'static str, String)>,
}

impl Opts {
    fn cookie(cookie: &str) -> Self {
        Self {
            cookie: Some(cookie.to_string()),
            ..Self::default()
        }
    }

    fn peer(peer: SocketAddr) -> Self {
        Self {
            peer: Some(peer),
            ..Self::default()
        }
    }
}

struct Fixture {
    state: Arc<AppState>,
    app: Router,
    password: String,
}

impl Fixture {
    fn build(rp: Option<RpConfig>, ttl: Duration) -> Self {
        let password = format!("PUBLIC-passkey-{:032x}", rand::random::<u128>());
        let db = store::open(":memory:");
        store::set_setting(
            &db,
            "admin_password_hash",
            &bcrypt::hash(&password, 4).unwrap(),
        );
        let mut state = AppState::from_db(String::new(), unused_upstream(), db);
        state.passkey_ticket_ttl = ttl;
        if let Some(rp) = rp {
            state.set_webauthn_rp(rp).expect("valid RP config installs");
        }
        let state = Arc::new(state);
        let app = build_router(state.clone());
        Self {
            state,
            app,
            password,
        }
    }

    fn configured() -> Self {
        Self::build(Some(rp_config()), Duration::from_secs(300))
    }

    fn unconfigured() -> Self {
        Self::build(None, Duration::from_secs(300))
    }

    fn with_ticket_ttl(ttl: Duration) -> Self {
        Self::build(Some(rp_config()), ttl)
    }

    async fn send(&self, method: &str, path: &str, body: Value, opts: Opts) -> Reply {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", opts.host.as_deref().unwrap_or(HOST))
            .header("content-type", "application/json");
        if let Some(cookie) = &opts.cookie {
            let prefix = format!("{SESSION_COOKIE}=");
            let token = cookie.strip_prefix(&prefix).unwrap_or(cookie);
            builder = builder.header("cookie", format!("{prefix}{token}"));
        }
        if let Some(origin) = &opts.origin {
            builder = builder.header("origin", origin);
        }
        if let Some((name, value)) = opts.header {
            builder = builder.header(name, value);
        }
        let mut request = builder.body(Body::from(body.to_string())).unwrap();
        if let Some(peer) = opts.peer {
            request.extensions_mut().insert(ConnectInfo(peer));
        }
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let no_store = response
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("no-store"));
        let (cookie, cookie_attrs) = match response.headers().get("set-cookie") {
            Some(value) => {
                let value = value.to_str().unwrap().to_string();
                let mut parts = value.split(';');
                let cookie = parts.next().unwrap().to_string();
                let attrs = value[cookie.len()..].to_string();
                (Some(cookie), attrs)
            }
            None => (None, String::new()),
        };
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        Reply {
            status,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            cookie,
            cookie_attrs,
            no_store,
        }
    }

    async fn password_login(&self, password: &str) -> Reply {
        self.send(
            "POST",
            "/api/login",
            json!({"password": password}),
            Opts::default(),
        )
        .await
    }

    /// Password step of the staged flow: must not issue a session.
    async fn stage_login(&self, peer: Option<SocketAddr>) -> String {
        let opts = peer.map_or_else(Opts::default, Opts::peer);
        let reply = self.password_login_opts(&self.password, opts).await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "correct password must stage the second factor, body={}",
            reply.body
        );
        assert_eq!(reply.body["two_factor_required"], true);
        assert!(
            reply.cookie.is_none(),
            "staged password step must not issue a session"
        );
        reply.body["challenge"]
            .as_str()
            .expect("staged login returns a challenge token")
            .to_string()
    }

    async fn password_login_opts(&self, password: &str, opts: Opts) -> Reply {
        self.send("POST", "/api/login", json!({"password": password}), opts)
            .await
    }

    async fn begin_login(&self, challenge: &str) -> Value {
        let reply = self
            .send(
                "POST",
                "/api/login/passkey/begin",
                json!({"challenge": challenge}),
                Opts::default(),
            )
            .await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "passkey login begin must succeed, body={}",
            reply.body
        );
        reply.body
    }

    async fn finish_login(&self, ticket: &str, credential: Value) -> Reply {
        self.send(
            "POST",
            &format!("/api/login/passkey/finish?ticket={ticket}"),
            credential,
            Opts::default(),
        )
        .await
    }

    async fn begin_register(&self, cookie: &str, password: &str) -> Value {
        let reply = self
            .send(
                "POST",
                "/api/auth/passkey/register/begin",
                json!({"current_password": password, "label": "PUBLIC-workspace-key"}),
                Opts::cookie(cookie),
            )
            .await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "registration begin must succeed, body={}",
            reply.body
        );
        reply.body
    }

    async fn finish_register(&self, ticket: &str, credential: Value, cookie: &str) -> Reply {
        self.send(
            "POST",
            &format!("/api/auth/passkey/register/finish?ticket={ticket}"),
            credential,
            Opts::cookie(cookie),
        )
        .await
    }

    /// Full native enrollment with a fresh soft authenticator.
    async fn enroll(&self, cookie: &str, authenticator: &SoftAuthenticator) -> Value {
        let begin = self.begin_register(cookie, &self.password).await;
        let options = public_key_options(&begin);
        let challenge = options_challenge(options);
        let reply = self
            .finish_register(
                begin["ticket"].as_str().expect("registration ticket"),
                authenticator.registration(&challenge, RP_ID, FLAG_UP | FLAG_UV),
                cookie,
            )
            .await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "native enrollment must verify, body={}",
            reply.body
        );
        reply.body
    }

    async fn status(&self, cookie: &str) -> Value {
        let reply = self
            .send(
                "GET",
                "/api/auth/passkey/status",
                json!({}),
                Opts::cookie(cookie),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "status={}", reply.body);
        reply.body
    }

    fn synthetic_session(&self, token: &str) -> String {
        self.state
            .sessions
            .lock()
            .unwrap()
            .insert(token.to_string(), now_secs() + 3600);
        token.to_string()
    }

    fn stored_credentials(&self) -> Value {
        serde_json::from_str(
            &self
                .state
                .setting("passkey_credentials")
                .unwrap_or_default(),
        )
        .unwrap_or(Value::Null)
    }

    fn seed_totp(&self) -> (String, Vec<String>) {
        let secret = zcode_core::new_totp_secret();
        let (plain, hashes) = zcode_core::generate_recovery_codes(10);
        let recovery = zcode_core::recovery_codes_to_json(&hashes);
        self.state
            .persist_settings(&[
                ("totp_enabled", "1"),
                ("totp_secret", &secret),
                ("recovery_codes", &recovery),
            ])
            .unwrap();
        (secret, plain)
    }
}

fn public_key_options(begin_reply: &Value) -> &Value {
    let options = begin_reply
        .get("options")
        .expect("begin must return ceremony options");
    match options.get("publicKey") {
        Some(public_key) if public_key.is_object() => public_key,
        _ => options,
    }
}

fn options_challenge(options: &Value) -> String {
    options["challenge"]
        .as_str()
        .expect("options carry a challenge")
        .to_string()
}

fn totp_code(secret: &str) -> String {
    zcode_core::totp_now(&zcode_core::base32_decode(secret).unwrap(), now_secs())
}

#[test]
fn soft_authenticator_cose_fixture_encodes_es256_negative_integers() {
    use serde_cbor_2::Value as CborValue;
    use webauthn_rs_core::proto::{COSEAlgorithm, COSEKey};

    let mut encoded = Vec::new();
    cbor_neg(&mut encoded, 7);
    assert_eq!(encoded, vec![0x26]);

    let authenticator = imported_authenticator();
    let value: CborValue = serde_cbor_2::from_slice(&authenticator.cose_key())
        .expect("soft authenticator emits valid CBOR");
    let CborValue::Map(ref map) = value else {
        panic!("COSE key must be a CBOR map");
    };
    assert_eq!(
        map.get(&CborValue::Integer(3)),
        Some(&CborValue::Integer(-7))
    );
    let key = COSEKey::try_from(&value).expect("soft authenticator emits a valid COSE key");
    assert_eq!(key.type_, COSEAlgorithm::ES256);
}

// ---- RP configuration ----

#[test]
fn rp_config_validate_rejects_insecure_or_malformed_relying_parties() {
    let valid = |rp_id: &str, origins: &[&str]| RpConfig {
        rp_id: rp_id.into(),
        origins: origins.iter().map(|o| o.to_string()).collect(),
    };

    assert!(valid("panel.example", &["https://panel.example:8443"])
        .validate()
        .is_ok());
    // A registrable-domain suffix of the origin host is allowed.
    assert!(valid("example.com", &["https://app.example.com"])
        .validate()
        .is_ok());
    // Plain HTTP is reserved for localhost development.
    assert!(valid("localhost", &["http://localhost:8080"])
        .validate()
        .is_ok());

    for (rp_id, origins) in [
        ("", &["https://panel.example:8443"][..]), // empty RP id
        ("panel.example", &[]),                    // no origins
        // IP relying parties are rejected.
        ("192.0.2.10", &["https://192.0.2.10"]),
        ("::1", &["https://[::1]:8443"]),
        // HTTP is not allowed off localhost.
        ("panel.example", &["http://panel.example:8443"]),
        // Origins must be exact scheme://host[:port] with no extra parts.
        ("panel.example", &["https://panel.example:8443/panel"]),
        ("panel.example", &["https://panel.example:8443/?x=1"]),
        ("panel.example", &["https://admin@panel.example:8443"]),
        // Wildcard subdomains and any-port origins are not a thing.
        ("*.example.com", &["https://app.example.com"]),
        ("example.com", &["https://app.example.com:*"]),
        // RP id must match the origin host or a real domain suffix.
        ("panel.example", &["https://app.example.com"]),
        // String-suffix is not a domain-boundary suffix.
        ("example.com", &["https://badexample.com"]),
    ] {
        let config = valid(rp_id, origins);
        assert!(
            config.validate().is_err(),
            "validate must reject rp_id={rp_id:?} origins={origins:?}"
        );
    }
}

// ---- Unconfigured RP fails closed ----

/// Go derives the RP from Host/X-Forwarded-Proto when unset; the Rust design
/// forbids that: client-controlled headers must never configure the ceremony.
#[tokio::test]
async fn unconfigured_rp_ceremonies_fail_closed_and_host_spoofing_cannot_configure() {
    let f = Fixture::unconfigured();

    // Other auth still works while passkeys are unconfigured.
    let direct = f.password_login(&f.password).await;
    assert_eq!(direct.status, StatusCode::OK, "body={}", direct.body);
    let cookie = direct.cookie.expect("password login issues a session");

    // Spoofed Host plus X-Forwarded-Proto must not mint a ceremony bound to
    // the attacker's host.
    let spoofed = f
        .send(
            "POST",
            "/api/auth/passkey/register/begin",
            json!({"current_password": f.password, "label": "spoof"}),
            Opts {
                cookie: Some(cookie.clone()),
                host: Some("attacker.example".into()),
                origin: Some("https://attacker.example".into()),
                header: Some(("x-forwarded-proto", "https".into())),
                ..Opts::default()
            },
        )
        .await;
    assert_eq!(
        spoofed.status,
        StatusCode::BAD_REQUEST,
        "unconfigured ceremony must fail with 400, not bind to spoofed Host, body={}",
        spoofed.body
    );
    let message = spoofed.error_message();
    assert!(
        !message.is_empty(),
        "error envelope must carry error.message"
    );
    let lower = message.to_lowercase();
    assert!(
        ["rpid", "zcode_web", "config", "origin"]
            .iter()
            .any(|needle| lower.contains(needle)),
        "unconfigured ceremony error must be actionable, got {message:?}"
    );

    // A rejected install must leave the state unconfigured.
    let invalid = RpConfig {
        rp_id: String::new(),
        origins: vec![ORIGIN.into()],
    };
    assert!(f.state.set_webauthn_rp(invalid).is_err());

    // Login side is equally fail-closed: an enrolled credential (seeded as a
    // Go-format store, no ceremony needed) cannot start a login ceremony.
    seed_go_credential_store(&f);
    let challenge = f.stage_login(None).await;
    let reply = f
        .send(
            "POST",
            "/api/login/passkey/begin",
            json!({"challenge": challenge}),
            Opts::default(),
        )
        .await;
    assert_eq!(
        reply.status,
        StatusCode::BAD_REQUEST,
        "unconfigured login ceremony must fail closed, body={}",
        reply.body
    );
    reply.denied("unconfigured login begin");
}

// ---- End-to-end ceremony with genuine signatures ----

#[tokio::test]
async fn registration_then_staged_login_verifies_real_signatures_and_persists_counters() {
    let f = Fixture::configured();
    let authenticator = SoftAuthenticator::new();

    // Wrong password cannot create a ceremony of either kind.
    let bad = f.password_login("PUBLIC-wrong-password").await;
    bad.denied("wrong password login");
    assert!(bad.body.get("challenge").is_none());

    // Before enrollment, password login still issues a session directly.
    let direct = f.password_login(&f.password).await;
    assert_eq!(direct.status, StatusCode::OK);
    let cookie = direct.cookie.expect("pre-enrollment session");

    // Registration begin is a password step-up.
    let wrong_step_up = f
        .send(
            "POST",
            "/api/auth/passkey/register/begin",
            json!({"current_password": "PUBLIC-wrong-password", "label": "x"}),
            Opts::cookie(&cookie),
        )
        .await;
    wrong_step_up.denied("registration begin without current password");

    let begin = f.begin_register(&cookie, &f.password).await;
    let options = public_key_options(&begin);
    assert_eq!(options["rp"]["id"], RP_ID);
    let user_handle = URL_SAFE_NO_PAD
        .decode(
            options["user"]["id"]
                .as_str()
                .expect("user handle in options"),
        )
        .expect("user handle is base64url");
    assert_eq!(
        user_handle.len(),
        32,
        "user handle is a stable 32-byte value"
    );
    let challenge = options_challenge(options);

    let finish = f
        .finish_register(
            begin["ticket"].as_str().unwrap(),
            authenticator.registration(&challenge, RP_ID, FLAG_UP | FLAG_UV),
            &cookie,
        )
        .await;
    assert_eq!(finish.status, StatusCode::OK, "body={}", finish.body);
    assert_eq!(finish.body["success"], true);
    assert_eq!(finish.body["count"], 1);
    let codes = finish.body["recovery_codes"]
        .as_array()
        .expect("first registration issues recovery codes");
    assert_eq!(codes.len(), 10, "one full set of recovery codes");

    // The credential store is encrypted at rest.
    let raw = store::get_setting(&f.state.db.lock().unwrap(), "passkey_credentials")
        .expect("credentials persisted");
    assert!(
        raw.starts_with("vault1:"),
        "passkey_credentials must be vault-encrypted at rest, got {raw:?}"
    );
    assert!(!raw.contains(&b64url(&authenticator.credential_id)));

    // Status mirrors the enrollment (session-gated).
    let no_session = f
        .send(
            "GET",
            "/api/auth/passkey/status",
            json!({}),
            Opts::default(),
        )
        .await;
    no_session.denied("status without a session");
    let status = f.status(&cookie).await;
    assert_eq!(status["count"], 1);
    let item = &status["items"][0];
    assert_eq!(item["id"], b64url(&authenticator.credential_id));
    assert_eq!(item["label"], "PUBLIC-workspace-key");
    assert!(!item["created_at"].is_null());

    // Password stage: 200 with a challenge, methods include passkey, no cookie.
    let challenge = f.stage_login(None).await;
    let staged = f.password_login(&f.password).await;
    let methods: Vec<&str> = staged.body["methods"]
        .as_array()
        .expect("staged login lists second-factor methods")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        methods.contains(&"passkey") && !methods.contains(&"totp"),
        "passkey is offered and TOTP is not enrolled, got {methods:?}"
    );

    let begin = f.begin_login(&challenge).await;
    let options = public_key_options(&begin);
    let login_challenge = options_challenge(options);
    let allowed: Vec<&str> = options["allowCredentials"]
        .as_array()
        .expect("allowCredentials lists enrolled credentials")
        .iter()
        .filter_map(|entry| entry["id"].as_str())
        .collect();
    assert!(
        allowed.contains(&b64url(&authenticator.credential_id).as_str()),
        "the enrolled credential must be usable, allow={allowed:?}"
    );

    // Genuine assertion with counter 1 completes login.
    let finish = f
        .finish_login(
            begin["ticket"].as_str().unwrap(),
            authenticator.valid_assertion(&login_challenge, 1),
        )
        .await;
    assert_eq!(finish.status, StatusCode::OK, "body={}", finish.body);
    assert_eq!(finish.body["success"], true);
    assert_eq!(finish.body["username"], "admin");
    let session = finish.cookie.expect("verified assertion issues a session");
    assert!(session.starts_with(&format!("{SESSION_COOKIE}=")));
    assert!(
        finish.cookie_attrs.contains("HttpOnly") && finish.cookie_attrs.contains("SameSite=Strict"),
        "passkey session cookie matches the existing auth cookie policy, attrs={}",
        finish.cookie_attrs
    );
    let check = f
        .send("GET", "/api/auth/check", json!({}), Opts::cookie(&session))
        .await;
    assert_eq!(check.body["authenticated"], true);

    // The staged challenge was consumed with the ceremony.
    let replayed_begin = f
        .send(
            "POST",
            "/api/login/passkey/begin",
            json!({"challenge": challenge}),
            Opts::default(),
        )
        .await;
    replayed_begin.denied("consumed challenge cannot begin another ceremony");

    // The counter was persisted: the next assertion must advance it.
    let challenge = f.stage_login(None).await;
    let begin = f.begin_login(&challenge).await;
    let login_challenge = options_challenge(public_key_options(&begin));
    let second = f
        .finish_login(
            begin["ticket"].as_str().unwrap(),
            authenticator.valid_assertion(&login_challenge, 2),
        )
        .await;
    assert_eq!(second.status, StatusCode::OK, "body={}", second.body);

    // Replaying the persisted counter must fail.
    let challenge = f.stage_login(None).await;
    let begin = f.begin_login(&challenge).await;
    let login_challenge = options_challenge(public_key_options(&begin));
    let replay = f
        .finish_login(
            begin["ticket"].as_str().unwrap(),
            authenticator.valid_assertion(&login_challenge, 2),
        )
        .await;
    replay.denied("assertion replaying the stored sign counter");
}

#[tokio::test]
async fn tampered_attestations_and_assertions_are_rejected() {
    let f = Fixture::configured();
    let authenticator = SoftAuthenticator::new();
    let direct = f.password_login(&f.password).await;
    let cookie = direct.cookie.expect("pre-enrollment session");
    f.enroll(&cookie, &authenticator).await;

    // Cross-origin Origin header on the public login route is refused before
    // any crypto runs.
    let challenge = f.stage_login(None).await;
    let cross_origin = f
        .send(
            "POST",
            "/api/login/passkey/begin",
            json!({"challenge": challenge}),
            Opts {
                origin: Some("https://attacker.example".into()),
                ..Opts::default()
            },
        )
        .await;
    assert_eq!(cross_origin.status, StatusCode::FORBIDDEN);

    // Each case needs a fresh ceremony (tickets are single use). Every case
    // tampers exactly one axis; all other material is genuine.
    let cases = [
        "zeroed ECDSA signature",
        "foreign origin in clientDataJSON",
        "authData hash of a foreign RP id",
        "user presence flag cleared",
        "challenge of a different ceremony",
    ];
    for (index, case) in cases.iter().enumerate() {
        let challenge = f.stage_login(None).await;
        let begin = f.begin_login(&challenge).await;
        let login_challenge = options_challenge(public_key_options(&begin));
        let credential = match index {
            0 => authenticator.zero_signature_assertion(&login_challenge, 1),
            1 => authenticator.assertion(
                &login_challenge,
                RP_ID,
                1,
                FLAG_UP | FLAG_UV,
                "https://attacker.example",
            ),
            2 => authenticator.assertion(
                &login_challenge,
                "attacker.example",
                1,
                FLAG_UP | FLAG_UV,
                ORIGIN,
            ),
            3 => authenticator.assertion(&login_challenge, RP_ID, 1, FLAG_UV, ORIGIN),
            _ => authenticator.valid_assertion("PUBLIC-other-ceremony", 1),
        };
        let reply = f
            .finish_login(begin["ticket"].as_str().unwrap(), credential)
            .await;
        reply.denied(&format!("tampered assertion: {case}"));
        assert_eq!(
            reply.status,
            StatusCode::UNAUTHORIZED,
            "{case}: body={}",
            reply.body
        );
        if index == 0 {
            assert!(
                reply.no_store,
                "passkey errors must be cache-control: no-store"
            );
            assert!(!reply.error_message().is_empty());
        }
    }

    // Registration side: malformed attestation objects are invalid
    // registrations, and user presence is mandatory there too.
    let begin = f.begin_register(&cookie, &f.password).await;
    let options = public_key_options(&begin);
    let reg_challenge = options_challenge(options);
    let garbage = f
        .finish_register(
            begin["ticket"].as_str().unwrap(),
            json!({
                "id": "PUBLIC",
                "rawId": "PUBLIC",
                "type": "public-key",
                "response": {
                    "attestationObject": b64url(b"PUBLIC-not-cbor"),
                    "clientDataJSON": b64url(&client_data(
                        "webauthn.create",
                        &reg_challenge,
                        ORIGIN
                    )),
                },
            }),
            &cookie,
        )
        .await;
    assert_eq!(
        garbage.status,
        StatusCode::BAD_REQUEST,
        "malformed attestation is an invalid registration, body={}",
        garbage.body
    );

    let begin = f.begin_register(&cookie, &f.password).await;
    let reg_challenge = options_challenge(public_key_options(&begin));
    let no_up = f
        .finish_register(
            begin["ticket"].as_str().unwrap(),
            authenticator.registration(&reg_challenge, RP_ID, FLAG_UV),
            &cookie,
        )
        .await;
    assert_eq!(
        no_up.status,
        StatusCode::BAD_REQUEST,
        "registration without user presence is invalid, body={}",
        no_up.body
    );
}

// ---- Ticket lifecycle ----

#[tokio::test]
async fn tickets_are_single_use_and_kind_checked() {
    let f = Fixture::configured();
    let authenticator = SoftAuthenticator::new();
    let cookie = f.password_login(&f.password).await.cookie.expect("session");
    f.enroll(&cookie, &authenticator).await;

    // A failed verification consumes the ticket before it verifies: a later
    // valid assertion with the same ticket must not succeed.
    let challenge = f.stage_login(None).await;
    let begin = f.begin_login(&challenge).await;
    let login_challenge = options_challenge(public_key_options(&begin));
    let ticket = begin["ticket"].as_str().unwrap().to_string();
    let bad = f
        .finish_login(
            &ticket,
            authenticator.zero_signature_assertion(&login_challenge, 1),
        )
        .await;
    bad.denied("invalid signature");
    let good = f
        .finish_login(&ticket, authenticator.valid_assertion(&login_challenge, 1))
        .await;
    good.denied("a failed finish must consume the ticket");

    // Kind mixing: a register ticket cannot finish a login and vice versa.
    let challenge = f.stage_login(None).await;
    let login_begin = f.begin_login(&challenge).await;
    let login_ticket = login_begin["ticket"].as_str().unwrap().to_string();

    let reg_begin = f.begin_register(&cookie, &f.password).await;
    let reg_ticket = reg_begin["ticket"].as_str().unwrap().to_string();

    let login_on_register = f
        .finish_register(
            &login_ticket,
            authenticator.registration("PUBLIC-dummy", RP_ID, FLAG_UP | FLAG_UV),
            &cookie,
        )
        .await;
    login_on_register.denied("login ticket at register finish");

    let register_on_login = f
        .finish_login(
            &reg_ticket,
            authenticator.valid_assertion("PUBLIC-dummy", 1),
        )
        .await;
    register_on_login.denied("register ticket at login finish");

    // Unknown or missing tickets are simply expired ceremonies.
    let unknown = f
        .finish_login(
            "PUBLIC-unknown-ticket",
            authenticator.valid_assertion("PUBLIC-dummy", 1),
        )
        .await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);

    // Login begin requires a live password challenge: no passwordless path.
    let bogus = f
        .send(
            "POST",
            "/api/login/passkey/begin",
            json!({"challenge": "PUBLIC-bogus-challenge"}),
            Opts::default(),
        )
        .await;
    bogus.denied("login begin without a password-stage challenge");
}

#[tokio::test]
async fn ticket_ttl_expires_pending_ceremonies() {
    assert_eq!(
        AppState::new(String::new(), unused_upstream()).passkey_ticket_ttl,
        Duration::from_secs(300),
        "default passkey ticket TTL is five minutes"
    );

    let f = Fixture::with_ticket_ttl(Duration::from_millis(30));
    let authenticator = SoftAuthenticator::new();
    let cookie = f.password_login(&f.password).await.cookie.expect("session");
    let begin = f.begin_register(&cookie, &f.password).await;
    let options = public_key_options(&begin);
    let challenge = options_challenge(options);
    tokio::time::sleep(Duration::from_millis(120)).await;
    let reply = f
        .finish_register(
            begin["ticket"].as_str().unwrap(),
            authenticator.registration(&challenge, RP_ID, FLAG_UP | FLAG_UV),
            &cookie,
        )
        .await;
    assert_eq!(
        reply.status,
        StatusCode::BAD_REQUEST,
        "expired ceremony must be rejected as expired, body={}",
        reply.body
    );
}

// ---- Registration races ----

#[tokio::test]
async fn registration_finish_revalidates_password_and_credential_snapshots() {
    // Password rotation between begin and finish kills the ceremony.
    let f = Fixture::configured();
    let authenticator = SoftAuthenticator::new();
    let cookie = f.password_login(&f.password).await.cookie.expect("session");
    let begin = f.begin_register(&cookie, &f.password).await;
    let challenge = options_challenge(public_key_options(&begin));
    f.state
        .persist_settings(&[(
            "admin_password_hash",
            &bcrypt::hash("PUBLIC-rotated-password", 4).unwrap(),
        )])
        .unwrap();
    let rotated = f
        .finish_register(
            begin["ticket"].as_str().unwrap(),
            authenticator.registration(&challenge, RP_ID, FLAG_UP | FLAG_UV),
            &cookie,
        )
        .await;
    rotated.denied("registration finish after password rotation");
    assert_eq!(
        f.status(&cookie).await["count"],
        0,
        "rejected finish must not store the credential"
    );

    // Deleting an existing credential between begin and finish is a
    // revocation race: the credentials snapshot no longer matches.
    let f = Fixture::configured();
    let first = SoftAuthenticator::new();
    let second = SoftAuthenticator::new();
    let cookie = f.password_login(&f.password).await.cookie.expect("session");
    f.enroll(&cookie, &first).await;
    let begin = f.begin_register(&cookie, &f.password).await;
    let challenge = options_challenge(public_key_options(&begin));
    let item_id = f.status(&cookie).await["items"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let deleted = f
        .send(
            "POST",
            "/api/auth/passkey/delete",
            json!({"id": item_id, "current_password": f.password}),
            Opts::cookie(&cookie),
        )
        .await;
    assert_eq!(deleted.status, StatusCode::OK, "body={}", deleted.body);
    let revoked = f
        .finish_register(
            begin["ticket"].as_str().unwrap(),
            second.registration(&challenge, RP_ID, FLAG_UP | FLAG_UV),
            &cookie,
        )
        .await;
    revoked.denied("registration finish after a credentials-set change");
    assert_eq!(
        f.status(&cookie).await["count"],
        0,
        "the race must not enroll anything"
    );
}

#[tokio::test]
async fn ceremonies_are_bound_to_session_peer_and_rp_config() {
    let f = Fixture::configured();
    let authenticator = SoftAuthenticator::new();
    let session_a = f.synthetic_session("PUBLIC-session-a-passkey");
    let session_b = f.synthetic_session("PUBLIC-session-b-passkey");
    let peer_a: SocketAddr = PEER_A.parse().unwrap();
    let peer_b: SocketAddr = PEER_B.parse().unwrap();

    // Session binding, with the owner success first: a foreign-session
    // finish consumes the ticket, so the retry must have its own ceremony.
    let begin = f
        .send(
            "POST",
            "/api/auth/passkey/register/begin",
            json!({"current_password": f.password, "label": "PUBLIC-key"}),
            Opts::cookie(&session_a),
        )
        .await;
    assert_eq!(begin.status, StatusCode::OK, "body={}", begin.body);
    let challenge = options_challenge(public_key_options(&begin.body));
    let owner = f
        .finish_register(
            begin.body["ticket"].as_str().unwrap(),
            authenticator.registration(&challenge, RP_ID, FLAG_UP | FLAG_UV),
            &session_a,
        )
        .await;
    assert_eq!(owner.status, StatusCode::OK, "body={}", owner.body);

    let begin = f
        .send(
            "POST",
            "/api/auth/passkey/register/begin",
            json!({"current_password": f.password, "label": "PUBLIC-key-2"}),
            Opts::cookie(&session_a),
        )
        .await;
    assert_eq!(begin.status, StatusCode::OK, "body={}", begin.body);
    let challenge = options_challenge(public_key_options(&begin.body));
    let ticket = begin.body["ticket"].as_str().unwrap().to_string();
    let foreign = f
        .finish_register(
            &ticket,
            authenticator.registration(&challenge, RP_ID, FLAG_UP | FLAG_UV),
            &session_b,
        )
        .await;
    foreign.denied("register finish from a different session");

    // Peer binding: begin and finish must come from the same client.
    let second = SoftAuthenticator::new();
    let begin = f
        .send(
            "POST",
            "/api/auth/passkey/register/begin",
            json!({"current_password": f.password, "label": "PUBLIC-key-3"}),
            Opts {
                cookie: Some(session_a.clone()),
                peer: Some(peer_a),
                ..Opts::default()
            },
        )
        .await;
    assert_eq!(begin.status, StatusCode::OK, "body={}", begin.body);
    let challenge = options_challenge(public_key_options(&begin.body));
    let ticket = begin.body["ticket"].as_str().unwrap().to_string();
    let moved = f
        .send(
            "POST",
            &format!("/api/auth/passkey/register/finish?ticket={ticket}"),
            second.registration(&challenge, RP_ID, FLAG_UP | FLAG_UV),
            Opts {
                cookie: Some(session_a),
                peer: Some(peer_b),
                ..Opts::default()
            },
        )
        .await;
    moved.denied("register finish from a different peer");

    // Login challenges are peer-bound too.
    let challenge = f.stage_login(Some(peer_a)).await;
    let foreign_peer = f
        .send(
            "POST",
            "/api/login/passkey/begin",
            json!({"challenge": challenge}),
            Opts::peer(peer_a),
        )
        .await;
    assert_eq!(foreign_peer.status, StatusCode::OK);
    let challenge = f.stage_login(Some(peer_a)).await;
    let other_peer = f
        .send(
            "POST",
            "/api/login/passkey/begin",
            json!({"challenge": challenge}),
            Opts::peer(peer_b),
        )
        .await;
    other_peer.denied("login begin from a different peer than the password stage");

    // RP-config binding: the ticket snapshots the RP config it was issued
    // under, so after a reconfiguration a valid attestation for the NEW RP
    // must still not complete the ceremony begun under the old one.
    let f2 = Fixture::configured();
    let session = f2.synthetic_session("PUBLIC-session-rp-reconfig");
    let begin = f2.begin_register(&session, &f2.password).await;
    let challenge = options_challenge(public_key_options(&begin));
    let ticket = begin["ticket"].as_str().unwrap().to_string();
    f2.state
        .set_webauthn_rp(RpConfig {
            rp_id: OTHER_RP_ID.into(),
            origins: vec![OTHER_ORIGIN.into()],
        })
        .expect("replacing with another valid config installs");
    let reconfigured = f2
        .finish_register(
            &ticket,
            authenticator.registration_for(
                &challenge,
                OTHER_RP_ID,
                FLAG_UP | FLAG_UV,
                OTHER_ORIGIN,
            ),
            &session,
        )
        .await;
    reconfigured.denied("attestation for a different RP than the ceremony's");
}

// ---- Duplicates and recovery-code issuance ----

#[tokio::test]
async fn duplicate_credentials_conflict_and_recovery_codes_issue_only_once() {
    let f = Fixture::configured();
    let authenticator = SoftAuthenticator::new();
    let other = SoftAuthenticator::new();
    let cookie = f.password_login(&f.password).await.cookie.expect("session");

    let first = f.enroll(&cookie, &authenticator).await;
    assert!(
        first["recovery_codes"].is_array(),
        "first registration issues recovery codes"
    );

    let second = f.enroll(&cookie, &other).await;
    assert!(
        second["recovery_codes"].is_null(),
        "existing recovery codes are not reissued, body={second}"
    );
    assert_eq!(f.status(&cookie).await["count"], 2);

    // The same credential id cannot register twice.
    let begin = f.begin_register(&cookie, &f.password).await;
    let challenge = options_challenge(public_key_options(&begin));
    let duplicate = f
        .finish_register(
            begin["ticket"].as_str().unwrap(),
            authenticator.registration(&challenge, RP_ID, FLAG_UP | FLAG_UV),
            &cookie,
        )
        .await;
    assert_eq!(
        duplicate.status,
        StatusCode::CONFLICT,
        "duplicate credential id conflicts, body={}",
        duplicate.body
    );
    assert_eq!(
        f.status(&cookie).await["count"],
        2,
        "conflicting registration must not change the stored set"
    );
}

// ---- Staged fallback factors ----

#[tokio::test]
async fn staged_totp_and_recovery_codes_complete_the_challenge_once() {
    let f = Fixture::configured();
    let authenticator = SoftAuthenticator::new();
    let cookie = f.password_login(&f.password).await.cookie.expect("session");
    f.enroll(&cookie, &authenticator).await;
    let (secret, recovery) = f.seed_totp();

    let staged = f.password_login(&f.password).await;
    let methods: Vec<&str> = staged.body["methods"]
        .as_array()
        .expect("methods list")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        methods.contains(&"passkey") && methods.contains(&"totp"),
        "both staged factors are advertised, got {methods:?}"
    );

    // TOTP completes the challenge and consumes it.
    let challenge = staged.body["challenge"].as_str().unwrap().to_string();
    let totp = f
        .send(
            "POST",
            "/api/login/totp",
            json!({"challenge": challenge, "code": totp_code(&secret)}),
            Opts::default(),
        )
        .await;
    assert_eq!(totp.status, StatusCode::OK, "body={}", totp.body);
    assert_eq!(totp.body["success"], true);
    assert!(totp.cookie.is_some(), "completed factor issues a session");
    let replay = f
        .send(
            "POST",
            "/api/login/totp",
            json!({"challenge": challenge, "code": totp_code(&secret)}),
            Opts::default(),
        )
        .await;
    replay.denied("consumed challenge cannot complete twice");

    // A recovery code is a shared fallback and burns on use.
    let challenge = f.stage_login(None).await;
    let used = f
        .send(
            "POST",
            "/api/login/totp",
            json!({"challenge": challenge, "code": recovery[0]}),
            Opts::default(),
        )
        .await;
    assert_eq!(used.status, StatusCode::OK, "body={}", used.body);
    assert!(used.cookie.is_some());
    let challenge = f.stage_login(None).await;
    let reused = f
        .send(
            "POST",
            "/api/login/totp",
            json!({"challenge": challenge, "code": recovery[0]}),
            Opts::default(),
        )
        .await;
    reused.denied("recovery codes are single use");
    for code in recovery.iter().skip(1) {
        let challenge = f.stage_login(None).await;
        let reply = f
            .send(
                "POST",
                "/api/login/totp",
                json!({"challenge": challenge, "code": code}),
                Opts::default(),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "body={}", reply.body);
    }
}

#[tokio::test]
async fn five_wrong_factor_attempts_cannot_exhaust_then_succeed() {
    let f = Fixture::configured();
    let authenticator = SoftAuthenticator::new();
    let cookie = f.password_login(&f.password).await.cookie.expect("session");
    f.enroll(&cookie, &authenticator).await;
    let (secret, _) = f.seed_totp();

    let challenge = f.stage_login(None).await;
    for index in 0..5 {
        let wrong = f
            .send(
                "POST",
                "/api/login/totp",
                json!({"challenge": challenge, "code": format!("PUBLIC-wrong-{index}")}),
                Opts::default(),
            )
            .await;
        wrong.denied("wrong second factor");
    }
    let correct = f
        .send(
            "POST",
            "/api/login/totp",
            json!({"challenge": challenge, "code": totp_code(&secret)}),
            Opts::default(),
        )
        .await;
    correct.denied("a challenge exhausted by failed factors must not verify");
}

#[tokio::test]
async fn legacy_inline_totp_login_without_passkeys_is_unchanged() {
    let f = Fixture::configured();
    let (secret, _) = f.seed_totp();

    // No passkey enrolled: TOTP stays inline in /api/login, immediate session.
    let inline = f
        .send(
            "POST",
            "/api/login",
            json!({"password": f.password, "code": totp_code(&secret)}),
            Opts::default(),
        )
        .await;
    assert_eq!(inline.status, StatusCode::OK, "body={}", inline.body);
    assert_eq!(inline.body["success"], true);
    assert!(
        inline.cookie.is_some(),
        "inline TOTP login issues the session directly"
    );
    assert!(inline.body.get("two_factor_required").is_none());

    let wrong = f
        .send(
            "POST",
            "/api/login",
            json!({"password": f.password, "code": "PUBLIC-wrong"}),
            Opts::default(),
        )
        .await;
    wrong.denied("wrong inline TOTP code");
}

// ---- Go-format credential import ----

// Deterministic import material, all public test data. The credential id is
// ASCII so standard and URL-safe base64 agree on its encoding.
const IMPORT_CRED_ID: &[u8] = b"PUBLIC-go-imported-credential-id";

fn imported_authenticator() -> SoftAuthenticator {
    let mut seed = Sha256::digest(b"PUBLIC-passkey-go-import-scalar-v1").to_vec();
    loop {
        if let Ok(key) = SigningKey::from_slice(&seed) {
            return SoftAuthenticator::from_signing_key(key, IMPORT_CRED_ID.to_vec());
        }
        let mut hasher = Sha256::new();
        hasher.update(&seed);
        seed = hasher.finalize().to_vec();
    }
}

/// Seeds passkey_credentials exactly the way the Go binary persists it
/// (webauthn.Credential JSON inside storedPasskey), including fields a Rust
/// model does not know about.
fn seed_go_credential_store(f: &Fixture) {
    let authenticator = imported_authenticator();
    let go_json = json!([{
        "credential": {
            "id": STANDARD.encode(IMPORT_CRED_ID),
            "publicKey": STANDARD.encode(authenticator.cose_key()),
            "attestationType": "none",
            "transport": ["usb", "internal"],
            "flags": {
                "userPresent": true,
                "userVerified": true,
                "backupEligible": false,
                "backupState": false,
            },
            "authenticator": {
                "AAGUID": STANDARD.encode([0u8; 16]),
                "signCount": 5,
            },
            "deviceName": "PUBLIC-go-extra-metadata",
        },
        "label": "PUBLIC-go-import",
        "created_at": "2026-11-01T12:00:00Z",
    }]);
    f.state
        .persist_settings(&[("passkey_credentials", &go_json.to_string())])
        .unwrap();
}

#[tokio::test]
async fn go_imported_credential_logins_preserve_unknown_metadata_and_encrypted_storage() {
    let f = Fixture::configured();
    seed_go_credential_store(&f);
    let authenticator = imported_authenticator();

    let challenge = f.stage_login(None).await;
    let begin = f.begin_login(&challenge).await;
    let options = public_key_options(&begin);
    let login_challenge = options_challenge(options);
    let allowed: Vec<&str> = options["allowCredentials"]
        .as_array()
        .expect("allowCredentials")
        .iter()
        .filter_map(|entry| entry["id"].as_str())
        .collect();
    let encoded_import_id = b64url(IMPORT_CRED_ID);
    assert!(
        allowed.contains(&encoded_import_id.as_str()),
        "imported Go credential is offered, allow={allowed:?}"
    );

    // The imported counter (5) is enforced: it must advance.
    let stale = f
        .finish_login(
            begin["ticket"].as_str().unwrap(),
            authenticator.valid_assertion(&login_challenge, 5),
        )
        .await;
    stale.denied("imported credential counter must advance");

    let challenge = f.stage_login(None).await;
    let begin = f.begin_login(&challenge).await;
    let login_challenge = options_challenge(public_key_options(&begin));
    let fresh = f
        .finish_login(
            begin["ticket"].as_str().unwrap(),
            authenticator.valid_assertion(&login_challenge, 6),
        )
        .await;
    assert_eq!(fresh.status, StatusCode::OK, "body={}", fresh.body);
    assert!(fresh.cookie.is_some(), "imported credential logs in");

    // The counter rewrite must not be a lossy overwrite of the Go record.
    let stored = f.stored_credentials();
    let credential = &stored[0]["credential"];
    assert_eq!(
        credential["authenticator"]["signCount"], 6,
        "counter persisted after the verified assertion, store={stored}"
    );
    assert_eq!(
        credential["transport"],
        json!(["usb", "internal"]),
        "unknown Go metadata survives the update, store={stored}"
    );
    assert_eq!(
        credential["deviceName"], "PUBLIC-go-extra-metadata",
        "extra Go fields survive the update, store={stored}"
    );
    assert_eq!(stored[0]["label"], "PUBLIC-go-import");
    assert_eq!(stored[0]["created_at"], "2026-11-01T12:00:00Z");
}

#[tokio::test]
async fn malformed_stored_credentials_fail_closed_without_disabling_passkeys() {
    let f = Fixture::configured();
    f.state
        .persist_settings(&[("passkey_credentials", "PUBLIC-not-json")])
        .unwrap();

    // Fail closed: an unreadable store must never degrade into password-only
    // login with a session.
    let reply = f.password_login(&f.password).await;
    assert!(
        reply.cookie.is_none(),
        "malformed credential store must not fall back to a password-only session"
    );
    assert!(
        reply.status != StatusCode::OK || reply.body["two_factor_required"] == true,
        "malformed store must still demand a second factor, got {} {}",
        reply.status,
        reply.body
    );

    if let Some(challenge) = reply.body["challenge"].as_str() {
        let begin = f
            .send(
                "POST",
                "/api/login/passkey/begin",
                json!({"challenge": challenge}),
                Opts::default(),
            )
            .await;
        begin.denied("no ceremony can be built from a malformed store");
    }
}

// ---- Login challenge snapshots ----

#[tokio::test]
async fn login_challenge_rejects_password_rotation_and_credential_deletion() {
    // Rotation after the password stage must invalidate the pending flow.
    let f = Fixture::configured();
    let authenticator = SoftAuthenticator::new();
    let cookie = f.password_login(&f.password).await.cookie.expect("session");
    f.enroll(&cookie, &authenticator).await;
    let challenge = f.stage_login(None).await;
    f.state
        .persist_settings(&[(
            "admin_password_hash",
            &bcrypt::hash("PUBLIC-rotated-password", 4).unwrap(),
        )])
        .unwrap();

    let begin = f
        .send(
            "POST",
            "/api/login/passkey/begin",
            json!({"challenge": challenge}),
            Opts::default(),
        )
        .await;
    if begin.status == StatusCode::OK {
        let login_challenge = options_challenge(public_key_options(&begin.body));
        let finish = f
            .finish_login(
                begin.body["ticket"].as_str().unwrap(),
                authenticator.valid_assertion(&login_challenge, 1),
            )
            .await;
        finish.denied("challenge issued under the old password hash");
    } else {
        begin.denied("challenge issued under the old password hash");
    }

    // Deleting the credential mid-ceremony invalidates the pending flow.
    let f = Fixture::configured();
    let authenticator = SoftAuthenticator::new();
    let cookie = f.password_login(&f.password).await.cookie.expect("session");
    f.enroll(&cookie, &authenticator).await;
    let challenge = f.stage_login(None).await;
    let begin = f.begin_login(&challenge).await;
    let login_challenge = options_challenge(public_key_options(&begin));
    let item_id = f.status(&cookie).await["items"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let deleted = f
        .send(
            "POST",
            "/api/auth/passkey/delete",
            json!({"id": item_id, "current_password": f.password}),
            Opts::cookie(&cookie),
        )
        .await;
    assert_eq!(deleted.status, StatusCode::OK, "body={}", deleted.body);
    let finish = f
        .finish_login(
            begin["ticket"].as_str().unwrap(),
            authenticator.valid_assertion(&login_challenge, 1),
        )
        .await;
    finish.denied("assertion for a credential deleted mid-ceremony");
}

// ---- Storage failure atomicity ----

#[tokio::test]
async fn storage_failure_on_finish_denies_session_and_registration_success() {
    // Counter persistence is atomic with session issuance: a failing store
    // must not hand out a cookie.
    let f = Fixture::configured();
    let authenticator = SoftAuthenticator::new();
    let cookie = f.password_login(&f.password).await.cookie.expect("session");
    f.enroll(&cookie, &authenticator).await;
    f.state
        .db
        .lock()
        .unwrap()
        .pragma_update(None, "query_only", true)
        .unwrap();

    let challenge = f.stage_login(None).await;
    let begin = f.begin_login(&challenge).await;
    let login_challenge = options_challenge(public_key_options(&begin));
    let failed_store = f
        .finish_login(
            begin["ticket"].as_str().unwrap(),
            authenticator.valid_assertion(&login_challenge, 1),
        )
        .await;
    assert_ne!(
        failed_store.status,
        StatusCode::OK,
        "body={}",
        failed_store.body
    );
    assert!(
        failed_store.cookie.is_none(),
        "a failed counter persist must not issue a session"
    );

    // Registration reports no false success when the store rejects the write.
    let f = Fixture::configured();
    let authenticator = SoftAuthenticator::new();
    let cookie = f.password_login(&f.password).await.cookie.expect("session");
    let begin = f.begin_register(&cookie, &f.password).await;
    let challenge = options_challenge(public_key_options(&begin));
    f.state
        .db
        .lock()
        .unwrap()
        .pragma_update(None, "query_only", true)
        .unwrap();
    let failed_register = f
        .finish_register(
            begin["ticket"].as_str().unwrap(),
            authenticator.registration(&challenge, RP_ID, FLAG_UP | FLAG_UV),
            &cookie,
        )
        .await;
    assert_ne!(
        failed_register.status,
        StatusCode::OK,
        "body={}",
        failed_register.body
    );
    assert!(failed_register.body["success"].is_null());
    assert!(
        failed_register.body["recovery_codes"].is_null(),
        "no recovery codes on a failed store, body={}",
        failed_register.body
    );
    assert!(
        f.state
            .setting("passkey_credentials")
            .is_none_or(|value| value.is_empty()),
        "nothing may be enrolled when the store rejects the write"
    );
}
