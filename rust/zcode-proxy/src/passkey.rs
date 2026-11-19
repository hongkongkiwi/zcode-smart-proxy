//! Password-gated WebAuthn second factors with single-use server-side ceremonies.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use webauthn_rs_core::{internals::AuthenticatorData, proto::*, WebauthnCore};

use crate::{admin, auth::now_secs, state::AppState};

#[derive(Clone, PartialEq, Eq)]
pub struct RpConfig {
    pub rp_id: String,
    pub origins: Vec<String>,
}

impl RpConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        let id = &self.rp_id;
        if id.is_empty()
            || id.len() > 253
            || id != &id.to_ascii_lowercase()
            || id.parse::<std::net::IpAddr>().is_ok()
            || id.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            || (id != "localhost" && !id.contains('.'))
        {
            return Err("ZCODE_WEB_RPID must be a domain name");
        }
        if self.origins.is_empty() {
            return Err("ZCODE_WEB_ORIGIN must contain an exact origin");
        }
        for origin in &self.origins {
            let url = url::Url::parse(origin).map_err(|_| "invalid ZCODE_WEB_ORIGIN")?;
            let host = url.host_str().ok_or("invalid ZCODE_WEB_ORIGIN")?;
            if !matches!(url.scheme(), "https" | "http")
                || (url.scheme() == "http" && host != "localhost")
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/"
                || origin != &url.origin().ascii_serialization()
                || !(host == id || host.ends_with(&format!(".{id}")))
            {
                return Err(
                    "ZCODE_WEB_ORIGIN must be an exact secure origin within ZCODE_WEB_RPID",
                );
            }
        }
        Ok(())
    }

    fn core(&self) -> WebauthnCore {
        // Exact origins and ports only. Core accepts the existing Go 32-byte user handle.
        WebauthnCore::new_unsafe_experts_only(
            "ZCode Proxy",
            &self.rp_id,
            self.origins
                .iter()
                .map(|s| url::Url::parse(s).unwrap())
                .collect(),
            Duration::from_secs(300),
            Some(false),
            Some(false),
        )
    }
}

impl AppState {
    pub fn set_webauthn_rp(&self, config: RpConfig) -> Result<(), &'static str> {
        config.validate()?;
        *self.webauthn_rp.lock().unwrap() = Some(config);
        Ok(())
    }
}

type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;

fn peer_key(peer: Peer) -> String {
    peer.map(|Extension(ConnectInfo(addr))| addr.ip().to_string())
        .unwrap_or_else(|| "local".into())
}

pub(crate) fn reply(status: StatusCode, value: Value) -> Response {
    let mut response = (status, Json(value)).into_response();
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
}

pub(crate) fn error(status: StatusCode, message: &str) -> Response {
    reply(
        status,
        json!({"error": {"message": message, "type": "api_error"}}),
    )
}

fn storage_error() -> Response {
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "authentication storage operation failed",
    )
}

fn unconfigured() -> Response {
    error(
        StatusCode::BAD_REQUEST,
        "configure ZCODE_WEB_RPID and ZCODE_WEB_ORIGIN to use passkeys",
    )
}

pub(crate) fn origin_allowed(state: &AppState, headers: &HeaderMap) -> bool {
    let rp = state.webauthn_rp.lock().unwrap();
    origin_matches(rp.as_ref(), headers)
}

fn origin_matches(rp: Option<&RpConfig>, headers: &HeaderMap) -> bool {
    let mut values = headers.get_all("origin").iter();
    let Some(origin) = values.next() else {
        return true;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    match rp {
        Some(config) => config.origins.iter().any(|s| s == origin),
        None => admin::origin_allowed(headers),
    }
}

fn random_token<const N: usize>() -> String {
    let mut bytes = [0; N];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Clone, PartialEq, Eq)]
struct Snapshot {
    password: String,
    username: String,
    credentials: String,
    handle: String,
}

impl Snapshot {
    fn read(settings: &HashMap<String, String>) -> Self {
        Self {
            password: settings
                .get("admin_password_hash")
                .cloned()
                .unwrap_or_default(),
            username: settings
                .get("admin_username")
                .cloned()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "admin".into()),
            credentials: settings
                .get("passkey_credentials")
                .cloned()
                .unwrap_or_default(),
            handle: settings
                .get("passkey_user_handle")
                .cloned()
                .unwrap_or_default(),
        }
    }
}

struct LoginChallenge {
    issued: Instant,
    peer: String,
    snapshot: Snapshot,
    rp: Option<RpConfig>,
    failures: u8,
}

enum Ceremony {
    Register {
        state: RegistrationState,
        session: String,
        label: String,
        handle: Vec<u8>,
        snapshot: Snapshot,
    },
    Login {
        state: AuthenticationState,
        challenge: String,
    },
}

struct Ticket {
    issued: Instant,
    peer: String,
    rp: RpConfig,
    ceremony: Ceremony,
}

#[derive(Default)]
pub(crate) struct FlowStore {
    tickets: HashMap<String, Ticket>,
    challenges: HashMap<String, LoginChallenge>,
}

impl FlowStore {
    fn prune(&mut self, ttl: Duration) {
        self.tickets.retain(|_, t| t.issued.elapsed() < ttl);
        self.challenges
            .retain(|_, c| c.issued.elapsed() < ttl && c.failures < 5);
    }

    fn failed(&mut self, challenge: &str) {
        if let Some(c) = self.challenges.get_mut(challenge) {
            c.failures += 1;
            if c.failures >= 5 {
                self.challenges.remove(challenge);
            }
        }
    }

    fn challenge_valid(
        &self,
        token: &str,
        peer: &str,
        snapshot: &Snapshot,
        rp: Option<&RpConfig>,
    ) -> bool {
        self.challenges.get(token).is_some_and(|c| {
            c.peer == peer && &c.snapshot == snapshot && c.rp.as_ref() == rp && c.failures < 5
        })
    }
}

// Keep the original JSON records so Go fields unknown to Rust survive counter updates.
struct StoredCredential {
    value: Value,
    core: Credential,
}

fn credentials(raw: &str) -> Result<Vec<StoredCredential>, ()> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let values: Vec<Value> = serde_json::from_str(raw).map_err(|_| ())?;
    let mut result: Vec<StoredCredential> = Vec::new();
    for value in values {
        let c = &value["credential"];
        let id = STANDARD
            .decode(c["id"].as_str().ok_or(())?)
            .map_err(|_| ())?;
        if id.is_empty() || result.iter().any(|previous| previous.core.cred_id == id) {
            return Err(());
        }
        let key = STANDARD
            .decode(c["publicKey"].as_str().ok_or(())?)
            .map_err(|_| ())?;
        let key: serde_cbor_2::Value = serde_cbor_2::from_slice(&key).map_err(|_| ())?;
        let key = COSEKey::try_from(&key).map_err(|_| ())?;
        let authenticator = c["authenticator"].as_object().ok_or(())?;
        let counter = match authenticator.get("signCount") {
            None => 0, // Go omits a zero signCount when serializing credentials.
            Some(value) => value
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or(())?,
        };
        let flag = |name: &str| c["flags"][name].as_bool().ok_or(());
        let core = Credential {
            cred_id: id,
            cred: key,
            counter,
            transports: None,
            user_verified: flag("userVerified")?,
            backup_eligible: flag("backupEligible")?,
            backup_state: flag("backupState")?,
            registration_policy: UserVerificationPolicy::Preferred,
            extensions: RegisteredExtensions::none(),
            attestation: ParsedAttestation {
                data: ParsedAttestationData::None,
                metadata: AttestationMetadata::None,
            },
            attestation_format: AttestationFormat::None,
        };
        result.push(StoredCredential { value, core });
    }
    Ok(result)
}

pub(crate) fn enrolled(raw: &str) -> Result<bool, ()> {
    credentials(raw).map(|c| !c.is_empty())
}

fn serialize_credentials(items: &[StoredCredential]) -> String {
    Value::Array(items.iter().map(|c| c.value.clone()).collect()).to_string()
}

pub(crate) fn stage_login(state: &AppState, peer: &str, verified_hash: &str) -> Response {
    let rp = state.webauthn_rp.lock().unwrap();
    let mut flows = state.passkey_flows.lock().unwrap();
    flows.prune(state.passkey_ticket_ttl);
    let settings = state.settings.lock().unwrap();
    let snapshot = Snapshot::read(&settings);
    if snapshot.password != verified_hash {
        return error(StatusCode::UNAUTHORIZED, "invalid credentials");
    }
    if flows.challenges.len() >= 256 {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many pending login challenges",
        );
    }
    let token = random_token::<32>();
    let mut methods = vec!["passkey"];
    if settings.get("totp_enabled").map(String::as_str) == Some("1") {
        methods.push("totp");
    }
    methods.push("recovery");
    flows.challenges.insert(
        token.clone(),
        LoginChallenge {
            issued: Instant::now(),
            peer: peer.into(),
            snapshot,
            rp: rp.clone(),
            failures: 0,
        },
    );
    reply(
        StatusCode::OK,
        json!({"two_factor_required": true, "challenge": token, "methods": methods}),
    )
}

pub async fn handle_status(State(state): State<Arc<AppState>>) -> Response {
    let raw = state.setting("passkey_credentials").unwrap_or_default();
    let Ok(items) = credentials(&raw) else {
        return storage_error();
    };
    let items: Vec<_> = items.iter().map(|c| json!({"id": URL_SAFE_NO_PAD.encode(&c.core.cred_id), "label": c.value["label"], "created_at": c.value["created_at"]})).collect();
    reply(
        StatusCode::OK,
        json!({"count": items.len(), "items": items}),
    )
}

pub async fn handle_register_begin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: Peer,
    body: String,
) -> Response {
    let rp = state.webauthn_rp.lock().unwrap();
    let Some(config) = rp.as_ref() else {
        return unconfigured();
    };
    if !origin_matches(Some(config), &headers) {
        return error(StatusCode::FORBIDDEN, "cross-origin request rejected");
    }
    let peer = peer_key(peer);
    let rate = format!("{peer}|passkey-register");
    let mut guard = state.step_up_guard.lock().unwrap();
    if guard.check(&rate, now_secs()) > 0 {
        return error(StatusCode::TOO_MANY_REQUESTS, "too many attempts");
    }
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let password = v["current_password"].as_str().unwrap_or("");
    let mut flows = state.passkey_flows.lock().unwrap();
    flows.prune(state.passkey_ticket_ttl);
    let settings = state.settings.lock().unwrap();
    let snapshot = Snapshot::read(&settings);
    if password.is_empty() || !admin::password_ok(Some(snapshot.password.clone()), password) {
        guard.record_failure(&rate, now_secs());
        return error(StatusCode::FORBIDDEN, "current password incorrect");
    }
    if credentials(&snapshot.credentials).is_err() {
        return storage_error();
    }
    let handle = if snapshot.handle.is_empty() {
        let mut bytes = vec![0; 32];
        OsRng.fill_bytes(&mut bytes);
        bytes
    } else {
        match STANDARD.decode(&snapshot.handle) {
            Ok(bytes) if bytes.len() == 32 => bytes,
            _ => return storage_error(),
        }
    };
    if flows.tickets.len() >= 256 {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many pending passkey ceremonies",
        );
    }
    let core = config.core();
    let Ok(builder) =
        core.new_challenge_register_builder(&handle, &snapshot.username, &snapshot.username)
    else {
        return storage_error();
    };
    let Ok((options, registration)) = core.generate_challenge_register(
        builder.user_verification_policy(UserVerificationPolicy::Preferred),
    ) else {
        return storage_error();
    };
    let Some(session) = admin::session_token(&headers) else {
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    let label: String = v["label"]
        .as_str()
        .unwrap_or("")
        .trim()
        .chars()
        .take(100)
        .collect();
    let token = random_token::<24>();
    flows.tickets.insert(
        token.clone(),
        Ticket {
            issued: Instant::now(),
            peer,
            rp: config.clone(),
            ceremony: Ceremony::Register {
                state: registration,
                session,
                label,
                handle,
                snapshot,
            },
        },
    );
    guard.clear(&rate);
    reply(StatusCode::OK, json!({"ticket": token, "options": options}))
}

pub async fn handle_register_finish(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    peer: Peer,
    body: String,
) -> Response {
    let rp = state.webauthn_rp.lock().unwrap();
    let mut flows = state.passkey_flows.lock().unwrap();
    flows.prune(state.passkey_ticket_ttl);
    let Some(ticket) = flows
        .tickets
        .remove(query.get("ticket").map(String::as_str).unwrap_or(""))
    else {
        return error(
            StatusCode::BAD_REQUEST,
            "passkey ceremony expired, start again",
        );
    };
    let Ceremony::Register {
        state: registration,
        session,
        label,
        handle,
        snapshot,
    } = ticket.ceremony
    else {
        return error(StatusCode::BAD_REQUEST, "invalid passkey ceremony");
    };
    if rp.as_ref() != Some(&ticket.rp)
        || ticket.peer != peer_key(peer)
        || admin::session_token(&headers).as_ref() != Some(&session)
        || !origin_matches(rp.as_ref(), &headers)
    {
        return error(StatusCode::BAD_REQUEST, "invalid passkey ceremony");
    }
    let mut db = state.db.lock().unwrap();
    let mut settings = state.settings.lock().unwrap();
    if Snapshot::read(&settings) != snapshot {
        return error(
            StatusCode::BAD_REQUEST,
            "passkey ceremony expired, start again",
        );
    }
    let sessions = state.sessions.lock().unwrap();
    if sessions
        .get(&session)
        .is_none_or(|expiry| *expiry <= now_secs())
    {
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let Ok(reg) = serde_json::from_str::<RegisterPublicKeyCredential>(&body) else {
        return error(StatusCode::BAD_REQUEST, "invalid passkey registration");
    };
    if reg.type_ != "public-key" || reg.id != URL_SAFE_NO_PAD.encode(&reg.raw_id) {
        return error(StatusCode::BAD_REQUEST, "invalid passkey registration");
    }
    let Ok(verified) = ticket
        .rp
        .core()
        .register_credential(&reg, &registration, None)
    else {
        return error(StatusCode::BAD_REQUEST, "invalid passkey registration");
    };
    if verified.cred_id != reg.raw_id {
        return error(StatusCode::BAD_REQUEST, "invalid passkey registration");
    }
    let Ok(mut items) = credentials(&snapshot.credentials) else {
        return storage_error();
    };
    if items.iter().any(|c| c.core.cred_id == verified.cred_id) {
        return error(StatusCode::CONFLICT, "passkey already registered");
    }
    let Ok(value) = native_record(&reg, &verified, &label) else {
        return error(StatusCode::BAD_REQUEST, "invalid passkey registration");
    };
    items.push(StoredCredential {
        value,
        core: verified,
    });
    let raw = serialize_credentials(&items);
    let handle = STANDARD.encode(handle);
    let existing =
        zcode_core::recovery_codes_from_json(settings.get("recovery_codes").map(String::as_str));
    let (plain, recovery) = if existing.is_empty() {
        let (plain, hashes) = zcode_core::generate_recovery_codes(10);
        (Some(plain), zcode_core::recovery_codes_to_json(&hashes))
    } else {
        (None, zcode_core::recovery_codes_to_json(&existing))
    };
    if state
        .persist_settings_locked(
            &mut db,
            &mut settings,
            &[
                ("passkey_credentials", &raw),
                ("passkey_user_handle", &handle),
                ("recovery_codes", &recovery),
            ],
        )
        .is_err()
    {
        return storage_error();
    }
    reply(
        StatusCode::OK,
        json!({"success": true, "count": items.len(), "recovery_codes": plain}),
    )
}

fn native_record(
    reg: &RegisterPublicKeyCredential,
    credential: &Credential,
    label: &str,
) -> Result<Value, ()> {
    // Parse the already-verified authenticator data through core to retain raw COSE CBOR for Go.
    let object: serde_cbor_2::Value =
        serde_cbor_2::from_slice(&reg.response.attestation_object).map_err(|_| ())?;
    let serde_cbor_2::Value::Map(map) = object else {
        return Err(());
    };
    let Some(serde_cbor_2::Value::Text(format)) = map.get(&serde_cbor_2::Value::Text("fmt".into()))
    else {
        return Err(());
    };
    let Some(serde_cbor_2::Value::Bytes(bytes)) =
        map.get(&serde_cbor_2::Value::Text("authData".into()))
    else {
        return Err(());
    };
    let data = AuthenticatorData::<Registration>::try_from(bytes.as_slice()).map_err(|_| ())?;
    let acd = data.acd.ok_or(())?;
    let key = serde_cbor_2::to_vec(&acd.credential_pk).map_err(|_| ())?;
    Ok(json!({"credential": {
        "id": STANDARD.encode(&credential.cred_id), "publicKey": STANDARD.encode(key),
        "attestationType": format, "transport": reg.response.transports,
        "flags": {"userPresent": true, "userVerified": credential.user_verified, "backupEligible": credential.backup_eligible, "backupState": credential.backup_state},
        "authenticator": {"AAGUID": STANDARD.encode(acd.aaguid), "signCount": credential.counter}
    }, "label": label, "created_at": chrono::Utc::now().to_rfc3339()}))
}

pub async fn handle_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: Peer,
    body: String,
) -> Response {
    if !origin_allowed(&state, &headers) {
        return error(StatusCode::FORBIDDEN, "cross-origin request rejected");
    }
    let rate = format!("{}|passkey-delete", peer_key(peer));
    let mut guard = state.step_up_guard.lock().unwrap();
    if guard.check(&rate, now_secs()) > 0 {
        return error(StatusCode::TOO_MANY_REQUESTS, "too many attempts");
    }
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let mut db = state.db.lock().unwrap();
    let mut settings = state.settings.lock().unwrap();
    let password = v["current_password"].as_str().unwrap_or("");
    if password.is_empty()
        || !admin::password_ok(settings.get("admin_password_hash").cloned(), password)
    {
        guard.record_failure(&rate, now_secs());
        return error(StatusCode::FORBIDDEN, "current password incorrect");
    }
    let Ok(mut items) = credentials(
        settings
            .get("passkey_credentials")
            .map(String::as_str)
            .unwrap_or(""),
    ) else {
        return storage_error();
    };
    let Ok(id) = URL_SAFE_NO_PAD.decode(v["id"].as_str().unwrap_or("")) else {
        return error(StatusCode::BAD_REQUEST, "invalid passkey id");
    };
    let count = items.len();
    items.retain(|c| c.core.cred_id != id);
    if count == items.len() {
        return error(StatusCode::NOT_FOUND, "passkey not found");
    }
    let raw = serialize_credentials(&items);
    if state
        .persist_settings_locked(&mut db, &mut settings, &[("passkey_credentials", &raw)])
        .is_err()
    {
        return storage_error();
    }
    guard.clear(&rate);
    reply(
        StatusCode::OK,
        json!({"success": true, "count": items.len()}),
    )
}

pub async fn handle_login_begin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: Peer,
    body: String,
) -> Response {
    let rp = state.webauthn_rp.lock().unwrap();
    let Some(config) = rp.as_ref() else {
        return unconfigured();
    };
    if !origin_matches(Some(config), &headers) {
        return error(StatusCode::FORBIDDEN, "cross-origin request rejected");
    }
    let peer = peer_key(peer);
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let challenge = v["challenge"].as_str().unwrap_or("");
    let mut flows = state.passkey_flows.lock().unwrap();
    flows.prune(state.passkey_ticket_ttl);
    let settings = state.settings.lock().unwrap();
    let snapshot = Snapshot::read(&settings);
    if !flows.challenge_valid(challenge, &peer, &snapshot, Some(config)) {
        return error(
            StatusCode::UNAUTHORIZED,
            "login challenge expired, start again",
        );
    }
    let Ok(items) = credentials(&snapshot.credentials) else {
        return storage_error();
    };
    if items.is_empty() {
        return error(StatusCode::BAD_REQUEST, "no passkey registered");
    }
    if flows.tickets.len() >= 256 {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many pending passkey ceremonies",
        );
    }
    let core = config.core();
    let Ok(builder) = core.new_challenge_authenticate_builder(
        items.into_iter().map(|c| c.core).collect(),
        Some(UserVerificationPolicy::Preferred),
    ) else {
        return storage_error();
    };
    let Ok((options, authentication)) = core.generate_challenge_authenticate(builder) else {
        return storage_error();
    };
    let token = random_token::<24>();
    flows.tickets.insert(
        token.clone(),
        Ticket {
            issued: Instant::now(),
            peer,
            rp: config.clone(),
            ceremony: Ceremony::Login {
                state: authentication,
                challenge: challenge.into(),
            },
        },
    );
    reply(StatusCode::OK, json!({"ticket": token, "options": options}))
}

pub async fn handle_login_finish(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    peer: Peer,
    body: String,
) -> Response {
    let rp = state.webauthn_rp.lock().unwrap();
    let mut flows = state.passkey_flows.lock().unwrap();
    flows.prune(state.passkey_ticket_ttl);
    let Some(ticket) = flows
        .tickets
        .remove(query.get("ticket").map(String::as_str).unwrap_or(""))
    else {
        return error(
            StatusCode::BAD_REQUEST,
            "passkey ceremony expired, start again",
        );
    };
    let Ceremony::Login {
        state: authentication,
        challenge,
    } = ticket.ceremony
    else {
        return error(StatusCode::BAD_REQUEST, "invalid passkey ceremony");
    };
    let peer = peer_key(peer);
    let mut login_guard = state.login_guard.lock().unwrap();
    let mut db = state.db.lock().unwrap();
    let mut settings = state.settings.lock().unwrap();
    let snapshot = Snapshot::read(&settings);
    if rp.as_ref() != Some(&ticket.rp)
        || ticket.peer != peer
        || !origin_matches(rp.as_ref(), &headers)
        || !flows.challenge_valid(&challenge, &peer, &snapshot, rp.as_ref())
        || login_guard.check(&peer, now_secs()) > 0
    {
        flows.failed(&challenge);
        return error(StatusCode::UNAUTHORIZED, "passkey verification failed");
    }
    let verified = (|| {
        let rsp: PublicKeyCredential = serde_json::from_str(&body).map_err(|_| ())?;
        if rsp.type_ != "public-key" || rsp.id != URL_SAFE_NO_PAD.encode(&rsp.raw_id) {
            return Err(());
        }
        if let Some(handle) = rsp.get_user_unique_id() {
            if STANDARD.decode(&snapshot.handle).map_err(|_| ())? != handle {
                return Err(());
            }
        }
        let mut items = credentials(&snapshot.credentials)?;
        let item = items
            .iter_mut()
            .find(|c| c.core.cred_id == rsp.raw_id)
            .ok_or(())?;
        // Verification uses the current counter under the same writer locks as persistence.
        let result = ticket
            .rp
            .core()
            .authenticate_single_credential(&rsp, &authentication, &item.core)
            .map_err(|_| ())?;
        item.value["credential"]["authenticator"]["signCount"] = json!(result.counter());
        item.value["credential"]["flags"]["userVerified"] =
            json!(item.core.user_verified || result.user_verified());
        item.value["credential"]["flags"]["backupState"] = json!(result.backup_state());
        item.value["credential"]["flags"]["backupEligible"] = json!(result.backup_eligible());
        Ok(serialize_credentials(&items))
    })();
    let raw = match verified {
        Ok(raw) => raw,
        Err(()) => {
            flows.failed(&challenge);
            login_guard.record_failure(&peer, now_secs());
            return error(StatusCode::UNAUTHORIZED, "passkey verification failed");
        }
    };
    if state
        .persist_settings_locked(&mut db, &mut settings, &[("passkey_credentials", &raw)])
        .is_err()
    {
        flows.challenges.remove(&challenge);
        return storage_error();
    }
    flows.challenges.remove(&challenge);
    login_guard.clear(&peer);
    admin::login_success(&state, &snapshot.username)
}

pub async fn handle_login_totp(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: Peer,
    body: String,
) -> Response {
    let rp = state.webauthn_rp.lock().unwrap();
    if !origin_matches(rp.as_ref(), &headers) {
        return error(StatusCode::FORBIDDEN, "cross-origin request rejected");
    }
    let peer = peer_key(peer);
    let mut flows = state.passkey_flows.lock().unwrap();
    flows.prune(state.passkey_ticket_ttl);
    let mut guard = state.login_guard.lock().unwrap();
    let mut db = state.db.lock().unwrap();
    let mut settings = state.settings.lock().unwrap();
    let snapshot = Snapshot::read(&settings);
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let challenge = v["challenge"].as_str().unwrap_or("");
    let code = v["code"].as_str().unwrap_or("");
    if !flows.challenge_valid(challenge, &peer, &snapshot, rp.as_ref())
        || guard.check(&peer, now_secs()) > 0
    {
        return error(
            StatusCode::UNAUTHORIZED,
            "login challenge expired, start again",
        );
    }
    let totp = settings.get("totp_enabled").map(String::as_str) == Some("1")
        && settings
            .get("totp_secret")
            .is_some_and(|s| admin::totp_code_ok(s, code));
    let hashes =
        zcode_core::recovery_codes_from_json(settings.get("recovery_codes").map(String::as_str));
    let recovery = if totp {
        None
    } else {
        zcode_core::consume_recovery_code(&hashes, code)
    };
    if !totp && recovery.is_none() {
        flows.failed(challenge);
        guard.record_failure(&peer, now_secs());
        return error(
            StatusCode::UNAUTHORIZED,
            "second factor verification failed",
        );
    }
    if let Some(rest) = recovery {
        let raw = zcode_core::recovery_codes_to_json(&rest);
        if state
            .persist_settings_locked(&mut db, &mut settings, &[("recovery_codes", &raw)])
            .is_err()
        {
            flows.challenges.remove(challenge);
            return storage_error();
        }
    }
    flows.challenges.remove(challenge);
    guard.clear(&peer);
    admin::login_success(&state, &snapshot.username)
}
