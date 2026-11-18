//! Multi-instance local import regressions, pinned to Go account_manager.go
//! ImportFromLocalClient/ImportMultiInstanceClients (lines 59-127) plus
//! DefaultCredentialSecret (credential_crypto.go lines 39-59): the
//! default-path import covers the primary ~/.zcode/v2/credentials.json and
//! every <instance>/v2/credentials.json under ~/.zcode-multi and, on darwin,
//! ~/Library/Application Support/zcode-multi. Each instance decrypts with the
//! fallback secret derived from its own instance directory. An explicit
//! state.local_credentials_path confines the import to that file and its
//! siblings and never runs discovery.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
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

const CHILD_CASE: &str = "ZCODE_PUBLIC_MULTI_INSTANCE_TEST_CASE";
const IMPORT: &str = "/api/accounts/import/local";
const SESSION: &str = "PUBLIC-multi-instance-session";
const USERNAME: &str = "PUBLIC-multi-instance-user";
const EXPLICIT_SECRET: &str = "PUBLIC multi-instance explicit secret";
const CORRUPT_CIPHERTEXT: &str = "enc:v1:PUBLIC-multi-corrupt-ciphertext.not-a-token";
const GROUP: &str = "PUBLIC-multi-group";
const PRIMARY_REMARK: &str = "本地客户端导入";

#[derive(Clone, Copy)]
enum Scenario {
    HappyPath,
    PrimaryMissing,
    CorruptPrimary,
    EmptyHome,
    Cap,
    Oversize,
    #[cfg(unix)]
    SymlinkEscape,
    #[cfg(unix)]
    SymlinkPrimaryDir,
    #[cfg(unix)]
    NonCanonicalHome,
    ExplicitPath,
}

struct Case {
    id: &'static str,
    scenario: Scenario,
}

struct Directory(PathBuf);

impl Directory {
    fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "{prefix}-{}-{:032x}",
            std::process::id(),
            rand::random::<u128>()
        ));
        fs::create_dir(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Reply {
    status: StatusCode,
    json: Value,
    raw: String,
}

struct Written {
    path: PathBuf,
    file: String,
}

struct Expected {
    user_id: &'static str,
    email: String,
    remark: String,
    group: String,
    token: String,
}

struct Fixture {
    state: Arc<AppState>,
    expected: Vec<Expected>,
    written: Vec<Written>,
    secrets: Vec<String>,
    emails: Vec<String>,
    // External escape-target homes must outlive the request and every check,
    // or their Directory guard deletes the target mid-test.
    externals: Vec<Directory>,
}

impl Fixture {
    fn new(explicit: Option<(PathBuf, &'static str)>) -> Self {
        let mut state = AppState::try_from_db_with_vault(
            "PUBLIC-multi-instance-root".into(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
            store::open(":memory:"),
            Vault::from_secret("PUBLIC multi instance persistence vault seed").unwrap(),
        )
        .unwrap();
        if let Some((path, secret)) = explicit {
            state.local_credentials_path = Some(path);
            state.local_credentials_secret = Some(secret.to_owned().into());
        }
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        Self {
            state: Arc::new(state),
            expected: Vec::new(),
            written: Vec::new(),
            secrets: Vec::new(),
            emails: Vec::new(),
            externals: Vec::new(),
        }
    }

    fn write(&mut self, path: &Path, file: String) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, &file).unwrap();
        self.written.push(Written {
            path: path.to_owned(),
            file,
        });
    }

    fn expect(
        &mut self,
        user_id: &'static str,
        email: String,
        remark: String,
        group: &str,
        token: String,
    ) {
        self.expected.push(Expected {
            user_id,
            email,
            remark,
            group: group.to_owned(),
            token,
        });
    }

    fn assert_sources_unchanged(&self) {
        for written in &self.written {
            assert_eq!(
                fs::read_to_string(&written.path).unwrap(),
                written.file,
                "import must never rewrite a source credential file"
            );
        }
    }

    fn assert_sanitized(&self, raw: &str, home: &Path) {
        for secret in &self.secrets {
            assert!(
                !raw.contains(secret.as_str()),
                "response leaked import data"
            );
        }
        assert!(!raw.contains("vault1:"), "response leaked ciphertext");
        assert!(!raw.contains("enc:v1:"), "response leaked envelope data");
        assert!(
            !raw.contains(home.to_str().unwrap()),
            "response leaked the credential home path"
        );
        assert!(
            !raw.contains(".zcode-multi"),
            "response leaked instance paths"
        );
    }

    // account.email is a public field of the established account view. On
    // success an email may appear only in the two exempted slots (top-level
    // account.email and accounts[*].email); remove exactly those and ban the
    // fixture emails from everything that remains, so an email surfacing in
    // errors[*], error messages, or any other value leaks. A rejected import
    // imports nothing and gets no exemption: every fixture email is banned
    // from the whole response body.
    fn assert_emails_confined(&self, reply: &Reply, success: bool) {
        if !success {
            for email in &self.emails {
                assert!(
                    !reply.raw.contains(email.as_str()),
                    "email leaked in a rejected import response"
                );
            }
            return;
        }
        let mut scrubbed = reply.json.clone();
        scrub_allowed_email_slots(&mut scrubbed);
        let rest = scrubbed.to_string();
        for email in &self.emails {
            assert!(
                !rest.contains(email.as_str()),
                "email leaked outside the exempted account email slots"
            );
        }
    }

    fn stored_user_ids(&self) -> Vec<String> {
        let db = self.state.db.lock().unwrap();
        let mut statement = db
            .prepare("SELECT user_id FROM accounts ORDER BY user_id")
            .unwrap();
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }

    fn stored_jwt_at_rest(&self, id: i64) -> String {
        self.state
            .db
            .lock()
            .unwrap()
            .query_row("SELECT zcode_jwt FROM accounts WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .unwrap()
    }

    async fn post(&self, body: &str) -> Reply {
        let response = build_router(self.state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(IMPORT)
                    .header("host", "localhost:8080")
                    .header("content-type", "application/json")
                    .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
                    .body(Body::from(body.to_owned()))
                    .unwrap(),
            )
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

    fn assert_imported_in_order(&self, reply: &Reply) {
        assert_eq!(reply.status, StatusCode::OK, "import must succeed");
        assert_eq!(reply.json["success"], true);
        let accounts = reply.json["accounts"].as_array().unwrap().clone();
        assert_eq!(
            accounts.len(),
            self.expected.len(),
            "accounts must list every import of this call in discovery order"
        );
        for (account, expected) in accounts.iter().zip(&self.expected) {
            assert_eq!(account["user_id"], expected.user_id);
            assert_eq!(account["email"], expected.email);
            assert_eq!(account["remark"], expected.remark);
            assert_eq!(account["group"], expected.group);
            assert_eq!(account["auth_type"], "jwt");
            assert_eq!(account["has_jwt"], true);
            assert!(account["id"].as_i64().unwrap() > 0);
        }
        assert_eq!(
            reply.json["imported"].as_i64(),
            Some(self.expected.len() as i64),
            "imported must count the accounts persisted by this call"
        );
        assert_eq!(
            reply.json["account"], accounts[0],
            "account stays the first imported view for old consumers"
        );
        let creds = self.state.creds.lock().unwrap();
        for (account, expected) in accounts.iter().zip(&self.expected) {
            let id = account["id"].as_i64().unwrap();
            assert_eq!(creds[&id].zcode_jwt, expected.token);
        }
        let mut stored = self.stored_user_ids();
        stored.sort();
        let mut expected_ids: Vec<String> = self
            .expected
            .iter()
            .map(|expected| expected.user_id.to_owned())
            .collect();
        expected_ids.sort();
        assert_eq!(stored, expected_ids, "database rows must match the imports");
    }

    fn assert_rejected(&self, reply: &Reply) {
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(reply.json["success"], false);
        assert!(
            !reply.json["error"]["message"]
                .as_str()
                .unwrap_or("")
                .is_empty(),
            "rejection must carry an explicit sanitized message"
        );
        assert!(
            self.stored_user_ids().is_empty(),
            "fail-closed rejection must not mutate accounts"
        );
    }
}

// Only the two exempted slots are removed: top-level account.email and each
// accounts[*].email. Every other email key (for example errors[*].email)
// stays in the scrubbed body and therefore counts as a leak.
fn scrub_allowed_email_slots(value: &mut Value) {
    if let Some(account) = value.get_mut("account").and_then(Value::as_object_mut) {
        account.remove("email");
    }
    if let Some(accounts) = value.get_mut("accounts").and_then(Value::as_array_mut) {
        for account in accounts {
            if let Some(account) = account.as_object_mut() {
                account.remove("email");
            }
        }
    }
}

#[cfg(unix)]
fn non_canonical_home(scenario: Scenario) -> bool {
    matches!(scenario, Scenario::NonCanonicalHome)
}

#[cfg(not(unix))]
fn non_canonical_home(_: Scenario) -> bool {
    false
}

// A HOME reached through a symlink keeps its lexical string as the trust
// anchor: Go builds instance secrets from the HOME-derived lexical path.
#[cfg(unix)]
fn home_alias(wrapper: &Path, home: &Path) -> PathBuf {
    let alias = wrapper.join("home-link");
    std::os::unix::fs::symlink(home, &alias).unwrap();
    alias
}

#[cfg(not(unix))]
fn home_alias(_: &Path, home: &Path) -> PathBuf {
    home.to_owned()
}

// Self-exec confines HOME/USER changes to one child so discovery cannot touch
// the real machine home and no global process environment is mutated.
fn run(test: &'static str, cases: &[Case]) {
    if let Some(id) = std::env::var_os(CHILD_CASE) {
        let case = cases.iter().find(|case| id == case.id).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(exercise(case.scenario));
        return;
    }
    for case in cases {
        let home = Directory::new("zcode-multi-instance");
        let log_path = home.0.join("child.log");
        let log = fs::File::create(&log_path).unwrap();
        let alias_wrapper =
            non_canonical_home(case.scenario).then(|| Directory::new("zcode-multi-instance-alias"));
        let child_home = match &alias_wrapper {
            Some(wrapper) => home_alias(&wrapper.0, &home.0),
            None => home.0.clone(),
        };
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .env_clear()
            .current_dir(&child_home)
            .env(CHILD_CASE, case.id)
            .env("HOME", &child_home)
            .env("USERPROFILE", &child_home)
            .env("USER", USERNAME)
            .env("LOGNAME", USERNAME)
            .args(["--exact", test, "--nocapture"])
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log);
        let mut child = Process(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                let output = fs::read_to_string(&log_path).unwrap();
                assert!(
                    status.success(),
                    "isolated {test}/{} failed: {output}",
                    case.id
                );
                assert!(
                    output.contains("test result: ok. 1 passed"),
                    "isolated {test}/{} did not execute exactly one test: {output}",
                    case.id
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "isolated {test}/{} exceeded ten seconds",
                case.id
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(windows) {
        "win32"
    } else {
        std::env::consts::OS
    }
}

// Go DefaultCredentialSecret: env override aside, the secret is derived from
// the home that owns the credentials (primary=HOME, instance=instance dir).
fn fallback_secret(dir: &Path) -> String {
    format!(
        "zcode-credential-fallback:{}:{}:{USERNAME}",
        platform(),
        dir.to_str().unwrap()
    )
}

// The Go-verified vault fixture establishes this prefix-only AES-GCM mapping.
fn sealed(secret: &str, plain: &str) -> String {
    let envelope = Vault::from_secret(secret).unwrap().encrypt(plain).unwrap();
    format!("enc:v1:{}", envelope.strip_prefix("vault1:").unwrap())
}

fn jwt(user_id: &str) -> String {
    format!(
        "e30.{}.PUBLIC-not-a-real-signature",
        URL_SAFE_NO_PAD.encode(json!({"user_id": user_id}).to_string())
    )
}

fn user_info(user_id: &str, email: &str) -> String {
    json!({"user_id": user_id, "email": email}).to_string()
}

fn credentials_file(token_value: &str, user_id: &str, email: &str) -> String {
    json!({
        "zcodejwttoken": token_value,
        "oauth:zai:user_info": user_info(user_id, email),
    })
    .to_string()
}

fn zmulti_root(home: &Path) -> PathBuf {
    home.join(".zcode-multi")
}

fn app_support_root(home: &Path) -> PathBuf {
    home.join("Library")
        .join("Application Support")
        .join("zcode-multi")
}

fn write_valid_instance(
    fixture: &mut Fixture,
    root: &Path,
    name: &str,
    user_id: &'static str,
    group: &str,
) {
    let instance_dir = root.join(name);
    let token = jwt(user_id);
    let email = format!("{user_id}@multi.invalid");
    let file = credentials_file(
        &sealed(&fallback_secret(&instance_dir), &token),
        user_id,
        &email,
    );
    fixture.secrets.push(token.clone());
    fixture.secrets.push(fallback_secret(&instance_dir));
    fixture.write(&instance_dir.join("v2/credentials.json"), file);
    fixture.emails.push(email.clone());
    fixture.expect(user_id, email, format!("多实例导入: {name}"), group, token);
}

fn write_primary(fixture: &mut Fixture, home: &Path, user_id: &'static str, group: &str) {
    let token = jwt(user_id);
    let email = format!("{user_id}@multi.invalid");
    let secret = fallback_secret(home);
    let file = credentials_file(&sealed(&secret, &token), user_id, &email);
    fixture.secrets.push(token.clone());
    fixture.secrets.push(secret);
    fixture.write(&home.join(".zcode/v2/credentials.json"), file);
    fixture.emails.push(email.clone());
    fixture.expect(user_id, email, PRIMARY_REMARK.to_owned(), group, token);
}

async fn exercise(scenario: Scenario) {
    // The lexical HOME string is the trust anchor for discovery paths and
    // per-instance fallback secrets, matching Go os.UserHomeDir usage.
    let home = PathBuf::from(std::env::var("HOME").unwrap());
    let explicit = matches!(scenario, Scenario::ExplicitPath)
        .then(|| (home.join("explicit/credentials.json"), EXPLICIT_SECRET));
    let mut fixture = Fixture::new(explicit);
    let group = match scenario {
        Scenario::HappyPath => GROUP,
        _ => "",
    };
    let body = if group.is_empty() {
        "{}".to_owned()
    } else {
        json!({"group": group}).to_string()
    };
    match scenario {
        Scenario::HappyPath => {
            write_primary(&mut fixture, &home, "PUBLIC-mi-primary", group);
            write_valid_instance(
                &mut fixture,
                &zmulti_root(&home),
                "alpha",
                "PUBLIC-mi-alpha",
                group,
            );
            write_valid_instance(
                &mut fixture,
                &zmulti_root(&home),
                "beta",
                "PUBLIC-mi-beta",
                group,
            );
            // Parseable map whose token cannot decrypt under any secret: the
            // Go fail-soft skip class that must surface honestly in errors.
            fixture.write(
                &zmulti_root(&home).join("zeta/v2/credentials.json"),
                credentials_file(CORRUPT_CIPHERTEXT, "PUBLIC-mi-zeta", "zeta@multi.invalid"),
            );
            fixture.secrets.push(CORRUPT_CIPHERTEXT.to_owned());
            fixture.emails.push("zeta@multi.invalid".to_owned());
            write_valid_instance(
                &mut fixture,
                &app_support_root(&home),
                "gamma",
                "PUBLIC-mi-gamma",
                group,
            );
            if !cfg!(target_os = "macos") {
                // Application Support is a darwin-only discovery root.
                fixture.expected.pop();
            }
        }
        Scenario::PrimaryMissing => {
            write_valid_instance(
                &mut fixture,
                &zmulti_root(&home),
                "delta",
                "PUBLIC-mi-delta",
                group,
            );
            write_valid_instance(
                &mut fixture,
                &app_support_root(&home),
                "epsilon",
                "PUBLIC-mi-epsilon",
                group,
            );
            if !cfg!(target_os = "macos") {
                fixture.expected.pop();
            }
        }
        Scenario::CorruptPrimary => {
            fixture.write(
                &home.join(".zcode/v2/credentials.json"),
                credentials_file(
                    CORRUPT_CIPHERTEXT,
                    "PUBLIC-mi-corrupt-primary",
                    "corrupt@multi.invalid",
                ),
            );
            fixture.secrets.push(CORRUPT_CIPHERTEXT.to_owned());
            fixture.emails.push("corrupt@multi.invalid".to_owned());
            write_valid_instance(
                &mut fixture,
                &zmulti_root(&home),
                "alpha",
                "PUBLIC-mi-alpha",
                group,
            );
        }
        Scenario::EmptyHome => {}
        Scenario::Cap => {
            for index in 0..65 {
                let name = format!("inst-{index:02}");
                let user_id: &'static str =
                    Box::leak(format!("PUBLIC-mi-inst-{index:02}").into_boxed_str());
                write_valid_instance(&mut fixture, &zmulti_root(&home), &name, user_id, group);
            }
            // Only the first 64 instances in lexical order may import.
            fixture.expected.truncate(64);
        }
        Scenario::Oversize => {
            write_valid_instance(
                &mut fixture,
                &zmulti_root(&home),
                "alpha",
                "PUBLIC-mi-alpha",
                group,
            );
            let token = jwt("PUBLIC-mi-oversize");
            let email = "oversize@multi.invalid";
            fixture.secrets.push(token.clone());
            fixture.emails.push(email.to_owned());
            // Otherwise-valid credentials whose file exceeds the 1 MiB read
            // bound: importing them would prove the bound is not enforced.
            let file = json!({
                "zcodejwttoken": token,
                "oauth:zai:user_info": user_info("PUBLIC-mi-oversize", email),
                "pad": "A".repeat((1 << 20) + 4096),
            })
            .to_string();
            assert!(file.len() > 1 << 20);
            fixture.write(&zmulti_root(&home).join("zz-big/v2/credentials.json"), file);
        }
        #[cfg(unix)]
        Scenario::SymlinkEscape => {
            write_valid_instance(
                &mut fixture,
                &zmulti_root(&home),
                "alpha",
                "PUBLIC-mi-alpha",
                group,
            );
            fixture
                .externals
                .push(Directory::new("zcode-multi-instance-escape"));
            let outside = fixture.externals.last().unwrap().0.clone();
            let token = jwt("PUBLIC-mi-escaped");
            fixture.secrets.push(token.clone());
            fixture.emails.push("escaped@multi.invalid".to_owned());
            fs::create_dir_all(outside.join("v2")).unwrap();
            fs::write(
                outside.join("v2/credentials.json"),
                credentials_file(&token, "PUBLIC-mi-escaped", "escaped@multi.invalid"),
            )
            .unwrap();
            std::os::unix::fs::symlink(&outside, zmulti_root(&home).join("evil")).unwrap();
        }
        #[cfg(unix)]
        Scenario::SymlinkPrimaryDir => {
            write_valid_instance(
                &mut fixture,
                &zmulti_root(&home),
                "alpha",
                "PUBLIC-mi-alpha",
                group,
            );
            fixture
                .externals
                .push(Directory::new("zcode-multi-instance-primary-escape"));
            let outside = fixture.externals.last().unwrap().0.clone();
            let external = user_info("PUBLIC-mi-external", "external@multi.invalid");
            let token = jwt("PUBLIC-mi-external");
            fixture.secrets.push(token.clone());
            fixture.secrets.push(external);
            fixture.emails.push("external@multi.invalid".to_owned());
            // ~/.zcode itself redirects outside HOME: the nofollow policy must
            // skip the primary (honest error) without aborting instance
            // discovery, and must never import the genuinely valid external
            // credentials written through the link.
            std::os::unix::fs::symlink(&outside, home.join(".zcode")).unwrap();
            fixture.write(
                &home.join(".zcode/v2/credentials.json"),
                credentials_file(&token, "PUBLIC-mi-external", "external@multi.invalid"),
            );
        }
        #[cfg(unix)]
        Scenario::NonCanonicalHome => {
            // HOME resolves through a symlink; the lexical instance path must
            // still derive the fallback secret, exactly like Go.
            write_valid_instance(
                &mut fixture,
                &zmulti_root(&home),
                "alpha",
                "PUBLIC-mi-alpha",
                group,
            );
        }
        Scenario::ExplicitPath => {
            write_primary(&mut fixture, &home, "PUBLIC-mi-primary", group);
            write_valid_instance(
                &mut fixture,
                &zmulti_root(&home),
                "alpha",
                "PUBLIC-mi-alpha",
                group,
            );
            let token = jwt("PUBLIC-mi-explicit");
            let email = "explicit@multi.invalid";
            fixture.secrets.push(token.clone());
            fixture.emails.push(email.to_owned());
            fixture.secrets.push(EXPLICIT_SECRET.to_owned());
            fixture.write(
                &home.join("explicit/credentials.json"),
                credentials_file(
                    &sealed(EXPLICIT_SECRET, &token),
                    "PUBLIC-mi-explicit",
                    email,
                ),
            );
            fixture.expect(
                "PUBLIC-mi-explicit",
                email.to_owned(),
                PRIMARY_REMARK.to_owned(),
                group,
                token,
            );
            // The explicit target is the only expectation: a valid primary and
            // a valid instance under HOME must contribute nothing.
            fixture
                .expected
                .retain(|expected| expected.user_id == "PUBLIC-mi-explicit");
        }
    }
    let reply = fixture.post(&body).await;
    match scenario {
        Scenario::CorruptPrimary | Scenario::EmptyHome => {
            fixture.assert_rejected(&reply);
            fixture.assert_sanitized(&reply.raw, &home);
            fixture.assert_emails_confined(&reply, false);
            fixture.assert_sources_unchanged();
        }
        _ => {
            fixture.assert_imported_in_order(&reply);
            fixture.assert_sanitized(&reply.raw, &home);
            fixture.assert_emails_confined(&reply, true);
            let alpha_id = reply.json["accounts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|account| account["user_id"] == "PUBLIC-mi-alpha")
                .map(|account| account["id"].as_i64().unwrap());
            if let Some(id) = alpha_id {
                let at_rest = fixture.stored_jwt_at_rest(id);
                assert!(at_rest.starts_with("vault1:"), "credential at rest");
                assert!(!at_rest.contains(
                    fixture
                        .expected
                        .iter()
                        .find(|e| e.user_id == "PUBLIC-mi-alpha")
                        .unwrap()
                        .token
                        .as_str()
                ));
                assert_eq!(
                    fixture.state.vault.decrypt(&at_rest).unwrap(),
                    fixture
                        .expected
                        .iter()
                        .find(|e| e.user_id == "PUBLIC-mi-alpha")
                        .unwrap()
                        .token
                );
            }
            match scenario {
                Scenario::HappyPath => {
                    let errors = reply.json["errors"].as_array().unwrap().clone();
                    assert_eq!(errors.len(), 1, "only zeta may fail: {}", reply.raw);
                    assert_eq!(errors[0]["instance"], "zeta");
                    assert!(
                        !errors[0]["error"].as_str().unwrap_or("").is_empty(),
                        "the corrupt instance must be reported honestly"
                    );
                }
                Scenario::PrimaryMissing | Scenario::ExplicitPath => {
                    assert_eq!(reply.json["errors"], json!([]));
                }
                #[cfg(unix)]
                Scenario::NonCanonicalHome => {
                    assert_eq!(reply.json["errors"], json!([]));
                }
                _ => {
                    assert!(reply.json["errors"].is_array(), "errors must be a list");
                }
            }
            fixture.assert_sources_unchanged();
            #[cfg(unix)]
            if matches!(scenario, Scenario::SymlinkEscape) {
                let stored = fixture.stored_user_ids();
                assert_eq!(stored, vec!["PUBLIC-mi-alpha".to_owned()]);
                assert!(
                    !reply.raw.contains("PUBLIC-mi-escaped"),
                    "a symlinked instance directory must not be discovered"
                );
            }
            #[cfg(unix)]
            if matches!(scenario, Scenario::SymlinkPrimaryDir) {
                let errors = reply.json["errors"].as_array().unwrap().clone();
                assert!(
                    !errors.is_empty(),
                    "an unusable primary parent must be reported honestly, not silently dropped"
                );
                for entry in &errors {
                    assert!(
                        !entry["error"].as_str().unwrap_or("").is_empty(),
                        "each reported failure must carry a sanitized message"
                    );
                }
                assert_eq!(
                    fixture.stored_user_ids(),
                    vec!["PUBLIC-mi-alpha".to_owned()]
                );
                assert!(
                    !reply.raw.contains("PUBLIC-mi-external"),
                    "a symlinked primary directory must not be followed"
                );
            }
            if let Scenario::Cap = scenario {
                assert!(
                    !reply.raw.contains("PUBLIC-mi-inst-64"),
                    "the discovery cap admits at most 64 instances"
                );
            }
        }
    }
}

#[test]
fn multi_instance_discovery_imports_primary_and_both_roots_with_per_instance_secrets() {
    run(
        "multi_instance_discovery_imports_primary_and_both_roots_with_per_instance_secrets",
        &[Case {
            id: "happy-path",
            scenario: Scenario::HappyPath,
        }],
    );
}

#[test]
fn multi_instance_discovery_imports_instances_when_primary_is_missing() {
    run(
        "multi_instance_discovery_imports_instances_when_primary_is_missing",
        &[Case {
            id: "primary-missing",
            scenario: Scenario::PrimaryMissing,
        }],
    );
}

#[test]
fn multi_instance_discovery_fails_closed_on_corrupt_primary_without_partial_import() {
    run(
        "multi_instance_discovery_fails_closed_on_corrupt_primary_without_partial_import",
        &[Case {
            id: "corrupt-primary",
            scenario: Scenario::CorruptPrimary,
        }],
    );
}

#[test]
fn multi_instance_discovery_without_any_credentials_fails_closed() {
    run(
        "multi_instance_discovery_without_any_credentials_fails_closed",
        &[Case {
            id: "empty-home",
            scenario: Scenario::EmptyHome,
        }],
    );
}

#[test]
fn multi_instance_discovery_is_capped_at_sixty_four_instances_in_deterministic_order() {
    run(
        "multi_instance_discovery_is_capped_at_sixty_four_instances_in_deterministic_order",
        &[Case {
            id: "cap",
            scenario: Scenario::Cap,
        }],
    );
}

#[test]
fn multi_instance_discovery_skips_oversized_instance_files() {
    run(
        "multi_instance_discovery_skips_oversized_instance_files",
        &[Case {
            id: "oversize",
            scenario: Scenario::Oversize,
        }],
    );
}

#[cfg(unix)]
#[test]
fn multi_instance_discovery_does_not_follow_symlinked_instance_directories() {
    run(
        "multi_instance_discovery_does_not_follow_symlinked_instance_directories",
        &[Case {
            id: "symlink-escape",
            scenario: Scenario::SymlinkEscape,
        }],
    );
}

#[cfg(unix)]
#[test]
fn symlinked_primary_parent_skips_primary_with_honest_error_and_discovers_instances() {
    run(
        "symlinked_primary_parent_skips_primary_with_honest_error_and_discovers_instances",
        &[Case {
            id: "symlink-primary-dir",
            scenario: Scenario::SymlinkPrimaryDir,
        }],
    );
}

#[cfg(unix)]
#[test]
fn non_canonical_home_still_derives_instance_secrets_from_the_lexical_home() {
    run(
        "non_canonical_home_still_derives_instance_secrets_from_the_lexical_home",
        &[Case {
            id: "non-canonical-home",
            scenario: Scenario::NonCanonicalHome,
        }],
    );
}

#[test]
fn explicit_local_credentials_path_imports_only_that_file_without_discovery() {
    run(
        "explicit_local_credentials_path_imports_only_that_file_without_discovery",
        &[Case {
            id: "explicit-path",
            scenario: Scenario::ExplicitPath,
        }],
    );
}
