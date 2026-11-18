use std::{
    fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
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
    store,
    vault::Vault,
};

const CHILD_CASE: &str = "ZCODE_PUBLIC_DESKTOP_SECRET_TEST_CASE";
const ENV_SECRET: &str = " PUBLIC environment desktop secret 密钥 ";
const EXPLICIT_SECRET: &str = "PUBLIC explicit desktop secret";
const TOKEN: &str = "PUBLIC synthetic desktop login token";
const SESSION: &str = "PUBLIC-desktop-secret-session";

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "zcode-desktop-secret-{}-{:032x}",
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

struct Case {
    id: &'static str,
    environment_secret: Option<&'static str>,
    explicit_secret: Option<&'static str>,
    username: &'static str,
    user: &'static str,
    logname: &'static str,
    expected_username: &'static str,
}

impl Case {
    fn machine(id: &'static str) -> Self {
        Self {
            id,
            environment_secret: None,
            explicit_secret: None,
            username: "PUBLIC-username-first",
            user: "PUBLIC-user-second",
            logname: "PUBLIC-logname-third",
            expected_username: "PUBLIC-username-first",
        }
    }
}

// Self-exec confines environment changes to one child and never inherits a real desktop home.
fn run(test: &str, cases: &[Case]) {
    if let Some(id) = std::env::var_os(CHILD_CASE) {
        let case = cases.iter().find(|case| id == case.id).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(exercise(case));
        return;
    }
    for case in cases {
        let home = Directory::new();
        let log_path = home.0.join("child.log");
        let log = fs::File::create(&log_path).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .env_clear()
            .current_dir(&home.0)
            .env(CHILD_CASE, case.id)
            .env("HOME", &home.0)
            .env("USERPROFILE", &home.0)
            .env("USERNAME", case.username)
            .env("USER", case.user)
            .env("LOGNAME", case.logname)
            .args(["--exact", test, "--nocapture"])
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log);
        if let Some(secret) = case.environment_secret {
            command.env("ZCODE_CREDENTIAL_SECRET", secret);
        }
        let mut child = Process(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
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
                "isolated {test}/{} exceeded five seconds",
                case.id
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

async fn exercise(case: &Case) {
    let home = std::env::current_dir().unwrap();
    let platform = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(windows) {
        "win32"
    } else {
        std::env::consts::OS
    };
    let machine_secret = format!(
        "zcode-credential-fallback:{platform}:{}:{}",
        home.to_str().unwrap(),
        case.expected_username
    );
    let expected_secret = case
        .explicit_secret
        .or(case.environment_secret.filter(|secret| !secret.is_empty()))
        .unwrap_or(&machine_secret);
    // The Go-verified vault fixture establishes this prefix-only AES-GCM envelope mapping.
    let envelope = Vault::from_secret(expected_secret)
        .unwrap()
        .encrypt(TOKEN)
        .unwrap();
    let desktop_token = format!("enc:v1:{}", envelope.strip_prefix("vault1:").unwrap());
    let path = home.join("synthetic-credentials.json");
    let source = json!({
        "zcodejwttoken":desktop_token,
        "oauth:zai:user_info":json!({"user_id":"PUBLIC-secret-resolution-account"}).to_string(),
    })
    .to_string();
    fs::write(&path, &source).unwrap();
    let mut state = AppState::try_from_db_with_vault(
        "PUBLIC-desktop-secret-root".into(),
        UpstreamUrls {
            zai: "http://127.0.0.1:1/unused".into(),
            zai_fallback: "http://127.0.0.1:1/unused".into(),
        },
        store::open(":memory:"),
        Vault::from_secret("PUBLIC independent persistence vault secret").unwrap(),
    )
    .unwrap();
    state.local_credentials_path = Some(path.clone());
    state.local_credentials_secret = case.explicit_secret.map(|secret| secret.to_owned().into());
    state
        .sessions
        .lock()
        .unwrap()
        .insert(SESSION.into(), now_secs() + 3600);
    let state = Arc::new(state);
    let response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/accounts/import/local")
                .header("host", "localhost:8080")
                .header("content-type", "application/json")
                .header("cookie", format!("{SESSION_COOKIE}={SESSION}"))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let raw = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "{}: local import must resolve the Go-compatible desktop secret: {raw}",
        case.id
    );
    let reply: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(reply["success"], true);
    assert_eq!(
        reply["account"]["user_id"],
        "PUBLIC-secret-resolution-account"
    );
    assert_eq!(reply["account"]["has_jwt"], true);
    for secret in [
        TOKEN,
        expected_secret,
        ENV_SECRET,
        EXPLICIT_SECRET,
        home.to_str().unwrap(),
        "enc:v1:",
        "vault1:",
    ] {
        assert!(!raw.contains(secret), "response leaked local import data");
    }
    let stored: String = state
        .db
        .lock()
        .unwrap()
        .query_row("SELECT zcode_jwt FROM accounts", [], |row| row.get(0))
        .unwrap();
    assert!(stored.starts_with("vault1:"));
    assert_eq!(state.vault.decrypt(&stored).unwrap(), TOKEN);
    let id = reply["account"]["id"].as_i64().unwrap();
    assert_eq!(state.creds.lock().unwrap()[&id].zcode_jwt, TOKEN);
    assert_eq!(fs::read_to_string(path).unwrap(), source);
}

#[test]
fn machine_desktop_secret_uses_go_platform_home_and_username_precedence() {
    run(
        "machine_desktop_secret_uses_go_platform_home_and_username_precedence",
        &[
            Case::machine("USERNAME-wins"),
            Case {
                id: "USER-fallback",
                username: "",
                expected_username: "PUBLIC-user-second",
                ..Case::machine("unused")
            },
            Case {
                id: "LOGNAME-fallback",
                username: "",
                user: "",
                expected_username: "PUBLIC-logname-third",
                ..Case::machine("unused")
            },
            Case {
                id: "unknown-fallback",
                username: "",
                user: "",
                logname: "",
                expected_username: "unknown",
                ..Case::machine("unused")
            },
        ],
    );
}

#[test]
fn explicit_desktop_secret_overrides_a_wrong_nonempty_environment_secret() {
    run(
        "explicit_desktop_secret_overrides_a_wrong_nonempty_environment_secret",
        &[Case {
            environment_secret: Some("PUBLIC deliberately wrong environment secret"),
            explicit_secret: Some(EXPLICIT_SECRET),
            ..Case::machine("explicit-over-environment")
        }],
    );
}

#[test]
fn environment_desktop_secret_is_literal_and_empty_environment_uses_machine_fallback() {
    run(
        "environment_desktop_secret_is_literal_and_empty_environment_uses_machine_fallback",
        &[
            Case {
                environment_secret: Some(ENV_SECRET),
                ..Case::machine("literal-nonempty-environment")
            },
            Case {
                environment_secret: Some(""),
                ..Case::machine("empty-environment-falls-back")
            },
        ],
    );
}
