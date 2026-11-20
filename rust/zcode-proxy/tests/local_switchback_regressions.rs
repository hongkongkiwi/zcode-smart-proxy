use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    http::{HeaderMap, Request, StatusCode},
    Router,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use zcode_core::AccountView;
use zcode_proxy::{
    admin::SESSION_COOKIE,
    auth::now_secs,
    build_router,
    state::{AppState, UpstreamUrls},
    store,
};

// Use the desktop decoder itself, including its directory-based secret derivation.
#[path = "../src/desktop_credentials.rs"]
mod desktop_credentials;

const SESSION: &str = "PUBLIC-local-switchback-session";
const ROOT: &str = "PUBLIC-local-switchback-root";
const JWT: &str = "PUBLIC-local-switchback-jwt";
const API_KEY: &str = "PUBLIC-local-switchback-api-key";
const ACCESS: &str = "PUBLIC-local-switchback-access-token";
const USER_INFO: &str = r#"{"user_id":"PUBLIC-local-user","email":"local@example.test"}"#;
const SWITCH_BACK: &str = "/api/accounts/1/switch-back";
const RESTORE_LOCAL: &str = "/api/accounts/1/restore-local";
const SENTINEL: &[u8] = b"PUBLIC outside-client sentinel must remain unchanged\n";
const DEADLINE: Duration = Duration::from_secs(5);

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "zcode-local-switchback-{}-{:032x}",
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

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn expect_status(&self, status: StatusCode) {
        assert_eq!(self.status, status, "body={}", self.body);
        assert_eq!(self.headers["cache-control"], "no-store");
    }

    fn expect_json(&self, status: StatusCode, expected: Value) {
        self.expect_status(status);
        let actual: Value = serde_json::from_str(&self.body).expect("response must be JSON");
        assert_eq!(actual, expected);
    }
}

struct Fixture {
    directory: Directory,
    client: PathBuf,
    state: Arc<AppState>,
    app: Router,
}

impl Fixture {
    fn new(account: AccountView) -> Self {
        Self::with_directory(account, true)
    }

    fn with_directory(account: AccountView, configured: bool) -> Self {
        let directory = Directory::new();
        // The parent directory is also test-owned, so a rejected ../escape stays contained.
        let client = directory.0.join("client");
        fs::create_dir(&client).unwrap();
        fs::write(directory.0.join("outside-client-sentinel"), SENTINEL).unwrap();
        let db = store::open(":memory:");
        let id = store::upsert_account(&db, &account, &account.zcode_jwt, &account.api_key);
        assert_eq!(id, 1);
        let mut state = AppState::from_db(
            ROOT.into(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
            db,
        );
        assert!(state.local_client_dir.is_none());
        state.local_client_dir = configured.then(|| client.clone());
        assert_eq!(
            state.local_client_dir.as_deref(),
            configured.then_some(client.as_path())
        );
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        let state = Arc::new(state);
        Self {
            app: build_router(state.clone()),
            state,
            directory,
            client,
        }
    }

    fn seed_details(&self, access: &str, user_info: &str, snapshot: &str) {
        let access = self.state.vault.encrypt(access).unwrap();
        let user_info = self.state.vault.encrypt(user_info).unwrap();
        let snapshot = self.state.vault.encrypt(snapshot).unwrap();
        assert_eq!(
            self.state
                .db
                .lock()
                .unwrap()
                .execute(
                    "UPDATE accounts SET access_token=?1,user_info=?2,creds_raw=?3 WHERE id=1",
                    rusqlite::params![access, user_info, snapshot],
                )
                .unwrap(),
            1
        );
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        assert!(matches!(
            name,
            "credentials.json" | "config.json" | "cache.json" | "backups"
        ));
        let path = self.client.join(name);
        assert!(path.starts_with(&self.directory.0));
        fs::write(path, bytes).unwrap();
    }

    fn read(&self, name: &str) -> Vec<u8> {
        assert!(matches!(
            name,
            "credentials.json" | "config.json" | "cache.json" | "backups"
        ));
        fs::read(self.client.join(name)).unwrap()
    }

    fn json(&self, name: &str) -> Value {
        serde_json::from_slice(&self.read(name)).unwrap()
    }

    async fn post(&self, path: &str, session: bool, body: &str) -> Reply {
        self.post_with_origin(path, session, body, "http://localhost:8787")
            .await
    }

    async fn post_with_origin(&self, path: &str, session: bool, body: &str, origin: &str) -> Reply {
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .header("host", "localhost:8787")
            .header("origin", origin)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {ROOT}"))
            .header("x-api-key", ROOT);
        if session {
            request = request.header("cookie", format!("{SESSION_COOKIE}={SESSION}"));
        }
        tokio::time::timeout(DEADLINE, async {
            let response = self
                .app
                .clone()
                .oneshot(request.body(Body::from(body.to_owned())).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let headers = response.headers().clone();
            let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
            Reply {
                status,
                headers,
                body: String::from_utf8(bytes.to_vec()).unwrap(),
            }
        })
        .await
        .expect("local credential request exceeded the test deadline")
    }

    fn assert_entries(&self, expected: &[String]) {
        fn visit(root: &Path, directory: &Path, entries: &mut BTreeSet<String>) {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                assert!(path.starts_with(root));
                let kind = entry.file_type().unwrap();
                assert!(
                    !kind.is_symlink(),
                    "local writes must not introduce symlinks"
                );
                entries.insert(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                );
                if kind.is_dir() {
                    visit(root, &path, entries);
                }
            }
        }
        let mut actual = BTreeSet::new();
        visit(&self.client, &self.client, &mut actual);
        assert_eq!(actual, expected.iter().cloned().collect::<BTreeSet<_>>());
        let siblings: BTreeSet<_> = fs::read_dir(&self.directory.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            siblings,
            BTreeSet::from(["client".into(), "outside-client-sentinel".into()])
        );
        assert_eq!(
            fs::read(self.directory.0.join("outside-client-sentinel")).unwrap(),
            SENTINEL
        );
    }

    fn assert_backups(&self, originals: &[(&str, &[u8])]) -> Vec<String> {
        let backup_dir = self.client.join("backups");
        let mut backups: Vec<_> = fs::read_dir(&backup_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        backups.sort();
        assert_eq!(backups.len(), originals.len());
        for (name, original) in originals {
            let prefix = format!("{name}.");
            let matches: Vec<_> = backups
                .iter()
                .filter(|path| {
                    let filename = path.file_name().unwrap().to_str().unwrap();
                    filename.starts_with(&prefix)
                        && filename.ends_with(".bak")
                        && filename.len() > prefix.len() + ".bak".len()
                })
                .collect();
            assert_eq!(matches.len(), 1, "expected one backup of {name}");
            assert!(fs::symlink_metadata(matches[0])
                .unwrap()
                .file_type()
                .is_file());
            assert_eq!(fs::read(matches[0]).unwrap(), *original);
            assert_private(matches[0]);
        }
        backups
            .iter()
            .map(|path| {
                path.strip_prefix(&self.client)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }
}

fn account(jwt: &str, api_key: &str) -> AccountView {
    AccountView {
        email: "local@example.test".into(),
        provider: "zai".into(),
        enabled: true,
        status: "active".into(),
        zcode_jwt: jwt.into(),
        api_key: api_key.into(),
        ..AccountView::default()
    }
}

fn assert_private(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn assert_decrypted(credentials: &Value, key: &str, expected: &str, _directory: &Path) {
    // Switch-back encrypts with the user home, matching the desktop client.
    let value = credentials[key]
        .as_str()
        .expect("credential must be a string");
    assert!(
        value.starts_with("enc:v1:"),
        "{key} must be encrypted, not plaintext"
    );
    assert_eq!(
        desktop_credentials::decrypt(value, None, None).expect("desktop decryption failed"),
        expected,
        "wrong plaintext for {key}"
    );
}

#[tokio::test]
async fn missing_local_directory_returns_exact_error_for_both_routes_without_writes() {
    let f = Fixture::with_directory(account(JWT, API_KEY), false);
    for path in [SWITCH_BACK, RESTORE_LOCAL] {
        f.post(path, true, "{}").await.expect_json(
            StatusCode::BAD_REQUEST,
            json!({"message": "no local client directory configured"}),
        );
        f.assert_entries(&[]);
    }
}

#[tokio::test]
async fn missing_session_returns_exact_unauthorized_for_both_routes_without_writes() {
    let f = Fixture::new(account(JWT, API_KEY));
    for path in [SWITCH_BACK, RESTORE_LOCAL] {
        f.post(path, false, "{}").await.expect_json(
            StatusCode::UNAUTHORIZED,
            json!({"error": {"message": "unauthorized", "type": "api_error"}}),
        );
        f.assert_entries(&[]);
    }
}

#[tokio::test]
async fn cross_origin_requests_are_rejected_for_both_routes_without_writes() {
    let f = Fixture::new(account(JWT, API_KEY));
    for path in [SWITCH_BACK, RESTORE_LOCAL] {
        f.post_with_origin(path, true, "{}", "https://other.example.test")
            .await
            .expect_json(
                StatusCode::FORBIDDEN,
                json!({"success": false, "message": "cross-origin request rejected"}),
            );
        f.assert_entries(&[]);
    }
}

#[tokio::test]
async fn unknown_accounts_return_not_found_for_both_routes_without_writes() {
    let f = Fixture::new(account(JWT, API_KEY));
    for path in [
        "/api/accounts/999/switch-back",
        "/api/accounts/999/restore-local",
    ] {
        f.post(path, true, "{}")
            .await
            .expect_status(StatusCode::NOT_FOUND);
        f.assert_entries(&[]);
    }
}

#[tokio::test]
async fn switch_back_rejects_missing_jwt_and_malformed_json_without_writes() {
    for (jwt, body) in [("", "{}"), (JWT, "{malformed")] {
        let f = Fixture::new(account(jwt, API_KEY));
        f.post(SWITCH_BACK, true, body)
            .await
            .expect_status(StatusCode::BAD_REQUEST);
        f.assert_entries(&[]);
    }
}

#[tokio::test]
async fn switch_back_encrypts_merges_backs_up_and_accepts_empty_body_or_ignored_kill_client() {
    for body in ["", r#"{"kill_client":true}"#] {
        let f = Fixture::new(account(JWT, API_KEY));
        f.seed_details(ACCESS, USER_INFO, "");
        let credentials = b" {\"bot\":\"keep-me\"}\n";
        let config = b" {\"unrelated\":\"keep\"}\n";
        f.write("credentials.json", credentials);
        f.write("config.json", config);
        f.write("cache.json", b"PUBLIC stale cache");
        f.post(SWITCH_BACK, true, body)
            .await
            .expect_json(StatusCode::OK, json!({"success": true, "killed": false}));
        let credentials_after = f.json("credentials.json");
        assert_eq!(credentials_after["bot"], "keep-me");
        for (key, expected) in [
            ("zcodejwttoken", JWT),
            ("oauth:zai:access_token", ACCESS),
            ("oauth:zai:user_info", USER_INFO),
            ("oauth:active_provider", "zai"),
        ] {
            assert_decrypted(&credentials_after, key, expected, &f.client);
        }
        let config_after = f.json("config.json");
        assert_eq!(config_after["unrelated"], "keep");
        let providers = &config_after["provider"];
        for (provider, key) in [
            ("builtin:zai-start-plan", JWT),
            ("builtin:zai-coding-plan", API_KEY),
        ] {
            assert_eq!(providers[provider]["options"]["apiKey"], key);
            assert_eq!(providers[provider]["enabled"], true);
        }
        assert_private(&f.client.join("credentials.json"));
        assert_private(&f.client.join("config.json"));
        let mut entries = vec![
            "credentials.json".into(),
            "config.json".into(),
            "backups".into(),
        ];
        entries.extend(
            f.assert_backups(&[("credentials.json", credentials), ("config.json", config)]),
        );
        // This exact inventory also excludes cache, temporary files, and kill-client markers.
        f.assert_entries(&entries);
    }
}

#[tokio::test]
async fn switch_back_disables_empty_api_key_and_removes_stale_optional_credentials() {
    let f = Fixture::new(account(JWT, ""));
    f.write("credentials.json", br#"{"oauth:zai:access_token":"PUBLIC stale access","oauth:zai:user_info":"PUBLIC stale profile"}"#);
    f.post(SWITCH_BACK, true, "{}")
        .await
        .expect_json(StatusCode::OK, json!({"success": true, "killed": false}));
    let credentials = f.json("credentials.json");
    let object = credentials.as_object().unwrap();
    assert!(!object.contains_key("oauth:zai:access_token"));
    assert!(!object.contains_key("oauth:zai:user_info"));
    let config = f.json("config.json");
    assert_eq!(
        config["provider"]["builtin:zai-coding-plan"]["enabled"],
        false
    );
    assert_eq!(
        config["provider"]["builtin:zai-coding-plan"]["options"]["apiKey"],
        ""
    );
    assert_eq!(
        config["provider"]["builtin:zai-start-plan"]["enabled"],
        true
    );
    assert_eq!(
        config["provider"]["builtin:zai-start-plan"]["options"]["apiKey"],
        JWT
    );
    let mut entries = vec![
        "credentials.json".into(),
        "config.json".into(),
        "backups".into(),
    ];
    entries.extend(f.assert_backups(&[("credentials.json", br#"{"oauth:zai:access_token":"PUBLIC stale access","oauth:zai:user_info":"PUBLIC stale profile"}"#)]));
    f.assert_entries(&entries);
}

#[tokio::test]
async fn invalid_existing_credentials_are_unchanged_and_do_not_create_backups() {
    let f = Fixture::new(account(JWT, API_KEY));
    let credentials = b"PUBLIC not valid JSON\n";
    let config = b" {\"unrelated\":\"keep\"}\n";
    f.write("credentials.json", credentials);
    f.write("config.json", config);
    f.write("cache.json", b"PUBLIC cache to preserve");
    f.post(SWITCH_BACK, true, "{}")
        .await
        .expect_status(StatusCode::BAD_REQUEST);
    assert_eq!(f.read("credentials.json"), credentials);
    assert_eq!(f.read("config.json"), config);
    assert_eq!(f.read("cache.json"), b"PUBLIC cache to preserve");
    f.assert_entries(&[
        "credentials.json".into(),
        "config.json".into(),
        "cache.json".into(),
    ]);
}

#[tokio::test]
async fn restore_local_rejects_empty_snapshot_without_writes() {
    for snapshot in ["", "{}"] {
        let f = Fixture::new(account(JWT, API_KEY));
        f.seed_details("", "", snapshot);
        f.post(RESTORE_LOCAL, true, "{}")
            .await
            .expect_status(StatusCode::BAD_REQUEST);
        f.assert_entries(&[]);
    }
}

#[tokio::test]
async fn restore_local_writes_only_allowlisted_snapshot_bytes_and_backs_up_previous_files() {
    let f = Fixture::new(account(JWT, API_KEY));
    let restored_credentials = " \n{\"bot\":\"PUBLIC restored bot\"}\t\n";
    let restored_config = "\t{\"unrelated\":\"PUBLIC restored config\"}\r\n";
    f.seed_details(
        "",
        "",
        &json!({
            "credentials.json": restored_credentials,
            "config.json": restored_config,
            "../escape": "x",
            "notes": "ignore",
        })
        .to_string(),
    );
    let credentials = b"PUBLIC previous credentials bytes\n";
    let config = b"PUBLIC previous config bytes\n";
    f.write("credentials.json", credentials);
    f.write("config.json", config);
    f.write("cache.json", b"PUBLIC cache to remove");
    f.post(RESTORE_LOCAL, true, "{}")
        .await
        .expect_json(StatusCode::OK, json!({"success": true}));
    assert_eq!(f.read("credentials.json"), restored_credentials.as_bytes());
    assert_eq!(f.read("config.json"), restored_config.as_bytes());
    assert_private(&f.client.join("credentials.json"));
    assert_private(&f.client.join("config.json"));
    let mut entries = vec![
        "credentials.json".into(),
        "config.json".into(),
        "backups".into(),
    ];
    entries.extend(f.assert_backups(&[("credentials.json", credentials), ("config.json", config)]));
    f.assert_entries(&entries);
}

#[tokio::test]
async fn backup_directory_failure_aborts_both_routes_before_changing_either_target() {
    for (path, snapshot) in [
        (SWITCH_BACK, "{}".to_string()),
        (
            RESTORE_LOCAL,
            // Plaintext file contents pass the decrypt preflight and reach the backup step.
            json!({
                "credentials.json": "{\"bot\":\"PUBLIC replacement credentials\"}",
                "config.json": "{}",
            })
            .to_string(),
        ),
    ] {
        let f = Fixture::new(account(JWT, API_KEY));
        f.seed_details(ACCESS, USER_INFO, &snapshot);
        let credentials = b" {\"bot\":\"keep-me\"}\n";
        let config = b" {\"unrelated\":\"keep\"}\n";
        f.write("credentials.json", credentials);
        f.write("config.json", config);
        f.write("cache.json", b"PUBLIC cache to preserve");
        f.write("backups", b"PUBLIC file blocking the backup directory");
        f.post(path, true, "{}")
            .await
            .expect_status(StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(f.read("credentials.json"), credentials);
        assert_eq!(f.read("config.json"), config);
        assert_eq!(f.read("cache.json"), b"PUBLIC cache to preserve");
        assert_eq!(
            f.read("backups"),
            b"PUBLIC file blocking the backup directory"
        );
        f.assert_entries(&[
            "credentials.json".into(),
            "config.json".into(),
            "cache.json".into(),
            "backups".into(),
        ]);
    }
}
