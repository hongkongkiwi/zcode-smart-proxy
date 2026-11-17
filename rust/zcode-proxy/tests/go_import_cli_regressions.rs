use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use zcode_proxy::{store, vault::Vault};

// Public synthetic seed shared with the Go-produced vault interop fixture.
const PUBLIC_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const PUBLIC_JWT: &str = "PUBLIC CLI imported jwt";
const PUBLIC_KEY: &str = "PUBLIC CLI imported account key";
const PUBLIC_ROOT_KEY: &str = "PUBLIC CLI imported root key";
const PUBLIC_BOOTSTRAP: &str = "PUBLIC CLI must not bootstrap this password";
const PUBLIC_WRONG_SECRET: &str = "PUBLIC CLI wrong vault secret";

struct Fixture {
    root: PathBuf,
    data: PathBuf,
    source: PathBuf,
    destination: PathBuf,
    sentinel: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "zcode-go-import-cli-{}-{:032x}",
            std::process::id(),
            rand::random::<u128>()
        ));
        let data = root.join("data");
        fs::create_dir_all(data.join("source")).unwrap();
        fs::create_dir(data.join("service")).unwrap();
        let source = data.join("source/go.sqlite");
        let destination = data.join("imported");
        let sentinel = data.join("service/sentinel.sqlite");
        let db = Connection::open(&source).unwrap();
        db.execute_batch(include_str!("fixtures/go_schema.sql"))
            .unwrap();
        let vault = Vault::from_secret(PUBLIC_SEED).unwrap();
        for (column, plain) in [("zcode_jwt", PUBLIC_JWT), ("api_key", PUBLIC_KEY)] {
            db.execute(
                &format!("UPDATE accounts SET {column} = ?1 WHERE id = 101"),
                [vault.encrypt(plain).unwrap()],
            )
            .unwrap();
        }
        db.execute(
            "INSERT INTO settings(key, value, updated_at) VALUES('api_key', ?1, '2026-01-01 00:00:00')",
            [vault.encrypt(PUBLIC_ROOT_KEY).unwrap()],
        )
        .unwrap();
        drop(db);
        let db = Connection::open(&sentinel).unwrap();
        db.execute_batch(
            "CREATE TABLE cli_sentinel(value TEXT NOT NULL);
             INSERT INTO cli_sentinel VALUES('PUBLIC untouched service database');",
        )
        .unwrap();
        drop(db);
        Self {
            root,
            data,
            source,
            destination,
            sentinel,
        }
    }

    fn import_args(&self) -> Vec<OsString> {
        vec![
            "import-go".into(),
            self.source.as_os_str().to_owned(),
            self.destination.as_os_str().to_owned(),
        ]
    }

    fn run(&self, args: &[OsString], secret: Option<&str>) -> Outcome {
        let stdout_path = self.root.join("stdout.log");
        let stderr_path = self.root.join("stderr.log");
        let mut command = Command::new(env!("CARGO_BIN_EXE_zcode-proxy-rs"));
        command
            .env_clear()
            .current_dir(&self.data)
            .args(args)
            .env("TOKIO_WORKER_THREADS", "2")
            .env("ZCODE_RS_DB", &self.sentinel)
            .env("ZCODE_RS_BIND", "PUBLIC-invalid-socket-address")
            .env("ZCODE_RS_ADMIN_PASSWORD", PUBLIC_BOOTSTRAP)
            .env("ZCODE_RS_UPSTREAM_ZAI", "http://127.0.0.1:1/unused")
            .env("ZCODE_RS_UPSTREAM_FALLBACK", "http://127.0.0.1:1/unused")
            .stdin(Stdio::null())
            .stdout(fs::File::create(&stdout_path).unwrap())
            .stderr(fs::File::create(&stderr_path).unwrap());
        if let Some(secret) = secret {
            command.env("ZCODE_PROXY_VAULT_SECRET", secret);
        }
        let mut child = Process(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                child.0.kill().unwrap();
                child.0.wait().unwrap();
                panic!("CLI did not exit within 5 seconds; child was killed and reaped");
            }
            thread::sleep(Duration::from_millis(10));
        };
        let outcome = Outcome {
            status,
            stdout: fs::read_to_string(stdout_path).unwrap(),
            stderr: fs::read_to_string(stderr_path).unwrap(),
        };
        for secret in [
            PUBLIC_SEED,
            PUBLIC_JWT,
            PUBLIC_KEY,
            PUBLIC_ROOT_KEY,
            PUBLIC_BOOTSTRAP,
            PUBLIC_WRONG_SECRET,
        ] {
            assert!(
                !outcome.stdout.contains(secret) && !outcome.stderr.contains(secret),
                "CLI output disclosed synthetic credential material"
            );
        }
        assert!(
            !outcome.stdout.contains("listening on") && !outcome.stderr.contains("listening on"),
            "offline CLI started the HTTP server"
        );
        outcome
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Debug)]
struct Outcome {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

fn files(path: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if entry.file_type().unwrap().is_dir() {
                result.insert(relative, None);
                visit(root, &path, result);
            } else {
                result.insert(relative, Some(fs::read(path).unwrap()));
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(path, path, &mut result);
    result
}

fn read_only(path: &Path) -> Connection {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
}

#[test]
fn import_go_exits_with_nonsecret_json_and_never_enters_service_startup() {
    let f = Fixture::new();
    let before = files(&f.data);
    let outcome = f.run(&f.import_args(), Some(PUBLIC_SEED));
    assert!(
        outcome.status.success(),
        "offline import failed: {outcome:?}"
    );
    let report: Value = serde_json::from_str(&outcome.stdout)
        .expect("stdout must be one JSON report, without service startup output");
    assert_eq!(report["complete"], true);
    assert_eq!(report["archive"], "go-source.sqlite");
    assert_eq!(report["runtime"], "zcode-rs.db");
    assert_eq!(report["history_projection"], "deferred");
    let manifest: Value =
        serde_json::from_slice(&fs::read(f.destination.join("import-manifest.json")).unwrap())
            .unwrap();
    assert_eq!(report, manifest);
    for artifact in ["go-source.sqlite", "zcode-rs.db", "vault.key"] {
        assert!(f.destination.join(artifact).is_file(), "missing {artifact}");
    }
    let mut after = files(&f.data);
    after.retain(|path, _| !path.starts_with("imported"));
    assert_eq!(
        after, before,
        "import mutated source or service startup files"
    );

    let seed = fs::read_to_string(f.destination.join("vault.key")).unwrap();
    let vault = Vault::from_secret(seed.trim()).unwrap();
    let runtime = read_only(&f.destination.join("zcode-rs.db"));
    let accounts = store::load_accounts(&runtime, &vault).unwrap();
    let (_, jwt, key) = accounts.iter().find(|(a, _, _)| a.id == 101).unwrap();
    assert_eq!(jwt, PUBLIC_JWT);
    assert_eq!(key, PUBLIC_KEY);
    let settings = store::load_settings(&runtime, &vault).unwrap();
    assert_eq!(settings["api_key"], PUBLIC_ROOT_KEY);
    assert!(
        !settings.contains_key("admin_password_hash"),
        "import applied server bootstrap settings"
    );
    let archived = read_only(&f.destination.join("go-source.sqlite"));
    let count: i64 = archived
        .query_row("SELECT count(*) FROM accounts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn import_go_requires_nonempty_explicit_environment_secret_without_any_writes() {
    for secret in [None, Some("")] {
        let f = Fixture::new();
        // A source keyfile must not silently replace the CLI's explicit secret.
        fs::write(f.source.parent().unwrap().join("vault.key"), PUBLIC_SEED).unwrap();
        let before = files(&f.data);
        let outcome = f.run(&f.import_args(), secret);
        assert!(!outcome.status.success(), "missing secret was accepted");
        assert_eq!(files(&f.data), before, "missing secret changed files");
        assert!(
            !outcome.stdout.trim().is_empty() || !outcome.stderr.trim().is_empty(),
            "missing secret had no diagnostic"
        );
    }
}

#[test]
fn import_go_arity_errors_and_help_exit_without_database_or_key_writes() {
    for case in [
        "missing both",
        "missing destination",
        "extra",
        "help",
        "import help",
    ] {
        let f = Fixture::new();
        let args = match case {
            "missing both" => vec!["import-go".into()],
            "missing destination" => vec!["import-go".into(), f.source.as_os_str().to_owned()],
            "extra" => {
                let mut args = f.import_args();
                args.push("PUBLIC-unexpected-secret-argument".into());
                args
            }
            "help" => vec!["--help".into()],
            "import help" => vec!["import-go".into(), "--help".into()],
            _ => unreachable!(),
        };
        let before = files(&f.data);
        let outcome = f.run(&args, Some(PUBLIC_SEED));
        assert_eq!(
            outcome.status.success(),
            case == "help" || case == "import help",
            "unexpected exit status for {case}: {outcome:?}"
        );
        assert_eq!(files(&f.data), before, "{case} changed files");
        assert!(
            outcome.stdout.contains("import-go") || outcome.stderr.contains("import-go"),
            "{case} must show import-go usage: {outcome:?}"
        );
    }
}

#[test]
fn import_go_rejects_wrong_secret_and_existing_destination_without_mutation() {
    for existing_destination in [false, true] {
        let f = Fixture::new();
        if existing_destination {
            fs::create_dir(&f.destination).unwrap();
            fs::write(
                f.destination.join("PUBLIC-marker"),
                "PUBLIC retained contents",
            )
            .unwrap();
        }
        let before = files(&f.data);
        let secret = if existing_destination {
            PUBLIC_SEED
        } else {
            PUBLIC_WRONG_SECRET
        };
        let outcome = f.run(&f.import_args(), Some(secret));
        assert!(!outcome.status.success(), "invalid import was accepted");
        assert_eq!(files(&f.data), before, "rejected import changed files");
        assert!(
            !outcome.stdout.trim().is_empty() || !outcome.stderr.trim().is_empty(),
            "rejected import had no diagnostic"
        );
    }
}
