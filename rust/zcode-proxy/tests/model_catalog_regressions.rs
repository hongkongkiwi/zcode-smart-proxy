use std::{
    collections::{BTreeMap, VecDeque},
    convert::Infallible,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{Request as IncomingRequest, State},
    http::{HeaderMap, Request, StatusCode},
    response::Response,
    Router,
};
use futures_util::{stream, StreamExt};
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

const CATALOG: &str = "/api/models/catalog";
const SYNC: &str = "/api/models/sync";
const CONFIGS: &str = "/api/v1/client/configs";
const HOST: &str = "localhost:8787";
const SESSION: &str = "PUBLIC-model-catalog-session";
const EXPIRED: &str = "PUBLIC-model-catalog-expired-session";
const ROOT: &str = "PUBLIC-model-catalog-root-key";
const JWT: &str = "PUBLIC-model-catalog-account-jwt";
const ACCOUNT_KEY: &str = "PUBLIC-model-catalog-account-api-key";
const VERSION: &str = "PUBLIC-catalog-version+build &1";
const LIMIT: usize = 4 << 20;
const DEADLINE: Duration = Duration::from_secs(5);
const FIXED_IDS: &[&str] = &[
    "GLM-5.3",
    "GLM-5.3-Flash",
    "GLM-5.2",
    "GLM-5.1",
    "GLM-5",
    "GLM-5-Turbo",
    "GLM-5V-Turbo",
    "GLM-5.1-Highspeed",
];

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    uri: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

struct Step {
    status: StatusCode,
    bytes: Vec<u8>,
    location: Option<String>,
    streamed: bool,
    park_after_body: bool,
}

impl Step {
    fn json(body: Value) -> Self {
        Self::raw(StatusCode::OK, body.to_string().into_bytes())
    }

    fn raw(status: StatusCode, bytes: Vec<u8>) -> Self {
        Self {
            status,
            bytes,
            location: None,
            streamed: false,
            park_after_body: false,
        }
    }

    fn streaming(mut self, park_after_body: bool) -> Self {
        self.streamed = true;
        self.park_after_body = park_after_body;
        self
    }
}

#[derive(Default)]
struct Script {
    steps: Mutex<VecDeque<Step>>,
    seen: Mutex<Vec<Seen>>,
}

struct Mock {
    base: String,
    script: Arc<Script>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Mock {
    async fn start(steps: Vec<Step>) -> Self {
        async fn serve(State(script): State<Arc<Script>>, request: IncomingRequest) -> Response {
            let (parts, body) = request.into_parts();
            let bytes = to_bytes(body, 1 << 20).await.unwrap();
            script.seen.lock().unwrap().push(Seen {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                headers: parts.headers,
                body: bytes.to_vec(),
            });
            let step = script.steps.lock().unwrap().pop_front().unwrap_or_else(|| {
                Step::raw(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    b"unexpected loopback request".to_vec(),
                )
            });
            let mut response = Response::builder()
                .status(step.status)
                .header("content-type", "application/json");
            if let Some(location) = step.location {
                response = response.header("location", location);
            }
            let body = if step.streamed {
                // Unknown stream length forces chunked HTTP; the parked tail never sends EOF.
                let chunks: Vec<Result<Bytes, Infallible>> = step
                    .bytes
                    .chunks(16 << 10)
                    .map(|chunk| Ok(Bytes::copy_from_slice(chunk)))
                    .collect();
                let tail = stream::unfold(step.park_after_body, |parked| async move {
                    if parked {
                        std::future::pending::<()>().await;
                    }
                    None::<(Result<Bytes, Infallible>, bool)>
                });
                Body::from_stream(stream::iter(chunks).chain(tail))
            } else {
                Body::from(step.bytes)
            };
            response.body(body).unwrap()
        }

        let script = Arc::new(Script {
            steps: Mutex::new(steps.into()),
            ..Script::default()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(serve).with_state(script.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base, script, task }
    }

    fn configs(&self) -> String {
        format!("{}{CONFIGS}", self.base)
    }

    fn seen(&self) -> Vec<Seen> {
        self.script.seen.lock().unwrap().clone()
    }
}

struct Reply {
    status: StatusCode,
    body: String,
}

impl Reply {
    fn expect_json(&self, status: StatusCode, body: Value) {
        assert_eq!(self.status, status, "body={}", self.body);
        assert_eq!(self.json(), body);
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).expect("response must be JSON")
    }

    fn expect_error(&self, status: StatusCode) {
        assert_eq!(self.status, status, "body={}", self.body);
        let body = self.json();
        assert!(body.is_object(), "body={body}");
        assert_ne!(body["success"], json!(true), "body={body}");
        // Error wording is not part of the packet contract; existing handlers use both shapes.
        let message = body["error"]["message"]
            .as_str()
            .or_else(|| body["message"].as_str());
        assert!(
            message.is_some_and(|message| !message.is_empty()),
            "body={body}"
        );
    }
}

struct Fixture {
    state: Arc<AppState>,
    app: Router,
}

impl Fixture {
    fn new(configs: String, cache: Option<&str>) -> Self {
        let db = store::open(":memory:");
        if let Some(cache) = cache {
            store::set_setting(&db, "model_catalog", cache);
        }
        let account = AccountView {
            id: 1,
            email: "catalog@example.test".into(),
            provider: "zai".into(),
            enabled: true,
            status: "active".into(),
            zcode_jwt: JWT.into(),
            api_key: ACCOUNT_KEY.into(),
            ..AccountView::default()
        };
        store::upsert_account(&db, &account, JWT, ACCOUNT_KEY);
        let mut state = AppState::from_db(
            ROOT.into(),
            UpstreamUrls {
                zai: "http://127.0.0.1:1/unused".into(),
                zai_fallback: "http://127.0.0.1:1/unused".into(),
            },
            db,
        );
        state.install_urls.client_configs = configs;
        state.management.app_version = VERSION.into();
        state
            .sessions
            .lock()
            .unwrap()
            .insert(SESSION.into(), now_secs() + 3600);
        state.sessions.lock().unwrap().insert(EXPIRED.into(), 0);
        let state = Arc::new(state);
        Self {
            app: build_router(state.clone()),
            state,
        }
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        session: Option<&str>,
        origin: Option<&str>,
        deadline: Duration,
    ) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", HOST)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {ROOT}"))
            .header("x-api-key", ROOT);
        if let Some(session) = session {
            request = request.header("cookie", format!("{SESSION_COOKIE}={session}"));
        }
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        tokio::time::timeout(deadline, async {
            let response = self
                .app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let bytes = to_bytes(response.into_body(), LIMIT + 1024).await.unwrap();
            Reply {
                status,
                body: String::from_utf8(bytes.to_vec()).unwrap(),
            }
        })
        .await
        .expect("catalog request exceeded the test deadline")
    }

    async fn get(&self, path: &str) -> Reply {
        self.send("GET", path, Some(SESSION), None, DEADLINE).await
    }

    async fn sync(&self) -> Reply {
        self.send(
            "POST",
            SYNC,
            Some(SESSION),
            Some("http://localhost:8787"),
            DEADLINE,
        )
        .await
    }

    fn assert_cache(&self, expected: Option<&str>) {
        assert_eq!(self.state.setting("model_catalog").as_deref(), expected);
        let db = self.state.db.lock().unwrap();
        let persisted = store::load_settings(&db, &self.state.vault).unwrap();
        assert_eq!(persisted.get("model_catalog").map(String::as_str), expected);
    }

    fn assert_persisted_models(&self, expected: &Value) {
        let raw = self
            .state
            .setting("model_catalog")
            .expect("cache must be published");
        self.assert_cache(Some(&raw));
        assert_eq!(serde_json::from_str::<Value>(&raw).unwrap(), *expected);
    }

    async fn assert_fixed_models(&self) {
        self.get("/api/models")
            .await
            .expect_json(StatusCode::OK, json!({"models": FIXED_IDS}));
        let reply = self.get("/v1/models").await;
        assert_eq!(reply.status, StatusCode::OK, "body={}", reply.body);
        let body = reply.json();
        assert_eq!(body["object"], json!("list"));
        let ids: Vec<&str> = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|model| model["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, FIXED_IDS);
    }
}

fn model(id: &str, name: &str, context: i64, priority: i64, vision: bool) -> Value {
    json!({"modelId": id, "name": name, "contextWindow": context,
        "priority": priority, "vision": vision})
}

fn old_models() -> Value {
    json!([model(
        "PUBLIC-old-model",
        "Old cached model",
        8192,
        2,
        false
    )])
}

fn envelope(models: Value) -> Value {
    json!({"code": 0, "msg": "ok", "data": {"builtinModels": models}})
}

fn padded_envelope(length: usize) -> Vec<u8> {
    let mut body = envelope(json!([{"modelId": "PUBLIC-boundary-model"}]))
        .to_string()
        .into_bytes();
    assert!(body.len() < length);
    body.resize(length, b' ');
    body
}

fn assert_wire(seen: &Seen) {
    assert_eq!(seen.method, "GET");
    assert!(seen.body.is_empty());
    let url = if seen.uri.starts_with("http://") {
        reqwest::Url::parse(&seen.uri).unwrap()
    } else {
        reqwest::Url::parse(&format!("http://localhost{}", seen.uri)).unwrap()
    };
    assert_eq!(url.path(), CONFIGS);
    let pairs: Vec<_> = url.query_pairs().into_owned().collect();
    assert_eq!(pairs.len(), 2, "query={pairs:?}");
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    };
    assert_eq!(
        pairs.into_iter().collect::<BTreeMap<_, _>>(),
        BTreeMap::from([("version".into(), VERSION.into()), ("os".into(), os.into())])
    );
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    };
    let os_category = if os == "win32" { "windows" } else { os };
    for (name, expected) in [
        ("user-agent", format!("ZCode/{VERSION}")),
        ("http-referer", "https://zcode.z.ai".into()),
        ("x-title", "Z Code@electron".into()),
        ("x-zcode-app-version", VERSION.into()),
        ("x-platform", format!("{os}-{arch}")),
        ("x-release-channel", "stable".into()),
        ("x-client-language", "zh-CN".into()),
        ("x-os-category", os_category.into()),
        ("content-type", "application/json".into()),
    ] {
        assert_eq!(
            seen.headers.get(name).unwrap().to_str().unwrap(),
            expected,
            "{name}"
        );
    }
    assert!(!seen.headers["x-client-timezone"]
        .to_str()
        .unwrap()
        .is_empty());
    let request_id = seen.headers["x-request-id"].to_str().unwrap();
    assert_eq!(request_id.len(), 36);
    for name in ["authorization", "x-api-key", "api-key", "cookie"] {
        assert!(
            !seen.headers.contains_key(name),
            "outbound {name} must be absent"
        );
    }
    for value in seen.headers.values() {
        let value = value.to_str().unwrap();
        for secret in [ROOT, SESSION, JWT, ACCOUNT_KEY] {
            assert!(
                !value.contains(secret),
                "outbound header leaked a fixture credential"
            );
        }
    }
}

#[tokio::test]
async fn catalog_get_returns_null_for_missing_or_malformed_cache_and_typed_arrays_for_valid_cache()
{
    for cache in [
        None,
        Some(""),
        Some("not JSON"),
        Some("["),
        Some("{}"),
        Some("null"),
        Some(r#"[{"modelId":7}]"#),
        Some(r#"[{"modelId":"valid"},{"modelId":"bad","vision":"yes"}]"#),
    ] {
        let f = Fixture::new("http://127.0.0.1:1/unused".into(), cache);
        f.get(CATALOG)
            .await
            .expect_json(StatusCode::OK, json!({"models": null}));
        f.assert_cache(cache);
    }
    for models in [json!([]), old_models()] {
        let cache = models.to_string();
        let f = Fixture::new("http://127.0.0.1:1/unused".into(), Some(&cache));
        f.get(CATALOG)
            .await
            .expect_json(StatusCode::OK, json!({"models": models}));
        f.assert_cache(Some(&cache));
    }
}

#[tokio::test]
async fn sync_prefers_builtins_defaults_fields_deduplicates_persists_and_keeps_fixed_model_ids() {
    let first = model("PUBLIC-z-model", "First wins", 131072, -3, true);
    let defaulted = model("PUBLIC-a-model", "", 0, 0, false);
    let expected = json!([first, defaulted]);
    let mock = Mock::start(vec![Step::json(json!({
        "code": 0, "msg": "ok", "data": {
            "builtinModels": [
                first,
                {"modelId": "", "name": "drop empty id"},
                {"name": "drop absent id"},
                {"modelId": "PUBLIC-z-model", "name": "Duplicate loses", "vision": false},
                {"modelId": "PUBLIC-a-model", "ignoredFutureField": "not cached"}
            ],
            "providers": [{"id": "ignored", "models": [{"modelId": "PUBLIC-provider-only"}]}]
        }
    }))])
    .await;
    let old = old_models().to_string();
    let f = Fixture::new(mock.configs(), Some(&old));
    f.assert_fixed_models().await;
    f.sync().await.expect_json(
        StatusCode::OK,
        json!({"success": true, "models": expected, "total": 2}),
    );
    f.assert_persisted_models(&expected);
    f.get(CATALOG)
        .await
        .expect_json(StatusCode::OK, json!({"models": expected}));
    f.assert_fixed_models().await;
    let seen = mock.seen();
    assert_eq!(seen.len(), 1);
    assert_wire(&seen[0]);
}

#[tokio::test]
async fn sync_falls_back_to_providers_in_order_only_when_builtins_are_empty_or_missing() {
    let expected = json!([
        model("PUBLIC-provider-b", "First provider", 4096, 4, true),
        model("PUBLIC-provider-a", "", 0, 0, false),
        model("PUBLIC-provider-c", "", 0, 0, false)
    ]);
    let providers = json!([
        {"id": "p1", "baseUrl": "http://unused.invalid", "models": [
            expected[0], {"modelId": "PUBLIC-provider-a"}, {"modelId": ""}
        ]},
        {"id": "empty"},
        {"id": "p2", "models": [
            {"modelId": "PUBLIC-provider-b", "name": "Later duplicate"},
            {"modelId": "PUBLIC-provider-c"}
        ]}
    ]);
    let mut data_without_builtins = json!({"providers": providers});
    for builtins in [None, Some(json!([]))] {
        if let Some(builtins) = builtins {
            data_without_builtins["builtinModels"] = builtins;
        }
        let mock = Mock::start(vec![Step::json(
            json!({"code": 0, "data": data_without_builtins}),
        )])
        .await;
        let f = Fixture::new(mock.configs(), None);
        f.sync().await.expect_json(
            StatusCode::OK,
            json!({"success": true, "models": expected, "total": 3}),
        );
        f.assert_persisted_models(&expected);
        f.get(CATALOG)
            .await
            .expect_json(StatusCode::OK, json!({"models": expected}));
    }
}

#[tokio::test]
async fn sync_successfully_persists_an_empty_array_without_falling_back_after_filtering_builtins() {
    for data in [
        json!({}),
        json!({"builtinModels": [{"modelId": ""}],
            "providers": [{"models": [{"modelId": "PUBLIC-must-not-fallback"}]}]}),
    ] {
        let mock = Mock::start(vec![Step::json(json!({"code": 0, "data": data}))]).await;
        let old = old_models().to_string();
        let f = Fixture::new(mock.configs(), Some(&old));
        f.sync().await.expect_json(
            StatusCode::OK,
            json!({"success": true, "models": [], "total": 0}),
        );
        f.assert_persisted_models(&json!([]));
        f.get(CATALOG)
            .await
            .expect_json(StatusCode::OK, json!({"models": []}));
    }
}

#[tokio::test]
async fn upstream_http_json_business_and_model_type_failures_return_502_and_retain_cache() {
    let good = envelope(json!([{"modelId": "PUBLIC-new-model"}]));
    let mut steps = vec![
        Step::raw(StatusCode::UNAUTHORIZED, good.to_string().into_bytes()),
        Step::raw(
            StatusCode::SERVICE_UNAVAILABLE,
            good.to_string().into_bytes(),
        ),
        Step::raw(StatusCode::OK, b"{not-json".to_vec()),
        Step::json(json!({"code": 7, "msg": "PUBLIC business failure", "data": good["data"]})),
        Step::json(json!({"code": 200, "data": good["data"]})),
        Step::json(json!({"code": "0", "data": good["data"]})),
    ];
    for invalid_model in [
        json!({"modelId": 1}),
        json!({"modelId": "m", "name": 1}),
        json!({"modelId": "m", "contextWindow": "4096"}),
        json!({"modelId": "m", "priority": true}),
        json!({"modelId": "m", "vision": "true"}),
    ] {
        steps.push(Step::json(envelope(json!([invalid_model]))));
    }
    let count = steps.len();
    let mock = Mock::start(steps).await;
    let old = old_models().to_string();
    let f = Fixture::new(mock.configs(), Some(&old));
    for case in 0..count {
        let reply = f.sync().await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_GATEWAY,
            "case={case}, body={}",
            reply.body
        );
        reply.expect_error(StatusCode::BAD_GATEWAY);
        f.assert_cache(Some(&old));
        f.get(CATALOG)
            .await
            .expect_json(StatusCode::OK, json!({"models": old_models()}));
    }
    assert_eq!(mock.seen().len(), count);
}

#[tokio::test]
async fn sync_storage_failure_returns_500_without_publishing_or_replacing_the_cache() {
    for previous in [None, Some(old_models().to_string())] {
        let mock = Mock::start(vec![Step::json(envelope(
            json!([{"modelId": "PUBLIC-new-model"}]),
        ))])
        .await;
        let f = Fixture::new(mock.configs(), previous.as_deref());
        f.state
            .db
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_catalog_insert BEFORE INSERT ON settings
             WHEN NEW.key = 'model_catalog'
             BEGIN SELECT RAISE(ABORT, 'PUBLIC injected catalog failure'); END;
             CREATE TRIGGER fail_catalog_update BEFORE UPDATE ON settings
             WHEN NEW.key = 'model_catalog'
             BEGIN SELECT RAISE(ABORT, 'PUBLIC injected catalog failure'); END;",
            )
            .unwrap();
        f.sync()
            .await
            .expect_error(StatusCode::INTERNAL_SERVER_ERROR);
        f.assert_cache(previous.as_deref());
        let expected = if previous.is_some() {
            old_models()
        } else {
            Value::Null
        };
        f.get(CATALOG)
            .await
            .expect_json(StatusCode::OK, json!({"models": expected}));
        assert_eq!(mock.seen().len(), 1);
    }
}

#[tokio::test]
async fn catalog_and_sync_require_sessions_and_sync_rejects_cross_origin_before_fetching() {
    let mock = Mock::start(vec![]).await;
    let old = old_models().to_string();
    let f = Fixture::new(mock.configs(), Some(&old));
    for (method, path) in [("GET", CATALOG), ("POST", SYNC)] {
        for session in [None, Some(EXPIRED)] {
            f.send(
                method,
                path,
                session,
                Some("http://localhost:8787"),
                DEADLINE,
            )
            .await
            .expect_json(
                StatusCode::UNAUTHORIZED,
                json!({"error": {"message": "unauthorized", "type": "api_error"}}),
            );
        }
    }
    f.send(
        "POST",
        SYNC,
        Some(SESSION),
        Some("http://localhost:8788"),
        DEADLINE,
    )
    .await
    .expect_json(
        StatusCode::FORBIDDEN,
        json!({"success": false, "message": "cross-origin request rejected"}),
    );
    f.send(
        "GET",
        CATALOG,
        Some(SESSION),
        Some("https://foreign.example.invalid"),
        DEADLINE,
    )
    .await
    .expect_json(StatusCode::OK, json!({"models": old_models()}));
    assert!(
        mock.seen().is_empty(),
        "rejected requests must not fetch configs"
    );
    f.assert_cache(Some(&old));
}

#[tokio::test]
async fn sync_refuses_redirects_and_retains_cache_without_contacting_the_target() {
    let target = Mock::start(vec![Step::json(envelope(
        json!([{"modelId": "PUBLIC-redirect-model"}]),
    ))])
    .await;
    let mut redirect = Step::raw(StatusCode::FOUND, Vec::new());
    redirect.location = Some(target.configs());
    let source = Mock::start(vec![redirect]).await;
    let old = old_models().to_string();
    let f = Fixture::new(source.configs(), Some(&old));
    f.sync().await.expect_error(StatusCode::BAD_GATEWAY);
    f.assert_cache(Some(&old));
    f.get(CATALOG)
        .await
        .expect_json(StatusCode::OK, json!({"models": old_models()}));
    assert_eq!(source.seen().len(), 1);
    assert!(
        target.seen().is_empty(),
        "redirect target must never be requested"
    );
}

#[tokio::test]
async fn sync_accepts_exactly_four_mib_with_or_without_content_length_and_rejects_excess_before_eof(
) {
    let expected = json!([model("PUBLIC-boundary-model", "", 0, 0, false)]);
    for step in [
        Step::raw(StatusCode::OK, padded_envelope(LIMIT)),
        Step::raw(StatusCode::OK, padded_envelope(LIMIT)).streaming(false),
    ] {
        let mock = Mock::start(vec![step]).await;
        let f = Fixture::new(mock.configs(), None);
        f.sync().await.expect_json(
            StatusCode::OK,
            json!({"success": true, "models": expected, "total": 1}),
        );
        f.assert_persisted_models(&expected);
    }
    for step in [
        Step::raw(StatusCode::OK, padded_envelope(LIMIT + 1)),
        Step::raw(StatusCode::OK, padded_envelope(LIMIT + 1)).streaming(true),
    ] {
        let mock = Mock::start(vec![step]).await;
        let old = old_models().to_string();
        let f = Fixture::new(mock.configs(), Some(&old));
        // The streamed case is valid JSON plus whitespace and never ends, so reading to EOF is a failure.
        f.sync().await.expect_error(StatusCode::BAD_GATEWAY);
        f.assert_cache(Some(&old));
        f.get(CATALOG)
            .await
            .expect_json(StatusCode::OK, json!({"models": old_models()}));
    }
}

#[tokio::test]
async fn sync_uses_global_egress_and_an_enabled_default_node_takes_precedence() {
    for default_node in [false, true] {
        let expected = json!([model("PUBLIC-proxied-model", "", 0, 0, false)]);
        let proxy_response = || Step::json(envelope(expected.clone()));
        let origin = Mock::start(vec![]).await;
        let global = Mock::start(vec![proxy_response()]).await;
        let default = Mock::start(vec![proxy_response()]).await;
        let f = Fixture::new(origin.configs(), None);
        f.state
            .persist_settings(&[("upstream_proxy", &global.base)])
            .unwrap();
        if default_node {
            let port = reqwest::Url::parse(&default.base).unwrap().port().unwrap();
            f.state
                .db
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO proxy_nodes(name, type, host, port, is_default, enabled)
                 VALUES('PUBLIC catalog default', 'http', '127.0.0.1', ?1, 1, 1)",
                    [i64::from(port)],
                )
                .unwrap();
        }
        // Missing Origin is valid for non-browser callers, just as for other management mutations.
        f.send("POST", SYNC, Some(SESSION), None, DEADLINE)
            .await
            .expect_json(
                StatusCode::OK,
                json!({"success": true, "models": expected, "total": 1}),
            );
        f.assert_persisted_models(&expected);
        assert!(
            origin.seen().is_empty(),
            "catalog fetch bypassed the selected proxy"
        );
        let (selected, unused) = if default_node {
            (&default, &global)
        } else {
            (&global, &default)
        };
        assert!(
            unused.seen().is_empty(),
            "unselected proxy received a request"
        );
        let seen = selected.seen();
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0].uri.starts_with(&origin.base),
            "forward proxy must receive the original absolute URI"
        );
        assert_wire(&seen[0]);
    }
}

#[tokio::test]
async fn sync_times_out_a_stalled_body_after_twenty_seconds_and_retains_cache() {
    let mock = Mock::start(vec![Step::raw(StatusCode::OK, Vec::new()).streaming(true)]).await;
    let old = old_models().to_string();
    let f = Fixture::new(mock.configs(), Some(&old));
    let started = Instant::now();
    let reply = f
        .send("POST", SYNC, Some(SESSION), None, Duration::from_secs(24))
        .await;
    reply.expect_error(StatusCode::BAD_GATEWAY);
    // Allow scheduler jitter without accepting the existing management client's shorter deadlines.
    assert!(
        started.elapsed() >= Duration::from_secs(19),
        "catalog timeout fired before 20s"
    );
    assert_eq!(mock.seen().len(), 1);
    f.assert_cache(Some(&old));
    f.get(CATALOG)
        .await
        .expect_json(StatusCode::OK, json!({"models": old_models()}));
}

#[tokio::test]
async fn sync_accepts_null_envelope_collections_and_data_as_go_zero_values() {
    let fallback = json!([model("PUBLIC-null-fallback", "", 0, 0, false)]);
    for (case, data, expected) in [
        (
            "null builtins use provider fallback",
            json!({
                "builtinModels": null,
                "providers": [{"models": [{"modelId": "PUBLIC-null-fallback"}]}]
            }),
            fallback,
        ),
        ("null providers", json!({"providers": null}), json!([])),
        (
            "null provider models",
            json!({"providers": [{"models": null}]}),
            json!([]),
        ),
        ("null data", Value::Null, json!([])),
    ] {
        let mock = Mock::start(vec![Step::json(json!({"code": 0, "data": data}))]).await;
        let old = old_models().to_string();
        let f = Fixture::new(mock.configs(), Some(&old));
        let reply = f.sync().await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "case={case}, body={}",
            reply.body
        );
        reply.expect_json(
            StatusCode::OK,
            json!({"success": true, "models": expected, "total": expected.as_array().unwrap().len()}),
        );
        f.assert_persisted_models(&expected);
        f.get(CATALOG)
            .await
            .expect_json(StatusCode::OK, json!({"models": expected}));
        assert_eq!(mock.seen().len(), 1, "case={case}");
    }
}
