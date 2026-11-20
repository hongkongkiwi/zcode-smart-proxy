//! Go-parity regressions for the plan-admin packet: plan CRUD on /api/plans
//! and the history readers /api/claim-records and /api/plan-runs (Go root
//! api_handlers.go routes 92-98, handlers 692-860; scheduler.go 599-671 cron
//! validation; database_ops.go 15-91 CRUD, 140-167 records, 691-711 runs).
//! Blackbox through the public router only. SQL seeding is used only for
//! reader fixtures whose tables the routes' own schema must create: seeding
//! is skipped while a table is absent so the baseline stays red on the
//! missing route instead of a seeding error.

use std::sync::Arc;

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
};

const SESSION: &str = "PUBLIC-plan-admin-session";
const PLAN_JSON: &str = r#"{"plan_name":"auth-probe","cron_expr":"0 9 * * *"}"#;

fn fixture() -> Arc<AppState> {
    let state = Arc::new(AppState::new(
        String::new(),
        UpstreamUrls {
            zai: "http://127.0.0.1:1/unused-relay".into(),
            zai_fallback: "http://127.0.0.1:1/unused-paid-relay".into(),
        },
    ));
    state
        .sessions
        .lock()
        .unwrap()
        .insert(SESSION.into(), now_secs() + 3600);
    state
}

async fn call(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<&str>,
    authenticated: bool,
    origin: &str,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "localhost:8080")
        .header("origin", origin);
    if authenticated {
        builder = builder.header("cookie", format!("{SESSION_COOKIE}={SESSION}"));
    }
    let request = match body {
        Some(payload) => builder
            .header("content-type", "application/json")
            .body(Body::from(payload.to_owned()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = build_router(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn authed(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<&str>,
) -> (StatusCode, Value) {
    call(state, method, uri, body, true, "http://localhost:8080").await
}

async fn create_plan(state: &Arc<AppState>, body: &Value) -> i64 {
    let (status, response) = authed(state, "POST", "/api/plans", Some(&body.to_string())).await;
    assert_eq!(status, StatusCode::OK, "POST /api/plans: {response}");
    response["id"]
        .as_i64()
        .unwrap_or_else(|| panic!("POST /api/plans must return an id: {response}"))
}

fn valid_plan_body(name: &str) -> Value {
    json!({
        "plan_name": name,
        "cron_expr": "0 9 * * *",
        "is_active": true,
        "task_type": "claim",
        "target_type": "all_accounts",
        "account_id": 0,
        "account_group": "",
        "auto_pick": true,
        "delay_seconds": 45,
    })
}

fn table_exists(state: &AppState, table: &str) -> bool {
    state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
            [table],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false)
}

fn plan_count(plans: &Value) -> usize {
    plans["plans"].as_array().map_or(0, Vec::len)
}

fn find_plan<'a>(plans: &'a Value, name: &str) -> Option<&'a Value> {
    plans["plans"]
        .as_array()?
        .iter()
        .find(|plan| plan["plan_name"] == name)
}

fn seed_claim_records(state: &AppState) {
    let rows = [
        (1, "acct-one-a"),
        (1, "acct-one-b"),
        (1, "acct-one-c"),
        (2, "acct-two-a"),
        (2, "acct-two-b"),
    ];
    let mut sql = String::new();
    for (account, tag) in rows {
        sql.push_str(&format!(
            "INSERT INTO claim_records (account_id, email, task_type, plan_id, plan_name, \
             success, code, message) VALUES ({account}, '{tag}@example.test', 'claim', '', \
             'seed', 1, 0, 'seed-{tag}');"
        ));
    }
    state
        .db
        .lock()
        .unwrap()
        .execute_batch(&sql)
        .expect("seed claim_records (table exists in the current migration)");
}

fn seed_plan_runs(state: &AppState, rows: i64) {
    if !table_exists(state, "plan_run_records") {
        return;
    }
    let mut sql = String::new();
    for i in 1..=rows {
        sql.push_str(&format!(
            "INSERT INTO plan_run_records (plan_id, plan_name, task_type, target_type, \
             account_id, run_at, status, message, total, success_count, fail_count, \
             duration_ms) VALUES ({i}, 'seed-plan', 'claim', 'all_accounts', 0, \
             '2026-11-19 08:00:00', 'ok', 'seed-{i}', 1, 1, 0, 5);"
        ));
    }
    state
        .db
        .lock()
        .unwrap()
        .execute_batch(&sql)
        .expect("seed plan_run_records");
}

fn install_plan_write_failure_triggers(state: &AppState) {
    if !table_exists(state, "claim_plans") {
        return;
    }
    state
        .db
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER plan_regr_fail_insert BEFORE INSERT ON claim_plans
             BEGIN SELECT RAISE(ABORT, 'regression seeded insert failure'); END;
             CREATE TRIGGER plan_regr_fail_update BEFORE UPDATE ON claim_plans
             BEGIN SELECT RAISE(ABORT, 'regression seeded update failure'); END;",
        )
        .expect("install plan write failure triggers");
}

fn drop_plan_write_failure_triggers(state: &AppState) {
    let _ = state.db.lock().unwrap().execute_batch(
        "DROP TRIGGER IF EXISTS plan_regr_fail_insert;
         DROP TRIGGER IF EXISTS plan_regr_fail_update;",
    );
}

/// Go handler emits "2006-01-02 15:04" for next_run_at (api_handlers.go:710).
fn is_go_minute_stamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 16
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b' '
        && bytes[13] == b':'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, &c)| matches!(i, 4 | 7 | 10 | 13) || c.is_ascii_digit())
}

#[tokio::test]
async fn plan_admin_routes_require_session_and_same_origin_for_writes() {
    let state = fixture();
    let routes: &[(&str, &str, Option<&str>)] = &[
        ("GET", "/api/plans", None),
        ("GET", "/api/plan-runs", None),
        ("GET", "/api/claim-records", None),
        ("POST", "/api/plans", Some(PLAN_JSON)),
        ("PUT", "/api/plans/1", Some(PLAN_JSON)),
        ("DELETE", "/api/plans/1", None),
    ];
    let mut failures = Vec::new();
    for &(method, uri, body) in routes {
        let (status, _) = call(&state, method, uri, body, false, "http://localhost:8080").await;
        if status != StatusCode::UNAUTHORIZED {
            failures.push(format!(
                "{method} {uri}: no session returned {status}, expected 401"
            ));
        }
        if method != "GET" {
            let (status, _) = call(
                &state,
                method,
                uri,
                body,
                true,
                "https://untrusted.example.invalid",
            )
            .await;
            if status != StatusCode::FORBIDDEN {
                failures.push(format!(
                    "{method} {uri}: cross-origin returned {status}, expected 403"
                ));
            }
        }
    }
    // Reads are exempt from the origin gate (Go auth.go Middleware).
    let (status, body) = call(
        &state,
        "GET",
        "/api/plans",
        None,
        true,
        "https://untrusted.example.invalid",
    )
    .await;
    if status != StatusCode::OK {
        failures.push(format!(
            "GET /api/plans cross-origin with session returned {status} {body}, expected 200"
        ));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn plan_save_rejects_invalid_five_field_cron_without_persisting() {
    let state = fixture();
    const VALID: &[&str] = &[
        "0 9 * * *",
        "* * * * *",
        "*/15 * * * *",
        "0 0-23 1,15 */2 1-5",
        " 0 9 * * * ",
    ];
    for (i, cron) in VALID.iter().enumerate() {
        let mut body = valid_plan_body(&format!("cron-valid-{i}"));
        body["cron_expr"] = json!(cron);
        create_plan(&state, &body).await;
    }
    const INVALID: &[&str] = &[
        "",
        "0 9 * *",
        "0 9 * * * *",
        "60 * * * *",
        "0 24 * * *",
        "0 9 0 * *",
        "0 9 32 * *",
        "0 9 * 0 *",
        "0 9 * 13 *",
        "0 9 * * 7",
        "10-5 * * * *",
        "1-70 * * * *",
        "*/0 * * * *",
        "*/x * * * *",
        "1,,5 * * * *",
        "abc * * * *",
    ];
    let mut failures = Vec::new();
    for (i, cron) in INVALID.iter().enumerate() {
        let mut body = valid_plan_body(&format!("cron-invalid-{i}"));
        body["cron_expr"] = json!(cron);
        let (status, response) =
            authed(&state, "POST", "/api/plans", Some(&body.to_string())).await;
        if status != StatusCode::BAD_REQUEST {
            failures.push(format!(
                "cron {cron:?}: got {status} {response}, expected 400"
            ));
        }
    }
    let (status, response) = authed(&state, "POST", "/api/plans", Some("{not json")).await;
    if status != StatusCode::BAD_REQUEST {
        failures.push(format!(
            "malformed body: got {status} {response}, expected 400"
        ));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));

    let (status, list) = authed(&state, "GET", "/api/plans", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        plan_count(&list),
        VALID.len(),
        "only the valid crons may persist: {list}"
    );
}

#[tokio::test]
async fn plan_save_task_and_target_semantics_match_go_defaults_and_rejections() {
    let state = fixture();

    // Omitted task_type defaults to claim; detect/activate accepted.
    create_plan(
        &state,
        &json!({"plan_name": "defaults-probe", "cron_expr": "0 9 * * *"}),
    )
    .await;
    let mut detect = valid_plan_body("detect-probe");
    detect["task_type"] = json!("detect");
    create_plan(&state, &detect).await;
    let mut activate = valid_plan_body("activate-probe");
    activate["task_type"] = json!("activate");
    create_plan(&state, &activate).await;

    // Omitted target_type defaults to all_accounts; single/group accepted.
    // Go does not require the account to exist at save time, and a group with
    // an empty name saves (resolution failure is a later, out-of-scope path).
    let mut single = valid_plan_body("single-probe");
    single["target_type"] = json!("single_account");
    single["account_id"] = json!(42);
    create_plan(&state, &single).await;
    let mut group = valid_plan_body("group-probe");
    group["target_type"] = json!("group");
    group["account_group"] = json!("weekend");
    create_plan(&state, &group).await;
    let mut empty_group = valid_plan_body("group-empty-probe");
    empty_group["target_type"] = json!("group");
    create_plan(&state, &empty_group).await;

    let (status, list) = authed(&state, "GET", "/api/plans", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(plan_count(&list), 6, "six accepted saves: {list}");
    let defaults = find_plan(&list, "defaults-probe").expect("defaults row listed");
    assert_eq!(defaults["task_type"], "claim");
    assert_eq!(defaults["target_type"], "all_accounts");
    let single = find_plan(&list, "single-probe").expect("single row listed");
    assert_eq!(single["target_type"], "single_account");
    assert_eq!(single["account_id"].as_i64(), Some(42));
    let group = find_plan(&list, "group-probe").expect("group row listed");
    assert_eq!(group["target_type"], "group");
    assert_eq!(group["account_group"], "weekend");

    let mut rejected: Vec<Value> = Vec::new();
    let mut reset = valid_plan_body("reset-probe");
    reset["task_type"] = json!("reset");
    rejected.push(reset);
    let mut bogus_task = valid_plan_body("bogus-task-probe");
    bogus_task["task_type"] = json!("nonsense");
    rejected.push(bogus_task);
    let mut bad_target = valid_plan_body("bad-target-probe");
    bad_target["target_type"] = json!("all");
    rejected.push(bad_target);
    let mut near_miss_target = valid_plan_body("near-miss-target-probe");
    near_miss_target["target_type"] = json!("single");
    rejected.push(near_miss_target);
    let mut missing_id = valid_plan_body("missing-id-probe");
    missing_id["target_type"] = json!("single_account");
    missing_id["account_id"] = json!(0);
    rejected.push(missing_id);
    let mut negative_id = valid_plan_body("negative-id-probe");
    negative_id["target_type"] = json!("single_account");
    negative_id["account_id"] = json!(-5);
    rejected.push(negative_id);

    let mut failures = Vec::new();
    for body in &rejected {
        let (status, response) =
            authed(&state, "POST", "/api/plans", Some(&body.to_string())).await;
        let name = body["plan_name"].as_str().unwrap_or("?");
        if status != StatusCode::BAD_REQUEST {
            failures.push(format!("{name}: got {status} {response}, expected 400"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));

    let (status, list) = authed(&state, "GET", "/api/plans", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        plan_count(&list),
        6,
        "rejected saves must not persist: {list}"
    );
}

#[tokio::test]
async fn plan_list_round_trips_created_fields_and_next_run_stamp() {
    let state = fixture();
    let (status, empty) = authed(&state, "GET", "/api/plans", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        empty["plans"].as_array().is_some_and(Vec::is_empty),
        "Go emits an empty plans array, not null: {empty}"
    );

    let id = create_plan(&state, &valid_plan_body("shape-probe")).await;
    let (status, list) = authed(&state, "GET", "/api/plans", None).await;
    assert_eq!(status, StatusCode::OK);
    let plan = find_plan(&list, "shape-probe").expect("created plan listed");
    assert_eq!(plan["id"].as_i64(), Some(id));
    assert_eq!(plan["cron_expr"], "0 9 * * *");
    assert_eq!(plan["is_active"], true);
    assert_eq!(plan["target_type"], "all_accounts");
    assert_eq!(plan["account_id"].as_i64(), Some(0));
    assert_eq!(plan["account_group"], "");
    assert_eq!(plan["task_type"], "claim");
    assert_eq!(plan["auto_pick"], true);
    assert_eq!(plan["delay_seconds"].as_i64(), Some(45));
    for key in [
        "last_run_at",
        "last_run_status",
        "last_run_msg",
        "created_at",
        "updated_at",
    ] {
        assert!(plan[key].is_string(), "{key} must be a string: {plan}");
    }
    let next = plan["next_run_at"]
        .as_str()
        .unwrap_or_else(|| panic!("valid daily cron must carry next_run_at: {plan}"))
        .to_owned();
    assert!(
        is_go_minute_stamp(&next),
        "next_run_at uses Go's YYYY-MM-DD HH:MM stamp: {next}"
    );
    assert!(
        next.ends_with(" 09:00"),
        "a 0 9 * * * plan must next fire at 09:00: {next}"
    );
}

#[tokio::test]
async fn plan_update_and_delete_follow_go_path_id_semantics() {
    let state = fixture();
    let id = create_plan(&state, &valid_plan_body("update-probe")).await;

    let mut rename = valid_plan_body("renamed-probe");
    rename["cron_expr"] = json!("*/15 * * * *");
    rename["task_type"] = json!("detect");
    rename["target_type"] = json!("single_account");
    rename["account_id"] = json!(7);
    rename["auto_pick"] = json!(false);
    rename["delay_seconds"] = json!(11);
    let (status, response) = authed(
        &state,
        "PUT",
        &format!("/api/plans/{id}"),
        Some(&rename.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PUT existing plan: {response}");
    assert_eq!(response["id"].as_i64(), Some(id));

    let (status, list) = authed(&state, "GET", "/api/plans", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(plan_count(&list), 1, "PUT must not create rows: {list}");
    let plan = find_plan(&list, "renamed-probe").expect("renamed plan listed");
    assert_eq!(plan["id"].as_i64(), Some(id));
    assert_eq!(plan["cron_expr"], "*/15 * * * *");
    assert_eq!(plan["task_type"], "detect");
    assert_eq!(plan["target_type"], "single_account");
    assert_eq!(plan["account_id"].as_i64(), Some(7));
    assert_eq!(plan["auto_pick"], false);
    assert_eq!(plan["delay_seconds"].as_i64(), Some(11));

    // The path id wins over a body id (Go sets p.ID from the path).
    let mut hijack = valid_plan_body("path-id-wins");
    hijack["id"] = json!(id + 5000);
    let (status, response) = authed(
        &state,
        "PUT",
        &format!("/api/plans/{id}"),
        Some(&hijack.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PUT with stray body id: {response}");
    assert_eq!(response["id"].as_i64(), Some(id));
    let (status, list) = authed(&state, "GET", "/api/plans", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(plan_count(&list), 1, "body id must not create rows: {list}");
    assert!(find_plan(&list, "path-id-wins").is_some());

    // PUT to a missing id is a real 404, not a silent zero-row update.
    let ghost = valid_plan_body("ghost-probe");
    let (status, response) = authed(
        &state,
        "PUT",
        &format!("/api/plans/{}", id + 5000),
        Some(&ghost.to_string()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "PUT missing plan: {response}"
    );

    let (status, _) = authed(
        &state,
        "PUT",
        "/api/plans/not-an-id",
        Some(&valid_plan_body("bad-path").to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Validation runs before the write: an invalid cron leaves the row intact.
    let mut bad = valid_plan_body("must-not-persist");
    bad["cron_expr"] = json!("99 * * * *");
    let (status, _) = authed(
        &state,
        "PUT",
        &format!("/api/plans/{id}"),
        Some(&bad.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, list) = authed(&state, "GET", "/api/plans", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(plan_count(&list), 1, "invalid PUT must not persist: {list}");
    assert!(find_plan(&list, "path-id-wins").is_some());

    let (status, response) = authed(&state, "DELETE", &format!("/api/plans/{id}"), None).await;
    assert_eq!(status, StatusCode::OK, "DELETE existing plan: {response}");
    assert_eq!(response["success"], true);
    let (status, list) = authed(&state, "GET", "/api/plans", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(plan_count(&list), 0, "deleted plan must disappear: {list}");

    // Go's DeleteClaimPlan is a bare DELETE: a missing id still succeeds.
    let (status, response) = authed(&state, "DELETE", &format!("/api/plans/{id}"), None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "deleting a missing plan is 200 in Go: {response}"
    );

    let (status, _) = authed(&state, "DELETE", "/api/plans/not-an-id", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn plan_post_body_id_cannot_overwrite_existing_plan() {
    let state = fixture();
    let id = create_plan(&state, &valid_plan_body("original-name")).await;

    let mut overwrite = valid_plan_body("hijack-name");
    overwrite["id"] = json!(id);
    overwrite["cron_expr"] = json!("*/5 * * * *");
    let (status, response) =
        authed(&state, "POST", "/api/plans", Some(&overwrite.to_string())).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "POST with a body id must still create: {response}"
    );
    let new_id = response["id"]
        .as_i64()
        .unwrap_or_else(|| panic!("POST must return the new id: {response}"));
    assert_ne!(new_id, id, "the body id must be ignored on POST");

    let (status, list) = authed(&state, "GET", "/api/plans", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(plan_count(&list), 2, "POST creates a second row: {list}");
    assert_eq!(
        find_plan(&list, "original-name").expect("original row intact")["id"].as_i64(),
        Some(id)
    );
    assert_eq!(
        find_plan(&list, "hijack-name").expect("new row listed")["id"].as_i64(),
        Some(new_id)
    );
}

#[tokio::test]
async fn plan_persist_failure_returns_server_error_without_state_drift() {
    let state = fixture();
    let id = create_plan(&state, &valid_plan_body("stable-plan")).await;
    install_plan_write_failure_triggers(&state);

    let (status, response) = authed(
        &state,
        "POST",
        "/api/plans",
        Some(&valid_plan_body("must-not-exist").to_string()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "failed insert must surface 500: {response}"
    );

    let (status, response) = authed(
        &state,
        "PUT",
        &format!("/api/plans/{id}"),
        Some(&valid_plan_body("must-not-rename").to_string()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "failed update must surface 500: {response}"
    );

    drop_plan_write_failure_triggers(&state);
    let (status, list) = authed(&state, "GET", "/api/plans", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        plan_count(&list),
        1,
        "failed writes must leave no partial rows: {list}"
    );
    assert!(find_plan(&list, "stable-plan").is_some());
    assert!(find_plan(&list, "must-not-exist").is_none());
    assert!(find_plan(&list, "must-not-rename").is_none());
}

#[tokio::test]
async fn claim_records_reader_enforces_account_filter_and_bounded_limit() {
    let state = fixture();
    seed_claim_records(&state);

    let (status, body) = authed(&state, "GET", "/api/claim-records", None).await;
    assert_eq!(status, StatusCode::OK, "default listing: {body}");
    let records = body["records"].as_array().expect("records array");
    assert_eq!(records.len(), 5);
    assert!(records
        .iter()
        .all(|record| matches!(record["account_id"].as_i64(), Some(1 | 2))));

    let (status, body) = authed(&state, "GET", "/api/claim-records?account_id=1", None).await;
    assert_eq!(status, StatusCode::OK, "account filter: {body}");
    let records = body["records"].as_array().expect("records array");
    assert_eq!(records.len(), 3);
    assert!(records
        .iter()
        .all(|record| record["account_id"].as_i64() == Some(1)));

    let (status, body) = authed(&state, "GET", "/api/claim-records?account_id=2", None).await;
    assert_eq!(status, StatusCode::OK, "second account filter: {body}");
    let records = body["records"].as_array().expect("records array");
    assert_eq!(records.len(), 2);
    assert!(records
        .iter()
        .all(|record| record["account_id"].as_i64() == Some(2)));

    // A present account_id must be a positive integer: scripts must not
    // silently receive the unfiltered list (Go api_handlers.go:843-851).
    for value in ["0", "-1", "abc", "1.5"] {
        let (status, body) = authed(
            &state,
            "GET",
            &format!("/api/claim-records?account_id={value}"),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "account_id={value}: {body}"
        );
    }

    // An empty value counts as absent (Go checks v != "").
    let (status, body) = authed(&state, "GET", "/api/claim-records?account_id=", None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "empty account_id is unfiltered: {body}"
    );
    assert_eq!(body["records"].as_array().map_or(0, Vec::len), 5);

    // Limit parity with Go queryInt: respected, newest-first, non-positive
    // clamps to 1, and an unparseable value falls back to the default.
    let (status, body) = authed(&state, "GET", "/api/claim-records?limit=2", None).await;
    assert_eq!(status, StatusCode::OK, "limit=2: {body}");
    let records = body["records"].as_array().expect("records array");
    assert_eq!(records.len(), 2);
    let first = records[0]["id"].as_i64().expect("id");
    let second = records[1]["id"].as_i64().expect("id");
    assert!(
        first > second,
        "records are newest-first: {first} !> {second}"
    );

    for value in ["0", "-5"] {
        let (status, body) = authed(
            &state,
            "GET",
            &format!("/api/claim-records?limit={value}"),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "limit={value} clamps, not 400: {body}"
        );
        assert_eq!(body["records"].as_array().map_or(0, Vec::len), 1);
    }

    let (status, body) = authed(&state, "GET", "/api/claim-records?limit=abc", None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "unparseable limit falls back to the default, not 400: {body}"
    );
    assert_eq!(body["records"].as_array().map_or(0, Vec::len), 5);
}

#[tokio::test]
async fn plan_runs_reader_defaults_to_fifty_and_applies_bounded_limit() {
    let state = fixture();
    seed_plan_runs(&state, 60);

    let (status, body) = authed(&state, "GET", "/api/plan-runs", None).await;
    assert_eq!(status, StatusCode::OK, "default listing: {body}");
    let records = body["records"].as_array().expect("records array");
    assert_eq!(records.len(), 50, "default limit is 50");
    assert_eq!(records[0]["plan_id"].as_i64(), Some(60), "newest first");
    assert_eq!(
        records[49]["plan_id"].as_i64(),
        Some(11),
        "the 50 newest of 60 rows"
    );
    assert_eq!(records[0]["status"], "ok");

    let (status, body) = authed(&state, "GET", "/api/plan-runs?limit=10", None).await;
    assert_eq!(status, StatusCode::OK, "limit=10: {body}");
    let records = body["records"].as_array().expect("records array");
    assert_eq!(records.len(), 10);
    assert_eq!(records[0]["plan_id"].as_i64(), Some(60));
    assert_eq!(records[9]["plan_id"].as_i64(), Some(51));

    for (query, expected) in [
        ("limit=0", 1usize),
        ("limit=-5", 1usize),
        ("limit=abc", 50usize),
    ] {
        let (status, body) = authed(&state, "GET", &format!("/api/plan-runs?{query}"), None).await;
        assert_eq!(status, StatusCode::OK, "{query} must not 400: {body}");
        assert_eq!(
            body["records"].as_array().map_or(0, Vec::len),
            expected,
            "{query}"
        );
    }
}
