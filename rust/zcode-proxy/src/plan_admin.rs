//! Plan configuration and history only. Saving a plan never executes its task.

use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Local;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{cron::Cron, state::AppState};

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"message": message}))).into_response()
}

fn storage_error() -> Response {
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "storage operation failed",
    )
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct PlanBody {
    plan_name: String,
    cron_expr: String,
    is_active: bool,
    target_type: String,
    account_id: i64,
    account_group: String,
    task_type: String,
    auto_pick: bool,
    delay_seconds: i64,
}

impl PlanBody {
    fn validate(&mut self) -> Result<(), &'static str> {
        Cron::parse(&self.cron_expr)?;
        if self.task_type.is_empty() {
            self.task_type = "claim".into();
        }
        match self.task_type.as_str() {
            "claim" | "detect" | "activate" => (),
            "reset" => return Err("reset is only supported manually, not in plans"),
            _ => return Err("invalid task_type"),
        }
        if self.target_type.is_empty() {
            self.target_type = "all_accounts".into();
        }
        match self.target_type.as_str() {
            "all_accounts" | "single_account" | "group" => (),
            _ => return Err("invalid target_type"),
        }
        if self.target_type == "single_account" && self.account_id <= 0 {
            return Err("single_account requires a positive account_id");
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct Plan {
    id: i64,
    plan_name: String,
    cron_expr: String,
    is_active: bool,
    target_type: String,
    account_id: i64,
    account_group: String,
    task_type: String,
    auto_pick: bool,
    delay_seconds: i64,
    last_run_at: String,
    last_run_status: String,
    last_run_msg: String,
    created_at: String,
    updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_run_at: Option<String>,
}

fn read_plans(conn: &Connection) -> rusqlite::Result<Vec<Plan>> {
    let mut stmt = conn.prepare(
        "SELECT id,plan_name,cron_expr,is_active,target_type,account_id,account_group,
            task_type,auto_pick,delay_seconds,last_run_at,last_run_status,last_run_msg,
            created_at,updated_at FROM claim_plans ORDER BY id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(Plan {
            id: row.get(0)?,
            plan_name: row.get(1)?,
            cron_expr: row.get(2)?,
            is_active: row.get::<_, i64>(3)? == 1,
            target_type: row.get(4)?,
            account_id: row.get(5)?,
            account_group: row.get(6)?,
            task_type: row.get(7)?,
            auto_pick: row.get::<_, i64>(8)? == 1,
            delay_seconds: row.get(9)?,
            last_run_at: row.get(10)?,
            last_run_status: row.get(11)?,
            last_run_msg: row.get(12)?,
            created_at: row.get(13)?,
            updated_at: row.get(14)?,
            next_run_at: None,
        })
    })?;
    rows.collect()
}

pub async fn handle_list(State(state): State<Arc<AppState>>) -> Response {
    let rows = {
        let db = state.db.lock().unwrap();
        read_plans(&db)
    };
    let mut plans = match rows {
        Ok(plans) => plans,
        Err(_) => return storage_error(),
    };
    let now = Local::now();
    let mut next_times = HashMap::new();
    // Repeated schedules share display work, always after releasing the database lock.
    for plan in &mut plans {
        plan.next_run_at = next_times
            .entry(plan.cron_expr.clone())
            .or_insert_with(|| {
                Cron::parse(&plan.cron_expr)
                    .ok()
                    .and_then(|cron| cron.next_run(now))
            })
            .clone();
    }
    Json(json!({"plans": plans})).into_response()
}

pub async fn handle_create(State(state): State<Arc<AppState>>, body: String) -> Response {
    save(&state, None, &body)
}

pub async fn handle_update(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: String,
) -> Response {
    let Ok(id) = id.parse::<i64>() else {
        return error(StatusCode::BAD_REQUEST, "invalid id");
    };
    save(&state, Some(id), &body)
}

fn save(state: &AppState, id: Option<i64>, body: &str) -> Response {
    // The body has no id field: only the PUT path can select an existing row.
    let mut plan: PlanBody = match serde_json::from_str(body) {
        Ok(plan) => plan,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid request body"),
    };
    if let Err(message) = plan.validate() {
        return error(StatusCode::BAD_REQUEST, message);
    }
    let mut db = state.db.lock().unwrap();
    let tx = match db.transaction() {
        Ok(tx) => tx,
        Err(_) => return storage_error(),
    };
    let values = params![
        plan.plan_name,
        plan.cron_expr,
        plan.is_active,
        plan.target_type,
        plan.account_id,
        plan.account_group,
        plan.task_type,
        plan.auto_pick,
        plan.delay_seconds,
    ];
    let id = if let Some(id) = id {
        let exists = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM claim_plans WHERE id=?1)",
            [id],
            |row| row.get::<_, bool>(0),
        );
        match exists {
            Ok(true) => (),
            Ok(false) => return error(StatusCode::NOT_FOUND, "plan not found"),
            Err(_) => return storage_error(),
        }
        if tx
            .execute(
                "UPDATE claim_plans SET plan_name=?1,cron_expr=?2,is_active=?3,target_type=?4,
                account_id=?5,account_group=?6,task_type=?7,auto_pick=?8,delay_seconds=?9,
                updated_at=datetime('now','localtime') WHERE id=?10",
                params![
                    plan.plan_name,
                    plan.cron_expr,
                    plan.is_active,
                    plan.target_type,
                    plan.account_id,
                    plan.account_group,
                    plan.task_type,
                    plan.auto_pick,
                    plan.delay_seconds,
                    id,
                ],
            )
            .is_err()
        {
            return storage_error();
        }
        id
    } else {
        if tx.execute(
            "INSERT INTO claim_plans(plan_name,cron_expr,is_active,target_type,account_id,
                account_group,task_type,auto_pick,delay_seconds) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            values,
        ).is_err() {
            return storage_error();
        }
        tx.last_insert_rowid()
    };
    if tx.commit().is_err() {
        return storage_error();
    }
    Json(json!({"success": true, "id": id})).into_response()
}

pub async fn handle_delete(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Ok(id) = id.parse::<i64>() else {
        return error(StatusCode::BAD_REQUEST, "invalid id");
    };
    let mut db = state.db.lock().unwrap();
    let tx = match db.transaction() {
        Ok(tx) => tx,
        Err(_) => return storage_error(),
    };
    if tx
        .execute("DELETE FROM claim_plans WHERE id=?1", [id])
        .is_err()
    {
        return storage_error();
    }
    if tx.commit().is_err() {
        return storage_error();
    }
    Json(json!({"success": true})).into_response()
}

#[derive(Default, Deserialize)]
pub(crate) struct HistoryQuery {
    limit: Option<String>,
    account_id: Option<String>,
}

impl HistoryQuery {
    fn limit(&self, default: i64) -> i64 {
        self.limit
            .as_deref()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(default)
            .clamp(1, 500)
    }
}

#[derive(Serialize)]
struct ClaimRecord {
    id: i64,
    created_at: String,
    account_id: i64,
    email: String,
    task_type: String,
    plan_id: String,
    plan_name: String,
    success: bool,
    code: i64,
    message: String,
    next_at: i64,
    used_at: i64,
}

fn read_claim_records(
    conn: &Connection,
    limit: i64,
    account: Option<i64>,
) -> rusqlite::Result<Vec<ClaimRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id,created_at,account_id,email,task_type,plan_id,plan_name,success,code,
            message,next_at,used_at FROM claim_records
         WHERE (?1 IS NULL OR account_id=?1) ORDER BY id DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![account, limit], |row| {
        Ok(ClaimRecord {
            id: row.get(0)?,
            created_at: row.get(1)?,
            account_id: row.get(2)?,
            email: row.get(3)?,
            task_type: row.get(4)?,
            plan_id: row.get(5)?,
            plan_name: row.get(6)?,
            success: row.get::<_, i64>(7)? == 1,
            code: row.get(8)?,
            message: row.get(9)?,
            next_at: row.get(10)?,
            used_at: row.get(11)?,
        })
    })?;
    rows.collect()
}

pub async fn handle_claim_records(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HistoryQuery>,
) -> Response {
    let account = match query.account_id.as_deref().filter(|s| !s.is_empty()) {
        Some(value) => match value.parse::<i64>() {
            Ok(id) if id > 0 => Some(id),
            _ => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "account_id must be a positive integer",
                )
            }
        },
        None => None,
    };
    let db = state.db.lock().unwrap();
    match read_claim_records(&db, query.limit(100), account) {
        Ok(records) => Json(json!({"records": records})).into_response(),
        Err(_) => storage_error(),
    }
}

#[derive(Serialize)]
struct PlanRunRecord {
    id: i64,
    plan_id: i64,
    plan_name: String,
    task_type: String,
    target_type: String,
    account_id: i64,
    run_at: String,
    status: String,
    message: String,
    total: i64,
    success_count: i64,
    fail_count: i64,
    duration_ms: i64,
}

fn read_plan_runs(conn: &Connection, limit: i64) -> rusqlite::Result<Vec<PlanRunRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id,plan_id,plan_name,task_type,target_type,account_id,run_at,status,
            message,total,success_count,fail_count,duration_ms
         FROM plan_run_records ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit], |row| {
        Ok(PlanRunRecord {
            id: row.get(0)?,
            plan_id: row.get(1)?,
            plan_name: row.get(2)?,
            task_type: row.get(3)?,
            target_type: row.get(4)?,
            account_id: row.get(5)?,
            run_at: row.get(6)?,
            status: row.get(7)?,
            message: row.get(8)?,
            total: row.get(9)?,
            success_count: row.get(10)?,
            fail_count: row.get(11)?,
            duration_ms: row.get(12)?,
        })
    })?;
    rows.collect()
}

pub async fn handle_plan_runs(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HistoryQuery>,
) -> Response {
    let db = state.db.lock().unwrap();
    match read_plan_runs(&db, query.limit(50)) {
        Ok(records) => Json(json!({"records": records})).into_response(),
        Err(_) => storage_error(),
    }
}
