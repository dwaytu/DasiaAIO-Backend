use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::json;
use sqlx::{PgPool, Row};
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    models::{FirearmAllocation, GuardAllocationView, IssueFirearmRequest, ReturnFirearmRequest},
    utils,
};

pub async fn issue_firearm(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<IssueFirearmRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    if payload.firearm_id.is_empty() || payload.guard_id.is_empty() {
        return Err(AppError::BadRequest(
            "Firearm ID and Guard ID are required".to_string(),
        ));
    }

    let force = payload.force.unwrap_or(false);

    // ── 1. Check firearm exists and is available ─────────────────────────────
    let firearm_row = sqlx::query("SELECT id, status FROM firearms WHERE id = $1")
        .bind(&payload.firearm_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Firearm not found".to_string()))?;

    let firearm_status: String = firearm_row.get("status");
    if !force && firearm_status != "available" {
        return Err(AppError::BadRequest(format!(
            "Firearm is not available for allocation (current status: {})",
            firearm_status
        )));
    }

    // ── 2. Check guard exists ────────────────────────────────────────────────
    let _guard = sqlx::query("SELECT id FROM users WHERE id = $1")
        .bind(&payload.guard_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Guard not found".to_string()))?;

    // ── 3. Authorization: valid permit check ─────────────────────────────────
    if !force {
        let permit = sqlx::query(
            r#"SELECT id FROM guard_firearm_permits
               WHERE guard_id = $1
                 AND status = 'active'
                 AND expiry_date > NOW()
               LIMIT 1"#,
        )
        .bind(&payload.guard_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Permit check error: {}", e)))?;

        if permit.is_none() {
            return Err(AppError::Forbidden(
                "Guard does not have a valid, active firearm permit. Use force=true to override."
                    .to_string(),
            ));
        }
    }

    // ── 4. Authorization: firearms_handling training check ───────────────────
    if !force {
        let training = sqlx::query(
            r#"SELECT id FROM training_records
               WHERE guard_id = $1
                 AND training_type = 'firearms_handling'
                 AND status = 'valid'
                 AND (expiry_date IS NULL OR expiry_date > NOW())
               LIMIT 1"#,
        )
        .bind(&payload.guard_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Training check error: {}", e)))?;

        if training.is_none() {
            return Err(AppError::Forbidden(
                "Guard does not have valid firearms_handling training. Use force=true to override."
                    .to_string(),
            ));
        }
    }

    // ── 5. Create allocation ─────────────────────────────────────────────────
    let allocation_id = utils::generate_id();

    sqlx::query(
        r#"INSERT INTO firearm_allocations
               (id, guard_id, firearm_id, allocation_date, status,
                issued_by, expected_return_date, notes)
           VALUES ($1, $2, $3, CURRENT_TIMESTAMP, 'active', $4, $5, $6)"#,
    )
    .bind(&allocation_id)
    .bind(&payload.guard_id)
    .bind(&payload.firearm_id)
    .bind(payload.issued_by.as_deref())
    .bind(payload.expected_return_date)
    .bind(payload.notes.as_deref())
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create allocation: {}", e)))?;

    // Update firearm status
    sqlx::query(
        "UPDATE firearms SET status = 'allocated', updated_at = CURRENT_TIMESTAMP WHERE id = $1",
    )
    .bind(&payload.firearm_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to update firearm: {}", e)))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Firearm allocated successfully",
            "allocationId": allocation_id
        })),
    ))
}

pub async fn return_firearm(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<ReturnFirearmRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    if payload.allocation_id.is_empty() {
        return Err(AppError::BadRequest(
            "Allocation ID is required".to_string(),
        ));
    }

    // Get the allocation
    let allocation = sqlx::query("SELECT firearm_id FROM firearm_allocations WHERE id = $1")
        .bind(&payload.allocation_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Allocation not found".to_string()))?;

    // Update allocation
    sqlx::query(
        "UPDATE firearm_allocations SET return_date = CURRENT_TIMESTAMP, status = 'returned', updated_at = CURRENT_TIMESTAMP WHERE id = $1"
    )
    .bind(&payload.allocation_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    // Update firearm status back to available
    let firearm_id: String = allocation.get("firearm_id");
    sqlx::query(
        "UPDATE firearms SET status = 'available', updated_at = CURRENT_TIMESTAMP WHERE id = $1",
    )
    .bind(&firearm_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "message": "Firearm returned successfully"
    })))
}

pub async fn get_guard_allocations(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(guard_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_self_or_min_role(&headers, &guard_id, "supervisor")?;

    let allocations = sqlx::query_as::<_, GuardAllocationView>(
        r#"
        SELECT fa.id, fa.guard_id, fa.firearm_id, fa.allocation_date, fa.return_date, fa.status, fa.created_at, fa.updated_at,
               f.model AS firearm_model, f.caliber AS firearm_caliber, f.serial_number AS firearm_serial_number
        FROM firearm_allocations fa
        JOIN firearms f ON f.id = fa.firearm_id
        WHERE fa.guard_id = $1 AND fa.status = 'active'
        ORDER BY fa.allocation_date DESC
        "#,
    )
    .bind(&guard_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "total": allocations.len(),
        "allocations": allocations
    })))
}

pub async fn get_active_allocations(
    State(db): State<Arc<PgPool>>,
) -> AppResult<Json<serde_json::Value>> {
    let allocations = sqlx::query_as::<_, FirearmAllocation>(
        "SELECT id, guard_id, firearm_id, allocation_date, return_date, status, created_at, updated_at FROM firearm_allocations WHERE status = 'active'"
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "total": allocations.len(),
        "allocations": allocations
    })))
}

pub async fn get_all_allocations(
    State(db): State<Arc<PgPool>>,
) -> AppResult<Json<serde_json::Value>> {
    let allocations = sqlx::query_as::<_, FirearmAllocation>(
        "SELECT id, guard_id, firearm_id, allocation_date, return_date, status, created_at, updated_at FROM firearm_allocations ORDER BY allocation_date DESC"
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "total": allocations.len(),
        "allocations": allocations
    })))
}

/// GET /api/firearm-allocations/overdue
/// Returns active allocations where return_date has passed
pub async fn get_overdue_allocations(
    State(db): State<Arc<PgPool>>,
) -> AppResult<Json<serde_json::Value>> {
    let rows = sqlx::query(
        r#"
        SELECT
            fa.id, fa.guard_id, fa.firearm_id, fa.allocation_date,
                        fa.return_date, fa.status,
            u.full_name AS guard_name,
            f.model AS firearm_model, f.serial_number AS firearm_serial_number
        FROM firearm_allocations fa
        JOIN users u ON u.id = fa.guard_id
        JOIN firearms f ON f.id = fa.firearm_id
        WHERE fa.status = 'active'
                    AND fa.return_date IS NOT NULL
                    AND fa.return_date < NOW()
                ORDER BY fa.return_date ASC
        "#,
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let overdue: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<String, _>("id"),
                "guardId": r.get::<String, _>("guard_id"),
                "guardName": r.get::<Option<String>, _>("guard_name"),
                "firearmId": r.get::<String, _>("firearm_id"),
                "firearmModel": r.get::<Option<String>, _>("firearm_model"),
                "firearmSerialNumber": r.get::<Option<String>, _>("firearm_serial_number"),
                "allocationDate": r.get::<chrono::DateTime<chrono::Utc>, _>("allocation_date"),
                "returnDate": r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("return_date"),
                "status": r.get::<String, _>("status"),
            })
        })
        .collect();

    Ok(Json(json!({
        "total": overdue.len(),
        "overdueAllocations": overdue
    })))
}
