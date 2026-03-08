use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    models::{CreateGuardFirearmPermitRequest, GuardFirearmPermit},
    utils,
};

pub async fn get_guard_permits(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(guard_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_self_or_min_role(&headers, &guard_id, "supervisor")?;

    let permits = sqlx::query_as::<_, GuardFirearmPermit>(
        "SELECT id, guard_id, firearm_id, permit_type, issued_date, expiry_date, status, created_at, updated_at FROM guard_firearm_permits WHERE guard_id = $1 ORDER BY issued_date DESC",
    )
    .bind(&guard_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "total": permits.len(),
        "permits": permits
    })))
}

pub async fn create_guard_permit(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CreateGuardFirearmPermitRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    if payload.guard_id.is_empty() || payload.permit_type.is_empty() {
        return Err(AppError::BadRequest(
            "Guard ID and permit type are required".to_string(),
        ));
    }

    let id = utils::generate_id();
    let status = payload.status.as_deref().unwrap_or("active");

    sqlx::query(
        "INSERT INTO guard_firearm_permits (id, guard_id, firearm_id, permit_type, issued_date, expiry_date, status) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&id)
    .bind(&payload.guard_id)
    .bind(&payload.firearm_id)
    .bind(&payload.permit_type)
    .bind(&payload.issued_date)
    .bind(&payload.expiry_date)
    .bind(status)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create permit: {}", e)))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Permit created successfully",
            "permitId": id
        })),
    ))
}

pub async fn get_all_permits(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let permits = sqlx::query_as::<_, GuardFirearmPermit>(
        "SELECT id, guard_id, firearm_id, permit_type, issued_date, expiry_date, status, created_at, updated_at FROM guard_firearm_permits ORDER BY issued_date DESC",
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "total": permits.len(),
        "permits": permits
    })))
}

/// GET /api/guard-firearm-permits/expiring  — expiring within 30 days
pub async fn get_expiring_permits(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let permits = sqlx::query_as::<_, GuardFirearmPermit>(
        r#"SELECT id, guard_id, firearm_id, permit_type, issued_date, expiry_date, status, created_at, updated_at
           FROM guard_firearm_permits
           WHERE status = 'active'
             AND expiry_date BETWEEN NOW() AND NOW() + INTERVAL '30 days'
           ORDER BY expiry_date ASC"#,
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "total": permits.len(),
        "expiringPermits": permits
    })))
}

/// PUT /api/guard-firearm-permits/:permit_id/revoke
pub async fn revoke_permit(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(permit_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let result = sqlx::query(
        "UPDATE guard_firearm_permits SET status = 'revoked', updated_at = NOW() WHERE id = $1",
    )
    .bind(&permit_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Permit not found".to_string()));
    }

    Ok(Json(json!({ "message": "Permit revoked successfully" })))
}

/// POST /api/guard-firearm-permits/auto-expire  — batch expire all past-due permits
pub async fn auto_expire_permits(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let result = sqlx::query(
        "UPDATE guard_firearm_permits SET status = 'expired', updated_at = NOW() WHERE status = 'active' AND expiry_date < NOW()",
    )
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Batch expire error: {}", e)))?;

    Ok(Json(json!({
        "message": "Auto-expire completed",
        "expiredCount": result.rows_affected()
    })))
}

