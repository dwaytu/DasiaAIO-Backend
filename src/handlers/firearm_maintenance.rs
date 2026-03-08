use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::Utc;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    error::{AppError, AppResult},
    models::{CompleteFirearmMaintenanceRequest, CreateFirearmMaintenanceRequest, FirearmMaintenance},
    utils,
};

/// POST /api/firearm-maintenance/schedule
pub async fn schedule_maintenance(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CreateFirearmMaintenanceRequest>,
) -> AppResult<(StatusCode, Json<FirearmMaintenance>)> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let rec = sqlx::query_as::<_, FirearmMaintenance>(
        r#"
        INSERT INTO firearm_maintenance
            (id, firearm_id, maintenance_type, description, scheduled_date,
             performed_by, cost, status, notes, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9, $9)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(&payload.firearm_id)
    .bind(&payload.maintenance_type)
    .bind(&payload.description)
    .bind(payload.scheduled_date)
    .bind(payload.performed_by.as_deref())
    .bind(payload.cost.as_deref())
    .bind(payload.notes.as_deref())
    .bind(now)
    .fetch_one(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to schedule maintenance: {}", e)))?;

    // Mark firearm as under maintenance
    sqlx::query("UPDATE firearms SET status = 'maintenance', updated_at = NOW() WHERE id = $1")
        .bind(&payload.firearm_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update firearm: {}", e)))?;

    Ok((StatusCode::CREATED, Json(rec)))
}

/// GET /api/firearm-maintenance/pending
pub async fn get_pending_maintenance(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<FirearmMaintenance>>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let recs = sqlx::query_as::<_, FirearmMaintenance>(
        "SELECT * FROM firearm_maintenance WHERE status = 'pending' ORDER BY scheduled_date ASC",
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(recs))
}

/// GET /api/firearm-maintenance/:firearm_id
pub async fn get_firearm_maintenance(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(firearm_id): Path<String>,
) -> AppResult<Json<Vec<FirearmMaintenance>>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let recs = sqlx::query_as::<_, FirearmMaintenance>(
        "SELECT * FROM firearm_maintenance WHERE firearm_id = $1 ORDER BY scheduled_date DESC",
    )
    .bind(&firearm_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(recs))
}

/// POST /api/firearm-maintenance/:maintenance_id/complete
pub async fn complete_maintenance(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(maintenance_id): Path<String>,
    Json(payload): Json<CompleteFirearmMaintenanceRequest>,
) -> AppResult<Json<FirearmMaintenance>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let now = Utc::now();

    // Get firearm_id so we can restore its status
    let firearm_id: String = sqlx::query_scalar(
        "SELECT firearm_id FROM firearm_maintenance WHERE id = $1",
    )
    .bind(&maintenance_id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Maintenance record not found".to_string()))?;

    let rec = sqlx::query_as::<_, FirearmMaintenance>(
        r#"
        UPDATE firearm_maintenance
        SET status = 'completed',
            completion_date = $1,
            performed_by = COALESCE($2, performed_by),
            cost = COALESCE($3, cost),
            notes = COALESCE($4, notes),
            updated_at = $1
        WHERE id = $5
        RETURNING *
        "#,
    )
    .bind(now)
    .bind(payload.performed_by.as_deref())
    .bind(payload.cost.as_deref())
    .bind(payload.notes.as_deref())
    .bind(&maintenance_id)
    .fetch_one(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to complete maintenance: {}", e)))?;

    // Restore firearm to available
    sqlx::query("UPDATE firearms SET status = 'available', updated_at = NOW() WHERE id = $1")
        .bind(&firearm_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to restore firearm: {}", e)))?;

    Ok(Json(rec))
}
