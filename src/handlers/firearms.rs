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
    models::{CreateFirearmRequest, Firearm, FirearmAllocation, UpdateFirearmRequest},
    utils,
};

pub async fn add_firearm(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CreateFirearmRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    if payload.serial_number.is_empty() || payload.model.is_empty() || payload.caliber.is_empty() {
        return Err(AppError::BadRequest(
            "Serial number, model, and caliber are required".to_string(),
        ));
    }

    let id = utils::generate_id();
    let status = payload.status.as_deref().unwrap_or("available");

    sqlx::query(
        "INSERT INTO firearms (id, name, serial_number, model, caliber, status) VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(&id)
    .bind(&payload.model)
    .bind(&payload.serial_number)
    .bind(&payload.model)
    .bind(&payload.caliber)
    .bind(status)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create firearm: {}", e)))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Firearm added successfully",
            "firearmId": id
        })),
    ))
}

pub async fn get_all_firearms(State(db): State<Arc<PgPool>>) -> AppResult<Json<Vec<Firearm>>> {
    let firearms = sqlx::query_as::<_, Firearm>(
        "SELECT id, name, serial_number, model, caliber, status, created_at, updated_at FROM firearms"
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(firearms))
}

pub async fn get_firearm_by_id(
    State(db): State<Arc<PgPool>>,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let firearm = sqlx::query_as::<_, Firearm>(
        "SELECT id, name, serial_number, model, caliber, status, created_at, updated_at FROM firearms WHERE id = $1"
    )
    .bind(&id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Firearm not found".to_string()))?;

    let allocation_history = sqlx::query_as::<_, FirearmAllocation>(
        "SELECT id, guard_id, firearm_id, allocation_date, return_date, status, created_at, updated_at FROM firearm_allocations WHERE firearm_id = $1"
    )
    .bind(&id)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "firearm": firearm,
        "allocationHistory": allocation_history
    })))
}

pub async fn update_firearm(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<UpdateFirearmRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    // Check if firearm exists
    sqlx::query("SELECT id FROM firearms WHERE id = $1")
        .bind(&id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Firearm not found".to_string()))?;

    if let Some(status) = payload.status {
        sqlx::query(
            "UPDATE firearms SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
        )
        .bind(&status)
        .bind(&id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;
    }

    if let Some(caliber) = payload.caliber {
        sqlx::query(
            "UPDATE firearms SET caliber = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
        )
        .bind(&caliber)
        .bind(&id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;
    }

    Ok(Json(json!({
        "message": "Firearm updated successfully"
    })))
}

pub async fn delete_firearm(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    // Check if firearm exists
    sqlx::query("SELECT id FROM firearms WHERE id = $1")
        .bind(&id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Firearm not found".to_string()))?;

    sqlx::query("DELETE FROM firearms WHERE id = $1")
        .bind(&id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "message": "Firearm deleted successfully"
    })))
}

pub async fn get_firearm_maintenance(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    // For now, return firearms that need maintenance (status = 'maintenance')
    let maintenance_firearms = sqlx::query_as::<_, Firearm>(
        "SELECT id, name, serial_number, model, caliber, status, created_at, updated_at FROM firearms WHERE status = 'maintenance' ORDER BY updated_at DESC"
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "total": maintenance_firearms.len(),
        "maintenances": maintenance_firearms
    })))
}
