use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    models::{CreateFirearmRequest, Firearm, FirearmAllocation, UpdateFirearmRequest},
    utils,
};

#[derive(Debug, Deserialize)]
pub struct FirearmListQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub state: Option<String>,
    pub search: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct FirearmInventoryRow {
    id: String,
    name: String,
    serial_number: String,
    model: String,
    make: Option<String>,
    caliber: String,
    status: String,
    license_expiry_date: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    active_custody: bool,
    custody_review: bool,
    mdr_batch_id: Option<String>,
    mdr_row_ref: Option<String>,
    source_guard_text: Option<String>,
    direct_guard_match: bool,
}

fn normalized_filter(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn validate_firearm_status(status: &str) -> AppResult<&'static str> {
    let normalized = status.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "available" => Ok("available"),
        "allocated" => Ok("allocated"),
        "maintenance" => Ok("maintenance"),
        "deployed" => Ok("deployed"),
        "lost" => Ok("lost"),
        _ => Err(AppError::ValidationError(
            "Invalid firearm status. Allowed values: available, allocated, maintenance, deployed, lost".to_string(),
        )),
    }
}

fn parse_license_expiry_date(value: Option<String>) -> AppResult<Option<DateTime<Utc>>> {
    let Some(value) = value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };

    if let Ok(parsed) = DateTime::parse_from_rfc3339(&value) {
        return Ok(Some(parsed.with_timezone(&Utc)));
    }

    let date = NaiveDate::parse_from_str(&value, "%Y-%m-%d").map_err(|_| {
        AppError::BadRequest(
            "License expiry date must use YYYY-MM-DD or RFC3339 format".to_string(),
        )
    })?;
    let midnight = date.and_hms_opt(0, 0, 0).ok_or_else(|| {
        AppError::BadRequest("License expiry date is outside the supported date range".to_string())
    })?;

    Ok(Some(DateTime::<Utc>::from_naive_utc_and_offset(
        midnight, Utc,
    )))
}

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
    let status = validate_firearm_status(payload.status.as_deref().unwrap_or("available"))?;
    let license_expiry_date = parse_license_expiry_date(payload.license_expiry_date)?;

    sqlx::query(
        "INSERT INTO firearms (id, name, serial_number, model, caliber, status, validity_date) VALUES ($1, $2, $3, $4, $5, $6, $7)"
    )
    .bind(&id)
    .bind(&payload.model)
    .bind(&payload.serial_number)
    .bind(&payload.model)
    .bind(&payload.caliber)
    .bind(status)
    .bind(license_expiry_date)
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

pub async fn get_all_firearms(
    State(db): State<Arc<PgPool>>,
    Query(query): Query<FirearmListQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let (page, page_size, offset) = utils::resolve_pagination(
        utils::PaginationQuery {
            page: query.page,
            page_size: query.page_size,
        },
        50,
        200,
    );
    let state = normalized_filter(query.state).map(|value| value.to_ascii_lowercase());
    if let Some(state) = state.as_deref() {
        if !matches!(
            state,
            "available" | "active_custody" | "custody_review" | "maintenance"
        ) {
            return Err(AppError::BadRequest(
                "state must be available, active_custody, custody_review, or maintenance"
                    .to_string(),
            ));
        }
    }
    let search = normalized_filter(query.search);

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::BIGINT
           FROM firearms f
           WHERE ($1::TEXT IS NULL
                  OR ($1 = 'available' AND LOWER(BTRIM(f.status)) = 'available')
                  OR ($1 = 'maintenance' AND LOWER(BTRIM(f.status)) = 'maintenance')
                  OR ($1 = 'active_custody' AND EXISTS (
                    SELECT 1 FROM firearm_allocations fa WHERE fa.firearm_id = f.id AND LOWER(BTRIM(fa.status)) = 'active'))
                  OR ($1 = 'custody_review' AND LOWER(BTRIM(f.status)) IN ('allocated', 'deployed') AND NOT EXISTS (
                    SELECT 1 FROM firearm_allocations fa WHERE fa.firearm_id = f.id AND LOWER(BTRIM(fa.status)) = 'active')))
             AND ($2::TEXT IS NULL OR f.serial_number ILIKE '%' || $2 || '%' OR COALESCE(f.make, '') ILIKE '%' || $2 || '%' OR f.model ILIKE '%' || $2 || '%')"#,
    )
    .bind(&state)
    .bind(&search)
        .fetch_one(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let firearms = sqlx::query_as::<_, FirearmInventoryRow>(
        r#"SELECT f.id, f.name, f.serial_number, f.model, f.make, f.caliber, f.status,
                  f.validity_date AS license_expiry_date, f.created_at, f.updated_at,
                  EXISTS (SELECT 1 FROM firearm_allocations fa WHERE fa.firearm_id = f.id AND LOWER(BTRIM(fa.status)) = 'active') AS active_custody,
                  (LOWER(BTRIM(f.status)) IN ('allocated', 'deployed') AND NOT EXISTS (
                    SELECT 1 FROM firearm_allocations fa WHERE fa.firearm_id = f.id AND LOWER(BTRIM(fa.status)) = 'active')) AS custody_review,
                  f.mdr_batch_id,
                  source.mdr_row_ref,
                  source.source_guard_text,
                  COALESCE(source.direct_guard_match, false) AS direct_guard_match
           FROM firearms f
           LEFT JOIN LATERAL (
             SELECT s.sheet_name || ':' || s.row_number::TEXT AS mdr_row_ref,
                    s.guard_name AS source_guard_text,
                    s.matched_guard_id IS NOT NULL AS direct_guard_match
             FROM mdr_staging_rows s
             WHERE s.batch_id = f.mdr_batch_id
               AND regexp_replace(UPPER(BTRIM(COALESCE(s.serial_number, ''))), '[^A-Z0-9]', '', 'g') = regexp_replace(UPPER(BTRIM(f.serial_number)), '[^A-Z0-9]', '', 'g')
             ORDER BY s.created_at DESC, s.sheet_name, s.row_number
             LIMIT 1
           ) source ON TRUE
           WHERE ($1::TEXT IS NULL
                  OR ($1 = 'available' AND LOWER(BTRIM(f.status)) = 'available')
                  OR ($1 = 'maintenance' AND LOWER(BTRIM(f.status)) = 'maintenance')
                  OR ($1 = 'active_custody' AND EXISTS (
                    SELECT 1 FROM firearm_allocations fa WHERE fa.firearm_id = f.id AND LOWER(BTRIM(fa.status)) = 'active'))
                  OR ($1 = 'custody_review' AND LOWER(BTRIM(f.status)) IN ('allocated', 'deployed') AND NOT EXISTS (
                    SELECT 1 FROM firearm_allocations fa WHERE fa.firearm_id = f.id AND LOWER(BTRIM(fa.status)) = 'active')))
             AND ($2::TEXT IS NULL OR f.serial_number ILIKE '%' || $2 || '%' OR COALESCE(f.make, '') ILIKE '%' || $2 || '%' OR f.model ILIKE '%' || $2 || '%')
           ORDER BY f.created_at DESC
           LIMIT $3 OFFSET $4"#,
    )
    .bind(&state)
    .bind(&search)
    .bind(page_size)
    .bind(offset)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "firearms": firearms
    })))
}

pub async fn get_firearm_by_id(
    State(db): State<Arc<PgPool>>,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let firearm = sqlx::query_as::<_, Firearm>(
        "SELECT id, name, serial_number, model, make, caliber, status, validity_date AS license_expiry_date, created_at, updated_at FROM firearms WHERE id = $1"
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

    if let Some(serial_number) = payload.serial_number {
        let serial_number = serial_number.trim();
        if serial_number.is_empty() {
            return Err(AppError::ValidationError(
                "Serial number cannot be empty".to_string(),
            ));
        }
        sqlx::query(
            "UPDATE firearms SET serial_number = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
        )
        .bind(serial_number)
        .bind(&id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update firearm: {}", e)))?;
    }

    if let Some(model) = payload.model {
        let model = model.trim();
        if model.is_empty() {
            return Err(AppError::ValidationError(
                "Model cannot be empty".to_string(),
            ));
        }
        sqlx::query(
            "UPDATE firearms SET name = $1, model = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
        )
        .bind(model)
        .bind(&id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update firearm: {}", e)))?;
    }

    if let Some(status) = payload.status {
        let normalized_status = validate_firearm_status(&status)?;
        sqlx::query(
            "UPDATE firearms SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
        )
        .bind(normalized_status)
        .bind(&id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;
    }

    if let Some(caliber) = payload.caliber {
        if caliber.trim().is_empty() {
            return Err(AppError::ValidationError(
                "Caliber cannot be empty".to_string(),
            ));
        }
        sqlx::query(
            "UPDATE firearms SET caliber = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
        )
        .bind(&caliber)
        .bind(&id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;
    }

    if let Some(license_expiry_date) = payload.license_expiry_date {
        let license_expiry_date = parse_license_expiry_date(Some(license_expiry_date))?;
        sqlx::query(
            "UPDATE firearms SET validity_date = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
        )
        .bind(license_expiry_date)
        .bind(&id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update firearm: {}", e)))?;
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

#[cfg(test)]
mod tests {
    use super::parse_license_expiry_date;

    #[test]
    fn parses_date_only_and_empty_license_expiry_values() {
        assert!(parse_license_expiry_date(Some("2026-12-31".to_string())).is_ok());
        assert!(parse_license_expiry_date(Some("  ".to_string()))
            .expect("blank dates should be optional")
            .is_none());
    }

    #[test]
    fn rejects_invalid_license_expiry_values() {
        assert!(parse_license_expiry_date(Some("31/12/2026".to_string())).is_err());
    }
}
