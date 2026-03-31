use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    models::{CreateIncidentRequest, Incident, UpdateIncidentStatusRequest},
    utils,
};

fn normalize_priority(priority: &str) -> AppResult<String> {
    let normalized = priority.trim().to_lowercase();
    match normalized.as_str() {
        "low" | "medium" | "high" | "critical" => Ok(normalized),
        _ => Err(AppError::BadRequest(
            "Invalid priority. Use low, medium, high, or critical".to_string(),
        )),
    }
}

fn normalize_status(status: &str) -> AppResult<String> {
    let normalized = status.trim().to_lowercase();
    match normalized.as_str() {
        "open" | "investigating" | "resolved" => Ok(normalized),
        _ => Err(AppError::BadRequest(
            "Invalid status. Use open, investigating, or resolved".to_string(),
        )),
    }
}

pub async fn create_incident(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CreateIncidentRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let claims = utils::require_min_role(&headers, "guard")?;

    if payload.title.trim().is_empty() {
        return Err(AppError::BadRequest("Title is required".to_string()));
    }
    if payload.description.trim().is_empty() {
        return Err(AppError::BadRequest("Description is required".to_string()));
    }
    if payload.location.trim().is_empty() {
        return Err(AppError::BadRequest("Location is required".to_string()));
    }

    let priority = normalize_priority(&payload.priority)?;
    let incident_id = utils::generate_id();

    sqlx::query(
        r#"INSERT INTO incidents (
               id, title, description, location, reported_by, status, priority
           ) VALUES ($1, $2, $3, $4, $5, 'open', $6)"#,
    )
    .bind(&incident_id)
    .bind(payload.title.trim())
    .bind(payload.description.trim())
    .bind(payload.location.trim())
    .bind(&claims.sub)
    .bind(priority)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create incident: {}", e)))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Incident reported successfully",
            "incidentId": incident_id
        })),
    ))
}

pub async fn get_incidents(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Query(pagination): Query<utils::PaginationQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let token = utils::extract_bearer_token(&headers)?;
    let claims = utils::verify_token(&token)?;
    let actor_role = utils::normalize_role(&claims.role);

    let (page, page_size, offset) = utils::resolve_pagination(pagination, 50, 200);

    let (total, incidents) = if actor_role == "guard" {
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE reported_by = $1")
            .bind(&claims.sub)
            .fetch_one(db.as_ref())
            .await
            .map_err(|e| {
                AppError::DatabaseError(format!("Failed to fetch incidents count: {}", e))
            })?;

        let incidents = sqlx::query_as::<_, Incident>(
            r#"SELECT id, title, description, location, reported_by, status, priority, created_at, updated_at
               FROM incidents
               WHERE reported_by = $1
               ORDER BY created_at DESC
               LIMIT $2 OFFSET $3"#,
        )
        .bind(&claims.sub)
        .bind(page_size)
        .bind(offset)
        .fetch_all(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to fetch incidents: {}", e)))?;

        (total, incidents)
    } else {
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM incidents")
            .fetch_one(db.as_ref())
            .await
            .map_err(|e| {
                AppError::DatabaseError(format!("Failed to fetch incidents count: {}", e))
            })?;

        let incidents = sqlx::query_as::<_, Incident>(
            r#"SELECT id, title, description, location, reported_by, status, priority, created_at, updated_at
               FROM incidents
               ORDER BY created_at DESC
               LIMIT $1 OFFSET $2"#,
        )
        .bind(page_size)
        .bind(offset)
        .fetch_all(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to fetch incidents: {}", e)))?;

        (total, incidents)
    };

    Ok(Json(json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "incidents": incidents
    })))
}

pub async fn get_active_incidents(
    State(db): State<Arc<PgPool>>,
        headers: HeaderMap,
    Query(pagination): Query<utils::PaginationQuery>,
) -> AppResult<Json<serde_json::Value>> {
        let token = utils::extract_bearer_token(&headers)?;
        let claims = utils::verify_token(&token)?;
        let actor_role = utils::normalize_role(&claims.role);

    let (page, page_size, offset) = utils::resolve_pagination(pagination, 50, 200);

        let (total, incidents) = if actor_role == "guard" {
                let total: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM incidents WHERE status IN ('open', 'investigating') AND reported_by = $1",
                )
                .bind(&claims.sub)
                .fetch_one(db.as_ref())
                .await
                .map_err(|e| {
                        AppError::DatabaseError(format!("Failed to fetch active incidents count: {}", e))
                })?;

                let incidents = sqlx::query_as::<_, Incident>(
                        r#"SELECT id, title, description, location, reported_by, status, priority, created_at, updated_at
                             FROM incidents
                             WHERE status IN ('open', 'investigating')
                                 AND reported_by = $1
                             ORDER BY
                                 CASE priority
                                     WHEN 'critical' THEN 4
                                     WHEN 'high' THEN 3
                                     WHEN 'medium' THEN 2
                                     ELSE 1
                                 END DESC,
                                 created_at DESC
                             LIMIT $2 OFFSET $3"#,
                )
                .bind(&claims.sub)
                .bind(page_size)
                .bind(offset)
                .fetch_all(db.as_ref())
                .await
                .map_err(|e| AppError::DatabaseError(format!("Failed to fetch active incidents: {}", e)))?;

                (total, incidents)
        } else {
                let total: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM incidents WHERE status IN ('open', 'investigating')",
                )
                .fetch_one(db.as_ref())
                .await
                .map_err(|e| {
                        AppError::DatabaseError(format!("Failed to fetch active incidents count: {}", e))
                })?;

                let incidents = sqlx::query_as::<_, Incident>(
                        r#"SELECT id, title, description, location, reported_by, status, priority, created_at, updated_at
                             FROM incidents
                             WHERE status IN ('open', 'investigating')
                             ORDER BY
                                 CASE priority
                                     WHEN 'critical' THEN 4
                                     WHEN 'high' THEN 3
                                     WHEN 'medium' THEN 2
                                     ELSE 1
                                 END DESC,
                                 created_at DESC
                             LIMIT $1 OFFSET $2"#,
                )
                .bind(page_size)
                .bind(offset)
                .fetch_all(db.as_ref())
                .await
                .map_err(|e| AppError::DatabaseError(format!("Failed to fetch active incidents: {}", e)))?;

                (total, incidents)
        };

    Ok(Json(json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "incidents": incidents
    })))
}

pub async fn update_incident_status(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(incident_id): Path<String>,
    Json(payload): Json<UpdateIncidentStatusRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;
    let status = normalize_status(&payload.status)?;

    let result = sqlx::query(
        r#"UPDATE incidents
           SET status = $1, updated_at = CURRENT_TIMESTAMP
           WHERE id = $2"#,
    )
    .bind(status)
    .bind(&incident_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to update incident status: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Incident not found".to_string()));
    }

    Ok(Json(json!({
        "message": "Incident status updated",
        "incidentId": incident_id
    })))
}
