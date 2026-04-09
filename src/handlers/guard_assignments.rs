use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    models::{GuardAssignment, GuardStatusTransition},
    utils,
};

pub async fn get_all_guard_assignments(
    State(pool): State<Arc<PgPool>>,
    Query(pagination): Query<utils::PaginationQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let (page, page_size, offset) = utils::resolve_pagination(pagination, 50, 200);

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM guard_assignments WHERE status = 'active'")
        .fetch_one(pool.as_ref())
        .await
        .map_err(|e| {
            AppError::DatabaseError(format!("Failed to count active guard assignments: {}", e))
        })?;

    let items = sqlx::query_as::<_, GuardAssignment>(
        r#"
        SELECT
            id,
            guard_id,
            client_id,
            client_site_id,
            post_label,
            guard_number,
            assignment_start,
            assignment_end,
            status,
            mdr_batch_id,
            mdr_row_ref,
            created_at,
            updated_at
        FROM guard_assignments
        WHERE status = 'active'
        ORDER BY assignment_start DESC NULLS LAST, created_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(page_size)
    .bind(offset)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to fetch active guard assignments: {}", e))
    })?;

    Ok(Json(json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "items": items
    })))
}

pub async fn get_assignments_by_client(
    State(pool): State<Arc<PgPool>>,
    Path(client_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let items = sqlx::query_as::<_, GuardAssignment>(
        r#"
        SELECT
            id,
            guard_id,
            client_id,
            client_site_id,
            post_label,
            guard_number,
            assignment_start,
            assignment_end,
            status,
            mdr_batch_id,
            mdr_row_ref,
            created_at,
            updated_at
        FROM guard_assignments
        WHERE client_id = $1
        ORDER BY assignment_start DESC NULLS LAST, created_at DESC
        "#,
    )
    .bind(&client_id)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to fetch guard assignments by client: {}", e))
    })?;

    Ok(Json(json!({
        "total": items.len(),
        "items": items
    })))
}

pub async fn get_guard_status_transitions(
    State(pool): State<Arc<PgPool>>,
    Query(pagination): Query<utils::PaginationQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let (page, page_size, offset) = utils::resolve_pagination(pagination, 50, 200);

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM guard_status_transitions")
        .fetch_one(pool.as_ref())
        .await
        .map_err(|e| {
            AppError::DatabaseError(format!("Failed to count guard status transitions: {}", e))
        })?;

    let items = sqlx::query_as::<_, GuardStatusTransition>(
        r#"
        SELECT
            id,
            guard_id,
            transition_type,
            reason,
            previous_client_id,
            effective_date,
            mdr_batch_id,
            mdr_row_ref,
            recorded_by,
            created_at
        FROM guard_status_transitions
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(page_size)
    .bind(offset)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to fetch guard status transitions: {}", e))
    })?;

    Ok(Json(json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "items": items
    })))
}
