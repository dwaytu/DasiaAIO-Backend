use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    models::Client,
    utils,
};

pub async fn get_all_clients(
    State(pool): State<Arc<PgPool>>,
    Query(pagination): Query<utils::PaginationQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let (page, page_size, offset) = utils::resolve_pagination(pagination, 50, 200);

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM clients")
        .fetch_one(pool.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to count clients: {}", e)))?;

    let items = sqlx::query_as::<_, Client>(
        r#"
        SELECT
            id,
            name,
            address,
            phone,
            client_number,
            branch,
            is_active,
            created_at,
            updated_at
        FROM clients
        ORDER BY name ASC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(page_size)
    .bind(offset)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch clients: {}", e)))?;

    Ok(Json(json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "items": items
    })))
}

pub async fn get_client_by_id(
    State(pool): State<Arc<PgPool>>,
    Path(id): Path<String>,
) -> AppResult<Json<Client>> {
    let client = sqlx::query_as::<_, Client>(
        r#"
        SELECT
            id,
            name,
            address,
            phone,
            client_number,
            branch,
            is_active,
            created_at,
            updated_at
        FROM clients
        WHERE id = $1
        "#,
    )
    .bind(&id)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch client: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Client not found".to_string()))?;

    Ok(Json(client))
}
