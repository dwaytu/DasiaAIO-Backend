use axum::{
    extract::{Path, State},
    http::HeaderMap,
    http::StatusCode,
    Json,
};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    models::{CreateSupportTicketRequest, SupportTicket},
    utils,
};

pub async fn get_guard_tickets(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(guard_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_self_or_min_role(&headers, &guard_id, "supervisor")?;

    let tickets = sqlx::query_as::<_, SupportTicket>(
        "SELECT id, guard_id, subject, message, status, created_at, updated_at FROM support_tickets WHERE guard_id = $1 ORDER BY created_at DESC",
    )
    .bind(&guard_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "total": tickets.len(),
        "tickets": tickets
    })))
}

pub async fn create_ticket(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CreateSupportTicketRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    if payload.guard_id.is_empty() || payload.subject.is_empty() || payload.message.is_empty() {
        return Err(AppError::BadRequest(
            "Guard ID, subject, and message are required".to_string(),
        ));
    }

    let _claims = utils::require_self_or_min_role(&headers, &payload.guard_id, "supervisor")?;

    let id = utils::generate_id();

    sqlx::query(
        "INSERT INTO support_tickets (id, guard_id, subject, message, status) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&id)
    .bind(&payload.guard_id)
    .bind(&payload.subject)
    .bind(&payload.message)
    .bind("open")
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create ticket: {}", e)))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Ticket created successfully",
            "ticketId": id
        })),
    ))
}
