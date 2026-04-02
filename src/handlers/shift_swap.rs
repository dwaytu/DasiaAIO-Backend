use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use sqlx::{PgPool, Row};
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    utils,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSwapRequest {
    pub requester_id: String,
    pub target_id: String,
    pub shift_id: String,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RespondSwapRequest {
    /// "accepted" or "declined"
    pub status: String,
}

/// POST /api/shifts/swap-request — guard requests a shift swap with another guard
pub async fn create_swap_request(
    State(db): State<Arc<PgPool>>,
    Json(payload): Json<CreateSwapRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    if payload.requester_id.trim().is_empty()
        || payload.target_id.trim().is_empty()
        || payload.shift_id.trim().is_empty()
    {
        return Err(AppError::BadRequest(
            "requester_id, target_id, and shift_id are required".to_string(),
        ));
    }

    let id = utils::generate_id();

    sqlx::query(
        r#"
        INSERT INTO guard_shift_swaps
            (id, requester_id, target_id, shift_id, reason, status)
        VALUES ($1, $2, $3, $4, $5, 'pending')
        "#,
    )
    .bind(&id)
    .bind(&payload.requester_id)
    .bind(&payload.target_id)
    .bind(&payload.shift_id)
    .bind(&payload.reason)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create swap request: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": id, "message": "Shift swap request created" })),
    ))
}

/// GET /api/shifts/swap-requests — list all swap requests (supervisors/admins); guards see own
pub async fn list_swap_requests(
    State(db): State<Arc<PgPool>>,
) -> AppResult<Json<serde_json::Value>> {
    let rows = sqlx::query(
        r#"
        SELECT
            s.id,
            s.requester_id,
            r.full_name AS requester_name,
            s.target_id,
            t.full_name AS target_name,
            s.shift_id,
            s.reason,
            s.status,
            s.responded_at,
            s.created_at
        FROM guard_shift_swaps s
        JOIN users r ON r.id = s.requester_id
        JOIN users t ON t.id = s.target_id
        ORDER BY s.created_at DESC
        LIMIT 200
        "#
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to list swap requests: {e}")))?;

    let items: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|row| {
            json!({
                "id":            row.get::<String, _>("id"),
                "requesterId":   row.get::<String, _>("requester_id"),
                "requesterName": row.get::<Option<String>, _>("requester_name"),
                "targetId":      row.get::<String, _>("target_id"),
                "targetName":    row.get::<Option<String>, _>("target_name"),
                "shiftId":       row.get::<String, _>("shift_id"),
                "reason":        row.get::<Option<String>, _>("reason"),
                "status":        row.get::<String, _>("status"),
                "respondedAt":   row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("responded_at"),
                "createdAt":     row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            })
        })
        .collect();

    Ok(Json(json!({ "swapRequests": items, "total": items.len() })))
}

/// PATCH /api/shifts/swap-requests/:id/respond — target guard accepts or declines
pub async fn respond_to_swap(
    State(db): State<Arc<PgPool>>,
    Path(swap_id): Path<String>,
    Json(payload): Json<RespondSwapRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let status = payload.status.trim().to_lowercase();
    if status != "accepted" && status != "declined" {
        return Err(AppError::BadRequest(
            "status must be 'accepted' or 'declined'".into(),
        ));
    }

    let result = sqlx::query(
        r#"
        UPDATE guard_shift_swaps
        SET status       = $1,
            responded_at = NOW(),
            updated_at   = NOW()
        WHERE id = $2
        "#,
    )
    .bind(&status)
    .bind(&swap_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to update swap request: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "Swap request '{swap_id}' not found"
        )));
    }

    Ok(Json(json!({ "message": "Swap request updated", "status": status })))
}
