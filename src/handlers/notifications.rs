use axum::{
    extract::{Path, State},
    http::HeaderMap,
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    models::{CreateNotificationRequest, Notification},
    utils,
};

#[derive(Deserialize)]
pub struct PushSubscribeRequest {
    #[serde(rename = "userId")]
    pub user_id: String,
    pub subscription: serde_json::Value,
}

// Get all notifications for a user
pub async fn get_user_notifications(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_self_or_min_role(&headers, &user_id, "supervisor")?;

    let notifications = sqlx::query_as::<_, Notification>(
        "SELECT id, user_id, title, message, type as notification_type, related_shift_id, read, created_at, updated_at 
         FROM notifications 
         WHERE user_id = $1 
         ORDER BY created_at DESC 
         LIMIT 50",
    )
    .bind(&user_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let unread_count = notifications.iter().filter(|n| !n.read).count();

    Ok(Json(json!({
        "total": notifications.len(),
        "unreadCount": unread_count,
        "notifications": notifications
    })))
}

// Get unread notifications count for a user
pub async fn get_unread_count(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_self_or_min_role(&headers, &user_id, "supervisor")?;

    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND read = false",
    )
    .bind(&user_id)
    .fetch_one(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "unreadCount": count
    })))
}

// Create a notification
pub async fn create_notification(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CreateNotificationRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    if payload.user_id.is_empty() || payload.title.is_empty() || payload.message.is_empty() {
        return Err(AppError::BadRequest(
            "User ID, title, and message are required".to_string(),
        ));
    }

    let _claims = utils::require_min_role(&headers, "supervisor")?;

    // Verify user exists
    sqlx::query("SELECT id FROM users WHERE id = $1")
        .bind(&payload.user_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let id = utils::generate_id();

    sqlx::query(
        "INSERT INTO notifications (id, user_id, title, message, type, related_shift_id, read) 
         VALUES ($1, $2, $3, $4, $5, $6, false)",
    )
    .bind(&id)
    .bind(&payload.user_id)
    .bind(&payload.title)
    .bind(&payload.message)
    .bind(&payload.notification_type)
    .bind(&payload.related_shift_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create notification: {}", e)))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Notification created successfully",
            "notificationId": id
        })),
    ))
}

// Mark notification as read
pub async fn mark_notification_read(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(notification_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    // Check if notification exists and enforce ownership/elevated access.
    let notif_user_id =
        sqlx::query_scalar::<_, String>("SELECT user_id FROM notifications WHERE id = $1")
            .bind(&notification_id)
            .fetch_optional(db.as_ref())
            .await
            .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
            .ok_or_else(|| AppError::NotFound("Notification not found".to_string()))?;

    let _claims = utils::require_self_or_min_role(&headers, &notif_user_id, "supervisor")?;

    sqlx::query(
        "UPDATE notifications SET read = true, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
    )
    .bind(&notification_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to mark notification as read: {}", e)))?;

    Ok(Json(json!({
        "message": "Notification marked as read"
    })))
}

// Mark all notifications as read for a user
pub async fn mark_all_read(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_self_or_min_role(&headers, &user_id, "supervisor")?;

    let result = sqlx::query(
        "UPDATE notifications SET read = true, updated_at = CURRENT_TIMESTAMP WHERE user_id = $1 AND read = false",
    )
    .bind(&user_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to mark notifications as read: {}", e)))?;

    Ok(Json(json!({
        "message": "All notifications marked as read",
        "updated": result.rows_affected()
    })))
}

// Delete a notification
pub async fn delete_notification(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(notification_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let notif_user_id =
        sqlx::query_scalar::<_, String>("SELECT user_id FROM notifications WHERE id = $1")
            .bind(&notification_id)
            .fetch_optional(db.as_ref())
            .await
            .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
            .ok_or_else(|| AppError::NotFound("Notification not found".to_string()))?;

    let _claims = utils::require_self_or_min_role(&headers, &notif_user_id, "supervisor")?;

    sqlx::query("DELETE FROM notifications WHERE id = $1")
        .bind(&notification_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to delete notification: {}", e)))?;

    Ok(Json(json!({
        "message": "Notification deleted successfully"
    })))
}

// Store a WebPush subscription for a user
pub async fn push_subscribe(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<PushSubscribeRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let _claims = utils::require_self_or_min_role(&headers, &payload.user_id, "guard")?;

    let endpoint = payload
        .subscription
        .get("endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("subscription.endpoint is required".to_string()))?
        .to_string();

    let p256dh = payload
        .subscription
        .pointer("/keys/p256dh")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("subscription.keys.p256dh is required".to_string()))?
        .to_string();

    let auth = payload
        .subscription
        .pointer("/keys/auth")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("subscription.keys.auth is required".to_string()))?
        .to_string();

    let id = uuid::Uuid::new_v4().to_string();

    // Upsert — update keys if the same user+endpoint re-subscribes
    sqlx::query(
        "INSERT INTO push_subscriptions (id, user_id, endpoint, p256dh, auth)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (user_id, endpoint) DO UPDATE
         SET p256dh = EXCLUDED.p256dh,
             auth   = EXCLUDED.auth,
             updated_at = CURRENT_TIMESTAMP",
    )
    .bind(&id)
    .bind(&payload.user_id)
    .bind(&endpoint)
    .bind(&p256dh)
    .bind(&auth)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to save push subscription: {}", e)))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({ "message": "Push subscription saved" })),
    ))
}
