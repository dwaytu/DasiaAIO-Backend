use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use serde_json::json;

use crate::{
    error::{AppError, AppResult},
    models::{
        Attendance, CheckInRequest, CheckOutRequest, CreateShiftRequest, RequestReplacementRequest,
        SetAvailabilityRequest, Shift,
    },
    utils,
};

pub async fn create_shift(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CreateShiftRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    if payload.guard_id.is_empty() || payload.start_time.is_empty() 
        || payload.end_time.is_empty() || payload.client_site.is_empty() {
        return Err(AppError::BadRequest(
            "All fields are required".to_string()
        ));
    }

    // Check if guard exists
    sqlx::query("SELECT id FROM users WHERE id = $1")
        .bind(&payload.guard_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Guard not found".to_string()))?;

    let shift_id = utils::generate_id();
    
    // Parse datetime strings
    let start_time = chrono::DateTime::parse_from_rfc3339(&payload.start_time)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .ok_or_else(|| AppError::BadRequest("Invalid start_time format".to_string()))?;
    
    let end_time = chrono::DateTime::parse_from_rfc3339(&payload.end_time)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .ok_or_else(|| AppError::BadRequest("Invalid end_time format".to_string()))?;

    sqlx::query(
        "INSERT INTO shifts (id, guard_id, start_time, end_time, client_site, status) VALUES ($1, $2, $3, $4, $5, 'scheduled')"
    )
    .bind(&shift_id)
    .bind(&payload.guard_id)
    .bind(start_time)
    .bind(end_time)
    .bind(&payload.client_site)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create shift: {}", e)))?;

    Ok((StatusCode::CREATED, Json(json!({
        "message": "Shift created successfully",
        "shiftId": shift_id,
        "shift": {
            "guardId": payload.guard_id,
            "startTime": payload.start_time,
            "endTime": payload.end_time,
            "clientSite": payload.client_site
        }
    }))))
}

pub async fn check_in(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CheckInRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    if payload.guard_id.is_empty() || payload.shift_id.is_empty() {
        return Err(AppError::BadRequest(
            "Guard ID and Shift ID are required".to_string()
        ));
    }

    let _claims = utils::require_self_or_min_role(&headers, &payload.guard_id, "supervisor")?;

    // Check if shift exists
    let shift_guard = sqlx::query("SELECT id, guard_id FROM shifts WHERE id = $1")
        .bind(&payload.shift_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Shift not found".to_string()))?;

    let assigned_guard_id: String = shift_guard
        .try_get("guard_id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse shift guard: {}", e)))?;

    if assigned_guard_id != payload.guard_id {
        return Err(AppError::Forbidden(
            "Guard can only check in for their assigned shift".to_string(),
        ));
    }

    let attendance_id = utils::generate_id();

    sqlx::query(
        "INSERT INTO attendance (id, guard_id, shift_id, check_in_time, status) VALUES ($1, $2, $3, CURRENT_TIMESTAMP, 'checked_in')"
    )
    .bind(&attendance_id)
    .bind(&payload.guard_id)
    .bind(&payload.shift_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to record check-in: {}", e)))?;

    let punctuality_id = utils::generate_id();
    sqlx::query(
        "INSERT INTO punctuality_records (id, guard_id, shift_id, scheduled_start_time, actual_check_in_time, minutes_late, is_on_time, status)
         SELECT $1, $2, s.id, s.start_time, CURRENT_TIMESTAMP,
                CAST(EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - s.start_time)) / 60 AS INT),
                CASE WHEN CURRENT_TIMESTAMP <= s.start_time + INTERVAL '5 minutes' THEN true ELSE false END,
                CASE
                    WHEN CURRENT_TIMESTAMP <= s.start_time THEN 'early'
                    WHEN CURRENT_TIMESTAMP <= s.start_time + INTERVAL '5 minutes' THEN 'on_time'
                    ELSE 'late'
                END
         FROM shifts s
         WHERE s.id = $3"
    )
    .bind(&punctuality_id)
    .bind(&payload.guard_id)
    .bind(&payload.shift_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to record punctuality: {}", e)))?;

    Ok((StatusCode::CREATED, Json(json!({
        "message": "Check-in recorded successfully",
        "attendanceId": attendance_id
    }))))
}

pub async fn check_out(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CheckOutRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if payload.attendance_id.is_empty() {
        return Err(AppError::BadRequest(
            "Attendance ID is required".to_string()
        ));
    }

    // Check if attendance exists and capture guard ownership.
    let attendance = sqlx::query("SELECT id, guard_id FROM attendance WHERE id = $1")
        .bind(&payload.attendance_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Attendance not found".to_string()))?;

    let attendance_guard_id: String = attendance
        .try_get("guard_id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse attendance guard: {}", e)))?;

    let _claims = utils::require_self_or_min_role(&headers, &attendance_guard_id, "supervisor")?;

    sqlx::query(
        "UPDATE attendance SET check_out_time = CURRENT_TIMESTAMP, status = 'checked_out', updated_at = CURRENT_TIMESTAMP WHERE id = $1"
    )
    .bind(&payload.attendance_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "message": "Check-out recorded successfully"
    })))
}

pub async fn detect_no_shows(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    // Enhanced no-show detection with grace period and automatic notifications
    
    // Step 1: Find shifts that have passed their grace period without check-in
    #[derive(sqlx::FromRow)]
    struct NoShowShift {
        id: String,
        guard_id: String,
        start_time: chrono::DateTime<chrono::Utc>,
        end_time: chrono::DateTime<chrono::Utc>,
        client_site: String,
        grace_period_minutes: Option<i32>,
        replacement_status: Option<String>,
    }
    
    let no_show_shifts = sqlx::query_as::<_, NoShowShift>(
        "SELECT s.id, s.guard_id, s.start_time, s.end_time, s.client_site, 
                s.grace_period_minutes, s.replacement_status
         FROM shifts s 
         LEFT JOIN attendance a ON s.id = a.shift_id 
         WHERE a.id IS NULL 
         AND s.status = 'scheduled'
         AND (s.start_time + INTERVAL '1 minute' * COALESCE(s.grace_period_minutes, 15)) <= CURRENT_TIMESTAMP
         AND COALESCE(s.replacement_status, 'not_needed') = 'not_needed'"
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to detect no-shows: {}", e)))?;

    let mut notified_guards = Vec::new();
    
    // Step 2: For each no-show, find available substitutes and notify them
    for shift in &no_show_shifts {
        // Update shift status to searching
        sqlx::query(
            "UPDATE shifts SET replacement_status = 'searching', updated_at = CURRENT_TIMESTAMP WHERE id = $1"
        )
        .bind(&shift.id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update shift status: {}", e)))?;
        
        // Find available guards (not the original guard, verified users, with role 'user')
        #[derive(sqlx::FromRow)]
        struct AvailableGuard {
            id: String,
            username: String,
            full_name: Option<String>,
        }
        
        let available_guards = sqlx::query_as::<_, AvailableGuard>(
            "SELECT DISTINCT u.id, u.username, u.full_name 
             FROM users u
             LEFT JOIN guard_availability ga ON u.id = ga.guard_id
             WHERE u.id != $1 
             AND u.role IN ('guard', 'user') 
             AND u.verified = true
             AND (ga.available IS NULL OR ga.available = true)
             AND NOT EXISTS (
                 SELECT 1 FROM shifts s2 
                 WHERE s2.guard_id = u.id 
                 AND s2.status IN ('scheduled', 'in_progress')
                 AND s2.start_time <= $2 
                 AND s2.end_time >= $3
             )
             LIMIT 20"
        )
        .bind(&shift.guard_id)
        .bind(&shift.end_time)
        .bind(&shift.start_time)
        .fetch_all(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to find available guards: {}", e)))?;
        
        // Step 3: Create notifications for available guards
        for guard in &available_guards {
            let notification_id = utils::generate_id();
            let guard_name = guard.full_name.as_ref().unwrap_or(&guard.username);
            
            sqlx::query(
                "INSERT INTO notifications (id, user_id, title, message, type, related_shift_id, read) 
                 VALUES ($1, $2, $3, $4, 'replacement_request', $5, false)"
            )
            .bind(&notification_id)
            .bind(&guard.id)
            .bind("Replacement Needed - Urgent")
            .bind(format!(
                "Guard no-show detected at {}. Can you cover this shift from {} to {}? Click to accept.",
                shift.client_site,
                shift.start_time.format("%I:%M %p"),
                shift.end_time.format("%I:%M %p")
            ))
            .bind(&shift.id)
            .execute(db.as_ref())
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to create notification: {}", e)))?;
            
            notified_guards.push(json!({
                "guardId": guard.id,
                "guardName": guard_name,
                "shiftId": shift.id
            }));
        }
        
        tracing::info!(
            "No-show detected for shift {} (Guard: {}). Notified {} available guards.",
            shift.id, shift.guard_id, available_guards.len()
        );
    }

    Ok(Json(json!({
        "message": "No-show detection completed",
        "noShowsCount": no_show_shifts.len(),
        "notifiedGuards": notified_guards
    })))
}

pub async fn request_replacement(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<RequestReplacementRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if payload.original_guard_id.is_empty() || payload.replacement_guard_id.is_empty() 
        || payload.shift_id.is_empty() {
        return Err(AppError::BadRequest(
            "Original Guard ID, Replacement Guard ID, and Shift ID are required".to_string()
        ));
    }

    let _claims = utils::require_self_or_min_role(&headers, &payload.original_guard_id, "supervisor")?;

    // Verify all references exist
    sqlx::query("SELECT id FROM users WHERE id = $1")
        .bind(&payload.original_guard_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Original guard not found".to_string()))?;

    sqlx::query("SELECT id FROM users WHERE id = $1")
        .bind(&payload.replacement_guard_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Replacement guard not found".to_string()))?;

    sqlx::query("SELECT id FROM shifts WHERE id = $1")
        .bind(&payload.shift_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Shift not found".to_string()))?;

    // Update shift to use replacement guard
    sqlx::query(
        "UPDATE shifts SET guard_id = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2"
    )
    .bind(&payload.replacement_guard_id)
    .bind(&payload.shift_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to update shift: {}", e)))?;

    Ok(Json(json!({
        "message": "Replacement accepted successfully"
    })))
}

pub async fn set_availability(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<SetAvailabilityRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if payload.guard_id.is_empty() {
        return Err(AppError::BadRequest(
            "Guard ID is required".to_string()
        ));
    }

    let _claims = utils::require_self_or_min_role(&headers, &payload.guard_id, "supervisor")?;

    // Check if guard exists
    sqlx::query("SELECT id FROM users WHERE id = $1")
        .bind(&payload.guard_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Guard not found".to_string()))?;

    // Check if availability record exists
    let existing = sqlx::query(
        "SELECT id FROM guard_availability WHERE guard_id = $1 ORDER BY created_at DESC LIMIT 1"
    )
    .bind(&payload.guard_id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    if existing.is_some() {
        // Update existing record
        sqlx::query(
            "UPDATE guard_availability 
             SET available = $1, updated_at = CURRENT_TIMESTAMP 
             WHERE guard_id = $2"
        )
        .bind(payload.available.unwrap_or(true))
        .bind(&payload.guard_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update availability: {}", e)))?;
    } else {
        // Create new record
        let id = utils::generate_id();
        sqlx::query(
            "INSERT INTO guard_availability (id, guard_id, available) VALUES ($1, $2, $3)"
        )
        .bind(&id)
        .bind(&payload.guard_id)
        .bind(payload.available.unwrap_or(true))
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to create availability: {}", e)))?;
    }

    Ok(Json(json!({
        "message": "Guard availability updated successfully"
    })))
}

// Accept a replacement shift
pub async fn accept_replacement(
    State(db): State<Arc<PgPool>>,
    Json(payload): Json<serde_json::Value>,
) -> AppResult<Json<serde_json::Value>> {
    let guard_id = payload.get("guardId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Guard ID is required".to_string()))?;
    
    let shift_id = payload.get("shiftId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Shift ID is required".to_string()))?;
    
    let notification_id = payload.get("notificationId")
        .and_then(|v| v.as_str());

    // Verify guard exists
    sqlx::query("SELECT id FROM users WHERE id = $1")
        .bind(guard_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Guard not found".to_string()))?;

    // Verify shift exists and needs replacement
    let _shift = sqlx::query(
        "SELECT id, replacement_status FROM shifts WHERE id = $1"
    )
    .bind(shift_id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Shift not found".to_string()))?;

    // Update shift with new guard and mark as accepted
    sqlx::query(
        "UPDATE shifts 
         SET guard_id = $1, replacement_status = 'accepted', updated_at = CURRENT_TIMESTAMP 
         WHERE id = $2"
    )
    .bind(guard_id)
    .bind(shift_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to accept replacement: {}", e)))?;

    // Mark the notification as read if provided
    if let Some(notif_id) = notification_id {
        sqlx::query(
            "UPDATE notifications SET read = true, updated_at = CURRENT_TIMESTAMP WHERE id = $1"
        )
        .bind(notif_id)
        .execute(db.as_ref())
        .await
        .ok(); // Ignore errors on notification update
    }

    // Cancel other pending notifications for this shift
    sqlx::query(
        "UPDATE notifications 
         SET read = true, updated_at = CURRENT_TIMESTAMP 
         WHERE related_shift_id = $1 AND type = 'replacement_request' AND read = false"
    )
    .bind(shift_id)
    .execute(db.as_ref())
    .await
    .ok(); // Ignore errors

    tracing::info!(
        "Replacement accepted: Guard {} accepted shift {}",
        guard_id, shift_id
    );

    Ok(Json(json!({
        "message": "Replacement shift accepted successfully",
        "shiftId": shift_id,
        "guardId": guard_id
    })))
}

// Get guard availability
pub async fn get_guard_availability(
    State(db): State<Arc<PgPool>>,
    Path(guard_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let availability = sqlx::query(
        "SELECT id, guard_id, available, available_from, available_to, notes, created_at, updated_at 
         FROM guard_availability 
         WHERE guard_id = $1 
         ORDER BY created_at DESC 
         LIMIT 1"
    )
    .bind(&guard_id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    if let Some(row) = availability {
        Ok(Json(json!({
            "available": row.try_get::<bool, _>("available").unwrap_or(true),
            "availableFrom": row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("available_from").ok().flatten(),
            "availableTo": row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("available_to").ok().flatten(),
            "notes": row.try_get::<Option<String>, _>("notes").ok().flatten()
        })))
    } else {
        // Default to available if no record exists
        Ok(Json(json!({
            "available": true,
            "availableFrom": null,
            "availableTo": null,
            "notes": null
        })))
    }
}


pub async fn get_guard_shifts(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(guard_id): Path<String>,
    Query(pagination): Query<utils::PaginationQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_self_or_min_role(&headers, &guard_id, "supervisor")?;

    let (page, page_size, offset) = utils::resolve_pagination(pagination, 30, 120);

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM shifts WHERE guard_id = $1")
        .bind(&guard_id)
        .fetch_one(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let shifts = sqlx::query_as::<_, Shift>(
        "SELECT id, guard_id, start_time, end_time, client_site, status, created_at, updated_at FROM shifts WHERE guard_id = $1 ORDER BY start_time DESC LIMIT $2 OFFSET $3",
    )
    .bind(&guard_id)
    .bind(page_size)
    .bind(offset)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "shifts": shifts
    })))
}

pub async fn get_guard_attendance(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(guard_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_self_or_min_role(&headers, &guard_id, "supervisor")?;

    let attendance = sqlx::query_as::<_, Attendance>(
        "SELECT id, guard_id, shift_id, check_in_time, check_out_time, status, created_at, updated_at FROM attendance WHERE guard_id = $1 ORDER BY check_in_time DESC",
    )
    .bind(&guard_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "total": attendance.len(),
        "attendance": attendance
    })))
}

// Get all shifts with guard information (admin view)
pub async fn get_all_shifts(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Query(pagination): Query<utils::PaginationQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let (page, page_size, offset) = utils::resolve_pagination(pagination, 40, 200);

    #[derive(sqlx::FromRow, serde::Serialize)]
    struct ShiftWithGuard {
        id: String,
        guard_id: String,
        guard_name: Option<String>,
        guard_username: String,
        start_time: chrono::DateTime<chrono::Utc>,
        end_time: chrono::DateTime<chrono::Utc>,
        client_site: String,
        status: String,
        created_at: chrono::DateTime<chrono::Utc>,
        updated_at: chrono::DateTime<chrono::Utc>,
    }

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM shifts")
        .fetch_one(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let shifts = sqlx::query_as::<_, ShiftWithGuard>(
        "SELECT s.id, s.guard_id, u.full_name as guard_name, u.username as guard_username, 
         s.start_time, s.end_time, s.client_site, s.status, s.created_at, s.updated_at 
         FROM shifts s 
         JOIN users u ON s.guard_id = u.id 
         ORDER BY s.start_time DESC
         LIMIT $1 OFFSET $2",
    )
    .bind(page_size)
    .bind(offset)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "shifts": shifts
    })))
}

// Update existing shift
pub async fn update_shift(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(shift_id): Path<String>,
    Json(payload): Json<CreateShiftRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    // Check if shift exists
    sqlx::query("SELECT id FROM shifts WHERE id = $1")
        .bind(&shift_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Shift not found".to_string()))?;

    // Parse datetime strings
    let start_time = chrono::DateTime::parse_from_rfc3339(&payload.start_time)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .ok_or_else(|| AppError::BadRequest("Invalid start_time format".to_string()))?;
    
    let end_time = chrono::DateTime::parse_from_rfc3339(&payload.end_time)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .ok_or_else(|| AppError::BadRequest("Invalid end_time format".to_string()))?;

    sqlx::query(
        "UPDATE shifts SET guard_id = $1, start_time = $2, end_time = $3, client_site = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5"
    )
    .bind(&payload.guard_id)
    .bind(start_time)
    .bind(end_time)
    .bind(&payload.client_site)
    .bind(&shift_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to update shift: {}", e)))?;

    Ok(Json(json!({
        "message": "Shift updated successfully",
        "shiftId": shift_id
    })))
}

// Delete shift
pub async fn delete_shift(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(shift_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    // Check if shift exists
    sqlx::query("SELECT id FROM shifts WHERE id = $1")
        .bind(&shift_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Shift not found".to_string()))?;

    // Delete shift
    sqlx::query("DELETE FROM shifts WHERE id = $1")
        .bind(&shift_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to delete shift: {}", e)))?;

    Ok(Json(json!({
        "message": "Shift deleted successfully"
    })))
}


