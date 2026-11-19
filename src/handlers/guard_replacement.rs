use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::json;
use sqlx::{PgPool, Row};
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    models::{
        Attendance, CheckInRequest, CheckOutRequest, CreateShiftRequest, RequestReplacementRequest,
        SetAvailabilityRequest, SetShiftReadinessRequest, Shift,
    },
    services::shift_alert_service::check_in_grace_minutes,
    utils,
};

async fn guard_has_shift_conflict(
    db: &PgPool,
    guard_id: &str,
    start_time: chrono::DateTime<chrono::Utc>,
    end_time: chrono::DateTime<chrono::Utc>,
    exclude_shift_id: Option<&str>,
) -> AppResult<bool> {
    let conflict = sqlx::query_scalar::<_, bool>(
        r#"SELECT EXISTS (
               SELECT 1
               FROM shifts s
               WHERE s.guard_id = $1
                 AND ($4::text IS NULL OR s.id <> $4)
                 AND s.status IN ('scheduled', 'in_progress')
                 AND s.start_time < $3
                 AND s.end_time > $2
           )"#,
    )
    .bind(guard_id)
    .bind(start_time)
    .bind(end_time)
    .bind(exclude_shift_id)
    .fetch_one(db)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to evaluate shift conflict: {}", e)))?;

    Ok(conflict)
}

fn is_approved_guard(role: &str, verified: bool, approval_status: &str) -> bool {
    utils::normalize_role(role) == "guard"
        && verified
        && approval_status.trim().eq_ignore_ascii_case("approved")
}

const READINESS_ITEMS: [&str; 3] = ["uniform", "firearm", "endorsement_form"];

fn normalize_readiness_items(items: &[String]) -> AppResult<Vec<String>> {
    let mut normalized = Vec::with_capacity(items.len());

    for item in items {
        let key = item.trim().to_ascii_lowercase();
        if !READINESS_ITEMS.contains(&key.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Unknown readiness item '{}'.",
                item
            )));
        }
        if normalized.iter().any(|existing| existing == &key) {
            return Err(AppError::BadRequest(format!(
                "Readiness item '{}' was submitted more than once.",
                item
            )));
        }
        normalized.push(key);
    }

    Ok(normalized)
}

async fn require_approved_guard(db: &PgPool, guard_id: &str) -> AppResult<()> {
    let guard = sqlx::query(
        "SELECT role, COALESCE(verified, false) AS verified, \
                COALESCE(approval_status, 'approved') AS approval_status \
         FROM users WHERE id = $1",
    )
    .bind(guard_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Guard not found".to_string()))?;

    let role: String = guard
        .try_get("role")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse guard role: {}", e)))?;
    let verified: bool = guard.try_get("verified").map_err(|e| {
        AppError::DatabaseError(format!("Failed to parse guard verification status: {}", e))
    })?;
    let approval_status: String = guard.try_get("approval_status").map_err(|e| {
        AppError::DatabaseError(format!("Failed to parse guard approval status: {}", e))
    })?;

    if !is_approved_guard(&role, verified, &approval_status) {
        return Err(AppError::BadRequest(
            "Selected account must be an approved, verified guard".to_string(),
        ));
    }

    Ok(())
}

pub async fn create_shift(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CreateShiftRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    if payload.guard_id.is_empty()
        || payload.start_time.is_empty()
        || payload.end_time.is_empty()
        || payload.client_site.is_empty()
    {
        return Err(AppError::BadRequest("All fields are required".to_string()));
    }

    require_approved_guard(db.as_ref(), &payload.guard_id).await?;

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

    if end_time <= start_time {
        return Err(AppError::BadRequest(
            "end_time must be later than start_time".to_string(),
        ));
    }

    if guard_has_shift_conflict(db.as_ref(), &payload.guard_id, start_time, end_time, None).await? {
        return Err(AppError::Conflict(
            "Guard already has an overlapping scheduled or in-progress shift".to_string(),
        ));
    }

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

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Shift created successfully",
            "shiftId": shift_id,
            "shift": {
                "guardId": payload.guard_id,
                "startTime": payload.start_time,
                "endTime": payload.end_time,
                "clientSite": payload.client_site
            }
        })),
    ))
}

pub(crate) struct CheckInResult {
    pub attendance_id: String,
    pub already_recorded: bool,
}

pub(crate) async fn record_check_in(
    db: &PgPool,
    guard_id: &str,
    shift_id: &str,
    source: &str,
) -> AppResult<CheckInResult> {
    let mut tx = db
        .begin()
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to start check-in: {}", e)))?;

    let shift_guard = sqlx::query("SELECT guard_id FROM shifts WHERE id = $1 FOR UPDATE")
        .bind(shift_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Shift not found".to_string()))?;

    let assigned_guard_id: String = shift_guard
        .try_get("guard_id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse shift guard: {}", e)))?;

    if assigned_guard_id != guard_id {
        return Err(AppError::Forbidden(
            "Guard can only check in for their assigned shift".to_string(),
        ));
    }

    let existing_attendance = sqlx::query(
        "SELECT id, guard_id FROM attendance \
         WHERE shift_id = $1 \
         ORDER BY check_in_time ASC, created_at ASC \
         LIMIT 1",
    )
    .bind(shift_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to check attendance: {}", e)))?;

    if let Some(existing_attendance) = existing_attendance {
        let attendance_id: String = existing_attendance.try_get("id").map_err(|e| {
            AppError::DatabaseError(format!("Failed to parse attendance ID: {}", e))
        })?;
        let attendance_guard_id: String = existing_attendance.try_get("guard_id").map_err(|e| {
            AppError::DatabaseError(format!("Failed to parse attendance guard: {}", e))
        })?;

        if attendance_guard_id != guard_id {
            return Err(AppError::Conflict(
                "Shift already has attendance recorded for a different guard".to_string(),
            ));
        }

        tx.commit()
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to complete check-in: {}", e)))?;

        return Ok(CheckInResult {
            attendance_id,
            already_recorded: true,
        });
    }

    let attendance_id = utils::generate_id();

    sqlx::query(
        "INSERT INTO attendance (id, guard_id, shift_id, check_in_time, status, check_in_source) VALUES ($1, $2, $3, CURRENT_TIMESTAMP, 'checked_in', $4)"
    )
    .bind(&attendance_id)
    .bind(guard_id)
    .bind(shift_id)
    .bind(source)
    .execute(&mut *tx)
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
    .bind(guard_id)
    .bind(shift_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to record punctuality: {}", e)))?;

    tx.commit()
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to complete check-in: {}", e)))?;

    Ok(CheckInResult {
        attendance_id,
        already_recorded: false,
    })
}

pub async fn check_in(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CheckInRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    if payload.guard_id.is_empty() || payload.shift_id.is_empty() {
        return Err(AppError::BadRequest(
            "Guard ID and Shift ID are required".to_string(),
        ));
    }

    let _claims = utils::require_self_or_min_role(&headers, &payload.guard_id, "supervisor")?;
    let result =
        record_check_in(db.as_ref(), &payload.guard_id, &payload.shift_id, "manual").await?;

    Ok((
        if result.already_recorded {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(json!({
            "message": if result.already_recorded { "Check-in already recorded" } else { "Check-in recorded successfully" },
            "attendanceId": result.attendance_id
        })),
    ))
}

pub async fn check_out(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CheckOutRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if payload.attendance_id.is_empty() {
        return Err(AppError::BadRequest(
            "Attendance ID is required".to_string(),
        ));
    }

    let mut tx = db
        .begin()
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to start check-out: {}", e)))?;

    let attendance =
        sqlx::query("SELECT guard_id, check_out_time FROM attendance WHERE id = $1 FOR UPDATE")
            .bind(&payload.attendance_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
            .ok_or_else(|| AppError::NotFound("Attendance not found".to_string()))?;

    let attendance_guard_id: String = attendance
        .try_get("guard_id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse attendance guard: {}", e)))?;

    let _claims = utils::require_self_or_min_role(&headers, &attendance_guard_id, "supervisor")?;

    let existing_check_out: Option<chrono::DateTime<chrono::Utc>> = attendance
        .try_get("check_out_time")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse check-out time: {}", e)))?;

    if existing_check_out.is_some() {
        tx.commit()
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to complete check-out: {}", e)))?;

        return Ok(Json(json!({
            "message": "Check-out already recorded"
        })));
    }

    sqlx::query(
        "UPDATE attendance \
         SET check_out_time = CURRENT_TIMESTAMP, status = 'checked_out', updated_at = CURRENT_TIMESTAMP \
         WHERE id = $1 AND check_out_time IS NULL"
    )
    .bind(&payload.attendance_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    tx.commit()
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to complete check-out: {}", e)))?;

    Ok(Json(json!({
        "message": "Check-out recorded successfully"
    })))
}

pub async fn detect_no_shows(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    #[derive(sqlx::FromRow)]
    struct NoShowShift {
        id: String,
        guard_id: String,
        start_time: chrono::DateTime<chrono::Utc>,
        end_time: chrono::DateTime<chrono::Utc>,
        client_site: String,
    }

    let mut tx = db.begin().await.map_err(|e| {
        AppError::DatabaseError(format!("Failed to start no-show detection: {}", e))
    })?;

    let no_show_shifts = sqlx::query_as::<_, NoShowShift>(
        "WITH candidates AS (
             SELECT s.id
             FROM shifts s
             WHERE s.status = 'scheduled'
               AND (s.start_time + INTERVAL '1 minute' * COALESCE(s.grace_period_minutes, 15)) <= CURRENT_TIMESTAMP
               AND COALESCE(s.replacement_status, 'not_needed') = 'not_needed'
               AND NOT EXISTS (
                   SELECT 1 FROM attendance a WHERE a.shift_id = s.id
               )
             FOR UPDATE OF s SKIP LOCKED
         )
         UPDATE shifts s
         SET replacement_status = 'searching', updated_at = CURRENT_TIMESTAMP
         FROM candidates c
         WHERE s.id = c.id
         RETURNING s.id, s.guard_id, s.start_time, s.end_time, s.client_site"
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to detect no-shows: {}", e)))?;

    let mut notified_guards = Vec::new();

    for shift in &no_show_shifts {
        let punctuality_id = utils::generate_id();
        sqlx::query(
            "INSERT INTO punctuality_records (
                 id, guard_id, shift_id, scheduled_start_time, actual_check_in_time,
                 minutes_late, is_on_time, status
             )
             SELECT $1, $2, $3, $4, NULL, NULL, false, 'no_show'
             WHERE NOT EXISTS (
                 SELECT 1
                 FROM punctuality_records
                 WHERE shift_id = $3 AND guard_id = $2 AND status = 'no_show'
             )",
        )
        .bind(&punctuality_id)
        .bind(&shift.guard_id)
        .bind(&shift.id)
        .bind(shift.start_time)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            AppError::DatabaseError(format!("Failed to record no-show punctuality: {}", e))
        })?;

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
             AND u.role IN ('guard') 
             AND u.verified = true
             AND (ga.available IS NULL OR ga.available = true)
             AND NOT EXISTS (
                 SELECT 1 FROM shifts s2 
                 WHERE s2.guard_id = u.id 
                 AND s2.status IN ('scheduled', 'in_progress')
                 AND s2.start_time <= $2 
                 AND s2.end_time >= $3
             )
             LIMIT 20",
        )
        .bind(&shift.guard_id)
        .bind(&shift.end_time)
        .bind(&shift.start_time)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to find available guards: {}", e)))?;

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
            .execute(&mut *tx)
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
            shift.id,
            shift.guard_id,
            available_guards.len()
        );
    }

    tx.commit().await.map_err(|e| {
        AppError::DatabaseError(format!("Failed to complete no-show detection: {}", e))
    })?;

    Ok(Json(json!({
        "message": "No-show detection completed",
        "noShowsCount": no_show_shifts.len(),
        "notifiedGuards": notified_guards
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmReplacementRequest {
    shift_id: String,
    original_guard_id: String,
    replacement_guard_id: String,
    shift_updated_at: DateTime<Utc>,
    confirmed_available: bool,
}

#[derive(sqlx::FromRow)]
struct ReplacementShift {
    guard_id: String,
    client_site: String,
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    status: String,
    updated_at: DateTime<Utc>,
    grace_minutes: i64,
}

fn replacement_database_error(error: sqlx::Error) -> AppError {
    AppError::DatabaseError(format!("Could not confirm guard replacement: {error}"))
}

pub async fn confirm_replacement(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<ConfirmReplacementRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let claims = utils::require_min_role(&headers, "supervisor")?;
    if !payload.confirmed_available {
        return Err(AppError::BadRequest(
            "Confirm the guard agreed to cover the remaining shift first.".to_string(),
        ));
    }
    if payload.shift_id.trim().is_empty()
        || payload.original_guard_id.trim().is_empty()
        || payload.replacement_guard_id.trim().is_empty()
        || payload.original_guard_id == payload.replacement_guard_id
    {
        return Err(AppError::BadRequest(
            "Select a different guard for this shift.".to_string(),
        ));
    }

    let mut tx = db.begin().await.map_err(replacement_database_error)?;
    let shift: ReplacementShift = sqlx::query_as(
        r#"SELECT guard_id, client_site, start_time, end_time, status, updated_at,
                  COALESCE(grace_period_minutes::bigint, $2) AS grace_minutes
           FROM shifts WHERE id = $1 FOR UPDATE"#,
    )
    .bind(&payload.shift_id)
    .bind(check_in_grace_minutes())
    .fetch_optional(&mut *tx)
    .await
    .map_err(replacement_database_error)?
    .ok_or_else(|| AppError::NotFound("Shift not found.".to_string()))?;
    if shift.guard_id != payload.original_guard_id || shift.updated_at != payload.shift_updated_at {
        return Err(AppError::Conflict(
            "The shift changed. Refresh it before choosing a replacement.".to_string(),
        ));
    }

    let has_attendance: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM attendance WHERE shift_id = $1)",
    )
    .bind(&payload.shift_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(replacement_database_error)?;
    if has_attendance {
        return Err(AppError::Conflict(
            "Attendance is already recorded for this shift.".to_string(),
        ));
    }

    let site_matches: Vec<String> = sqlx::query_scalar(
        r#"SELECT id FROM client_sites
           WHERE is_active = true
             AND LOWER(BTRIM($1)) NOT IN ('', 'n/a', 'na', 'none', 'unassigned', '-', '—')
             AND (id = BTRIM($1) OR LOWER(BTRIM(name)) = LOWER(BTRIM($1)))
           ORDER BY (id = BTRIM($1)) DESC, id LIMIT 2 FOR SHARE"#,
    )
    .bind(&shift.client_site)
    .fetch_all(&mut *tx)
    .await
    .map_err(replacement_database_error)?;
    let site_id = match site_matches.as_slice() {
        [id] => id,
        [id, ..] if id == shift.client_site.trim() => id,
        _ => {
            return Err(AppError::Conflict(
                "Set an active client site on this shift in Schedule before assigning coverage."
                    .to_string(),
            ));
        }
    };

    let candidate: Option<(String, bool, String, String)> = sqlx::query_as(
        r#"SELECT role, COALESCE(verified, false), COALESCE(approval_status, 'approved'),
                  COALESCE(status, 'active')
           FROM users WHERE id = $1 FOR UPDATE"#,
    )
    .bind(&payload.replacement_guard_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(replacement_database_error)?;
    let candidate_eligible = candidate.is_some_and(|(role, verified, approval, status)| {
        is_approved_guard(&role, verified, &approval) && status.trim().eq_ignore_ascii_case("active")
    });
    if !candidate_eligible {
        return Err(AppError::Conflict(
            "The selected guard is no longer active and eligible for coverage.".to_string(),
        ));
    }

    let availability: Option<(bool, Option<DateTime<Utc>>, Option<DateTime<Utc>>)> =
        sqlx::query_as(
            r#"SELECT available, available_from, available_to FROM guard_availability
               WHERE guard_id = $1
               ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST, id DESC
               LIMIT 1 FOR UPDATE"#,
        )
        .bind(&payload.replacement_guard_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(replacement_database_error)?;

    // Writes use actual time, even when a presentation read clock is configured.
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await
        .map_err(replacement_database_error)?;
    let explicit_absence = matches!(shift.status.as_str(), "absent" | "no_show");
    let missed_check_in = shift.status == "scheduled"
        && shift.start_time + Duration::minutes(shift.grace_minutes) <= now;
    if shift.start_time > now || shift.end_time <= now || (!explicit_absence && !missed_check_in) {
        return Err(AppError::Conflict(
            "This shift no longer needs replacement coverage.".to_string(),
        ));
    }
    if availability.is_some_and(|(available, from, to)| {
        !available || from.is_some_and(|from| from > now) || to.is_some_and(|to| to < shift.end_time)
    }) {
        return Err(AppError::Conflict(
            "The selected guard is unavailable for the remaining shift.".to_string(),
        ));
    }
    let overlapping: bool = sqlx::query_scalar(
        r#"SELECT EXISTS (
               SELECT 1 FROM shifts
               WHERE guard_id = $1 AND id <> $2 AND status IN ('scheduled', 'in_progress')
                 AND start_time < $3 AND end_time > $4
           )"#,
    )
    .bind(&payload.replacement_guard_id)
    .bind(&payload.shift_id)
    .bind(shift.end_time)
    .bind(now)
    .fetch_one(&mut *tx)
    .await
    .map_err(replacement_database_error)?;
    if overlapping {
        return Err(AppError::Conflict(
            "The selected guard has an overlapping shift during the remaining coverage."
                .to_string(),
        ));
    }

    let covered_from: DateTime<Utc> = sqlx::query_scalar(
        r#"UPDATE shifts SET guard_id = $1, status = 'scheduled', replacement_status = 'accepted',
                            start_time = $2, updated_at = $2
           WHERE id = $3 AND end_time > clock_timestamp() RETURNING start_time"#,
    )
    .bind(&payload.replacement_guard_id)
    .bind(now)
    .bind(&payload.shift_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(replacement_database_error)?
    .ok_or_else(|| AppError::Conflict("The shift has already ended.".to_string()))?;

    if explicit_absence {
        sqlx::query(
            r#"INSERT INTO punctuality_records (
                   id, guard_id, shift_id, scheduled_start_time, is_on_time, status
               ) SELECT $1, $2, $3, $4, false, 'no_show'
                 WHERE NOT EXISTS (
                     SELECT 1 FROM punctuality_records
                     WHERE guard_id = $2 AND shift_id = $3 AND status = 'no_show'
                 )"#,
        )
        .bind(utils::generate_id())
        .bind(&shift.guard_id)
        .bind(&payload.shift_id)
        .bind(shift.start_time)
        .execute(&mut *tx)
        .await
        .map_err(replacement_database_error)?;
    }

    let history_id = utils::generate_id();
    let metadata = json!({
        "replacementId": history_id,
        "originalGuardId": shift.guard_id,
        "replacementGuardId": payload.replacement_guard_id,
        "confirmedBy": claims.sub,
        "confirmationSource": "supervisor_reported_guard_confirmation",
        "coverage": "unarmed",
        "siteId": site_id,
        "clientSite": shift.client_site,
        "originalStatus": shift.status,
        "originalShiftUpdatedAt": shift.updated_at,
        "originalStartTime": shift.start_time,
        "coverageStartTime": covered_from,
        "endTime": shift.end_time,
    });

    // The legacy history table requires numeric scores. This manual decision has no model scores.
    sqlx::query(
        r#"INSERT INTO smart_guard_replacements (
               id, shift_id, absent_guard_id, recommended_guard_id, compatibility_score,
               confidence_score, rationale, scoring_breakdown, recommendation_status,
               feature_version
           ) VALUES ($1, $2, $3, $4, 0, 0, $5, $6, 'accepted', 'supervisor-confirmed-v1')"#,
    )
    .bind(&history_id)
    .bind(&payload.shift_id)
    .bind(&shift.guard_id)
    .bind(&payload.replacement_guard_id)
    .bind("Supervisor confirmed the guard agreed to cover the remaining unarmed shift.")
    .bind(&metadata)
    .execute(&mut *tx)
    .await
    .map_err(replacement_database_error)?;

    sqlx::query(
        r#"INSERT INTO audit_logs (id, actor_user_id, action_key, entity_type, entity_id, result, metadata)
           VALUES ($1, $2, 'shift.replacement.confirmed', 'shift', $3, 'success', $4)"#,
    )
    .bind(utils::generate_id())
    .bind(&claims.sub)
    .bind(&payload.shift_id)
    .bind(&metadata)
    .execute(&mut *tx)
    .await
    .map_err(replacement_database_error)?;

    tx.commit().await.map_err(replacement_database_error)?;
    Ok(Json(json!({
        "message": "Replacement guard assigned to the remaining shift.",
        "shiftId": payload.shift_id,
        "guardId": payload.replacement_guard_id,
        "replacementId": history_id,
        "coverageStartTime": covered_from,
        "endTime": shift.end_time,
    })))
}

pub async fn request_replacement(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<RequestReplacementRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if payload.original_guard_id.is_empty()
        || payload.replacement_guard_id.is_empty()
        || payload.shift_id.is_empty()
    {
        return Err(AppError::BadRequest(
            "Original Guard ID, Replacement Guard ID, and Shift ID are required".to_string(),
        ));
    }

    let _claims =
        utils::require_self_or_min_role(&headers, &payload.original_guard_id, "supervisor")?;

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

    let shift_row = sqlx::query("SELECT id, start_time, end_time FROM shifts WHERE id = $1")
        .bind(&payload.shift_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Shift not found".to_string()))?;

    let shift_start: chrono::DateTime<chrono::Utc> = shift_row
        .try_get("start_time")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse shift start_time: {}", e)))?;
    let shift_end: chrono::DateTime<chrono::Utc> = shift_row
        .try_get("end_time")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse shift end_time: {}", e)))?;

    if guard_has_shift_conflict(
        db.as_ref(),
        &payload.replacement_guard_id,
        shift_start,
        shift_end,
        Some(&payload.shift_id),
    )
    .await?
    {
        return Err(AppError::Conflict(
            "Replacement guard already has an overlapping scheduled or in-progress shift"
                .to_string(),
        ));
    }

    // Update shift to use replacement guard
    sqlx::query("UPDATE shifts SET guard_id = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2")
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
        return Err(AppError::BadRequest("Guard ID is required".to_string()));
    }

    let _claims = utils::require_self_or_min_role(&headers, &payload.guard_id, "supervisor")?;

    // Availability is a guard status. Supervisors can update it for operations,
    // but the target account must still be a guard.
    let guard_role = sqlx::query_scalar::<_, String>("SELECT role FROM users WHERE id = $1")
        .bind(&payload.guard_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Guard not found".to_string()))?;

    if utils::normalize_role(&guard_role) != "guard" {
        return Err(AppError::BadRequest(
            "Availability can only be set for guard accounts".to_string(),
        ));
    }

    if let (Some(from), Some(to)) = (payload.available_from, payload.available_to) {
        if to <= from {
            return Err(AppError::BadRequest(
                "availableTo must be later than availableFrom".to_string(),
            ));
        }
    }

    let available = payload.available.unwrap_or(true);
    let notes = payload
        .notes
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    // Check if availability record exists
    let existing = sqlx::query(
        "SELECT id FROM guard_availability WHERE guard_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&payload.guard_id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    if existing.is_some() {
        // Update existing record
        sqlx::query(
            "UPDATE guard_availability 
             SET available = $1, available_from = $2, available_to = $3, notes = $4,
                 updated_at = CURRENT_TIMESTAMP
             WHERE guard_id = $5",
        )
        .bind(available)
        .bind(payload.available_from)
        .bind(payload.available_to)
        .bind(notes)
        .bind(&payload.guard_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update availability: {}", e)))?;
    } else {
        // Create new record
        let id = utils::generate_id();
        sqlx::query(
            "INSERT INTO guard_availability
             (id, guard_id, available, available_from, available_to, notes)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&id)
        .bind(&payload.guard_id)
        .bind(available)
        .bind(payload.available_from)
        .bind(payload.available_to)
        .bind(notes)
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
    let guard_id = payload
        .get("guardId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Guard ID is required".to_string()))?;

    let shift_id = payload
        .get("shiftId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Shift ID is required".to_string()))?;

    let notification_id = payload.get("notificationId").and_then(|v| v.as_str());

    // Verify guard exists
    sqlx::query("SELECT id FROM users WHERE id = $1")
        .bind(guard_id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Guard not found".to_string()))?;

    // Verify shift exists and needs replacement
    let shift = sqlx::query(
        "SELECT id, replacement_status, start_time, end_time FROM shifts WHERE id = $1",
    )
    .bind(shift_id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Shift not found".to_string()))?;

    let shift_start: chrono::DateTime<chrono::Utc> = shift
        .try_get("start_time")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse shift start_time: {}", e)))?;
    let shift_end: chrono::DateTime<chrono::Utc> = shift
        .try_get("end_time")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse shift end_time: {}", e)))?;

    if guard_has_shift_conflict(
        db.as_ref(),
        guard_id,
        shift_start,
        shift_end,
        Some(shift_id),
    )
    .await?
    {
        return Err(AppError::Conflict(
            "Guard already has an overlapping scheduled or in-progress shift".to_string(),
        ));
    }

    // Update shift with new guard and mark as accepted
    sqlx::query(
        "UPDATE shifts 
         SET guard_id = $1, replacement_status = 'accepted', updated_at = CURRENT_TIMESTAMP 
         WHERE id = $2",
    )
    .bind(guard_id)
    .bind(shift_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to accept replacement: {}", e)))?;

    // Mark the notification as read if provided
    if let Some(notif_id) = notification_id {
        sqlx::query(
            "UPDATE notifications SET read = true, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
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
         WHERE related_shift_id = $1 AND type = 'replacement_request' AND read = false",
    )
    .bind(shift_id)
    .execute(db.as_ref())
    .await
    .ok(); // Ignore errors

    tracing::info!(
        "Replacement accepted: Guard {} accepted shift {}",
        guard_id,
        shift_id
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
    headers: HeaderMap,
    Path(guard_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_self_or_min_role(&headers, &guard_id, "supervisor")?;

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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadinessQuery {
    pub shift_id: String,
}

async fn verify_guard_shift(db: &PgPool, guard_id: &str, shift_id: &str) -> AppResult<()> {
    let guard_role = sqlx::query_scalar::<_, String>(
        "SELECT u.role
         FROM shifts s
         JOIN users u ON u.id = s.guard_id
         WHERE s.id = $1 AND s.guard_id = $2",
    )
    .bind(shift_id)
    .bind(guard_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to verify assigned shift: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Assigned shift not found".to_string()))?;

    if utils::normalize_role(&guard_role) != "guard" {
        return Err(AppError::BadRequest(
            "Readiness can only be recorded for guard shifts".to_string(),
        ));
    }

    Ok(())
}

pub async fn get_guard_shift_readiness(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(guard_id): Path<String>,
    Query(query): Query<ReadinessQuery>,
) -> AppResult<Json<serde_json::Value>> {
    if guard_id.is_empty() || query.shift_id.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Guard ID and shift ID are required".to_string(),
        ));
    }

    let _claims = utils::require_self_or_min_role(&headers, &guard_id, "supervisor")?;
    verify_guard_shift(db.as_ref(), &guard_id, &query.shift_id).await?;

    let row = sqlx::query(
        "SELECT checked_items, notes, updated_at
         FROM guard_shift_readiness
         WHERE guard_id = $1 AND shift_id = $2
         LIMIT 1",
    )
    .bind(&guard_id)
    .bind(&query.shift_id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to load shift readiness: {}", e)))?;

    let (checked_items, notes, updated_at) = match row {
        Some(row) => {
            let value = row
                .try_get::<serde_json::Value, _>("checked_items")
                .map_err(|e| {
                    AppError::DatabaseError(format!("Failed to parse readiness items: {}", e))
                })?;
            let items = serde_json::from_value::<Vec<String>>(value).map_err(|e| {
                AppError::DatabaseError(format!("Failed to decode readiness items: {}", e))
            })?;
            let notes = row.try_get::<Option<String>, _>("notes").map_err(|e| {
                AppError::DatabaseError(format!("Failed to parse readiness notes: {}", e))
            })?;
            let updated_at = row
                .try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
                .map_err(|e| {
                    AppError::DatabaseError(format!("Failed to parse readiness timestamp: {}", e))
                })?;
            (items, notes, Some(updated_at))
        }
        None => (Vec::new(), None, None),
    };
    let ready = checked_items.len() == READINESS_ITEMS.len();

    Ok(Json(json!({
        "shiftId": query.shift_id,
        "guardId": guard_id,
        "checkedItems": checked_items,
        "ready": ready,
        "notes": notes,
        "updatedAt": updated_at,
        "requiredItems": READINESS_ITEMS,
    })))
}

pub async fn set_guard_shift_readiness(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<SetShiftReadinessRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if payload.guard_id.trim().is_empty() || payload.shift_id.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Guard ID and shift ID are required".to_string(),
        ));
    }

    let _claims = utils::require_self_or_min_role(&headers, &payload.guard_id, "supervisor")?;
    let checked_items = normalize_readiness_items(&payload.checked_items)?;
    verify_guard_shift(db.as_ref(), &payload.guard_id, &payload.shift_id).await?;

    let notes = payload
        .notes
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if notes.is_some_and(|value| value.chars().count() > 1000) {
        return Err(AppError::BadRequest(
            "Readiness notes cannot exceed 1000 characters".to_string(),
        ));
    }

    let checked_items_json = serde_json::to_value(&checked_items).map_err(|e| {
        AppError::InternalServerError(format!("Failed to encode readiness items: {}", e))
    })?;

    sqlx::query(
        "INSERT INTO guard_shift_readiness
         (id, shift_id, guard_id, checked_items, notes)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (shift_id, guard_id)
         DO UPDATE SET checked_items = EXCLUDED.checked_items,
                       notes = EXCLUDED.notes,
                       updated_at = CURRENT_TIMESTAMP",
    )
    .bind(utils::generate_id())
    .bind(&payload.shift_id)
    .bind(&payload.guard_id)
    .bind(checked_items_json)
    .bind(notes)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to save shift readiness: {}", e)))?;
    let ready = checked_items.len() == READINESS_ITEMS.len();

    Ok(Json(json!({
        "message": "Shift readiness saved successfully",
        "shiftId": payload.shift_id,
        "guardId": payload.guard_id,
        "checkedItems": checked_items,
        "ready": ready,
    })))
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

#[derive(Deserialize)]
pub struct AllShiftsQuery {
    page: Option<i64>,
    page_size: Option<i64>,
    scope: Option<String>,
}

// Get all shifts with guard information (admin view)
pub async fn get_all_shifts(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Query(query): Query<AllShiftsQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let today_only = match query.scope.as_deref() {
        None => false,
        Some("today") => true,
        Some(_) => return Err(AppError::BadRequest("Unknown shift scope.".to_string())),
    };
    let (page, page_size, offset) = utils::resolve_pagination(
        utils::PaginationQuery {
            page: query.page,
            page_size: query.page_size,
        },
        40,
        200,
    );

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
        missed_check_in: bool,
        replacement_eligible: bool,
        replacement_status: String,
        replacement_site_id: Option<String>,
        availability_available: Option<bool>,
        availability_updated_at: Option<chrono::DateTime<chrono::Utc>>,
        readiness_ready: Option<bool>,
        readiness_updated_at: Option<chrono::DateTime<chrono::Utc>>,
        created_at: chrono::DateTime<chrono::Utc>,
        updated_at: chrono::DateTime<chrono::Utc>,
    }

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM shifts
           WHERE NOT $1 OR (
               start_time < ((timezone('Asia/Manila', CURRENT_TIMESTAMP)::date + 1)::timestamp AT TIME ZONE 'Asia/Manila')
               AND end_time > (timezone('Asia/Manila', CURRENT_TIMESTAMP)::date::timestamp AT TIME ZONE 'Asia/Manila')
           )"#,
    )
        .bind(today_only)
        .fetch_one(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let shifts = sqlx::query_as::<_, ShiftWithGuard>(
        r#"SELECT s.id, s.guard_id, u.full_name as guard_name, u.username as guard_username,
         s.start_time, s.end_time, s.client_site, s.status,
         check_in.missed AS missed_check_in,
         (
           s.start_time <= CURRENT_TIMESTAMP AND s.end_time > CURRENT_TIMESTAMP
           AND (check_in.missed OR s.status IN ('absent', 'no_show'))
           AND NOT EXISTS (SELECT 1 FROM attendance a WHERE a.shift_id = s.id)
         ) AS replacement_eligible,
         COALESCE(s.replacement_status, 'not_needed') AS replacement_status,
         replacement_site.id AS replacement_site_id,
         ga.available AS availability_available,
         ga.updated_at AS availability_updated_at,
         CASE WHEN gsr.checked_items IS NULL THEN NULL
              WHEN jsonb_typeof(gsr.checked_items) <> 'array' THEN false
              ELSE jsonb_array_length(gsr.checked_items) = 3 END AS readiness_ready,
         gsr.updated_at AS readiness_updated_at,
         s.created_at, s.updated_at
         FROM shifts s
         JOIN users u ON s.guard_id = u.id
         CROSS JOIN LATERAL (
             SELECT s.status = 'scheduled'
                 AND s.start_time + COALESCE(s.grace_period_minutes::bigint, $4) * INTERVAL '1 minute' <= CURRENT_TIMESTAMP
                 AND NOT EXISTS (
                     SELECT 1 FROM attendance a
                     WHERE a.shift_id = s.id AND a.guard_id = s.guard_id AND a.check_in_time IS NOT NULL
                 ) AS missed
         ) check_in
         LEFT JOIN LATERAL (
             SELECT COALESCE(MAX(cs.id) FILTER (WHERE cs.id = BTRIM(s.client_site)),
                             CASE WHEN COUNT(*) = 1 THEN MIN(cs.id) END) AS id
             FROM client_sites cs
             WHERE cs.is_active = true
               AND LOWER(BTRIM(s.client_site)) NOT IN ('', 'n/a', 'na', 'none', 'unassigned', '-', '—')
               AND (cs.id = BTRIM(s.client_site) OR LOWER(BTRIM(cs.name)) = LOWER(BTRIM(s.client_site)))
         ) replacement_site ON true
         LEFT JOIN LATERAL (
             SELECT available, updated_at
             FROM guard_availability
             WHERE guard_id = s.guard_id
             ORDER BY updated_at DESC
             LIMIT 1
         ) ga ON true
         LEFT JOIN guard_shift_readiness gsr
           ON gsr.shift_id = s.id AND gsr.guard_id = s.guard_id
         WHERE NOT $3 OR (
             s.start_time < ((timezone('Asia/Manila', CURRENT_TIMESTAMP)::date + 1)::timestamp AT TIME ZONE 'Asia/Manila')
             AND s.end_time > (timezone('Asia/Manila', CURRENT_TIMESTAMP)::date::timestamp AT TIME ZONE 'Asia/Manila')
         )
         ORDER BY ($3 AND s.start_time <= CURRENT_TIMESTAMP AND s.end_time > CURRENT_TIMESTAMP) DESC,
                  s.start_time DESC, s.id
         LIMIT $1 OFFSET $2"#,
    )
    .bind(page_size)
    .bind(offset)
    .bind(today_only)
    .bind(check_in_grace_minutes())
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

    if payload.guard_id.is_empty()
        || payload.start_time.is_empty()
        || payload.end_time.is_empty()
        || payload.client_site.is_empty()
    {
        return Err(AppError::BadRequest("All fields are required".to_string()));
    }

    require_approved_guard(db.as_ref(), &payload.guard_id).await?;

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

    if end_time <= start_time {
        return Err(AppError::BadRequest(
            "end_time must be later than start_time".to_string(),
        ));
    }

    if guard_has_shift_conflict(
        db.as_ref(),
        &payload.guard_id,
        start_time,
        end_time,
        Some(&shift_id),
    )
    .await?
    {
        return Err(AppError::Conflict(
            "Guard already has an overlapping scheduled or in-progress shift".to_string(),
        ));
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approved_guard_check_rejects_wrong_role_or_status() {
        assert!(is_approved_guard("guard", true, "approved"));
        assert!(is_approved_guard(" GUARD ", true, "Approved"));
        assert!(!is_approved_guard("admin", true, "approved"));
        assert!(!is_approved_guard("guard", false, "approved"));
        assert!(!is_approved_guard("guard", true, "pending"));
    }

    #[test]
    fn readiness_items_are_whitelisted_and_deduplicated() {
        let valid = vec!["uniform".to_string(), " ENDORSEMENT_FORM ".to_string()];
        assert_eq!(
            normalize_readiness_items(&valid).expect("valid readiness items"),
            vec!["uniform", "endorsement_form"]
        );

        let unknown = vec!["keys".to_string()];
        assert!(normalize_readiness_items(&unknown).is_err());

        let duplicate = vec!["uniform".to_string(), "UNIFORM".to_string()];
        assert!(normalize_readiness_items(&duplicate).is_err());
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires an isolated PostgreSQL instance"]
    async fn supervisor_confirms_exact_remaining_shift_and_preserves_original_guard(pool: PgPool) {
        crate::db::run_migrations(&pool).await.unwrap();
        sqlx::query("INSERT INTO users (id, username, email, password, role, verified, full_name, phone_number) VALUES
            ('leader', 'leader', 'leader@example.test', 'fixture', 'supervisor', true, 'Fixture Leader', ''),
            ('original', 'original', 'original@example.test', 'fixture', 'guard', true, 'Original Guard', ''),
            ('replacement', 'replacement', 'replacement@example.test', 'fixture', 'guard', true, 'Replacement Guard', ''),
            ('backup', 'backup', 'backup@example.test', 'fixture', 'guard', true, 'Backup Guard', '')")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO client_sites (id, name, latitude, longitude) VALUES ('site', 'Fixture Post', 7, 125)")
            .execute(&pool).await.unwrap();
        let (version, original_start): (DateTime<Utc>, DateTime<Utc>) = sqlx::query_as(
            "INSERT INTO shifts (id, guard_id, client_site, start_time, end_time, status)
             VALUES ('target', 'original', 'Fixture Post', NOW() - INTERVAL '45 minutes', NOW() + INTERVAL '2 hours', 'scheduled')
             RETURNING updated_at, start_time",
        ).fetch_one(&pool).await.unwrap();
        let leader_token = utils::generate_access_token("leader", "leader@example.test", "supervisor", true).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {leader_token}").parse().unwrap());
        let Json(before) = get_all_shifts(State(Arc::new(pool.clone())), headers, Query(AllShiftsQuery {
            page: None, page_size: None, scope: Some("today".into()),
        })).await.unwrap();
        assert_eq!(before["shifts"][0]["missed_check_in"], true);
        assert_eq!(before["shifts"][0]["replacement_eligible"], true);
        assert_eq!(before["shifts"][0]["replacement_site_id"], "site");
        let submit = |id: &str, role: &str, confirmed: bool| {
            let token = utils::generate_access_token(id, "fixture@example.test", role, true).unwrap();
            let mut headers = HeaderMap::new();
            headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());
            confirm_replacement(State(Arc::new(pool.clone())), headers, Json(ConfirmReplacementRequest {
                shift_id: "target".into(), original_guard_id: "original".into(), replacement_guard_id: "replacement".into(),
                shift_updated_at: version, confirmed_available: confirmed,
            }))
        };
        assert!(matches!(submit("original", "guard", true).await, Err(AppError::Forbidden(_))));
        assert!(matches!(submit("leader", "supervisor", false).await, Err(AppError::BadRequest(_))));
        let (first, second) = tokio::join!(submit("leader", "supervisor", true), submit("leader", "supervisor", true));
        assert!(matches!((first, second), (Ok(_), Err(AppError::Conflict(_))) | (Err(AppError::Conflict(_)), Ok(_))));

        let (assigned, starts_at, status): (String, DateTime<Utc>, String) = sqlx::query_as(
            "SELECT guard_id, start_time, replacement_status FROM shifts WHERE id = 'target'",
        ).fetch_one(&pool).await.unwrap();
        assert_eq!((assigned.as_str(), status.as_str()), ("replacement", "accepted"));
        assert!(starts_at > original_start);
        let audit: (i64, Option<String>) = sqlx::query_as(
            "SELECT COUNT(*), MAX(metadata->>'originalGuardId') FROM audit_logs WHERE action_key = 'shift.replacement.confirmed' AND entity_id = 'target'",
        ).fetch_one(&pool).await.unwrap();
        assert_eq!(audit, (1, Some("original".into())));
        let attendance: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM attendance WHERE shift_id = 'target'")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(attendance, 0);

        let retry_handoff = |shift_updated_at: DateTime<Utc>| {
            let mut headers = HeaderMap::new();
            headers.insert("Authorization", format!("Bearer {leader_token}").parse().unwrap());
            confirm_replacement(State(Arc::new(pool.clone())), headers, Json(ConfirmReplacementRequest {
                shift_id: "target".into(), original_guard_id: "replacement".into(), replacement_guard_id: "backup".into(),
                shift_updated_at, confirmed_available: true,
            }))
        };
        assert!(matches!(retry_handoff(starts_at).await, Err(AppError::Conflict(_))));

        let overdue_version: DateTime<Utc> = sqlx::query_scalar(
            "UPDATE shifts SET start_time = NOW() - INTERVAL '20 minutes', updated_at = NOW()
             WHERE id = 'target' RETURNING updated_at",
        ).fetch_one(&pool).await.unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {leader_token}").parse().unwrap());
        let Json(overdue) = get_all_shifts(State(Arc::new(pool.clone())), headers, Query(AllShiftsQuery {
            page: None, page_size: None, scope: Some("today".into()),
        })).await.unwrap();
        assert_eq!(overdue["shifts"][0]["replacement_eligible"], true);
        assert_eq!(overdue["shifts"][0]["guard_id"], "replacement");
        let candidates = crate::services::replacement_scoring_service::suggest_shift_replacement(&pool, "site", "target").await.unwrap();
        assert!(candidates.iter().any(|guard| guard.guard_id == "backup"));
        assert!(!candidates.iter().any(|guard| guard.guard_id == "replacement"));
        let _ = retry_handoff(overdue_version).await.unwrap();
        let previous_guards: Vec<String> = sqlx::query_scalar(
            "SELECT absent_guard_id FROM smart_guard_replacements WHERE shift_id = 'target' ORDER BY created_at",
        ).fetch_all(&pool).await.unwrap();
        assert_eq!(previous_guards, ["original", "replacement"]);
    }
}
