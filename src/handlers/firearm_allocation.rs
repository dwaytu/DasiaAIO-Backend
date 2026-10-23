use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::NaiveDate;
use serde::Deserialize;
use serde_json::json;
use sqlx::{PgPool, Row};
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    models::{
        AllocationListView, FirearmAllocation, GuardAllocationView, IssueFirearmRequest,
        ReturnFirearmRequest,
    },
    utils,
};

#[derive(Debug, Deserialize)]
pub struct AllocationListQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub search: Option<String>,
    pub status: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EligibleGuardQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub search: Option<String>,
}

const CORE_ISSUE_GUARD_SQL: &str = r#"
    SELECT EXISTS(
        SELECT 1
        FROM users u
        WHERE u.id = $1
          AND LOWER(BTRIM(u.role)) = 'guard'
          AND COALESCE(LOWER(BTRIM(u.status)), 'active') = 'active'
          AND COALESCE(LOWER(BTRIM(u.approval_status)), 'approved') = 'approved'
    )
"#;

const ELIGIBLE_ISSUE_GUARD_SQL: &str =
    "SELECT EXISTS(SELECT 1 FROM firearm_eligible_guards WHERE id = $1)";

fn normalized_filter(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let normalized = value.trim().to_string();
        (!normalized.is_empty()).then_some(normalized)
    })
}

fn date_filter(value: Option<String>, label: &str) -> AppResult<Option<String>> {
    let Some(value) = normalized_filter(value) else {
        return Ok(None);
    };

    NaiveDate::parse_from_str(&value, "%Y-%m-%d")
        .map_err(|_| AppError::BadRequest(format!("{label} must use YYYY-MM-DD format")))?;
    Ok(Some(value))
}

async fn record_force_allocation(
    db: &PgPool,
    actor_user_id: &str,
    actor_role: &str,
    allocation_id: &str,
    firearm_id: &str,
    guard_id: &str,
) -> AppResult<()> {
    sqlx::query(
        r#"INSERT INTO audit_logs (
                id, actor_user_id, action_key, entity_type, entity_id, result, reason, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
    )
    .bind(utils::generate_id())
    .bind(actor_user_id)
    .bind("FIREARM_ALLOCATION_FORCE_ISSUED")
    .bind("firearm_allocation")
    .bind(allocation_id)
    .bind("success")
    .bind("Authorized force override bypassed permit and training eligibility checks")
    .bind(json!({
        "firearmId": firearm_id,
        "guardId": guard_id,
        "actorRole": utils::normalize_role(actor_role),
        "override": "permit_and_training_only",
    }))
    .execute(db)
    .await
    .map_err(|error| {
        AppError::DatabaseError(format!("Failed to audit firearm override: {error}"))
    })?;

    Ok(())
}

pub async fn issue_firearm(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<IssueFirearmRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let claims = utils::require_min_role(&headers, "supervisor")?;

    if payload.firearm_id.is_empty() || payload.guard_id.is_empty() {
        return Err(AppError::BadRequest(
            "Firearm ID and Guard ID are required".to_string(),
        ));
    }

    let force = payload.force.unwrap_or(false);
    if force
        && !matches!(
            utils::normalize_role(&claims.role).as_str(),
            "admin" | "superadmin"
        )
    {
        return Err(AppError::Forbidden(
            "Only administrators may use the firearm allocation override".to_string(),
        ));
    }

    let valid_issue_guard: bool = sqlx::query_scalar(CORE_ISSUE_GUARD_SQL)
        .bind(&payload.guard_id)
        .fetch_one(db.as_ref())
        .await
        .map_err(|error| {
            AppError::DatabaseError(format!("Guard eligibility check failed: {error}"))
        })?;
    if !valid_issue_guard {
        return Err(AppError::BadRequest(
            "Select an active, approved guard account for firearm issuance".to_string(),
        ));
    }

    if !force {
        let eligible: bool = sqlx::query_scalar(ELIGIBLE_ISSUE_GUARD_SQL)
            .bind(&payload.guard_id)
            .fetch_one(db.as_ref())
            .await
            .map_err(|error| {
                AppError::DatabaseError(format!("Guard eligibility check failed: {error}"))
            })?;
        if !eligible {
            return Err(AppError::Forbidden(
                "Guard does not have a valid firearm permit and firearms-handling training"
                    .to_string(),
            ));
        }
    }

    // ── 1. Check firearm exists and is available ─────────────────────────────
    let mut transaction = db.begin().await.map_err(|error| {
        AppError::DatabaseError(format!("Failed to start allocation transaction: {error}"))
    })?;

    let firearm_row = sqlx::query("SELECT id, status FROM firearms WHERE id = $1 FOR UPDATE")
        .bind(&payload.firearm_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Firearm not found".to_string()))?;

    let firearm_status: String = firearm_row.get("status");
    if firearm_status != "available" {
        return Err(AppError::BadRequest(format!(
            "Firearm is not available for allocation (current status: {})",
            firearm_status
        )));
    }

    // ── 2. Check guard exists ────────────────────────────────────────────────
    // ── 3. Authorization: valid permit check ─────────────────────────────────
    // ── 4. Authorization: firearms_handling training check ───────────────────
    // ── 5. Create allocation ─────────────────────────────────────────────────
    let allocation_id = utils::generate_id();

    sqlx::query(
        r#"INSERT INTO firearm_allocations
               (id, guard_id, firearm_id, allocation_date, status,
                issued_by, expected_return_date, notes)
           VALUES ($1, $2, $3, CURRENT_TIMESTAMP, 'active', $4, $5, $6)"#,
    )
    .bind(&allocation_id)
    .bind(&payload.guard_id)
    .bind(&payload.firearm_id)
    .bind(payload.issued_by.as_deref())
    .bind(payload.expected_return_date)
    .bind(payload.notes.as_deref())
    .execute(&mut *transaction)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create allocation: {}", e)))?;

    // Update firearm status
    sqlx::query(
        "UPDATE firearms SET status = 'allocated', updated_at = CURRENT_TIMESTAMP WHERE id = $1",
    )
    .bind(&payload.firearm_id)
    .execute(&mut *transaction)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to update firearm: {}", e)))?;

    transaction.commit().await.map_err(|error| {
        AppError::DatabaseError(format!("Failed to commit firearm allocation: {error}"))
    })?;

    if force {
        record_force_allocation(
            db.as_ref(),
            &claims.sub,
            &claims.role,
            &allocation_id,
            &payload.firearm_id,
            &payload.guard_id,
        )
        .await?;
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Firearm allocated successfully",
            "allocationId": allocation_id
        })),
    ))
}

pub async fn return_firearm(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<ReturnFirearmRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    if payload.allocation_id.is_empty() {
        return Err(AppError::BadRequest(
            "Allocation ID is required".to_string(),
        ));
    }

    let mut transaction = db.begin().await.map_err(|error| {
        AppError::DatabaseError(format!("Failed to start return transaction: {error}"))
    })?;

    let allocation = sqlx::query(
        "SELECT firearm_id FROM firearm_allocations WHERE id = $1 AND LOWER(BTRIM(status)) = 'active' FOR UPDATE",
    )
        .bind(&payload.allocation_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Active allocation not found".to_string()))?;

    // Update allocation
    sqlx::query(
        "UPDATE firearm_allocations SET return_date = CURRENT_TIMESTAMP, status = 'returned', updated_at = CURRENT_TIMESTAMP WHERE id = $1"
    )
    .bind(&payload.allocation_id)
    .execute(&mut *transaction)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    // Update firearm status back to available
    let firearm_id: String = allocation.get("firearm_id");
    sqlx::query(
        "UPDATE firearms SET status = 'available', updated_at = CURRENT_TIMESTAMP WHERE id = $1",
    )
    .bind(&firearm_id)
    .execute(&mut *transaction)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    transaction.commit().await.map_err(|error| {
        AppError::DatabaseError(format!("Failed to commit firearm return: {error}"))
    })?;

    Ok(Json(json!({
        "message": "Firearm returned successfully"
    })))
}

pub async fn get_guard_allocations(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(guard_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_self_or_min_role(&headers, &guard_id, "supervisor")?;

    let allocations = sqlx::query_as::<_, GuardAllocationView>(
        r#"
        SELECT fa.id, fa.guard_id, fa.firearm_id, fa.allocation_date, fa.return_date, fa.status, fa.created_at, fa.updated_at,
               f.model AS firearm_model, f.caliber AS firearm_caliber, f.serial_number AS firearm_serial_number
        FROM firearm_allocations fa
        JOIN firearms f ON f.id = fa.firearm_id
        WHERE fa.guard_id = $1 AND fa.status = 'active'
        ORDER BY fa.allocation_date DESC
        "#,
    )
    .bind(&guard_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "total": allocations.len(),
        "allocations": allocations
    })))
}

pub async fn get_active_allocations(
    State(db): State<Arc<PgPool>>,
) -> AppResult<Json<serde_json::Value>> {
    let allocations = sqlx::query_as::<_, FirearmAllocation>(
        "SELECT id, guard_id, firearm_id, allocation_date, return_date, status, created_at, updated_at FROM firearm_allocations WHERE status = 'active'"
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "total": allocations.len(),
        "allocations": allocations
    })))
}

pub async fn get_allocation_summary(
    State(db): State<Arc<PgPool>>,
) -> AppResult<Json<serde_json::Value>> {
    let row = sqlx::query(
        r#"WITH capstone_roster AS (
                SELECT DISTINCT guard_id
                FROM capstone_firearm_custody_mappings
                WHERE batch_id = 'sentinel-october-2026-firearm-custody-v1'
            )
            SELECT
                (SELECT COUNT(*)::BIGINT FROM firearms) AS total_firearms,
                (SELECT COUNT(*)::BIGINT FROM firearms WHERE LOWER(BTRIM(status)) = 'available') AS available_firearms,
                (SELECT COUNT(*)::BIGINT FROM firearms WHERE LOWER(BTRIM(status)) IN ('allocated', 'deployed')) AS allocated_firearms,
                (SELECT COUNT(*)::BIGINT FROM firearms WHERE LOWER(BTRIM(status)) = 'maintenance') AS maintenance_firearms,
                (SELECT COUNT(*)::BIGINT FROM firearm_allocations WHERE LOWER(BTRIM(status)) = 'active') AS active_custody,
                (SELECT COUNT(*)::BIGINT FROM firearms f
                 WHERE LOWER(BTRIM(f.status)) IN ('allocated', 'deployed')
                   AND NOT EXISTS (
                     SELECT 1 FROM firearm_allocations fa
                     WHERE fa.firearm_id = f.id AND LOWER(BTRIM(fa.status)) = 'active'
                   )) AS custody_review_firearms,
                (SELECT COUNT(*)::BIGINT FROM firearm_allocations WHERE LOWER(BTRIM(status)) = 'returned') AS returned_allocations,
                (SELECT COUNT(*)::BIGINT FROM firearm_allocations) AS total_allocation_records,
                (SELECT COUNT(*)::BIGINT FROM firearm_eligible_guards) AS eligible_guards,
                (SELECT COUNT(*)::BIGINT
                 FROM users u
                 WHERE LOWER(BTRIM(u.role)) = 'guard'
                   AND COALESCE(LOWER(BTRIM(u.status)), 'active') = 'active'
                   AND COALESCE(LOWER(BTRIM(u.approval_status)), 'approved') = 'approved'
                   AND (
                     NOT EXISTS (SELECT 1 FROM capstone_roster)
                     OR u.id IN (SELECT guard_id FROM capstone_roster)
                   )) AS active_approved_guards,
                (SELECT COUNT(*)::BIGINT
                 FROM users u
                 WHERE LOWER(BTRIM(u.role)) = 'guard'
                   AND COALESCE(LOWER(BTRIM(u.status)), 'active') = 'active'
                   AND COALESCE(LOWER(BTRIM(u.approval_status)), 'approved') = 'approved'
                   AND (
                     NOT EXISTS (SELECT 1 FROM capstone_roster)
                     OR u.id IN (SELECT guard_id FROM capstone_roster)
                   )
                   AND EXISTS (
                     SELECT 1 FROM guard_firearm_permits p
                     WHERE p.guard_id = u.id
                       AND LOWER(BTRIM(p.status)) = 'active'
                       AND p.expiry_date > NOW()
                   )) AS guards_with_active_permit,
                (SELECT COUNT(*)::BIGINT
                 FROM users u
                 WHERE LOWER(BTRIM(u.role)) = 'guard'
                   AND COALESCE(LOWER(BTRIM(u.status)), 'active') = 'active'
                   AND COALESCE(LOWER(BTRIM(u.approval_status)), 'approved') = 'approved'
                   AND (
                     NOT EXISTS (SELECT 1 FROM capstone_roster)
                     OR u.id IN (SELECT guard_id FROM capstone_roster)
                   )
                   AND EXISTS (
                     SELECT 1 FROM training_records t
                     WHERE t.guard_id = u.id
                       AND LOWER(BTRIM(t.training_type)) = 'firearms_handling'
                       AND LOWER(BTRIM(t.status)) = 'valid'
                       AND (t.expiry_date IS NULL OR t.expiry_date > NOW())
                   )) AS guards_with_valid_firearms_training"#,
    )
    .fetch_one(db.as_ref())
    .await
    .map_err(|error| AppError::DatabaseError(format!("Failed to load firearm allocation summary: {error}")))?;

    Ok(Json(json!({
        "totalFirearms": row.get::<i64, _>("total_firearms"),
        "availableFirearms": row.get::<i64, _>("available_firearms"),
        "allocatedFirearms": row.get::<i64, _>("allocated_firearms"),
        "maintenanceFirearms": row.get::<i64, _>("maintenance_firearms"),
        "activeCustody": row.get::<i64, _>("active_custody"),
        "custodyReviewFirearms": row.get::<i64, _>("custody_review_firearms"),
        "returnedAllocations": row.get::<i64, _>("returned_allocations"),
        "totalAllocationRecords": row.get::<i64, _>("total_allocation_records"),
        "eligibleGuards": row.get::<i64, _>("eligible_guards"),
        "activeApprovedGuards": row.get::<i64, _>("active_approved_guards"),
        "guardsWithActivePermit": row.get::<i64, _>("guards_with_active_permit"),
        "guardsWithValidFirearmsTraining": row.get::<i64, _>("guards_with_valid_firearms_training"),
    })))
}

pub async fn get_eligible_guards(
    State(db): State<Arc<PgPool>>,
    Query(query): Query<EligibleGuardQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let (page, page_size, offset) = utils::resolve_pagination(
        utils::PaginationQuery {
            page: query.page,
            page_size: query.page_size,
        },
        50,
        200,
    );
    let search = normalized_filter(query.search);
    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::BIGINT
           FROM firearm_eligible_guards
           WHERE $1::TEXT IS NULL
              OR full_name ILIKE '%' || $1 || '%'
              OR COALESCE(guard_code, '') ILIKE '%' || $1 || '%'"#,
    )
    .bind(&search)
    .fetch_one(db.as_ref())
    .await
    .map_err(|error| {
        AppError::DatabaseError(format!("Failed to count eligible guards: {error}"))
    })?;

    let guards = sqlx::query(
        r#"SELECT id, full_name, guard_code
           FROM firearm_eligible_guards
           WHERE $1::TEXT IS NULL
              OR full_name ILIKE '%' || $1 || '%'
              OR COALESCE(guard_code, '') ILIKE '%' || $1 || '%'
           ORDER BY full_name ASC
           LIMIT $2 OFFSET $3"#,
    )
    .bind(&search)
    .bind(page_size)
    .bind(offset)
    .fetch_all(db.as_ref())
    .await
    .map_err(|error| AppError::DatabaseError(format!("Failed to load eligible guards: {error}")))?
    .into_iter()
    .map(|row| {
        json!({
            "id": row.get::<String, _>("id"),
            "fullName": row.get::<String, _>("full_name"),
            "guardCode": row.get::<Option<String>, _>("guard_code"),
        })
    })
    .collect::<Vec<_>>();

    Ok(Json(json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "guards": guards,
    })))
}

pub async fn get_all_allocations(
    State(db): State<Arc<PgPool>>,
    Query(query): Query<AllocationListQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let (page, page_size, offset) = utils::resolve_pagination(
        utils::PaginationQuery {
            page: query.page,
            page_size: query.page_size,
        },
        25,
        100,
    );
    let search = normalized_filter(query.search);
    let status = normalized_filter(query.status).map(|value| value.to_lowercase());
    let start_date = date_filter(query.start_date, "startDate")?;
    let end_date = date_filter(query.end_date, "endDate")?;

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::BIGINT
           FROM firearm_allocations fa
           LEFT JOIN users u ON u.id = fa.guard_id
           LEFT JOIN firearms f ON f.id = fa.firearm_id
           WHERE ($1::TEXT IS NULL OR LOWER(BTRIM(fa.status)) = $1)
             AND ($2::DATE IS NULL OR fa.allocation_date >= $2::DATE)
             AND ($3::DATE IS NULL OR fa.allocation_date < ($3::DATE + INTERVAL '1 day'))
             AND ($4::TEXT IS NULL
                  OR COALESCE(u.full_name, '') ILIKE '%' || $4 || '%'
                  OR COALESCE(u.guard_code, '') ILIKE '%' || $4 || '%'
                  OR COALESCE(f.serial_number, '') ILIKE '%' || $4 || '%')"#,
    )
    .bind(&status)
    .bind(&start_date)
    .bind(&end_date)
    .bind(&search)
    .fetch_one(db.as_ref())
    .await
    .map_err(|error| {
        AppError::DatabaseError(format!("Failed to count firearm allocations: {error}"))
    })?;

    let allocations = sqlx::query_as::<_, AllocationListView>(
        r#"
        SELECT fa.id, fa.guard_id, fa.firearm_id, fa.allocation_date, fa.return_date, fa.status, fa.created_at, fa.updated_at,
               u.full_name AS guard_name,
               f.serial_number AS firearm_serial_number,
               f.model AS firearm_model,
               fa.mdr_batch_id,
               CASE WHEN fa.mdr_batch_id IS NULL THEN 'application_recorded' ELSE 'mdr_import_recorded' END AS issue_date_source
        FROM firearm_allocations fa
        LEFT JOIN users u ON u.id = fa.guard_id
        LEFT JOIN firearms f ON f.id = fa.firearm_id
        WHERE ($1::TEXT IS NULL OR LOWER(BTRIM(fa.status)) = $1)
          AND ($2::DATE IS NULL OR fa.allocation_date >= $2::DATE)
          AND ($3::DATE IS NULL OR fa.allocation_date < ($3::DATE + INTERVAL '1 day'))
          AND ($4::TEXT IS NULL
               OR COALESCE(u.full_name, '') ILIKE '%' || $4 || '%'
               OR COALESCE(u.guard_code, '') ILIKE '%' || $4 || '%'
               OR COALESCE(f.serial_number, '') ILIKE '%' || $4 || '%')
        ORDER BY fa.allocation_date DESC
        LIMIT $5 OFFSET $6
        "#,
    )
    .bind(&status)
    .bind(&start_date)
    .bind(&end_date)
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
        "allocations": allocations
    })))
}

/// GET /api/firearm-allocations/overdue
/// Returns active allocations where return_date has passed
pub async fn get_overdue_allocations(
    State(db): State<Arc<PgPool>>,
) -> AppResult<Json<serde_json::Value>> {
    let rows = sqlx::query(
        r#"
        SELECT
            fa.id, fa.guard_id, fa.firearm_id, fa.allocation_date,
                        fa.return_date, fa.status,
            u.full_name AS guard_name,
            f.model AS firearm_model, f.serial_number AS firearm_serial_number
        FROM firearm_allocations fa
        JOIN users u ON u.id = fa.guard_id
        JOIN firearms f ON f.id = fa.firearm_id
        WHERE fa.status = 'active'
                    AND fa.return_date IS NOT NULL
                    AND fa.return_date < NOW()
                ORDER BY fa.return_date ASC
        "#,
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let overdue: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<String, _>("id"),
                "guardId": r.get::<String, _>("guard_id"),
                "guardName": r.get::<Option<String>, _>("guard_name"),
                "firearmId": r.get::<String, _>("firearm_id"),
                "firearmModel": r.get::<Option<String>, _>("firearm_model"),
                "firearmSerialNumber": r.get::<Option<String>, _>("firearm_serial_number"),
                "allocationDate": r.get::<chrono::DateTime<chrono::Utc>, _>("allocation_date"),
                "returnDate": r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("return_date"),
                "status": r.get::<String, _>("status"),
            })
        })
        .collect();

    Ok(Json(json!({
        "total": overdue.len(),
        "overdueAllocations": overdue
    })))
}
