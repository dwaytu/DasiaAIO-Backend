use chrono::NaiveDate;
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::{
    error::{AppError, AppResult},
    models::{
        CreateOperationalRequest, OperationalRequest, OperationalRequestDecision,
        OperationalRequestEvent, ResubmitOperationalRequest,
    },
    utils,
};

const REQUEST_TYPES: &[&str] = &["service", "deposit", "return", "firearm_registration"];
const PRIORITIES: &[&str] = &["normal", "high", "urgent"];
const STATUSES: &[&str] = &[
    "pending",
    "needs_correction",
    "approved",
    "rejected",
    "in_progress",
    "completed",
    "cancelled",
];

#[derive(Debug, Clone, Default)]
pub struct RequestListFilters {
    pub status: Option<String>,
    pub request_type: Option<String>,
    pub priority: Option<String>,
    pub requester: Option<String>,
    pub date_from: Option<String>,
    pub date_to: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[derive(Debug)]
struct ValidatedCreation {
    request_type: String,
    priority: String,
    subject: String,
    reason: String,
    resource_type: Option<String>,
    resource_id: Option<String>,
}

fn required_text(value: &str, label: &str, max_len: usize) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::BadRequest(format!("{} is required", label)));
    }
    if value.chars().count() > max_len {
        return Err(AppError::BadRequest(format!(
            "{} must be {} characters or fewer",
            label, max_len
        )));
    }
    Ok(value.to_string())
}

fn optional_text(value: Option<&str>, label: &str, max_len: usize) -> AppResult<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.chars().count() > max_len {
        return Err(AppError::BadRequest(format!(
            "{} must be {} characters or fewer",
            label, max_len
        )));
    }
    Ok(Some(value.to_string()))
}

fn constrained_value(value: &str, allowed: &[&str], label: &str) -> AppResult<String> {
    let value = value.trim().to_ascii_lowercase();
    if allowed.contains(&value.as_str()) {
        Ok(value)
    } else {
        Err(AppError::BadRequest(format!("Invalid {}", label)))
    }
}

fn validate_creation(payload: &CreateOperationalRequest) -> AppResult<ValidatedCreation> {
    let request_type = constrained_value(&payload.request_type, REQUEST_TYPES, "request type")?;
    let priority = constrained_value(
        payload.priority.as_deref().unwrap_or("normal"),
        PRIORITIES,
        "priority",
    )?;
    let subject = required_text(&payload.subject, "Subject", 255)?;
    let reason = required_text(&payload.reason, "Reason", 2_000)?;
    let resource_type = optional_text(payload.resource_type.as_deref(), "Resource type", 40)?
        .map(|value| value.to_ascii_lowercase());
    let resource_id = optional_text(payload.resource_id.as_deref(), "Resource ID", 36)?;

    if matches!(request_type.as_str(), "deposit" | "return")
        && (resource_type.is_none() || resource_id.is_none())
    {
        return Err(AppError::BadRequest(
            "Deposit and return requests require a resource type and resource".to_string(),
        ));
    }

    if matches!(request_type.as_str(), "deposit" | "return")
        && !matches!(
            resource_type.as_deref(),
            Some("firearm_allocation" | "equipment")
        )
    {
        return Err(AppError::BadRequest(
            "Deposit and return requests only support assigned firearms or equipment".to_string(),
        ));
    }

    if request_type == "firearm_registration"
        && optional_text(payload.details.as_deref(), "Details", 4_000)?.is_none()
    {
        return Err(AppError::BadRequest(
            "Firearm registration requests require identifying details".to_string(),
        ));
    }

    Ok(ValidatedCreation {
        request_type,
        priority,
        subject,
        reason,
        resource_type,
        resource_id,
    })
}

fn validate_filter(
    value: Option<String>,
    allowed: &[&str],
    label: &str,
) -> AppResult<Option<String>> {
    value
        .map(|value| constrained_value(&value, allowed, label))
        .transpose()
}

fn validate_date(value: Option<String>, label: &str) -> AppResult<Option<NaiveDate>> {
    value
        .map(|value| {
            NaiveDate::parse_from_str(value.trim(), "%Y-%m-%d")
                .map_err(|_| AppError::BadRequest(format!("{} must use YYYY-MM-DD", label)))
        })
        .transpose()
}

fn map_insert_error(error: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(database_error) = &error {
        if database_error.is_unique_violation() {
            return AppError::Conflict(
                "An active request already exists for this requester, type, and resource"
                    .to_string(),
            );
        }
    }
    AppError::DatabaseError(format!("Failed to create operational request: {}", error))
}

async fn validate_resource(
    pool: &PgPool,
    requester_id: &str,
    requester_role: &str,
    request_type: &str,
    resource_type: Option<&str>,
    resource_id: Option<&str>,
) -> AppResult<()> {
    let (Some(resource_type), Some(resource_id)) = (resource_type, resource_id) else {
        return Ok(());
    };

    match resource_type {
        "firearm_allocation" => {
            let row = sqlx::query("SELECT guard_id, status FROM firearm_allocations WHERE id = $1")
                .bind(resource_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| AppError::DatabaseError(format!("Resource lookup failed: {}", e)))?
                .ok_or_else(|| AppError::NotFound("Firearm allocation not found".to_string()))?;

            let guard_id: String = row.try_get("guard_id").map_err(|e| {
                AppError::DatabaseError(format!("Failed to read allocation owner: {}", e))
            })?;
            let status: String = row.try_get("status").map_err(|e| {
                AppError::DatabaseError(format!("Failed to read allocation status: {}", e))
            })?;
            if guard_id != requester_id
                && (utils::normalize_role(requester_role) == "guard"
                    || matches!(request_type, "deposit" | "return"))
            {
                return Err(AppError::Forbidden(
                    "You can only request action for your own allocation".to_string(),
                ));
            }
            if matches!(request_type, "deposit" | "return") && status != "active" {
                return Err(AppError::Conflict(
                    "Only an active firearm allocation can be deposited or returned".to_string(),
                ));
            }
        }
        "equipment" => {
            let assigned_to = sqlx::query_scalar::<_, Option<String>>(
                "SELECT assigned_to_guard_id FROM equipment WHERE id = $1",
            )
            .bind(resource_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Resource lookup failed: {}", e)))?
            .ok_or_else(|| AppError::NotFound("Equipment not found".to_string()))?;

            if (utils::normalize_role(requester_role) == "guard"
                || matches!(request_type, "deposit" | "return"))
                && assigned_to.as_deref() != Some(requester_id)
            {
                return Err(AppError::Forbidden(
                    "You can only request action for equipment assigned to you".to_string(),
                ));
            }
        }
        "firearm" => {
            sqlx::query_scalar::<_, String>("SELECT id FROM firearms WHERE id = $1")
                .bind(resource_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| AppError::DatabaseError(format!("Resource lookup failed: {}", e)))?
                .ok_or_else(|| AppError::NotFound("Firearm not found".to_string()))?;
        }
        "armored_car" => {
            sqlx::query_scalar::<_, String>("SELECT id FROM armored_cars WHERE id = $1")
                .bind(resource_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| AppError::DatabaseError(format!("Resource lookup failed: {}", e)))?
                .ok_or_else(|| AppError::NotFound("Armored car not found".to_string()))?;
        }
        _ => {
            return Err(AppError::BadRequest(
                "Unsupported resource type".to_string(),
            ))
        }
    }

    Ok(())
}

async fn insert_event(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: &str,
    actor_user_id: &str,
    from_status: Option<&str>,
    to_status: &str,
    comment: Option<&str>,
    action: &str,
) -> AppResult<()> {
    sqlx::query(
        r#"INSERT INTO operational_request_events
           (id, request_id, actor_user_id, from_status, to_status, comment, metadata)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(utils::generate_id())
    .bind(request_id)
    .bind(actor_user_id)
    .bind(from_status)
    .bind(to_status)
    .bind(comment)
    .bind(json!({ "action": action }))
    .execute(&mut **transaction)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to record request history: {}", e)))?;
    Ok(())
}

async fn notify_user(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: &str,
    request_id: &str,
    notification_type: &str,
    title: &str,
    message: &str,
) -> AppResult<()> {
    for occurrence in 1..=100 {
        let event_type = if occurrence == 1 {
            notification_type.to_string()
        } else {
            format!("{}_{}", notification_type, occurrence)
        };
        let result = sqlx::query(
            r#"INSERT INTO notifications
               (id, user_id, title, message, type, related_shift_id, related_request_id, read)
               VALUES ($1, $2, $3, $4, $5, NULL, $6, false)
               ON CONFLICT (user_id, type, related_request_id)
               WHERE related_request_id IS NOT NULL DO NOTHING"#,
        )
        .bind(utils::generate_id())
        .bind(user_id)
        .bind(title)
        .bind(message)
        .bind(&event_type)
        .bind(request_id)
        .execute(&mut **transaction)
        .await
        .map_err(|e| {
            AppError::DatabaseError(format!("Failed to create request notification: {}", e))
        })?;
        if result.rows_affected() == 1 {
            return Ok(());
        }
    }

    Err(AppError::Conflict(
        "Request notification occurrence limit reached".to_string(),
    ))
}

async fn notify_reviewers(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: &str,
    requester_id: &str,
    title: &str,
    notification_type: &str,
) -> AppResult<()> {
    let reviewer_ids = sqlx::query_scalar::<_, String>(
        r#"SELECT id FROM users
           WHERE LOWER(BTRIM(role)) IN ('supervisor', 'admin', 'superadmin')
             AND id <> $1
             AND COALESCE(approval_status, 'approved') = 'approved'
             AND COALESCE(status, 'active') = 'active'"#,
    )
    .bind(requester_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to find request reviewers: {}", e)))?;

    for reviewer_id in reviewer_ids {
        notify_user(
            transaction,
            &reviewer_id,
            request_id,
            notification_type,
            "Operational Request Pending",
            title,
        )
        .await?;
    }
    Ok(())
}

pub async fn create_request(
    pool: &PgPool,
    requester_id: &str,
    requester_role: &str,
    payload: CreateOperationalRequest,
) -> AppResult<OperationalRequest> {
    let ValidatedCreation {
        request_type,
        priority,
        subject,
        reason,
        resource_type,
        resource_id,
    } = validate_creation(&payload)?;
    let details = optional_text(payload.details.as_deref(), "Details", 4_000)?;
    let client_site_id = optional_text(payload.client_site_id.as_deref(), "Client site ID", 36)?;
    let shift_id = optional_text(payload.shift_id.as_deref(), "Shift ID", 36)?;
    let operational_event_key = optional_text(
        payload.operational_event_key.as_deref(),
        "Operational event key",
        255,
    )?;

    validate_resource(
        pool,
        requester_id,
        requester_role,
        &request_type,
        resource_type.as_deref(),
        resource_id.as_deref(),
    )
    .await?;

    let id = utils::generate_id();
    let mut transaction = pool.begin().await.map_err(|e| {
        AppError::DatabaseError(format!("Failed to start request transaction: {}", e))
    })?;

    sqlx::query(
        r#"INSERT INTO operational_requests
           (id, request_type, status, requester_id, resource_type, resource_id,
            subject, reason, details, priority, client_site_id, shift_id, operational_event_key)
           VALUES ($1, $2, 'pending', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"#,
    )
    .bind(&id)
    .bind(&request_type)
    .bind(requester_id)
    .bind(resource_type.as_deref())
    .bind(resource_id.as_deref())
    .bind(&subject)
    .bind(&reason)
    .bind(details.as_deref())
    .bind(&priority)
    .bind(client_site_id.as_deref())
    .bind(shift_id.as_deref())
    .bind(operational_event_key.as_deref())
    .execute(&mut *transaction)
    .await
    .map_err(map_insert_error)?;

    insert_event(
        &mut transaction,
        &id,
        requester_id,
        None,
        "pending",
        Some(&reason),
        "submitted",
    )
    .await?;
    notify_reviewers(
        &mut transaction,
        &id,
        requester_id,
        &subject,
        "operational_request_pending",
    )
    .await?;

    transaction
        .commit()
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to commit request: {}", e)))?;

    get_request(pool, requester_id, requester_role, &id).await
}

pub async fn list_requests(
    pool: &PgPool,
    actor_id: &str,
    actor_role: &str,
    filters: RequestListFilters,
) -> AppResult<Value> {
    let status = validate_filter(filters.status, STATUSES, "status")?;
    let request_type = validate_filter(filters.request_type, REQUEST_TYPES, "request type")?;
    let priority = validate_filter(filters.priority, PRIORITIES, "priority")?;
    let requester = optional_text(filters.requester.as_deref(), "Requester", 255)?
        .map(|value| format!("%{}%", value));
    let date_from = validate_date(filters.date_from, "Start date")?;
    let date_to = validate_date(filters.date_to, "End date")?;
    if matches!((date_from, date_to), (Some(from), Some(to)) if from > to) {
        return Err(AppError::BadRequest(
            "Start date cannot be after end date".to_string(),
        ));
    }
    let pagination = utils::PaginationQuery {
        page: filters.page,
        page_size: filters.page_size,
    };
    let (page, page_size, offset) = utils::resolve_pagination(pagination, 25, 100);
    let elevated = utils::role_rank(actor_role).unwrap_or_default() >= 2;

    let total = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM operational_requests
           WHERE ($1::text IS NULL OR status = $1)
             AND ($2::text IS NULL OR request_type = $2)
             AND ($3::boolean OR requester_id = $4)
             AND ($5::text IS NULL OR priority = $5)
             AND ($6::text IS NULL OR requester_id IN (
                 SELECT id FROM users WHERE full_name ILIKE $6 OR username ILIKE $6 OR email ILIKE $6
             ))
             AND ($7::date IS NULL OR created_at >= $7::date)
             AND ($8::date IS NULL OR created_at < ($8::date + INTERVAL '1 day'))"#,
    )
    .bind(status.as_deref())
    .bind(request_type.as_deref())
    .bind(elevated)
    .bind(actor_id)
    .bind(priority.as_deref())
    .bind(requester.as_deref())
    .bind(date_from)
    .bind(date_to)
    .fetch_one(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to count requests: {}", e)))?;

    let items = sqlx::query_as::<_, OperationalRequest>(
        r#"SELECT o.id, o.request_type, o.status, o.requester_id,
                  COALESCE(u.full_name, u.username) AS requester_name,
                  o.resource_type, o.resource_id, o.subject, o.reason, o.details,
                  o.priority, o.client_site_id, o.shift_id, o.operational_event_key,
                  o.reviewer_id, o.reviewed_at, o.decision_reason,
                  o.fulfilled_by, o.fulfilled_at, o.created_at, o.updated_at
           FROM operational_requests o
           JOIN users u ON u.id = o.requester_id
           WHERE ($1::text IS NULL OR o.status = $1)
             AND ($2::text IS NULL OR o.request_type = $2)
             AND ($3::boolean OR o.requester_id = $4)
             AND ($5::text IS NULL OR o.priority = $5)
             AND ($6::text IS NULL OR o.requester_id IN (
                 SELECT id FROM users WHERE full_name ILIKE $6 OR username ILIKE $6 OR email ILIKE $6
             ))
             AND ($7::date IS NULL OR o.created_at >= $7::date)
             AND ($8::date IS NULL OR o.created_at < ($8::date + INTERVAL '1 day'))
           ORDER BY
             CASE o.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
             o.created_at DESC
           LIMIT $9 OFFSET $10"#,
    )
    .bind(status.as_deref())
    .bind(request_type.as_deref())
    .bind(elevated)
    .bind(actor_id)
    .bind(priority.as_deref())
    .bind(requester.as_deref())
    .bind(date_from)
    .bind(date_to)
    .bind(page_size)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to list requests: {}", e)))?;

    Ok(json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "items": items
    }))
}

pub async fn get_request(
    pool: &PgPool,
    actor_id: &str,
    actor_role: &str,
    request_id: &str,
) -> AppResult<OperationalRequest> {
    let request = sqlx::query_as::<_, OperationalRequest>(
        r#"SELECT o.id, o.request_type, o.status, o.requester_id,
                  COALESCE(u.full_name, u.username) AS requester_name,
                  o.resource_type, o.resource_id, o.subject, o.reason, o.details,
                  o.priority, o.client_site_id, o.shift_id, o.operational_event_key,
                  o.reviewer_id, o.reviewed_at, o.decision_reason,
                  o.fulfilled_by, o.fulfilled_at, o.created_at, o.updated_at
           FROM operational_requests o
           JOIN users u ON u.id = o.requester_id
           WHERE o.id = $1"#,
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to load request: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Operational request not found".to_string()))?;

    if utils::role_rank(actor_role).unwrap_or_default() < 2 && request.requester_id != actor_id {
        return Err(AppError::NotFound(
            "Operational request not found".to_string(),
        ));
    }
    Ok(request)
}

pub async fn get_events(
    pool: &PgPool,
    actor_id: &str,
    actor_role: &str,
    request_id: &str,
) -> AppResult<Vec<OperationalRequestEvent>> {
    get_request(pool, actor_id, actor_role, request_id).await?;

    sqlx::query_as::<_, OperationalRequestEvent>(
        r#"SELECT e.id, e.request_id, e.actor_user_id,
                  COALESCE(u.full_name, u.username) AS actor_name,
                  e.from_status, e.to_status, e.comment, e.metadata, e.created_at
           FROM operational_request_events e
           LEFT JOIN users u ON u.id = e.actor_user_id
           WHERE e.request_id = $1
           ORDER BY e.created_at ASC"#,
    )
    .bind(request_id)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to load request history: {}", e)))
}

pub async fn get_my_resources(
    pool: &PgPool,
    actor_id: &str,
    _actor_role: &str,
) -> AppResult<Value> {
    let guard_only = true;
    let allocations = sqlx::query(
        r#"SELECT fa.id, fa.firearm_id, fa.guard_id, f.model, f.serial_number, f.caliber
           FROM firearm_allocations fa
           JOIN firearms f ON f.id = fa.firearm_id
           WHERE fa.status = 'active' AND ($1::boolean = false OR fa.guard_id = $2)
           ORDER BY f.model, f.serial_number"#,
    )
    .bind(guard_only)
    .bind(actor_id)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to load firearm resources: {}", e)))?;

    let equipment = sqlx::query(
        r#"SELECT id, equipment_type, serial_number, description, assigned_to_guard_id
           FROM equipment
           WHERE assigned_to_guard_id IS NOT NULL
             AND ($1::boolean = false OR assigned_to_guard_id = $2)
           ORDER BY equipment_type, serial_number"#,
    )
    .bind(guard_only)
    .bind(actor_id)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to load equipment resources: {}", e)))?;

    Ok(json!({
        "firearmAllocations": allocations.into_iter().map(|row| json!({
            "id": row.get::<String, _>("id"),
            "resourceType": "firearm_allocation",
            "guardId": row.get::<String, _>("guard_id"),
            "firearmId": row.get::<String, _>("firearm_id"),
            "label": format!("{} - S/N {}", row.get::<String, _>("model"), row.get::<String, _>("serial_number")),
            "caliber": row.get::<String, _>("caliber"),
        })).collect::<Vec<_>>(),
        "equipment": equipment.into_iter().map(|row| json!({
            "id": row.get::<String, _>("id"),
            "resourceType": "equipment",
            "guardId": row.get::<Option<String>, _>("assigned_to_guard_id"),
            "label": row.get::<String, _>("equipment_type"),
            "serialNumber": row.get::<Option<String>, _>("serial_number"),
            "description": row.get::<Option<String>, _>("description"),
        })).collect::<Vec<_>>()
    }))
}

async fn transition_request(
    pool: &PgPool,
    actor_id: &str,
    actor_role: &str,
    request_id: &str,
    action: &str,
    payload: OperationalRequestDecision,
) -> AppResult<OperationalRequest> {
    let reason = optional_text(payload.reason.as_deref(), "Reason", 2_000)?;
    let role_rank = utils::role_rank(actor_role).unwrap_or_default();
    let mut transaction = pool.begin().await.map_err(|e| {
        AppError::DatabaseError(format!("Failed to start request transaction: {}", e))
    })?;

    let row = sqlx::query(
        r#"SELECT requester_id, request_type, status, resource_type, resource_id, subject
           FROM operational_requests WHERE id = $1 FOR UPDATE"#,
    )
    .bind(request_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to lock request: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Operational request not found".to_string()))?;

    let requester_id: String = row.get("requester_id");
    let request_type: String = row.get("request_type");
    let from_status: String = row.get("status");
    let resource_type: Option<String> = row.get("resource_type");
    let resource_id: Option<String> = row.get("resource_id");
    let subject: String = row.get("subject");

    let to_status = match action {
        "approve" if role_rank >= 2 && from_status == "pending" => "approved",
        "reject" if role_rank >= 2 && from_status == "pending" => "rejected",
        "return_for_correction" if role_rank >= 2 && from_status == "pending" => "needs_correction",
        "start" if role_rank >= 3 && from_status == "approved" => "in_progress",
        "complete"
            if role_rank >= 3 && matches!(from_status.as_str(), "approved" | "in_progress") =>
        {
            "completed"
        }
        "cancel"
            if (actor_id == requester_id
                && matches!(from_status.as_str(), "pending" | "needs_correction"))
                || (role_rank >= 3
                    && matches!(from_status.as_str(), "approved" | "in_progress")) =>
        {
            "cancelled"
        }
        _ => {
            return Err(AppError::Conflict(format!(
                "Action '{}' is not allowed while the request is '{}'",
                action, from_status
            )))
        }
    };

    if matches!(action, "approve" | "reject" | "return_for_correction") && actor_id == requester_id
    {
        return Err(AppError::Forbidden(
            "A requester cannot review their own request".to_string(),
        ));
    }
    if matches!(action, "reject" | "return_for_correction") && reason.is_none() {
        return Err(AppError::BadRequest(
            "A reason is required for this decision".to_string(),
        ));
    }
    if action == "cancel" && actor_id != requester_id && reason.is_none() {
        return Err(AppError::BadRequest(
            "An operator cancellation reason is required".to_string(),
        ));
    }

    if action == "complete" {
        fulfill_linked_resource(
            &mut transaction,
            &requester_id,
            &request_type,
            resource_type.as_deref(),
            resource_id.as_deref(),
        )
        .await?;
    }

    let review_action = matches!(action, "approve" | "reject" | "return_for_correction");
    let fulfillment_action = matches!(action, "start" | "complete");
    sqlx::query(
        r#"UPDATE operational_requests
           SET status = $1,
               reviewer_id = CASE WHEN $2 THEN $3 ELSE reviewer_id END,
               reviewed_at = CASE WHEN $2 THEN CURRENT_TIMESTAMP ELSE reviewed_at END,
               decision_reason = CASE WHEN $2 THEN $4 ELSE decision_reason END,
               fulfilled_by = CASE WHEN $5 THEN $3 ELSE fulfilled_by END,
               fulfilled_at = CASE WHEN $1 = 'completed' THEN CURRENT_TIMESTAMP ELSE fulfilled_at END,
               updated_at = CURRENT_TIMESTAMP
           WHERE id = $6 AND status = $7"#,
    )
    .bind(to_status)
    .bind(review_action)
    .bind(actor_id)
    .bind(reason.as_deref())
    .bind(fulfillment_action)
    .bind(request_id)
    .bind(&from_status)
    .execute(&mut *transaction)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to update request: {}", e)))?;

    insert_event(
        &mut transaction,
        request_id,
        actor_id,
        Some(&from_status),
        to_status,
        reason.as_deref(),
        action,
    )
    .await?;

    let (notification_title, notification_message) = match to_status {
        "approved" => (
            "Request Approved",
            format!("Your operational request \"{}\" was approved.", subject),
        ),
        "rejected" => (
            "Request Denied",
            format!(
                "Your operational request \"{}\" was denied.{}",
                subject,
                reason
                    .as_deref()
                    .map(|value| format!(" Reason: {}", value))
                    .unwrap_or_default()
            ),
        ),
        "needs_correction" => (
            "Request Needs Correction",
            format!(
                "Your operational request \"{}\" needs correction.{}",
                subject,
                reason
                    .as_deref()
                    .map(|value| format!(" Note: {}", value))
                    .unwrap_or_default()
            ),
        ),
        "completed" => (
            "Request Completed",
            format!("Your operational request \"{}\" was completed.", subject),
        ),
        "cancelled" => (
            "Request Cancelled",
            format!("Your operational request \"{}\" was cancelled.", subject),
        ),
        "in_progress" => (
            "Request In Progress",
            format!(
                "Work has started on your operational request \"{}\".",
                subject
            ),
        ),
        _ => (
            "Operational Request Updated",
            format!(
                "Your operational request \"{}\" is now {}.",
                subject,
                to_status.replace('_', " ")
            ),
        ),
    };

    notify_user(
        &mut transaction,
        &requester_id,
        request_id,
        &format!("operational_request_{}", to_status),
        notification_title,
        &notification_message,
    )
    .await?;

    transaction
        .commit()
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to commit request update: {}", e)))?;

    get_request(pool, actor_id, actor_role, request_id).await
}

async fn fulfill_linked_resource(
    transaction: &mut Transaction<'_, Postgres>,
    requester_id: &str,
    request_type: &str,
    resource_type: Option<&str>,
    resource_id: Option<&str>,
) -> AppResult<()> {
    if !matches!(request_type, "deposit" | "return") {
        return Ok(());
    }

    match (resource_type, resource_id) {
        (Some("firearm_allocation"), Some(allocation_id)) => {
            let allocation = sqlx::query(
                "SELECT guard_id, firearm_id, status FROM firearm_allocations WHERE id = $1 FOR UPDATE",
            )
            .bind(allocation_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to load allocation: {}", e)))?
            .ok_or_else(|| AppError::NotFound("Firearm allocation not found".to_string()))?;
            let guard_id: String = allocation.get("guard_id");
            let firearm_id: String = allocation.get("firearm_id");
            let status: String = allocation.get("status");
            if guard_id != requester_id || status != "active" {
                return Err(AppError::Conflict(
                    "The firearm allocation is no longer active for this requester".to_string(),
                ));
            }
            sqlx::query(
                "UPDATE firearm_allocations SET return_date = CURRENT_TIMESTAMP, status = 'returned', updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND status = 'active'",
            )
            .bind(allocation_id)
            .execute(&mut **transaction)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to return allocation: {}", e)))?;
            sqlx::query(
                "UPDATE firearms SET status = 'available', updated_at = CURRENT_TIMESTAMP WHERE id = $1",
            )
            .bind(&firearm_id)
            .execute(&mut **transaction)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to update firearm: {}", e)))?;
        }
        (Some("equipment"), Some(equipment_id)) => {
            let result = sqlx::query(
                "UPDATE equipment SET assigned_to_guard_id = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = $1 AND assigned_to_guard_id = $2",
            )
            .bind(equipment_id)
            .bind(requester_id)
            .execute(&mut **transaction)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to deposit equipment: {}", e)))?;
            if result.rows_affected() == 0 {
                return Err(AppError::Conflict(
                    "The equipment is no longer assigned to this requester".to_string(),
                ));
            }
        }
        _ => {
            return Err(AppError::BadRequest(
                "Deposit and return completion requires a supported resource".to_string(),
            ))
        }
    }
    Ok(())
}

pub async fn resubmit_request(
    pool: &PgPool,
    actor_id: &str,
    actor_role: &str,
    request_id: &str,
    payload: ResubmitOperationalRequest,
) -> AppResult<OperationalRequest> {
    let subject = required_text(&payload.subject, "Subject", 255)?;
    let reason = required_text(&payload.reason, "Reason", 2_000)?;
    let details = optional_text(payload.details.as_deref(), "Details", 4_000)?;
    let priority = constrained_value(
        payload.priority.as_deref().unwrap_or("normal"),
        PRIORITIES,
        "priority",
    )?;
    let mut transaction = pool.begin().await.map_err(|e| {
        AppError::DatabaseError(format!("Failed to start request transaction: {}", e))
    })?;

    let row = sqlx::query(
        "SELECT requester_id, status, request_type FROM operational_requests WHERE id = $1 FOR UPDATE",
    )
    .bind(request_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to lock request: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Operational request not found".to_string()))?;
    let requester_id: String = row.get("requester_id");
    let from_status: String = row.get("status");
    if requester_id != actor_id {
        return Err(AppError::Forbidden(
            "Only the requester can resubmit this request".to_string(),
        ));
    }
    if from_status != "needs_correction" {
        return Err(AppError::Conflict(
            "Only a request returned for correction can be resubmitted".to_string(),
        ));
    }

    let request_type: String = row.get("request_type");
    if request_type == "firearm_registration" && details.is_none() {
        return Err(AppError::BadRequest(
            "Firearm registration requests require identifying details".to_string(),
        ));
    }

    sqlx::query(
        r#"UPDATE operational_requests
           SET subject = $1, reason = $2, details = $3, priority = $4,
               status = 'pending', reviewer_id = NULL, reviewed_at = NULL,
               decision_reason = NULL, updated_at = CURRENT_TIMESTAMP
           WHERE id = $5 AND status = 'needs_correction'"#,
    )
    .bind(&subject)
    .bind(&reason)
    .bind(details.as_deref())
    .bind(&priority)
    .bind(request_id)
    .execute(&mut *transaction)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to resubmit request: {}", e)))?;

    insert_event(
        &mut transaction,
        request_id,
        actor_id,
        Some("needs_correction"),
        "pending",
        Some(&reason),
        "resubmitted",
    )
    .await?;
    notify_reviewers(
        &mut transaction,
        request_id,
        actor_id,
        &subject,
        "operational_request_resubmitted",
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to commit resubmission: {}", e)))?;

    get_request(pool, actor_id, actor_role, request_id).await
}

pub async fn approve_request(
    pool: &PgPool,
    actor_id: &str,
    actor_role: &str,
    request_id: &str,
    payload: OperationalRequestDecision,
) -> AppResult<OperationalRequest> {
    transition_request(pool, actor_id, actor_role, request_id, "approve", payload).await
}

pub async fn reject_request(
    pool: &PgPool,
    actor_id: &str,
    actor_role: &str,
    request_id: &str,
    payload: OperationalRequestDecision,
) -> AppResult<OperationalRequest> {
    transition_request(pool, actor_id, actor_role, request_id, "reject", payload).await
}

pub async fn return_for_correction(
    pool: &PgPool,
    actor_id: &str,
    actor_role: &str,
    request_id: &str,
    payload: OperationalRequestDecision,
) -> AppResult<OperationalRequest> {
    transition_request(
        pool,
        actor_id,
        actor_role,
        request_id,
        "return_for_correction",
        payload,
    )
    .await
}

pub async fn cancel_request(
    pool: &PgPool,
    actor_id: &str,
    actor_role: &str,
    request_id: &str,
    payload: OperationalRequestDecision,
) -> AppResult<OperationalRequest> {
    transition_request(pool, actor_id, actor_role, request_id, "cancel", payload).await
}

pub async fn start_request(
    pool: &PgPool,
    actor_id: &str,
    actor_role: &str,
    request_id: &str,
    payload: OperationalRequestDecision,
) -> AppResult<OperationalRequest> {
    transition_request(pool, actor_id, actor_role, request_id, "start", payload).await
}

pub async fn complete_request(
    pool: &PgPool,
    actor_id: &str,
    actor_role: &str,
    request_id: &str,
    payload: OperationalRequestDecision,
) -> AppResult<OperationalRequest> {
    transition_request(pool, actor_id, actor_role, request_id, "complete", payload).await
}

#[cfg(test)]
mod tests {
    use super::{constrained_value, required_text, validate_creation, validate_date, PRIORITIES};
    use crate::models::CreateOperationalRequest;

    fn request(request_type: &str) -> CreateOperationalRequest {
        CreateOperationalRequest {
            request_type: request_type.to_string(),
            resource_type: None,
            resource_id: None,
            subject: "Inspection request".to_string(),
            reason: "Operational inspection is required".to_string(),
            details: Some("Serial number and registration details".to_string()),
            priority: None,
            client_site_id: None,
            shift_id: None,
            operational_event_key: None,
        }
    }

    #[test]
    fn accepts_supported_request_types() {
        for request_type in ["service", "firearm_registration"] {
            assert!(validate_creation(&request(request_type)).is_ok());
        }
    }

    #[test]
    fn deposit_requires_a_resource() {
        let error = validate_creation(&request("deposit")).unwrap_err();
        assert!(error.to_string().contains("require a resource"));
    }

    #[test]
    fn deposit_rejects_unsupported_resource_types() {
        let mut payload = request("deposit");
        payload.resource_type = Some("firearm".to_string());
        payload.resource_id = Some("firearm-1".to_string());
        let error = validate_creation(&payload).unwrap_err();
        assert!(error.to_string().contains("assigned firearms or equipment"));
    }

    #[test]
    fn validation_rejects_empty_and_unknown_values() {
        assert!(required_text("  ", "Subject", 255).is_err());
        assert!(constrained_value("critical", PRIORITIES, "priority").is_err());
    }

    #[test]
    fn date_filters_require_iso_dates() {
        assert!(validate_date(Some("2026-09-09".to_string()), "Start date").is_ok());
        assert!(validate_date(Some("09/09/2026".to_string()), "Start date").is_err());
    }
}
