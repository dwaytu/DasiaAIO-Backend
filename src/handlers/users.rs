use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use sqlx::Row;
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    models::{User, UserResponse},
    utils,
};

const MAX_PROFILE_PHOTO_BYTES: usize = 5 * 1024 * 1024;

fn optional_string_field(
    payload: &serde_json::Value,
    field_names: &[&str],
    label: &str,
) -> AppResult<Option<String>> {
    for field_name in field_names {
        if let Some(value) = payload.get(field_name) {
            return value
                .as_str()
                .map(|value| Some(value.trim().to_string()))
                .ok_or_else(|| AppError::BadRequest(format!("{} must be a string", label)));
        }
    }

    Ok(None)
}

fn parse_user_date(value: Option<String>, label: &str) -> AppResult<Option<chrono::DateTime<chrono::Utc>>> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };

    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(&value) {
        return Ok(Some(parsed.with_timezone(&chrono::Utc)));
    }

    let date = chrono::NaiveDate::parse_from_str(&value, "%Y-%m-%d").map_err(|_| {
        AppError::BadRequest(format!(
            "{} must use YYYY-MM-DD or RFC3339 format",
            label
        ))
    })?;
    let midnight = date.and_hms_opt(0, 0, 0).ok_or_else(|| {
        AppError::BadRequest(format!("{} is outside the supported date range", label))
    })?;

    Ok(Some(chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
        midnight,
        chrono::Utc,
    )))
}

fn ensure_actor_can_manage_target(
    actor_id: &str,
    actor_role: &str,
    target_id: &str,
    target_role: &str,
) -> AppResult<()> {
    if actor_id == target_id || utils::can_manage_role(actor_role, target_role) {
        return Ok(());
    }

    Err(AppError::Forbidden(
        "You cannot manage an account with an equal or higher role".to_string(),
    ))
}

fn validate_profile_photo_data_url(value: &str) -> AppResult<()> {
    let (metadata, encoded) = value.split_once(',').ok_or_else(|| {
        AppError::BadRequest("Profile photo must be a base64 image data URL".to_string())
    })?;

    if !matches!(
        metadata.to_ascii_lowercase().as_str(),
        "data:image/png;base64" | "data:image/jpeg;base64" | "data:image/webp;base64"
    ) {
        return Err(AppError::BadRequest(
            "Profile photo must be a PNG, JPEG, or WebP image".to_string(),
        ));
    }

    if encoded.is_empty()
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return Err(AppError::BadRequest(
            "Profile photo contains invalid base64 data".to_string(),
        ));
    }

    let padding = encoded.bytes().rev().take_while(|byte| *byte == b'=').count();
    let content_length = encoded.len().saturating_sub(padding);
    if encoded.len() % 4 != 0 || padding > 2 || encoded[..content_length].contains('=') {
        return Err(AppError::BadRequest(
            "Profile photo contains invalid base64 padding".to_string(),
        ));
    }
    let decoded_size = (encoded.len() / 4).saturating_mul(3).saturating_sub(padding);
    if decoded_size > MAX_PROFILE_PHOTO_BYTES {
        return Err(AppError::BadRequest(
            "Profile photo must be 5 MB or smaller".to_string(),
        ));
    }

    Ok(())
}

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct PendingApprovalUser {
    pub id: String,
    pub email: String,
    pub username: String,
    pub role: String,
    pub full_name: String,
    pub phone_number: String,
    pub license_number: Option<String>,
    pub license_issued_date: Option<chrono::DateTime<chrono::Utc>>,
    pub license_expiry_date: Option<chrono::DateTime<chrono::Utc>>,
    pub address: Option<String>,
    pub verified: bool,
    pub approval_status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct GuardApprovalRequest {
    pub action: String,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateManagedUserRequest {
    pub email: String,
    pub password: String,
    pub username: String,
    pub role: String,
    pub full_name: String,
    pub phone_number: String,
    pub license_number: Option<String>,
    pub license_issued_date: Option<chrono::DateTime<chrono::Utc>>,
    pub license_expiry_date: Option<chrono::DateTime<chrono::Utc>>,
    pub address: Option<String>,
}

pub async fn create_user_by_actor(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CreateManagedUserRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let token = utils::extract_bearer_token(&headers)?;
    let claims = utils::verify_token(&token)?;

    let actor_role = utils::normalize_role(&claims.role);
    let target_role = utils::normalize_role(&payload.role);

    if !utils::can_create_role(&actor_role, &target_role) {
        return Err(AppError::Forbidden(format!(
            "Role '{}' cannot create '{}' accounts",
            actor_role, target_role
        )));
    }

    if payload.email.is_empty()
        || payload.password.is_empty()
        || payload.username.is_empty()
        || payload.full_name.is_empty()
        || payload.phone_number.is_empty()
    {
        return Err(AppError::BadRequest(
            "Email, password, username, full name, and phone number are required".to_string(),
        ));
    }

    if target_role == "guard"
        && (payload.license_number.is_none()
            || payload.license_issued_date.is_none()
            || payload.license_expiry_date.is_none())
    {
        return Err(AppError::BadRequest(
            "Guard accounts require license number and license dates".to_string(),
        ));
    }

    utils::validate_email(&payload.email)?;

    let existing = sqlx::query("SELECT id FROM users WHERE email = $1 OR username = $2")
        .bind(&payload.email)
        .bind(&payload.username)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    if existing.is_some() {
        return Err(AppError::Conflict(
            "User with email or username already exists".to_string(),
        ));
    }

    let user_id = utils::generate_id();
    let hashed_password = utils::hash_password(&payload.password).await?;

    sqlx::query(
        r#"INSERT INTO users (
            id, email, username, password, role, full_name, phone_number,
            license_number, license_issued_date, license_expiry_date, address,
            verified, approval_status, approved_by, approval_date, created_by
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11,
            TRUE, 'approved', $12, CURRENT_TIMESTAMP, $13
        )"#,
    )
    .bind(&user_id)
    .bind(&payload.email)
    .bind(&payload.username)
    .bind(&hashed_password)
    .bind(&target_role)
    .bind(&payload.full_name)
    .bind(&payload.phone_number)
    .bind(&payload.license_number)
    .bind(&payload.license_issued_date)
    .bind(&payload.license_expiry_date)
    .bind(&payload.address)
    .bind(&claims.sub)
    .bind(&claims.sub)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create user: {}", e)))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "User created successfully",
            "userId": user_id,
            "role": target_role,
            "approvalStatus": "approved"
        })),
    ))
}

pub async fn get_all_users(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Query(pagination): Query<utils::PaginationQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let (page, page_size, offset) = utils::resolve_pagination(pagination, 50, 200);

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let users = sqlx::query_as::<_, User>(
        "SELECT id, email, username, password, role, full_name, phone_number, license_number, license_issued_date, license_expiry_date, address, profile_photo, verified, last_seen_at, created_at, updated_at FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2"
    )
    .bind(page_size)
    .bind(offset)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let user_responses: Vec<UserResponse> = users.into_iter().map(|u| u.into()).collect();

    Ok(Json(json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "users": user_responses
    })))
}

pub async fn get_guards(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<UserResponse>>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let guards = sqlx::query_as::<_, User>(
        r#"SELECT id, email, username, password, role, full_name, phone_number,
                  license_number, license_issued_date, license_expiry_date, address,
                  profile_photo, verified, last_seen_at, created_at, updated_at
           FROM users
           WHERE LOWER(role) = 'guard'
             AND COALESCE(approval_status, 'approved') = 'approved'
           ORDER BY full_name ASC"#,
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let response: Vec<UserResponse> = guards.into_iter().map(|u| u.into()).collect();
    Ok(Json(response))
}

pub async fn get_pending_guard_approvals(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let pending = sqlx::query_as::<_, PendingApprovalUser>(
        r#"SELECT
            id, email, username, role, full_name, phone_number,
            license_number, license_issued_date, license_expiry_date, address,
            verified, COALESCE(approval_status, 'approved') AS approval_status,
            created_at
        FROM users
        WHERE COALESCE(approval_status, 'approved') = 'pending'
          AND LOWER(role) IN ('guard')
        ORDER BY created_at ASC"#,
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "total": pending.len(),
        "users": pending
    })))
}

pub async fn update_guard_approval_status(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<GuardApprovalRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let claims = utils::require_min_role(&headers, "supervisor")?;

    let action = payload.action.trim().to_lowercase();
    let new_status = match action.as_str() {
        "approve" | "approved" => "approved",
        "reject" | "rejected" => "rejected",
        _ => {
            return Err(AppError::BadRequest(
                "Invalid action. Use 'approve' or 'reject'".to_string(),
            ))
        }
    };

    let user = sqlx::query(
        r#"UPDATE users
           SET approval_status = $1,
               approved_by = $2,
               approval_date = CURRENT_TIMESTAMP,
               updated_at = CURRENT_TIMESTAMP
           WHERE id = $3
             AND LOWER(role) IN ('guard')
           RETURNING id, email, username, full_name, COALESCE(approval_status, 'approved') AS approval_status"#,
    )
    .bind(new_status)
    .bind(&claims.sub)
    .bind(&id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Pending guard registration not found".to_string()))?;

    let target_user_id: String = user
        .try_get("id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse target user id: {}", e)))?;
    let target_email: String = user
        .try_get("email")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse target email: {}", e)))?;
    let target_username: String = user
        .try_get("username")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse target username: {}", e)))?;

    let notification_title = if new_status == "approved" {
        "Account Approved"
    } else {
        "Account Update"
    };
    let notification_message = if new_status == "approved" {
        "Your guard account has been approved. You can now log in.".to_string()
    } else if let Some(reason) = payload
        .reason
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        format!("Your guard account was not approved. Reason: {}", reason)
    } else {
        "Your guard account was not approved. Please contact an administrator for details."
            .to_string()
    };

    let notification_id = utils::generate_id();
    sqlx::query(
        "INSERT INTO notifications (id, user_id, title, message, type, related_shift_id, read) VALUES ($1, $2, $3, $4, $5, NULL, false)",
    )
    .bind(&notification_id)
    .bind(&target_user_id)
    .bind(notification_title)
    .bind(&notification_message)
    .bind("account_approval")
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create approval notification: {}", e)))?;

    Ok(Json(json!({
        "message": if new_status == "approved" { "Guard account approved" } else { "Guard account rejected" },
        "user": {
            "id": target_user_id,
            "email": target_email,
            "username": target_username,
            "approvalStatus": new_status,
        }
    })))
}

pub async fn get_user_by_id(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<UserResponse>> {
    let _claims = utils::require_self_or_min_role(&headers, &id, "supervisor")?;

    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, username, password, role, full_name, phone_number, license_number, license_issued_date, license_expiry_date, address, profile_photo, verified, last_seen_at, created_at, updated_at FROM users WHERE id = $1"
    )
    .bind(&id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
    .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(Json(user.into()))
}

pub async fn update_user(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> AppResult<Json<serde_json::Value>> {
    let claims = utils::require_self_or_min_role(&headers, &id, "supervisor")?;

    let target_user = sqlx::query("SELECT id, role FROM users WHERE id = $1")
        .bind(&id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let target_role_raw: String = target_user
        .try_get("role")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse target role: {}", e)))?;
    let target_role = utils::normalize_role(&target_role_raw);
    let actor_role = utils::normalize_role(&claims.role);
    ensure_actor_can_manage_target(&claims.sub, &actor_role, &id, &target_role)?;

    let full_name = optional_string_field(&payload, &["fullName", "full_name"], "full name")?;
    let phone_number =
        optional_string_field(&payload, &["phoneNumber", "phone_number"], "phone number")?;
    let email = optional_string_field(&payload, &["email"], "email")?;
    let username = optional_string_field(&payload, &["username"], "username")?;
    let license_number = optional_string_field(
        &payload,
        &["licenseNumber", "license_number"],
        "license number",
    )?;
    let license_issued_date = parse_user_date(
        optional_string_field(
            &payload,
            &["licenseIssuedDate", "license_issued_date"],
            "license issued date",
        )?,
        "license issued date",
    )?;
    let license_expiry_date = parse_user_date(
        optional_string_field(
            &payload,
            &["licenseExpiryDate", "license_expiry_date"],
            "license expiry date",
        )?,
        "license expiry date",
    )?;
    let address = optional_string_field(&payload, &["address"], "address")?;

    if let Some(value) = full_name.as_deref() {
        if value.is_empty() {
            return Err(AppError::BadRequest("Full name cannot be empty".to_string()));
        }
    }
    if let Some(value) = phone_number.as_deref() {
        if value.is_empty() {
            return Err(AppError::BadRequest(
                "Phone number cannot be empty".to_string(),
            ));
        }
    }

    if let Some(email) = email.as_deref() {
        utils::validate_email(email)?;
        let duplicate = sqlx::query(
            "SELECT id FROM users WHERE email = $1 AND id <> $2",
        )
        .bind(email)
        .bind(&id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;
        if duplicate.is_some() {
            return Err(AppError::Conflict("Email already in use".to_string()));
        }
    }

    if let Some(username) = username.as_deref() {
        let username_regex = regex::Regex::new(r"^[A-Za-z0-9_]{3,}$")
            .map_err(|e| AppError::InternalServerError(format!("Regex error: {}", e)))?;
        if !username_regex.is_match(username) {
            return Err(AppError::BadRequest(
                "Username must be at least 3 characters and use only letters, numbers, and underscores".to_string(),
            ));
        }
        let duplicate = sqlx::query(
            "SELECT id FROM users WHERE username = $1 AND id <> $2",
        )
        .bind(username)
        .bind(&id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;
        if duplicate.is_some() {
            return Err(AppError::Conflict("Username already in use".to_string()));
        }
    }

    sqlx::query(
        r#"UPDATE users
           SET full_name = COALESCE($1, full_name),
               phone_number = COALESCE($2, phone_number),
               email = COALESCE($3, email),
               username = COALESCE($4, username),
               license_number = COALESCE($5, license_number),
               license_issued_date = COALESCE($6, license_issued_date),
               license_expiry_date = COALESCE($7, license_expiry_date),
               address = COALESCE($8, address),
               updated_at = CURRENT_TIMESTAMP
           WHERE id = $9"#,
    )
    .bind(full_name.as_deref())
    .bind(phone_number.as_deref())
    .bind(email.as_deref())
    .bind(username.as_deref())
    .bind(license_number.as_deref())
    .bind(license_issued_date)
    .bind(license_expiry_date)
    .bind(address.as_deref())
    .bind(&id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "message": "User updated successfully"
    })))
}

pub async fn delete_user(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let claims = utils::require_min_role(&headers, "admin")?;

    if claims.sub == id {
        return Err(AppError::Forbidden(
            "You cannot delete your own account".to_string(),
        ));
    }

    let target_user = sqlx::query("SELECT role FROM users WHERE id = $1")
        .bind(&id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let target_role: String = target_user
        .try_get("role")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse target role: {}", e)))?;
    ensure_actor_can_manage_target(&claims.sub, &claims.role, &id, &target_role)?;

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "message": "User deleted successfully"
    })))
}

pub async fn update_profile_photo(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> AppResult<Json<serde_json::Value>> {
    let claims = utils::require_self_or_min_role(&headers, &id, "supervisor")?;

    let target_user = sqlx::query("SELECT role FROM users WHERE id = $1")
        .bind(&id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let target_role: String = target_user
        .try_get("role")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse target role: {}", e)))?;
    ensure_actor_can_manage_target(&claims.sub, &claims.role, &id, &target_role)?;

    let profile_photo = payload
        .get("profilePhoto")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing profilePhoto field".to_string()))?;

    validate_profile_photo_data_url(profile_photo)?;

    tracing::info!("Updating profile photo for user: {}", id);

    sqlx::query(
        "UPDATE users SET profile_photo = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
    )
    .bind(profile_photo)
    .bind(&id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    tracing::info!("Profile photo updated successfully for user: {}", id);

    Ok(Json(json!({
        "message": "Profile photo updated successfully"
    })))
}

pub async fn delete_profile_photo(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let claims = utils::require_self_or_min_role(&headers, &id, "supervisor")?;

    let target_user = sqlx::query("SELECT role FROM users WHERE id = $1")
        .bind(&id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let target_role: String = target_user
        .try_get("role")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse target role: {}", e)))?;
    ensure_actor_can_manage_target(&claims.sub, &claims.role, &id, &target_role)?;

    sqlx::query(
        "UPDATE users SET profile_photo = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
    )
    .bind(&id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "message": "Profile photo removed successfully"
    })))
}

#[cfg(test)]
mod tests {
    use super::{parse_user_date, validate_profile_photo_data_url};

    #[test]
    fn user_dates_accept_date_only_and_rfc3339_values() {
        assert!(parse_user_date(Some("2026-08-19".to_string()), "date")
            .expect("date-only value should parse")
            .is_some());
        assert!(parse_user_date(Some("2026-08-19T08:30:00Z".to_string()), "date")
            .expect("RFC3339 value should parse")
            .is_some());
        assert!(parse_user_date(Some("19/08/2026".to_string()), "date").is_err());
    }

    #[test]
    fn profile_photo_validation_restricts_type_and_size() {
        assert!(validate_profile_photo_data_url("data:image/png;base64,aGVsbG8=").is_ok());
        assert!(validate_profile_photo_data_url("data:image/svg+xml;base64,PHN2Zz4=").is_err());

        let oversized = format!(
            "data:image/jpeg;base64,{}",
            "A".repeat(((5usize * 1024 * 1024 + 1) * 4).div_ceil(3))
        );
        assert!(validate_profile_photo_data_url(&oversized).is_err());
    }
}
