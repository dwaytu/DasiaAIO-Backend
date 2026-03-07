use axum::{
    extract::{State, Path},
    Json,
};
use sqlx::PgPool;
use std::sync::Arc;
use serde_json::json;

use crate::{
    error::{AppError, AppResult},
    models::{UserResponse, User},
};

pub async fn get_all_users(
    State(db): State<Arc<PgPool>>,
) -> AppResult<Json<serde_json::Value>> {
    let users = sqlx::query_as::<_, User>(
        "SELECT id, email, username, password, role, full_name, phone_number, license_number, license_issued_date, license_expiry_date, address, profile_photo, verified, created_at, updated_at FROM users"
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let user_responses: Vec<UserResponse> = users.into_iter().map(|u| u.into()).collect();

    Ok(Json(json!({
        "total": user_responses.len(),
        "users": user_responses
    })))
}

pub async fn get_user_by_id(
    State(db): State<Arc<PgPool>>,
    Path(id): Path<String>,
) -> AppResult<Json<UserResponse>> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, username, password, role, full_name, phone_number, license_number, license_issued_date, license_expiry_date, address, profile_photo, verified, created_at, updated_at FROM users WHERE id = $1"
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
    Path(id): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> AppResult<Json<serde_json::Value>> {
    // Check if user exists
    sqlx::query("SELECT id FROM users WHERE id = $1")
        .bind(&id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let full_name = payload.get("fullName").and_then(|v| v.as_str());
    let phone_number = payload.get("phoneNumber").and_then(|v| v.as_str());
    let email = payload.get("email").and_then(|v| v.as_str());
    let license_number = payload.get("licenseNumber").and_then(|v| v.as_str());
    let license_issued_date = payload.get("licenseIssuedDate").and_then(|v| v.as_str());
    let license_expiry_date = payload.get("licenseExpiryDate").and_then(|v| v.as_str());
    let address = payload.get("address").and_then(|v| v.as_str());

    // Build query based on provided fields
    if let Some(full_name) = full_name {
        sqlx::query(
            "UPDATE users SET full_name = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2"
        )
        .bind(full_name)
        .bind(&id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;
    }

    if let Some(email) = email {
        sqlx::query(
            "UPDATE users SET email = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2"
        )
        .bind(email)
        .bind(&id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;
    }

    if let Some(phone_number) = phone_number {
        sqlx::query(
            "UPDATE users SET phone_number = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2"
        )
        .bind(phone_number)
        .bind(&id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;
    }

    if let Some(license_number) = license_number {
        sqlx::query(
            "UPDATE users SET license_number = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2"
        )
        .bind(license_number)
        .bind(&id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;
    }

    if let Some(license_expiry_date) = license_expiry_date {
        let expiry_date = chrono::DateTime::parse_from_rfc3339(license_expiry_date)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc));
        
        if let Some(expiry_date) = expiry_date {
            sqlx::query(
                "UPDATE users SET license_expiry_date = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2"
            )
            .bind(expiry_date)
            .bind(&id)
            .execute(db.as_ref())
            .await
            .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;
        }
    }

    if let Some(license_issued_date) = license_issued_date {
        let issued_date = chrono::DateTime::parse_from_rfc3339(license_issued_date)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc));
        
        if let Some(issued_date) = issued_date {
            sqlx::query(
                "UPDATE users SET license_issued_date = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2"
            )
            .bind(issued_date)
            .bind(&id)
            .execute(db.as_ref())
            .await
            .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;
        }
    }

    if let Some(address) = address {
        sqlx::query(
            "UPDATE users SET address = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2"
        )
        .bind(address)
        .bind(&id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;
    }

    Ok(Json(json!({
        "message": "User updated successfully"
    })))
}

pub async fn delete_user(
    State(db): State<Arc<PgPool>>,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    // Check if user exists
    sqlx::query("SELECT id FROM users WHERE id = $1")
        .bind(&id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

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
    Path(id): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> AppResult<Json<serde_json::Value>> {
    // Check if user exists
    sqlx::query("SELECT id FROM users WHERE id = $1")
        .bind(&id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let profile_photo = payload.get("profilePhoto")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing profilePhoto field".to_string()))?;

    // Validate base64 format
    if !profile_photo.starts_with("data:image/") {
        return Err(AppError::BadRequest("Invalid image format".to_string()));
    }

    tracing::info!("Updating profile photo for user: {}", id);

    sqlx::query(
        "UPDATE users SET profile_photo = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2"
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
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    // Check if user exists
    sqlx::query("SELECT id FROM users WHERE id = $1")
        .bind(&id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    sqlx::query(
        "UPDATE users SET profile_photo = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = $1"
    )
    .bind(&id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "message": "Profile photo removed successfully"
    })))
}

