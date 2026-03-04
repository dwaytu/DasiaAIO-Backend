use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use chrono::Duration;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use serde_json::json;

use crate::{
    error::{AppError, AppResult},
    models::{CreateUserRequest, LoginRequest, VerifyEmailRequest, ResendCodeRequest, UserResponse},
    utils::{self, verify_password},
};

pub async fn register(
    State(db): State<Arc<PgPool>>,
    Json(payload): Json<CreateUserRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    tracing::info!("Register request received for user: {}", payload.email);

    // Validate required fields
    if payload.role == "admin" {
        if payload.email.is_empty() || payload.password.is_empty() || payload.username.is_empty() 
            || payload.full_name.is_empty() || payload.phone_number.is_empty() {
            return Err(AppError::BadRequest(
                "Email, password, username, full name, and phone number are required for admin accounts".to_string()
            ));
        }
    } else {
        if payload.email.is_empty() || payload.password.is_empty() || payload.username.is_empty() 
            || payload.full_name.is_empty() || payload.phone_number.is_empty() 
            || payload.license_number.is_none() || payload.license_issued_date.is_none() 
            || payload.license_expiry_date.is_none() {
            return Err(AppError::BadRequest(
                "All fields are required for regular user accounts".to_string()
            ));
        }
    }

    // Validate Gmail
    utils::validate_gmail(&payload.email)?;

    // Validate role
    if payload.role != "user" && payload.role != "admin" {
        return Err(AppError::BadRequest("Role must be 'user' or 'admin'".to_string()));
    }

    // Validate admin code
    if payload.role == "admin" {
        let admin_code = payload.admin_code.as_ref()
            .ok_or_else(|| AppError::BadRequest("Admin code is required".to_string()))?;
        if admin_code != "122601" {
            return Err(AppError::BadRequest("Invalid admin code".to_string()));
        }
    }

    // Check if user exists
    let existing_user = sqlx::query("SELECT id FROM users WHERE email = $1")
        .bind(&payload.email)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    if existing_user.is_some() {
        return Err(AppError::Conflict("User already exists".to_string()));
    }

    // Hash password
    let hashed_password = utils::hash_password(&payload.password).await?;

    // Generate user ID and confirmation code
    let user_id = utils::generate_id();
    let confirmation_code = utils::generate_confirmation_code();
    let expires_at = chrono::Utc::now() + Duration::minutes(10);

    // Determine if Resend API key is configured
    let resend_api_key = std::env::var("RESEND_API_KEY").unwrap_or_default();
    let smtp_configured = !resend_api_key.is_empty();

    // If email is not configured, auto-verify immediately so users can log in
    let initial_verified = !smtp_configured;

    // Create user
    sqlx::query(
        r#"INSERT INTO users (id, email, username, password, role, full_name, phone_number, license_number, license_issued_date, license_expiry_date, address, verified)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"#
    )
    .bind(&user_id)
    .bind(&payload.email)
    .bind(&payload.username)
    .bind(&hashed_password)
    .bind(&payload.role)
    .bind(&payload.full_name)
    .bind(&payload.phone_number)
    .bind(&payload.license_number)
    .bind(&payload.license_issued_date)
    .bind(&payload.license_expiry_date)
    .bind(&payload.address)
    .bind(initial_verified)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create user: {}", e)))?;;

    // Only create verification record + send email when SMTP is configured
    if smtp_configured {
        // Create verification record
        let verification_id = utils::generate_id();
        sqlx::query(
            "INSERT INTO verifications (id, user_id, code, expires_at) VALUES ($1, $2, $3, $4)"
        )
        .bind(&verification_id)
        .bind(&user_id)
        .bind(&confirmation_code)
        .bind(expires_at)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to create verification: {}", e)))?;

        match utils::send_confirmation_email(
            &resend_api_key,
            &payload.email,
            &confirmation_code,
        ).await {
            Ok(_) => {
                tracing::info!("Verification email sent to {}", payload.email);
            }
            Err(e) => {
                tracing::warn!("Failed to send verification email to {}: {}. User must resend the verification code.", payload.email, e);
                // Do NOT auto-verify — user must verify their email
                return Ok((
                    StatusCode::CREATED,
                    Json(json!({
                        "message": "Registration successful! We couldn't send the verification email. Please use Resend Code to try again.",
                        "userId": user_id,
                        "email": payload.email,
                        "requiresVerification": true
                    })),
                ));
            }
        }

        return Ok((
            StatusCode::CREATED,
            Json(json!({
                "message": "Registration successful! Check your Gmail for confirmation code.",
                "userId": user_id,
                "email": payload.email,
                "requiresVerification": true
            })),
        ));
    }

    // SMTP not configured — user is already verified, can log in immediately
    tracing::info!("SMTP not configured — user {} auto-verified, can log in immediately.", payload.email);
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Registration successful! You can now log in.",
            "userId": user_id,
            "email": payload.email,
            "requiresVerification": false
        })),
    ))
}

pub async fn verify_email(
    State(db): State<Arc<PgPool>>,
    Json(payload): Json<VerifyEmailRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if payload.email.is_empty() || payload.code.is_empty() {
        return Err(AppError::BadRequest(
            "Email and code are required".to_string()
        ));
    }

    // Find verification record
    let verification = sqlx::query(
        "SELECT id, user_id, expires_at FROM verifications WHERE code = $1"
    )
    .bind(&payload.code)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
    .ok_or_else(|| AppError::BadRequest("Invalid confirmation code".to_string()))?;

    // Check if code expired
    let expires_at: chrono::DateTime<chrono::Utc> = verification.try_get("expires_at")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse verification expiry: {}", e)))?;
    if chrono::Utc::now() > expires_at {
        let ver_id: String = verification.try_get("id")
            .map_err(|e| AppError::DatabaseError(format!("Failed to parse verification id: {}", e)))?;
        sqlx::query("DELETE FROM verifications WHERE id = $1")
            .bind(&ver_id)
            .execute(db.as_ref())
            .await
            .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;
        return Err(AppError::BadRequest("Confirmation code expired".to_string()));
    }

    // Mark user as verified
    let user_id: String = verification.try_get("user_id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse user_id: {}", e)))?;
    sqlx::query(
        "UPDATE users SET verified = TRUE WHERE id = $1"
    )
    .bind(&user_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    // Delete verification record
    let ver_id: String = verification.try_get("id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse verification id: {}", e)))?;
    sqlx::query("DELETE FROM verifications WHERE id = $1")
        .bind(&ver_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "message": "Email verified successfully! You can now login."
    })))
}

pub async fn resend_verification_code(
    State(db): State<Arc<PgPool>>,
    Json(payload): Json<ResendCodeRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if payload.email.is_empty() {
        return Err(AppError::BadRequest("Email is required".to_string()));
    }

    // Find user
    let user = sqlx::query("SELECT id FROM users WHERE email = $1")
        .bind(&payload.email)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Generate new code
    let confirmation_code = utils::generate_confirmation_code();
    let expires_at = chrono::Utc::now() + Duration::minutes(10);

    // Delete old verification
    let user_id: String = user.try_get("id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse user id: {}", e)))?;
    sqlx::query("DELETE FROM verifications WHERE user_id = $1")
        .bind(&user_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    // Create new verification
    let verification_id = utils::generate_id();
    sqlx::query(
        "INSERT INTO verifications (id, user_id, code, expires_at) VALUES ($1, $2, $3, $4)"
    )
    .bind(&verification_id)
    .bind(&user_id)
    .bind(&confirmation_code)
    .bind(expires_at)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let resend_api_key = std::env::var("RESEND_API_KEY").unwrap_or_default();
    utils::send_confirmation_email(
        &resend_api_key,
        &payload.email,
        &confirmation_code,
    ).await?;

    Ok(Json(json!({
        "message": "Verification code resent to your email"
    })))
}

pub async fn login(
    State(db): State<Arc<PgPool>>,
    Json(payload): Json<LoginRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if payload.identifier.is_empty() || payload.password.is_empty() {
        return Err(AppError::BadRequest(
            "Email, username, phone number, and password are required".to_string()
        ));
    }

    // Find user by email, username, or phone
    let user = sqlx::query(
        r#"SELECT id, email, username, password, role, full_name, phone_number, license_number, license_issued_date, license_expiry_date, address, profile_photo, verified, created_at, updated_at FROM users 
           WHERE email = $1 OR username = $1 OR phone_number = $1"#
    )
    .bind(&payload.identifier)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
    .ok_or_else(|| AppError::BadRequest("Invalid credentials".to_string()))?;

    // Check if user is verified
    let verified: bool = user.try_get("verified").unwrap_or(false);
    if !verified {
        return Err(AppError::BadRequest(
            "Please verify your email first".to_string()
        ));
    }

    // Verify password
    let password_hash: String = user.try_get("password")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse password hash: {}", e)))?;
    let password_valid = verify_password(&payload.password, &password_hash).await?;
    if !password_valid {
        return Err(AppError::BadRequest("Invalid credentials".to_string()));
    }

    let id: String = user.try_get("id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse user id: {}", e)))?;
    let email: String = user.try_get("email")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse email: {}", e)))?;
    let username: String = user.try_get("username")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse username: {}", e)))?;
    let role: String = user.try_get("role")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse role: {}", e)))?;
    let full_name: Option<String> = user.try_get("full_name").ok();
    let phone_number: Option<String> = user.try_get("phone_number").ok();
    let license_number: Option<String> = user.try_get("license_number").ok();
    let license_issued_date: Option<chrono::DateTime<chrono::Utc>> = user.try_get("license_issued_date").ok();
    let license_expiry_date: Option<chrono::DateTime<chrono::Utc>> = user.try_get("license_expiry_date").ok();
    let address: Option<String> = user.try_get("address").ok();
    let profile_photo: Option<String> = user.try_get("profile_photo").ok();

    Ok(Json(json!({
        "message": "Login successful",
        "user": {
            "id": id,
            "email": email,
            "username": username,
            "role": role,
            "fullName": full_name,
            "phoneNumber": phone_number,
            "licenseNumber": license_number,
            "licenseIssuedDate": license_issued_date,
            "licenseExpiryDate": license_expiry_date,
            "address": address,
            "profilePhoto": profile_photo,
        }
    })))
}



