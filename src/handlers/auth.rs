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
    models::{CreateUserRequest, LoginRequest, VerifyEmailRequest, ResendCodeRequest, ForgotPasswordRequest, VerifyResetCodeRequest, ResetPasswordRequest},
    utils::{self, verify_password},
};

pub async fn register(
    State(db): State<Arc<PgPool>>,
    Json(payload): Json<CreateUserRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    tracing::info!("Register request received for user: {}", payload.email);

    let requested_role = utils::normalize_role(&payload.role);

    // Validate required fields
    if payload.email.is_empty() || payload.password.is_empty() || payload.username.is_empty()
        || payload.full_name.is_empty() || payload.phone_number.is_empty()
        || payload.license_number.is_none() || payload.license_issued_date.is_none()
        || payload.license_expiry_date.is_none() {
        return Err(AppError::BadRequest(
            "All fields are required for guard self-registration".to_string()
        ));
    }

    // Validate Gmail
    utils::validate_gmail(&payload.email)?;

    // Validate role
    if requested_role != "guard" {
        return Err(AppError::BadRequest("Public registration only supports guard accounts".to_string()));
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

    // Email verification is mandatory for guard self-registration.
    let resend_api_key = std::env::var("RESEND_API_KEY").unwrap_or_default();
    if resend_api_key.is_empty() {
        return Err(AppError::InternalServerError(
            "Registration is temporarily unavailable because email verification is not configured".to_string(),
        ));
    }

    // Create user
    sqlx::query(
        r#"INSERT INTO users (id, email, username, password, role, full_name, phone_number, license_number, license_issued_date, license_expiry_date, address, verified, approval_status, created_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'pending', NULL)"#
    )
    .bind(&user_id)
    .bind(&payload.email)
    .bind(&payload.username)
    .bind(&hashed_password)
    .bind(&requested_role)
    .bind(&payload.full_name)
    .bind(&payload.phone_number)
    .bind(&payload.license_number)
    .bind(&payload.license_issued_date)
    .bind(&payload.license_expiry_date)
    .bind(&payload.address)
    .bind(false)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create user: {}", e)))?;

    // Notify reviewers (superadmin/admin/supervisor) that a guard registration is waiting for approval.
    let reviewer_ids = sqlx::query_scalar::<_, String>(
        r#"SELECT id
           FROM users
           WHERE LOWER(role) IN ('superadmin', 'admin', 'supervisor')
             AND verified = TRUE
             AND COALESCE(approval_status, 'approved') = 'approved'"#,
    )
    .fetch_all(db.as_ref())
    .await
    .unwrap_or_default();

    for reviewer_id in reviewer_ids {
        let notification_id = utils::generate_id();
        if let Err(e) = sqlx::query(
            "INSERT INTO notifications (id, user_id, title, message, type, related_shift_id, read) VALUES ($1, $2, $3, $4, $5, NULL, false)",
        )
        .bind(&notification_id)
        .bind(&reviewer_id)
        .bind("Guard Registration Pending Approval")
        .bind(format!(
            "New guard registration submitted by {} ({}) and is waiting for approval.",
            payload.full_name, payload.email
        ))
        .bind("approval_request")
        .execute(db.as_ref())
        .await
        {
            tracing::warn!("Failed to create reviewer notification: {}", e);
        }
    }

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

    utils::send_confirmation_email(
        &resend_api_key,
        &payload.email,
        &confirmation_code,
    ).await?;

    tracing::info!("Verification email sent to {}", payload.email);
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Registration submitted. Check your Gmail for confirmation code, then wait for supervisor/admin approval.",
            "userId": user_id,
            "email": payload.email,
            "requiresVerification": true
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
        r#"SELECT v.id, v.user_id, v.expires_at
           FROM verifications v
           INNER JOIN users u ON u.id = v.user_id
           WHERE v.code = $1 AND LOWER(u.email) = LOWER($2)"#
    )
    .bind(&payload.code)
    .bind(&payload.email)
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
        r#"SELECT id, email, username, password, role, full_name, phone_number, license_number, license_issued_date, license_expiry_date, address, profile_photo, verified, COALESCE(approval_status, 'approved') AS approval_status, created_at, updated_at FROM users 
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

    let approval_status: String = user.try_get("approval_status").unwrap_or_else(|_| "approved".to_string());
    if approval_status != "approved" {
        return Err(AppError::Forbidden(
            "Your account is pending approval".to_string()
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

    sqlx::query("UPDATE users SET last_seen_at = CURRENT_TIMESTAMP WHERE id = $1")
        .bind(&id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update last_seen_at: {}", e)))?;

    // Generate JWT token
    let token = utils::generate_token(&id, &email, &role)?;

    Ok(Json(json!({
        "message": "Login successful",
        "token": token,
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

pub async fn forgot_password(
    State(db): State<Arc<PgPool>>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if payload.email.is_empty() {
        return Err(AppError::BadRequest("Email is required".to_string()));
    }

    // Find user by email
    let user = sqlx::query("SELECT id FROM users WHERE email = $1")
        .bind(&payload.email)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let user_id: String = user.try_get("id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse user id: {}", e)))?;

    // Generate reset code (6 digits)
    let reset_code = utils::generate_confirmation_code();
    let expires_at = chrono::Utc::now() + Duration::minutes(10);

    // Delete any existing unused reset codes for this user
    sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = $1 AND is_used = FALSE")
        .bind(&user_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to delete old tokens: {}", e)))?;

    // Create new password reset token
    sqlx::query(
        "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)"
    )
    .bind(&user_id)
    .bind(&reset_code)
    .bind(expires_at)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create reset token: {}", e)))?;

    // Send email with reset code
    let resend_api_key = std::env::var("RESEND_API_KEY").unwrap_or_default();
    if !resend_api_key.is_empty() {
        let html_body = format!(
            r#"
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px; text-align: center; border-radius: 8px 8px 0 0;">
                    <h1 style="color: white; margin: 0;">Davao Security & Investigation Agency</h1>
                    <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0 0;">Password Reset</p>
                </div>
                <div style="background: #f9f9f9; padding: 40px; border-radius: 0 0 8px 8px;">
                    <h2 style="color: #333; margin-top: 0;">Reset Your Password</h2>
                    <p style="color: #666; font-size: 16px; line-height: 1.6;">
                        We received a request to reset your password. Use the following code to proceed:
                    </p>
                    <div style="background: white; border: 2px solid #667eea; border-radius: 8px; padding: 20px; text-align: center; margin: 30px 0;">
                        <code style="font-size: 32px; font-weight: bold; color: #667eea; letter-spacing: 2px;">{}</code>
                    </div>
                    <p style="color: #666; font-size: 14px;">
                        This code will expire in 10 minutes. If you did not request a password reset, please ignore this email.
                    </p>
                    <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
                    <p style="color: #999; font-size: 12px; margin: 0;">
                        © 2024 Davao Security & Investigation Agency. All rights reserved.
                    </p>
                </div>
            </div>
            "#,
            reset_code
        );

        let client = reqwest::Client::new();
        let _ = client
            .post("https://api.resend.com/emails")
            .header("Authorization", format!("Bearer {}", resend_api_key))
            .json(&serde_json::json!({
                "from": "Sentinel DASIA <noreply@dasiasentinel.xyz>",
                "to": [&payload.email],
                "subject": "Davao Security - Password Reset Code",
                "html": html_body
            }))
            .send()
            .await;
    }

    Ok(Json(json!({
        "message": "Password reset code sent to your email"
    })))
}

pub async fn verify_reset_code(
    State(db): State<Arc<PgPool>>,
    Json(payload): Json<VerifyResetCodeRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if payload.email.is_empty() || payload.code.is_empty() {
        return Err(AppError::BadRequest("Email and code are required".to_string()));
    }

    // Find user
    let user = sqlx::query("SELECT id FROM users WHERE email = $1")
        .bind(&payload.email)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let user_id: String = user.try_get("id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse user id: {}", e)))?;

    // Find reset token
    let token_record = sqlx::query(
        "SELECT id, expires_at, is_used FROM password_reset_tokens WHERE user_id = $1 AND token = $2"
    )
    .bind(&user_id)
    .bind(&payload.code)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
    .ok_or_else(|| AppError::BadRequest("Invalid reset code".to_string()))?;

    let is_used: bool = token_record.try_get("is_used")
        .unwrap_or(false);
    if is_used {
        return Err(AppError::BadRequest("Reset code has already been used".to_string()));
    }

    // Check if code expired
    let expires_at: chrono::DateTime<chrono::Utc> = token_record.try_get("expires_at")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse expiry: {}", e)))?;
    if chrono::Utc::now() > expires_at {
        return Err(AppError::BadRequest("Reset code expired".to_string()));
    }

    Ok(Json(json!({
        "message": "Reset code verified"
    })))
}

pub async fn reset_password(
    State(db): State<Arc<PgPool>>,
    Json(payload): Json<ResetPasswordRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if payload.email.is_empty() || payload.code.is_empty() || payload.new_password.is_empty() {
        return Err(AppError::BadRequest("Email, code, and new password are required".to_string()));
    }

    if payload.new_password.len() < 6 {
        return Err(AppError::BadRequest("Password must be at least 6 characters".to_string()));
    }

    // Find user
    let user = sqlx::query("SELECT id FROM users WHERE email = $1")
        .bind(&payload.email)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let user_id: String = user.try_get("id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse user id: {}", e)))?;

    // Find and validate reset token
    let token_record = sqlx::query(
        "SELECT id, expires_at, is_used FROM password_reset_tokens WHERE user_id = $1 AND token = $2"
    )
    .bind(&user_id)
    .bind(&payload.code)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
    .ok_or_else(|| AppError::BadRequest("Invalid reset code".to_string()))?;

    let is_used: bool = token_record.try_get("is_used")
        .unwrap_or(false);
    if is_used {
        return Err(AppError::BadRequest("Reset code has already been used".to_string()));
    }

    let expires_at: chrono::DateTime<chrono::Utc> = token_record.try_get("expires_at")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse expiry: {}", e)))?;
    if chrono::Utc::now() > expires_at {
        return Err(AppError::BadRequest("Reset code expired".to_string()));
    }

    let token_id: String = token_record.try_get("id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse token id: {}", e)))?;

    // Hash new password
    let hashed_password = utils::hash_password(&payload.new_password).await?;

    // Update user password and mark token as used
    sqlx::query("UPDATE users SET password = $1 WHERE id = $2")
        .bind(&hashed_password)
        .bind(&user_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update password: {}", e)))?;

    sqlx::query("UPDATE password_reset_tokens SET is_used = TRUE WHERE id = $1")
        .bind(&token_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to mark token as used: {}", e)))?;

    Ok(Json(json!({
        "message": "Password reset successful. You can now login with your new password."
    })))
}



