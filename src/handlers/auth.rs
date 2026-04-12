use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sqlx::{PgPool, Row};
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    models::{
        CreateUserRequest, ForgotPasswordRequest, LoginRequest, RefreshTokenRequest,
        ResendCodeRequest, ResetPasswordRequest, VerifyEmailRequest, VerifyResetCodeRequest,
    },
    utils::{self, verify_password},
};

fn login_attempt_threshold() -> u32 {
    std::env::var("LOGIN_MAX_FAILED_ATTEMPTS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value >= 3 && *value <= 20)
        .unwrap_or(5)
}

fn login_failure_window_minutes() -> i64 {
    std::env::var("LOGIN_FAILURE_WINDOW_MINUTES")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value >= 1 && *value <= 240)
        .unwrap_or(15)
}

fn lockout_window_minutes() -> i64 {
    std::env::var("LOGIN_LOCKOUT_MINUTES")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value >= 1 && *value <= 120)
        .unwrap_or(15)
}

fn make_login_key(prefix: &str, value: &str) -> String {
    format!("{}:{}", prefix, value.trim().to_lowercase())
}

fn password_reset_code_length() -> usize {
    std::env::var("PASSWORD_RESET_CODE_LENGTH")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value >= 8 && *value <= 12)
        .unwrap_or(8)
}

fn generate_password_reset_code() -> String {
    use rand::Rng;

    let code_length = password_reset_code_length();
    let max = 10_u64.pow(code_length as u32);
    let mut rng = rand::thread_rng();

    format!(
        "{:0width$}",
        rng.gen_range(0..max),
        width = code_length
    )
}

fn is_valid_password_reset_code(code: &str) -> bool {
    code.len() == password_reset_code_length() && code.chars().all(|c| c.is_ascii_digit())
}

fn refresh_expiry_datetime(epoch_seconds: i64) -> AppResult<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(epoch_seconds, 0).ok_or_else(|| {
        AppError::InternalServerError("Invalid refresh token expiry value".to_string())
    })
}

fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn canonicalize_login_role(raw_role: &str) -> AppResult<String> {
    utils::normalize_authenticated_role(raw_role).map_err(|_| {
        AppError::Forbidden("Account role is not allowed for authentication".to_string())
    })
}

#[derive(Debug, Clone)]
struct RefreshTokenContext {
    email: String,
    role: String,
    legal_consent_accepted: bool,
}

async fn load_refresh_token_context(db: &PgPool, user_id: &str) -> AppResult<RefreshTokenContext> {
    let user = sqlx::query(
        r#"SELECT email, role, verified, COALESCE(approval_status, 'approved') AS approval_status, consent_accepted_at
           FROM users
           WHERE id = $1"#,
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to validate refresh token user state: {}",
            e
        ))
    })?
    .ok_or_else(|| AppError::Unauthorized("Invalid refresh token session".to_string()))?;

    let verified: bool = user.try_get("verified").map_err(|e| {
        AppError::DatabaseError(format!("Failed to parse refresh user verification state: {}", e))
    })?;

    let approval_status: String = user.try_get("approval_status").map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to parse refresh user approval status: {}",
            e
        ))
    })?;

    if !verified || approval_status != "approved" {
        return Err(AppError::Unauthorized(
            "Invalid refresh token session".to_string(),
        ));
    }

    let email: String = user.try_get("email").map_err(|e| {
        AppError::DatabaseError(format!("Failed to parse refresh user email: {}", e))
    })?;

    let persisted_role: String = user.try_get("role").map_err(|e| {
        AppError::DatabaseError(format!("Failed to parse refresh user role: {}", e))
    })?;

    let role = canonicalize_login_role(&persisted_role)
        .map_err(|_| AppError::Unauthorized("Invalid refresh token session".to_string()))?;

    let consent_accepted_at: Option<chrono::DateTime<chrono::Utc>> =
        user.try_get("consent_accepted_at").map_err(|e| {
            AppError::DatabaseError(format!(
                "Failed to parse refresh user consent state: {}",
                e
            ))
        })?;

    Ok(RefreshTokenContext {
        email,
        role,
        legal_consent_accepted: consent_accepted_at.is_some(),
    })
}

async fn get_lockout_seconds_remaining(db: &PgPool, key: &str) -> AppResult<Option<i64>> {
    let remaining = sqlx::query_scalar::<_, i64>(
        r#"SELECT GREATEST(1, EXTRACT(EPOCH FROM (locked_until - NOW()))::BIGINT)
           FROM auth_login_attempts
           WHERE scope_key = $1
             AND locked_until IS NOT NULL
             AND locked_until > NOW()"#,
    )
    .bind(key)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to check login lockout state: {}", e)))?;

    Ok(remaining)
}

async fn register_login_failure(db: &PgPool, key: &str) -> AppResult<bool> {
    let now = Utc::now();
    let threshold = login_attempt_threshold() as i32;
    let failure_window = Duration::minutes(login_failure_window_minutes());
    let lockout_until = now + Duration::minutes(lockout_window_minutes());

    let existing = sqlx::query(
        "SELECT failed_attempts, first_failed_at, locked_until FROM auth_login_attempts WHERE scope_key = $1"
    )
    .bind(key)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to load login failure state: {}", e)))?;

    let (next_failed_attempts, next_first_failed_at, next_locked_until) =
        if let Some(row) = existing {
            let mut failed_attempts: i32 = row.try_get("failed_attempts").unwrap_or(0);
            let mut first_failed_at: DateTime<Utc> = row.try_get("first_failed_at").unwrap_or(now);
            let mut locked_until: Option<DateTime<Utc>> = row.try_get("locked_until").ok();

            if locked_until.map(|until| until <= now).unwrap_or(false) {
                failed_attempts = 0;
                first_failed_at = now;
                locked_until = None;
            }

            if now.signed_duration_since(first_failed_at) >= failure_window {
                failed_attempts = 0;
                first_failed_at = now;
                locked_until = None;
            }

            failed_attempts += 1;
            if failed_attempts >= threshold {
                locked_until = Some(lockout_until);
            }

            (failed_attempts, first_failed_at, locked_until)
        } else {
            (1, now, None)
        };

    sqlx::query(
        r#"INSERT INTO auth_login_attempts (scope_key, failed_attempts, first_failed_at, last_failed_at, locked_until)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (scope_key) DO UPDATE
           SET failed_attempts = EXCLUDED.failed_attempts,
               first_failed_at = EXCLUDED.first_failed_at,
               last_failed_at = EXCLUDED.last_failed_at,
               locked_until = EXCLUDED.locked_until"#,
    )
    .bind(key)
    .bind(next_failed_attempts)
    .bind(next_first_failed_at)
    .bind(now)
    .bind(next_locked_until)
    .execute(db)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to persist login failure state: {}", e)))?;

    Ok(next_locked_until.map(|until| until > now).unwrap_or(false))
}

async fn clear_login_failures(db: &PgPool, keys: &[String]) -> AppResult<()> {
    for key in keys {
        sqlx::query("DELETE FROM auth_login_attempts WHERE scope_key = $1")
            .bind(key)
            .execute(db)
            .await
            .map_err(|e| {
                AppError::DatabaseError(format!("Failed to clear login failure state: {}", e))
            })?;
    }

    Ok(())
}

async fn store_refresh_session(
    db: &PgPool,
    user_id: &str,
    refresh_token: &str,
    claims: &utils::RefreshTokenClaims,
    source_ip: &str,
    user_agent: Option<&str>,
) -> AppResult<()> {
    let expires_at = refresh_expiry_datetime(claims.exp)?;
    let token_hash = utils::hash_token(refresh_token);

    sqlx::query(
        r#"INSERT INTO refresh_token_sessions (
                jti, user_id, token_hash, issued_at, expires_at, source_ip, user_agent
           ) VALUES ($1, $2, $3, NOW(), $4, $5, $6)"#,
    )
    .bind(&claims.jti)
    .bind(user_id)
    .bind(token_hash)
    .bind(expires_at)
    .bind(source_ip)
    .bind(user_agent)
    .execute(db)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to persist refresh token session: {}", e))
    })?;

    Ok(())
}

async fn rotate_refresh_session(
    db: &PgPool,
    current_claims: &utils::RefreshTokenClaims,
    current_refresh_token: &str,
    new_refresh_token: &str,
    new_claims: &utils::RefreshTokenClaims,
    source_ip: &str,
    user_agent: Option<&str>,
) -> AppResult<()> {
    let current_hash = utils::hash_token(current_refresh_token);
    let new_hash = utils::hash_token(new_refresh_token);
    let new_expires_at = refresh_expiry_datetime(new_claims.exp)?;

    let mut tx = db.begin().await.map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to start refresh rotation transaction: {}",
            e
        ))
    })?;

    let updated = sqlx::query(
        r#"UPDATE refresh_token_sessions
           SET revoked_at = NOW(),
               replaced_by_jti = $1,
               last_used_at = NOW()
           WHERE jti = $2
             AND user_id = $3
             AND token_hash = $4
             AND revoked_at IS NULL
             AND expires_at > NOW()"#,
    )
    .bind(&new_claims.jti)
    .bind(&current_claims.jti)
    .bind(&current_claims.sub)
    .bind(current_hash)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to revoke previous refresh token: {}", e))
    })?;

    if updated.rows_affected() != 1 {
        tx.rollback().await.map_err(|e| {
            AppError::DatabaseError(format!(
                "Failed to rollback refresh rotation transaction: {}",
                e
            ))
        })?;
        return Err(AppError::Unauthorized(
            "Invalid or revoked refresh token".to_string(),
        ));
    }

    sqlx::query(
        r#"INSERT INTO refresh_token_sessions (
                jti, user_id, token_hash, issued_at, expires_at, source_ip, user_agent
           ) VALUES ($1, $2, $3, NOW(), $4, $5, $6)"#,
    )
    .bind(&new_claims.jti)
    .bind(&current_claims.sub)
    .bind(new_hash)
    .bind(new_expires_at)
    .bind(source_ip)
    .bind(user_agent)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to persist rotated refresh token: {}", e))
    })?;

    tx.commit().await.map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to commit refresh rotation transaction: {}",
            e
        ))
    })?;

    Ok(())
}

async fn log_security_event(
    db: &PgPool,
    actor_user_id: Option<&str>,
    action_key: &str,
    result: &str,
    reason: &str,
    source_ip: &str,
    user_agent: Option<&str>,
    metadata: serde_json::Value,
) {
    if let Err(err) = sqlx::query(
        r#"INSERT INTO audit_logs (
                id, actor_user_id, action_key, entity_type, entity_id, result, reason, source_ip, user_agent, metadata
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
    )
    .bind(utils::generate_id())
    .bind(actor_user_id)
    .bind(action_key)
    .bind("auth")
    .bind(None::<String>)
    .bind(result)
    .bind(reason)
    .bind(source_ip)
    .bind(user_agent)
    .bind(metadata)
    .execute(db)
    .await
    {
        tracing::error!(error = %err, action_key = %action_key, "failed to persist auth security event");
    }
}

pub async fn register(
    State(db): State<Arc<PgPool>>,
    Json(payload): Json<CreateUserRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    tracing::info!("Register request received for user: {}", payload.email);

    let requested_role = utils::normalize_role(&payload.role);

    // Validate required fields
    if payload.email.is_empty()
        || payload.password.is_empty()
        || payload.username.is_empty()
        || payload.full_name.is_empty()
        || payload.phone_number.is_empty()
        || payload.license_number.is_none()
        || payload.license_issued_date.is_none()
        || payload.license_expiry_date.is_none()
    {
        return Err(AppError::BadRequest(
            "All fields are required for guard self-registration".to_string(),
        ));
    }

    // Validate email and password strength
    utils::validate_email(&payload.email)?;
    utils::validate_password_strength(&payload.password)?;

    // Validate role
    if requested_role != "guard" {
        return Err(AppError::BadRequest(
            "Public registration only supports guard accounts".to_string(),
        ));
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
            "Registration is temporarily unavailable because email verification is not configured"
                .to_string(),
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
        "INSERT INTO verifications (id, user_id, code, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&verification_id)
    .bind(&user_id)
    .bind(&confirmation_code)
    .bind(expires_at)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create verification: {}", e)))?;

    utils::send_confirmation_email(&resend_api_key, &payload.email, &confirmation_code).await?;

    tracing::info!("Verification email sent to {}", payload.email);
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Registration submitted. Check your email for confirmation code, then wait for supervisor/admin approval.",
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
            "Email and code are required".to_string(),
        ));
    }

    // Find verification record
    let verification = sqlx::query(
        r#"SELECT v.id, v.user_id, v.expires_at
           FROM verifications v
           INNER JOIN users u ON u.id = v.user_id
           WHERE v.code = $1 AND LOWER(u.email) = LOWER($2)"#,
    )
    .bind(&payload.code)
    .bind(&payload.email)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
    .ok_or_else(|| AppError::BadRequest("Invalid confirmation code".to_string()))?;

    // Check if code expired
    let expires_at: chrono::DateTime<chrono::Utc> =
        verification.try_get("expires_at").map_err(|e| {
            AppError::DatabaseError(format!("Failed to parse verification expiry: {}", e))
        })?;
    if chrono::Utc::now() > expires_at {
        let ver_id: String = verification.try_get("id").map_err(|e| {
            AppError::DatabaseError(format!("Failed to parse verification id: {}", e))
        })?;
        sqlx::query("DELETE FROM verifications WHERE id = $1")
            .bind(&ver_id)
            .execute(db.as_ref())
            .await
            .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;
        return Err(AppError::BadRequest(
            "Confirmation code expired".to_string(),
        ));
    }

    // Mark user as verified
    let user_id: String = verification
        .try_get("user_id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse user_id: {}", e)))?;
    sqlx::query("UPDATE users SET verified = TRUE WHERE id = $1")
        .bind(&user_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    // Delete verification record
    let ver_id: String = verification
        .try_get("id")
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
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let Some(user) = user else {
        // Prevent account enumeration by returning a generic success response.
        return Ok(Json(json!({
            "message": "If the account exists, a verification code has been sent"
        })));
    };

    // Generate new code
    let confirmation_code = utils::generate_confirmation_code();
    let expires_at = chrono::Utc::now() + Duration::minutes(10);

    // Delete old verification
    let user_id: String = user
        .try_get("id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse user id: {}", e)))?;
    sqlx::query("DELETE FROM verifications WHERE user_id = $1")
        .bind(&user_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    // Create new verification
    let verification_id = utils::generate_id();
    sqlx::query(
        "INSERT INTO verifications (id, user_id, code, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&verification_id)
    .bind(&user_id)
    .bind(&confirmation_code)
    .bind(expires_at)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let resend_api_key = std::env::var("RESEND_API_KEY").unwrap_or_default();
    utils::send_confirmation_email(&resend_api_key, &payload.email, &confirmation_code).await?;

    Ok(Json(json!({
        "message": "If the account exists, a verification code has been sent"
    })))
}

pub async fn login(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let identifier = payload.identifier.trim();
    let password = payload.password.as_str();

    if identifier.is_empty() || password.is_empty() {
        return Err(AppError::BadRequest(
            "Email, username, phone number, and password are required".to_string(),
        ));
    }

    if identifier.len() > 150 {
        return Err(AppError::BadRequest("Identifier is too long".to_string()));
    }

    if password.len() > 256 {
        return Err(AppError::BadRequest("Password is too long".to_string()));
    }

    let requester = utils::extract_requester(&headers);
    let user_agent = extract_user_agent(&headers);
    let user_key = make_login_key("user", identifier);
    let ip_key = make_login_key("ip", &requester);

    if let Some(remaining) = get_lockout_seconds_remaining(db.as_ref(), &user_key).await? {
        log_security_event(
            db.as_ref(),
            None,
            "AUTH_LOGIN_LOCKED",
            "blocked",
            "Login blocked due to repeated failed attempts",
            &requester,
            user_agent.as_deref(),
            json!({ "identifier": identifier, "retryAfterSeconds": remaining, "scope": "user" }),
        )
        .await;
        return Err(AppError::RateLimited(format!(
            "Account is temporarily locked. Try again in {} second(s).",
            remaining
        )));
    }

    if let Some(remaining) = get_lockout_seconds_remaining(db.as_ref(), &ip_key).await? {
        log_security_event(
            db.as_ref(),
            None,
            "AUTH_LOGIN_LOCKED",
            "blocked",
            "Login blocked due to repeated failed attempts",
            &requester,
            user_agent.as_deref(),
            json!({ "identifier": identifier, "retryAfterSeconds": remaining, "scope": "ip" }),
        )
        .await;
        return Err(AppError::RateLimited(format!(
            "Too many login attempts. Try again in {} second(s).",
            remaining
        )));
    }

    // Find user by email, username, or phone
    let user = sqlx::query(
        r#"SELECT id, email, username, password, role, full_name, phone_number, license_number, license_issued_date, license_expiry_date, address, profile_photo, verified, COALESCE(approval_status, 'approved') AS approval_status, consent_accepted_at, consent_version, created_at, updated_at FROM users 
           WHERE email = $1 OR username = $1 OR phone_number = $1"#
    )
    .bind(identifier)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let Some(user) = user else {
        let user_locked = register_login_failure(db.as_ref(), &user_key).await?;
        let ip_locked = register_login_failure(db.as_ref(), &ip_key).await?;
        log_security_event(
            db.as_ref(),
            None,
            "AUTH_LOGIN_ATTEMPT",
            "failed",
            "Invalid credentials",
            &requester,
            user_agent.as_deref(),
            json!({ "identifier": identifier, "userLocked": user_locked, "ipLocked": ip_locked }),
        )
        .await;

        if user_locked || ip_locked {
            return Err(AppError::RateLimited(
                "Too many failed login attempts. Please wait before retrying.".to_string(),
            ));
        }

        return Err(AppError::BadRequest("Invalid credentials".to_string()));
    };

    let id: String = user
        .try_get("id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse user id: {}", e)))?;

    // Check if user is verified
    let verified: bool = user.try_get("verified").unwrap_or(false);
    if !verified {
        log_security_event(
            db.as_ref(),
            Some(&id),
            "AUTH_LOGIN_ATTEMPT",
            "failed",
            "Email not verified",
            &requester,
            user_agent.as_deref(),
            json!({ "identifier": identifier }),
        )
        .await;
        return Err(AppError::BadRequest(
            "Please verify your email first".to_string(),
        ));
    }

    let approval_status: String = user
        .try_get("approval_status")
        .unwrap_or_else(|_| "approved".to_string());
    if approval_status != "approved" {
        log_security_event(
            db.as_ref(),
            Some(&id),
            "AUTH_LOGIN_ATTEMPT",
            "failed",
            "Account pending approval",
            &requester,
            user_agent.as_deref(),
            json!({ "identifier": identifier }),
        )
        .await;
        return Err(AppError::Forbidden(
            "Your account is pending approval".to_string(),
        ));
    }

    // Verify password
    let password_hash: String = user
        .try_get("password")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse password hash: {}", e)))?;
    let password_valid = verify_password(password, &password_hash).await?;
    if !password_valid {
        let user_locked = register_login_failure(db.as_ref(), &user_key).await?;
        let ip_locked = register_login_failure(db.as_ref(), &ip_key).await?;
        log_security_event(
            db.as_ref(),
            Some(&id),
            "AUTH_LOGIN_ATTEMPT",
            "failed",
            "Invalid credentials",
            &requester,
            user_agent.as_deref(),
            json!({ "identifier": identifier, "userLocked": user_locked, "ipLocked": ip_locked }),
        )
        .await;

        if user_locked || ip_locked {
            return Err(AppError::RateLimited(
                "Too many failed login attempts. Please wait before retrying.".to_string(),
            ));
        }

        return Err(AppError::BadRequest("Invalid credentials".to_string()));
    }

    let email: String = user
        .try_get("email")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse email: {}", e)))?;
    let username: String = user
        .try_get("username")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse username: {}", e)))?;
    let persisted_role: String = user
        .try_get("role")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse role: {}", e)))?;
    let role = canonicalize_login_role(&persisted_role)?;
    let full_name: Option<String> = user.try_get("full_name").ok();
    let phone_number: Option<String> = user.try_get("phone_number").ok();
    let license_number: Option<String> = user.try_get("license_number").ok();
    let license_issued_date: Option<chrono::DateTime<chrono::Utc>> =
        user.try_get("license_issued_date").ok();
    let license_expiry_date: Option<chrono::DateTime<chrono::Utc>> =
        user.try_get("license_expiry_date").ok();
    let address: Option<String> = user.try_get("address").ok();
    let profile_photo: Option<String> = user.try_get("profile_photo").ok();
    let consent_accepted_at: Option<chrono::DateTime<chrono::Utc>> =
        user.try_get("consent_accepted_at").ok();
    let consent_version: Option<String> = user.try_get("consent_version").ok();
    let legal_consent_accepted = consent_accepted_at.is_some();

    sqlx::query("UPDATE users SET last_seen_at = CURRENT_TIMESTAMP WHERE id = $1")
        .bind(&id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update last_seen_at: {}", e)))?;

    clear_login_failures(db.as_ref(), &[user_key, ip_key]).await?;

    // Generate JWT access + refresh tokens
    let token = utils::generate_access_token(&id, &email, &role, legal_consent_accepted)?;
    let refresh_token =
        utils::generate_refresh_token(&id, &email, &role, legal_consent_accepted)?;
    let refresh_claims = utils::verify_refresh_token(&refresh_token)?;

    store_refresh_session(
        db.as_ref(),
        &id,
        &refresh_token,
        &refresh_claims,
        &requester,
        user_agent.as_deref(),
    )
    .await?;

    log_security_event(
        db.as_ref(),
        Some(&id),
        "AUTH_LOGIN_ATTEMPT",
        "success",
        "Login successful",
        &requester,
        user_agent.as_deref(),
        json!({ "identifier": identifier }),
    )
    .await;

    let access_expiry_secs = std::env::var("JWT_EXPIRY_HOURS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value >= 1 && *value <= 168)
        .unwrap_or(24)
        * 3600;

    Ok(Json(json!({
        "message": "Login successful",
        "token": token,
        "refreshToken": refresh_token,
        "tokenType": "Bearer",
        "expiresInSeconds": access_expiry_secs,
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
            "consentAcceptedAt": consent_accepted_at,
            "consentVersion": consent_version,
            "legalConsentAccepted": legal_consent_accepted,
        }
    })))
}

pub async fn refresh_token(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<RefreshTokenRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let presented_refresh_token = payload.refresh_token.trim();
    if presented_refresh_token.is_empty() {
        return Err(AppError::BadRequest(
            "Refresh token is required".to_string(),
        ));
    }

    let claims = utils::verify_refresh_token(presented_refresh_token)?;

    let requester = utils::extract_requester(&headers);
    let user_agent = extract_user_agent(&headers);

    let refresh_context = match load_refresh_token_context(db.as_ref(), &claims.sub).await {
        Ok(context) => context,
        Err(err) => {
            let reason = if matches!(err, AppError::DatabaseError(_)) {
                "Failed to validate refresh token user state"
            } else {
                "User is not active for token refresh"
            };

            let metadata = if matches!(err, AppError::DatabaseError(_)) {
                json!({ "jti": claims.jti, "error": err.to_string() })
            } else {
                json!({ "jti": claims.jti })
            };

            log_security_event(
                db.as_ref(),
                Some(&claims.sub),
                "AUTH_TOKEN_REFRESH",
                "failed",
                reason,
                &requester,
                user_agent.as_deref(),
                metadata,
            )
            .await;

            return if matches!(err, AppError::DatabaseError(_)) {
                Err(err)
            } else {
                Err(AppError::Unauthorized(
                    "Invalid refresh token session".to_string(),
                ))
            };
        }
    };

    let token = utils::generate_access_token(
        &claims.sub,
        &refresh_context.email,
        &refresh_context.role,
        refresh_context.legal_consent_accepted,
    )?;
    let refresh_token = utils::generate_refresh_token(
        &claims.sub,
        &refresh_context.email,
        &refresh_context.role,
        refresh_context.legal_consent_accepted,
    )?;
    let new_claims = utils::verify_refresh_token(&refresh_token)?;

    if new_claims.sub != claims.sub {
        log_security_event(
            db.as_ref(),
            Some(&claims.sub),
            "AUTH_TOKEN_REFRESH",
            "failed",
            "Refresh token subject mismatch during rotation",
            &requester,
            user_agent.as_deref(),
            json!({ "jti": claims.jti, "newJti": new_claims.jti }),
        )
        .await;

        return Err(AppError::Unauthorized(
            "Invalid refresh token session".to_string(),
        ));
    }

    rotate_refresh_session(
        db.as_ref(),
        &claims,
        presented_refresh_token,
        &refresh_token,
        &new_claims,
        &requester,
        user_agent.as_deref(),
    )
    .await?;

    log_security_event(
        db.as_ref(),
        Some(&claims.sub),
        "AUTH_TOKEN_REFRESH",
        "success",
        "Refresh token rotated successfully",
        &requester,
        user_agent.as_deref(),
        json!({ "previousJti": claims.jti, "newJti": new_claims.jti }),
    )
    .await;

    let access_expiry_secs = std::env::var("JWT_EXPIRY_HOURS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value >= 1 && *value <= 168)
        .unwrap_or(24)
        * 3600;

    Ok(Json(json!({
        "message": "Token refreshed",
        "token": token,
        "refreshToken": refresh_token,
        "tokenType": "Bearer",
        "expiresInSeconds": access_expiry_secs,
    })))
}

pub async fn logout(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<RefreshTokenRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let requester = utils::extract_requester(&headers);
    let user_agent = extract_user_agent(&headers);

    if payload.refresh_token.trim().is_empty() {
        return Ok(Json(json!({ "message": "Logged out" })));
    }

    match utils::verify_refresh_token(payload.refresh_token.trim()) {
        Ok(claims) => {
            let token_hash = utils::hash_token(payload.refresh_token.trim());
            let _ = sqlx::query(
                r#"UPDATE refresh_token_sessions
                   SET revoked_at = NOW(),
                       last_used_at = NOW()
                   WHERE jti = $1
                     AND user_id = $2
                     AND token_hash = $3
                     AND revoked_at IS NULL"#,
            )
            .bind(&claims.jti)
            .bind(&claims.sub)
            .bind(token_hash)
            .execute(db.as_ref())
            .await;

            log_security_event(
                db.as_ref(),
                Some(&claims.sub),
                "AUTH_LOGOUT",
                "success",
                "Refresh token revoked on logout",
                &requester,
                user_agent.as_deref(),
                json!({ "jti": claims.jti }),
            )
            .await;
        }
        Err(_) => {
            log_security_event(
                db.as_ref(),
                None,
                "AUTH_LOGOUT",
                "failed",
                "Logout request included invalid refresh token",
                &requester,
                user_agent.as_deref(),
                json!({}),
            )
            .await;
        }
    }

    Ok(Json(json!({ "message": "Logged out" })))
}

pub async fn forgot_password(
    State(db): State<Arc<PgPool>>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let email = payload.email.trim();
    if email.is_empty() {
        return Err(AppError::BadRequest("Email is required".to_string()));
    }

    utils::validate_email(email)?;

    // Find user by email
    let user = sqlx::query("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let Some(user) = user else {
        // Prevent account enumeration by returning a generic success response.
        return Ok(Json(json!({
            "message": "If the account exists, a password reset code has been sent"
        })));
    };

    let user_id: String = user
        .try_get("id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse user id: {}", e)))?;

    // Generate reset code and store only a hash in persistence.
    let reset_code = generate_password_reset_code();
    let reset_code_hash = utils::hash_token(&reset_code);
    let expires_at = chrono::Utc::now() + Duration::minutes(10);

    // Delete any existing unused reset codes for this user
    sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = $1 AND is_used = FALSE")
        .bind(&user_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to delete old tokens: {}", e)))?;

    // Create new password reset token
    sqlx::query(
        "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(&user_id)
    .bind(&reset_code_hash)
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
                "to": [email],
                "subject": "Davao Security - Password Reset Code",
                "html": html_body
            }))
            .send()
            .await;
    }

    Ok(Json(json!({
        "message": "If the account exists, a password reset code has been sent"
    })))
}

pub async fn verify_reset_code(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<VerifyResetCodeRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let email = payload.email.trim();
    let code = payload.code.trim();
    let requester = utils::extract_requester(&headers);
    let user_key = make_login_key("reset-user", email);
    let ip_key = make_login_key("reset-ip", &requester);

    if email.is_empty() || code.is_empty() {
        return Err(AppError::BadRequest(
            "Email and code are required".to_string(),
        ));
    }

    utils::validate_email(email)?;

    if !is_valid_password_reset_code(code) {
        return Err(AppError::BadRequest(
            "Invalid reset code format".to_string(),
        ));
    }

    if let Some(remaining) = get_lockout_seconds_remaining(db.as_ref(), &user_key).await? {
        return Err(AppError::RateLimited(format!(
            "Too many reset attempts. Try again in {} second(s).",
            remaining
        )));
    }

    if let Some(remaining) = get_lockout_seconds_remaining(db.as_ref(), &ip_key).await? {
        return Err(AppError::RateLimited(format!(
            "Too many reset attempts. Try again in {} second(s).",
            remaining
        )));
    }

    // Find user
    let user = sqlx::query("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let Some(user) = user else {
        let _ = register_login_failure(db.as_ref(), &user_key).await;
        let _ = register_login_failure(db.as_ref(), &ip_key).await;
        return Err(AppError::BadRequest(
            "Invalid or expired reset code".to_string(),
        ));
    };

    let user_id: String = user
        .try_get("id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse user id: {}", e)))?;

    let code_hash = utils::hash_token(code);

    // Verify token hash. Keep a plain-code fallback only for short-lived transition compatibility.
    let token_record = sqlx::query(
        "SELECT 1 FROM password_reset_tokens WHERE user_id = $1 AND is_used = FALSE AND expires_at > NOW() AND (token = $2 OR token = $3) LIMIT 1"
    )
    .bind(&user_id)
    .bind(&code_hash)
    .bind(code)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    if token_record.is_none() {
        let _ = register_login_failure(db.as_ref(), &user_key).await;
        let _ = register_login_failure(db.as_ref(), &ip_key).await;
        return Err(AppError::BadRequest(
            "Invalid or expired reset code".to_string(),
        ));
    }

    clear_login_failures(db.as_ref(), &[user_key, ip_key]).await?;

    Ok(Json(json!({
        "message": "Reset code verified"
    })))
}

pub async fn reset_password(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<ResetPasswordRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let email = payload.email.trim();
    let code = payload.code.trim();
    let new_password = payload.new_password.as_str();
    let requester = utils::extract_requester(&headers);
    let user_key = make_login_key("reset-user", email);
    let ip_key = make_login_key("reset-ip", &requester);

    if email.is_empty() || code.is_empty() || new_password.is_empty() {
        return Err(AppError::BadRequest(
            "Email, code, and new password are required".to_string(),
        ));
    }

    utils::validate_email(email)?;
    utils::validate_password_strength(new_password)?;

    if !is_valid_password_reset_code(code) {
        return Err(AppError::BadRequest(
            "Invalid reset code format".to_string(),
        ));
    }

    if let Some(remaining) = get_lockout_seconds_remaining(db.as_ref(), &user_key).await? {
        return Err(AppError::RateLimited(format!(
            "Too many reset attempts. Try again in {} second(s).",
            remaining
        )));
    }

    if let Some(remaining) = get_lockout_seconds_remaining(db.as_ref(), &ip_key).await? {
        return Err(AppError::RateLimited(format!(
            "Too many reset attempts. Try again in {} second(s).",
            remaining
        )));
    }

    // Find user
    let user = sqlx::query("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let Some(user) = user else {
        let _ = register_login_failure(db.as_ref(), &user_key).await;
        let _ = register_login_failure(db.as_ref(), &ip_key).await;
        return Err(AppError::BadRequest(
            "Invalid or expired reset code".to_string(),
        ));
    };

    let user_id: String = user
        .try_get("id")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse user id: {}", e)))?;

    let code_hash = utils::hash_token(code);

    // Hash new password
    let hashed_password = utils::hash_password(new_password).await?;

    // Redeem token and rotate password atomically to prevent replay races.
    let mut tx = db.begin().await.map_err(|e| {
        AppError::DatabaseError(format!("Failed to start reset transaction: {}", e))
    })?;

    let redeemed_token_id = sqlx::query_scalar::<_, String>(
        r#"UPDATE password_reset_tokens
           SET is_used = TRUE
           WHERE user_id = $1
             AND is_used = FALSE
             AND expires_at > NOW()
             AND (token = $2 OR token = $3)
           RETURNING id"#,
    )
    .bind(&user_id)
    .bind(&code_hash)
    .bind(code)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to redeem reset token: {}", e)))?;

    if redeemed_token_id.is_none() {
        tx.rollback().await.map_err(|e| {
            AppError::DatabaseError(format!("Failed to rollback reset transaction: {}", e))
        })?;

        let _ = register_login_failure(db.as_ref(), &user_key).await;
        let _ = register_login_failure(db.as_ref(), &ip_key).await;
        return Err(AppError::BadRequest(
            "Invalid or expired reset code".to_string(),
        ));
    }

    sqlx::query("UPDATE users SET password = $1 WHERE id = $2")
        .bind(&hashed_password)
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update password: {}", e)))?;

    // Revoke any active refresh sessions after a password reset.
    sqlx::query(
        r#"UPDATE refresh_token_sessions
           SET revoked_at = NOW(),
               last_used_at = NOW()
           WHERE user_id = $1
             AND revoked_at IS NULL"#,
    )
    .bind(&user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to revoke refresh sessions after reset: {}", e))
    })?;

    tx.commit()
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to commit reset transaction: {}", e)))?;

    clear_login_failures(db.as_ref(), &[user_key, ip_key]).await?;

    Ok(Json(json!({
        "message": "Password reset successful. You can now login with your new password."
    })))
}

#[cfg(test)]
mod tests {
    use super::canonicalize_login_role;

    use crate::error::AppError;

    #[test]
    fn canonicalize_login_role_maps_legacy_user_to_guard() {
        let role = canonicalize_login_role("user").expect("legacy user role should map to guard");
        assert_eq!(role, "guard");
    }

    #[test]
    fn canonicalize_login_role_rejects_unknown_role() {
        let result = canonicalize_login_role("guest");
        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    #[test]
    fn canonicalize_login_role_accepts_operational_roles() {
        let superadmin =
            canonicalize_login_role("SUPERADMIN").expect("superadmin should remain allowed");
        let admin = canonicalize_login_role("admin").expect("admin should remain allowed");
        let supervisor =
            canonicalize_login_role("supervisor").expect("supervisor should remain allowed");
        let guard = canonicalize_login_role("guard").expect("guard should remain allowed");

        assert_eq!(superadmin, "superadmin");
        assert_eq!(admin, "admin");
        assert_eq!(supervisor, "supervisor");
        assert_eq!(guard, "guard");
    }
}
