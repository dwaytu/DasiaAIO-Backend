use crate::error::{AppError, AppResult};
use axum::http::HeaderMap;
use regex::Regex;
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize, Clone, Copy)]
pub struct PaginationQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

pub fn resolve_pagination(query: PaginationQuery, default_size: i64, max_size: i64) -> (i64, i64, i64) {
    let page = query.page.unwrap_or(1).max(1);
    let requested_size = query.page_size.unwrap_or(default_size).max(1);
    let page_size = requested_size.min(max_size.max(1));
    let offset = (page - 1) * page_size;
    (page, page_size, offset)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenClaims {
    pub sub: String,  // user_id
    pub email: String,
    pub role: String,
    pub exp: i64,     // expiration time
    pub iat: i64,     // issued at time
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RefreshTokenClaims {
    pub sub: String,
    pub email: String,
    pub role: String,
    pub token_type: String,
    pub jti: String,
    pub exp: i64,
    pub iat: i64,
}

fn jwt_secret() -> String {
    std::env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key-change-in-production".to_string())
}

pub fn generate_access_token(user_id: &str, email: &str, role: &str) -> AppResult<String> {
    let secret = jwt_secret();
    let expiry_hours = std::env::var("JWT_EXPIRY_HOURS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value >= 1 && *value <= 168)
        .unwrap_or(24);

    let claims = TokenClaims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        exp: (Utc::now() + Duration::hours(expiry_hours)).timestamp(),
        iat: Utc::now().timestamp(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|e| AppError::InternalServerError(format!("Failed to generate token: {}", e)))
}

pub fn generate_token(user_id: &str, email: &str, role: &str) -> AppResult<String> {
    generate_access_token(user_id, email, role)
}

pub fn generate_refresh_token(user_id: &str, email: &str, role: &str) -> AppResult<String> {
    let secret = jwt_secret();
    let refresh_hours = std::env::var("JWT_REFRESH_EXPIRY_HOURS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value >= 24 && *value <= 24 * 30)
        .unwrap_or(24 * 7);

    let claims = RefreshTokenClaims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        token_type: "refresh".to_string(),
        jti: uuid::Uuid::new_v4().to_string(),
        exp: (Utc::now() + Duration::hours(refresh_hours)).timestamp(),
        iat: Utc::now().timestamp(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|e| AppError::InternalServerError(format!("Failed to generate refresh token: {}", e)))
}

pub fn verify_token(token: &str) -> AppResult<TokenClaims> {
    let secret = jwt_secret();
    
    decode::<TokenClaims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|e| AppError::Unauthorized(format!("Invalid or expired token: {}", e)))
}

pub fn verify_refresh_token(token: &str) -> AppResult<RefreshTokenClaims> {
    let secret = jwt_secret();

    let claims = decode::<RefreshTokenClaims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|e| AppError::Unauthorized(format!("Invalid or expired refresh token: {}", e)))?;

    if claims.token_type != "refresh" {
        return Err(AppError::Unauthorized("Invalid refresh token type".to_string()));
    }

    Ok(claims)
}

pub fn extract_bearer_token(headers: &HeaderMap) -> AppResult<String> {
    let auth_header = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("Invalid Authorization header format".to_string()))?;

    if token.is_empty() {
        return Err(AppError::Unauthorized("Missing bearer token".to_string()));
    }

    Ok(token.to_string())
}

pub fn extract_requester(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| raw.split(',').next())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .or_else(|| {
            headers
                .get("cf-connecting-ip")
                .and_then(|value| value.to_str().ok())
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "unknown-client".to_string())
}

pub fn normalize_role(role: &str) -> String {
    let normalized = role.to_lowercase();
    if normalized == "user" {
        "guard".to_string()
    } else {
        normalized
    }
}

pub fn role_rank(role: &str) -> Option<u8> {
    match normalize_role(role).as_str() {
        "guard" => Some(1),
        "supervisor" => Some(2),
        "admin" => Some(3),
        "superadmin" => Some(4),
        _ => None,
    }
}

pub fn role_permissions(role: &str) -> &'static [&'static str] {
    match normalize_role(role).as_str() {
        "superadmin" => &[
            "create_user",
            "update_user",
            "delete_user",
            "approve_guard_registration",
            "manage_firearms",
            "allocate_firearm",
            "manage_armored_cars",
            "assign_vehicle_driver",
            "manage_missions",
            "manage_schedules",
            "view_analytics",
            "manage_trip_status",
            "view_support_tickets",
            "create_support_ticket",
            "manage_notifications",
            "view_merit",
            "manage_merit",
        ],
        "admin" => &[
            "create_user",
            "update_user",
            "delete_user",
            "approve_guard_registration",
            "manage_firearms",
            "allocate_firearm",
            "manage_armored_cars",
            "assign_vehicle_driver",
            "manage_missions",
            "manage_schedules",
            "view_analytics",
            "manage_trip_status",
            "view_support_tickets",
            "create_support_ticket",
            "manage_notifications",
            "view_merit",
            "manage_merit",
        ],
        "supervisor" => &[
            "update_user",
            "approve_guard_registration",
            "manage_firearms",
            "allocate_firearm",
            "manage_armored_cars",
            "assign_vehicle_driver",
            "manage_missions",
            "manage_schedules",
            "view_analytics",
            "manage_trip_status",
            "view_support_tickets",
            "create_support_ticket",
            "manage_notifications",
            "view_merit",
            "manage_merit",
        ],
        "guard" => &[
            "create_support_ticket",
            "manage_notifications",
            "view_merit",
        ],
        _ => &[],
    }
}

pub fn has_permission(role: &str, permission: &str) -> bool {
    role_permissions(role).contains(&permission)
}

pub fn can_create_role(actor_role: &str, target_role: &str) -> bool {
    let actor = normalize_role(actor_role);
    let target = normalize_role(target_role);

    match actor.as_str() {
        "superadmin" => matches!(target.as_str(), "admin" | "supervisor" | "guard"),
        "admin" => matches!(target.as_str(), "supervisor" | "guard"),
        _ => false,
    }
}

pub fn require_min_role(headers: &HeaderMap, minimum_role: &str) -> AppResult<TokenClaims> {
    let token = extract_bearer_token(headers)?;
    let claims = verify_token(&token)?;

    let actor_rank = role_rank(&claims.role)
        .ok_or_else(|| AppError::Forbidden("Unknown account role".to_string()))?;
    let required_rank = role_rank(minimum_role)
        .ok_or_else(|| AppError::InternalServerError("Invalid RBAC policy role".to_string()))?;

    if actor_rank < required_rank {
        return Err(AppError::Forbidden(format!(
            "This action requires '{}' or higher role",
            minimum_role
        )));
    }

    Ok(claims)
}

pub fn require_self_or_min_role(
    headers: &HeaderMap,
    target_user_id: &str,
    minimum_role: &str,
) -> AppResult<TokenClaims> {
    let token = extract_bearer_token(headers)?;
    let claims = verify_token(&token)?;

    if claims.sub == target_user_id {
        return Ok(claims);
    }

    let actor_rank = role_rank(&claims.role)
        .ok_or_else(|| AppError::Forbidden("Unknown account role".to_string()))?;
    let required_rank = role_rank(minimum_role)
        .ok_or_else(|| AppError::InternalServerError("Invalid RBAC policy role".to_string()))?;

    if actor_rank < required_rank {
        return Err(AppError::Forbidden(format!(
            "This action requires '{}' role unless accessing your own account",
            minimum_role
        )));
    }

    Ok(claims)
}

pub fn generate_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn generate_confirmation_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:06}", rng.gen_range(0..1000000))
}

pub async fn hash_password(password: &str) -> AppResult<String> {
    let hash_cost = std::env::var("BCRYPT_COST")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value >= 10 && *value <= 14)
        .unwrap_or(12);

    let hashed = bcrypt::hash(password, hash_cost)
        .map_err(|e| AppError::InternalServerError(format!("Failed to hash password: {}", e)))?;
    Ok(hashed)
}

pub async fn verify_password(password: &str, hash: &str) -> AppResult<bool> {
    let valid = bcrypt::verify(password, hash)
        .map_err(|e| AppError::InternalServerError(format!("Failed to verify password: {}", e)))?;
    Ok(valid)
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn validate_gmail(email: &str) -> AppResult<()> {
    if !email.ends_with("@gmail.com") {
        return Err(AppError::ValidationError(
            "You must use a Gmail account (email must end with @gmail.com)".to_string()
        ));
    }
    Ok(())
}

pub fn validate_email(email: &str) -> AppResult<()> {
    let email_regex = Regex::new(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    ).unwrap();
    
    if !email_regex.is_match(email) {
        return Err(AppError::ValidationError("Invalid email format".to_string()));
    }
    Ok(())
}

pub fn validate_password_strength(password: &str) -> AppResult<()> {
    let min_len = std::env::var("PASSWORD_MIN_LENGTH")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value >= 8 && *value <= 128)
        .unwrap_or(12);

    if password.len() < min_len {
        return Err(AppError::ValidationError(format!(
            "Password must be at least {} characters",
            min_len
        )));
    }

    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());

    if !(has_upper && has_lower && has_digit && has_special) {
        return Err(AppError::ValidationError(
            "Password must include upper, lower, number, and special character".to_string(),
        ));
    }

    Ok(())
}

pub async fn send_confirmation_email(
    api_key: &str,
    to_email: &str,
    code: &str,
) -> AppResult<()> {
    let html_body = format!(
        r#"
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px; text-align: center; border-radius: 8px 8px 0 0;">
                <h1 style="color: white; margin: 0;">Davao Security & Investigation Agency</h1>
                <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0 0;">Email Verification</p>
            </div>
            <div style="background: #f9f9f9; padding: 40px; border-radius: 0 0 8px 8px;">
                <h2 style="color: #333; margin-top: 0;">Verify Your Email Address</h2>
                <p style="color: #666; font-size: 16px; line-height: 1.6;">
                    Thank you for registering with Davao Security & Investigation Agency.
                    Please use the following verification code to confirm your email address:
                </p>
                <div style="background: white; border: 2px solid #667eea; border-radius: 8px; padding: 20px; text-align: center; margin: 30px 0;">
                    <code style="font-size: 32px; font-weight: bold; color: #667eea; letter-spacing: 2px;">{}</code>
                </div>
                <p style="color: #666; font-size: 14px;">
                    This code will expire in 10 minutes. If you did not request this verification code, please ignore this email.
                </p>
                <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
                <p style="color: #999; font-size: 12px; margin: 0;">
                    © 2024 Davao Security & Investigation Agency. All rights reserved.
                </p>
            </div>
        </div>
        "#,
        code
    );

    let client = reqwest::Client::new();
    let response = client
        .post("https://api.resend.com/emails")
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&serde_json::json!({
            "from": "Sentinel DASIA <noreply@dasiasentinel.xyz>",
            "to": [to_email],
            "subject": "Davao Security - Email Verification Code",
            "html": html_body
        }))
        .send()
        .await
        .map_err(|e| AppError::InternalServerError(format!("Failed to reach email API: {}", e)))?;

    if response.status().is_success() {
        tracing::info!("Verification email sent successfully to {}", to_email);
        Ok(())
    } else {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        tracing::error!("Failed to send verification email to {}: {} {}", to_email, status, error_text);
        Err(AppError::InternalServerError(format!("Email API error {}: {}", status, error_text)))
    }
}

