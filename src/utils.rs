use crate::error::{AppError, AppResult};
use regex::Regex;
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenClaims {
    pub sub: String,  // user_id
    pub email: String,
    pub role: String,
    pub exp: i64,     // expiration time
    pub iat: i64,     // issued at time
}

pub fn generate_token(user_id: &str, email: &str, role: &str) -> AppResult<String> {
    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key-change-in-production".to_string());
    
    let claims = TokenClaims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        exp: (Utc::now() + Duration::days(7)).timestamp(),
        iat: Utc::now().timestamp(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|e| AppError::InternalServerError(format!("Failed to generate token: {}", e)))
}

pub fn verify_token(token: &str) -> AppResult<TokenClaims> {
    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key-change-in-production".to_string());
    
    decode::<TokenClaims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|e| AppError::BadRequest(format!("Invalid or expired token: {}", e)))
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
    let hashed = bcrypt::hash(password, 10)
        .map_err(|e| AppError::InternalServerError(format!("Failed to hash password: {}", e)))?;
    Ok(hashed)
}

pub async fn verify_password(password: &str, hash: &str) -> AppResult<bool> {
    let valid = bcrypt::verify(password, hash)
        .map_err(|e| AppError::InternalServerError(format!("Failed to verify password: {}", e)))?;
    Ok(valid)
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

