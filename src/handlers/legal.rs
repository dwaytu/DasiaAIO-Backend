use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use serde_json::json;
use sqlx::{PgPool, Row};
use std::sync::Arc;

use crate::{error::AppError, error::AppResult, utils};

fn refresh_expiry_datetime(refresh_exp: i64) -> AppResult<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp(refresh_exp, 0).ok_or_else(|| {
        AppError::InternalServerError("Failed to resolve refresh token expiry timestamp".to_string())
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct ConsentAcceptanceRequest {
    pub terms_accepted: bool,
    pub privacy_accepted: bool,
    pub acceptable_use_accepted: bool,
    pub consent_version: Option<String>,
}

pub async fn record_consent_acceptance(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<ConsentAcceptanceRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if !(payload.terms_accepted && payload.privacy_accepted && payload.acceptable_use_accepted) {
        return Err(AppError::BadRequest(
            "Terms, Privacy Policy, and Acceptable Use Policy must all be accepted."
                .to_string(),
        ));
    }

    let token = utils::extract_bearer_token(&headers)?;
    let claims = utils::verify_token(&token)?;

    let consent_version = payload
        .consent_version
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("2026-03-28")
        .to_string();

    let requester = utils::extract_requester(&headers);
    let user_agent = headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();

    let consent_row = sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
        r#"UPDATE users
           SET consent_accepted_at = CURRENT_TIMESTAMP,
               consent_version = $2,
               consent_ip = $3,
               consent_user_agent = $4,
               updated_at = CURRENT_TIMESTAMP
           WHERE id = $1
           RETURNING consent_accepted_at"#,
    )
    .bind(&claims.sub)
    .bind(&consent_version)
    .bind(&requester)
    .bind(if user_agent.is_empty() {
        None::<String>
    } else {
        Some(user_agent)
    })
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to record legal consent: {}", e)))?;

    let consent_accepted_at = consent_row
        .ok_or_else(|| AppError::NotFound("User record not found for consent update".to_string()))?;

    let token = utils::generate_access_token(&claims.sub, &claims.email, &claims.role, true)?;
    let refresh_token = utils::generate_refresh_token(&claims.sub, &claims.email, &claims.role, true)?;
    let refresh_claims = utils::verify_refresh_token(&refresh_token)?;

    sqlx::query(
        r#"INSERT INTO refresh_token_sessions (
                jti, user_id, token_hash, issued_at, expires_at, source_ip, user_agent
           ) VALUES ($1, $2, $3, NOW(), $4, $5, $6)"#,
    )
    .bind(&refresh_claims.jti)
    .bind(&claims.sub)
    .bind(utils::hash_token(&refresh_token))
    .bind(refresh_expiry_datetime(refresh_claims.exp)?)
    .bind(&requester)
    .bind(
        headers
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string()),
    )
    .execute(db.as_ref())
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to persist consent refresh token session: {}",
            e
        ))
    })?;

    Ok(Json(json!({
        "message": "Legal consent recorded",
        "consentAcceptedAt": consent_accepted_at,
        "consentVersion": consent_version,
        "token": token,
        "refreshToken": refresh_token,
        "legalConsentAccepted": true
    })))
}

pub async fn get_consent_status(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let token = utils::extract_bearer_token(&headers)?;
    let claims = utils::verify_token(&token)?;

    let row = sqlx::query(
        "SELECT consent_accepted_at, consent_version FROM users WHERE id = $1",
    )
    .bind(&claims.sub)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch consent status: {}", e)))?;

    let row = row.ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let consent_accepted_at: Option<chrono::DateTime<chrono::Utc>> =
        row.try_get("consent_accepted_at")
            .map_err(|e| AppError::DatabaseError(format!("Failed to parse consent_accepted_at: {}", e)))?;
    let consent_version: Option<String> = row
        .try_get("consent_version")
        .map_err(|e| AppError::DatabaseError(format!("Failed to parse consent_version: {}", e)))?;

    Ok(Json(json!({
        "legalConsentAccepted": consent_accepted_at.is_some(),
        "consentAcceptedAt": consent_accepted_at,
        "consentVersion": consent_version
    })))
}
