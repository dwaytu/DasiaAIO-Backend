use axum::{
    extract::State,
    http::HeaderMap,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    utils,
};

#[derive(Debug, Deserialize)]
pub struct SubmitFeedbackRequest {
    pub rating: i32,
    pub comments: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct FeedbackRecord {
    pub id: String,
    pub user_id: String,
    pub rating: i32,
    pub comments: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct FeedbackWithUserResponse {
    pub id: String,
    pub user_id: String,
    pub user_name: String,
    pub user_role: String,
    pub rating: i32,
    pub comments: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct FeedbackStatusResponse {
    pub has_submitted: bool,
}

fn extract_claims(headers: &HeaderMap) -> AppResult<utils::TokenClaims> {
    let token = utils::extract_bearer_token(headers)?;
    utils::verify_token(&token)
}

pub async fn submit_feedback(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<SubmitFeedbackRequest>,
) -> AppResult<Json<FeedbackRecord>> {
    let claims = extract_claims(&headers)?;
    let role = utils::normalize_role(&claims.role);

    if !matches!(role.as_str(), "guard" | "supervisor" | "admin") {
        return Err(AppError::Forbidden(
            "Only guard, supervisor, and admin users can submit feedback".to_string(),
        ));
    }

    if !(1..=5).contains(&payload.rating) {
        return Err(AppError::BadRequest(
            "Rating must be between 1 and 5".to_string(),
        ));
    }

    let feedback_id = utils::generate_id();

    let feedback = sqlx::query_as::<_, FeedbackRecord>(
        r#"
        INSERT INTO feedback (id, user_id, rating, comments)
        VALUES ($1, $2, $3, $4)
        RETURNING id, user_id, rating, comments, created_at
        "#,
    )
    .bind(&feedback_id)
    .bind(&claims.sub)
    .bind(payload.rating)
    .bind(&payload.comments)
    .fetch_one(db.as_ref())
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db_err)
            if db_err.code().as_deref() == Some("23505")
                || db_err.constraint() == Some("feedback_user_unique") =>
        {
            AppError::Conflict("You have already submitted feedback".to_string())
        }
        other => AppError::DatabaseError(other.to_string()),
    })?;

    Ok(Json(feedback))
}

pub async fn list_feedback(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<FeedbackWithUserResponse>>> {
    let claims = extract_claims(&headers)?;
    let role = utils::normalize_role(&claims.role);

    if role != "superadmin" {
        return Err(AppError::Forbidden(
            "Only superadmin can view all feedback".to_string(),
        ));
    }

    let feedback_items = sqlx::query_as::<_, FeedbackWithUserResponse>(
        r#"
        SELECT
            f.id,
            f.user_id,
            u.full_name AS user_name,
            LOWER(u.role) AS user_role,
            f.rating,
            f.comments,
            f.created_at
        FROM feedback f
        INNER JOIN users u ON u.id = f.user_id
        ORDER BY f.created_at DESC
        "#,
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    Ok(Json(feedback_items))
}

pub async fn get_feedback_status(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<FeedbackStatusResponse>> {
    let claims = extract_claims(&headers)?;

    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM feedback WHERE user_id = $1")
        .bind(&claims.sub)
        .fetch_one(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    Ok(Json(FeedbackStatusResponse {
        has_submitted: count > 0,
    }))
}
