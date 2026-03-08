use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::Utc;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    error::{AppError, AppResult},
    models::{CreateTrainingRecordRequest, TrainingRecord},
    utils,
};

/// POST /api/training-records
pub async fn create_training_record(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CreateTrainingRecordRequest>,
) -> AppResult<(StatusCode, Json<TrainingRecord>)> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let rec = sqlx::query_as::<_, TrainingRecord>(
        r#"
        INSERT INTO training_records
            (id, guard_id, training_type, completed_date, expiry_date,
             certificate_number, status, notes, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, 'valid', $7, $8, $8)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(&payload.guard_id)
    .bind(&payload.training_type)
    .bind(payload.completed_date)
    .bind(payload.expiry_date)
    .bind(payload.certificate_number.as_deref())
    .bind(payload.notes.as_deref())
    .bind(now)
    .fetch_one(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create training record: {}", e)))?;

    Ok((StatusCode::CREATED, Json(rec)))
}

/// GET /api/training-records/:guard_id
pub async fn get_guard_training(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(guard_id): Path<String>,
) -> AppResult<Json<Vec<TrainingRecord>>> {
    let _claims = utils::require_self_or_min_role(&headers, &guard_id, "supervisor")?;

    // Auto-expire any records past their expiry_date first
    sqlx::query(
        "UPDATE training_records
         SET status = 'expired', updated_at = NOW()
         WHERE status = 'valid'
           AND expiry_date IS NOT NULL
           AND expiry_date < NOW()",
    )
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Auto-expire error: {}", e)))?;

    let recs = sqlx::query_as::<_, TrainingRecord>(
        "SELECT * FROM training_records WHERE guard_id = $1 ORDER BY completed_date DESC",
    )
    .bind(&guard_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(recs))
}

/// GET /api/training-records/expiring  (expiring within 30 days)
pub async fn get_expiring_training(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<TrainingRecord>>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let recs = sqlx::query_as::<_, TrainingRecord>(
        r#"
        SELECT * FROM training_records
        WHERE status = 'valid'
          AND expiry_date IS NOT NULL
          AND expiry_date BETWEEN NOW() AND NOW() + INTERVAL '30 days'
        ORDER BY expiry_date ASC
        "#,
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(recs))
}
