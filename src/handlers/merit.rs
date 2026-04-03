use axum::{
    extract::{Path, State},
    http::HeaderMap,
    http::StatusCode,
    Json,
};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    models::{
        CalculateMeritScoreRequest, ClientEvaluation, CreateClientEvaluationRequest,
        GuardMeritScore, MeritScoreResponse, MeritStats, RankedGuardResponse,
    },
    utils,
};

// Calculate merit score for a guard based on performance metrics
pub async fn calculate_merit_score(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CalculateMeritScoreRequest>,
) -> AppResult<(StatusCode, Json<MeritScoreResponse>)> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let guard_id = &payload.guard_id;

    // 1. Calculate Attendance Score (% of shifts attended)
    let attendance_result = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(CASE WHEN status = 'completed' THEN 1 END)::int8 as completed 
         FROM attendance 
         WHERE guard_id = $1",
    )
    .bind(guard_id)
    .fetch_one(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to query attendance: {}", e)))?;

    let total_shifts =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::int8 FROM shifts WHERE guard_id = $1")
            .bind(guard_id)
            .fetch_one(db.as_ref())
            .await
            .unwrap_or(0);

    let attendance_score = if total_shifts > 0 {
        (attendance_result as f64 / total_shifts as f64) * 100.0
    } else {
        0.0
    };

    // 2. Calculate Punctuality Score (% of on-time check-ins)
    let on_time_count = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT COUNT(*) FROM punctuality_records WHERE guard_id = $1 AND is_on_time = true",
    )
    .bind(guard_id)
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(None)
    .unwrap_or(0) as i32;

    let total_punctuality_records = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT COUNT(*) FROM punctuality_records WHERE guard_id = $1",
    )
    .bind(guard_id)
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(None)
    .unwrap_or(0);

    let punctuality_score = if total_punctuality_records > 0 {
        (on_time_count as f64 / total_punctuality_records as f64) * 100.0
    } else {
        0.0
    };

    // 3. Calculate Client Rating (average of all evaluations)
    let (avg_rating, eval_count): (Option<f64>, Option<i64>) = sqlx::query_as(
        "SELECT CAST(AVG(rating) AS FLOAT8), COUNT(*)::int8 FROM client_evaluations WHERE guard_id = $1"
    )
    .bind(guard_id)
    .fetch_one(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to query evaluations: {}", e)))?;

    let client_rating = match avg_rating {
        Some(avg) => (avg / 5.0) * 100.0, // Convert 0-5 to 0-100
        None => 0.0,
    };
    let eval_count = eval_count.unwrap_or(0) as i32;

    // 4. Calculate Overall Score (weighted average)
    // Attendance: 30%, Punctuality: 35%, Client Rating: 35%
    let overall_score =
        (attendance_score * 0.30) + (punctuality_score * 0.35) + (client_rating * 0.35);

    // 5. Determine Rank based on score
    let rank = match overall_score {
        score if score >= 90.0 => "Gold",
        score if score >= 80.0 => "Silver",
        score if score >= 70.0 => "Bronze",
        _ => "Standard",
    };

    // 6. Get late and no-show counts
    let late_count = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT COUNT(*) FROM punctuality_records WHERE guard_id = $1 AND status = 'late'",
    )
    .bind(guard_id)
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(None)
    .unwrap_or(0) as i32;

    let no_show_count = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT COUNT(*) FROM punctuality_records WHERE guard_id = $1 AND status = 'no_show'",
    )
    .bind(guard_id)
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(None)
    .unwrap_or(0) as i32;

    // 7. Update or create merit score record
    let merit_score_id = sqlx::query_scalar::<_, Option<String>>(
        "SELECT id FROM guard_merit_scores WHERE guard_id = $1",
    )
    .bind(guard_id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
    .flatten();

    if let Some(_id) = merit_score_id {
        // Update existing record
        sqlx::query(
            "UPDATE guard_merit_scores 
             SET attendance_score = $2, punctuality_score = $3, client_rating = $4, 
                 overall_score = $5, rank = $6, total_shifts_completed = $7,
                 on_time_count = $8, late_count = $9, no_show_count = $10,
                 average_client_rating = $11, evaluation_count = $12, last_calculated_at = CURRENT_TIMESTAMP
             WHERE guard_id = $1"
        )
        .bind(guard_id)
        .bind(attendance_score)
        .bind(punctuality_score)
        .bind(client_rating)
        .bind(overall_score)
        .bind(rank)
        .bind(total_shifts as i32)
        .bind(on_time_count)
        .bind(late_count)
        .bind(no_show_count)
        .bind(client_rating / 100.0 * 5.0) // Convert back to 0-5
        .bind(eval_count)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update merit score: {}", e)))?;
    } else {
        // Create new record
        let id = utils::generate_id();
        sqlx::query(
            "INSERT INTO guard_merit_scores 
             (id, guard_id, attendance_score, punctuality_score, client_rating, overall_score, rank, 
              total_shifts_completed, on_time_count, late_count, no_show_count, average_client_rating, evaluation_count)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)"
        )
        .bind(&id)
        .bind(guard_id)
        .bind(attendance_score)
        .bind(punctuality_score)
        .bind(client_rating)
        .bind(overall_score)
        .bind(rank)
        .bind(total_shifts as i32)
        .bind(on_time_count)
        .bind(late_count)
        .bind(no_show_count)
        .bind(client_rating / 100.0 * 5.0)
        .bind(eval_count)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to create merit score: {}", e)))?;
    }

    // Get guard name
    let guard_name: Option<String> =
        sqlx::query_scalar("SELECT full_name FROM users WHERE id = $1")
            .bind(guard_id)
            .fetch_optional(db.as_ref())
            .await
            .ok()
            .flatten();

    Ok((
        StatusCode::OK,
        Json(MeritScoreResponse {
            guard_id: guard_id.clone(),
            guard_name,
            overall_score: overall_score.min(100.0).max(0.0),
            rank: Some(rank.to_string()),
            attendance_score: attendance_score.min(100.0).max(0.0),
            punctuality_score: punctuality_score.min(100.0).max(0.0),
            client_rating: client_rating.min(100.0).max(0.0),
            stats: MeritStats {
                total_shifts: total_shifts as i32,
                on_time_count,
                late_count,
                no_show_count,
                evaluations: eval_count,
                average_rating: avg_rating.unwrap_or(0.0),
            },
        }),
    ))
}

// Get merit score for a specific guard
pub async fn get_guard_merit_score(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(guard_id): Path<String>,
) -> AppResult<Json<MeritScoreResponse>> {
    let _claims = utils::require_self_or_min_role(&headers, &guard_id, "supervisor")?;

    let merit_score: GuardMeritScore = sqlx::query_as(
        "SELECT id, guard_id, CAST(attendance_score AS FLOAT8), CAST(punctuality_score AS FLOAT8), 
                CAST(client_rating AS FLOAT8), CAST(overall_score AS FLOAT8), rank, 
                total_shifts_completed, on_time_count, late_count, no_show_count, 
                CAST(average_client_rating AS FLOAT8), evaluation_count, last_calculated_at, 
                created_at, updated_at
         FROM guard_merit_scores WHERE guard_id = $1",
    )
    .bind(&guard_id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Merit score not found".to_string()))?;

    let guard_name: Option<String> =
        sqlx::query_scalar("SELECT full_name FROM users WHERE id = $1")
            .bind(&guard_id)
            .fetch_optional(db.as_ref())
            .await
            .ok()
            .flatten();

    Ok(Json(MeritScoreResponse {
        guard_id,
        guard_name,
        overall_score: merit_score.overall_score,
        rank: merit_score.rank,
        attendance_score: merit_score.attendance_score,
        punctuality_score: merit_score.punctuality_score,
        client_rating: merit_score.client_rating,
        stats: MeritStats {
            total_shifts: merit_score.total_shifts_completed.unwrap_or(0),
            on_time_count: merit_score.on_time_count.unwrap_or(0),
            late_count: merit_score.late_count.unwrap_or(0),
            no_show_count: merit_score.no_show_count.unwrap_or(0),
            evaluations: merit_score.evaluation_count.unwrap_or(0),
            average_rating: merit_score.average_client_rating.unwrap_or(0.0),
        },
    }))
}

// Get all guards ranked by merit score
pub async fn get_ranked_guards(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let guards = sqlx::query_as::<_, (String, String, f64, Option<String>, i32, i32, f64)>(
        "SELECT gms.guard_id, u.full_name, CAST(gms.overall_score AS FLOAT8), gms.rank, 
                gms.on_time_count, 
                COALESCE(gms.on_time_count + gms.late_count + gms.no_show_count, 0) as total_tracked,
                CAST(gms.average_client_rating AS FLOAT8)
         FROM guard_merit_scores gms
         JOIN users u ON gms.guard_id = u.id
         WHERE u.role IN ('guard')
         ORDER BY gms.overall_score DESC, u.full_name"
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to query guards: {}", e)))?;

    let ranked: Vec<RankedGuardResponse> = guards
        .into_iter()
        .enumerate()
        .map(
            |(idx, (guard_id, guard_name, score, rank, on_time, total, rating))| {
                let on_time_pct = if total > 0 {
                    (on_time as f64 / total as f64) * 100.0
                } else {
                    0.0
                };

                RankedGuardResponse {
                    rank: (idx + 1) as i32,
                    guard_id,
                    guard_name: Some(guard_name),
                    overall_score: score,
                    merit_rank: rank,
                    on_time_percentage: on_time_pct,
                    client_rating: rating,
                }
            },
        )
        .collect();

    Ok(Json(json!({
        "total": ranked.len(),
        "rankings": ranked
    })))
}

// Submit client evaluation for a guard
pub async fn submit_client_evaluation(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CreateClientEvaluationRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    if payload.rating < 0.0 || payload.rating > 5.0 {
        return Err(AppError::BadRequest(
            "Rating must be between 0 and 5".to_string(),
        ));
    }

    let id = utils::generate_id();
    sqlx::query(
        "INSERT INTO client_evaluations 
         (id, guard_id, shift_id, mission_id, evaluator_name, evaluator_role, rating, comment)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&id)
    .bind(&payload.guard_id)
    .bind(&payload.shift_id)
    .bind(&payload.mission_id)
    .bind(&payload.evaluator_name)
    .bind(&payload.evaluator_role)
    .bind(payload.rating)
    .bind(&payload.comment)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create evaluation: {}", e)))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "message": "Evaluation submitted successfully"
        })),
    ))
}

// Get all evaluations for a guard
pub async fn get_guard_evaluations(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(guard_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_self_or_min_role(&headers, &guard_id, "supervisor")?;

    let evaluations = sqlx::query_as::<_, ClientEvaluation>(
        "SELECT id, guard_id, shift_id, mission_id, evaluator_name, evaluator_role, 
                CAST(rating AS FLOAT8) AS rating, comment, created_at 
         FROM client_evaluations 
         WHERE guard_id = $1
         ORDER BY created_at DESC",
    )
    .bind(&guard_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to query evaluations: {}", e)))?;

    let avg_rating = evaluations.iter().map(|e| e.rating).sum::<f64>()
        / if evaluations.is_empty() {
            1.0
        } else {
            evaluations.len() as f64
        };

    Ok(Json(json!({
        "total": evaluations.len(),
        "average_rating": avg_rating,
        "evaluations": evaluations
    })))
}

// Get top-performing guards for overtime assignment
pub async fn get_overtime_candidates(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    // Filter for Gold and Silver rank guards (top performers)
    let candidates = sqlx::query_as::<_, (String, String, f64, Option<String>)>(
        "SELECT gms.guard_id, u.full_name, CAST(gms.overall_score AS FLOAT8), gms.rank
         FROM guard_merit_scores gms
         JOIN users u ON gms.guard_id = u.id
         WHERE u.role IN ('guard') AND gms.rank IN ('Gold', 'Silver')
         ORDER BY gms.overall_score DESC
         LIMIT 20",
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to query candidates: {}", e)))?;

    Ok(Json(json!({
        "total": candidates.len(),
        "candidates": candidates.into_iter().map(|(id, name, score, rank)| {
            json!({
                "guardId": id,
                "guardName": name,
                "overallScore": score,
                "rank": rank
            })
        }).collect::<Vec<_>>()
    })))
}

