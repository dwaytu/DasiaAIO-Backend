use axum::{
    extract::{Path, Query, State},
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
        GuardMeritScore, MeritScoreBasis, MeritScoreResponse, MeritStats, RankedGuardResponse,
    },
    services::guard_performance_history,
    utils,
};

const ATTENDANCE_SCORE_BATCH: &str = "capstone-live-october-2026";

fn saved_score_basis(rank: Option<&str>, from_attendance_batch: bool) -> MeritScoreBasis {
    match rank {
        Some("Excellent" | "Good" | "For review") if from_attendance_batch => {
            MeritScoreBasis::AttendancePunctuality
        }
        Some("Gold" | "Silver" | "Bronze" | "Standard") => MeritScoreBasis::WeightedMerit,
        _ => MeritScoreBasis::Saved,
    }
}

fn validate_evaluation_rating(rating: f64) -> AppResult<()> {
    if !rating.is_finite() || !(1.0..=5.0).contains(&rating) {
        return Err(AppError::BadRequest(
            "Rating must be between 1 and 5".to_string(),
        ));
    }
    Ok(())
}

async fn guard_evaluation_summary(db: &PgPool, guard_id: &str) -> AppResult<(Option<f64>, i64)> {
    sqlx::query_as(
        "SELECT AVG(rating)::FLOAT8, COUNT(*) FROM client_evaluations WHERE guard_id = $1",
    )
    .bind(guard_id)
    .fetch_one(db)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to query evaluations: {e}")))
}

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

    // 3. Calculate the evaluator rating (average of supervisor/admin evaluations)
    let (avg_rating, eval_count) = guard_evaluation_summary(db.as_ref(), guard_id).await?;

    let client_rating = match avg_rating {
        Some(avg) => (avg / 5.0) * 100.0, // Convert 0-5 to 0-100
        None => 0.0,
    };
    let eval_count = eval_count as i32;

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
            score_basis: MeritScoreBasis::WeightedMerit,
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

    let guard_name: Option<String> = sqlx::query_scalar(
        "SELECT COALESCE(full_name, username) FROM users
         WHERE id = $1
           AND LOWER(BTRIM(COALESCE(role, ''))) = 'guard'
           AND COALESCE(status, 'active') = 'active'
           AND verified = true
           AND COALESCE(approval_status, 'approved') = 'approved'",
    )
    .bind(&guard_id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let guard_name = guard_name.ok_or_else(|| AppError::NotFound("Guard not found".to_string()))?;

    let merit_score: Option<GuardMeritScore> = sqlx::query_as(
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
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    let score_basis = match &merit_score {
        Some(score) => {
            let from_attendance_batch = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM capstone_seed_records
                 WHERE batch_id = $1 AND table_name = 'guard_merit_scores' AND record_id = $2)",
            )
            .bind(ATTENDANCE_SCORE_BATCH)
            .bind(&score.id)
            .fetch_one(db.as_ref())
            .await
            .map_err(|e| {
                AppError::DatabaseError(format!("Failed to read merit score source: {e}"))
            })?;
            saved_score_basis(score.rank.as_deref(), from_attendance_batch)
        }
        None => MeritScoreBasis::NotScored,
    };

    let (average_rating, evaluation_count) =
        guard_evaluation_summary(db.as_ref(), &guard_id).await?;
    let average_rating = average_rating.unwrap_or(0.0);
    let (total_shifts, on_time, late, no_shows) =
        guard_performance_history::activity_counts(db.as_ref(), &guard_id).await?;
    let stats = MeritStats {
        total_shifts: total_shifts as i32,
        on_time_count: on_time as i32,
        late_count: late as i32,
        no_show_count: no_shows as i32,
        evaluations: evaluation_count as i32,
        average_rating,
    };
    let response = match merit_score {
        Some(merit_score) => MeritScoreResponse {
            guard_id,
            guard_name: Some(guard_name),
            overall_score: merit_score.overall_score,
            score_basis,
            rank: merit_score.rank,
            attendance_score: merit_score.attendance_score,
            punctuality_score: merit_score.punctuality_score,
            client_rating: average_rating * 20.0,
            stats,
        },
        None => MeritScoreResponse {
            guard_id,
            guard_name: Some(guard_name),
            overall_score: 0.0,
            score_basis,
            rank: Some("Not evaluated".to_string()),
            attendance_score: 0.0,
            punctuality_score: 0.0,
            client_rating: average_rating * 20.0,
            stats,
        },
    };

    Ok(Json(response))
}

#[derive(serde::Deserialize)]
pub struct GuardPerformanceHistoryQuery {
    category: Option<String>,
    page: Option<i64>,
    page_size: Option<i64>,
}

pub async fn get_guard_performance_history(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(guard_id): Path<String>,
    Query(query): Query<GuardPerformanceHistoryQuery>,
) -> AppResult<Json<serde_json::Value>> {
    utils::require_min_role(&headers, "supervisor")?;
    let category = query.category.as_deref().unwrap_or("concerns");
    if !matches!(
        category,
        "concerns" | "shifts" | "punctuality" | "on_time" | "late" | "no_show" | "evaluations"
    ) {
        return Err(AppError::BadRequest("Unknown history category".to_string()));
    }
    if query.page.is_some_and(|page| page > i64::MAX / 50) {
        return Err(AppError::BadRequest("Page number is out of range".to_string()));
    }
    let guard_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND LOWER(BTRIM(role)) = 'guard')",
    )
    .bind(&guard_id)
    .fetch_one(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to look up guard: {e}")))?;
    if !guard_exists {
        return Err(AppError::NotFound("Guard not found".to_string()));
    }
    let (page, page_size, offset) = utils::resolve_pagination(
        utils::PaginationQuery { page: query.page, page_size: query.page_size },
        20,
        50,
    );
    let (total, items) =
        guard_performance_history::list_history(db.as_ref(), &guard_id, category, page_size, offset)
            .await?;
    Ok(Json(json!({ "total": total, "page": page, "pageSize": page_size, "items": items })))
}

// Get all guards ranked by merit score
pub async fn get_ranked_guards(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let guards = sqlx::query_as::<_, (String, String, f64, Option<String>, i32, i32, f64, i64, bool, bool)>(
        "SELECT u.id, COALESCE(u.full_name, u.username),
                COALESCE(gms.overall_score, 0)::FLOAT8, gms.rank,
                COALESCE(gms.on_time_count, 0),
                COALESCE(gms.on_time_count, 0) + COALESCE(gms.late_count, 0) + COALESCE(gms.no_show_count, 0),
                COALESCE(reviews.average_rating, 0) * 20.0,
                COALESCE(reviews.evaluation_count, 0),
                gms.id IS NOT NULL,
                EXISTS (SELECT 1 FROM capstone_seed_records
                  WHERE batch_id = $1 AND table_name = 'guard_merit_scores' AND record_id = gms.id)
         FROM users u
         LEFT JOIN guard_merit_scores gms ON gms.guard_id = u.id
         LEFT JOIN (
             SELECT guard_id, AVG(rating)::FLOAT8 AS average_rating, COUNT(*) AS evaluation_count
             FROM client_evaluations GROUP BY guard_id
         ) reviews ON reviews.guard_id = u.id
         WHERE LOWER(BTRIM(COALESCE(u.role, ''))) = 'guard'
           AND COALESCE(u.status, 'active') = 'active'
           AND u.verified = true
           AND COALESCE(u.approval_status, 'approved') = 'approved'
         ORDER BY COALESCE(gms.overall_score, 0) DESC, COALESCE(u.full_name, u.username)"
    )
    .bind(ATTENDANCE_SCORE_BATCH)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to query guards: {}", e)))?;

    let ranked: Vec<RankedGuardResponse> = guards
        .into_iter()
        .enumerate()
        .map(
            |(
                idx,
                (
                    guard_id,
                    guard_name,
                    score,
                    rank,
                    on_time,
                    total,
                    rating,
                    evaluation_count,
                    has_score,
                    from_attendance_batch,
                ),
            )| {
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
                    score_basis: if has_score {
                        saved_score_basis(rank.as_deref(), from_attendance_batch)
                    } else {
                        MeritScoreBasis::NotScored
                    },
                    merit_rank: rank.or_else(|| Some("Not evaluated".to_string())),
                    on_time_percentage: on_time_pct,
                    client_rating: rating,
                    evaluation_count,
                }
            },
        )
        .collect();

    Ok(Json(json!({
        "total": ranked.len(),
        "rankings": ranked
    })))
}

// Submit a supervisor/admin evaluation for a guard.
// The legacy client_evaluations table is retained so existing records remain available.
pub async fn submit_guard_evaluation(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CreateClientEvaluationRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    // Only supervisors, admins, and superadmins may create evaluations.
    let claims = utils::require_min_role(&headers, "supervisor")?;

    validate_evaluation_rating(payload.rating)?;

    let guard_exists = sqlx::query_scalar::<_, bool>(
        r#"SELECT EXISTS(
               SELECT 1 FROM users
               WHERE id = $1
                 AND LOWER(BTRIM(role)) = 'guard'
                 AND COALESCE(status, 'active') = 'active'
                 AND verified = true
                 AND COALESCE(approval_status, 'approved') = 'approved'
           )"#,
    )
    .bind(&payload.guard_id)
    .fetch_one(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to validate guard: {}", e)))?;

    if !guard_exists {
        return Err(AppError::BadRequest(
            "Evaluation target must be an active, approved guard".to_string(),
        ));
    }

    if let Some(shift_id) = payload.shift_id.as_deref() {
        let shift_matches = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM shifts WHERE id = $1 AND guard_id = $2)",
        )
        .bind(shift_id)
        .bind(&payload.guard_id)
        .fetch_one(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to validate shift: {}", e)))?;

        if !shift_matches {
            return Err(AppError::BadRequest(
                "Selected shift does not belong to the evaluated guard".to_string(),
            ));
        }
    }

    if let Some(mission_id) = payload.mission_id.as_deref() {
        let mission_exists =
            sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM trips WHERE id = $1)")
                .bind(mission_id)
                .fetch_one(db.as_ref())
                .await
                .map_err(|e| {
                    AppError::DatabaseError(format!("Failed to validate mission: {}", e))
                })?;

        if !mission_exists {
            return Err(AppError::BadRequest(
                "Selected mission does not exist".to_string(),
            ));
        }
    }

    let evaluator = sqlx::query_as::<_, (String, String)>(
        "SELECT COALESCE(NULLIF(full_name, ''), username), LOWER(BTRIM(role)) FROM users WHERE id = $1",
    )
    .bind(&claims.sub)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to load evaluator identity: {}", e)))?
    .ok_or_else(|| AppError::Unauthorized("Evaluator account no longer exists".to_string()))?;

    let comment = payload
        .comment
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if comment.is_some_and(|value| value.len() > 2000) {
        return Err(AppError::BadRequest(
            "Evaluation comment must be 2000 characters or fewer".to_string(),
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
    .bind(&evaluator.0)
    .bind(&evaluator.1)
    .bind(payload.rating)
    .bind(comment)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluation_rating_accepts_the_documented_scale() {
        assert!(validate_evaluation_rating(1.0).is_ok());
        assert!(validate_evaluation_rating(3.5).is_ok());
        assert!(validate_evaluation_rating(5.0).is_ok());
    }

    #[test]
    fn evaluation_rating_rejects_invalid_values() {
        assert!(validate_evaluation_rating(0.0).is_err());
        assert!(validate_evaluation_rating(5.1).is_err());
        assert!(validate_evaluation_rating(f64::NAN).is_err());
        assert!(validate_evaluation_rating(f64::INFINITY).is_err());
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires an isolated PostgreSQL instance"]
    async fn merit_reads_current_reviews_with_saved_scores(pool: PgPool) {
        crate::db::run_migrations(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, email, username, password, role, full_name, phone_number, verified) VALUES
             ('reviewed', 'reviewed@example.test', 'reviewed', 'fixture', 'guard', 'Guard A', '', true),
             ('unreviewed', 'unreviewed@example.test', 'unreviewed', 'fixture', 'guard', 'Guard B', '', true),
             ('unscored', 'unscored@example.test', 'unscored', 'fixture', 'guard', 'Guard C', '', true)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO guard_merit_scores (id, guard_id, overall_score, rank) VALUES
             ('score-a', 'reviewed', 96.5, 'Gold'), ('score-b', 'unreviewed', 100.0, 'Excellent')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO capstone_seed_batches (batch_id, data_origin, reference_at, status) VALUES ($1, 'test', NOW(), 'complete')")
            .bind(ATTENDANCE_SCORE_BATCH)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO capstone_seed_records (batch_id, table_name, record_id) VALUES
             ($1, 'guard_merit_scores', 'score-a'), ($1, 'guard_merit_scores', 'score-b')",
        )
        .bind(ATTENDANCE_SCORE_BATCH)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO client_evaluations (id, guard_id, evaluator_name, rating) VALUES
             ('review-a', 'reviewed', 'Fixture Reviewer', 4), ('review-b', 'reviewed', 'Fixture Reviewer', 5)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let token =
            utils::generate_access_token("reviewer", "reviewer@example.test", "supervisor", true)
                .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let db = Arc::new(pool);

        let Json(result) = get_ranked_guards(State(db.clone()), headers.clone())
            .await
            .unwrap();
        let rankings = result["rankings"].as_array().unwrap();
        assert_eq!(rankings[0]["evaluationCount"], 0);
        assert_eq!(rankings[0]["overallScore"], 100.0);
        assert_eq!(rankings[0]["scoreBasis"], "attendance_punctuality");
        assert_eq!(rankings[1]["evaluationCount"], 2);
        assert_eq!(rankings[1]["clientRating"], 90.0);
        assert_eq!(rankings[1]["scoreBasis"], "weighted_merit");
        assert_eq!(rankings[2]["scoreBasis"], "not_scored");

        let Json(scorecard) = get_guard_merit_score(State(db), headers, Path("reviewed".into()))
            .await
            .unwrap();
        assert_eq!(scorecard.stats.evaluations, 2);
        assert_eq!(scorecard.stats.average_rating, 4.5);
        assert_eq!(scorecard.overall_score, 96.5);
        assert!(matches!(scorecard.score_basis, MeritScoreBasis::WeightedMerit));
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires an isolated PostgreSQL instance"]
    async fn guard_history_filters_recorded_activity_for_the_selected_guard(pool: PgPool) {
        crate::db::run_migrations(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, email, username, password, role, full_name, phone_number, verified) VALUES
             ('target', 'target@example.test', 'target', 'fixture', 'guard', 'Fixture Guard', '', true),
             ('other', 'other@example.test', 'other', 'fixture', 'guard', 'Other Fixture Guard', '', true)",
        ).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO shifts (id, guard_id, client_site, start_time, end_time, status) VALUES
             ('post', 'target', 'Fixture Site', NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days' + INTERVAL '1 hour', 'scheduled')",
        ).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO punctuality_records
             (id, guard_id, shift_id, scheduled_start_time, actual_check_in_time, minutes_late, is_on_time, status)
             VALUES
             ('late-entry', 'target', 'post', NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days' + INTERVAL '16 minutes', 16, false, 'late'),
             ('absent-entry', 'target', 'past', NOW() - INTERVAL '2 days', NULL, NULL, false, 'absent'),
             ('present-entry', 'target', 'past-2', NOW() - INTERVAL '4 days', NOW() - INTERVAL '4 days', 0, true, 'present'),
             ('other-entry', 'other', 'other-post', NOW(), NOW(), 18, false, 'late')",
        ).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO client_evaluations (id, guard_id, evaluator_name, rating, comment) VALUES
             ('review-concern', 'target', 'Fixture Reviewer', 2, 'Recorded review comment'),
             ('review-positive', 'target', 'Fixture Reviewer', 5, 'Recorded positive comment')",
        ).execute(&pool).await.unwrap();
        let db = Arc::new(pool);
        let read_history = |role: &str, category: &str, page, page_size| {
            let token = utils::generate_access_token("target", "target@example.test", role, true).unwrap();
            let mut headers = HeaderMap::new();
            headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());
            let uri = format!("/api/merit/history/target?category={category}&page={page}&page_size={page_size}")
                .parse().unwrap();
            get_guard_performance_history(
                State(db.clone()),
                headers,
                Path("target".into()),
                Query::try_from_uri(&uri).unwrap(),
            )
        };

        let Json(first) = read_history("admin", "concerns", 1, 2).await.unwrap();
        assert_eq!(first["total"], 3);
        assert_eq!(first["pageSize"], 2);
        assert_eq!(first["items"][0]["comment"], "Recorded review comment");
        assert_eq!(first["items"][1]["status"], "absent");
        let Json(second) = read_history("supervisor", "concerns", 2, 2).await.unwrap();
        assert_eq!(second["items"][0]["site"], "Fixture Site");
        assert_eq!(second["items"][0]["minutes_late"], 16);

        let Json(on_time) = read_history("superadmin", "on_time", 1, 20).await.unwrap();
        assert_eq!(on_time["total"], 1);
        assert_eq!(on_time["items"][0]["status"], "on_time");
        assert_eq!(guard_performance_history::activity_counts(&db, "target").await.unwrap(), (1, 1, 1, 1));
        assert!(matches!(read_history("guard", "concerns", 1, 20).await, Err(AppError::Forbidden(_))));
    }
}
