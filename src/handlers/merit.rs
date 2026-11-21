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
        MeritScoreBasis, MeritScoreResponse, MeritStats, RankedGuardResponse,
    },
    services::{
        guard_performance_history,
        merit_scoring::{load_merit_inputs, rank as merit_rank, MeritInputs},
    },
    utils,
};



fn validate_evaluation_rating(rating: f64) -> AppResult<()> {
    if !rating.is_finite() || !(1.0..=5.0).contains(&rating) {
        return Err(AppError::BadRequest(
            "Rating must be between 1 and 5".to_string(),
        ));
    }
    Ok(())
}

async fn load_guard_merit(db: &PgPool, guard_id: &str) -> AppResult<MeritInputs> {
    load_merit_inputs(db, Some(guard_id))
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| AppError::NotFound("Guard not found".to_string()))
}

async fn merit_scorecard(db: &PgPool, inputs: MeritInputs) -> AppResult<MeritScoreResponse> {
    let overall = inputs.overall();
    let attendance = inputs.attendance();
    let punctuality = inputs.punctuality();
    let (total_shifts, on_time, late, no_shows) =
        guard_performance_history::activity_counts(db, &inputs.guard_id).await?;
    Ok(MeritScoreResponse {
        guard_id: inputs.guard_id,
        guard_name: Some(inputs.guard_name),
        overall_score: overall,
        score_basis: if overall.is_some() {
            MeritScoreBasis::WeightedMerit
        } else {
            MeritScoreBasis::NotScored
        },
        rank: Some(overall.map(merit_rank).unwrap_or("Unranked").to_string()),
        attendance_score: attendance.unwrap_or_default(),
        punctuality_score: punctuality.unwrap_or_default(),
        has_attendance_records: attendance.is_some(),
        has_punctuality_records: punctuality.is_some(),
        client_rating: inputs.average_rating.unwrap_or_default() * 20.0,
        stats: MeritStats {
            total_shifts: total_shifts as i32,
            on_time_count: on_time as i32,
            late_count: late as i32,
            no_show_count: no_shows as i32,
            evaluations: inputs.evaluation_count as i32,
            average_rating: inputs.average_rating.unwrap_or_default(),
        },
    })
}

async fn ranked_merit(db: &PgPool) -> AppResult<Vec<(MeritInputs, Option<f64>)>> {
    let mut ranked: Vec<_> = load_merit_inputs(db, None)
        .await?
        .into_iter()
        .map(|inputs| {
            let score = inputs.overall();
            (inputs, score)
        })
        .collect();
    ranked.sort_by(|a, b| b.1.unwrap_or(-1.0).total_cmp(&a.1.unwrap_or(-1.0)));
    Ok(ranked)
}

pub async fn calculate_merit_score(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CalculateMeritScoreRequest>,
) -> AppResult<(StatusCode, Json<MeritScoreResponse>)> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;
    let inputs = load_guard_merit(db.as_ref(), &payload.guard_id).await?;

    if let (Some(score), Some(attendance), Some(punctuality), Some(rating)) = (
        inputs.overall(),
        inputs.attendance(),
        inputs.punctuality(),
        inputs.average_rating,
    ) {
        sqlx::query(
            r#"INSERT INTO guard_merit_scores (
                id, guard_id, attendance_score, punctuality_score, client_rating, overall_score,
                rank, total_shifts_completed, on_time_count, late_count, no_show_count,
                average_client_rating, evaluation_count, last_calculated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, CURRENT_TIMESTAMP)
            ON CONFLICT (guard_id) DO UPDATE SET
                attendance_score = EXCLUDED.attendance_score,
                punctuality_score = EXCLUDED.punctuality_score,
                client_rating = EXCLUDED.client_rating,
                overall_score = EXCLUDED.overall_score,
                rank = EXCLUDED.rank,
                total_shifts_completed = EXCLUDED.total_shifts_completed,
                on_time_count = EXCLUDED.on_time_count,
                late_count = EXCLUDED.late_count,
                no_show_count = EXCLUDED.no_show_count,
                average_client_rating = EXCLUDED.average_client_rating,
                evaluation_count = EXCLUDED.evaluation_count,
                last_calculated_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP"#,
        )
        .bind(utils::generate_id())
        .bind(&inputs.guard_id)
        .bind(attendance)
        .bind(punctuality)
        .bind(rating * 20.0)
        .bind(score)
        .bind(merit_rank(score))
        .bind(inputs.completed_shifts as i32)
        .bind(inputs.on_time as i32)
        .bind(inputs.late as i32)
        .bind(inputs.no_shows as i32)
        .bind(rating)
        .bind(inputs.evaluation_count as i32)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to save merit score: {e}")))?;
    }

    Ok((StatusCode::OK, Json(merit_scorecard(db.as_ref(), inputs).await?)))
}

pub async fn get_guard_merit_score(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(guard_id): Path<String>,
) -> AppResult<Json<MeritScoreResponse>> {
    let _claims = utils::require_self_or_min_role(&headers, &guard_id, "supervisor")?;
    let inputs = load_guard_merit(db.as_ref(), &guard_id).await?;
    Ok(Json(merit_scorecard(db.as_ref(), inputs).await?))
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

pub async fn get_ranked_guards(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;
    let ranked: Vec<_> = ranked_merit(db.as_ref())
        .await?
        .into_iter()
        .enumerate()
        .map(|(index, (inputs, overall))| RankedGuardResponse {
            rank: if overall.is_some() { (index + 1) as i32 } else { 0 },
            attendance_percentage: inputs.attendance(),
            on_time_percentage: inputs.punctuality().unwrap_or_default(),
            has_punctuality_records: inputs.punctuality().is_some(),
            guard_id: inputs.guard_id,
            guard_name: Some(inputs.guard_name),
            overall_score: overall,
            score_basis: if overall.is_some() {
                MeritScoreBasis::WeightedMerit
            } else {
                MeritScoreBasis::NotScored
            },
            merit_rank: Some(overall.map(merit_rank).unwrap_or("Unranked").to_string()),
            client_rating: inputs.average_rating.unwrap_or_default() * 20.0,
            evaluation_count: inputs.evaluation_count,
        })
        .collect();

    Ok(Json(json!({ "total": ranked.len(), "rankings": ranked })))
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

pub async fn get_overtime_candidates(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;
    let candidates: Vec<_> = ranked_merit(db.as_ref())
        .await?
        .into_iter()
        .filter_map(|(guard, score)| {
            let score = score.filter(|score| *score >= 80.0)?;
            Some(json!({
                "guardId": guard.guard_id,
                "guardName": guard.guard_name,
                "overallScore": score,
                "rank": merit_rank(score),
            }))
        })
        .take(20)
        .collect();

    Ok(Json(json!({ "total": candidates.len(), "candidates": candidates })))
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
    async fn merit_requires_evaluation_and_uses_recorded_attendance(pool: PgPool) {
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
             ('score-a', 'reviewed', 100.0, 'Excellent'), ('score-b', 'unreviewed', 100.0, 'Excellent')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO shifts (id, guard_id, client_site, start_time, end_time, status) VALUES
             ('a-done', 'reviewed', 'Fixture', NOW()-INTERVAL '2 days', NOW()-INTERVAL '1 day', 'completed'),
             ('a-future', 'reviewed', 'Fixture', NOW()+INTERVAL '1 day', NOW()+INTERVAL '2 days', 'scheduled'),
             ('a-cancel', 'reviewed', 'Fixture', NOW()-INTERVAL '2 days', NOW()-INTERVAL '1 day', 'canceled'),
             ('b-done', 'unreviewed', 'Fixture', NOW()-INTERVAL '2 days', NOW()-INTERVAL '1 day', 'completed')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO attendance (id, guard_id, shift_id, check_in_time, status) VALUES
             ('a-attendance', 'reviewed', 'a-done', NOW()-INTERVAL '2 days', 'completed'),
             ('b-attendance', 'unreviewed', 'b-done', NOW()-INTERVAL '2 days', 'completed')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO punctuality_records (id, guard_id, shift_id, scheduled_start_time, actual_check_in_time, is_on_time, status) VALUES
             ('a-time', 'reviewed', 'a-done', NOW()-INTERVAL '2 days', NOW()-INTERVAL '2 days', true, 'present'),
             ('b-time', 'unreviewed', 'b-done', NOW()-INTERVAL '2 days', NOW()-INTERVAL '2 days', true, 'on_time')",
        )
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
        assert_eq!(rankings[0]["evaluationCount"], 2);
        assert_eq!(rankings[0]["clientRating"], 90.0);
        assert_eq!(rankings[0]["overallScore"], 96.5);
        assert_eq!(rankings[0]["scoreBasis"], "weighted_merit");
        assert_eq!(rankings[1]["evaluationCount"], 0);
        assert_eq!(rankings[1]["attendancePercentage"], 100.0);
        assert_eq!(rankings[1]["onTimePercentage"], 100.0);
        assert_eq!(rankings[1]["scoreBasis"], "not_scored");
        assert!(rankings[1]["overallScore"].is_null());
        assert_eq!(rankings[1]["meritRank"], "Unranked");
        assert_eq!(rankings[1]["rank"], 0);
        assert_eq!(rankings[2]["scoreBasis"], "not_scored");
        assert!(rankings[2]["attendancePercentage"].is_null());
        assert_eq!(rankings[2]["hasPunctualityRecords"], false);

        let Json(unreviewed) =
            get_guard_merit_score(State(db.clone()), headers.clone(), Path("unreviewed".into()))
                .await
                .unwrap();
        assert!(matches!(unreviewed.score_basis, MeritScoreBasis::NotScored));
        assert!(unreviewed.overall_score.is_none());
        assert_eq!(unreviewed.attendance_score, 100.0);

        let Json(scorecard) =
            get_guard_merit_score(State(db.clone()), headers.clone(), Path("reviewed".into()))
                .await
                .unwrap();
        assert_eq!(scorecard.stats.evaluations, 2);
        assert_eq!(scorecard.stats.average_rating, 4.5);
        assert_eq!(scorecard.overall_score, Some(96.5));
        assert!(matches!(scorecard.score_basis, MeritScoreBasis::WeightedMerit));

        for (guard_id, expected_score) in [("reviewed", Some(96.5)), ("unreviewed", None)] {
            let (status, Json(calculated)) = calculate_merit_score(
                State(db.clone()),
                headers.clone(),
                Json(CalculateMeritScoreRequest { guard_id: guard_id.to_string() }),
            )
            .await
            .unwrap();
            assert_eq!(status, StatusCode::OK);
            assert_eq!(calculated.overall_score, expected_score);
        }
        let persisted = sqlx::query_as::<_, (String, f64)>(
            "SELECT guard_id, overall_score FROM guard_merit_scores ORDER BY guard_id",
        )
        .fetch_all(db.as_ref())
        .await
        .unwrap();
        assert_eq!(
            persisted,
            vec![("reviewed".to_string(), 96.5), ("unreviewed".to_string(), 100.0)],
        );
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
