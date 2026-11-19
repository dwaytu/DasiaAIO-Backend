use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::{FromRow, PgPool};

use crate::{
    error::{AppError, AppResult},
    services::shift_alert_service::check_in_grace_minutes,
};

const COVERAGE: &str = "unarmed";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplacementSuggestion {
    pub guard_id: String,
    pub guard_name: String,
    pub reliability_score: f64,
    pub distance_km: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distance_known: Option<bool>,
    pub availability: bool,
    pub coverage: &'static str,
    pub distance_score: f64,
    pub replacement_score: f64,
    pub formula: String,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct PostRow {
    id: String,
    name: String,
    latitude: f64,
    longitude: f64,
}

#[derive(Debug, FromRow)]
struct CandidateRow {
    guard_id: String,
    guard_name: String,
    reliability_score: Option<f64>,
    availability: Option<bool>,
    distance_km: Option<f64>,
}

#[derive(Debug, FromRow)]
struct ShiftRow {
    id: String,
}

#[derive(Debug, FromRow)]
struct ShiftCoverage {
    original_guard_id: String,
    starts_at: DateTime<Utc>,
    ends_at: DateTime<Utc>,
}

fn clamp_unit(value: f64) -> f64 {
    value.clamp(0.0, 1.0)
}

fn distance_to_score(distance_km: f64) -> f64 {
    if distance_km <= 1.0 {
        1.0
    } else if distance_km <= 3.0 {
        0.8
    } else if distance_km <= 7.0 {
        0.5
    } else if distance_km <= 15.0 {
        0.2
    } else {
        0.05
    }
}

async fn persist_suggestions(
    pool: &PgPool,
    post: &PostRow,
    shift_id: Option<&str>,
    suggestions: &[ReplacementSuggestion],
) -> AppResult<()> {
    let Some(target_shift_id) = shift_id else {
        return Ok(());
    };

    for (idx, suggestion) in suggestions.iter().enumerate() {
        sqlx::query(
            r#"
            INSERT INTO smart_guard_replacements (
                id,
                shift_id,
                absent_guard_id,
                recommended_guard_id,
                recommendation_rank,
                compatibility_score,
                confidence_score,
                rationale,
                scoring_breakdown,
                candidate_pool,
                recommendation_status,
                generated_at,
                expires_at,
                feature_version,
                created_at,
                updated_at
            ) VALUES (
                $1,
                $2,
                NULL,
                $3,
                $4,
                $5,
                0.75,
                $6,
                $7,
                $8,
                'proposed',
                NOW(),
                NOW() + INTERVAL '6 hours',
                'replacement-heuristic-v2',
                NOW(),
                NOW()
            )
            "#,
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(target_shift_id)
        .bind(&suggestion.guard_id)
        .bind((idx + 1) as i32)
        .bind(suggestion.replacement_score)
        .bind(format!(
            "Unarmed staffing candidate for post {} ({})",
            post.name, post.id
        ))
        .bind(json!({
            "replacementScore": suggestion.replacement_score,
            "reliabilityScore": suggestion.reliability_score,
            "distanceKm": suggestion.distance_km,
            "distanceScore": suggestion.distance_score,
            "availability": suggestion.availability,
            "coverage": suggestion.coverage,
            "formula": suggestion.formula,
        }))
        .bind(json!({
            "postId": post.id,
            "postName": post.name,
            "postLatitude": post.latitude,
            "postLongitude": post.longitude,
        }))
        .execute(pool)
        .await
        .map_err(|e| {
            AppError::DatabaseError(format!("Failed to persist replacement suggestion: {}", e))
        })?;
    }

    Ok(())
}

async fn load_post(pool: &PgPool, post_id: &str) -> AppResult<PostRow> {
    sqlx::query_as::<_, PostRow>(
        r#"
        SELECT id, name, latitude, longitude
        FROM client_sites
        WHERE id = $1 AND is_active = true
        "#,
    )
    .bind(post_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to load post location: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Post not found or inactive".to_string()))
}

pub async fn suggest_replacement(
    pool: &PgPool,
    post_id: &str,
) -> AppResult<Vec<ReplacementSuggestion>> {
    let post = load_post(pool, post_id).await?;

    let candidates = sqlx::query_as::<_, CandidateRow>(
        r#"
        WITH latest_guard_position AS (
            SELECT DISTINCT ON (tp.entity_id)
                tp.entity_id AS guard_id,
                tp.latitude,
                tp.longitude,
                tp.recorded_at
            FROM tracking_points tp
            WHERE tp.entity_type = 'guard'
            ORDER BY tp.entity_id, tp.recorded_at DESC
        ), guard_conflicts AS (
            SELECT DISTINCT s.guard_id
            FROM shifts s
            WHERE s.status IN ('scheduled', 'in_progress')
              AND s.start_time <= NOW() + INTERVAL '8 hours'
              AND s.end_time >= NOW()
        )
        SELECT
            u.id AS guard_id,
            COALESCE(NULLIF(u.full_name, ''), u.username) AS guard_name,
            COALESCE(gms.overall_score, 0) AS reliability_score,
            (
              COALESCE(ga.available, true)
              AND gc.guard_id IS NULL
              AND (
                ga.available_from IS NULL OR ga.available_from <= NOW() + INTERVAL '2 hours'
              )
              AND (
                ga.available_to IS NULL OR ga.available_to >= NOW()
              )
            ) AS availability,
            COALESCE(
                (
                    6371.0 * ACOS(
                        GREATEST(-1.0, LEAST(1.0,
                            COS(RADIANS($1)) * COS(RADIANS(lgp.latitude)) * COS(RADIANS(lgp.longitude) - RADIANS($2))
                            + SIN(RADIANS($1)) * SIN(RADIANS(lgp.latitude))
                        ))
                    )
                ),
                99.0
            ) AS distance_km
        FROM users u
        LEFT JOIN guard_merit_scores gms ON gms.guard_id = u.id
        LEFT JOIN guard_availability ga ON ga.guard_id = u.id
        LEFT JOIN latest_guard_position lgp ON lgp.guard_id = u.id
        LEFT JOIN guard_conflicts gc ON gc.guard_id = u.id
        WHERE u.role IN ('guard')
          AND u.verified = true
        ORDER BY COALESCE(gms.overall_score, 0) DESC, guard_name ASC
        "#,
    )
    .bind(post.latitude)
    .bind(post.longitude)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to load replacement candidates: {}", e)))?;

    let top_three = score_candidates(candidates, false);

    let shift_id = sqlx::query_as::<_, ShiftRow>(
        r#"
        SELECT s.id
        FROM shifts s
        WHERE s.status IN ('scheduled', 'in_progress')
          AND s.start_time >= NOW() - INTERVAL '2 hours'
          AND s.start_time <= NOW() + INTERVAL '8 hours'
          AND (
            s.client_site = $1
            OR s.client_site = $2
          )
        ORDER BY s.start_time ASC
        LIMIT 1
        "#,
    )
    .bind(post.name.as_str())
    .bind(post.id.as_str())
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to locate post shift for persistence: {}",
            e
        ))
    })?
    .map(|row| row.id);

    persist_suggestions(pool, &post, shift_id.as_deref(), &top_three).await?;

    Ok(top_three)
}

pub async fn suggest_shift_replacement(
    pool: &PgPool,
    post_id: &str,
    shift_id: &str,
) -> AppResult<Vec<ReplacementSuggestion>> {
    let post = load_post(pool, post_id).await?;
    let coverage = sqlx::query_as::<_, ShiftCoverage>(
        r#"
        SELECT s.guard_id AS original_guard_id,
               GREATEST(s.start_time, CURRENT_TIMESTAMP) AS starts_at,
               s.end_time AS ends_at
        FROM shifts s
        JOIN LATERAL (
            SELECT COALESCE(
                MAX(cs.id) FILTER (WHERE cs.id = BTRIM(s.client_site)),
                CASE WHEN COUNT(*) FILTER (WHERE LOWER(BTRIM(cs.name)) = LOWER(BTRIM(s.client_site))) = 1
                     THEN MAX(cs.id) FILTER (WHERE LOWER(BTRIM(cs.name)) = LOWER(BTRIM(s.client_site))) END
            ) AS id
            FROM client_sites cs
            WHERE cs.is_active = TRUE
              AND (cs.id = BTRIM(s.client_site) OR LOWER(BTRIM(cs.name)) = LOWER(BTRIM(s.client_site)))
        ) site ON site.id = $2
        WHERE s.id = $1
          AND s.start_time <= CURRENT_TIMESTAMP AND s.end_time > CURRENT_TIMESTAMP
          AND (s.status IN ('absent', 'no_show') OR (
              s.status = 'scheduled'
              AND s.start_time + COALESCE(s.grace_period_minutes, $3::bigint) * INTERVAL '1 minute' <= CURRENT_TIMESTAMP
          ))
          AND NOT EXISTS (SELECT 1 FROM attendance a WHERE a.shift_id = s.id)
        "#,
    )
    .bind(shift_id)
    .bind(&post.id)
    .bind(check_in_grace_minutes())
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to load replacement shift: {e}")))?
    .ok_or_else(|| AppError::Conflict("This shift no longer needs replacement at the selected site.".to_string()))?;

    let candidates = sqlx::query_as::<_, CandidateRow>(
        r#"
        SELECT u.id AS guard_id,
               COALESCE(NULLIF(u.full_name, ''), u.username) AS guard_name,
               COALESCE(gms.overall_score, 0) AS reliability_score,
               TRUE AS availability,
               CASE WHEN location.latitude IS NOT NULL THEN
                   6371.0 * ACOS(GREATEST(-1.0, LEAST(1.0,
                       COS(RADIANS($1)) * COS(RADIANS(location.latitude))
                           * COS(RADIANS(location.longitude) - RADIANS($2))
                       + SIN(RADIANS($1)) * SIN(RADIANS(location.latitude))
                   )))
               END AS distance_km
        FROM users u
        LEFT JOIN guard_merit_scores gms ON gms.guard_id = u.id
        LEFT JOIN LATERAL (
            SELECT available, available_from, available_to
            FROM guard_availability ga
            WHERE ga.guard_id = u.id
            ORDER BY ga.updated_at DESC NULLS LAST, ga.created_at DESC NULLS LAST, ga.id DESC
            LIMIT 1
        ) callout ON TRUE
        LEFT JOIN LATERAL (
            SELECT tp.latitude, tp.longitude
            FROM tracking_points tp
            WHERE tp.entity_type = 'guard' AND tp.entity_id = u.id
              AND tp.status IS DISTINCT FROM 'presentation_checkpoint'
              AND tp.recorded_at <= $3
              AND tp.latitude BETWEEN -90 AND 90 AND tp.longitude BETWEEN -180 AND 180
            ORDER BY tp.recorded_at DESC, tp.id DESC
            LIMIT 1
        ) location ON TRUE
        WHERE LOWER(BTRIM(u.role)) = 'guard' AND u.id <> $5 AND u.verified = TRUE
          AND LOWER(BTRIM(COALESCE(u.approval_status, 'approved'))) = 'approved'
          AND LOWER(BTRIM(COALESCE(u.status, 'active'))) = 'active'
          AND COALESCE(callout.available, TRUE)
          AND (callout.available_from IS NULL OR callout.available_from <= $3)
          AND (callout.available_to IS NULL OR callout.available_to >= $4)
          AND NOT EXISTS (
              SELECT 1 FROM shifts other
              WHERE other.guard_id = u.id AND other.status IN ('scheduled', 'in_progress')
                AND other.start_time < $4 AND other.end_time > $3
          )
        "#,
    )
    .bind(post.latitude)
    .bind(post.longitude)
    .bind(coverage.starts_at)
    .bind(coverage.ends_at)
    .bind(coverage.original_guard_id)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to load replacement candidates: {e}")))?;

    Ok(score_candidates(candidates, true))
}

fn score_candidates(
    candidates: Vec<CandidateRow>,
    expose_distance_known: bool,
) -> Vec<ReplacementSuggestion> {
    let now = Utc::now();
    let mut scored = candidates
        .into_iter()
        .filter(|row| row.availability.unwrap_or(false))
        .map(|row| {
            let reliability = row.reliability_score.unwrap_or(0.0).clamp(0.0, 100.0);
            let reliability_component = clamp_unit(reliability / 100.0);
            let availability_component = if row.availability.unwrap_or(false) { 1.0 } else { 0.0 };
            let distance_km = row.distance_km.unwrap_or(99.0).max(0.0);
            let distance_component = distance_to_score(distance_km);
            let replacement_score =
                (reliability_component * 0.4) + (availability_component * 0.3) + (distance_component * 0.3);

            ReplacementSuggestion {
                guard_id: row.guard_id,
                guard_name: row.guard_name,
                reliability_score: (reliability * 100.0).round() / 100.0,
                distance_km: (distance_km * 100.0).round() / 100.0,
                distance_known: expose_distance_known.then_some(row.distance_km.is_some()),
                availability: row.availability.unwrap_or(false),
                coverage: COVERAGE,
                distance_score: (distance_component * 100.0).round() / 100.0,
                replacement_score: (replacement_score * 1000.0).round() / 1000.0,
                formula: "ReplacementScore = (reliability_score * 0.4) + (availability * 0.3) + (distance_score * 0.3)".to_string(),
                generated_at: now,
            }
        })
        .collect::<Vec<_>>();

    scored.sort_by(|a, b| {
        b.replacement_score
            .partial_cmp(&a.replacement_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                a.distance_km
                    .partial_cmp(&b.distance_km)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.guard_name.cmp(&b.guard_name))
    });

    scored.into_iter().take(3).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = false)]
    #[ignore = "requires an isolated PostgreSQL instance"]
    async fn unarmed_staffing_uses_callouts_and_schedule_conflicts(pool: PgPool) {
        crate::db::run_migrations(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, email, password, role, verified, full_name, phone_number) VALUES
             ('ready', 'ready', 'ready@example.test', 'fixture', 'guard', true, 'Ready Guard', ''),
             ('busy', 'busy', 'busy@example.test', 'fixture', 'guard', true, 'Busy Guard', ''),
             ('off', 'off', 'off@example.test', 'fixture', 'guard', true, 'Off Call Guard', '')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO client_sites (id, name, latitude, longitude) VALUES ('post', 'Fixture Post', 7, 125)")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO guard_availability (id, guard_id, available) VALUES ('callout-off', 'off', false)")
            .execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO shifts (id, guard_id, start_time, end_time, client_site, status) VALUES
             ('shift', 'busy', NOW(), NOW() + INTERVAL '4 hours', 'post', 'in_progress')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let suggestions = suggest_replacement(&pool, "post").await.unwrap();
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].guard_id, "ready");
        assert_eq!(suggestions[0].coverage, "unarmed");
        let saved_coverage: String = sqlx::query_scalar(
            "SELECT scoring_breakdown->>'coverage' FROM smart_guard_replacements WHERE shift_id = 'shift'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(saved_coverage, "unarmed");
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires an isolated PostgreSQL instance"]
    async fn shift_candidates_match_the_post_and_full_remaining_coverage(pool: PgPool) {
        crate::db::run_migrations(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, email, password, role, verified, status, approval_status, phone_number, full_name) VALUES
             ('original', 'original', 'original@example.test', 'fixture', 'guard', true, 'active', 'approved', '', 'Original Guard'),
             ('ready', 'ready', 'ready@example.test', 'fixture', 'guard', true, 'active', 'approved', '', 'Ready Guard'),
             ('no-location', 'no-location', 'no-location@example.test', 'fixture', 'guard', true, 'active', 'approved', '', 'Unknown Location'),
             ('overlapping', 'overlapping', 'overlapping@example.test', 'fixture', 'guard', true, 'active', 'approved', '', 'Overlapping Guard'),
             ('short-window', 'short-window', 'short-window@example.test', 'fixture', 'guard', true, 'active', 'approved', '', 'Short Window'),
             ('pending', 'pending', 'pending@example.test', 'fixture', 'guard', true, 'active', 'pending', '', 'Pending Guard'),
             ('inactive', 'inactive', 'inactive@example.test', 'fixture', 'guard', true, 'inactive', 'approved', '', 'Inactive Guard')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO client_sites (id, name, latitude, longitude) VALUES
                     ('target-post', 'Target Post', 7, 125), ('other-post', 'Other Post', 7, 125)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO shifts (id, guard_id, start_time, end_time, client_site, status, grace_period_minutes) VALUES
                     ('overdue', 'original', CURRENT_TIMESTAMP - INTERVAL '2 hours', CURRENT_TIMESTAMP + INTERVAL '10 hours', '  tArGeT pOsT  ', 'scheduled', 15),
                     ('conflict', 'overlapping', CURRENT_TIMESTAMP + INTERVAL '9 hours', CURRENT_TIMESTAMP + INTERVAL '11 hours', 'Other Post', 'scheduled', 15)")
            .execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO guard_availability (id, guard_id, available, available_to) VALUES
                     ('limited', 'short-window', TRUE, CURRENT_TIMESTAMP + INTERVAL '9 hours')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO tracking_points (id, entity_type, entity_id, status, latitude, longitude) VALUES
                     ('actual', 'guard', 'ready', 'active', 7.01, 125),
                     ('presentation', 'guard', 'no-location', 'presentation_checkpoint', 7, 125)")
            .execute(&pool).await.unwrap();

        let suggestions = suggest_shift_replacement(&pool, "target-post", "overdue")
            .await
            .unwrap();
        assert_eq!(
            suggestions
                .iter()
                .map(|row| row.guard_id.as_str())
                .collect::<Vec<_>>(),
            ["ready", "no-location"]
        );
        assert_eq!(suggestions[0].coverage, "unarmed");
        assert_eq!(suggestions[0].distance_known, Some(true));
        assert_eq!(suggestions[1].distance_known, Some(false));
        let saved_suggestions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM smart_guard_replacements")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(saved_suggestions, 0);
        assert!(matches!(
            suggest_shift_replacement(&pool, "other-post", "overdue").await,
            Err(AppError::Conflict(_))
        ));

        sqlx::query("INSERT INTO client_sites (id, name, latitude, longitude) VALUES ('duplicate', ' target post ', 7, 125)")
            .execute(&pool).await.unwrap();
        assert!(matches!(
            suggest_shift_replacement(&pool, "target-post", "overdue").await,
            Err(AppError::Conflict(_))
        ));
        sqlx::query("UPDATE shifts SET client_site = 'target-post' WHERE id = 'overdue'")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            suggest_shift_replacement(&pool, "target-post", "overdue")
                .await
                .unwrap()
                .len(),
            2
        );
        sqlx::query("INSERT INTO attendance (id, guard_id, shift_id, check_in_time) VALUES ('checked-in', 'original', 'overdue', CURRENT_TIMESTAMP)")
            .execute(&pool).await.unwrap();
        assert!(matches!(
            suggest_shift_replacement(&pool, "target-post", "overdue").await,
            Err(AppError::Conflict(_))
        ));
    }
}
