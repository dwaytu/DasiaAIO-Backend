use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::{FromRow, PgPool};

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplacementSuggestion {
    pub guard_id: String,
    pub guard_name: String,
    pub reliability_score: f64,
    pub distance_km: f64,
    pub availability: bool,
    pub permit_valid: bool,
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
    permit_valid: Option<bool>,
    distance_km: Option<f64>,
}

#[derive(Debug, FromRow)]
struct ShiftRow {
    id: String,
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
                'replacement-heuristic-v1',
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
            "Selected by deterministic scoring for post {} ({})",
            post.name, post.id
        ))
        .bind(json!({
            "replacementScore": suggestion.replacement_score,
            "reliabilityScore": suggestion.reliability_score,
            "distanceKm": suggestion.distance_km,
            "distanceScore": suggestion.distance_score,
            "availability": suggestion.availability,
            "permitValid": suggestion.permit_valid,
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

pub async fn suggest_replacement(
    pool: &PgPool,
    post_id: &str,
) -> AppResult<Vec<ReplacementSuggestion>> {
    let post = sqlx::query_as::<_, PostRow>(
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
    .ok_or_else(|| AppError::NotFound("Post not found or inactive".to_string()))?;

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
            EXISTS (
                SELECT 1
                FROM guard_firearm_permits gfp
                WHERE gfp.guard_id = u.id
                  AND gfp.status = 'active'
                  AND gfp.expiry_date > NOW()
            ) AS permit_valid,
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

    let now = Utc::now();
    let mut scored = candidates
        .into_iter()
        .filter(|row| row.availability.unwrap_or(false) && row.permit_valid.unwrap_or(false))
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
                availability: row.availability.unwrap_or(false),
                permit_valid: row.permit_valid.unwrap_or(false),
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

    let top_three = scored.into_iter().take(3).collect::<Vec<_>>();

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

