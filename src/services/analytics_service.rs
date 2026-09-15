use chrono::NaiveDate;
use serde::Serialize;
use sqlx::PgPool;

use crate::error::{AppError, AppResult};

#[derive(Debug, sqlx::FromRow)]
pub struct ResourceSnapshot {
    pub total_guards: i64,
    pub guards_on_duty: i64,
    pub guards_available: i64,
    pub total_firearms: i64,
    pub firearms_in_use: i64,
    pub firearms_available: i64,
    pub total_vehicles: i64,
    pub vehicles_deployed: i64,
    pub vehicles_available: i64,
}

impl ResourceSnapshot {
    pub fn guards_unavailable(&self) -> i64 {
        (self.total_guards - self.guards_available).max(0)
    }

    pub fn firearms_unavailable(&self) -> i64 {
        (self.total_firearms - self.firearms_available).max(0)
    }

    pub fn vehicles_unavailable(&self) -> i64 {
        (self.total_vehicles - self.vehicles_available).max(0)
    }
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct EvaluationRatingBucket {
    pub rating: i32,
    pub count: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct EvaluationTrendPoint {
    pub date: Option<NaiveDate>,
    pub average_rating: f64,
    pub evaluation_count: i64,
}

#[derive(Debug, Serialize)]
pub struct EvaluationAnalytics {
    pub period_days: i64,
    pub total_evaluations: i64,
    pub guards_evaluated: i64,
    pub average_rating: f64,
    pub low_rating_count: i64,
    pub rating_distribution: Vec<EvaluationRatingBucket>,
}

#[derive(Debug, Serialize)]
pub struct EvaluationAnalyticsResponse {
    pub summary: EvaluationAnalytics,
    pub trend: Vec<EvaluationTrendPoint>,
}

#[derive(Debug, sqlx::FromRow)]
struct EvaluationSummaryRow {
    total_evaluations: i64,
    guards_evaluated: i64,
    average_rating: f64,
    low_rating_count: i64,
}

fn round_metric(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

pub async fn fetch_resource_snapshot(pool: &PgPool) -> AppResult<ResourceSnapshot> {
    sqlx::query_as::<_, ResourceSnapshot>(
        r#"
        WITH eligible_guards AS (
            SELECT u.id
            FROM users u
            WHERE LOWER(BTRIM(u.role)) = 'guard'
              AND COALESCE(u.status, 'active') = 'active'
              AND u.verified = true
              AND COALESCE(u.approval_status, 'approved') = 'approved'
        ), current_assignments AS (
            SELECT DISTINCT s.guard_id
            FROM shifts s
            WHERE s.status IN ('scheduled', 'in_progress')
              AND s.start_time <= CURRENT_TIMESTAMP
              AND s.end_time >= CURRENT_TIMESTAMP
        ), checked_in_guards AS (
            SELECT DISTINCT a.guard_id
            FROM attendance a
            JOIN shifts s ON s.id = a.shift_id AND s.guard_id = a.guard_id
            WHERE a.check_in_time IS NOT NULL
              AND a.check_out_time IS NULL
              AND s.start_time <= CURRENT_TIMESTAMP
              AND s.end_time >= CURRENT_TIMESTAMP
        )
        SELECT
            (SELECT COUNT(*) FROM eligible_guards)::BIGINT AS total_guards,
            (SELECT COUNT(*) FROM checked_in_guards cig JOIN eligible_guards eg ON eg.id = cig.guard_id)::BIGINT AS guards_on_duty,
            (
                SELECT COUNT(*)
                FROM eligible_guards eg
                LEFT JOIN guard_availability ga ON ga.guard_id = eg.id
                LEFT JOIN current_assignments ca ON ca.guard_id = eg.id
                WHERE COALESCE(ga.available, true) = true
                  AND (ga.available_from IS NULL OR ga.available_from <= CURRENT_TIMESTAMP)
                  AND (ga.available_to IS NULL OR ga.available_to >= CURRENT_TIMESTAMP)
                  AND ca.guard_id IS NULL
            )::BIGINT AS guards_available,
            (SELECT COUNT(*) FROM firearms)::BIGINT AS total_firearms,
            (SELECT COUNT(*) FROM firearms WHERE status IN ('allocated', 'deployed'))::BIGINT AS firearms_in_use,
            (SELECT COUNT(*) FROM firearms WHERE status = 'available')::BIGINT AS firearms_available,
            (SELECT COUNT(*) FROM armored_cars)::BIGINT AS total_vehicles,
            (SELECT COUNT(*) FROM armored_cars WHERE status IN ('allocated', 'in_transit', 'deployed'))::BIGINT AS vehicles_deployed,
            (SELECT COUNT(*) FROM armored_cars WHERE status = 'available')::BIGINT AS vehicles_available
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch resource analytics: {}", e)))
}

pub async fn fetch_evaluation_analytics(
    pool: &PgPool,
    period_days: i64,
) -> AppResult<EvaluationAnalyticsResponse> {
    let period_days = period_days.clamp(7, 90);
    let summary = sqlx::query_as::<_, EvaluationSummaryRow>(
        r#"
        WITH bounds AS (
            SELECT
                ((timezone('Asia/Manila', CURRENT_TIMESTAMP)::date - ($1::BIGINT * INTERVAL '1 day'))::timestamp AT TIME ZONE 'Asia/Manila') AS starts_at,
                ((timezone('Asia/Manila', CURRENT_TIMESTAMP)::date + INTERVAL '1 day')::timestamp AT TIME ZONE 'Asia/Manila') AS ends_at
        )
        SELECT
            COUNT(*)::BIGINT AS total_evaluations,
            COUNT(DISTINCT guard_id)::BIGINT AS guards_evaluated,
            COALESCE(AVG(rating), 0)::DOUBLE PRECISION AS average_rating,
            COUNT(*) FILTER (WHERE rating < 3)::BIGINT AS low_rating_count
        FROM client_evaluations
        CROSS JOIN bounds
        WHERE created_at >= bounds.starts_at
          AND created_at < bounds.ends_at
        "#,
    )
    .bind(period_days)
    .fetch_one(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch evaluation summary: {}", e)))?;

    let rating_distribution = sqlx::query_as::<_, EvaluationRatingBucket>(
        r#"
        WITH bounds AS (
            SELECT
                ((timezone('Asia/Manila', CURRENT_TIMESTAMP)::date - ($1::BIGINT * INTERVAL '1 day'))::timestamp AT TIME ZONE 'Asia/Manila') AS starts_at,
                ((timezone('Asia/Manila', CURRENT_TIMESTAMP)::date + INTERVAL '1 day')::timestamp AT TIME ZONE 'Asia/Manila') AS ends_at
        )
        SELECT bucket::INTEGER AS rating, COUNT(ce.id)::BIGINT AS count
        FROM generate_series(1, 5) AS bucket
        CROSS JOIN bounds
        LEFT JOIN client_evaluations ce
          ON ROUND(ce.rating)::INTEGER = bucket
         AND ce.created_at >= bounds.starts_at
         AND ce.created_at < bounds.ends_at
        GROUP BY bucket
        ORDER BY bucket
        "#,
    )
    .bind(period_days)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to fetch evaluation distribution: {}", e))
    })?;

    let trend = sqlx::query_as::<_, EvaluationTrendPoint>(
        r#"
        WITH bounds AS (
            SELECT
                ((timezone('Asia/Manila', CURRENT_TIMESTAMP)::date - ($1::BIGINT * INTERVAL '1 day'))::timestamp AT TIME ZONE 'Asia/Manila') AS starts_at,
                ((timezone('Asia/Manila', CURRENT_TIMESTAMP)::date + INTERVAL '1 day')::timestamp AT TIME ZONE 'Asia/Manila') AS ends_at
        )
        SELECT
            DATE(timezone('Asia/Manila', created_at)) AS date,
            ROUND(AVG(rating)::NUMERIC, 2)::DOUBLE PRECISION AS average_rating,
            COUNT(*)::BIGINT AS evaluation_count
        FROM client_evaluations
        CROSS JOIN bounds
        WHERE created_at >= bounds.starts_at
          AND created_at < bounds.ends_at
        GROUP BY DATE(timezone('Asia/Manila', created_at))
        ORDER BY DATE(timezone('Asia/Manila', created_at)) ASC
        "#,
    )
    .bind(period_days)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch evaluation trend: {}", e)))?;

    Ok(EvaluationAnalyticsResponse {
        summary: EvaluationAnalytics {
            period_days,
            total_evaluations: summary.total_evaluations,
            guards_evaluated: summary.guards_evaluated,
            average_rating: round_metric(summary.average_rating),
            low_rating_count: summary.low_rating_count,
            rating_distribution,
        },
        trend,
    })
}

#[cfg(test)]
mod tests {
    use super::ResourceSnapshot;

    #[test]
    fn unavailable_counts_never_become_negative() {
        let snapshot = ResourceSnapshot {
            total_guards: 1,
            guards_on_duty: 0,
            guards_available: 2,
            total_firearms: 1,
            firearms_in_use: 0,
            firearms_available: 2,
            total_vehicles: 1,
            vehicles_deployed: 0,
            vehicles_available: 2,
        };

        assert_eq!(snapshot.guards_unavailable(), 0);
        assert_eq!(snapshot.firearms_unavailable(), 0);
        assert_eq!(snapshot.vehicles_unavailable(), 0);
    }
}
