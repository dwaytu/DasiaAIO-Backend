use serde_json::Value;
use sqlx::PgPool;

use crate::error::{AppError, AppResult};

pub async fn activity_counts(db: &PgPool, guard_id: &str) -> AppResult<(i64, i64, i64, i64)> {
    sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM shifts WHERE guard_id = $1),
                COUNT(*) FILTER (WHERE is_on_time AND actual_check_in_time IS NOT NULL),
                COUNT(*) FILTER (WHERE status = 'late'),
                COUNT(*) FILTER (WHERE status IN ('no_show', 'absent'))
         FROM punctuality_records
         WHERE guard_id = $1",
    )
    .bind(guard_id)
    .fetch_one(db)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to read guard activity: {e}")))
}

pub async fn list_history(
    db: &PgPool,
    guard_id: &str,
    category: &str,
    limit: i64,
    offset: i64,
) -> AppResult<(i64, Value)> {
    sqlx::query_as(
        r#"WITH history AS (
            SELECT s.id, 'shift' AS kind, s.start_time AS occurred_at, s.client_site AS site,
                   CASE
                       WHEN s.status NOT IN ('scheduled', 'in_progress', 'active') THEN s.status
                       WHEN attendance.check_out_time IS NOT NULL THEN 'checked_out'
                       WHEN attendance.check_in_time IS NOT NULL THEN 'checked_in'
                       ELSE s.status
                   END AS status,
                   attendance.check_in_time, attendance.check_out_time,
                   NULL::INTEGER AS minutes_late, NULL::FLOAT8 AS rating,
                   NULL::TEXT AS comment, NULL::TEXT AS evaluator_name
            FROM shifts s
            LEFT JOIN LATERAL (
                SELECT a.check_in_time, a.check_out_time FROM attendance a
                WHERE a.shift_id = s.id AND a.guard_id = s.guard_id
                ORDER BY a.check_in_time DESC, a.id DESC LIMIT 1
            ) attendance ON true
            WHERE s.guard_id = $1 AND $2 = 'shifts'

            UNION ALL

            SELECT p.id, 'punctuality', p.scheduled_start_time, s.client_site,
                   CASE WHEN p.status = 'present' AND p.is_on_time AND p.actual_check_in_time IS NOT NULL
                        THEN 'on_time' ELSE p.status END,
                   p.actual_check_in_time, NULL::TIMESTAMPTZ, p.minutes_late, NULL, NULL, NULL
            FROM punctuality_records p
            LEFT JOIN shifts s ON s.id = p.shift_id
            WHERE p.guard_id = $1 AND (
                $2 = 'punctuality'
                OR ($2 = 'on_time' AND p.is_on_time AND p.actual_check_in_time IS NOT NULL)
                OR ($2 IN ('late', 'concerns') AND p.status = 'late')
                OR ($2 IN ('no_show', 'concerns') AND p.status IN ('no_show', 'absent'))
            )

            UNION ALL

            SELECT e.id, 'evaluation', e.created_at, s.client_site, NULL, NULL, NULL, NULL,
                   e.rating, e.comment,
                   CASE WHEN e.evaluator_name = 'Capstone presentation evaluation'
                             AND e.evaluator_role = 'presentation scenario'
                        THEN NULL ELSE e.evaluator_name END
            FROM client_evaluations e
            LEFT JOIN shifts s ON s.id = e.shift_id
            WHERE e.guard_id = $1 AND ($2 = 'evaluations' OR ($2 = 'concerns' AND e.rating < 3))
        ), page AS (
            SELECT * FROM history ORDER BY occurred_at DESC NULLS LAST, kind, id
            LIMIT $3 OFFSET $4
        )
        SELECT (SELECT COUNT(*) FROM history),
               COALESCE((SELECT jsonb_agg(to_jsonb(page) ORDER BY occurred_at DESC NULLS LAST, kind, id) FROM page), '[]'::jsonb)"#,
    )
    .bind(guard_id)
    .bind(category)
    .bind(limit)
    .bind(offset)
    .fetch_one(db)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to read guard performance history: {e}")))
}
