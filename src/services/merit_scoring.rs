use sqlx::PgPool;

use crate::error::{AppError, AppResult};

#[derive(sqlx::FromRow)]
pub struct MeritInputs {
    pub guard_id: String,
    pub guard_name: String,
    pub total_shifts: i64,
    pub attended_shifts: i64,
    pub completed_shifts: i64,
    pub on_time: i64,
    pub late: i64,
    pub no_shows: i64,
    pub tracked_punctuality: i64,
    pub average_rating: Option<f64>,
    pub evaluation_count: i64,
}

fn percentage(count: i64, total: i64) -> Option<f64> {
    (total > 0).then(|| 100.0 * count as f64 / total as f64)
}

impl MeritInputs {
    pub fn attendance(&self) -> Option<f64> {
        percentage(self.attended_shifts, self.total_shifts)
    }

    pub fn punctuality(&self) -> Option<f64> {
        percentage(self.on_time, self.tracked_punctuality)
    }

    pub fn overall(&self) -> Option<f64> {
        let weighted = self.attendance()? * 0.30
            + self.punctuality()? * 0.35
            + self.average_rating? * 20.0 * 0.35;
        Some((weighted * 100.0).round() / 100.0)
    }
}

pub fn rank(score: f64) -> &'static str {
    match score {
        score if score >= 90.0 => "Gold",
        score if score >= 80.0 => "Silver",
        score if score >= 70.0 => "Bronze",
        _ => "Standard",
    }
}

pub async fn load_merit_inputs(db: &PgPool, guard_id: Option<&str>) -> AppResult<Vec<MeritInputs>> {
    // Match the Guard Performance report's shift and check-in definitions.
    sqlx::query_as(
        r#"
        WITH guards AS (
            SELECT id, COALESCE(NULLIF(full_name, ''), username) AS guard_name
            FROM users
            WHERE LOWER(BTRIM(role)) = 'guard'
              AND COALESCE(status, 'active') = 'active'
              AND verified = true
              AND COALESCE(approval_status, 'approved') = 'approved'
              AND ($1::TEXT IS NULL OR id = $1)
        ), attendance_by_shift AS (
            SELECT a.shift_id, a.guard_id,
                   BOOL_OR(a.check_in_time IS NOT NULL) AS checked_in,
                   BOOL_OR(a.check_out_time IS NOT NULL OR a.status IN ('checked_out', 'completed')) AS checked_out
            FROM attendance a JOIN guards g ON g.id = a.guard_id
            GROUP BY a.shift_id, a.guard_id
        ), punctuality_by_shift AS (
            SELECT p.shift_id, p.guard_id,
                   MIN(p.scheduled_start_time) AS scheduled_start_time,
                   BOOL_OR(p.status IN ('early', 'on_time') OR
                     (p.status = 'present' AND p.is_on_time AND p.actual_check_in_time IS NOT NULL)) AS on_time,
                   BOOL_OR(p.status = 'late') AS late,
                   BOOL_OR(p.status IN ('absent', 'no_show')) AS absent
            FROM punctuality_records p JOIN guards g ON g.id = p.guard_id
            GROUP BY p.shift_id, p.guard_id
        ), report_shifts AS (
            SELECT s.id, s.guard_id, s.start_time, s.status
            FROM shifts s JOIN guards g ON g.id = s.guard_id
            WHERE s.status NOT IN ('cancelled', 'canceled')
            UNION ALL
            SELECT s.id, p.guard_id, p.scheduled_start_time, 'absent'
            FROM punctuality_by_shift p JOIN shifts s ON s.id = p.shift_id AND s.guard_id <> p.guard_id
            WHERE p.absent AND s.status NOT IN ('cancelled', 'canceled')
        ), metrics AS (
            SELECT s.guard_id,
                   COUNT(*) AS total_shifts,
                   COUNT(*) FILTER (WHERE a.checked_in) AS attended_shifts,
                   COUNT(*) FILTER (WHERE a.checked_out OR s.status = 'completed') AS completed_shifts,
                   COUNT(*) FILTER (WHERE p.on_time AND NOT p.late) AS on_time,
                   COUNT(*) FILTER (WHERE p.late) AS late,
                   COUNT(*) FILTER (
                       WHERE NOT COALESCE(a.checked_in, false)
                         AND (p.absent OR s.status IN ('absent', 'no_show'))
                   ) AS no_shows,
                   COUNT(*) FILTER (
                       WHERE p.on_time OR p.late OR (
                           NOT COALESCE(a.checked_in, false)
                           AND (p.absent OR s.status IN ('absent', 'no_show'))
                       )
                   ) AS tracked_punctuality
            FROM report_shifts s
            LEFT JOIN attendance_by_shift a ON a.shift_id = s.id AND a.guard_id = s.guard_id
            LEFT JOIN punctuality_by_shift p ON p.shift_id = s.id AND p.guard_id = s.guard_id
            WHERE s.start_time <= CURRENT_TIMESTAMP OR a.checked_in
            GROUP BY s.guard_id
        ), reviews AS (
            SELECT e.guard_id, AVG(e.rating)::FLOAT8 AS average_rating, COUNT(*) AS evaluation_count
            FROM client_evaluations e JOIN guards g ON g.id = e.guard_id
            WHERE e.rating BETWEEN 1 AND 5
            GROUP BY e.guard_id
        )
        SELECT g.id AS guard_id, g.guard_name,
               COALESCE(m.total_shifts, 0) AS total_shifts,
               COALESCE(m.attended_shifts, 0) AS attended_shifts,
               COALESCE(m.completed_shifts, 0) AS completed_shifts,
               COALESCE(m.on_time, 0) AS on_time,
               COALESCE(m.late, 0) AS late,
               COALESCE(m.no_shows, 0) AS no_shows,
               COALESCE(m.tracked_punctuality, 0) AS tracked_punctuality,
               r.average_rating, COALESCE(r.evaluation_count, 0) AS evaluation_count
        FROM guards g LEFT JOIN metrics m ON m.guard_id = g.id
        LEFT JOIN reviews r ON r.guard_id = g.id
        ORDER BY g.guard_name, g.id
        "#,
    )
    .bind(guard_id)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to read merit scoring inputs: {e}")))
}
