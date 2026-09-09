use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};
use axum::extract::Query;
use chrono::{DateTime, Days, NaiveDate, Utc};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    utils,
};

#[derive(Debug, Serialize)]
pub struct AnalyticsResponse {
    pub overview: OverviewStats,
    pub performance_metrics: PerformanceMetrics,
    pub resource_utilization: ResourceUtilization,
    pub mission_stats: MissionStats,
    pub attendance_analytics: AttendanceAnalytics,
    pub attendance_trend: Vec<AttendanceTrendPoint>,
}

#[derive(Debug, Serialize)]
pub struct AttendanceAnalytics {
    pub period_days: i64,
    pub total_scheduled_shifts: i64,
    pub attended_shifts: i64,
    pub on_time_check_ins: i64,
    pub late_check_ins: i64,
    pub no_shows: i64,
    pub attendance_rate: f64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct AttendanceTrendPoint {
    pub date: Option<NaiveDate>,
    pub scheduled_shifts: i64,
    pub attended_shifts: i64,
    pub late_check_ins: i64,
    pub no_shows: i64,
}

#[derive(Debug, Serialize)]
pub struct OverviewStats {
    pub total_guards: i64,
    pub active_guards: i64,
    pub total_missions: i64,
    pub completed_missions: i64,
    pub active_missions: i64,
    pub total_firearms: i64,
    pub allocated_firearms: i64,
    pub total_vehicles: i64,
    pub deployed_vehicles: i64,
}

#[derive(Debug, Serialize)]
pub struct PerformanceMetrics {
    pub mission_completion_rate: f64,
    pub average_mission_duration: f64,
    pub guard_attendance_rate: f64,
    pub firearm_availability_rate: f64,
    pub vehicle_utilization_rate: f64,
}

#[derive(Debug, Serialize)]
pub struct ResourceUtilization {
    pub firearms_in_use: i64,
    pub firearms_available: i64,
    pub firearms_unavailable: i64,
    pub vehicles_deployed: i64,
    pub vehicles_available: i64,
    pub vehicles_unavailable: i64,
    pub guards_on_duty: i64,
    pub guards_available: i64,
}

#[derive(Debug, Serialize)]
pub struct MissionStats {
    pub total_missions_this_month: i64,
    pub completed_missions_this_month: i64,
    pub pending_missions: i64,
    pub average_guards_per_mission: f64,
    pub average_duration_hours: f64,
}

#[derive(Debug, Deserialize)]
pub struct AnalyticsQuery {
    pub days: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct GuardPerformanceReportQuery {
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardPerformancePeriod {
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardPerformanceSummary {
    pub total_guards: i64,
    pub average_attendance_rate: f64,
    pub total_late_check_ins: i64,
    pub total_completed_shifts: i64,
    pub total_no_shows: i64,
    pub total_incident_reports: i64,
    pub average_client_rating: f64,
    pub average_merit_score: f64,
    pub total_replacement_frequency: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct GuardPerformanceReportRow {
    pub guard_id: String,
    pub guard_name: String,
    pub total_shifts: i64,
    pub attended_shifts: i64,
    pub attendance_rate: f64,
    pub late_check_ins: i64,
    pub completed_shifts: i64,
    pub no_shows: i64,
    pub incident_reports_submitted: i64,
    pub average_client_rating: f64,
    pub evaluation_count: i64,
    pub merit_score: f64,
    pub replacement_frequency: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardPerformanceReportResponse {
    pub period: GuardPerformancePeriod,
    pub summary: GuardPerformanceSummary,
    pub guards: Vec<GuardPerformanceReportRow>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct GuardReliabilityScore {
    pub guard_id: String,
    pub guard_name: String,
    pub attendance_score: f64,
    pub mission_performance: f64,
    pub permit_compliance: f64,
    pub reliability_score: f64,
    pub rank: i64,
}

fn parse_report_date(
    value: &Option<String>,
    add_day_for_exclusive_end: bool,
    field_name: &str,
) -> AppResult<(Option<DateTime<Utc>>, Option<String>)> {
    let Some(raw) = value else {
        return Ok((None, None));
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok((None, None));
    }

    let date = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d").map_err(|_| {
        AppError::BadRequest(format!(
            "{} must use YYYY-MM-DD format, for example 2026-08-19",
            field_name
        ))
    })?;

    let boundary_date = if add_day_for_exclusive_end {
        date.checked_add_days(Days::new(1)).ok_or_else(|| {
            AppError::BadRequest(format!("{} is outside the supported date range", field_name))
        })?
    } else {
        date
    };

    let naive_boundary = boundary_date.and_hms_opt(0, 0, 0).ok_or_else(|| {
        AppError::BadRequest(format!("{} is outside the supported date range", field_name))
    })?;

    Ok((
        Some(DateTime::<Utc>::from_naive_utc_and_offset(
            naive_boundary,
            Utc,
        )),
        Some(date.to_string()),
    ))
}

fn round_metric(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn build_guard_performance_summary(
    guards: &[GuardPerformanceReportRow],
) -> GuardPerformanceSummary {
    let total_guards = guards.len() as i64;
    let total_shifts: i64 = guards.iter().map(|guard| guard.total_shifts).sum();
    let attended_shifts: i64 = guards.iter().map(|guard| guard.attended_shifts).sum();
    let total_late_check_ins: i64 = guards.iter().map(|guard| guard.late_check_ins).sum();
    let total_completed_shifts: i64 = guards.iter().map(|guard| guard.completed_shifts).sum();
    let total_no_shows: i64 = guards.iter().map(|guard| guard.no_shows).sum();
    let total_incident_reports: i64 = guards
        .iter()
        .map(|guard| guard.incident_reports_submitted)
        .sum();
    let total_replacement_frequency: i64 = guards
        .iter()
        .map(|guard| guard.replacement_frequency)
        .sum();
    let total_evaluations: i64 = guards.iter().map(|guard| guard.evaluation_count).sum();

    let average_attendance_rate = if total_shifts > 0 {
        (attended_shifts as f64 / total_shifts as f64) * 100.0
    } else {
        0.0
    };

    let weighted_rating_sum = guards.iter().fold(0.0, |sum, guard| {
        sum + (guard.average_client_rating * guard.evaluation_count as f64)
    });
    let average_client_rating = if total_evaluations > 0 {
        weighted_rating_sum / total_evaluations as f64
    } else {
        0.0
    };

    let average_merit_score = if total_guards > 0 {
        guards.iter().map(|guard| guard.merit_score).sum::<f64>() / total_guards as f64
    } else {
        0.0
    };

    GuardPerformanceSummary {
        total_guards,
        average_attendance_rate: round_metric(average_attendance_rate),
        total_late_check_ins,
        total_completed_shifts,
        total_no_shows,
        total_incident_reports,
        average_client_rating: round_metric(average_client_rating),
        average_merit_score: round_metric(average_merit_score),
        total_replacement_frequency,
    }
}

// Get comprehensive analytics
pub async fn get_analytics(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Query(query): Query<AnalyticsQuery>,
) -> AppResult<Json<AnalyticsResponse>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;
    let period_days = query.days.unwrap_or(30).clamp(7, 90);

    // Overview stats
    let total_guards = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE role = 'guard' AND status = 'active'",
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let active_guards = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(DISTINCT guard_id) FROM shifts 
         WHERE status = 'in_progress' OR status = 'scheduled'",
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let total_missions = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM trips")
        .fetch_one(db.as_ref())
        .await
        .unwrap_or(0);

    let completed_missions =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM trips WHERE status = 'completed'")
            .fetch_one(db.as_ref())
            .await
            .unwrap_or(0);

    let active_missions = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM trips WHERE status = 'in_progress' OR status = 'scheduled'",
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let total_firearms = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM firearms")
        .fetch_one(db.as_ref())
        .await
        .unwrap_or(0);

    let allocated_firearms =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM firearms WHERE status = 'allocated'")
            .fetch_one(db.as_ref())
            .await
            .unwrap_or(0);

    let available_firearms =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM firearms WHERE status = 'available'")
            .fetch_one(db.as_ref())
            .await
            .unwrap_or(0);

    let total_vehicles = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM armored_cars")
        .fetch_one(db.as_ref())
        .await
        .unwrap_or(0);

    let deployed_vehicles =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM armored_cars WHERE status = 'deployed'")
            .fetch_one(db.as_ref())
            .await
            .unwrap_or(0);

    let available_vehicles =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM armored_cars WHERE status = 'available'")
            .fetch_one(db.as_ref())
            .await
            .unwrap_or(0);

    // Performance metrics
    let mission_completion_rate = if total_missions > 0 {
        (completed_missions as f64 / total_missions as f64) * 100.0
    } else {
        0.0
    };

    let average_mission_duration = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT AVG(EXTRACT(EPOCH FROM (end_time - start_time)) / 3600.0) 
         FROM trips WHERE end_time IS NOT NULL AND start_time IS NOT NULL",
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(None)
    .unwrap_or(0.0);

    let total_shifts =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM shifts WHERE status = 'completed'")
            .fetch_one(db.as_ref())
            .await
            .unwrap_or(0);

    let attended_shifts = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(DISTINCT shift_id) FROM attendance WHERE check_in_time IS NOT NULL",
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let guard_attendance_rate = if total_shifts > 0 {
        (attended_shifts as f64 / total_shifts as f64) * 100.0
    } else {
        100.0
    };

    let firearm_availability_rate = if total_firearms > 0 {
        (available_firearms as f64 / total_firearms as f64) * 100.0
    } else {
        0.0
    };

    let vehicle_utilization_rate = if total_vehicles > 0 {
        (deployed_vehicles as f64 / total_vehicles as f64) * 100.0
    } else {
        0.0
    };

    // Resource utilization
    let firearms_available = available_firearms;
    let firearms_unavailable = total_firearms - firearms_available;
    let vehicles_available = available_vehicles;
    let vehicles_unavailable = total_vehicles - vehicles_available;
    let guards_available = total_guards - active_guards;

    // Mission stats
    let total_missions_this_month = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM trips 
         WHERE EXTRACT(MONTH FROM start_time) = EXTRACT(MONTH FROM CURRENT_TIMESTAMP)
         AND EXTRACT(YEAR FROM start_time) = EXTRACT(YEAR FROM CURRENT_TIMESTAMP)",
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let completed_missions_this_month = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM trips 
         WHERE status = 'completed'
         AND EXTRACT(MONTH FROM start_time) = EXTRACT(MONTH FROM CURRENT_TIMESTAMP)
         AND EXTRACT(YEAR FROM start_time) = EXTRACT(YEAR FROM CURRENT_TIMESTAMP)",
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let pending_missions =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM trips WHERE status = 'scheduled'")
            .fetch_one(db.as_ref())
            .await
            .unwrap_or(0);

    let average_guards_per_mission = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT AVG(guard_count) FROM (
            SELECT t.id, COUNT(DISTINCT s.guard_id) as guard_count
            FROM trips t
            LEFT JOIN shifts s ON DATE(t.start_time) = DATE(s.start_time)
            WHERE t.start_time IS NOT NULL
            GROUP BY t.id
        ) mission_guards",
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(None)
    .unwrap_or(0.0);

    let attendance_row = sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(
        "WITH scoped_shifts AS (
            SELECT id, start_time, end_time
            FROM shifts
            WHERE start_time >= CURRENT_DATE - ($1::BIGINT * INTERVAL '1 day')
              AND start_time < CURRENT_DATE + INTERVAL '1 day'
        )
        SELECT
            COUNT(*)::BIGINT,
            COUNT(*) FILTER (WHERE EXISTS (
                SELECT 1 FROM attendance a
                WHERE a.shift_id = s.id AND a.check_in_time IS NOT NULL
            ))::BIGINT,
            COUNT(*) FILTER (WHERE EXISTS (
                SELECT 1 FROM punctuality_records p
                WHERE p.shift_id = s.id AND p.status IN ('early', 'on_time')
            ))::BIGINT,
            COUNT(*) FILTER (WHERE EXISTS (
                SELECT 1 FROM punctuality_records p
                WHERE p.shift_id = s.id AND p.status = 'late'
            ))::BIGINT,
            COUNT(*) FILTER (WHERE s.end_time < CURRENT_TIMESTAMP AND NOT EXISTS (
                SELECT 1 FROM attendance a
                WHERE a.shift_id = s.id AND a.check_in_time IS NOT NULL
            ))::BIGINT
        FROM scoped_shifts s",
    )
    .bind(period_days)
    .fetch_one(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch attendance analytics: {}", e)))?;

    let attendance_rate = if attendance_row.0 > 0 {
        (attendance_row.1 as f64 / attendance_row.0 as f64) * 100.0
    } else {
        0.0
    };

    let attendance_trend = sqlx::query_as::<_, AttendanceTrendPoint>(
        "SELECT
            DATE(s.start_time) AS date,
            COUNT(*)::BIGINT AS scheduled_shifts,
            COUNT(*) FILTER (WHERE EXISTS (
                SELECT 1 FROM attendance a
                WHERE a.shift_id = s.id AND a.check_in_time IS NOT NULL
            ))::BIGINT AS attended_shifts,
            COUNT(*) FILTER (WHERE EXISTS (
                SELECT 1 FROM punctuality_records p
                WHERE p.shift_id = s.id AND p.status = 'late'
            ))::BIGINT AS late_check_ins,
            COUNT(*) FILTER (WHERE s.end_time < CURRENT_TIMESTAMP AND NOT EXISTS (
                SELECT 1 FROM attendance a
                WHERE a.shift_id = s.id AND a.check_in_time IS NOT NULL
            ))::BIGINT AS no_shows
        FROM shifts s
        WHERE s.start_time >= CURRENT_DATE - ($1::BIGINT * INTERVAL '1 day')
          AND s.start_time < CURRENT_DATE + INTERVAL '1 day'
        GROUP BY DATE(s.start_time)
        ORDER BY DATE(s.start_time) ASC",
    )
    .bind(period_days)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch attendance trend: {}", e)))?;

    let response = AnalyticsResponse {
        overview: OverviewStats {
            total_guards,
            active_guards,
            total_missions,
            completed_missions,
            active_missions,
            total_firearms,
            allocated_firearms,
            total_vehicles,
            deployed_vehicles,
        },
        performance_metrics: PerformanceMetrics {
            mission_completion_rate,
            average_mission_duration,
            guard_attendance_rate,
            firearm_availability_rate,
            vehicle_utilization_rate,
        },
        resource_utilization: ResourceUtilization {
            firearms_in_use: allocated_firearms,
            firearms_available,
            firearms_unavailable,
            vehicles_deployed: deployed_vehicles,
            vehicles_available,
            vehicles_unavailable,
            guards_on_duty: active_guards,
            guards_available,
        },
        mission_stats: MissionStats {
            total_missions_this_month,
            completed_missions_this_month,
            pending_missions,
            average_guards_per_mission,
            average_duration_hours: average_mission_duration,
        },
        attendance_analytics: AttendanceAnalytics {
            period_days,
            total_scheduled_shifts: attendance_row.0,
            attended_shifts: attendance_row.1,
            on_time_check_ins: attendance_row.2,
            late_check_ins: attendance_row.3,
            no_shows: attendance_row.4,
            attendance_rate: round_metric(attendance_rate),
        },
        attendance_trend,
    };

    Ok(Json(response))
}

pub async fn get_guard_performance_report(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Query(query): Query<GuardPerformanceReportQuery>,
) -> AppResult<Json<GuardPerformanceReportResponse>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;
    let (from_bound, from_label) = parse_report_date(&query.from, false, "from")?;
    let (to_bound, to_label) = parse_report_date(&query.to, true, "to")?;

    if let (Some(from), Some(to)) = (from_bound, to_bound) {
        if from >= to {
            return Err(AppError::BadRequest(
                "from must be earlier than or equal to to".to_string(),
            ));
        }
    }

    let guards = sqlx::query_as::<_, GuardPerformanceReportRow>(
        r#"
        WITH guard_base AS (
            SELECT
                id,
                COALESCE(NULLIF(full_name, ''), username) AS guard_name
            FROM users
            WHERE LOWER(role) = 'guard'
        ), attendance_by_shift AS (
            SELECT
                shift_id,
                guard_id,
                BOOL_OR(check_in_time IS NOT NULL) AS checked_in,
                BOOL_OR(check_out_time IS NOT NULL OR status = 'checked_out') AS checked_out
            FROM attendance
            GROUP BY shift_id, guard_id
        ), shift_metrics AS (
            SELECT
                s.guard_id,
                COUNT(*)::BIGINT AS total_shifts,
                COUNT(*) FILTER (WHERE COALESCE(abs.checked_in, false))::BIGINT AS attended_shifts,
                COUNT(*) FILTER (
                    WHERE COALESCE(abs.checked_out, false) OR s.status = 'completed'
                )::BIGINT AS completed_shifts,
                COUNT(*) FILTER (
                    WHERE NOT COALESCE(abs.checked_in, false) AND s.end_time < CURRENT_TIMESTAMP
                )::BIGINT AS inferred_no_shows
            FROM shifts s
            LEFT JOIN attendance_by_shift abs ON abs.shift_id = s.id AND abs.guard_id = s.guard_id
            WHERE ($1::TIMESTAMPTZ IS NULL OR s.start_time >= $1)
              AND ($2::TIMESTAMPTZ IS NULL OR s.start_time < $2)
            GROUP BY s.guard_id
        ), punctuality_metrics AS (
            SELECT
                guard_id,
                COUNT(*) FILTER (WHERE status = 'late')::BIGINT AS late_check_ins,
                COUNT(*) FILTER (WHERE status = 'no_show')::BIGINT AS recorded_no_shows
            FROM punctuality_records
            WHERE ($1::TIMESTAMPTZ IS NULL OR scheduled_start_time >= $1)
              AND ($2::TIMESTAMPTZ IS NULL OR scheduled_start_time < $2)
            GROUP BY guard_id
        ), incident_metrics AS (
            SELECT
                reported_by AS guard_id,
                COUNT(*)::BIGINT AS incident_reports_submitted
            FROM incidents
            WHERE ($1::TIMESTAMPTZ IS NULL OR created_at >= $1)
              AND ($2::TIMESTAMPTZ IS NULL OR created_at < $2)
            GROUP BY reported_by
        ), evaluation_metrics AS (
            SELECT
                guard_id,
                COALESCE(AVG(rating), 0)::DOUBLE PRECISION AS average_client_rating,
                COUNT(*)::BIGINT AS evaluation_count
            FROM client_evaluations
            WHERE ($1::TIMESTAMPTZ IS NULL OR created_at >= $1)
              AND ($2::TIMESTAMPTZ IS NULL OR created_at < $2)
            GROUP BY guard_id
        ), replacement_events AS (
            SELECT requester_id AS guard_id, status, created_at
            FROM guard_shift_swaps
            UNION ALL
            SELECT target_id AS guard_id, status, created_at
            FROM guard_shift_swaps
        ), replacement_metrics AS (
            SELECT
                guard_id,
                COUNT(*) FILTER (WHERE status = 'accepted')::BIGINT AS replacement_frequency
            FROM replacement_events
            WHERE ($1::TIMESTAMPTZ IS NULL OR created_at >= $1)
              AND ($2::TIMESTAMPTZ IS NULL OR created_at < $2)
            GROUP BY guard_id
        )
        SELECT
            gb.id AS guard_id,
            gb.guard_name,
            COALESCE(sm.total_shifts, 0)::BIGINT AS total_shifts,
            COALESCE(sm.attended_shifts, 0)::BIGINT AS attended_shifts,
            ROUND(
                CASE
                    WHEN COALESCE(sm.total_shifts, 0) > 0
                    THEN (COALESCE(sm.attended_shifts, 0)::DOUBLE PRECISION / sm.total_shifts::DOUBLE PRECISION) * 100.0
                    ELSE 0.0
                END::NUMERIC,
                2
            )::DOUBLE PRECISION AS attendance_rate,
            COALESCE(pm.late_check_ins, 0)::BIGINT AS late_check_ins,
            COALESCE(sm.completed_shifts, 0)::BIGINT AS completed_shifts,
            GREATEST(
                COALESCE(pm.recorded_no_shows, 0),
                COALESCE(sm.inferred_no_shows, 0)
            )::BIGINT AS no_shows,
            COALESCE(im.incident_reports_submitted, 0)::BIGINT AS incident_reports_submitted,
            ROUND(COALESCE(em.average_client_rating, 0)::NUMERIC, 2)::DOUBLE PRECISION AS average_client_rating,
            COALESCE(em.evaluation_count, 0)::BIGINT AS evaluation_count,
            ROUND(COALESCE(gms.overall_score, 0)::NUMERIC, 2)::DOUBLE PRECISION AS merit_score,
            COALESCE(rm.replacement_frequency, 0)::BIGINT AS replacement_frequency
        FROM guard_base gb
        LEFT JOIN shift_metrics sm ON sm.guard_id = gb.id
        LEFT JOIN punctuality_metrics pm ON pm.guard_id = gb.id
        LEFT JOIN incident_metrics im ON im.guard_id = gb.id
        LEFT JOIN evaluation_metrics em ON em.guard_id = gb.id
        LEFT JOIN guard_merit_scores gms ON gms.guard_id = gb.id
        LEFT JOIN replacement_metrics rm ON rm.guard_id = gb.id
        ORDER BY merit_score DESC, attendance_rate DESC, gb.guard_name ASC
        "#,
    )
    .bind(from_bound)
    .bind(to_bound)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to fetch guard performance report: {}", e))
    })?;

    let summary = build_guard_performance_summary(&guards);

    Ok(Json(GuardPerformanceReportResponse {
        period: GuardPerformancePeriod {
            from: from_label,
            to: to_label,
        },
        summary,
        guards,
    }))
}

// Get performance trends
pub async fn get_performance_trends(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    #[derive(sqlx::FromRow, Serialize)]
    struct DailyStats {
        date: Option<chrono::NaiveDate>,
        missions_count: Option<i64>,
        completed_count: Option<i64>,
    }

    let daily_stats = sqlx::query_as::<_, DailyStats>(
        "SELECT DATE(start_time) as date,
                COUNT(*) as missions_count,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_count
         FROM trips
         WHERE start_time >= CURRENT_DATE - INTERVAL '30 days'
         GROUP BY DATE(start_time)
         ORDER BY DATE(start_time) DESC
         LIMIT 30",
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch trends: {}", e)))?;

    Ok(Json(json!({
        "daily_stats": daily_stats,
        "period": "Last 30 days"
    })))
}

pub async fn get_guard_reliability(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<GuardReliabilityScore>>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let rows = sqlx::query_as::<_, GuardReliabilityScore>(
        r#"
        WITH guard_base AS (
            SELECT id,
                   COALESCE(NULLIF(full_name, ''), username) AS guard_name
            FROM users
            WHERE role IN ('guard')
        ), attendance AS (
            SELECT
                s.guard_id,
                COUNT(*) AS total_shifts,
                COUNT(*) FILTER (WHERE a.check_in_time IS NOT NULL) AS attended_shifts
            FROM shifts s
            LEFT JOIN attendance a ON a.shift_id = s.id AND a.guard_id = s.guard_id
            GROUP BY s.guard_id
        ), missions AS (
            SELECT
                driver_id AS guard_id,
                COUNT(*) AS missions_total,
                COUNT(*) FILTER (WHERE status = 'completed') AS missions_completed
            FROM trips
            GROUP BY driver_id
        ), permits AS (
            SELECT
                guard_id,
                COUNT(*) AS total_permits,
                COUNT(*) FILTER (WHERE status = 'active' AND expiry_date > NOW()) AS active_permits
            FROM guard_firearm_permits
            GROUP BY guard_id
        )
        SELECT
            gb.id AS guard_id,
            gb.guard_name,
            ROUND((COALESCE(att.attended_shifts::DOUBLE PRECISION / NULLIF(att.total_shifts, 0), 1.0) * 100.0)::NUMERIC, 2)::DOUBLE PRECISION AS attendance_score,
            ROUND((COALESCE(mis.missions_completed::DOUBLE PRECISION / NULLIF(mis.missions_total, 0), 1.0) * 100.0)::NUMERIC, 2)::DOUBLE PRECISION AS mission_performance,
            ROUND((COALESCE(perm.active_permits::DOUBLE PRECISION / NULLIF(perm.total_permits, 0), 1.0) * 100.0)::NUMERIC, 2)::DOUBLE PRECISION AS permit_compliance,
            ROUND(
                ((COALESCE(att.attended_shifts::DOUBLE PRECISION / NULLIF(att.total_shifts, 0), 1.0) * 100.0 * 0.4) +
                (COALESCE(mis.missions_completed::DOUBLE PRECISION / NULLIF(mis.missions_total, 0), 1.0) * 100.0 * 0.4) +
                (COALESCE(perm.active_permits::DOUBLE PRECISION / NULLIF(perm.total_permits, 0), 1.0) * 100.0 * 0.2))::NUMERIC,
                2
            )::DOUBLE PRECISION AS reliability_score,
            ROW_NUMBER() OVER (
                ORDER BY (
                    (COALESCE(att.attended_shifts::DOUBLE PRECISION / NULLIF(att.total_shifts, 0), 1.0) * 100.0 * 0.4) +
                    (COALESCE(mis.missions_completed::DOUBLE PRECISION / NULLIF(mis.missions_total, 0), 1.0) * 100.0 * 0.4) +
                    (COALESCE(perm.active_permits::DOUBLE PRECISION / NULLIF(perm.total_permits, 0), 1.0) * 100.0 * 0.2)
                ) DESC,
                gb.guard_name ASC
            ) AS rank
        FROM guard_base gb
        LEFT JOIN attendance att ON att.guard_id = gb.id
        LEFT JOIN missions mis ON mis.guard_id = gb.id
        LEFT JOIN permits perm ON perm.guard_id = gb.id
        ORDER BY reliability_score DESC, gb.guard_name ASC
        LIMIT 5
        "#,
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch guard reliability: {}", e)))?;

    Ok(Json(rows))
}

// Update mission status
pub async fn update_mission_status(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<UpdateMissionStatusRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    // Update trip status
    sqlx::query("UPDATE trips SET status = $1 WHERE id = $2")
        .bind(&payload.status)
        .bind(&payload.mission_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update mission: {}", e)))?;

    // If completed, update vehicle status back to operational
    if payload.status == "completed" {
        sqlx::query(
            "UPDATE armored_cars SET status = 'operational' 
             WHERE id IN (SELECT car_id FROM trips WHERE id = $1)",
        )
        .bind(&payload.mission_id)
        .execute(db.as_ref())
        .await
        .ok();

        // Return allocated firearms
        sqlx::query(
            "UPDATE firearms SET status = 'available'
             WHERE id IN (
                 SELECT fa.firearm_id FROM firearm_allocations fa
                 JOIN shifts s ON fa.guard_id = s.guard_id
                 JOIN trips t ON DATE(s.start_time) = DATE(t.start_time)
                 WHERE t.id = $1 AND fa.status = 'active'
             )",
        )
        .bind(&payload.mission_id)
        .execute(db.as_ref())
        .await
        .ok();

        // Update firearm allocations
        sqlx::query(
            "UPDATE firearm_allocations SET status = 'returned'
             WHERE guard_id IN (
                 SELECT s.guard_id FROM shifts s
                 JOIN trips t ON DATE(s.start_time) = DATE(t.start_time)
                 WHERE t.id = $1
             ) AND status = 'active'",
        )
        .bind(&payload.mission_id)
        .execute(db.as_ref())
        .await
        .ok();
    }

    Ok(Json(json!({
        "success": true,
        "message": "Mission status updated successfully"
    })))
}

#[derive(Debug, Deserialize)]
pub struct UpdateMissionStatusRequest {
    pub mission_id: String,
    pub status: String,
}

