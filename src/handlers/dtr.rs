use axum::{extract::{Query, State}, http::HeaderMap, Json};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    utils,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DtrQuery {
    pub guard_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub site: Option<String>,
    pub status: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct DtrRecord {
    pub shift_id: String,
    pub attendance_id: Option<String>,
    pub guard_id: String,
    pub guard_name: String,
    pub client_site: String,
    pub scheduled_start: DateTime<Utc>,
    pub scheduled_end: DateTime<Utc>,
    pub actual_check_in: Option<DateTime<Utc>>,
    pub actual_check_out: Option<DateTime<Utc>>,
    pub late_minutes: Option<i32>,
    pub total_hours: Option<f64>,
    pub status: String,
    #[serde(skip)]
    pub total_count: i64,
}

const VALID_STATUSES: [&str; 5] = ["scheduled", "checked_in", "completed", "absent", "no_show"];

fn normalize_date(value: Option<String>, field: &str) -> AppResult<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };

    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    NaiveDate::parse_from_str(trimmed, "%Y-%m-%d")
        .map(|date| Some(date.format("%Y-%m-%d").to_string()))
        .map_err(|_| AppError::BadRequest(format!("{} must use YYYY-MM-DD format", field)))
}

fn normalize_status(value: Option<String>) -> AppResult<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };

    let trimmed = value.trim().to_lowercase();
    if trimmed.is_empty() {
        return Ok(None);
    }

    if !VALID_STATUSES.contains(&trimmed.as_str()) {
        return Err(AppError::BadRequest(format!(
            "status must be one of: {}",
            VALID_STATUSES.join(", ")
        )));
    }

    Ok(Some(trimmed))
}

pub async fn get_dtr_report(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Query(query): Query<DtrQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;
    let from = normalize_date(query.from, "from")?;
    let to = normalize_date(query.to, "to")?;
    if let (Some(from), Some(to)) = (&from, &to) {
        if from > to {
            return Err(AppError::BadRequest(
                "from must be earlier than or equal to to".to_string(),
            ));
        }
    }

    let guard_id = query
        .guard_id
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_string());
    let site = query
        .site
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_string());
    let status = normalize_status(query.status)?;
    let (page, page_size, offset) = utils::resolve_pagination(
        utils::PaginationQuery {
            page: query.page,
            page_size: query.page_size,
        },
        40,
        200,
    );

    let rows = sqlx::query_as::<_, DtrRecord>(
        r#"
        WITH dtr_base AS (
            SELECT
                s.id AS shift_id,
                a.id AS attendance_id,
                s.guard_id,
                u.full_name AS guard_name,
                s.client_site,
                s.start_time AS scheduled_start,
                s.end_time AS scheduled_end,
                a.check_in_time AS actual_check_in,
                a.check_out_time AS actual_check_out,
                COALESCE(pr.minutes_late,
                    CASE
                        WHEN a.check_in_time IS NOT NULL AND a.check_in_time > s.start_time
                        THEN GREATEST(0, EXTRACT(EPOCH FROM (a.check_in_time - s.start_time))::INTEGER / 60)
                        ELSE 0
                    END
                ) AS late_minutes,
                CASE
                    WHEN a.check_in_time IS NOT NULL AND a.check_out_time IS NOT NULL
                    THEN ROUND((EXTRACT(EPOCH FROM (a.check_out_time - a.check_in_time)) / 3600.0)::NUMERIC, 2)::DOUBLE PRECISION
                    ELSE NULL
                END AS total_hours,
                CASE
                    WHEN pr.status = 'no_show' THEN 'no_show'
                    WHEN a.check_out_time IS NOT NULL OR a.status = 'completed' THEN 'completed'
                    WHEN a.check_in_time IS NOT NULL OR a.status = 'checked_in' THEN 'checked_in'
                    WHEN s.end_time < NOW() THEN 'absent'
                    ELSE 'scheduled'
                END AS status
            FROM shifts s
            INNER JOIN users u ON u.id = s.guard_id
            LEFT JOIN LATERAL (
                SELECT a1.id, a1.check_in_time, a1.check_out_time, a1.status
                FROM attendance a1
                WHERE a1.shift_id = s.id AND a1.guard_id = s.guard_id
                ORDER BY a1.check_in_time DESC
                LIMIT 1
            ) a ON TRUE
            LEFT JOIN LATERAL (
                SELECT p1.status, p1.minutes_late
                FROM punctuality_records p1
                WHERE p1.shift_id = s.id AND p1.guard_id = s.guard_id
                ORDER BY p1.created_at DESC
                LIMIT 1
            ) pr ON TRUE
            WHERE ($1::TEXT IS NULL OR s.guard_id = $1)
              AND ($2::DATE IS NULL OR s.start_time >= ($2::DATE)::TIMESTAMPTZ)
              AND ($3::DATE IS NULL OR s.start_time < (($3::DATE + INTERVAL '1 day')::TIMESTAMPTZ))
              AND ($4::TEXT IS NULL OR s.client_site ILIKE '%' || $4 || '%')
        )
        SELECT
            shift_id,
            attendance_id,
            guard_id,
            guard_name,
            client_site,
            scheduled_start,
            scheduled_end,
            actual_check_in,
            actual_check_out,
            late_minutes,
            total_hours,
            status,
            COUNT(*) OVER() AS total_count
        FROM dtr_base
        WHERE ($5::TEXT IS NULL OR status = $5)
        ORDER BY scheduled_start DESC, guard_name ASC
        LIMIT $6 OFFSET $7
        "#,
    )
    .bind(&guard_id)
    .bind(&from)
    .bind(&to)
    .bind(&site)
    .bind(&status)
    .bind(page_size)
    .bind(offset)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to generate DTR report: {}", e)))?;

    let total = rows.first().map(|row| row.total_count).unwrap_or(0);
    Ok(Json(serde_json::json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "filters": {
            "guardId": guard_id,
            "from": from,
            "to": to,
            "site": site,
            "status": status,
        },
        "items": rows,
    })))
}

#[cfg(test)]
mod tests {
    use super::{normalize_date, normalize_status};

    #[test]
    fn date_filters_are_normalized_and_validated() {
        assert_eq!(normalize_date(Some("2026-08-19".to_string()), "from").unwrap(), Some("2026-08-19".to_string()));
        assert!(normalize_date(Some("19-08-2026".to_string()), "from").is_err());
        assert_eq!(normalize_date(Some("  ".to_string()), "from").unwrap(), None);
    }

    #[test]
    fn status_filter_accepts_only_report_statuses() {
        assert_eq!(normalize_status(Some("COMPLETED".to_string())).unwrap(), Some("completed".to_string()));
        assert!(normalize_status(Some("late".to_string())).is_err());
    }
}
