use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use sqlx::{FromRow, PgPool, Row};
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    utils,
};

#[derive(Debug, Deserialize)]
pub struct GuardComplianceQuery {
    pub status: Option<String>,
    #[serde(rename = "windowDays")]
    pub window_days: Option<i64>,
    pub page: Option<i64>,
    #[serde(rename = "pageSize")]
    pub page_size: Option<i64>,
}

#[derive(Debug, Clone, FromRow, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardLicenseComplianceRow {
    pub guard_id: String,
    pub guard_number: Option<i32>,
    pub guard_name: String,
    pub license_number: Option<String>,
    pub license_issued_date: Option<DateTime<Utc>>,
    pub license_expiry_date: Option<DateTime<Utc>>,
    pub license_days_remaining: Option<i64>,
    pub compliance_status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardComplianceNotificationRequest {
    pub window_days: Option<i64>,
}

fn normalized_status(status: Option<String>) -> AppResult<Option<String>> {
    let Some(status) = status else {
        return Ok(None);
    };

    let normalized = status.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized == "all" {
        return Ok(None);
    }

    match normalized.as_str() {
        "compliant" | "expiring_soon" | "expired" | "no_license" => Ok(Some(normalized)),
        _ => Err(AppError::ValidationError(
            "Invalid guard license compliance status. Allowed values: compliant, expiring_soon, expired, no_license".to_string(),
        )),
    }
}

fn window_days(value: Option<i64>) -> AppResult<i64> {
    let days = value.unwrap_or(30);
    if !(1..=365).contains(&days) {
        return Err(AppError::ValidationError(
            "windowDays must be between 1 and 365".to_string(),
        ));
    }
    Ok(days)
}

const REPORT_CTE: &str = r#"
WITH report AS (
    SELECT
        u.id AS guard_id,
        u.guard_number,
        u.full_name AS guard_name,
        NULLIF(BTRIM(u.license_number), '') AS license_number,
        u.license_issued_date,
        u.license_expiry_date,
        CASE
            WHEN u.license_expiry_date IS NULL THEN NULL
            ELSE CEIL(EXTRACT(EPOCH FROM (u.license_expiry_date - NOW())) / 86400.0)::BIGINT
        END AS license_days_remaining,
        CASE
            WHEN NULLIF(BTRIM(u.license_number), '') IS NULL OR u.license_expiry_date IS NULL THEN 'no_license'
            WHEN u.license_expiry_date <= NOW() THEN 'expired'
            WHEN u.license_expiry_date <= NOW() + ($1::BIGINT * INTERVAL '1 day') THEN 'expiring_soon'
            ELSE 'compliant'
        END AS compliance_status
    FROM users u
    WHERE LOWER(u.role) = 'guard'
      AND u.verified = TRUE
      AND COALESCE(u.approval_status, 'approved') = 'approved'
)
"#;

pub async fn get_compliance_report(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Query(query): Query<GuardComplianceQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;
    let status = normalized_status(query.status)?;
    let days = window_days(query.window_days)?;
    let (page, page_size, offset) = utils::resolve_pagination(
        utils::PaginationQuery {
            page: query.page,
            page_size: query.page_size,
        },
        50,
        200,
    );

    let total: i64 = sqlx::query_scalar(&format!(
        "{REPORT_CTE} SELECT COUNT(*) FROM report WHERE ($2::TEXT IS NULL OR compliance_status = $2)"
    ))
    .bind(days)
    .bind(status.as_deref())
    .fetch_one(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to count guard license compliance report: {e}")))?;

    let rows = sqlx::query_as::<_, GuardLicenseComplianceRow>(&format!(
        "{REPORT_CTE} SELECT * FROM report WHERE ($2::TEXT IS NULL OR compliance_status = $2) ORDER BY CASE compliance_status WHEN 'expired' THEN 0 WHEN 'expiring_soon' THEN 1 WHEN 'no_license' THEN 2 ELSE 3 END, guard_name LIMIT $3 OFFSET $4"
    ))
    .bind(days)
    .bind(status.as_deref())
    .bind(page_size)
    .bind(offset)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch guard license compliance report: {e}")))?;

    let summary = sqlx::query(&format!(
        "{REPORT_CTE} SELECT COUNT(*)::BIGINT AS total_guards, COUNT(*) FILTER (WHERE compliance_status = 'expired')::BIGINT AS expired, COUNT(*) FILTER (WHERE compliance_status = 'expiring_soon')::BIGINT AS expiring_soon, COUNT(*) FILTER (WHERE compliance_status = 'no_license')::BIGINT AS no_license, COUNT(*) FILTER (WHERE compliance_status = 'compliant')::BIGINT AS compliant FROM report"
    ))
    .bind(days)
    .fetch_one(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to summarize guard license compliance: {e}")))?;

    Ok(Json(json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "filters": { "status": status, "windowDays": days },
        "summary": {
            "totalGuards": summary.get::<i64, _>("total_guards"),
            "expired": summary.get::<i64, _>("expired"),
            "expiringSoon": summary.get::<i64, _>("expiring_soon"),
            "noLicense": summary.get::<i64, _>("no_license"),
            "compliant": summary.get::<i64, _>("compliant"),
        },
        "items": rows,
    })))
}

pub async fn create_expiry_notifications(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<GuardComplianceNotificationRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;
    let days = window_days(payload.window_days)?;

    let candidates = sqlx::query(
        r#"
        SELECT u.full_name AS guard_name,
               NULLIF(BTRIM(u.license_number), '') AS license_number,
               u.license_expiry_date,
               CASE WHEN u.license_expiry_date <= NOW() THEN 'expired' ELSE 'expiring_soon' END AS issue
        FROM users u
        WHERE LOWER(u.role) = 'guard'
          AND u.verified = TRUE
          AND COALESCE(u.approval_status, 'approved') = 'approved'
          AND NULLIF(BTRIM(u.license_number), '') IS NOT NULL
          AND u.license_expiry_date IS NOT NULL
          AND u.license_expiry_date <= NOW() + ($1::BIGINT * INTERVAL '1 day')
        ORDER BY u.license_expiry_date ASC, u.full_name ASC
        "#,
    )
    .bind(days)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to find guard license expiry candidates: {e}")))?;

    let recipients = sqlx::query_scalar::<_, String>(
        "SELECT id FROM users WHERE role IN ('supervisor', 'admin', 'superadmin') AND approval_status = 'approved'",
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to find compliance notification recipients: {e}")))?;

    let mut created = 0_i64;
    for candidate in candidates {
        let guard_name = candidate.get::<String, _>("guard_name");
        let license_number = candidate.get::<String, _>("license_number");
        let issue = candidate.get::<String, _>("issue");
        let expiry = candidate.get::<DateTime<Utc>, _>("license_expiry_date");
        let title = if issue == "expired" {
            format!("Guard license expired: {guard_name} ({license_number})")
        } else {
            format!("Guard license expiring: {guard_name} ({license_number})")
        };
        let message = format!(
            "{guard_name}'s license ({license_number}) requires compliance attention. Expiry date: {}.",
            expiry.format("%Y-%m-%d")
        );

        for recipient_id in &recipients {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM notifications WHERE user_id = $1 AND type = 'guard_compliance' AND title = $2 AND created_at >= NOW() - INTERVAL '24 hours')",
            )
            .bind(recipient_id)
            .bind(&title)
            .fetch_one(db.as_ref())
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to check duplicate guard compliance notification: {e}")))?;

            if exists {
                continue;
            }

            sqlx::query(
                "INSERT INTO notifications (id, user_id, title, message, type, related_shift_id, read) VALUES ($1, $2, $3, $4, 'guard_compliance', NULL, false)",
            )
            .bind(utils::generate_id())
            .bind(recipient_id)
            .bind(&title)
            .bind(&message)
            .execute(db.as_ref())
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to create guard compliance notification: {e}")))?;
            created += 1;
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Guard license compliance notifications synchronized",
            "created": created,
            "windowDays": days,
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::{normalized_status, window_days};

    #[test]
    fn compliance_status_filter_is_strict() {
        assert_eq!(
            normalized_status(Some("expired".into())).unwrap(),
            Some("expired".into())
        );
        assert_eq!(normalized_status(Some("all".into())).unwrap(), None);
        assert!(normalized_status(Some("unknown".into())).is_err());
    }

    #[test]
    fn notification_window_is_bounded() {
        assert_eq!(window_days(None).unwrap(), 30);
        assert_eq!(window_days(Some(365)).unwrap(), 365);
        assert!(window_days(Some(0)).is_err());
        assert!(window_days(Some(366)).is_err());
    }
}
