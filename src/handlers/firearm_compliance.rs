use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{FromRow, PgPool};
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    utils,
};

#[derive(Debug, Deserialize)]
pub struct ComplianceQuery {
    pub status: Option<String>,
    #[serde(rename = "windowDays")]
    pub window_days: Option<i64>,
    pub page: Option<i64>,
    #[serde(rename = "pageSize")]
    pub page_size: Option<i64>,
}

#[derive(Debug, Clone, Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct FirearmComplianceRow {
    pub firearm_id: String,
    pub serial_number: String,
    pub model: String,
    pub caliber: String,
    pub firearm_status: String,
    pub holder_id: Option<String>,
    pub holder_name: Option<String>,
    pub allocation_id: Option<String>,
    pub allocation_date: Option<DateTime<Utc>>,
    pub expected_return_date: Option<DateTime<Utc>>,
    pub permit_id: Option<String>,
    pub permit_type: Option<String>,
    pub permit_expiry_date: Option<DateTime<Utc>>,
    pub permit_status: Option<String>,
    pub permit_days_remaining: Option<i64>,
    pub maintenance_id: Option<String>,
    pub maintenance_type: Option<String>,
    pub maintenance_date: Option<DateTime<Utc>>,
    pub maintenance_status: Option<String>,
    pub compliance_status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceNotificationRequest {
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
        "compliant" | "expiring_soon" | "expired" | "no_permit" | "maintenance"
        | "allocated" | "unallocated" => Ok(Some(normalized)),
        _ => Err(AppError::ValidationError(
            "Invalid firearm compliance status. Allowed values: compliant, expiring_soon, expired, no_permit, maintenance, allocated, unallocated".to_string(),
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
        f.id AS firearm_id,
        f.serial_number,
        f.model,
        f.caliber,
        f.status AS firearm_status,
        fa.guard_id AS holder_id,
        u.full_name AS holder_name,
        fa.id AS allocation_id,
        fa.allocation_date,
        fa.expected_return_date,
        p.id AS permit_id,
        p.permit_type,
        p.expiry_date AS permit_expiry_date,
        p.status AS permit_status,
        CASE
            WHEN p.expiry_date IS NULL THEN NULL
            ELSE CEIL(EXTRACT(EPOCH FROM (p.expiry_date - NOW())) / 86400.0)::BIGINT
        END AS permit_days_remaining,
        fm.id AS maintenance_id,
        fm.maintenance_type,
        fm.scheduled_date AS maintenance_date,
        fm.status AS maintenance_status,
        CASE
            WHEN f.status = 'maintenance' OR fm.status IN ('pending', 'in_progress') THEN 'maintenance'
            WHEN p.id IS NULL AND fa.id IS NOT NULL THEN 'no_permit'
            WHEN p.status IN ('expired', 'revoked') OR p.expiry_date <= NOW() THEN 'expired'
            WHEN p.expiry_date <= NOW() + ($1::BIGINT * INTERVAL '1 day') THEN 'expiring_soon'
            WHEN fa.id IS NOT NULL THEN 'allocated'
            ELSE 'compliant'
        END AS compliance_status
    FROM firearms f
    LEFT JOIN LATERAL (
        SELECT id, guard_id, allocation_date, expected_return_date
        FROM firearm_allocations
        WHERE firearm_id = f.id AND status = 'active'
        ORDER BY allocation_date DESC
        LIMIT 1
    ) fa ON TRUE
    LEFT JOIN users u ON u.id = fa.guard_id
    LEFT JOIN LATERAL (
        SELECT id, permit_type, expiry_date, status
        FROM guard_firearm_permits
        WHERE (firearm_id = f.id OR (firearm_id IS NULL AND guard_id = fa.guard_id))
        ORDER BY expiry_date DESC, updated_at DESC
        LIMIT 1
    ) p ON TRUE
    LEFT JOIN LATERAL (
        SELECT id, maintenance_type, scheduled_date, status
        FROM firearm_maintenance
        WHERE firearm_id = f.id AND status <> 'completed'
        ORDER BY scheduled_date DESC, updated_at DESC
        LIMIT 1
    ) fm ON TRUE
)
"#;

pub async fn get_compliance_report(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Query(query): Query<ComplianceQuery>,
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
    let filter = status.as_deref();

    let total: i64 = sqlx::query_scalar(&format!(
        "{REPORT_CTE} SELECT COUNT(*) FROM report WHERE ($2::TEXT IS NULL OR compliance_status = $2 OR ($2 = 'allocated' AND allocation_id IS NOT NULL) OR ($2 = 'unallocated' AND allocation_id IS NULL))"
    ))
    .bind(days)
    .bind(filter)
    .fetch_one(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to count firearm compliance report: {e}")))?;

    let rows = sqlx::query_as::<_, FirearmComplianceRow>(&format!(
        "{REPORT_CTE} SELECT * FROM report WHERE ($2::TEXT IS NULL OR compliance_status = $2 OR ($2 = 'allocated' AND allocation_id IS NOT NULL) OR ($2 = 'unallocated' AND allocation_id IS NULL)) ORDER BY CASE compliance_status WHEN 'expired' THEN 0 WHEN 'no_permit' THEN 1 WHEN 'maintenance' THEN 2 WHEN 'expiring_soon' THEN 3 ELSE 4 END, serial_number LIMIT $3 OFFSET $4"
    ))
    .bind(days)
    .bind(filter)
    .bind(page_size)
    .bind(offset)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch firearm compliance report: {e}")))?;

    let summary = sqlx::query(&format!(
        "{REPORT_CTE} SELECT COUNT(*)::BIGINT AS total_firearms, COUNT(*) FILTER (WHERE allocation_id IS NOT NULL)::BIGINT AS allocated, COUNT(*) FILTER (WHERE allocation_id IS NULL)::BIGINT AS unallocated, COUNT(*) FILTER (WHERE compliance_status = 'expiring_soon')::BIGINT AS expiring_soon, COUNT(*) FILTER (WHERE compliance_status = 'expired')::BIGINT AS expired, COUNT(*) FILTER (WHERE compliance_status = 'maintenance')::BIGINT AS maintenance, COUNT(*) FILTER (WHERE compliance_status = 'no_permit')::BIGINT AS no_permit FROM report"
    ))
    .bind(days)
    .fetch_one(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to summarize firearm compliance: {e}")))?;

    use sqlx::Row;
    Ok(Json(json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "filters": { "status": filter, "windowDays": days },
        "summary": {
            "totalFirearms": summary.get::<i64, _>("total_firearms"),
            "allocated": summary.get::<i64, _>("allocated"),
            "unallocated": summary.get::<i64, _>("unallocated"),
            "expiringSoon": summary.get::<i64, _>("expiring_soon"),
            "expired": summary.get::<i64, _>("expired"),
            "maintenance": summary.get::<i64, _>("maintenance"),
            "noPermit": summary.get::<i64, _>("no_permit"),
        },
        "items": rows,
    })))
}

pub async fn create_expiry_notifications(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<ComplianceNotificationRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;
    let days = window_days(payload.window_days)?;

    let candidates = sqlx::query(
        r#"
        SELECT f.id AS firearm_id, f.serial_number, f.model,
               p.expiry_date,
               CASE WHEN p.expiry_date <= NOW() THEN 'expired' ELSE 'expiring_soon' END AS issue
        FROM firearms f
        JOIN guard_firearm_permits p ON p.firearm_id = f.id
        WHERE p.status IN ('active', 'expired')
          AND p.expiry_date <= NOW() + ($1::BIGINT * INTERVAL '1 day')
        ORDER BY p.expiry_date ASC
        "#,
    )
    .bind(days)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to find firearm expiry candidates: {e}"))
    })?;

    let recipients = sqlx::query_scalar::<_, String>(
        "SELECT id FROM users WHERE role IN ('supervisor', 'admin', 'superadmin') AND approval_status = 'approved'",
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to find compliance notification recipients: {e}")))?;

    use sqlx::Row;
    let mut created = 0_i64;
    for candidate in candidates {
        let serial = candidate.get::<String, _>("serial_number");
        let model = candidate.get::<String, _>("model");
        let issue = candidate.get::<String, _>("issue");
        let expiry = candidate.get::<DateTime<Utc>, _>("expiry_date");
        let title = if issue == "expired" {
            format!("Firearm permit expired: {serial}")
        } else {
            format!("Firearm permit expiring: {serial}")
        };
        let message = format!(
            "{model} ({serial}) requires compliance attention. Permit date: {}.",
            expiry.format("%Y-%m-%d")
        );

        for recipient_id in &recipients {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM notifications WHERE user_id = $1 AND type = 'firearm_compliance' AND title = $2 AND created_at >= NOW() - INTERVAL '24 hours')",
            )
            .bind(recipient_id)
            .bind(&title)
            .fetch_one(db.as_ref())
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to check duplicate compliance notification: {e}")))?;

            if exists {
                continue;
            }

            sqlx::query(
                "INSERT INTO notifications (id, user_id, title, message, type, related_shift_id, read) VALUES ($1, $2, $3, $4, 'firearm_compliance', NULL, false)",
            )
            .bind(utils::generate_id())
            .bind(recipient_id)
            .bind(&title)
            .bind(&message)
            .execute(db.as_ref())
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to create compliance notification: {e}")))?;
            created += 1;
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Firearm compliance notifications synchronized",
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
