use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use sqlx::{postgres::Postgres, PgPool, QueryBuilder, Row};
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    models::{AuditLogEntry, AuditLogListResponse},
    utils,
};

#[derive(Debug, Deserialize, Default)]
pub struct AuditLogQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub result: Option<String>,
    pub status: Option<String>,
    pub entity_type: Option<String>,
    pub resource_type: Option<String>,
    pub actor_id: Option<String>,
    pub action_type: Option<String>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub search: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct UserActivityQuery {
    pub window_hours: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AuditAnomalyQuery {
    pub window_hours: Option<i64>,
}

struct AuditFilterWindow {
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
}

fn parse_optional_rfc3339(
    value: Option<&str>,
    field_name: &str,
) -> AppResult<Option<DateTime<Utc>>> {
    let Some(raw) = value else {
        return Ok(None);
    };

    if raw.trim().is_empty() {
        return Ok(None);
    }

    DateTime::parse_from_rfc3339(raw.trim())
        .map(|value| value.with_timezone(&Utc))
        .map(Some)
        .map_err(|_| {
            AppError::BadRequest(format!(
                "Invalid {} value. Expected RFC3339 timestamp.",
                field_name
            ))
        })
}

pub async fn get_audit_logs(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Query(params): Query<AuditLogQuery>,
) -> AppResult<Json<AuditLogListResponse>> {
    utils::require_min_role(&headers, "superadmin")?;

    let page = params.page.unwrap_or(1).max(1);
    let page_size = params.page_size.unwrap_or(25).clamp(1, 100);
    let offset = (page - 1) * page_size;
    let filter_window = AuditFilterWindow {
        from: parse_optional_rfc3339(params.from.as_deref(), "from")?,
        to: parse_optional_rfc3339(params.to.as_deref(), "to")?,
    };

    let mut list_query = QueryBuilder::<Postgres>::new(
        "SELECT 
            al.id,
            al.actor_user_id,
            al.action_key,
            al.entity_type,
            al.entity_id,
            al.result,
            al.reason,
            al.source_ip,
            al.user_agent,
            al.metadata,
            al.created_at,
            u.full_name AS actor_name,
            u.email AS actor_email,
            u.role AS actor_role
        FROM audit_logs al
        LEFT JOIN users u ON u.id = al.actor_user_id",
    );
    apply_filters(&mut list_query, &params, &filter_window);
    list_query.push(" ORDER BY al.created_at DESC ");
    list_query.push(" LIMIT ");
    list_query.push_bind(page_size);
    list_query.push(" OFFSET ");
    list_query.push_bind(offset);

    let items = list_query
        .build_query_as::<AuditLogEntry>()
        .fetch_all(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to load audit logs: {}", e)))?;

    let mut count_query = QueryBuilder::<Postgres>::new(
        "SELECT COUNT(*) FROM audit_logs al LEFT JOIN users u ON u.id = al.actor_user_id",
    );
    apply_filters(&mut count_query, &params, &filter_window);
    let total: i64 = count_query
        .build_query_scalar()
        .fetch_one(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to count audit logs: {}", e)))?;

    let meta = crate::models::AuditLogPageMeta {
        total,
        page,
        page_size,
        has_more: offset + (items.len() as i64) < total,
    };

    Ok(Json(AuditLogListResponse { items, meta }))
}

pub async fn get_audit_logs_filtered(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Query(params): Query<AuditLogQuery>,
) -> AppResult<Json<AuditLogListResponse>> {
    get_audit_logs(State(db), headers, Query(params)).await
}

pub async fn get_user_activity(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Query(params): Query<UserActivityQuery>,
) -> AppResult<Json<serde_json::Value>> {
    utils::require_min_role(&headers, "superadmin")?;

    let window_hours = params.window_hours.unwrap_or(72).clamp(1, 720);
    let limit = params.limit.unwrap_or(300).clamp(20, 1500);

    let events = sqlx::query(
        r#"SELECT
               al.id,
               al.action_key,
               al.entity_type,
               al.entity_id,
               al.result,
               al.reason,
               al.source_ip,
               al.user_agent,
               al.metadata,
               al.created_at
           FROM audit_logs al
           WHERE al.actor_user_id = $1
             AND al.created_at >= (CURRENT_TIMESTAMP - ($2 || ' hours')::interval)
           ORDER BY al.created_at ASC
           LIMIT $3"#,
    )
    .bind(&user_id)
    .bind(window_hours.to_string())
    .bind(limit)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch user activity: {}", e)))?;

    let timeline: Vec<serde_json::Value> = events
        .into_iter()
        .map(|row| {
            json!({
                "id": row.try_get::<String, _>("id").unwrap_or_default(),
                "actionType": row.try_get::<String, _>("action_key").unwrap_or_default(),
                "resourceType": row.try_get::<String, _>("entity_type").unwrap_or_default(),
                "resourceId": row.try_get::<Option<String>, _>("entity_id").unwrap_or(None),
                "status": row.try_get::<String, _>("result").unwrap_or_default(),
                "reason": row.try_get::<Option<String>, _>("reason").unwrap_or(None),
                "ipAddress": row.try_get::<Option<String>, _>("source_ip").unwrap_or(None),
                "userAgent": row.try_get::<Option<String>, _>("user_agent").unwrap_or(None),
                "metadata": row.try_get::<Option<serde_json::Value>, _>("metadata").unwrap_or(None),
                "timestamp": row
                    .try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
            })
        })
        .collect();

    let heatmap_rows = sqlx::query(
        r#"SELECT
               EXTRACT(HOUR FROM al.created_at) AS hour_bucket,
               COUNT(*) AS event_count
           FROM audit_logs al
           WHERE al.actor_user_id = $1
             AND al.created_at >= (CURRENT_TIMESTAMP - ($2 || ' hours')::interval)
           GROUP BY hour_bucket
           ORDER BY hour_bucket"#,
    )
    .bind(&user_id)
    .bind(window_hours.to_string())
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to build user activity heatmap: {}", e))
    })?;

    let heatmap: Vec<serde_json::Value> = heatmap_rows
        .into_iter()
        .map(|row| {
            let hour_bucket = row.try_get::<f64, _>("hour_bucket").unwrap_or(0.0).round() as i32;
            let event_count = row.try_get::<i64, _>("event_count").unwrap_or(0);
            json!({
                "hour": hour_bucket,
                "count": event_count,
            })
        })
        .collect();

    Ok(Json(json!({
        "userId": user_id,
        "windowHours": window_hours,
        "eventCount": timeline.len(),
        "timeline": timeline,
        "heatmap": heatmap,
    })))
}

pub async fn get_audit_anomalies(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Query(params): Query<AuditAnomalyQuery>,
) -> AppResult<Json<serde_json::Value>> {
    utils::require_min_role(&headers, "superadmin")?;

    let window_hours = params.window_hours.unwrap_or(24).clamp(1, 168);

    let failed_bursts = sqlx::query(
        r#"SELECT
               al.actor_user_id,
               COALESCE(NULLIF(u.full_name, ''), u.email, 'Unknown actor') AS actor_name,
               COUNT(*) AS failed_count,
               MIN(al.created_at) AS first_seen,
               MAX(al.created_at) AS last_seen
           FROM audit_logs al
           LEFT JOIN users u ON u.id = al.actor_user_id
           WHERE al.result = 'failed'
             AND al.created_at >= (CURRENT_TIMESTAMP - ($1 || ' hours')::interval)
           GROUP BY al.actor_user_id, actor_name
           HAVING COUNT(*) >= 4
           ORDER BY failed_count DESC
           LIMIT 25"#,
    )
    .bind(window_hours.to_string())
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to detect failed burst anomalies: {}", e))
    })?;

    let failed_burst_payload: Vec<serde_json::Value> = failed_bursts
        .into_iter()
        .map(|row| {
            json!({
                "type": "failed_burst",
                "actorUserId": row.try_get::<Option<String>, _>("actor_user_id").unwrap_or(None),
                "actorName": row.try_get::<String, _>("actor_name").unwrap_or_default(),
                "failedCount": row.try_get::<i64, _>("failed_count").unwrap_or(0),
                "firstSeen": row
                    .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("first_seen")
                    .unwrap_or(None)
                    .map(|d| d.to_rfc3339()),
                "lastSeen": row
                    .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_seen")
                    .unwrap_or(None)
                    .map(|d| d.to_rfc3339()),
                "severity": "high",
            })
        })
        .collect();

    let activity_spikes = sqlx::query(
        r#"WITH hourly AS (
               SELECT date_trunc('hour', created_at) AS bucket, COUNT(*) AS event_total
               FROM audit_logs
               WHERE created_at >= (CURRENT_TIMESTAMP - ($1 || ' hours')::interval)
               GROUP BY bucket
           ), stats AS (
               SELECT COALESCE(AVG(event_total), 0) AS avg_total,
                      COALESCE(STDDEV_POP(event_total), 0) AS std_total
               FROM hourly
           )
           SELECT
               hourly.bucket,
               hourly.event_total,
               stats.avg_total,
               stats.std_total
           FROM hourly
           CROSS JOIN stats
           WHERE hourly.event_total > (stats.avg_total + GREATEST(stats.std_total * 2, 10))
           ORDER BY hourly.event_total DESC
           LIMIT 24"#,
    )
    .bind(window_hours.to_string())
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to detect volume spike anomalies: {}", e))
    })?;

    let spike_payload: Vec<serde_json::Value> = activity_spikes
        .into_iter()
        .map(|row| {
            json!({
                "type": "activity_spike",
                "bucket": row
                    .try_get::<chrono::DateTime<chrono::Utc>, _>("bucket")
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
                "eventTotal": row.try_get::<i64, _>("event_total").unwrap_or(0),
                "baselineAverage": row.try_get::<f64, _>("avg_total").unwrap_or(0.0),
                "baselineStd": row.try_get::<f64, _>("std_total").unwrap_or(0.0),
                "severity": "medium",
            })
        })
        .collect();

    let suspicious_ips = sqlx::query(
        r#"SELECT
               source_ip,
               COUNT(*) AS event_total,
               COUNT(*) FILTER (WHERE result = 'failed') AS failed_total
           FROM audit_logs
           WHERE source_ip IS NOT NULL
             AND created_at >= (CURRENT_TIMESTAMP - ($1 || ' hours')::interval)
           GROUP BY source_ip
           HAVING COUNT(*) >= 12
              AND COUNT(*) FILTER (WHERE result = 'failed') >= 4
           ORDER BY failed_total DESC, event_total DESC
           LIMIT 20"#,
    )
    .bind(window_hours.to_string())
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to detect suspicious IP anomalies: {}", e))
    })?;

    let ip_payload: Vec<serde_json::Value> = suspicious_ips
        .into_iter()
        .map(|row| {
            json!({
                "type": "suspicious_ip",
                "sourceIp": row.try_get::<Option<String>, _>("source_ip").unwrap_or(None),
                "eventTotal": row.try_get::<i64, _>("event_total").unwrap_or(0),
                "failedTotal": row.try_get::<i64, _>("failed_total").unwrap_or(0),
                "severity": "medium",
            })
        })
        .collect();

    let mut anomalies = Vec::new();
    anomalies.extend(failed_burst_payload.clone());
    anomalies.extend(spike_payload.clone());
    anomalies.extend(ip_payload.clone());

    Ok(Json(json!({
        "windowHours": window_hours,
        "total": anomalies.len(),
        "anomalies": anomalies,
        "groups": {
            "failedBursts": failed_burst_payload,
            "activitySpikes": spike_payload,
            "suspiciousIps": ip_payload,
        }
    })))
}

fn apply_filters(
    builder: &mut QueryBuilder<'_, Postgres>,
    params: &AuditLogQuery,
    window: &AuditFilterWindow,
) {
    let mut has_where = false;

    if let Some(from) = window.from {
        append_condition_prefix(builder, &mut has_where);
        builder.push("al.created_at >= ");
        builder.push_bind(from);
    }

    if let Some(to) = window.to {
        append_condition_prefix(builder, &mut has_where);
        builder.push("al.created_at <= ");
        builder.push_bind(to);
    }

    let status_filter = params.status.as_deref().or(params.result.as_deref());

    if let Some(result) = status_filter.filter(|value| !value.trim().is_empty()) {
        append_condition_prefix(builder, &mut has_where);
        builder.push("al.result = ");
        builder.push_bind(result.to_string());
    }

    if let Some(action_type) = params
        .action_type
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        append_condition_prefix(builder, &mut has_where);
        builder.push("al.action_key ILIKE ");
        builder.push_bind(format!("%{}%", action_type.trim()));
    }

    let resource_type_filter = params
        .resource_type
        .as_ref()
        .or(params.entity_type.as_ref());

    if let Some(entity_type) = resource_type_filter
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        append_condition_prefix(builder, &mut has_where);
        let normalized = entity_type.trim().to_lowercase();
        match normalized.as_str() {
            // Historical writes can be stored as either singular or plural
            // because both /api/user/:id and /api/users/:id route aliases exist.
            "users" => {
                builder.push("al.entity_type IN (");
                builder.push_bind("users".to_string());
                builder.push(", ");
                builder.push_bind("user".to_string());
                builder.push(")");
            }
            "user" => {
                builder.push("al.entity_type IN (");
                builder.push_bind("users".to_string());
                builder.push(", ");
                builder.push_bind("user".to_string());
                builder.push(")");
            }
            _ => {
                builder.push("al.entity_type = ");
                builder.push_bind(normalized);
            }
        }
    }

    if let Some(actor_id) = params
        .actor_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        append_condition_prefix(builder, &mut has_where);
        builder.push("al.actor_user_id = ");
        builder.push_bind(actor_id.to_string());
    }

    if let Some(source_ip) = params
        .source_ip
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        append_condition_prefix(builder, &mut has_where);
        builder.push("COALESCE(al.source_ip, '') ILIKE ");
        builder.push_bind(format!("%{}%", source_ip));
    }

    if let Some(user_agent) = params
        .user_agent
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        append_condition_prefix(builder, &mut has_where);
        builder.push("COALESCE(al.user_agent, '') ILIKE ");
        builder.push_bind(format!("%{}%", user_agent));
    }

    if let Some(search) = params
        .search
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let like_value = format!("%{}%", search);
        append_condition_prefix(builder, &mut has_where);
        builder.push("(");
        builder.push("al.action_key ILIKE ");
        builder.push_bind(like_value.clone());
        builder.push(" OR COALESCE(al.reason, '') ILIKE ");
        builder.push_bind(like_value.clone());
        builder.push(" OR COALESCE(al.source_ip, '') ILIKE ");
        builder.push_bind(like_value.clone());
        builder.push(" OR COALESCE(al.user_agent, '') ILIKE ");
        builder.push_bind(like_value.clone());
        builder.push(" OR COALESCE(al.entity_id, '') ILIKE ");
        builder.push_bind(like_value.clone());
        builder.push(" OR COALESCE(al.entity_type, '') ILIKE ");
        builder.push_bind(like_value.clone());
        builder.push(" OR COALESCE(u.full_name, '') ILIKE ");
        builder.push_bind(like_value.clone());
        builder.push(" OR COALESCE(u.email, '') ILIKE ");
        builder.push_bind(like_value);
        builder.push(")");
    }
}

fn append_condition_prefix(builder: &mut QueryBuilder<'_, Postgres>, has_where: &mut bool) {
    if *has_where {
        builder.push(" AND ");
    } else {
        builder.push(" WHERE ");
        *has_where = true;
    }
}
