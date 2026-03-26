use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};
use serde::Deserialize;
use sqlx::{postgres::Postgres, PgPool, QueryBuilder};
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
    pub entity_type: Option<String>,
    pub actor_id: Option<String>,
    pub source_ip: Option<String>,
    pub search: Option<String>,
}

pub async fn get_audit_logs(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Query(params): Query<AuditLogQuery>,
) -> AppResult<Json<AuditLogListResponse>> {
    // Only admins and superadmins should see audit logs
    utils::require_min_role(&headers, "admin")?;

    let page = params.page.unwrap_or(1).max(1);
    let page_size = params.page_size.unwrap_or(25).clamp(1, 100);
    let offset = (page - 1) * page_size;

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
            al.metadata,
            al.created_at,
            u.full_name AS actor_name,
            u.email AS actor_email,
            u.role AS actor_role
        FROM audit_logs al
        LEFT JOIN users u ON u.id = al.actor_user_id",
    );
    apply_filters(&mut list_query, &params);
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
    apply_filters(&mut count_query, &params);
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

fn apply_filters(builder: &mut QueryBuilder<'_, Postgres>, params: &AuditLogQuery) {
    let mut has_where = false;

    if let Some(result) = params
        .result
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        append_condition_prefix(builder, &mut has_where);
        builder.push("al.result = ");
        builder.push_bind(result.to_string());
    }

    if let Some(entity_type) = params
        .entity_type
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
