use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    models::{MdrImportBatch, MdrStagingRow},
    services::mdr_import_service,
    utils,
};

async fn insert_mdr_audit_event(
    pool: &PgPool,
    actor_user_id: Option<&str>,
    action_key: &str,
    entity_type: &str,
    entity_id: &str,
    result: &str,
    reason: Option<&str>,
    metadata: serde_json::Value,
) {
    let _ = sqlx::query(
        "INSERT INTO audit_logs (id, actor_user_id, action_key, entity_type, entity_id, result, reason, metadata) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(utils::generate_id())
    .bind(actor_user_id)
    .bind(action_key)
    .bind(entity_type)
    .bind(entity_id)
    .bind(result)
    .bind(reason)
    .bind(metadata)
    .execute(pool)
    .await;
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MdrImportRequest {
    pub filename: String,
    pub report_month: String,
    pub branch: Option<String>,
    pub sheets: MdrSheets,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MdrSheets {
    pub main_roster: Vec<MdrRowInput>,
    pub supplementary: Vec<MdrRowInput>,
    pub pull_out: Vec<MdrRowInput>,
    pub returned_firearms: Vec<MdrRowInput>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MdrRowInput {
    pub sheet_name: String,
    pub row_number: i32,
    pub section: Option<String>,
    pub client_number: Option<i32>,
    pub client_name: Option<String>,
    pub client_address: Option<String>,
    pub guard_number: Option<i32>,
    pub guard_name: Option<String>,
    pub contact_number: Option<String>,
    pub license_number: Option<String>,
    pub license_expiry: Option<String>,
    pub firearm_kind: Option<String>,
    pub firearm_make: Option<String>,
    pub caliber: Option<String>,
    pub serial_number: Option<String>,
    pub firearm_validity: Option<String>,
    pub actual_ammo: Option<String>,
    pub ammo_count: Option<String>,
    pub lic_reg_name: Option<String>,
    pub pullout_status: Option<String>,
    pub fa_remarks: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveRequest {
    pub match_status: String,
    pub matched_guard_id: Option<String>,
    pub matched_firearm_id: Option<String>,
    pub matched_client_id: Option<String>,
}

/// POST /api/mdr/import
pub async fn import_mdr(
    State(pool): State<Arc<PgPool>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<MdrImportRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let claims = utils::extract_bearer_token(&headers).and_then(|token| utils::verify_token(&token))?;

    let batch_id = utils::generate_id();

    let all_rows: Vec<&MdrRowInput> = body
        .sheets
        .main_roster
        .iter()
        .chain(body.sheets.supplementary.iter())
        .chain(body.sheets.pull_out.iter())
        .chain(body.sheets.returned_firearms.iter())
        .collect();

    sqlx::query(
        "INSERT INTO mdr_import_batches (id, filename, report_month, branch, uploaded_by, status, total_rows) VALUES ($1, $2, $3, $4, $5, 'staging', $6)",
    )
    .bind(&batch_id)
    .bind(&body.filename)
    .bind(&body.report_month)
    .bind(&body.branch)
    .bind(&claims.sub)
    .bind(all_rows.len() as i32)
    .execute(pool.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create batch: {}", e)))?;

    for row in &all_rows {
        let row_id = utils::generate_id();
        sqlx::query(
            r#"INSERT INTO mdr_staging_rows (
                id, batch_id, sheet_name, row_number, section,
                client_number, client_name, client_address,
                guard_number, guard_name, contact_number,
                license_number, license_expiry,
                firearm_kind, firearm_make, caliber, serial_number, firearm_validity,
                actual_ammo, ammo_count, lic_reg_name,
                pullout_status, fa_remarks, match_status
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8,
                $9, $10, $11,
                $12, $13,
                $14, $15, $16, $17, $18,
                $19, $20, $21,
                $22, $23, 'pending'
            )"#,
        )
        .bind(&row_id)
        .bind(&batch_id)
        .bind(&row.sheet_name)
        .bind(row.row_number)
        .bind(&row.section)
        .bind(row.client_number)
        .bind(&row.client_name)
        .bind(&row.client_address)
        .bind(row.guard_number)
        .bind(&row.guard_name)
        .bind(&row.contact_number)
        .bind(&row.license_number)
        .bind(&row.license_expiry)
        .bind(&row.firearm_kind)
        .bind(&row.firearm_make)
        .bind(&row.caliber)
        .bind(&row.serial_number)
        .bind(&row.firearm_validity)
        .bind(&row.actual_ammo)
        .bind(&row.ammo_count)
        .bind(&row.lic_reg_name)
        .bind(&row.pullout_status)
        .bind(&row.fa_remarks)
        .execute(pool.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to insert staging row: {}", e)))?;
    }

    let summary = mdr_import_service::match_staging_rows(pool.as_ref(), &batch_id).await?;

    insert_mdr_audit_event(
        pool.as_ref(),
        Some(&claims.sub),
        "mdr.batch.import",
        "mdr_import_batch",
        &batch_id,
        "success",
        None,
        json!({
            "filename": body.filename,
            "reportMonth": body.report_month,
            "branch": body.branch,
            "totalRows": summary.total,
            "matched": summary.matched,
            "new": summary.new_rows,
            "ambiguous": summary.ambiguous,
            "errors": summary.errors,
        }),
    )
    .await;

    Ok(Json(json!({
        "batchId": batch_id,
        "totalRows": summary.total,
        "preview": {
            "matched": summary.matched,
            "new": summary.new_rows,
            "ambiguous": summary.ambiguous,
            "errors": summary.errors,
            "pending": 0,
        }
    })))
}

/// GET /api/mdr/batches
pub async fn get_batches(
    State(pool): State<Arc<PgPool>>,
    Query(pagination): Query<utils::PaginationQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let (page, page_size, offset) = utils::resolve_pagination(pagination, 20, 100);

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mdr_import_batches")
        .fetch_one(pool.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let items = sqlx::query_as::<_, MdrImportBatch>(
        r#"
        SELECT
            mib.*,
            (
                SELECT COUNT(*)::INT
                FROM mdr_staging_rows msr
                WHERE msr.batch_id = mib.id
                  AND msr.match_status = 'pending'
            ) AS pending_rows
        FROM mdr_import_batches mib
        ORDER BY mib.created_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(page_size)
    .bind(offset)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "items": items
    })))
}

/// GET /api/mdr/batches/:id
pub async fn get_batch_by_id(
    State(pool): State<Arc<PgPool>>,
    Path(id): Path<String>,
) -> AppResult<Json<MdrImportBatch>> {
    let batch = sqlx::query_as::<_, MdrImportBatch>(
        r#"
        SELECT
            mib.*,
            (
                SELECT COUNT(*)::INT
                FROM mdr_staging_rows msr
                WHERE msr.batch_id = mib.id
                  AND msr.match_status = 'pending'
            ) AS pending_rows
        FROM mdr_import_batches mib
        WHERE mib.id = $1
        "#,
    )
        .bind(&id)
        .fetch_optional(pool.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Batch not found".to_string()))?;

    Ok(Json(batch))
}

/// GET /api/mdr/batches/:id/review
pub async fn get_batch_review(
    State(pool): State<Arc<PgPool>>,
    Path(id): Path<String>,
    Query(pagination): Query<utils::PaginationQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let (page, page_size, offset) = utils::resolve_pagination(pagination, 50, 200);

    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mdr_staging_rows WHERE batch_id = $1")
            .bind(&id)
            .fetch_one(pool.as_ref())
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let items = sqlx::query_as::<_, MdrStagingRow>(
        "SELECT * FROM mdr_staging_rows WHERE batch_id = $1 ORDER BY row_number LIMIT $2 OFFSET $3",
    )
    .bind(&id)
    .bind(page_size)
    .bind(offset)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "items": items
    })))
}

/// PATCH /api/mdr/staging/:id/resolve
pub async fn resolve_staging_row(
    State(pool): State<Arc<PgPool>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ResolveRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if !matches!(body.match_status.as_str(), "matched" | "new") {
        return Err(AppError::BadRequest(
            "match_status must be 'matched' or 'new'".to_string(),
        ));
    }

    let updated_batch_id = sqlx::query_scalar::<_, String>(
        "UPDATE mdr_staging_rows SET match_status = $1, matched_guard_id = $2, matched_firearm_id = $3, matched_client_id = $4 WHERE id = $5 RETURNING batch_id",
    )
    .bind(&body.match_status)
    .bind(&body.matched_guard_id)
    .bind(&body.matched_firearm_id)
    .bind(&body.matched_client_id)
    .bind(&id)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let Some(batch_id) = updated_batch_id else {
        return Err(AppError::NotFound("Staging row not found".to_string()));
    };

    mdr_import_service::refresh_batch_statistics(pool.as_ref(), &batch_id).await?;

    let actor_claims = utils::extract_bearer_token(&headers)
        .ok()
        .and_then(|token| utils::verify_token(&token).ok());

    insert_mdr_audit_event(
        pool.as_ref(),
        actor_claims.as_ref().map(|claims| claims.sub.as_str()),
        "mdr.row.resolve",
        "mdr_staging_row",
        &id,
        "success",
        None,
        json!({
            "batchId": batch_id,
            "matchStatus": body.match_status,
            "matchedGuardId": body.matched_guard_id,
            "matchedFirearmId": body.matched_firearm_id,
            "matchedClientId": body.matched_client_id,
        }),
    )
    .await;

    Ok(Json(json!({ "status": "resolved" })))
}

/// POST /api/mdr/batches/:id/commit
pub async fn commit_batch(
    State(pool): State<Arc<PgPool>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let claims = utils::require_min_role(&headers, "superadmin")?;
    let unresolved = mdr_import_service::unresolved_breakdown(pool.as_ref(), &id).await?;
    if unresolved.total > 0 {
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({
                "status": "blocked",
                "reason": "unresolved_rows",
                "message": "Commit blocked: resolve all pending, ambiguous, and error rows first.",
                "unresolved": unresolved
            })),
        ));
    }

    let summary = mdr_import_service::commit_batch(pool.as_ref(), &id, &claims.sub).await?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "committed",
            "summary": summary
        })),
    ))
}

/// POST /api/mdr/batches/:id/reject
pub async fn reject_batch(
    State(pool): State<Arc<PgPool>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let claims = utils::require_min_role(&headers, "superadmin")?;
    mdr_import_service::reject_batch(pool.as_ref(), &id).await?;
    insert_mdr_audit_event(
        pool.as_ref(),
        Some(&claims.sub),
        "mdr.batch.reject",
        "mdr_import_batch",
        &id,
        "success",
        None,
        json!({}),
    )
    .await;
    Ok(Json(json!({ "status": "rejected" })))
}

/// GET /api/mdr/batches/:id/compliance-report
pub async fn get_batch_compliance_report(
    State(pool): State<Arc<PgPool>>,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let batch = sqlx::query_as::<_, MdrImportBatch>(
        r#"
        SELECT
            mib.*,
            (
                SELECT COUNT(*)::INT
                FROM mdr_staging_rows msr
                WHERE msr.batch_id = mib.id
                  AND msr.match_status = 'pending'
            ) AS pending_rows
        FROM mdr_import_batches mib
        WHERE mib.id = $1
        "#,
    )
    .bind(&id)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Batch not found".to_string()))?;

    let status_breakdown = sqlx::query_as::<_, (String, i64)>(
        "SELECT match_status, COUNT(*)::BIGINT FROM mdr_staging_rows WHERE batch_id = $1 GROUP BY match_status ORDER BY match_status",
    )
    .bind(&id)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let section_breakdown = sqlx::query_as::<_, (Option<String>, i64)>(
        "SELECT section, COUNT(*)::BIGINT FROM mdr_staging_rows WHERE batch_id = $1 GROUP BY section ORDER BY section",
    )
    .bind(&id)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let validation_issue_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM mdr_staging_rows WHERE batch_id = $1 AND validation_errors IS NOT NULL AND jsonb_typeof(validation_errors) = 'array' AND jsonb_array_length(validation_errors) > 0",
    )
    .bind(&id)
    .fetch_one(pool.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let audit_events = sqlx::query_as::<_, (String, String, String, Option<String>)>(
        "SELECT action_key, result, created_at::TEXT, reason FROM audit_logs WHERE entity_type = 'mdr_import_batch' AND entity_id = $1 ORDER BY created_at DESC LIMIT 20",
    )
    .bind(&id)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "batch": batch,
        "statusBreakdown": status_breakdown
            .into_iter()
            .map(|(status, count)| json!({ "status": status, "count": count }))
            .collect::<Vec<_>>(),
        "sectionBreakdown": section_breakdown
            .into_iter()
            .map(|(section, count)| json!({ "section": section.unwrap_or_else(|| "unclassified".to_string()), "count": count }))
            .collect::<Vec<_>>(),
        "validationIssueCount": validation_issue_count,
        "auditEvents": audit_events
            .into_iter()
            .map(|(action_key, result, created_at, reason)| {
                json!({
                    "actionKey": action_key,
                    "result": result,
                    "createdAt": created_at,
                    "reason": reason
                })
            })
            .collect::<Vec<_>>()
    })))
}

/// GET /api/mdr/ops-health
pub async fn get_mdr_ops_health(
    State(pool): State<Arc<PgPool>>,
) -> AppResult<Json<serde_json::Value>> {
    let reviewing_batches: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM mdr_import_batches WHERE status = 'reviewing'",
    )
    .fetch_one(pool.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let stale_reviewing_batches: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM mdr_import_batches WHERE status = 'reviewing' AND created_at < NOW() - INTERVAL '24 hours'",
    )
    .fetch_one(pool.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let pending_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM mdr_staging_rows WHERE match_status = 'pending'",
    )
    .fetch_one(pool.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let failed_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM mdr_staging_rows WHERE match_status = 'error'",
    )
    .fetch_one(pool.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let rejected_last_7d: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM mdr_import_batches WHERE status = 'rejected' AND created_at >= NOW() - INTERVAL '7 days'",
    )
    .fetch_one(pool.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let last_committed_at: Option<String> = sqlx::query_scalar(
        "SELECT committed_at::TEXT FROM mdr_import_batches WHERE status = 'committed' ORDER BY committed_at DESC NULLS LAST LIMIT 1",
    )
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "reviewingBatches": reviewing_batches,
        "staleReviewingBatches24h": stale_reviewing_batches,
        "pendingRows": pending_rows,
        "errorRows": failed_rows,
        "rejectedBatchesLast7d": rejected_last_7d,
        "lastCommittedAt": last_committed_at,
    })))
}
