use axum::{
    extract::{Path, Query, State},
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

    Ok(Json(json!({
        "batchId": batch_id,
        "totalRows": summary.total,
        "preview": {
            "matched": summary.matched,
            "new": summary.new_rows,
            "ambiguous": summary.ambiguous,
            "errors": summary.errors,
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
        "SELECT * FROM mdr_import_batches ORDER BY created_at DESC LIMIT $1 OFFSET $2",
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
    let batch = sqlx::query_as::<_, MdrImportBatch>("SELECT * FROM mdr_import_batches WHERE id = $1")
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
    Path(id): Path<String>,
    Json(body): Json<ResolveRequest>,
) -> AppResult<Json<serde_json::Value>> {
    if !matches!(body.match_status.as_str(), "matched" | "new") {
        return Err(AppError::BadRequest(
            "match_status must be 'matched' or 'new'".to_string(),
        ));
    }

    let result = sqlx::query(
        "UPDATE mdr_staging_rows SET match_status = $1, matched_guard_id = $2, matched_firearm_id = $3, matched_client_id = $4 WHERE id = $5",
    )
    .bind(&body.match_status)
    .bind(&body.matched_guard_id)
    .bind(&body.matched_firearm_id)
    .bind(&body.matched_client_id)
    .bind(&id)
    .execute(pool.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Staging row not found".to_string()));
    }

    Ok(Json(json!({ "status": "resolved" })))
}

/// POST /api/mdr/batches/:id/commit
pub async fn commit_batch(
    State(pool): State<Arc<PgPool>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let claims = utils::require_min_role(&headers, "superadmin")?;
    let summary = mdr_import_service::commit_batch(pool.as_ref(), &id, &claims.sub).await?;

    Ok(Json(json!({
        "status": "committed",
        "summary": summary
    })))
}

/// POST /api/mdr/batches/:id/reject
pub async fn reject_batch(
    State(pool): State<Arc<PgPool>>,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    mdr_import_service::reject_batch(pool.as_ref(), &id).await?;
    Ok(Json(json!({ "status": "rejected" })))
}
