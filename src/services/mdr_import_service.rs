use serde::Serialize;
use sqlx::PgPool;
use std::collections::HashMap;

use crate::{
    error::{AppError, AppResult},
    utils,
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchSummary {
    pub total: i32,
    pub matched: i32,
    pub new_rows: i32,
    pub ambiguous: i32,
    pub errors: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitSummary {
    pub clients_created: i32,
    pub clients_updated: i32,
    pub guards_created: i32,
    pub guards_updated: i32,
    pub firearms_created: i32,
    pub firearms_updated: i32,
    pub allocations_created: i32,
    pub assignments_created: i32,
    pub transitions_created: i32,
    pub equipment_created: i32,
}

/// Match staging rows against existing data.
/// For each row in a batch:
/// - Match guard by license_number -> users.license_number (primary)
/// - Fallback: UPPER(guard_name) matches UPPER(users.full_name)
/// - Match firearm by serial_number -> firearms.serial_number
/// - Match client by UPPER(client_name) -> UPPER(clients.name)
/// Sets match_status and matched_*_id fields on each staging row.
pub async fn match_staging_rows(pool: &PgPool, batch_id: &str) -> AppResult<MatchSummary> {
    let rows = sqlx::query_as::<_, crate::models::MdrStagingRow>(
        "SELECT * FROM mdr_staging_rows WHERE batch_id = $1",
    )
    .bind(batch_id)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch staging rows: {}", e)))?;

    let mut matched = 0i32;
    let mut new_rows = 0i32;
    let mut ambiguous = 0i32;
    let mut errors = 0i32;
    let total = rows.len() as i32;

    for row in &rows {
        let mut status = "new";
        let mut guard_id: Option<String> = None;
        let mut firearm_id: Option<String> = None;
        let mut client_id: Option<String> = None;

        if let Some(ref lic) = row.license_number {
            if !lic.trim().is_empty() {
                let guard_matches: Vec<(String,)> = sqlx::query_as(
                    "SELECT id FROM users WHERE license_number = $1 AND role = 'guard'",
                )
                .bind(lic.trim())
                .fetch_all(pool)
                .await
                .map_err(|e| AppError::DatabaseError(e.to_string()))?;

                match guard_matches.len() {
                    1 => {
                        guard_id = Some(guard_matches[0].0.clone());
                        status = "matched";
                    }
                    0 => {
                        if let Some(ref name) = row.guard_name {
                            if !name.trim().is_empty() {
                                let name_matches: Vec<(String,)> = sqlx::query_as(
                                    "SELECT id FROM users WHERE UPPER(full_name) = UPPER($1) AND role = 'guard'",
                                )
                                .bind(name.trim())
                                .fetch_all(pool)
                                .await
                                .map_err(|e| AppError::DatabaseError(e.to_string()))?;

                                match name_matches.len() {
                                    1 => {
                                        guard_id = Some(name_matches[0].0.clone());
                                        status = "matched";
                                    }
                                    x if x > 1 => {
                                        status = "ambiguous";
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {
                        status = "ambiguous";
                    }
                }
            }
        }

        if let Some(ref serial_number) = row.serial_number {
            if !serial_number.trim().is_empty() {
                let firearm_matches: Vec<(String,)> = sqlx::query_as(
                    "SELECT id FROM firearms WHERE serial_number = $1",
                )
                .bind(serial_number.trim())
                .fetch_all(pool)
                .await
                .map_err(|e| AppError::DatabaseError(e.to_string()))?;

                if firearm_matches.len() == 1 {
                    firearm_id = Some(firearm_matches[0].0.clone());
                }
            }
        }

        if let Some(ref client_name) = row.client_name {
            if !client_name.trim().is_empty() {
                let client_matches: Vec<(String,)> = sqlx::query_as(
                    "SELECT id FROM clients WHERE UPPER(name) = UPPER($1)",
                )
                .bind(client_name.trim())
                .fetch_all(pool)
                .await
                .map_err(|e| AppError::DatabaseError(e.to_string()))?;

                if client_matches.len() == 1 {
                    client_id = Some(client_matches[0].0.clone());
                }
            }
        }

        if row.section.as_deref() != Some("equipment") && row.section.as_deref() != Some("returned") {
            if row.guard_name.as_ref().is_none_or(|name| name.trim().is_empty()) {
                status = "error";
            }
        }

        match status {
            "matched" => matched += 1,
            "new" => new_rows += 1,
            "ambiguous" => ambiguous += 1,
            "error" => errors += 1,
            _ => new_rows += 1,
        }

        sqlx::query(
            "UPDATE mdr_staging_rows SET match_status = $1, matched_guard_id = $2, matched_firearm_id = $3, matched_client_id = $4 WHERE id = $5",
        )
        .bind(status)
        .bind(&guard_id)
        .bind(&firearm_id)
        .bind(&client_id)
        .bind(&row.id)
        .execute(pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update staging row: {}", e)))?;
    }

    sqlx::query(
        "UPDATE mdr_import_batches SET total_rows = $1, matched_rows = $2, new_rows = $3, ambiguous_rows = $4, error_rows = $5, status = 'reviewing' WHERE id = $6",
    )
    .bind(total)
    .bind(matched)
    .bind(new_rows)
    .bind(ambiguous)
    .bind(errors)
    .bind(batch_id)
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to update batch stats: {}", e)))?;

    Ok(MatchSummary {
        total,
        matched,
        new_rows,
        ambiguous,
        errors,
    })
}

/// Commit batch: transactional upsert of all staging rows to production tables.
pub async fn commit_batch(pool: &PgPool, batch_id: &str, committed_by: &str) -> AppResult<CommitSummary> {
    let batch_status: Option<String> = sqlx::query_scalar("SELECT status FROM mdr_import_batches WHERE id = $1")
        .bind(batch_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    match batch_status.as_deref() {
        Some("staging") | Some("reviewing") => {}
        Some(status) => {
            return Err(AppError::BadRequest(format!(
                "Batch is already '{}', cannot commit",
                status
            )));
        }
        None => return Err(AppError::NotFound("Batch not found".to_string())),
    }

    let unresolved: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mdr_staging_rows WHERE batch_id = $1 AND match_status IN ('ambiguous', 'error', 'pending')",
    )
    .bind(batch_id)
    .fetch_one(pool)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    if unresolved > 0 {
        return Err(AppError::BadRequest(format!(
            "{} staging rows are still unresolved (ambiguous/error/pending). Resolve them first.",
            unresolved
        )));
    }

    let rows = sqlx::query_as::<_, crate::models::MdrStagingRow>(
        "SELECT * FROM mdr_staging_rows WHERE batch_id = $1 ORDER BY row_number",
    )
    .bind(batch_id)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to begin transaction: {}", e)))?;

    let mut summary = CommitSummary {
        clients_created: 0,
        clients_updated: 0,
        guards_created: 0,
        guards_updated: 0,
        firearms_created: 0,
        firearms_updated: 0,
        allocations_created: 0,
        assignments_created: 0,
        transitions_created: 0,
        equipment_created: 0,
    };

    let mut created_clients: HashMap<String, String> = HashMap::new();

    for row in &rows {
        let section = row.section.as_deref().unwrap_or("clients");

        let effective_client_id = if let Some(ref client_name) = row.client_name {
            let normalized_name = client_name.trim().to_uppercase();
            if let Some(existing_client_id) = &row.matched_client_id {
                sqlx::query("UPDATE clients SET updated_at = NOW() WHERE id = $1")
                    .bind(existing_client_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                summary.clients_updated += 1;
                Some(existing_client_id.clone())
            } else if let Some(batch_client_id) = created_clients.get(&normalized_name) {
                Some(batch_client_id.clone())
            } else if !normalized_name.is_empty() {
                let client_id = utils::generate_id();
                sqlx::query(
                    "INSERT INTO clients (id, name, address, phone, client_number, branch, is_active) VALUES ($1, $2, $3, $4, $5, $6, true)",
                )
                .bind(&client_id)
                .bind(client_name.trim())
                .bind(&row.client_address)
                .bind(&row.contact_number)
                .bind(row.client_number)
                .bind(Option::<&str>::None)
                .execute(&mut *tx)
                .await
                .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                summary.clients_created += 1;
                created_clients.insert(normalized_name, client_id.clone());
                Some(client_id)
            } else {
                None
            }
        } else {
            None
        };

        match section {
            "equipment" => {
                if let Some(ref equipment_type) = row.firearm_kind {
                    let equipment_id = utils::generate_id();
                    sqlx::query(
                        "INSERT INTO equipment (id, equipment_type, description, assigned_to_client_id, quantity, status, mdr_batch_id) VALUES ($1, $2, $3, $4, $5, 'active', $6)",
                    )
                    .bind(&equipment_id)
                    .bind(equipment_type)
                    .bind(&row.firearm_make)
                    .bind(&effective_client_id)
                    .bind(
                        row.actual_ammo
                            .as_ref()
                            .and_then(|value| value.parse::<i32>().ok())
                            .unwrap_or(1),
                    )
                    .bind(batch_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                    summary.equipment_created += 1;
                }
            }
            "returned" => {
                if let Some(ref firearm_id) = row.matched_firearm_id {
                    sqlx::query(
                        "UPDATE firearms SET status = 'maintenance', vault_status = 'returned_ghq', return_remarks = $1, mdr_batch_id = $2, updated_at = NOW() WHERE id = $3",
                    )
                    .bind(&row.fa_remarks)
                    .bind(batch_id)
                    .bind(firearm_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                    summary.firearms_updated += 1;
                } else if let Some(ref serial_number) = row.serial_number {
                    if !serial_number.trim().is_empty() {
                        let firearm_id = utils::generate_id();
                        sqlx::query(
                            "INSERT INTO firearms (id, serial_number, model, caliber, status, kind, make, vault_status, return_remarks, mdr_batch_id) VALUES ($1, $2, $3, $4, 'maintenance', $5, $6, 'returned_ghq', $7, $8)",
                        )
                        .bind(&firearm_id)
                        .bind(serial_number.trim())
                        .bind(row.firearm_make.as_deref().unwrap_or("Unknown"))
                        .bind(&row.caliber)
                        .bind(&row.firearm_kind)
                        .bind(&row.firearm_make)
                        .bind(&row.fa_remarks)
                        .bind(batch_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                        summary.firearms_created += 1;
                    }
                }
            }
            "pullout" => {
                if let Some(ref guard_id) = row.matched_guard_id {
                    let transition_id = utils::generate_id();
                    let transition_type = match row.pullout_status.as_deref() {
                        Some("RESIGN") => "resignation",
                        Some("FLOATING") => "floating",
                        Some("ESCORT LBP A/C") | Some("ESCORT") => "reassignment",
                        _ => "pull_out",
                    };

                    sqlx::query(
                        "INSERT INTO guard_status_transitions (id, guard_id, transition_type, reason, previous_client_id, mdr_batch_id, mdr_row_ref, recorded_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                    )
                    .bind(&transition_id)
                    .bind(guard_id)
                    .bind(transition_type)
                    .bind(&row.pullout_status)
                    .bind(&effective_client_id)
                    .bind(batch_id)
                    .bind(format!("{}:{}", row.sheet_name, row.row_number))
                    .bind(committed_by)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                    summary.transitions_created += 1;

                    let new_status = match transition_type {
                        "resignation" => "resigned",
                        "floating" => "floating",
                        _ => "active",
                    };

                    sqlx::query("UPDATE users SET status = $1, updated_at = NOW() WHERE id = $2")
                        .bind(new_status)
                        .bind(guard_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

                    sqlx::query(
                        "UPDATE guard_assignments SET status = 'ended', assignment_end = NOW(), updated_at = NOW() WHERE guard_id = $1 AND status = 'active'",
                    )
                    .bind(guard_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

                    sqlx::query(
                        "UPDATE firearm_allocations SET status = 'returned', updated_at = NOW() WHERE guard_id = $1 AND status = 'active'",
                    )
                    .bind(guard_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                }
            }
            "vault" => {
                if let Some(ref firearm_id) = row.matched_firearm_id {
                    sqlx::query(
                        "UPDATE firearms SET vault_status = 'vault', kind = COALESCE($1, kind), make = COALESCE($2, make), mdr_batch_id = $3, updated_at = NOW() WHERE id = $4",
                    )
                    .bind(&row.firearm_kind)
                    .bind(&row.firearm_make)
                    .bind(batch_id)
                    .bind(firearm_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                    summary.firearms_updated += 1;
                } else if let Some(ref serial_number) = row.serial_number {
                    if !serial_number.trim().is_empty() {
                        let firearm_id = utils::generate_id();
                        sqlx::query(
                            "INSERT INTO firearms (id, serial_number, model, caliber, status, kind, make, vault_status, mdr_batch_id) VALUES ($1, $2, $3, $4, 'available', $5, $6, 'vault', $7)",
                        )
                        .bind(&firearm_id)
                        .bind(serial_number.trim())
                        .bind(row.firearm_make.as_deref().unwrap_or("Unknown"))
                        .bind(&row.caliber)
                        .bind(&row.firearm_kind)
                        .bind(&row.firearm_make)
                        .bind(batch_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                        summary.firearms_created += 1;
                    }
                }
            }
            _ => {
                let effective_guard_id = if let Some(ref guard_id) = row.matched_guard_id {
                    sqlx::query(
                        "UPDATE users SET guard_number = COALESCE($1, guard_number), phone_number = COALESCE($2, phone_number), lic_reg_name = $3, mdr_batch_id = $4, updated_at = NOW() WHERE id = $5",
                    )
                    .bind(row.guard_number)
                    .bind(&row.contact_number)
                    .bind(&row.lic_reg_name)
                    .bind(batch_id)
                    .bind(guard_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                    summary.guards_updated += 1;
                    Some(guard_id.clone())
                } else if let Some(ref guard_name) = row.guard_name {
                    if !guard_name.trim().is_empty() {
                        let guard_id = utils::generate_id();
                        let temp_password = crate::utils::hash_password("changeme123!").await?;
                        let username = guard_name
                            .trim()
                            .to_lowercase()
                            .replace(' ', ".")
                            .replace(',', "");
                        let email = format!("{}@sentinel.local", username);

                        sqlx::query(
                            "INSERT INTO users (id, email, username, password, role, full_name, phone_number, license_number, license_expiry_date, guard_number, status, lic_reg_name, mdr_batch_id, verified) VALUES ($1, $2, $3, $4, 'guard', $5, $6, $7, $8::timestamptz, $9, 'active', $10, $11, true)",
                        )
                        .bind(&guard_id)
                        .bind(&email)
                        .bind(&username)
                        .bind(&temp_password)
                        .bind(guard_name.trim())
                        .bind(row.contact_number.as_deref().unwrap_or(""))
                        .bind(&row.license_number)
                        .bind(&row.license_expiry)
                        .bind(row.guard_number)
                        .bind(&row.lic_reg_name)
                        .bind(batch_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                        summary.guards_created += 1;
                        Some(guard_id)
                    } else {
                        None
                    }
                } else {
                    None
                };

                let effective_firearm_id = if let Some(ref firearm_id) = row.matched_firearm_id {
                    sqlx::query(
                        "UPDATE firearms SET kind = COALESCE($1, kind), make = COALESCE($2, make), validity_date = $3::timestamptz, ammo_issued = $4, lic_reg_name = $5, mdr_batch_id = $6, updated_at = NOW() WHERE id = $7",
                    )
                    .bind(&row.firearm_kind)
                    .bind(&row.firearm_make)
                    .bind(&row.firearm_validity)
                    .bind(row.actual_ammo.as_ref().and_then(|value| value.parse::<i32>().ok()))
                    .bind(&row.lic_reg_name)
                    .bind(batch_id)
                    .bind(firearm_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                    summary.firearms_updated += 1;
                    Some(firearm_id.clone())
                } else if let Some(ref serial_number) = row.serial_number {
                    if !serial_number.trim().is_empty() {
                        let firearm_id = utils::generate_id();
                        sqlx::query(
                            "INSERT INTO firearms (id, serial_number, model, caliber, status, kind, make, validity_date, ammo_issued, lic_reg_name, mdr_batch_id) VALUES ($1, $2, $3, $4, 'allocated', $5, $6, $7::timestamptz, $8, $9, $10)",
                        )
                        .bind(&firearm_id)
                        .bind(serial_number.trim())
                        .bind(row.firearm_make.as_deref().unwrap_or("Unknown"))
                        .bind(&row.caliber)
                        .bind(&row.firearm_kind)
                        .bind(&row.firearm_make)
                        .bind(&row.firearm_validity)
                        .bind(row.actual_ammo.as_ref().and_then(|value| value.parse::<i32>().ok()))
                        .bind(&row.lic_reg_name)
                        .bind(batch_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                        summary.firearms_created += 1;
                        Some(firearm_id)
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let (Some(ref guard_id), Some(ref firearm_id)) =
                    (&effective_guard_id, &effective_firearm_id)
                {
                    let allocation_id = utils::generate_id();
                    sqlx::query(
                        "INSERT INTO firearm_allocations (id, firearm_id, guard_id, allocated_by, status, mdr_batch_id, mdr_row_ref) VALUES ($1, $2, $3, $4, 'active', $5, $6)",
                    )
                    .bind(&allocation_id)
                    .bind(firearm_id)
                    .bind(guard_id)
                    .bind(committed_by)
                    .bind(batch_id)
                    .bind(format!("{}:{}", row.sheet_name, row.row_number))
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                    summary.allocations_created += 1;
                }

                if let (Some(ref guard_id), Some(ref client_id)) =
                    (&effective_guard_id, &effective_client_id)
                {
                    let assignment_id = utils::generate_id();
                    sqlx::query(
                        "INSERT INTO guard_assignments (id, guard_id, client_id, post_label, guard_number, status, mdr_batch_id, mdr_row_ref) VALUES ($1, $2, $3, $4, $5, 'active', $6, $7)",
                    )
                    .bind(&assignment_id)
                    .bind(guard_id)
                    .bind(client_id)
                    .bind(&row.client_name)
                    .bind(row.guard_number)
                    .bind(batch_id)
                    .bind(format!("{}:{}", row.sheet_name, row.row_number))
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                    summary.assignments_created += 1;
                }
            }
        }
    }

    sqlx::query(
        "UPDATE mdr_import_batches SET status = 'committed', committed_at = NOW(), committed_by = $1 WHERE id = $2",
    )
    .bind(committed_by)
    .bind(batch_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let metadata = serde_json::to_value(&summary).map_err(|e| {
        AppError::InternalServerError(format!("Failed to serialize commit summary: {}", e))
    })?;

    let audit_id = utils::generate_id();
    sqlx::query(
        "INSERT INTO audit_logs (id, user_id, action, entity_type, entity_id, metadata) VALUES ($1, $2, 'mdr_batch_committed', 'mdr_import_batch', $3, $4)",
    )
    .bind(&audit_id)
    .bind(committed_by)
    .bind(batch_id)
    .bind(metadata)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to commit transaction: {}", e)))?;

    Ok(summary)
}

/// Reject a batch, setting status to 'rejected'.
pub async fn reject_batch(pool: &PgPool, batch_id: &str) -> AppResult<()> {
    let result = sqlx::query(
        "UPDATE mdr_import_batches SET status = 'rejected' WHERE id = $1 AND status IN ('staging', 'reviewing')",
    )
    .bind(batch_id)
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(
            "Batch not found or not in a rejectable state".to_string(),
        ));
    }

    Ok(())
}
