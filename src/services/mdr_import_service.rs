use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use serde_json::json;
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

#[derive(Debug)]
struct BatchCounters {
    total: i32,
    matched: i32,
    new_rows: i32,
    ambiguous: i32,
    errors: i32,
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
    pub armored_cars_created: i32,
    pub armored_cars_updated: i32,
    pub car_allocations_created: i32,
    pub car_transitions_created: i32,
    pub guard_records_blocked: i32,
    pub firearm_records_blocked: i32,
}

fn normalize_optional_text(value: &Option<String>) -> Option<String> {
    value
        .as_ref()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

fn parse_mdr_date(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }

    DateTime::parse_from_rfc3339(trimmed).is_ok()
        || NaiveDate::parse_from_str(trimmed, "%Y-%m-%d").is_ok()
        || NaiveDate::parse_from_str(trimmed, "%m/%d/%Y").is_ok()
}

fn parse_mdr_datetime(value: &str) -> Option<DateTime<Utc>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.with_timezone(&Utc));
    }

    if let Ok(date) = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        let naive = date.and_hms_opt(0, 0, 0)?;
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
    }

    if let Ok(date) = NaiveDate::parse_from_str(trimmed, "%m/%d/%Y") {
        let naive = date.and_hms_opt(0, 0, 0)?;
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
    }

    None
}

fn derive_firearm_name(
    row: &crate::models::MdrStagingRow,
    serial_number: &str,
) -> (String, String, String) {
    let make = normalize_optional_text(&row.firearm_make).unwrap_or_else(|| "Unknown".to_string());
    let kind = normalize_optional_text(&row.firearm_kind).unwrap_or_else(|| "Firearm".to_string());
    let caliber = normalize_optional_text(&row.caliber).unwrap_or_else(|| "Unknown".to_string());

    (
        format!("{} {} ({})", make, kind, serial_number.trim()),
        make,
        caliber,
    )
}

fn validate_staging_row(
    row: &crate::models::MdrStagingRow,
    has_duplicate_license: bool,
    has_duplicate_serial: bool,
) -> Vec<String> {
    let section = row
        .section
        .as_deref()
        .map(str::trim)
        .unwrap_or("clients")
        .to_lowercase();

    let mut issues: Vec<String> = Vec::new();

    let guard_name = normalize_optional_text(&row.guard_name);
    let client_name = normalize_optional_text(&row.client_name);
    let serial_number = normalize_optional_text(&row.serial_number);
    let contact_number = normalize_optional_text(&row.contact_number);

    let requires_guard = !matches!(section.as_str(), "equipment" | "returned");
    let requires_client = matches!(
        section.as_str(),
        "clients" | "tower" | "backup" | "pullout" | "armored"
    );

    if requires_guard && guard_name.is_none() {
        issues.push("Guard name is required for this section.".to_string());
    }

    if requires_client && client_name.is_none() {
        issues.push("Client name is required for this section.".to_string());
    }

    if section == "armored" && serial_number.is_none() {
        issues.push("Armored row requires a vehicle identifier (plate/VIN).".to_string());
    }

    if let Some(ref phone) = contact_number {
        let compact = phone.replace([' ', '-', '(', ')'], "");
        let valid_digits = compact.chars().all(|ch| ch.is_ascii_digit() || ch == '+');
        if !valid_digits || compact.len() < 7 || compact.len() > 16 {
            issues.push("Contact number format is invalid.".to_string());
        }
    }

    if let Some(ref expiry) = row.license_expiry {
        if !expiry.trim().is_empty() && !parse_mdr_date(expiry) {
            issues.push("License expiry has an invalid date format.".to_string());
        }
    }

    if let Some(ref validity) = row.firearm_validity {
        if !validity.trim().is_empty() && !parse_mdr_date(validity) {
            issues.push("Firearm validity has an invalid date format.".to_string());
        }
    }

    if let Some(ref serial) = serial_number {
        let normalized = serial.trim();
        let allowed = normalized
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '/');
        if !allowed || normalized.len() < 4 {
            issues.push("Serial number format is invalid.".to_string());
        }
    }

    if has_duplicate_license {
        issues.push("Duplicate license number detected inside this MDR batch.".to_string());
    }

    if has_duplicate_serial {
        issues.push("Duplicate serial number detected inside this MDR batch.".to_string());
    }

    issues
}

async fn recompute_batch_counters(pool: &PgPool, batch_id: &str) -> AppResult<BatchCounters> {
    let counters: (i32, i32, i32, i32, i32) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*)::INT AS total,
            COUNT(*) FILTER (WHERE match_status = 'matched')::INT AS matched,
            COUNT(*) FILTER (WHERE match_status = 'new')::INT AS new_rows,
            COUNT(*) FILTER (WHERE match_status = 'ambiguous')::INT AS ambiguous,
            COUNT(*) FILTER (WHERE match_status = 'error')::INT AS errors
        FROM mdr_staging_rows
        WHERE batch_id = $1
        "#,
    )
    .bind(batch_id)
    .fetch_one(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to compute batch counters: {}", e)))?;

    Ok(BatchCounters {
        total: counters.0,
        matched: counters.1,
        new_rows: counters.2,
        ambiguous: counters.3,
        errors: counters.4,
    })
}

pub async fn refresh_batch_statistics(pool: &PgPool, batch_id: &str) -> AppResult<()> {
    let counters = recompute_batch_counters(pool, batch_id).await?;
    sqlx::query(
        "UPDATE mdr_import_batches SET total_rows = $1, matched_rows = $2, new_rows = $3, ambiguous_rows = $4, error_rows = $5, status = 'reviewing' WHERE id = $6",
    )
    .bind(counters.total)
    .bind(counters.matched)
    .bind(counters.new_rows)
    .bind(counters.ambiguous)
    .bind(counters.errors)
    .bind(batch_id)
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to refresh batch stats: {}", e)))?;

    Ok(())
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

    let mut license_counts: HashMap<String, i32> = HashMap::new();
    let mut serial_counts: HashMap<String, i32> = HashMap::new();

    for row in &rows {
        if let Some(license) = normalize_optional_text(&row.license_number) {
            *license_counts.entry(license.to_uppercase()).or_insert(0) += 1;
        }

        if let Some(serial) = normalize_optional_text(&row.serial_number) {
            *serial_counts.entry(serial.to_uppercase()).or_insert(0) += 1;
        }
    }

    for row in &rows {
        let mut status = "new";
        let mut guard_id: Option<String> = None;
        let mut firearm_id: Option<String> = None;
        let mut client_id: Option<String> = None;
        let mut validation_errors: Option<serde_json::Value> = None;

        let duplicate_license = normalize_optional_text(&row.license_number)
            .map(|license| {
                license_counts
                    .get(&license.to_uppercase())
                    .copied()
                    .unwrap_or(0)
                    > 1
            })
            .unwrap_or(false);
        let duplicate_serial = normalize_optional_text(&row.serial_number)
            .map(|serial| {
                serial_counts
                    .get(&serial.to_uppercase())
                    .copied()
                    .unwrap_or(0)
                    > 1
            })
            .unwrap_or(false);
        let row_issues = validate_staging_row(row, duplicate_license, duplicate_serial);
        if !row_issues.is_empty() {
            status = "error";
            validation_errors = Some(json!(row_issues));
        }

        if status != "error" {
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

            if row.section.as_deref() != Some("equipment")
                && row.section.as_deref() != Some("returned")
            {
                if row.guard_name.as_ref().is_none_or(|name| name.trim().is_empty()) {
                    status = "error";
                    validation_errors = Some(json!(["Guard name is required for this row."]));
                }
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
            "UPDATE mdr_staging_rows SET match_status = $1, matched_guard_id = $2, matched_firearm_id = $3, matched_client_id = $4, validation_errors = $5 WHERE id = $6",
        )
        .bind(status)
        .bind(&guard_id)
        .bind(&firearm_id)
        .bind(&client_id)
        .bind(&validation_errors)
        .bind(&row.id)
        .execute(pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update staging row: {}", e)))?;
    }

    refresh_batch_statistics(pool, batch_id).await?;

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
        armored_cars_created: 0,
        armored_cars_updated: 0,
        car_allocations_created: 0,
        car_transitions_created: 0,
        guard_records_blocked: 0,
        firearm_records_blocked: 0,
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
            "armored" => {
                if let Some(vehicle_identifier) = normalize_optional_text(&row.serial_number) {
                    let normalized_plate = vehicle_identifier.to_uppercase();
                    let provided_vin = normalize_optional_text(&row.license_number)
                        .unwrap_or_else(|| format!("MDR-{}", normalized_plate.replace(' ', "-")));
                    let model = normalize_optional_text(&row.firearm_make)
                        .unwrap_or_else(|| "Armored Unit".to_string());
                    let manufacturer = normalize_optional_text(&row.firearm_kind)
                        .unwrap_or_else(|| "Unknown".to_string());
                    let next_status = match row.pullout_status.as_deref().map(str::trim) {
                        Some("MAINTENANCE") => "maintenance",
                        Some("OFFLINE") => "offline",
                        Some("DEPLOYED") => "deployed",
                        _ => "available",
                    };

                    let existing_car = sqlx::query_as::<_, (String, String)>(
                        "SELECT id, status FROM armored_cars WHERE UPPER(license_plate) = UPPER($1) OR UPPER(vin) = UPPER($2) LIMIT 1",
                    )
                    .bind(&normalized_plate)
                    .bind(&provided_vin)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

                    let effective_car_id = if let Some((car_id, previous_status)) = existing_car {
                        sqlx::query(
                            "UPDATE armored_cars SET license_plate = $1, vin = $2, model = $3, manufacturer = $4, status = $5, updated_at = NOW() WHERE id = $6",
                        )
                        .bind(&normalized_plate)
                        .bind(&provided_vin)
                        .bind(&model)
                        .bind(&manufacturer)
                        .bind(next_status)
                        .bind(&car_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                        summary.armored_cars_updated += 1;

                        if previous_status != next_status {
                            let transition_id = utils::generate_id();
                            sqlx::query(
                                "INSERT INTO armored_car_status_transitions (id, car_id, previous_status, new_status, reason, mdr_batch_id, mdr_row_ref, recorded_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                            )
                            .bind(&transition_id)
                            .bind(&car_id)
                            .bind(&previous_status)
                            .bind(next_status)
                            .bind(row.pullout_status.as_deref())
                            .bind(batch_id)
                            .bind(format!("{}:{}", row.sheet_name, row.row_number))
                            .bind(committed_by)
                            .execute(&mut *tx)
                            .await
                            .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                            summary.car_transitions_created += 1;
                        }

                        car_id
                    } else {
                        let car_id = utils::generate_id();
                        sqlx::query(
                            "INSERT INTO armored_cars (id, license_plate, vin, model, manufacturer, capacity_kg, passenger_capacity, status, mileage) VALUES ($1, $2, $3, $4, $5, 0, 4, $6, 0)",
                        )
                        .bind(&car_id)
                        .bind(&normalized_plate)
                        .bind(&provided_vin)
                        .bind(&model)
                        .bind(&manufacturer)
                        .bind(next_status)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                        summary.armored_cars_created += 1;

                        let transition_id = utils::generate_id();
                        sqlx::query(
                            "INSERT INTO armored_car_status_transitions (id, car_id, previous_status, new_status, reason, mdr_batch_id, mdr_row_ref, recorded_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                        )
                        .bind(&transition_id)
                        .bind(&car_id)
                        .bind("unknown")
                        .bind(next_status)
                        .bind(Some("MDR import"))
                        .bind(batch_id)
                        .bind(format!("{}:{}", row.sheet_name, row.row_number))
                        .bind(committed_by)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                        summary.car_transitions_created += 1;

                        car_id
                    };

                    if let Some(ref client_id) = effective_client_id {
                        let existing_active_allocation = sqlx::query_scalar::<_, String>(
                            "SELECT id FROM car_allocations WHERE car_id = $1 AND client_id = $2 AND status = 'active' LIMIT 1",
                        )
                        .bind(&effective_car_id)
                        .bind(client_id)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

                        if existing_active_allocation.is_none() {
                            let car_allocation_id = utils::generate_id();
                            sqlx::query(
                                "INSERT INTO car_allocations (id, car_id, client_id, status, notes) VALUES ($1, $2, $3, 'active', $4)",
                            )
                            .bind(&car_allocation_id)
                            .bind(&effective_car_id)
                            .bind(client_id)
                            .bind(format!("MDR {}:{}", row.sheet_name, row.row_number))
                            .execute(&mut *tx)
                            .await
                            .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                            summary.car_allocations_created += 1;
                        }
                    }
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
                        let (firearm_name, firearm_model, firearm_caliber) =
                            derive_firearm_name(&row, serial_number);
                        let firearm_id = utils::generate_id();
                        let persisted_firearm_id = sqlx::query_scalar::<_, String>(
                            "INSERT INTO firearms (id, name, serial_number, model, caliber, status, kind, make, vault_status, return_remarks, mdr_batch_id) VALUES ($1, $2, $3, $4, $5, 'maintenance', $6, $7, 'returned_ghq', $8, $9) ON CONFLICT (serial_number) DO UPDATE SET name = EXCLUDED.name, model = EXCLUDED.model, caliber = EXCLUDED.caliber, status = 'maintenance', kind = COALESCE(EXCLUDED.kind, firearms.kind), make = COALESCE(EXCLUDED.make, firearms.make), vault_status = 'returned_ghq', return_remarks = COALESCE(EXCLUDED.return_remarks, firearms.return_remarks), mdr_batch_id = EXCLUDED.mdr_batch_id, updated_at = NOW() RETURNING id",
                        )
                        .bind(&firearm_id)
                        .bind(&firearm_name)
                        .bind(serial_number.trim())
                        .bind(&firearm_model)
                        .bind(&firearm_caliber)
                        .bind(&row.firearm_kind)
                        .bind(&row.firearm_make)
                        .bind(&row.fa_remarks)
                        .bind(batch_id)
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

                        if persisted_firearm_id == firearm_id {
                            summary.firearms_created += 1;
                        } else {
                            summary.firearms_updated += 1;
                        }
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
                        let (firearm_name, firearm_model, firearm_caliber) =
                            derive_firearm_name(&row, serial_number);
                        let firearm_id = utils::generate_id();
                        let persisted_firearm_id = sqlx::query_scalar::<_, String>(
                            "INSERT INTO firearms (id, name, serial_number, model, caliber, status, kind, make, vault_status, mdr_batch_id) VALUES ($1, $2, $3, $4, $5, 'available', $6, $7, 'vault', $8) ON CONFLICT (serial_number) DO UPDATE SET name = EXCLUDED.name, model = EXCLUDED.model, caliber = EXCLUDED.caliber, status = 'available', kind = COALESCE(EXCLUDED.kind, firearms.kind), make = COALESCE(EXCLUDED.make, firearms.make), vault_status = 'vault', mdr_batch_id = EXCLUDED.mdr_batch_id, updated_at = NOW() RETURNING id",
                        )
                        .bind(&firearm_id)
                        .bind(&firearm_name)
                        .bind(serial_number.trim())
                        .bind(&firearm_model)
                        .bind(&firearm_caliber)
                        .bind(&row.firearm_kind)
                        .bind(&row.firearm_make)
                        .bind(batch_id)
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

                        if persisted_firearm_id == firearm_id {
                            summary.firearms_created += 1;
                        } else {
                            summary.firearms_updated += 1;
                        }
                    }
                }
            }
            _ => {
                let guard_license_expired = row
                    .license_expiry
                    .as_ref()
                    .and_then(|value| parse_mdr_datetime(value))
                    .is_some_and(|expiry| expiry < Utc::now());
                let firearm_validity_expired = row
                    .firearm_validity
                    .as_ref()
                    .and_then(|value| parse_mdr_datetime(value))
                    .is_some_and(|validity| validity < Utc::now());
                let parsed_license_expiry = row
                    .license_expiry
                    .as_ref()
                    .and_then(|value| parse_mdr_datetime(value));
                let parsed_firearm_validity = row
                    .firearm_validity
                    .as_ref()
                    .and_then(|value| parse_mdr_datetime(value));

                let effective_guard_id = if let Some(ref guard_id) = row.matched_guard_id {
                    sqlx::query(
                        "UPDATE users SET guard_number = COALESCE($1, guard_number), phone_number = COALESCE($2, phone_number), lic_reg_name = $3, mdr_batch_id = $4, status = CASE WHEN $6 THEN 'inactive' ELSE status END, updated_at = NOW() WHERE id = $5",
                    )
                    .bind(row.guard_number)
                    .bind(&row.contact_number)
                    .bind(&row.lic_reg_name)
                    .bind(batch_id)
                    .bind(guard_id)
                    .bind(guard_license_expired)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                    summary.guards_updated += 1;
                    Some(guard_id.clone())
                } else if let Some(ref guard_name) = row.guard_name {
                    if !guard_name.trim().is_empty() {
                        let normalized_license = normalize_optional_text(&row.license_number);
                        let username_base = guard_name
                            .trim()
                            .to_lowercase()
                            .replace(' ', ".")
                            .replace(',', "");
                        let username_suffix = row
                            .guard_number
                            .map(|guard_number| format!("g{}", guard_number))
                            .or_else(|| {
                                normalized_license.as_ref().map(|license| {
                                    let compact: String = license
                                        .chars()
                                        .filter(|character| character.is_ascii_alphanumeric())
                                        .collect();
                                    let snippet: String = compact.chars().take(8).collect();
                                    format!("l{}", snippet.to_lowercase())
                                })
                            });
                        let username = if let Some(suffix) = username_suffix {
                            format!("{}.{}", username_base, suffix)
                        } else {
                            username_base
                        };
                        let email = format!("{}@sentinel.local", username);
                        let guard_status = if guard_license_expired {
                            "inactive"
                        } else {
                            "active"
                        };
                        let existing_guard_id = if let Some(ref license_number) = normalized_license {
                            sqlx::query_scalar::<_, String>(
                                "SELECT id FROM users WHERE license_number = $1 LIMIT 1",
                            )
                            .bind(license_number)
                            .fetch_optional(&mut *tx)
                            .await
                            .map_err(|e| AppError::DatabaseError(e.to_string()))?
                        } else {
                            sqlx::query_scalar::<_, String>(
                                "SELECT id FROM users WHERE username = $1 OR email = $2 LIMIT 1",
                            )
                            .bind(&username)
                            .bind(&email)
                            .fetch_optional(&mut *tx)
                            .await
                            .map_err(|e| AppError::DatabaseError(e.to_string()))?
                        };

                        if let Some(existing_guard_id) = existing_guard_id {
                            sqlx::query(
                                "UPDATE users SET full_name = COALESCE($2, full_name), phone_number = COALESCE($3, phone_number), license_number = COALESCE($4, license_number), license_expiry_date = COALESCE($5, license_expiry_date), guard_number = COALESCE($6, guard_number), lic_reg_name = COALESCE($7, lic_reg_name), mdr_batch_id = $8, status = CASE WHEN $9 THEN 'inactive' ELSE status END, updated_at = NOW() WHERE id = $1",
                            )
                            .bind(&existing_guard_id)
                            .bind(Some(guard_name.trim()))
                            .bind(&row.contact_number)
                            .bind(&normalized_license)
                            .bind(parsed_license_expiry)
                            .bind(row.guard_number)
                            .bind(&row.lic_reg_name)
                            .bind(batch_id)
                            .bind(guard_license_expired)
                            .execute(&mut *tx)
                            .await
                            .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                            summary.guards_updated += 1;
                            Some(existing_guard_id)
                        } else {
                            let guard_id = utils::generate_id();
                            let temp_password = crate::utils::hash_password("changeme123!").await?;

                            sqlx::query(
                                "INSERT INTO users (id, email, username, password, role, full_name, phone_number, license_number, license_expiry_date, guard_number, status, lic_reg_name, mdr_batch_id, verified) VALUES ($1, $2, $3, $4, 'guard', $5, $6, $7, $8, $9, $10, $11, $12, true)",
                            )
                            .bind(&guard_id)
                            .bind(&email)
                            .bind(&username)
                            .bind(&temp_password)
                            .bind(guard_name.trim())
                            .bind(row.contact_number.as_deref().unwrap_or(""))
                            .bind(&normalized_license)
                            .bind(parsed_license_expiry)
                            .bind(row.guard_number)
                            .bind(guard_status)
                            .bind(&row.lic_reg_name)
                            .bind(batch_id)
                            .execute(&mut *tx)
                            .await
                            .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                            summary.guards_created += 1;
                            Some(guard_id)
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                let effective_firearm_id = if let Some(ref firearm_id) = row.matched_firearm_id {
                    sqlx::query(
                        "UPDATE firearms SET kind = COALESCE($1, kind), make = COALESCE($2, make), validity_date = $3, ammo_issued = $4, lic_reg_name = $5, status = CASE WHEN $8 THEN 'maintenance' ELSE status END, mdr_batch_id = $6, updated_at = NOW() WHERE id = $7",
                    )
                    .bind(&row.firearm_kind)
                    .bind(&row.firearm_make)
                    .bind(parsed_firearm_validity)
                    .bind(row.actual_ammo.as_ref().and_then(|value| value.parse::<i32>().ok()))
                    .bind(&row.lic_reg_name)
                    .bind(batch_id)
                    .bind(firearm_id)
                    .bind(firearm_validity_expired)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                    summary.firearms_updated += 1;
                    Some(firearm_id.clone())
                } else if let Some(ref serial_number) = row.serial_number {
                    if !serial_number.trim().is_empty() {
                        let (firearm_name, firearm_model, firearm_caliber) =
                            derive_firearm_name(&row, serial_number);
                        let firearm_id = utils::generate_id();
                        let persisted_firearm_id = sqlx::query_scalar::<_, String>(
                            "INSERT INTO firearms (id, name, serial_number, model, caliber, status, kind, make, validity_date, ammo_issued, lic_reg_name, mdr_batch_id) VALUES ($1, $2, $3, $4, $5, 'allocated', $6, $7, $8, $9, $10, $11) ON CONFLICT (serial_number) DO UPDATE SET name = EXCLUDED.name, model = EXCLUDED.model, caliber = EXCLUDED.caliber, status = 'allocated', kind = COALESCE(EXCLUDED.kind, firearms.kind), make = COALESCE(EXCLUDED.make, firearms.make), validity_date = COALESCE(EXCLUDED.validity_date, firearms.validity_date), ammo_issued = COALESCE(EXCLUDED.ammo_issued, firearms.ammo_issued), lic_reg_name = COALESCE(EXCLUDED.lic_reg_name, firearms.lic_reg_name), mdr_batch_id = EXCLUDED.mdr_batch_id, updated_at = NOW() RETURNING id",
                        )
                        .bind(&firearm_id)
                        .bind(&firearm_name)
                        .bind(serial_number.trim())
                        .bind(&firearm_model)
                        .bind(&firearm_caliber)
                        .bind(&row.firearm_kind)
                        .bind(&row.firearm_make)
                        .bind(parsed_firearm_validity)
                        .bind(row.actual_ammo.as_ref().and_then(|value| value.parse::<i32>().ok()))
                        .bind(&row.lic_reg_name)
                        .bind(batch_id)
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

                        if persisted_firearm_id == firearm_id {
                            summary.firearms_created += 1;
                        } else {
                            summary.firearms_updated += 1;
                        }
                        Some(persisted_firearm_id)
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let (Some(ref guard_id), Some(ref firearm_id)) =
                    (&effective_guard_id, &effective_firearm_id)
                {
                    if guard_license_expired {
                        summary.guard_records_blocked += 1;
                    } else if firearm_validity_expired {
                        summary.firearm_records_blocked += 1;
                    } else {
                        sqlx::query(
                            "UPDATE firearm_allocations SET status = 'returned', return_date = NOW(), updated_at = NOW() WHERE (guard_id = $1 OR firearm_id = $2) AND status = 'active'",
                        )
                        .bind(guard_id)
                        .bind(firearm_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

                        let allocation_id = utils::generate_id();
                        sqlx::query(
                            "INSERT INTO firearm_allocations (id, firearm_id, guard_id, status, mdr_batch_id, mdr_row_ref) VALUES ($1, $2, $3, 'active', $4, $5)",
                        )
                        .bind(&allocation_id)
                        .bind(firearm_id)
                        .bind(guard_id)
                        .bind(batch_id)
                        .bind(format!("{}:{}", row.sheet_name, row.row_number))
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| AppError::DatabaseError(e.to_string()))?;
                        summary.allocations_created += 1;
                    }
                }

                if let (Some(ref guard_id), Some(ref client_id)) =
                    (&effective_guard_id, &effective_client_id)
                {
                    if guard_license_expired {
                        summary.guard_records_blocked += 1;
                    } else {
                        sqlx::query(
                            "UPDATE guard_assignments SET status = 'ended', assignment_end = NOW(), updated_at = NOW() WHERE guard_id = $1 AND status = 'active'",
                        )
                        .bind(guard_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

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
        "INSERT INTO audit_logs (id, actor_user_id, action_key, entity_type, entity_id, result, reason, metadata) VALUES ($1, $2, 'mdr.batch.commit', 'mdr_import_batch', $3, 'success', NULL, $4)",
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
