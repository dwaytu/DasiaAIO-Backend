use sqlx::{PgPool, Row};

use crate::error::{AppError, AppResult};

pub struct MdrResourceCounts {
    pub guards: u64,
    pub firearms: u64,
    pub vehicles: u64,
}

pub struct MdrResourceExport {
    pub csv: String,
    pub counts: MdrResourceCounts,
}

fn csv_cell(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn append_row(csv: &mut String, values: &[String]) {
    csv.push_str(
        &values
            .iter()
            .map(|value| csv_cell(value))
            .collect::<Vec<_>>()
            .join(","),
    );
    csv.push('\n');
}

fn row_text(row: &sqlx::postgres::PgRow, column: &str) -> AppResult<String> {
    row.try_get(column)
        .map_err(|error| AppError::DatabaseError(format!("Failed to read MDR export row: {error}")))
}

pub async fn export_current_resources(pool: &PgPool) -> AppResult<MdrResourceExport> {
    let guards = sqlx::query(
        "SELECT id, COALESCE(full_name, '') AS full_name, COALESCE(username, '') AS username, COALESCE(email, '') AS email, COALESCE(phone_number, '') AS phone, COALESCE(guard_number::TEXT, '') AS guard_number, COALESCE(license_number, '') AS license_number, COALESCE(license_expiry_date::TEXT, '') AS license_expiry, COALESCE(status, '') AS status FROM users WHERE LOWER(BTRIM(role)) IN ('guard', 'user') ORDER BY LOWER(COALESCE(full_name, username))",
    )
    .fetch_all(pool)
    .await
    .map_err(|error| AppError::DatabaseError(format!("Failed to export guard records: {error}")))?;

    let firearms = sqlx::query(
        "SELECT id, COALESCE(name, '') AS name, COALESCE(serial_number, '') AS serial_number, COALESCE(model, '') AS model, COALESCE(caliber, '') AS caliber, COALESCE(status, '') AS status, COALESCE(validity_date::TEXT, '') AS validity_date, COALESCE(lic_reg_name, '') AS lic_reg_name, COALESCE(vault_status, '') AS vault_status FROM firearms ORDER BY LOWER(serial_number)",
    )
    .fetch_all(pool)
    .await
    .map_err(|error| AppError::DatabaseError(format!("Failed to export firearm records: {error}")))?;

    let vehicles = sqlx::query(
        "SELECT id, COALESCE(license_plate, '') AS license_plate, COALESCE(plate_number, '') AS plate_number, COALESCE(vin, '') AS vin, COALESCE(model, '') AS model, COALESCE(manufacturer, '') AS manufacturer, COALESCE(capacity_kg::TEXT, '') AS capacity_kg, COALESCE(passenger_capacity::TEXT, '') AS passenger_capacity, COALESCE(status, '') AS status, COALESCE(registration_expiry::TEXT, '') AS registration_expiry, COALESCE(insurance_expiry::TEXT, '') AS insurance_expiry FROM armored_cars ORDER BY LOWER(license_plate)",
    )
    .fetch_all(pool)
    .await
    .map_err(|error| AppError::DatabaseError(format!("Failed to export vehicle records: {error}")))?;

    let mut csv = String::from("SENTINEL MDR RESOURCE EXPORT\n\n");

    csv.push_str("GUARDS\n");
    append_row(
        &mut csv,
        &[
            "ID".to_string(),
            "Full Name".to_string(),
            "Username".to_string(),
            "Email".to_string(),
            "Phone".to_string(),
            "Guard Number".to_string(),
            "License Number".to_string(),
            "License Expiry".to_string(),
            "Status".to_string(),
        ],
    );
    for row in &guards {
        append_row(
            &mut csv,
            &[
                row_text(row, "id")?,
                row_text(row, "full_name")?,
                row_text(row, "username")?,
                row_text(row, "email")?,
                row_text(row, "phone")?,
                row_text(row, "guard_number")?,
                row_text(row, "license_number")?,
                row_text(row, "license_expiry")?,
                row_text(row, "status")?,
            ],
        );
    }

    csv.push_str("\nFIREARMS\n");
    append_row(
        &mut csv,
        &[
            "ID".to_string(),
            "Name".to_string(),
            "Serial Number".to_string(),
            "Model".to_string(),
            "Caliber".to_string(),
            "Status".to_string(),
            "License Validity".to_string(),
            "License Registration Name".to_string(),
            "Vault Status".to_string(),
        ],
    );
    for row in &firearms {
        append_row(
            &mut csv,
            &[
                row_text(row, "id")?,
                row_text(row, "name")?,
                row_text(row, "serial_number")?,
                row_text(row, "model")?,
                row_text(row, "caliber")?,
                row_text(row, "status")?,
                row_text(row, "validity_date")?,
                row_text(row, "lic_reg_name")?,
                row_text(row, "vault_status")?,
            ],
        );
    }

    csv.push_str("\nVEHICLES\n");
    append_row(
        &mut csv,
        &[
            "ID".to_string(),
            "A/C Number".to_string(),
            "Plate Number".to_string(),
            "VIN".to_string(),
            "Model".to_string(),
            "Manufacturer".to_string(),
            "Capacity (kg)".to_string(),
            "Passenger Capacity".to_string(),
            "Status".to_string(),
            "Registration Expiry".to_string(),
            "Insurance Expiry".to_string(),
        ],
    );
    for row in &vehicles {
        append_row(
            &mut csv,
            &[
                row_text(row, "id")?,
                row_text(row, "license_plate")?,
                row_text(row, "plate_number")?,
                row_text(row, "vin")?,
                row_text(row, "model")?,
                row_text(row, "manufacturer")?,
                row_text(row, "capacity_kg")?,
                row_text(row, "passenger_capacity")?,
                row_text(row, "status")?,
                row_text(row, "registration_expiry")?,
                row_text(row, "insurance_expiry")?,
            ],
        );
    }

    Ok(MdrResourceExport {
        csv,
        counts: MdrResourceCounts {
            guards: guards.len() as u64,
            firearms: firearms.len() as u64,
            vehicles: vehicles.len() as u64,
        },
    })
}

pub async fn clear_current_resources(pool: &PgPool) -> AppResult<MdrResourceCounts> {
    let mut transaction = pool.begin().await.map_err(|error| {
        AppError::DatabaseError(format!("Failed to start MDR clear transaction: {error}"))
    })?;

    sqlx::query(
        "UPDATE equipment SET assigned_to_guard_id = NULL, updated_at = CURRENT_TIMESTAMP WHERE assigned_to_guard_id IN (SELECT id FROM users WHERE LOWER(BTRIM(role)) IN ('guard', 'user'))",
    )
    .execute(&mut *transaction)
    .await
    .map_err(|error| AppError::DatabaseError(format!("Failed to release guard equipment: {error}")))?;

    sqlx::query(
        "UPDATE guard_status_transitions SET recorded_by = NULL WHERE recorded_by IN (SELECT id FROM users WHERE LOWER(BTRIM(role)) IN ('guard', 'user'))",
    )
    .execute(&mut *transaction)
    .await
    .map_err(|error| AppError::DatabaseError(format!("Failed to release guard audit references: {error}")))?;

    let firearms = sqlx::query("DELETE FROM firearms")
        .execute(&mut *transaction)
        .await
        .map_err(|error| AppError::DatabaseError(format!("Failed to delete firearms: {error}")))?
        .rows_affected();

    let vehicles = sqlx::query("DELETE FROM armored_cars")
        .execute(&mut *transaction)
        .await
        .map_err(|error| AppError::DatabaseError(format!("Failed to delete vehicles: {error}")))?
        .rows_affected();

    let guards = sqlx::query("DELETE FROM users WHERE LOWER(BTRIM(role)) IN ('guard', 'user')")
        .execute(&mut *transaction)
        .await
        .map_err(|error| AppError::DatabaseError(format!("Failed to delete guards: {error}")))?
        .rows_affected();

    transaction.commit().await.map_err(|error| {
        AppError::DatabaseError(format!("Failed to commit MDR clear transaction: {error}"))
    })?;

    Ok(MdrResourceCounts {
        guards,
        firearms,
        vehicles,
    })
}

#[cfg(test)]
mod tests {
    use super::csv_cell;

    #[test]
    fn csv_cells_escape_quotes() {
        assert_eq!(csv_cell("Guard, \"Alpha\""), "\"Guard, \"\"Alpha\"\"\"");
    }
}
