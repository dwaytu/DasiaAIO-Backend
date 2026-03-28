use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::{FromRow, PgPool};

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VehicleMaintenanceRiskResult {
    pub vehicle_id: String,
    pub license_plate: String,
    pub risk_score: f64,
    pub risk_level: String,
    pub mileage_since_service: f64,
    pub days_since_service: i64,
    pub maintenance_history_count: i64,
    pub recommended_action: String,
    pub formula: String,
    pub calculated_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct VehicleMetricsRow {
    id: String,
    license_plate: String,
    mileage: Option<i32>,
    created_at: DateTime<Utc>,
    last_maintenance_date: Option<DateTime<Utc>>,
    maintenance_history_count: Option<i64>,
    distance_since_service_km: Option<f64>,
}

#[derive(Debug, FromRow)]
struct VehicleIdRow {
    id: String,
}

fn derive_risk_level(score: f64) -> &'static str {
    if score < 0.34 {
        "LOW"
    } else if score < 0.67 {
        "MEDIUM"
    } else {
        "HIGH"
    }
}

fn derive_recommended_action(level: &str) -> &'static str {
    match level {
        "HIGH" => "Schedule immediate vehicle inspection and maintenance within 24 hours.",
        "MEDIUM" => "Schedule preventive maintenance within 14 days and monitor daily mileage.",
        _ => "Continue routine monitoring and keep next scheduled maintenance date.",
    }
}

async fn load_vehicle_metrics(pool: &PgPool, vehicle_id: &str) -> AppResult<VehicleMetricsRow> {
    let metrics = sqlx::query_as::<_, VehicleMetricsRow>(
        r#"
        SELECT
            ac.id,
            ac.license_plate,
            ac.mileage,
            ac.created_at,
            ac.last_maintenance_date,
            (
                SELECT COUNT(*)::BIGINT
                FROM car_maintenance cm
                WHERE cm.car_id = ac.id
                  AND cm.status = 'completed'
            ) AS maintenance_history_count,
            (
                SELECT COALESCE(SUM(t.distance_km)::FLOAT8, 0)
                FROM trips t
                WHERE t.car_id = ac.id
                  AND t.end_time IS NOT NULL
                  AND t.end_time >= COALESCE(ac.last_maintenance_date, ac.created_at)
            ) AS distance_since_service_km
        FROM armored_cars ac
        WHERE ac.id = $1
        "#,
    )
    .bind(vehicle_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to load vehicle metrics: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Vehicle not found".to_string()))?;

    Ok(metrics)
}

async fn persist_vehicle_prediction(
    pool: &PgPool,
    prediction: &VehicleMaintenanceRiskResult,
) -> AppResult<()> {
    let lower_level = prediction.risk_level.to_lowercase();

    sqlx::query(
        r#"
        INSERT INTO predictive_vehicle_maintenance (
            id,
            car_id,
            risk_score,
            risk_level,
            days_to_service,
            predicted_failure_window_days,
            recommended_action,
            rationale,
            signal_snapshot,
            maintenance_type_suggestion,
            generated_at,
            valid_until,
            feature_version,
            created_at,
            updated_at
        ) VALUES (
            $1,
            $2,
            $3,
            $4,
            NULL,
            $5,
            $6,
            $7,
            $8,
            'preventive',
            NOW(),
            NOW() + INTERVAL '30 days',
            'vehicle-maintenance-heuristic-v1',
            NOW(),
            NOW()
        )
        "#,
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&prediction.vehicle_id)
    .bind(prediction.risk_score)
    .bind(lower_level)
    .bind(if prediction.risk_level == "HIGH" {
        7_i32
    } else if prediction.risk_level == "MEDIUM" {
        14_i32
    } else {
        30_i32
    })
    .bind(&prediction.recommended_action)
    .bind(prediction.formula.clone())
    .bind(json!({
        "licensePlate": prediction.license_plate,
        "mileageSinceService": prediction.mileage_since_service,
        "daysSinceService": prediction.days_since_service,
        "maintenanceHistoryCount": prediction.maintenance_history_count,
        "calculatedAt": prediction.calculated_at,
    }))
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to persist vehicle maintenance prediction: {}",
            e
        ))
    })?;

    Ok(())
}

pub async fn predict_vehicle_risk(
    pool: &PgPool,
    vehicle_id: &str,
) -> AppResult<VehicleMaintenanceRiskResult> {
    let metrics = load_vehicle_metrics(pool, vehicle_id).await?;

    let reference_date = metrics.last_maintenance_date.unwrap_or(metrics.created_at);
    let days_since_service = (Utc::now() - reference_date).num_days().max(0);

    let mileage_from_trips = metrics.distance_since_service_km.unwrap_or(0.0).max(0.0);
    let fallback_mileage = f64::from(metrics.mileage.unwrap_or(0).max(0));
    let mileage_since_service = if mileage_from_trips > 0.0 {
        mileage_from_trips
    } else {
        fallback_mileage
    };

    let mileage_component = (mileage_since_service / 10_000.0).clamp(0.0, 1.0);
    let days_component = ((days_since_service as f64) / 180.0).clamp(0.0, 1.0);

    let risk_score = ((mileage_component * 0.5) + (days_component * 0.5)).clamp(0.0, 1.0);
    let risk_level = derive_risk_level(risk_score).to_string();
    let recommended_action = derive_recommended_action(&risk_level).to_string();

    let prediction = VehicleMaintenanceRiskResult {
        vehicle_id: metrics.id,
        license_plate: metrics.license_plate,
        risk_score: (risk_score * 1000.0).round() / 1000.0,
        risk_level,
        mileage_since_service: (mileage_since_service * 100.0).round() / 100.0,
        days_since_service,
        maintenance_history_count: metrics.maintenance_history_count.unwrap_or(0),
        recommended_action,
        formula: "MaintenanceRisk = (mileage_since_service * 0.5) + (days_since_service * 0.5) [normalized by 10,000 mileage and 180 days]".to_string(),
        calculated_at: Utc::now(),
    };

    persist_vehicle_prediction(pool, &prediction).await?;

    Ok(prediction)
}

pub async fn predict_fleet_vehicle_risk(
    pool: &PgPool,
) -> AppResult<Vec<VehicleMaintenanceRiskResult>> {
    let vehicle_ids = sqlx::query_as::<_, VehicleIdRow>(
        r#"
        SELECT id
        FROM armored_cars
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to list vehicles for maintenance prediction: {}",
            e
        ))
    })?;

    let mut predictions = Vec::new();
    for row in vehicle_ids {
        let prediction = predict_vehicle_risk(pool, &row.id).await?;
        predictions.push(prediction);
    }

    predictions.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.license_plate.cmp(&b.license_plate))
    });

    Ok(predictions)
}
