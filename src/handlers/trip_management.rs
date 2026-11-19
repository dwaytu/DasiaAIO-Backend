use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    utils,
};

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TripDetails {
    pub id: String,
    pub car_id: Option<String>,
    pub driver_id: Option<String>,
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub destination: Option<String>,
    pub status: Option<String>,
    pub vehicle_model: Option<String>,
    pub vehicle_plate: Option<String>,
    pub driver_name: Option<String>,
    pub driver_phone: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[allow(dead_code)]
pub struct ActiveTripWithGuards {
    pub trip_id: String,
    pub destination: Option<String>,
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub vehicle_model: Option<String>,
    pub driver_name: Option<String>,
    pub guards: Vec<GuardInfo>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct GuardInfo {
    pub id: String,
    pub name: Option<String>,
    pub username: String,
}

// Get all active trips with details
pub async fn get_active_trips(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let trips = sqlx::query_as::<_, TripDetails>(
        "SELECT t.id, t.car_id, t.driver_id, t.start_time, t.end_time, 
                t.destination, t.status,
                ac.model as vehicle_model, ac.license_plate as vehicle_plate,
                u.full_name as driver_name, u.phone_number as driver_phone
         FROM trips t
         LEFT JOIN armored_cars ac ON t.car_id = ac.id
         LEFT JOIN users u ON t.driver_id = u.id
         WHERE t.status IN ('scheduled', 'in_progress')
         ORDER BY t.start_time ASC",
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch trips: {}", e)))?;

    Ok(Json(json!({
        "total": trips.len(),
        "trips": trips
    })))
}

// Get trip details by ID with assigned guards
pub async fn get_trip_details(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(trip_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    // Get trip details
    let trip = sqlx::query_as::<_, TripDetails>(
        "SELECT t.id, t.car_id, t.driver_id, t.start_time, t.end_time, 
                t.destination, t.status,
                ac.model as vehicle_model, ac.license_plate as vehicle_plate,
                u.full_name as driver_name, u.phone_number as driver_phone
         FROM trips t
         LEFT JOIN armored_cars ac ON t.car_id = ac.id
         LEFT JOIN users u ON t.driver_id = u.id
         WHERE t.id = $1",
    )
    .bind(&trip_id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch trip: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Trip not found".to_string()))?;

    // Get assigned guards for this trip
    let guards = sqlx::query_as::<_, GuardInfo>(
        "SELECT DISTINCT u.id, u.full_name as name, u.username
         FROM users u
         JOIN shifts s ON u.id = s.guard_id
         JOIN trips t ON DATE(s.start_time) = DATE(t.start_time)
         WHERE t.id = $1 AND s.status IN ('scheduled', 'in_progress')",
    )
    .bind(&trip_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch guards: {}", e)))?;

    // Get allocated firearms
    #[derive(sqlx::FromRow, Serialize)]
    struct FirearmInfo {
        id: String,
        name: Option<String>,
        model: Option<String>,
        serial_number: Option<String>,
    }

    let firearms = sqlx::query_as::<_, FirearmInfo>(
        "SELECT DISTINCT f.id, f.name, f.model, f.serial_number
         FROM firearms f
         JOIN firearm_allocations fa ON f.id = fa.firearm_id
         JOIN shifts s ON fa.guard_id = s.guard_id
         JOIN trips t ON DATE(s.start_time) = DATE(t.start_time)
         WHERE t.id = $1 AND fa.status = 'active'",
    )
    .bind(&trip_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch firearms: {}", e)))?;

    Ok(Json(json!({
        "trip": trip,
        "guards": guards,
        "firearms": firearms,
        "guard_count": guards.len(),
        "firearm_count": firearms.len()
    })))
}

// Assign driver to trip
pub async fn assign_driver_to_trip(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<AssignDriverRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    if payload.trip_id.trim().is_empty() || payload.driver_id.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Trip ID and driver ID are required".to_string(),
        ));
    }

    // Verify driver exists and is verified
    let driver_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND verified = true)",
    )
    .bind(&payload.driver_id)
    .fetch_one(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to verify driver: {}", e)))?;

    if !driver_exists {
        return Err(AppError::BadRequest(
            "Driver not found or not verified".to_string(),
        ));
    }

    // Update trip with driver
    let result = sqlx::query("UPDATE trips SET driver_id = $1 WHERE id = $2")
        .bind(&payload.driver_id)
        .bind(&payload.trip_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to assign driver: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Trip not found".to_string()));
    }

    Ok(Json(json!({
        "success": true,
        "message": "Driver assigned successfully"
    })))
}

// Update trip status
pub async fn update_trip_status(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(trip_id): Path<String>,
    Json(payload): Json<UpdateTripStatusRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let status = payload.status.trim();
    if status.is_empty() {
        return Err(AppError::BadRequest("Status is required".to_string()));
    }

    let allowed_statuses = ["scheduled", "in_progress", "completed", "cancelled"];
    if !allowed_statuses.contains(&status) {
        return Err(AppError::BadRequest("Invalid trip status".to_string()));
    }

    record_trip_status(db.as_ref(), &trip_id, status).await?;

    Ok(Json(json!({
        "success": true,
        "message": "Trip status updated"
    })))
}

async fn record_trip_status(pool: &PgPool, trip_id: &str, status: &str) -> AppResult<()> {
    let mut tx = pool.begin().await.map_err(trip_status_error)?;
    // Serialize status changes for the same vehicle, including allocation returns.
    let car_id: String = sqlx::query_scalar(
        "SELECT c.id FROM armored_cars c JOIN trips t ON t.car_id = c.id
         WHERE t.id = $1 FOR NO KEY UPDATE OF c",
    )
    .bind(trip_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(trip_status_error)?
    .ok_or_else(|| AppError::NotFound("Trip not found".to_string()))?;

    let updated =
        sqlx::query("UPDATE trips SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2")
            .bind(status)
            .bind(trip_id)
            .execute(&mut *tx)
            .await
            .map_err(trip_status_error)?;
    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound("Trip not found".to_string()));
    }

    if status == "in_progress" {
        sqlx::query(
            "UPDATE armored_cars SET status = 'in_transit', updated_at = CURRENT_TIMESTAMP
             WHERE id = $1 AND status IN ('available', 'operational', 'deployed')",
        )
        .bind(&car_id)
        .execute(&mut *tx)
        .await
        .map_err(trip_status_error)?;
    } else if status == "completed" {
        sqlx::query(
            "UPDATE armored_cars SET status = CASE
                WHEN EXISTS (SELECT 1 FROM trips WHERE car_id = $1 AND status IN ('in_progress', 'in_transit'))
                    THEN 'in_transit'
                WHEN EXISTS (SELECT 1 FROM car_allocations WHERE car_id = $1 AND status = 'active')
                    THEN 'allocated'
                ELSE 'available'
             END, updated_at = CURRENT_TIMESTAMP
             WHERE id = $1 AND status IN ('available', 'operational', 'in_transit', 'deployed')",
        )
        .bind(&car_id)
        .execute(&mut *tx)
        .await
        .map_err(trip_status_error)?;
    }

    tx.commit().await.map_err(trip_status_error)
}

fn trip_status_error(error: sqlx::Error) -> AppError {
    AppError::DatabaseError(format!("Failed to update trip status: {error}"))
}

// Get driver assignments
pub async fn get_driver_assignments(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    #[derive(sqlx::FromRow, Serialize)]
    struct DriverAssignment {
        driver_id: String,
        driver_name: Option<String>,
        active_trips: Option<i64>,
        total_trips: Option<i64>,
    }

    let assignments = sqlx::query_as::<_, DriverAssignment>(
        "SELECT u.id as driver_id, u.full_name as driver_name,
                COUNT(CASE WHEN t.status IN ('scheduled', 'in_progress') THEN 1 END) as active_trips,
                COUNT(t.id) as total_trips
         FROM users u
         LEFT JOIN trips t ON u.id = t.driver_id
         WHERE u.role IN ('guard') AND u.verified = true
         GROUP BY u.id, u.full_name
         ORDER BY active_trips DESC"
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch assignments: {}", e)))?;

    Ok(Json(json!({
        "total_drivers": assignments.len(),
        "assignments": assignments
    })))
}

#[derive(Debug, Deserialize)]
pub struct AssignDriverRequest {
    pub trip_id: String,
    pub driver_id: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTripStatusRequest {
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = false)]
    #[ignore = "requires an isolated PostgreSQL instance"]
    async fn completing_managed_trips_releases_only_ready_vehicles(pool: PgPool) {
        crate::db::run_migrations(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, email, username, password, role, full_name, phone_number)
             VALUES ('driver', 'fixture@example.test', 'fixture', 'fixture', 'guard', 'Fixture Driver', '')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO armored_cars (id, license_plate, vin, model, manufacturer, capacity_kg, status) VALUES
             ('car', 'QA-1', 'qa-vin-1', 'Fixture', 'Fixture', 1000, 'available'),
             ('loaned', 'QA-2', 'qa-vin-2', 'Fixture', 'Fixture', 1000, 'deployed'),
             ('service', 'QA-3', 'qa-vin-3', 'Fixture', 'Fixture', 1000, 'maintenance')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO trips (id, car_id, driver_id, start_time, status) VALUES
             ('first', 'car', 'driver', CURRENT_TIMESTAMP, 'scheduled'),
             ('other', 'car', 'driver', CURRENT_TIMESTAMP, 'in_transit'),
             ('client', 'loaned', 'driver', CURRENT_TIMESTAMP, 'in_progress'),
             ('service', 'service', 'driver', CURRENT_TIMESTAMP, 'in_progress')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO car_allocations (id, car_id, client_id, status)
             VALUES ('allocation', 'loaned', 'Fixture Site', 'active')",
        )
        .execute(&pool)
        .await
        .unwrap();

        record_trip_status(&pool, "first", "in_progress")
            .await
            .unwrap();
        record_trip_status(&pool, "first", "completed")
            .await
            .unwrap();
        record_trip_status(&pool, "client", "completed")
            .await
            .unwrap();
        record_trip_status(&pool, "service", "completed")
            .await
            .unwrap();
        let fleet_statuses = || async {
            sqlx::query_scalar::<_, String>("SELECT status FROM armored_cars ORDER BY id")
                .fetch_all(&pool)
                .await
                .unwrap()
        };
        assert_eq!(
            fleet_statuses().await,
            ["in_transit", "allocated", "maintenance"]
        );

        record_trip_status(&pool, "other", "completed")
            .await
            .unwrap();
        assert_eq!(
            fleet_statuses().await,
            ["available", "allocated", "maintenance"]
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM trips WHERE status = 'completed'")
                .fetch_one(&pool)
                .await
                .unwrap(),
            4,
        );
    }
}
