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

    let result = sqlx::query("UPDATE trips SET status = $1 WHERE id = $2")
        .bind(status)
        .bind(&trip_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update trip: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Trip not found".to_string()));
    }

    // If completed, update vehicle status
    if status == "completed" {
        sqlx::query(
            "UPDATE armored_cars SET status = 'operational' 
             WHERE id IN (SELECT car_id FROM trips WHERE id = $1)",
        )
        .bind(&trip_id)
        .execute(db.as_ref())
        .await
        .ok();
    } else if status == "in_progress" {
        sqlx::query(
            "UPDATE armored_cars SET status = 'deployed' 
             WHERE id IN (SELECT car_id FROM trips WHERE id = $1)",
        )
        .bind(&trip_id)
        .execute(db.as_ref())
        .await
        .ok();
    }

    Ok(Json(json!({
        "success": true,
        "message": "Trip status updated"
    })))
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

