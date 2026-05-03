use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    models::{
        ArmoredCar, AssignDriverRequest, CarAllocation, CarMaintenance, CreateArmoredCarRequest,
        CreateMaintenanceRequest, CreateTripRequest, DriverAssignment, EndTripRequest,
        IssueCarRequest, ReturnCarRequest, Trip, UpdateArmoredCarRequest,
    },
    utils,
};

fn validate_armored_car_status(status: &str) -> AppResult<&'static str> {
    let normalized = status.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "available" => Ok("available"),
        "allocated" => Ok("allocated"),
        "maintenance" => Ok("maintenance"),
        "in_transit" => Ok("in_transit"),
        "inactive" => Ok("inactive"),
        _ => Err(AppError::ValidationError(
            "Invalid armored car status. Allowed values: available, allocated, maintenance, in_transit, inactive".to_string(),
        )),
    }
}

// ========== Armored Car Management ==========

pub async fn add_armored_car(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CreateArmoredCarRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    if payload.license_plate.is_empty() || payload.vin.is_empty() || payload.model.is_empty() {
        return Err(AppError::BadRequest(
            "License plate, VIN, and model are required".to_string(),
        ));
    }

    let id = utils::generate_id();

    sqlx::query(
        "INSERT INTO armored_cars (id, license_plate, vin, model, manufacturer, capacity_kg, passenger_capacity, registration_expiry, insurance_expiry, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
    )
    .bind(&id)
    .bind(&payload.license_plate)
    .bind(&payload.vin)
    .bind(&payload.model)
    .bind(&payload.manufacturer)
    .bind(payload.capacity_kg)
    .bind(payload.passenger_capacity.unwrap_or(4))
    .bind(&payload.registration_expiry)
    .bind(&payload.insurance_expiry)
    .bind("available")
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create armored car: {}", e)))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Armored car added successfully",
            "carId": id
        })),
    ))
}

pub async fn get_all_armored_cars(
    State(db): State<Arc<PgPool>>,
) -> AppResult<Json<Vec<ArmoredCar>>> {
    let cars = sqlx::query_as::<_, ArmoredCar>(
        "SELECT id, license_plate, vin, model, manufacturer, capacity_kg, passenger_capacity, status, registration_expiry, insurance_expiry, last_maintenance_date, mileage, created_at, updated_at FROM armored_cars"
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(cars))
}

pub async fn get_armored_car_by_id(
    State(db): State<Arc<PgPool>>,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let car = sqlx::query_as::<_, ArmoredCar>(
        "SELECT id, license_plate, vin, model, manufacturer, capacity_kg, passenger_capacity, status, registration_expiry, insurance_expiry, last_maintenance_date, mileage, created_at, updated_at FROM armored_cars WHERE id = $1"
    )
    .bind(&id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Armored car not found".to_string()))?;

    let allocations = sqlx::query_as::<_, CarAllocation>(
        "SELECT id, car_id, client_id, allocation_date, return_date, expected_return_date, status, notes, created_at, updated_at FROM car_allocations WHERE car_id = $1 ORDER BY allocation_date DESC"
    )
    .bind(&id)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(json!({
        "car": car,
        "allocations": allocations
    })))
}

pub async fn update_armored_car(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<UpdateArmoredCarRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let car = sqlx::query_as::<_, ArmoredCar>(
        "SELECT id, license_plate, vin, model, manufacturer, capacity_kg, passenger_capacity, status, registration_expiry, insurance_expiry, last_maintenance_date, mileage, created_at, updated_at FROM armored_cars WHERE id = $1"
    )
    .bind(&id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Armored car not found".to_string()))?;

    let status = validate_armored_car_status(payload.status.as_deref().unwrap_or(&car.status))?;
    let mileage = payload.mileage.unwrap_or(car.mileage);
    let registration_expiry = payload.registration_expiry.or(car.registration_expiry);
    let insurance_expiry = payload.insurance_expiry.or(car.insurance_expiry);

    sqlx::query(
        "UPDATE armored_cars SET status = $1, mileage = $2, registration_expiry = $3, insurance_expiry = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5"
    )
    .bind(status)
    .bind(mileage)
    .bind(&registration_expiry)
    .bind(&insurance_expiry)
    .bind(&id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to update armored car: {}", e)))?;

    Ok(Json(
        json!({ "message": "Armored car updated successfully" }),
    ))
}

pub async fn delete_armored_car(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let exists = sqlx::query_scalar::<_, String>("SELECT id FROM armored_cars WHERE id = $1")
        .bind(&id)
        .fetch_optional(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;
    if exists.is_none() {
        return Err(AppError::NotFound("Armored car not found".to_string()));
    }

    sqlx::query("DELETE FROM armored_cars WHERE id = $1")
        .bind(&id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to delete armored car: {}", e)))?;

    Ok(Json(
        json!({ "message": "Armored car deleted successfully" }),
    ))
}

// ========== Car Allocation Management ==========

pub async fn issue_car(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<IssueCarRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let id = utils::generate_id();

    sqlx::query(
        "INSERT INTO car_allocations (id, car_id, client_id, expected_return_date, notes, status) VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(&id)
    .bind(&payload.car_id)
    .bind(&payload.client_id)
    .bind(&payload.expected_return_date)
    .bind(&payload.notes)
    .bind("active")
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to issue car: {}", e)))?;

    // Update car status to allocated
    sqlx::query(
        "UPDATE armored_cars SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
    )
    .bind("allocated")
    .bind(&payload.car_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to update car status: {}", e)))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Car allocated successfully",
            "allocationId": id
        })),
    ))
}

pub async fn return_car(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<ReturnCarRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let allocation = sqlx::query_as::<_, CarAllocation>(
        "SELECT id, car_id, client_id, allocation_date, return_date, expected_return_date, status, notes, created_at, updated_at FROM car_allocations WHERE id = $1"
    )
    .bind(&payload.allocation_id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Allocation not found".to_string()))?;

    sqlx::query(
        "UPDATE car_allocations SET return_date = CURRENT_TIMESTAMP, status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2"
    )
    .bind("returned")
    .bind(&payload.allocation_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to return car: {}", e)))?;

    // Update car status to available
    sqlx::query(
        "UPDATE armored_cars SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
    )
    .bind("available")
    .bind(&allocation.car_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to update car status: {}", e)))?;

    Ok(Json(json!({ "message": "Car returned successfully" })))
}

pub async fn get_car_allocations(
    State(db): State<Arc<PgPool>>,
    Path(car_id): Path<String>,
) -> AppResult<Json<Vec<CarAllocation>>> {
    let allocations = sqlx::query_as::<_, CarAllocation>(
        "SELECT id, car_id, client_id, allocation_date, return_date, expected_return_date, status, notes, created_at, updated_at FROM car_allocations WHERE car_id = $1 ORDER BY allocation_date DESC"
    )
    .bind(&car_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(allocations))
}

pub async fn get_active_car_allocations(
    State(db): State<Arc<PgPool>>,
) -> AppResult<Json<Vec<CarAllocation>>> {
    let allocations = sqlx::query_as::<_, CarAllocation>(
        "SELECT id, car_id, client_id, allocation_date, return_date, expected_return_date, status, notes, created_at, updated_at FROM car_allocations WHERE status = 'active' ORDER BY allocation_date DESC"
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(allocations))
}

// ========== Car Maintenance Management ==========

pub async fn schedule_maintenance(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CreateMaintenanceRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let id = utils::generate_id();

    // Parse cost string to f64 for the NUMERIC column; null if absent or unparseable.
    let cost_f64: Option<f64> = payload.cost.as_deref().and_then(|s| s.parse::<f64>().ok());

    sqlx::query(
        "INSERT INTO car_maintenance (id, car_id, maintenance_type, description, scheduled_date, cost, status) VALUES ($1, $2, $3, $4, $5, $6, $7)"
    )
    .bind(&id)
    .bind(&payload.car_id)
    .bind(&payload.maintenance_type)
    .bind(&payload.description)
    .bind(&payload.scheduled_date)
    .bind(cost_f64)
    .bind("scheduled")
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to schedule maintenance: {}", e)))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Maintenance scheduled successfully",
            "maintenanceId": id
        })),
    ))
}

pub async fn complete_maintenance(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(maintenance_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let maintenance = sqlx::query_as::<_, CarMaintenance>(
        "SELECT id, car_id, maintenance_type, description, cost::FLOAT8 as cost, scheduled_date, completion_date, status, notes, created_at, updated_at FROM car_maintenance WHERE id = $1"
    )
    .bind(&maintenance_id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Maintenance record not found".to_string()))?;

    sqlx::query(
        "UPDATE car_maintenance SET completion_date = CURRENT_TIMESTAMP, status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2"
    )
    .bind("completed")
    .bind(&maintenance_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to complete maintenance: {}", e)))?;

    // Update car last maintenance date
    sqlx::query("UPDATE armored_cars SET last_maintenance_date = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1")
        .bind(&maintenance.car_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update car maintenance date: {}", e)))?;

    Ok(Json(
        json!({ "message": "Maintenance completed successfully" }),
    ))
}

pub async fn get_car_maintenance_records(
    State(db): State<Arc<PgPool>>,
    Path(car_id): Path<String>,
) -> AppResult<Json<Vec<CarMaintenance>>> {
    let records = sqlx::query_as::<_, CarMaintenance>(
        "SELECT id, car_id, maintenance_type, description, cost::FLOAT8 as cost, scheduled_date, completion_date, status, notes, created_at, updated_at FROM car_maintenance WHERE car_id = $1 ORDER BY scheduled_date DESC"
    )
    .bind(&car_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(records))
}

// ========== Driver Assignment Management ==========

pub async fn assign_driver(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<AssignDriverRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let id = utils::generate_id();

    sqlx::query(
        "INSERT INTO driver_assignments (id, car_id, guard_id, status) VALUES ($1, $2, $3, $4)",
    )
    .bind(&id)
    .bind(&payload.car_id)
    .bind(&payload.guard_id)
    .bind("active")
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to assign driver: {}", e)))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Driver assigned successfully",
            "assignmentId": id
        })),
    ))
}

pub async fn unassign_driver(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(assignment_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    sqlx::query(
        "UPDATE driver_assignments SET end_date = CURRENT_TIMESTAMP, status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2"
    )
    .bind("inactive")
    .bind(&assignment_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to unassign driver: {}", e)))?;

    Ok(Json(json!({ "message": "Driver unassigned successfully" })))
}

pub async fn get_car_drivers(
    State(db): State<Arc<PgPool>>,
    Path(car_id): Path<String>,
) -> AppResult<Json<Vec<DriverAssignment>>> {
    let drivers = sqlx::query_as::<_, DriverAssignment>(
        "SELECT id, car_id, guard_id, assignment_date, end_date, status, created_at, updated_at FROM driver_assignments WHERE car_id = $1 ORDER BY assignment_date DESC"
    )
    .bind(&car_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(drivers))
}

// ========== Trip Management ==========

pub async fn create_trip(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CreateTripRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let id = utils::generate_id();

    sqlx::query(
        "INSERT INTO trips (id, car_id, driver_id, allocation_id, start_location, start_time, mission_details, status) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, $6, $7)"
    )
    .bind(&id)
    .bind(&payload.car_id)
    .bind(&payload.driver_id)
    .bind(&payload.allocation_id)
    .bind(&payload.start_location)
    .bind(&payload.mission_details)
    .bind("in_transit")
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create trip: {}", e)))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Trip created successfully",
            "tripId": id
        })),
    ))
}

pub async fn end_trip(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<EndTripRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    // Parse distance_km string to f64 for the DECIMAL column; null if unparseable.
    let distance_km_f64: Option<f64> = payload
        .distance_km
        .as_deref()
        .and_then(|s| s.parse::<f64>().ok());

    sqlx::query(
        "UPDATE trips SET end_location = $1, distance_km = $2, end_time = CURRENT_TIMESTAMP, status = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4"
    )
    .bind(&payload.end_location)
    .bind(distance_km_f64)
    .bind("completed")
    .bind(&payload.trip_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to end trip: {}", e)))?;

    Ok(Json(json!({ "message": "Trip completed successfully" })))
}

pub async fn get_car_trips(
    State(db): State<Arc<PgPool>>,
    Path(car_id): Path<String>,
) -> AppResult<Json<Vec<Trip>>> {
    let trips = sqlx::query_as::<_, Trip>(
        "SELECT id, car_id, driver_id, allocation_id, start_location, end_location, start_time, end_time, distance_km::FLOAT8 as distance_km, status, mission_details, created_at, updated_at FROM trips WHERE car_id = $1 ORDER BY start_time DESC"
    )
    .bind(&car_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(trips))
}

pub async fn get_all_trips(State(db): State<Arc<PgPool>>) -> AppResult<Json<Vec<Trip>>> {
    let trips = sqlx::query_as::<_, Trip>(
        "SELECT id, car_id, driver_id, allocation_id, start_location, end_location, start_time, end_time, distance_km::FLOAT8 as distance_km, status, mission_details, created_at, updated_at FROM trips ORDER BY start_time DESC"
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Database error: {}", e)))?;

    Ok(Json(trips))
}
