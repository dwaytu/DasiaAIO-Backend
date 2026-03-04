use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use sqlx::PgPool;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    error::{AppError, AppResult},
    utils,
};

#[derive(Debug, Deserialize)]
pub struct MissionAssignmentRequest {
    pub mission_name: String,
    pub guards_required: i32,
    pub vehicles_required: i32,
    pub firearms_required: i32,
    pub date: String,
    pub start_time: String,
    pub end_time: String,
    pub destination: String,
    pub priority: Option<String>,
    pub special_requirements: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MissionAssignmentResponse {
    pub mission_id: String,
    pub status: String,
    pub allocated_resources: AllocatedResources,
    pub mission_details: MissionDetails,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct AllocatedResources {
    pub guards: Vec<GuardAssignment>,
    pub firearms: Vec<FirearmAssignment>,
    pub vehicles: Vec<VehicleAssignment>,
}

#[derive(Debug, Serialize)]
pub struct GuardAssignment {
    pub id: String,
    pub name: String,
    pub assignment_status: String,
}

#[derive(Debug, Serialize)]
pub struct FirearmAssignment {
    pub id: String,
    pub r#type: String,
    pub allocation_status: String,
}

#[derive(Debug, Serialize)]
pub struct VehicleAssignment {
    pub id: String,
    pub r#type: String,
    pub capacity_passengers: i32,
    pub deployment_status: String,
}

#[derive(Debug, Serialize)]
pub struct MissionDetails {
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: chrono::DateTime<chrono::Utc>,
    pub destination: String,
    pub estimated_duration_hours: f64,
}

// Integrated mission assignment endpoint
pub async fn assign_mission(
    State(db): State<Arc<PgPool>>,
    Json(payload): Json<MissionAssignmentRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    use chrono::{NaiveDate, NaiveTime, NaiveDateTime};
    
    // Parse date (YYYY-MM-DD format from HTML date input)
    let date = NaiveDate::parse_from_str(&payload.date, "%Y-%m-%d")
        .map_err(|_| AppError::BadRequest("Invalid date format. Expected YYYY-MM-DD".to_string()))?;
    
    // Parse times (HH:MM format from HTML time input)
    let start_time_naive = NaiveTime::parse_from_str(&payload.start_time, "%H:%M")
        .map_err(|_| AppError::BadRequest("Invalid start time format. Expected HH:MM".to_string()))?;
    
    let end_time_naive = NaiveTime::parse_from_str(&payload.end_time, "%H:%M")
        .map_err(|_| AppError::BadRequest("Invalid end time format. Expected HH:MM".to_string()))?;
    
    // Combine date and time
    let start_datetime = NaiveDateTime::new(date, start_time_naive);
    let end_datetime = NaiveDateTime::new(date, end_time_naive);
    
    // Convert to UTC DateTime
    let start_time = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(start_datetime, chrono::Utc);
    let end_time = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(end_datetime, chrono::Utc);

    let duration = (end_time - start_time).num_hours() as f64;

    // 1. Find available guards
    #[derive(sqlx::FromRow)]
    struct GuardRow {
        id: String,
        full_name: Option<String>,
        username: String,
    }
    
    let guards = sqlx::query_as::<_, GuardRow>(
        "SELECT id, full_name, username FROM users 
         WHERE role = 'user' 
         AND verified = true 
         LIMIT $1"
    )
    .bind(payload.guards_required as i64)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to query guards: {}", e)))?;

    if guards.len() < payload.guards_required as usize {
        return Err(AppError::BadRequest(format!(
            "Insufficient guards available. Requested: {}, Available: {}",
            payload.guards_required, guards.len()
        )));
    }

    // 2. Find available firearms
    #[derive(sqlx::FromRow)]
    struct FirearmRow {
        id: String,
        name: Option<String>,
        model: Option<String>,
    }
    
    let firearms = sqlx::query_as::<_, FirearmRow>(
        "SELECT id, name, model FROM firearms 
         WHERE status = 'available' 
         LIMIT $1"
    )
    .bind(payload.firearms_required as i64)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to query firearms: {}", e)))?;

    if firearms.len() < payload.firearms_required as usize {
        return Err(AppError::BadRequest(format!(
            "Insufficient firearms available. Requested: {}, Available: {}",
            payload.firearms_required, firearms.len()
        )));
    }

    // 3. Find available vehicles
    #[derive(sqlx::FromRow)]
    struct VehicleRow {
        id: String,
        model: Option<String>,
        passenger_capacity: Option<i32>,
    }
    
    let vehicles = sqlx::query_as::<_, VehicleRow>(
        "SELECT id, model, passenger_capacity FROM armored_cars 
         WHERE status = 'operational' 
         LIMIT $1"
    )
    .bind(payload.vehicles_required as i64)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to query vehicles: {}", e)))?;

    if vehicles.len() < payload.vehicles_required as usize {
        return Err(AppError::BadRequest(format!(
            "Insufficient vehicles available. Requested: {}, Available: {}",
            payload.vehicles_required, vehicles.len()
        )));
    }

    let mission_id = format!("MISSION_{}_{}", 
        start_time.format("%Y%m%d"),
        utils::generate_id().split('-').next().unwrap_or("001")
    );

    // 4. Create shifts for guards
    let mut guard_assignments = Vec::new();
    for guard in &guards {
        let shift_id = utils::generate_id();
        sqlx::query(
            "INSERT INTO shifts (id, guard_id, start_time, end_time, client_site, status) 
             VALUES ($1, $2, $3, $4, $5, 'scheduled')"
        )
        .bind(&shift_id)
        .bind(&guard.id)
        .bind(start_time)
        .bind(end_time)
        .bind(&payload.destination)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to create shift: {}", e)))?;

        guard_assignments.push(GuardAssignment {
            id: guard.id.clone(),
            name: guard.full_name.clone().unwrap_or_else(|| guard.username.clone()),
            assignment_status: "confirmed".to_string(),
        });
    }

    // 5. Allocate firearms to guards
    let mut firearm_assignments = Vec::new();
    for (i, firearm) in firearms.iter().enumerate() {
        if let Some(guard) = guards.get(i) {
            let allocation_id = utils::generate_id();
            sqlx::query(
                "INSERT INTO firearm_allocations (id, guard_id, firearm_id, allocation_date, status) 
                 VALUES ($1, $2, $3, $4, 'active')"
            )
            .bind(&allocation_id)
            .bind(&guard.id)
            .bind(&firearm.id)
            .bind(start_time)
            .execute(db.as_ref())
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to allocate firearm: {}", e)))?;

            // Update firearm status
            sqlx::query("UPDATE firearms SET status = 'allocated' WHERE id = $1")
                .bind(&firearm.id)
                .execute(db.as_ref())
                .await
                .map_err(|e| AppError::DatabaseError(format!("Failed to update firearm: {}", e)))?;

            firearm_assignments.push(FirearmAssignment {
                id: firearm.id.clone(),
                r#type: format!("{} {}", firearm.model.as_deref().unwrap_or("Unknown"), firearm.name.as_deref().unwrap_or("")),
                allocation_status: "active".to_string(),
            });
        }
    }

    // 6. Allocate vehicles
    let mut vehicle_assignments = Vec::new();
    for vehicle in &vehicles {
        let trip_id = utils::generate_id();
        sqlx::query(
            "INSERT INTO trips (id, car_id, start_time, end_time, destination, driver_id, status) 
             VALUES ($1, $2, $3, $4, $5, $6, 'scheduled')"
        )
        .bind(&trip_id)
        .bind(&vehicle.id)
        .bind(start_time)
        .bind(end_time)
        .bind(&payload.destination)
        .bind(&guards.first().map(|g| g.id.clone()).unwrap_or_default())
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to create trip: {}", e)))?;

        vehicle_assignments.push(VehicleAssignment {
            id: vehicle.id.clone(),
            r#type: vehicle.model.clone().unwrap_or_else(|| "Armored Vehicle".to_string()),
            capacity_passengers: vehicle.passenger_capacity.unwrap_or(0),
            deployment_status: "ready".to_string(),
        });
    }

    let response = MissionAssignmentResponse {
        mission_id: mission_id.clone(),
        status: "allocated".to_string(),
        allocated_resources: AllocatedResources {
            guards: guard_assignments,
            firearms: firearm_assignments,
            vehicles: vehicle_assignments,
        },
        mission_details: MissionDetails {
            start_time,
            end_time,
            destination: payload.destination.clone(),
            estimated_duration_hours: duration,
        },
        created_at: chrono::Utc::now(),
    };

    Ok((StatusCode::CREATED, Json(json!(response))))
}

// Get mission details
pub async fn get_missions(
    State(db): State<Arc<PgPool>>,
) -> AppResult<Json<serde_json::Value>> {
    // Get recent trips with associated details
    #[derive(sqlx::FromRow, Serialize)]
    struct MissionRow {
        id: String,
        destination: Option<String>,
        start_time: Option<chrono::DateTime<chrono::Utc>>,
        end_time: Option<chrono::DateTime<chrono::Utc>>,
        status: Option<String>,
        vehicle_model: Option<String>,
        driver_name: Option<String>,
    }
    
    let missions = sqlx::query_as::<_, MissionRow>(
        "SELECT t.id, t.destination, t.start_time, t.end_time, t.status,
         ac.model as vehicle_model, u.full_name as driver_name
         FROM trips t
         LEFT JOIN armored_cars ac ON t.car_id = ac.id
         LEFT JOIN users u ON t.driver_id = u.id
         ORDER BY t.start_time DESC
         LIMIT 50"
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to query missions: {}", e)))?;

    Ok(Json(json!({
        "total": missions.len(),
        "missions": missions
    })))
}
