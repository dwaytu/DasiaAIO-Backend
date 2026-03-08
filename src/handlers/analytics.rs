use axum::{
    extract::State,
    http::HeaderMap,
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

#[derive(Debug, Serialize)]
pub struct AnalyticsResponse {
    pub overview: OverviewStats,
    pub performance_metrics: PerformanceMetrics,
    pub resource_utilization: ResourceUtilization,
    pub mission_stats: MissionStats,
}

#[derive(Debug, Serialize)]
pub struct OverviewStats {
    pub total_guards: i64,
    pub active_guards: i64,
    pub total_missions: i64,
    pub completed_missions: i64,
    pub active_missions: i64,
    pub total_firearms: i64,
    pub allocated_firearms: i64,
    pub total_vehicles: i64,
    pub deployed_vehicles: i64,
}

#[derive(Debug, Serialize)]
pub struct PerformanceMetrics {
    pub mission_completion_rate: f64,
    pub average_mission_duration: f64,
    pub guard_attendance_rate: f64,
    pub firearm_availability_rate: f64,
    pub vehicle_utilization_rate: f64,
}

#[derive(Debug, Serialize)]
pub struct ResourceUtilization {
    pub firearms_in_use: i64,
    pub firearms_available: i64,
    pub vehicles_deployed: i64,
    pub vehicles_available: i64,
    pub guards_on_duty: i64,
    pub guards_available: i64,
}

#[derive(Debug, Serialize)]
pub struct MissionStats {
    pub total_missions_this_month: i64,
    pub completed_missions_this_month: i64,
    pub pending_missions: i64,
    pub average_guards_per_mission: f64,
    pub average_duration_hours: f64,
}

// Get comprehensive analytics
pub async fn get_analytics(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<AnalyticsResponse>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    // Overview stats
    let total_guards = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE role IN ('guard', 'user')"
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let active_guards = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(DISTINCT guard_id) FROM shifts 
         WHERE status = 'in_progress' OR status = 'scheduled'"
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let total_missions = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM trips"
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let completed_missions = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM trips WHERE status = 'completed'"
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let active_missions = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM trips WHERE status = 'in_progress' OR status = 'scheduled'"
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let total_firearms = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM firearms"
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let allocated_firearms = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM firearms WHERE status = 'allocated'"
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let total_vehicles = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM armored_cars"
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let deployed_vehicles = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM armored_cars WHERE status = 'deployed'"
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    // Performance metrics
    let mission_completion_rate = if total_missions > 0 {
        (completed_missions as f64 / total_missions as f64) * 100.0
    } else {
        0.0
    };

    let average_mission_duration = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT AVG(EXTRACT(EPOCH FROM (end_time - start_time)) / 3600.0) 
         FROM trips WHERE end_time IS NOT NULL AND start_time IS NOT NULL"
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(None)
    .unwrap_or(0.0);

    let total_shifts = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM shifts WHERE status = 'completed'"
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let attended_shifts = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(DISTINCT shift_id) FROM attendance WHERE check_in_time IS NOT NULL"
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let guard_attendance_rate = if total_shifts > 0 {
        (attended_shifts as f64 / total_shifts as f64) * 100.0
    } else {
        100.0
    };

    let firearm_availability_rate = if total_firearms > 0 {
        ((total_firearms - allocated_firearms) as f64 / total_firearms as f64) * 100.0
    } else {
        0.0
    };

    let vehicle_utilization_rate = if total_vehicles > 0 {
        (deployed_vehicles as f64 / total_vehicles as f64) * 100.0
    } else {
        0.0
    };

    // Resource utilization
    let firearms_available = total_firearms - allocated_firearms;
    let vehicles_available = total_vehicles - deployed_vehicles;
    let guards_available = total_guards - active_guards;

    // Mission stats
    let total_missions_this_month = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM trips 
         WHERE EXTRACT(MONTH FROM start_time) = EXTRACT(MONTH FROM CURRENT_TIMESTAMP)
         AND EXTRACT(YEAR FROM start_time) = EXTRACT(YEAR FROM CURRENT_TIMESTAMP)"
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let completed_missions_this_month = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM trips 
         WHERE status = 'completed'
         AND EXTRACT(MONTH FROM start_time) = EXTRACT(MONTH FROM CURRENT_TIMESTAMP)
         AND EXTRACT(YEAR FROM start_time) = EXTRACT(YEAR FROM CURRENT_TIMESTAMP)"
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let pending_missions = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM trips WHERE status = 'scheduled'"
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(0);

    let average_guards_per_mission = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT AVG(guard_count) FROM (
            SELECT t.id, COUNT(DISTINCT s.guard_id) as guard_count
            FROM trips t
            LEFT JOIN shifts s ON DATE(t.start_time) = DATE(s.start_time)
            WHERE t.start_time IS NOT NULL
            GROUP BY t.id
        ) mission_guards"
    )
    .fetch_one(db.as_ref())
    .await
    .unwrap_or(None)
    .unwrap_or(0.0);

    let response = AnalyticsResponse {
        overview: OverviewStats {
            total_guards,
            active_guards,
            total_missions,
            completed_missions,
            active_missions,
            total_firearms,
            allocated_firearms,
            total_vehicles,
            deployed_vehicles,
        },
        performance_metrics: PerformanceMetrics {
            mission_completion_rate,
            average_mission_duration,
            guard_attendance_rate,
            firearm_availability_rate,
            vehicle_utilization_rate,
        },
        resource_utilization: ResourceUtilization {
            firearms_in_use: allocated_firearms,
            firearms_available,
            vehicles_deployed: deployed_vehicles,
            vehicles_available,
            guards_on_duty: active_guards,
            guards_available,
        },
        mission_stats: MissionStats {
            total_missions_this_month,
            completed_missions_this_month,
            pending_missions,
            average_guards_per_mission,
            average_duration_hours: average_mission_duration,
        },
    };

    Ok(Json(response))
}

// Get performance trends
pub async fn get_performance_trends(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    #[derive(sqlx::FromRow, Serialize)]
    struct DailyStats {
        date: Option<chrono::NaiveDate>,
        missions_count: Option<i64>,
        completed_count: Option<i64>,
    }

    let daily_stats = sqlx::query_as::<_, DailyStats>(
        "SELECT DATE(start_time) as date,
                COUNT(*) as missions_count,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_count
         FROM trips
         WHERE start_time >= CURRENT_DATE - INTERVAL '30 days'
         GROUP BY DATE(start_time)
         ORDER BY DATE(start_time) DESC
         LIMIT 30"
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch trends: {}", e)))?;

    Ok(Json(json!({
        "daily_stats": daily_stats,
        "period": "Last 30 days"
    })))
}

// Update mission status
pub async fn update_mission_status(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<UpdateMissionStatusRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    // Update trip status
    sqlx::query(
        "UPDATE trips SET status = $1 WHERE id = $2"
    )
    .bind(&payload.status)
    .bind(&payload.mission_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to update mission: {}", e)))?;

    // If completed, update vehicle status back to operational
    if payload.status == "completed" {
        sqlx::query(
            "UPDATE armored_cars SET status = 'operational' 
             WHERE id IN (SELECT car_id FROM trips WHERE id = $1)"
        )
        .bind(&payload.mission_id)
        .execute(db.as_ref())
        .await
        .ok();

        // Return allocated firearms
        sqlx::query(
            "UPDATE firearms SET status = 'available'
             WHERE id IN (
                 SELECT fa.firearm_id FROM firearm_allocations fa
                 JOIN shifts s ON fa.guard_id = s.guard_id
                 JOIN trips t ON DATE(s.start_time) = DATE(t.start_time)
                 WHERE t.id = $1 AND fa.status = 'active'
             )"
        )
        .bind(&payload.mission_id)
        .execute(db.as_ref())
        .await
        .ok();

        // Update firearm allocations
        sqlx::query(
            "UPDATE firearm_allocations SET status = 'returned'
             WHERE guard_id IN (
                 SELECT s.guard_id FROM shifts s
                 JOIN trips t ON DATE(s.start_time) = DATE(t.start_time)
                 WHERE t.id = $1
             ) AND status = 'active'"
        )
        .bind(&payload.mission_id)
        .execute(db.as_ref())
        .await
        .ok();
    }

    Ok(Json(json!({
        "success": true,
        "message": "Mission status updated successfully"
    })))
}

#[derive(Debug, Deserialize)]
pub struct UpdateMissionStatusRequest {
    pub mission_id: String,
    pub status: String,
}
