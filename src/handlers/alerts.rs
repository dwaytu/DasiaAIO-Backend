use axum::{extract::State, http::HeaderMap, Json};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::{FromRow, PgPool};
use std::sync::Arc;

use crate::{
    error::{AppError, AppResult},
    utils,
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PredictiveAlert {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub message: String,
    pub detected_at: DateTime<Utc>,
    pub context: serde_json::Value,
}

#[derive(Debug, FromRow)]
struct PermitStats {
    total: Option<i64>,
    soonest_days: Option<f64>,
}

#[derive(Debug, FromRow)]
struct VehicleMaintenanceRow {
    license_plate: Option<String>,
    scheduled_date: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow)]
struct GuardNoShowRow {
    guard_id: String,
    guard_name: Option<String>,
    no_shows: Option<i64>,
}

#[derive(Debug, FromRow)]
struct GuardCapacityRow {
    total_guards: Option<i64>,
    scheduled_tomorrow: Option<i64>,
    committed_today: Option<i64>,
}

pub async fn get_predictive_alerts(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<PredictiveAlert>>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let mut alerts: Vec<PredictiveAlert> = Vec::new();

    // Permit expiry within 7 days
    let permit_stats = sqlx::query_as::<_, PermitStats>(
        r#"
        SELECT
            COUNT(*)::BIGINT AS total,
            MIN(GREATEST(CEIL(EXTRACT(EPOCH FROM (expiry_date - NOW())) / 86400.0), 0)) AS soonest_days
        FROM guard_firearm_permits
        WHERE status = 'active'
          AND expiry_date IS NOT NULL
          AND expiry_date <= NOW() + INTERVAL '7 days'
        "#,
    )
    .fetch_one(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to query expiring permits: {}", e)))?;

    let permit_total = permit_stats.total.unwrap_or(0);
    if permit_total > 0 {
        let soonest = permit_stats
            .soonest_days
            .and_then(|d| if d.is_finite() { Some(d as i64) } else { None })
            .unwrap_or(7);
        let message = if soonest <= 0 {
            format!("{permit_total} firearm permit(s) already expired or due today")
        } else {
            let plural = if soonest == 1 { "day" } else { "days" };
            format!("{permit_total} firearm permit(s) expiring in {soonest} {plural}")
        };

        alerts.push(PredictiveAlert {
            id: "permits-expiring".to_string(),
            category: "permits".to_string(),
            severity: if permit_total >= 3 {
                "critical".into()
            } else {
                "warning".into()
            },
            message,
            detected_at: Utc::now(),
            context: json!({
                "count": permit_total,
                "soonestInDays": soonest.max(0),
            }),
        });
    }

    // Vehicle maintenance overdue
    let vehicle_rows = sqlx::query_as::<_, VehicleMaintenanceRow>(
        r#"
        SELECT ac.license_plate, cm.scheduled_date
        FROM car_maintenance cm
        JOIN armored_cars ac ON ac.id = cm.car_id
        WHERE cm.status = 'pending'
          AND cm.scheduled_date IS NOT NULL
          AND cm.scheduled_date < NOW()
        ORDER BY cm.scheduled_date ASC
        LIMIT 5
        "#,
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to query overdue vehicle maintenance: {}",
            e
        ))
    })?;

    if !vehicle_rows.is_empty() {
        let first_plate = vehicle_rows
            .first()
            .and_then(|row| row.license_plate.clone())
            .unwrap_or_else(|| "Fleet vehicle".to_string());
        let message = if vehicle_rows.len() == 1 {
            format!("Vehicle {first_plate} maintenance overdue")
        } else {
            format!(
                "{} vehicles with overdue maintenance (earliest: {first_plate})",
                vehicle_rows.len()
            )
        };

        alerts.push(PredictiveAlert {
            id: "vehicle-maintenance".to_string(),
            category: "vehicles".to_string(),
            severity: if vehicle_rows.len() >= 3 {
                "critical".into()
            } else {
                "warning".into()
            },
            message,
            detected_at: Utc::now(),
            context: json!({
                "count": vehicle_rows.len(),
                "samples": vehicle_rows.iter().map(|row| {
                    json!({
                        "licensePlate": row.license_plate,
                        "scheduledDate": row.scheduled_date,
                    })
                }).collect::<Vec<_>>(),
            }),
        });
    }

    // Guards with repeated recent no-shows
    let guard_rows = sqlx::query_as::<_, GuardNoShowRow>(
        r#"
                SELECT pr.guard_id,
                             COALESCE(NULLIF(u.full_name, ''), u.username) AS guard_name,
               COUNT(*)::BIGINT AS no_shows
        FROM punctuality_records pr
        JOIN users u ON u.id = pr.guard_id
        WHERE pr.status = 'no_show'
          AND pr.scheduled_start_time >= NOW() - INTERVAL '14 days'
                GROUP BY pr.guard_id, guard_name
        HAVING COUNT(*) >= 2
        ORDER BY no_shows DESC, guard_name ASC
        LIMIT 5
        "#,
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to query guard absences: {}", e)))?;

    if !guard_rows.is_empty() {
        let preview_names = guard_rows
            .iter()
            .take(3)
            .map(|row| {
                row.guard_name
                    .clone()
                    .unwrap_or_else(|| "Guard".to_string())
            })
            .collect::<Vec<_>>()
            .join(", ");
        let message = if guard_rows.len() == 1 {
            format!("{} flagged for repeated no-shows", preview_names)
        } else {
            format!(
                "{} guards flagged for repeated no-shows ({preview_names}...)",
                guard_rows.len()
            )
        };

        alerts.push(PredictiveAlert {
            id: "guard-absence-risk".to_string(),
            category: "personnel".to_string(),
            severity: if guard_rows.len() >= 3 {
                "critical".into()
            } else {
                "warning".into()
            },
            message,
            detected_at: Utc::now(),
            context: json!({
                "guards": guard_rows
                    .iter()
                    .map(|row| json!({
                        "name": row.guard_name,
                        "noShows": row.no_shows.unwrap_or(0),
                    }))
                    .collect::<Vec<_>>(),
            }),
        });
    }

    // Guard availability forecast
    let guard_capacity = sqlx::query_as::<_, GuardCapacityRow>(
        r#"
        SELECT
            (SELECT COUNT(*) FROM users WHERE role IN ('guard'))::BIGINT AS total_guards,
            (SELECT COUNT(DISTINCT guard_id) FROM shifts WHERE DATE(start_time) = CURRENT_DATE + INTERVAL '1 day' AND status IN ('scheduled', 'in_progress'))::BIGINT AS scheduled_tomorrow,
            (SELECT COUNT(DISTINCT guard_id) FROM shifts WHERE DATE(start_time) = CURRENT_DATE AND status IN ('scheduled', 'in_progress'))::BIGINT AS committed_today
        "#,
    )
    .fetch_one(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to query guard availability: {}", e)))?;

    let total_guards = guard_capacity.total_guards.unwrap_or(0).max(0);
    let scheduled_tomorrow = guard_capacity.scheduled_tomorrow.unwrap_or(0).max(0);
    let available_tomorrow = (total_guards - scheduled_tomorrow).max(0);

    if total_guards > 0 {
        let availability_ratio = if total_guards > 0 {
            available_tomorrow as f64 / total_guards as f64
        } else {
            1.0
        };

        if available_tomorrow <= 3 || availability_ratio < 0.25 {
            let plural = if available_tomorrow == 1 {
                "guard"
            } else {
                "guards"
            };
            let message =
                format!("Only {available_tomorrow} {plural} unassigned for tomorrow's roster");

            alerts.push(PredictiveAlert {
                id: "guard-availability".to_string(),
                category: "capacity".to_string(),
                severity: if available_tomorrow <= 1 {
                    "critical".into()
                } else {
                    "warning".into()
                },
                message,
                detected_at: Utc::now(),
                context: json!({
                    "totalGuards": total_guards,
                    "scheduledTomorrow": scheduled_tomorrow,
                    "availableTomorrow": available_tomorrow,
                    "committedToday": guard_capacity.committed_today.unwrap_or(0),
                }),
            });
        }
    }

    fn severity_score(level: &str) -> i32 {
        match level {
            "critical" => 3,
            "warning" => 2,
            _ => 1,
        }
    }

    alerts.sort_by(|a, b| severity_score(&b.severity).cmp(&severity_score(&a.severity)));

    Ok(Json(alerts))
}

