use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::{FromRow, PgPool};

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardAbsenceRiskResult {
    pub guard_id: String,
    pub guard_name: String,
    pub risk_score: f64,
    pub risk_level: String,
    pub previous_absences: i64,
    pub late_checkins: i64,
    pub recent_leave_requests: i64,
    pub formula: String,
    pub calculated_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct GuardNameRow {
    guard_name: Option<String>,
}

#[derive(Debug, FromRow)]
struct CountRow {
    count: Option<i64>,
}

#[derive(Debug, FromRow)]
struct UpcomingGuardRow {
    guard_id: String,
}

async fn persist_absence_prediction(
    pool: &PgPool,
    prediction: &GuardAbsenceRiskResult,
) -> AppResult<()> {
    let lower_level = prediction.risk_level.to_lowercase();
    let feature_version = "absence-heuristic-v1";
    let explanation = json!({
        "formula": prediction.formula,
        "riskLevel": prediction.risk_level,
    });
    let w_absences = std::env::var("ABSENCE_WEIGHT_ABSENCES")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.5);
    let w_late = std::env::var("ABSENCE_WEIGHT_LATE")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.3);
    let w_leave = std::env::var("ABSENCE_WEIGHT_LEAVE")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.2);

    let contributing_factors = json!({
        "previousAbsences": prediction.previous_absences,
        "lateCheckins": prediction.late_checkins,
        "recentLeaveRequests": prediction.recent_leave_requests,
        "weights": {
            "previousAbsences": w_absences,
            "lateCheckins": w_late,
            "recentLeaveRequests": w_leave
        }
    });

    sqlx::query(
        r#"
        INSERT INTO guard_absence_predictions (
            id,
            guard_id,
            prediction_window_hours,
            risk_score,
            risk_level,
            confidence_score,
            explanation,
            contributing_factors,
            source_snapshot,
            generated_at,
            valid_until,
            feature_version,
            created_at,
            updated_at
        ) VALUES (
            $1, $2, 24, $3, $4, 0.75, $5, $6, $7, NOW(), NOW() + INTERVAL '24 hours', $8, NOW(), NOW()
        )
        "#,
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&prediction.guard_id)
    .bind(prediction.risk_score)
    .bind(lower_level)
    .bind(explanation)
    .bind(contributing_factors)
    .bind(json!({
        "calculatedAt": prediction.calculated_at,
        "guardName": prediction.guard_name,
    }))
    .bind(feature_version)
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to persist guard absence prediction: {}", e)))?;

    Ok(())
}

pub async fn calculate_absence_risk(
    pool: &PgPool,
    guard_id: &str,
) -> AppResult<GuardAbsenceRiskResult> {
    let guard_name_row = sqlx::query_as::<_, GuardNameRow>(
        r#"
        SELECT COALESCE(NULLIF(full_name, ''), username) AS guard_name
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(guard_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to load guard profile: {}", e)))?
    .ok_or_else(|| AppError::NotFound("Guard not found".to_string()))?;

    let previous_absences = sqlx::query_as::<_, CountRow>(
        r#"
        SELECT COUNT(*)::BIGINT AS count
        FROM punctuality_records
        WHERE guard_id = $1
          AND status = 'no_show'
          AND scheduled_start_time >= NOW() - INTERVAL '90 days'
        "#,
    )
    .bind(guard_id)
    .fetch_one(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to query absences: {}", e)))?
    .count
    .unwrap_or(0);

    let late_checkins = sqlx::query_as::<_, CountRow>(
        r#"
        SELECT COUNT(*)::BIGINT AS count
        FROM punctuality_records
        WHERE guard_id = $1
          AND status = 'late'
          AND scheduled_start_time >= NOW() - INTERVAL '90 days'
        "#,
    )
    .bind(guard_id)
    .fetch_one(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to query late check-ins: {}", e)))?
    .count
    .unwrap_or(0);

    let leave_unavailable = sqlx::query_as::<_, CountRow>(
        r#"
        SELECT COUNT(*)::BIGINT AS count
        FROM guard_availability
        WHERE guard_id = $1
          AND available = FALSE
          AND created_at >= NOW() - INTERVAL '30 days'
        "#,
    )
    .bind(guard_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to query availability leave signals: {}", e))
    })?
    .count
    .unwrap_or(0);

    let leave_tickets = sqlx::query_as::<_, CountRow>(
        r#"
        SELECT COUNT(*)::BIGINT AS count
        FROM support_tickets
        WHERE guard_id = $1
          AND created_at >= NOW() - INTERVAL '30 days'
          AND (
            subject ILIKE '%leave%'
            OR subject ILIKE '%absence%'
            OR message ILIKE '%leave%'
            OR message ILIKE '%absence%'
          )
        "#,
    )
    .bind(guard_id)
    .fetch_one(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to query leave request tickets: {}", e)))?
    .count
    .unwrap_or(0);

    let recent_leave_requests = leave_unavailable + leave_tickets;

    let w_absences = std::env::var("ABSENCE_WEIGHT_ABSENCES")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.5);
    let w_late = std::env::var("ABSENCE_WEIGHT_LATE")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.3);
    let w_leave = std::env::var("ABSENCE_WEIGHT_LEAVE")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.2);

    let raw_score = (previous_absences as f64 * w_absences)
        + (late_checkins as f64 * w_late)
        + (recent_leave_requests as f64 * w_leave);

    let risk_level = if raw_score < 1.0 {
        "LOW"
    } else if raw_score < 2.0 {
        "MEDIUM"
    } else {
        "HIGH"
    };

    Ok(GuardAbsenceRiskResult {
        guard_id: guard_id.to_string(),
        guard_name: guard_name_row.guard_name.unwrap_or_else(|| "Guard".to_string()),
        risk_score: (raw_score * 100.0).round() / 100.0,
        risk_level: risk_level.to_string(),
        previous_absences,
        late_checkins,
        recent_leave_requests,
        formula: format!("AbsenceRisk = (previous_absences * {w_absences}) + (late_checkins * {w_late}) + (recent_leave_requests * {w_leave})"),
        calculated_at: Utc::now(),
    })
}

pub async fn calculate_upcoming_shift_absence_risks(
    pool: &PgPool,
) -> AppResult<Vec<GuardAbsenceRiskResult>> {
    let guards = sqlx::query_as::<_, UpcomingGuardRow>(
        r#"
        SELECT DISTINCT s.guard_id
        FROM shifts s
        WHERE s.start_time >= NOW()
          AND s.start_time <= NOW() + INTERVAL '48 hours'
          AND s.status IN ('scheduled', 'in_progress')
        ORDER BY s.guard_id ASC
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to query upcoming shift guards: {}", e))
    })?;

    let mut results = Vec::new();
    for guard in guards {
        let prediction = calculate_absence_risk(pool, &guard.guard_id).await?;
        persist_absence_prediction(pool, &prediction).await?;
        results.push(prediction);
    }

    results.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.guard_name.cmp(&b.guard_name))
    });

    Ok(results)
}
