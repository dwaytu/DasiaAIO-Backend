use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    error::AppResult,
    services::{
        guard_prediction_service,
        incident_ai_classifier,
        incident_summary_service,
        replacement_ai_service,
        vehicle_predictive_service,
    },
    utils,
};

#[derive(Debug, Deserialize)]
pub struct ReplacementSuggestionsQuery {
    pub post_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ClassifyIncidentRequest {
    pub title: Option<String>,
    pub description: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassifyIncidentResponse {
    pub severity: String,
}

#[derive(Debug, Deserialize)]
pub struct SummarizeIncidentRequest {
    pub description: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SummarizeIncidentResponse {
    pub summary: String,
    pub key_phrases: Vec<String>,
}

pub async fn get_guard_absence_risk(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<guard_prediction_service::GuardAbsenceRiskResult>>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let rows = guard_prediction_service::calculate_upcoming_shift_absence_risks(db.as_ref()).await?;
    Ok(Json(rows))
}

pub async fn get_replacement_suggestions(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Query(query): Query<ReplacementSuggestionsQuery>,
) -> AppResult<Json<Vec<replacement_ai_service::ReplacementSuggestion>>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let rows = replacement_ai_service::suggest_replacement(db.as_ref(), &query.post_id).await?;
    Ok(Json(rows))
}

pub async fn classify_incident(
    headers: HeaderMap,
    Json(payload): Json<ClassifyIncidentRequest>,
) -> AppResult<Json<ClassifyIncidentResponse>> {
    let _claims = utils::require_min_role(&headers, "guard")?;

    let normalized_description = payload.description.trim();
    let merged_text = if let Some(title) = payload.title.as_ref() {
        format!("{} {}", title.trim(), normalized_description)
    } else {
        normalized_description.to_string()
    };

    let severity = incident_ai_classifier::classify_incident(&merged_text);
    Ok(Json(ClassifyIncidentResponse { severity }))
}

pub async fn summarize_incident(
    headers: HeaderMap,
    Json(payload): Json<SummarizeIncidentRequest>,
) -> AppResult<Json<SummarizeIncidentResponse>> {
    let _claims = utils::require_min_role(&headers, "guard")?;

    let summary = incident_summary_service::summarize_incident(&payload.description);
    let key_phrases = incident_summary_service::extract_key_phrases(&payload.description);

    Ok(Json(SummarizeIncidentResponse {
        summary,
        key_phrases,
    }))
}

pub async fn get_vehicle_maintenance_risk(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<vehicle_predictive_service::VehicleMaintenanceRiskResult>>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let rows = vehicle_predictive_service::predict_fleet_vehicle_risk(db.as_ref()).await?;
    Ok(Json(rows))
}
