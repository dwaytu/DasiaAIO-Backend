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
        guard_prediction_service, incident_ai_classifier, incident_summary_service,
        replacement_ai_service, vehicle_predictive_service,
    },
    utils,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacementSuggestionsQuery {
    pub post_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassifyIncidentRequest {
    pub title: Option<String>,
    pub description: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassifyIncidentResponse {
    pub risk_level: String,
    pub severity: String,
    pub confidence: f64,
    pub explanation: String,
    pub suggested_actions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummarizeIncidentRequest {
    pub description: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SummarizeIncidentResponse {
    pub risk_level: String,
    pub confidence: f64,
    pub explanation: String,
    pub suggested_actions: Vec<String>,
    pub summary: String,
    pub key_phrases: Vec<String>,
}

fn confidence_from_severity(severity: &str) -> f64 {
    match severity.to_lowercase().as_str() {
        "critical" => 0.94,
        "high" => 0.88,
        "medium" => 0.79,
        "low" => 0.71,
        _ => 0.65,
    }
}



fn suggested_actions_from_severity(severity: &str) -> Vec<String> {
    match severity.to_lowercase().as_str() {
        "critical" => vec![
            "Escalate incident to command lead immediately.".to_string(),
            "Dispatch nearest verified response team to location.".to_string(),
            "Lock down nearby high-risk assets until cleared.".to_string(),
        ],
        "high" => vec![
            "Assign supervisor review within the next 5 minutes.".to_string(),
            "Verify guard presence and asset status on site.".to_string(),
            "Prepare contingency staffing if status worsens.".to_string(),
        ],
        "medium" => vec![
            "Monitor the incident channel and validate updates.".to_string(),
            "Capture additional evidence in the next patrol cycle.".to_string(),
        ],
        _ => vec![
            "Track the incident for trend analysis.".to_string(),
            "Include this event in shift handoff notes.".to_string(),
        ],
    }
}

fn explanation_from_context(description: &str, severity: &str) -> String {
    let clue_count = description
        .split_whitespace()
        .filter(|token| token.len() >= 5)
        .count();

    format!(
        "Severity '{}' was inferred from incident wording and {} contextual signal(s).",
        severity, clue_count
    )
}

fn risk_level_from_summary(summary: &str, key_phrases: &[String]) -> String {
    let summary_lc = summary.to_lowercase();
    let phrase_lc: Vec<String> = key_phrases.iter().map(|item| item.to_lowercase()).collect();

    if summary_lc.contains("critical")
        || phrase_lc.iter().any(|item| {
            item.contains("critical") || item.contains("weapon") || item.contains("injury")
        })
    {
        return "critical".to_string();
    }
    if summary_lc.contains("high")
        || phrase_lc
            .iter()
            .any(|item| item.contains("breach") || item.contains("unauthorized"))
    {
        return "high".to_string();
    }
    if summary_lc.contains("medium")
        || phrase_lc
            .iter()
            .any(|item| item.contains("delay") || item.contains("warning"))
    {
        return "medium".to_string();
    }
    "low".to_string()
}

pub async fn get_guard_absence_risk(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<guard_prediction_service::GuardAbsenceRiskResult>>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let rows =
        guard_prediction_service::calculate_upcoming_shift_absence_risks(db.as_ref()).await?;
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

    let result = incident_ai_classifier::classify_incident_smart(&merged_text).await;
    let explanation = format!(
        "Severity '{}' classified via {} with {:.0}% confidence based on incident wording and {} contextual token(s).",
        result.severity,
        result.source,
        result.confidence * 100.0,
        merged_text.split_whitespace().filter(|t| t.len() >= 5).count()
    );
    let suggested_actions = suggested_actions_from_severity(&result.severity);

    Ok(Json(ClassifyIncidentResponse {
        risk_level: result.severity.clone(),
        severity: result.severity,
        confidence: result.confidence,
        explanation,
        suggested_actions,
    }))
}

pub async fn summarize_incident(
    headers: HeaderMap,
    Json(payload): Json<SummarizeIncidentRequest>,
) -> AppResult<Json<SummarizeIncidentResponse>> {
    let _claims = utils::require_min_role(&headers, "guard")?;

    let summary = incident_summary_service::summarize_incident(&payload.description);
    let key_phrases = incident_summary_service::extract_key_phrases(&payload.description);
    let risk_level = risk_level_from_summary(&summary, &key_phrases);
    let confidence = confidence_from_severity(&risk_level);
    let explanation = format!(
        "Summary confidence is based on extracted terms and sentence consistency ({} key phrase(s)).",
        key_phrases.len()
    );
    let suggested_actions = suggested_actions_from_severity(&risk_level);

    Ok(Json(SummarizeIncidentResponse {
        risk_level,
        confidence,
        explanation,
        suggested_actions,
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
