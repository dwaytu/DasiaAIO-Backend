use axum::{
    extract::ws::{Message, WebSocket},
    extract::State,
    extract::{Path, Query, WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::Response,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgPool, Row};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::sync::broadcast;

use crate::{
    error::{AppError, AppResult},
    utils,
};

const CLIENT_PROXIMITY_RADIUS_KM: f64 = 1.0;
const PRE_SHIFT_ALERT_WINDOW_MINUTES: i64 = 60;
const PROXIMITY_ALERT_DEDUPE_MINUTES: i64 = 45;
const GEOFENCE_EVENT_DEDUPE_MINUTES: i64 = 5;
const ACTIVE_GUARD_WINDOW_MINUTES: i64 = 15;
const MOVING_SPEED_THRESHOLD_KPH: f64 = 2.0;
const MAX_GEOFENCE_RADIUS_KM: f64 = 25.0;

fn tracking_accuracy_mode() -> String {
    std::env::var("TRACKING_ACCURACY_MODE")
        .unwrap_or_else(|_| "strict".to_string())
        .to_lowercase()
}

fn parse_env_f64(key: &str) -> Option<f64> {
    std::env::var(key).ok().and_then(|v| v.parse::<f64>().ok())
}

fn parse_env_i64(key: &str) -> Option<i64> {
    std::env::var(key).ok().and_then(|v| v.parse::<i64>().ok())
}

fn required_accuracy_meters() -> f64 {
    if let Some(value) = parse_env_f64("TRACKING_REQUIRED_ACCURACY_METERS") {
        return value;
    }

    if tracking_accuracy_mode() == "balanced" {
        35.0
    } else {
        20.0
    }
}

fn person_recency_minutes() -> i64 {
    if let Some(value) = parse_env_i64("TRACKING_PERSON_RECENCY_MINUTES") {
        return value;
    }

    if tracking_accuracy_mode() == "balanced" {
        8
    } else {
        3
    }
}

fn vehicle_recency_minutes() -> i64 {
    if let Some(value) = parse_env_i64("TRACKING_VEHICLE_RECENCY_MINUTES") {
        return value;
    }

    if tracking_accuracy_mode() == "balanced" {
        20
    } else {
        10
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackingWsAuthQuery {
    pub token: Option<String>,
}

fn extract_ws_token_from_protocols(headers: &HeaderMap) -> Option<String> {
    let protocols = headers
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())?;

    for protocol in protocols.split(',').map(|value| value.trim()) {
        if let Some(token) = protocol.strip_prefix("bearer.") {
            if !token.trim().is_empty() {
                return Some(token.trim().to_string());
            }
        }
    }

    None
}

fn has_requested_ws_protocol(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        .map(|protocols| {
            protocols
                .split(',')
                .map(|value| value.trim())
                .any(|value| value.eq_ignore_ascii_case(expected))
        })
        .unwrap_or(false)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct UpsertClientSiteRequest {
    pub name: String,
    pub address: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    pub is_active: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeofenceVertex {
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct UpsertGeofenceZoneRequest {
    pub zone_type: String,
    pub radius_km: Option<f64>,
    pub polygon_points: Option<Vec<GeofenceVertex>>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct TrackPointRequest {
    pub entity_type: String,
    pub entity_id: String,
    pub label: Option<String>,
    pub status: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    pub heading: Option<f64>,
    pub speed_kph: Option<f64>,
    pub accuracy_meters: Option<f64>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct GuardHistoryQuery {
    pub limit: Option<i64>,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct ActiveGuardsQuery {
    pub window_minutes: Option<i64>,
}

fn active_ws_connections() -> &'static AtomicUsize {
    static ACTIVE_WS_CONNECTIONS: OnceLock<AtomicUsize> = OnceLock::new();
    ACTIVE_WS_CONNECTIONS.get_or_init(|| AtomicUsize::new(0))
}

pub fn active_websocket_connections() -> usize {
    active_ws_connections().load(Ordering::Relaxed)
}

fn tracking_bus() -> &'static broadcast::Sender<String> {
    static BUS: OnceLock<broadcast::Sender<String>> = OnceLock::new();
    BUS.get_or_init(|| {
        let (tx, _) = broadcast::channel(256);
        tx
    })
}

fn publish_tracking_event(event_key: &str) {
    let _ = tracking_bus().send(event_key.to_string());
}

fn validate_coordinates(latitude: f64, longitude: f64) -> AppResult<()> {
    if !(-90.0..=90.0).contains(&latitude) || !(-180.0..=180.0).contains(&longitude) {
        return Err(AppError::BadRequest(
            "Invalid latitude or longitude".to_string(),
        ));
    }
    Ok(())
}

fn parse_optional_rfc3339(
    value: Option<&str>,
    field_name: &str,
) -> AppResult<Option<DateTime<Utc>>> {
    let Some(raw) = value else {
        return Ok(None);
    };

    if raw.trim().is_empty() {
        return Ok(None);
    }

    DateTime::parse_from_rfc3339(raw.trim())
        .map(|value| value.with_timezone(&Utc))
        .map(Some)
        .map_err(|_| {
            AppError::BadRequest(format!(
                "Invalid {} value. Expected RFC3339 timestamp.",
                field_name
            ))
        })
}

fn is_guard_entity(entity_type: &str) -> bool {
    matches!(entity_type, "guard" | "user")
}

fn derive_movement_status(
    status: Option<&str>,
    speed_kph: Option<f64>,
    recorded_at: DateTime<Utc>,
) -> &'static str {
    let age_minutes = (Utc::now() - recorded_at).num_minutes();
    if age_minutes > person_recency_minutes() {
        return "offline";
    }

    let normalized_status = status.unwrap_or_default().trim().to_lowercase();
    if matches!(
        normalized_status.as_str(),
        "moving" | "in_transit" | "patrolling"
    ) {
        return "moving";
    }

    if speed_kph.unwrap_or(0.0) >= MOVING_SPEED_THRESHOLD_KPH {
        "moving"
    } else {
        "idle"
    }
}

fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let earth_radius_km = 6371.0_f64;
    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();
    let a = (d_lat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (d_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    earth_radius_km * c
}

fn point_in_polygon(latitude: f64, longitude: f64, vertices: &[GeofenceVertex]) -> bool {
    if vertices.len() < 3 {
        return false;
    }

    let mut inside = false;
    let mut prev_idx = vertices.len() - 1;

    for (idx, vertex) in vertices.iter().enumerate() {
        let prev = &vertices[prev_idx];
        let intersect = ((vertex.longitude > longitude) != (prev.longitude > longitude))
            && (latitude
                < (prev.latitude - vertex.latitude) * (longitude - vertex.longitude)
                    / ((prev.longitude - vertex.longitude).abs().max(f64::EPSILON))
                    + vertex.latitude);

        if intersect {
            inside = !inside;
        }

        prev_idx = idx;
    }

    inside
}

fn parse_polygon_points(value: Option<serde_json::Value>) -> Option<Vec<GeofenceVertex>> {
    value.and_then(|raw| serde_json::from_value::<Vec<GeofenceVertex>>(raw).ok())
}

fn validate_geofence_payload(
    payload: &UpsertGeofenceZoneRequest,
) -> AppResult<(String, Option<f64>, Option<serde_json::Value>, bool)> {
    let zone_type = payload.zone_type.trim().to_lowercase();
    let is_active = payload.is_active.unwrap_or(true);

    if zone_type == "radius" {
        let radius_km = payload.radius_km.unwrap_or(CLIENT_PROXIMITY_RADIUS_KM);
        if !(radius_km > 0.0 && radius_km <= MAX_GEOFENCE_RADIUS_KM) {
            return Err(AppError::BadRequest(format!(
                "radiusKm must be > 0 and <= {}",
                MAX_GEOFENCE_RADIUS_KM
            )));
        }

        return Ok((zone_type, Some(radius_km), None, is_active));
    }

    if zone_type == "polygon" {
        let Some(points) = payload.polygon_points.as_ref() else {
            return Err(AppError::BadRequest(
                "polygonPoints are required for polygon zones".to_string(),
            ));
        };

        if points.len() < 3 {
            return Err(AppError::BadRequest(
                "polygonPoints must include at least 3 coordinates".to_string(),
            ));
        }

        for point in points {
            validate_coordinates(point.latitude, point.longitude)?;
        }

        let polygon_json = serde_json::to_value(points).map_err(|e| {
            AppError::BadRequest(format!("Failed to serialize polygon points: {}", e))
        })?;

        return Ok((zone_type, None, Some(polygon_json), is_active));
    }

    Err(AppError::BadRequest(
        "zoneType must be either 'radius' or 'polygon'".to_string(),
    ))
}

#[derive(sqlx::FromRow)]
struct ShiftProximityCandidate {
    shift_id: String,
    guard_id: String,
    guard_name: Option<String>,
    client_site: String,
    start_time: chrono::DateTime<chrono::Utc>,
    client_latitude: f64,
    client_longitude: f64,
    guard_latitude: Option<f64>,
    guard_longitude: Option<f64>,
}

#[derive(sqlx::FromRow)]
struct LeadershipRecipient {
    id: String,
}

#[derive(sqlx::FromRow)]
struct GeofenceEvaluationZone {
    site_id: String,
    site_name: String,
    site_latitude: f64,
    site_longitude: f64,
    geofence_id: Option<String>,
    zone_type: Option<String>,
    radius_km: Option<f64>,
    polygon_points: Option<serde_json::Value>,
}

#[derive(sqlx::FromRow)]
struct RecentTrackPoint {
    latitude: f64,
    longitude: f64,
}

async fn evaluate_geofence_transitions(
    db: &PgPool,
    entity_type: &str,
    entity_id: &str,
    label: Option<&str>,
) -> AppResult<Vec<serde_json::Value>> {
    if !is_guard_entity(entity_type) {
        return Ok(Vec::new());
    }

    let recent_points = sqlx::query_as::<_, RecentTrackPoint>(
        r#"SELECT latitude, longitude
           FROM tracking_points
           WHERE entity_type = $1
             AND entity_id = $2
           ORDER BY recorded_at DESC
           LIMIT 2"#,
    )
    .bind(entity_type)
    .bind(entity_id)
    .fetch_all(db)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to fetch geofence comparison points: {}", e))
    })?;

    if recent_points.len() < 2 {
        return Ok(Vec::new());
    }

    let current = &recent_points[0];
    let previous = &recent_points[1];

    let zones = sqlx::query_as::<_, GeofenceEvaluationZone>(
        r#"SELECT
               cs.id AS site_id,
               cs.name AS site_name,
               cs.latitude AS site_latitude,
               cs.longitude AS site_longitude,
               sg.id AS geofence_id,
               sg.zone_type,
               sg.radius_km,
               sg.polygon_points
           FROM client_sites cs
           LEFT JOIN site_geofences sg
             ON sg.client_site_id = cs.id
            AND sg.is_active = true
           WHERE cs.is_active = true
           ORDER BY cs.created_at DESC"#,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch geofence zones: {}", e)))?;

    if zones.is_empty() {
        return Ok(Vec::new());
    }

    let leadership = sqlx::query_as::<_, LeadershipRecipient>(
        r#"SELECT id
           FROM users
           WHERE LOWER(role) IN ('superadmin', 'admin', 'supervisor')
             AND verified = true"#,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch geofence recipients: {}", e)))?;

    let mut transitions = Vec::new();
    let guard_label = label.unwrap_or(entity_id);

    for zone in zones {
        let zone_type = zone
            .zone_type
            .as_deref()
            .unwrap_or("radius")
            .trim()
            .to_lowercase();

        let current_distance = haversine_km(
            current.latitude,
            current.longitude,
            zone.site_latitude,
            zone.site_longitude,
        );

        let previous_distance = haversine_km(
            previous.latitude,
            previous.longitude,
            zone.site_latitude,
            zone.site_longitude,
        );

        let (current_inside, previous_inside, zone_radius) = if zone_type == "polygon" {
            let Some(vertices) = parse_polygon_points(zone.polygon_points.clone()) else {
                continue;
            };

            (
                point_in_polygon(current.latitude, current.longitude, &vertices),
                point_in_polygon(previous.latitude, previous.longitude, &vertices),
                None,
            )
        } else {
            let radius_km = zone.radius_km.unwrap_or(CLIENT_PROXIMITY_RADIUS_KM);
            (
                current_distance <= radius_km,
                previous_distance <= radius_km,
                Some(radius_km),
            )
        };

        if current_inside == previous_inside {
            continue;
        }

        let event_type = if current_inside { "enter" } else { "exit" };

        let duplicate_count = sqlx::query_scalar::<_, i64>(
            r#"SELECT COUNT(*)
               FROM geofence_events
               WHERE guard_id = $1
                 AND client_site_id = $2
                 AND event_type = $3
                 AND created_at >= (CURRENT_TIMESTAMP - ($4 || ' minutes')::interval)"#,
        )
        .bind(entity_id)
        .bind(&zone.site_id)
        .bind(event_type)
        .bind(GEOFENCE_EVENT_DEDUPE_MINUTES.to_string())
        .fetch_one(db)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to dedupe geofence events: {}", e)))?;

        if duplicate_count > 0 {
            continue;
        }

        let event_id = utils::generate_id();
        let zone_descriptor = if zone_type == "polygon" {
            "polygon zone".to_string()
        } else {
            format!(
                "{:.2} km radius zone",
                zone_radius.unwrap_or(CLIENT_PROXIMITY_RADIUS_KM)
            )
        };

        let message = if event_type == "enter" {
            format!(
                "{} entered geofence '{}' ({}). Distance {:.2} km.",
                guard_label, zone.site_name, zone_descriptor, current_distance
            )
        } else {
            format!(
                "{} exited geofence '{}' ({}). Distance {:.2} km.",
                guard_label, zone.site_name, zone_descriptor, current_distance
            )
        };

        sqlx::query(
            r#"INSERT INTO geofence_events (
                    id,
                    guard_id,
                    client_site_id,
                    event_type,
                    latitude,
                    longitude,
                    distance_km,
                    message
               ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(&event_id)
        .bind(entity_id)
        .bind(&zone.site_id)
        .bind(event_type)
        .bind(current.latitude)
        .bind(current.longitude)
        .bind(current_distance)
        .bind(&message)
        .execute(db)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to store geofence event: {}", e)))?;

        for recipient in &leadership {
            let notification_id = utils::generate_id();
            sqlx::query(
                r#"INSERT INTO notifications (id, user_id, title, message, type, read)
                   VALUES ($1, $2, $3, $4, 'geofence_alert', false)"#,
            )
            .bind(&notification_id)
            .bind(&recipient.id)
            .bind("Geofence Transition")
            .bind(&message)
            .execute(db)
            .await
            .map_err(|e| {
                AppError::DatabaseError(format!("Failed to notify geofence transition: {}", e))
            })?;
        }

        transitions.push(json!({
            "eventId": event_id,
            "eventType": event_type,
            "guardId": entity_id,
            "guardLabel": guard_label,
            "siteId": zone.site_id,
            "siteName": zone.site_name,
            "geofenceId": zone.geofence_id,
            "zoneType": zone_type,
            "radiusKm": zone_radius,
            "distanceKm": current_distance,
            "message": message,
        }));
    }

    Ok(transitions)
}

async fn evaluate_and_send_proximity_alerts(db: &PgPool) -> AppResult<(usize, usize)> {
    let candidates = sqlx::query_as::<_, ShiftProximityCandidate>(
        r#"SELECT
               s.id AS shift_id,
               s.guard_id,
               COALESCE(NULLIF(u.full_name, ''), u.username) AS guard_name,
               s.client_site,
               s.start_time,
               cs.latitude AS client_latitude,
               cs.longitude AS client_longitude,
               last_tp.latitude AS guard_latitude,
               last_tp.longitude AS guard_longitude
           FROM shifts s
           JOIN users u ON u.id = s.guard_id
           JOIN client_sites cs
             ON LOWER(TRIM(cs.name)) = LOWER(TRIM(s.client_site))
            AND cs.is_active = true
           LEFT JOIN LATERAL (
               SELECT tp.latitude, tp.longitude, tp.recorded_at
               FROM tracking_points tp
               WHERE tp.entity_id = s.guard_id
                 AND tp.entity_type IN ('guard')
               ORDER BY tp.recorded_at DESC
               LIMIT 1
           ) last_tp ON true
           WHERE s.status = 'scheduled'
             AND s.start_time > CURRENT_TIMESTAMP
                         AND s.start_time <= (CURRENT_TIMESTAMP + ($1 || ' minutes')::interval)"#,
    )
    .bind(PRE_SHIFT_ALERT_WINDOW_MINUTES.to_string())
    .fetch_all(db)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to evaluate shift proximity candidates: {}",
            e
        ))
    })?;

    if candidates.is_empty() {
        return Ok((0, 0));
    }

    let leadership = sqlx::query_as::<_, LeadershipRecipient>(
        r#"SELECT id
           FROM users
           WHERE LOWER(role) IN ('superadmin', 'admin', 'supervisor')
             AND verified = true"#,
    )
    .fetch_all(db)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to fetch leadership recipients: {}", e))
    })?;

    if leadership.is_empty() {
        return Ok((0, 0));
    }

    let mut risky_shifts = 0usize;
    let mut notifications_created = 0usize;

    for candidate in candidates {
        let guard_distance_km = match (candidate.guard_latitude, candidate.guard_longitude) {
            (Some(guard_lat), Some(guard_lon)) => haversine_km(
                guard_lat,
                guard_lon,
                candidate.client_latitude,
                candidate.client_longitude,
            ),
            _ => f64::INFINITY,
        };

        if guard_distance_km <= CLIENT_PROXIMITY_RADIUS_KM {
            continue;
        }

        risky_shifts += 1;

        let guard_label = candidate
            .guard_name
            .clone()
            .unwrap_or_else(|| "Assigned guard".to_string());

        let distance_text = if guard_distance_km.is_finite() {
            format!("{:.2} km", guard_distance_km)
        } else {
            "unknown distance (no recent location)".to_string()
        };

        for recipient in &leadership {
            let already_notified = sqlx::query_scalar::<_, i64>(
                r#"SELECT COUNT(*)
                   FROM notifications
                   WHERE user_id = $1
                     AND type = 'proximity_alert'
                     AND related_shift_id = $2
                     AND created_at >= (CURRENT_TIMESTAMP - ($3 || ' minutes')::interval)"#,
            )
            .bind(&recipient.id)
            .bind(&candidate.shift_id)
            .bind(PROXIMITY_ALERT_DEDUPE_MINUTES.to_string())
            .fetch_one(db)
            .await
            .map_err(|e| {
                AppError::DatabaseError(format!(
                    "Failed to check duplicate proximity alerts: {}",
                    e
                ))
            })?;

            if already_notified > 0 {
                continue;
            }

            let notification_id = utils::generate_id();
            sqlx::query(
                r#"INSERT INTO notifications (id, user_id, title, message, type, related_shift_id, read)
                   VALUES ($1, $2, $3, $4, 'proximity_alert', $5, false)"#,
            )
            .bind(&notification_id)
            .bind(&recipient.id)
            .bind("Guard Arrival Risk")
            .bind(format!(
                "{} is not yet within 1 km of client site '{}' one hour before shift start. Current distance: {}.",
                guard_label,
                candidate.client_site,
                distance_text
            ))
            .bind(&candidate.shift_id)
            .execute(db)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to create proximity alert notification: {}", e)))?;

            notifications_created += 1;
        }
    }

    Ok((risky_shifts, notifications_created))
}

async fn fetch_map_snapshot(
    db: &PgPool,
    claims: &utils::TokenClaims,
) -> AppResult<serde_json::Value> {
    let role = utils::normalize_role(&claims.role);
    let required_accuracy = required_accuracy_meters();
    let person_recency = person_recency_minutes();
    let vehicle_recency = vehicle_recency_minutes();

    let client_sites = sqlx::query(
        r#"SELECT id, name, address, latitude, longitude, is_active
           FROM client_sites
           WHERE is_active = true
           ORDER BY created_at DESC"#,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch client sites: {}", e)))?;

    let tracking_points = if role == "guard" {
        sqlx::query(
                        r#"SELECT id, entity_type, entity_id, user_id, label, status, latitude, longitude, heading, speed_kph, accuracy_meters, recorded_at
                             FROM tracking_points
                             WHERE entity_type IN ('guard')
                                 AND entity_id = $1
                                 AND recorded_at >= (CURRENT_TIMESTAMP - ($2 || ' minutes')::interval)
                                 AND accuracy_meters IS NOT NULL
                                 AND accuracy_meters <= $3
                             ORDER BY recorded_at DESC
                             LIMIT 1"#,
        )
        .bind(&claims.sub)
        .bind(person_recency.to_string())
        .bind(required_accuracy)
        .fetch_all(db)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to fetch guard tracking points: {}", e)))?
    } else {
        sqlx::query(
                        r#"WITH ranked_points AS (
                                     SELECT
                                         id,
                                         entity_type,
                                         entity_id,
                                         user_id,
                                         label,
                                         status,
                                         latitude,
                                         longitude,
                                         heading,
                                         speed_kph,
                                         accuracy_meters,
                                         recorded_at,
                                         ROW_NUMBER() OVER (
                                             PARTITION BY entity_type, entity_id
                                             ORDER BY recorded_at DESC
                                         ) AS rn
                                     FROM tracking_points
                                     WHERE (
                                         entity_type IN ('guard')
                                         AND recorded_at >= (CURRENT_TIMESTAMP - ($1 || ' minutes')::interval)
                                         AND accuracy_meters IS NOT NULL
                                         AND accuracy_meters <= $2
                                     )
                                     OR (
                                         entity_type = 'vehicle'
                                         AND recorded_at >= (CURRENT_TIMESTAMP - ($3 || ' minutes')::interval)
                                     )
                             )
                             SELECT
                                 id, entity_type, entity_id, user_id, label, status, latitude, longitude, heading, speed_kph, accuracy_meters, recorded_at
                             FROM ranked_points
                             WHERE rn = 1
                             ORDER BY entity_type, entity_id
               LIMIT 300"#,
        )
        .bind(person_recency.to_string())
        .bind(required_accuracy)
        .bind(vehicle_recency.to_string())
        .fetch_all(db)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to fetch tracking points: {}", e)))?
    };

    let sites_payload: Vec<serde_json::Value> = client_sites
        .into_iter()
        .map(|row| {
            json!({
                "id": row.try_get::<String, _>("id").unwrap_or_default(),
                "name": row.try_get::<String, _>("name").unwrap_or_default(),
                "address": row.try_get::<Option<String>, _>("address").unwrap_or(None),
                "latitude": row.try_get::<f64, _>("latitude").unwrap_or(0.0),
                "longitude": row.try_get::<f64, _>("longitude").unwrap_or(0.0),
                "isActive": row.try_get::<bool, _>("is_active").unwrap_or(true),
            })
        })
        .collect();

    let geofence_zones = sqlx::query(
        r#"SELECT
               sg.id,
               sg.client_site_id,
               cs.name AS site_name,
               sg.zone_type,
               sg.radius_km,
               sg.polygon_points,
               sg.is_active,
               sg.created_at,
               sg.updated_at
           FROM site_geofences sg
           JOIN client_sites cs ON cs.id = sg.client_site_id
           WHERE sg.is_active = true
             AND cs.is_active = true
           ORDER BY sg.created_at DESC
           LIMIT 500"#,
    )
    .fetch_all(db)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to fetch geofence zones for map: {}", e))
    })?;

    let geofence_zone_payload: Vec<serde_json::Value> = geofence_zones
        .into_iter()
        .map(|row| {
            json!({
                "id": row.try_get::<String, _>("id").unwrap_or_default(),
                "siteId": row.try_get::<String, _>("client_site_id").unwrap_or_default(),
                "siteName": row.try_get::<String, _>("site_name").unwrap_or_default(),
                "zoneType": row.try_get::<String, _>("zone_type").unwrap_or_default(),
                "radiusKm": row.try_get::<Option<f64>, _>("radius_km").unwrap_or(None),
                "polygonPoints": row.try_get::<Option<serde_json::Value>, _>("polygon_points").unwrap_or(None),
                "isActive": row.try_get::<bool, _>("is_active").unwrap_or(true),
                "createdAt": row
                    .try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
                "updatedAt": row
                    .try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
            })
        })
        .collect();

    let points_payload: Vec<serde_json::Value> = tracking_points
        .into_iter()
        .map(|row| {
            let recorded_at = row
                .try_get::<chrono::DateTime<chrono::Utc>, _>("recorded_at")
                .ok();
            let status = row
                .try_get::<Option<String>, _>("status")
                .unwrap_or(None);
            let speed_kph = row.try_get::<Option<f64>, _>("speed_kph").unwrap_or(None);

            json!({
                "id": row.try_get::<String, _>("id").unwrap_or_default(),
                "entityType": row.try_get::<String, _>("entity_type").unwrap_or_default(),
                "entityId": row.try_get::<String, _>("entity_id").unwrap_or_default(),
                "userId": row.try_get::<Option<String>, _>("user_id").unwrap_or(None),
                "label": row.try_get::<Option<String>, _>("label").unwrap_or(None),
                "status": status,
                "latitude": row.try_get::<f64, _>("latitude").unwrap_or(0.0),
                "longitude": row.try_get::<f64, _>("longitude").unwrap_or(0.0),
                "heading": row.try_get::<Option<f64>, _>("heading").unwrap_or(None),
                "speedKph": speed_kph,
                "accuracyMeters": row.try_get::<Option<f64>, _>("accuracy_meters").unwrap_or(None),
                "movementStatus": recorded_at
                    .map(|recorded| derive_movement_status(status.as_deref(), speed_kph, recorded).to_string())
                    .unwrap_or_else(|| "offline".to_string()),
                "recordedAt": recorded_at
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
            })
        })
        .collect();

    let geofence_events = if role == "guard" {
        sqlx::query(
            r#"SELECT ge.id, ge.guard_id, ge.event_type, ge.distance_km, ge.message, ge.created_at,
                      cs.id AS site_id, cs.name AS site_name,
                      COALESCE(NULLIF(u.full_name, ''), u.username) AS guard_name
               FROM geofence_events ge
               JOIN client_sites cs ON cs.id = ge.client_site_id
               LEFT JOIN users u ON u.id = ge.guard_id
               WHERE ge.guard_id = $1
                 AND ge.created_at >= (CURRENT_TIMESTAMP - INTERVAL '8 hours')
               ORDER BY ge.created_at DESC
               LIMIT 30"#,
        )
        .bind(&claims.sub)
        .fetch_all(db)
        .await
        .map_err(|e| {
            AppError::DatabaseError(format!("Failed to fetch guard geofence alerts: {}", e))
        })?
    } else {
        sqlx::query(
            r#"SELECT ge.id, ge.guard_id, ge.event_type, ge.distance_km, ge.message, ge.created_at,
                      cs.id AS site_id, cs.name AS site_name,
                      COALESCE(NULLIF(u.full_name, ''), u.username) AS guard_name
               FROM geofence_events ge
               JOIN client_sites cs ON cs.id = ge.client_site_id
               LEFT JOIN users u ON u.id = ge.guard_id
               WHERE ge.created_at >= (CURRENT_TIMESTAMP - INTERVAL '8 hours')
               ORDER BY ge.created_at DESC
               LIMIT 80"#,
        )
        .fetch_all(db)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to fetch geofence alerts: {}", e)))?
    };

    let geofence_payload: Vec<serde_json::Value> = geofence_events
        .into_iter()
        .map(|row| {
            json!({
                "id": row.try_get::<String, _>("id").unwrap_or_default(),
                "guardId": row.try_get::<String, _>("guard_id").unwrap_or_default(),
                "guardName": row.try_get::<Option<String>, _>("guard_name").unwrap_or(None),
                "eventType": row.try_get::<String, _>("event_type").unwrap_or_default(),
                "siteId": row.try_get::<String, _>("site_id").unwrap_or_default(),
                "siteName": row.try_get::<String, _>("site_name").unwrap_or_default(),
                "distanceKm": row.try_get::<Option<f64>, _>("distance_km").unwrap_or(None),
                "message": row.try_get::<Option<String>, _>("message").unwrap_or(None),
                "createdAt": row
                    .try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
            })
        })
        .collect();

    Ok(json!({
        "clientSites": sites_payload,
        "geofenceZones": geofence_zone_payload,
        "trackingPoints": points_payload,
        "geofenceAlerts": geofence_payload,
    }))
}

async fn send_ws_snapshot(
    socket: &mut WebSocket,
    db: Arc<PgPool>,
    claims: utils::TokenClaims,
) -> Result<(), ()> {
    let snapshot = match fetch_map_snapshot(db.as_ref(), &claims).await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            tracing::warn!(
                user_id = %claims.sub,
                role = %claims.role,
                error = %error,
                "Failed to build tracking websocket snapshot"
            );
            return Err(());
        }
    };

    let payload = json!({ "type": "snapshot", "data": snapshot }).to_string();

    if let Err(error) = socket.send(Message::Text(payload)).await {
        tracing::debug!(
            user_id = %claims.sub,
            error = %error,
            "Failed to send tracking websocket snapshot"
        );
        return Err(());
    }

    Ok(())
}

async fn handle_tracking_ws(mut socket: WebSocket, db: Arc<PgPool>, claims: utils::TokenClaims) {
    let active_connections = active_ws_connections().fetch_add(1, Ordering::Relaxed) + 1;
    tracing::info!(user_id = %claims.sub, role = %claims.role, active_connections, "Tracking websocket connected");

    if send_ws_snapshot(&mut socket, db.clone(), claims.clone())
        .await
        .is_err()
    {
        tracing::warn!(
            user_id = %claims.sub,
            "Closing tracking websocket after initial snapshot failure"
        );
        active_ws_connections().fetch_sub(1, Ordering::Relaxed);
        return;
    }

    let mut rx = tracking_bus().subscribe();

    loop {
        tokio::select! {
            recv_result = socket.recv() => {
                match recv_result {
                    Some(Ok(Message::Close(_))) | None => {
                        tracing::info!(user_id = %claims.sub, "Tracking websocket closed by client");
                        break;
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            tracing::debug!(user_id = %claims.sub, "Tracking websocket pong send failed");
                            break;
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => {
                        tracing::warn!(user_id = %claims.sub, error = %error, "Tracking websocket receive error");
                        break;
                    }
                }
            }
            bus_result = rx.recv() => {
                match bus_result {
                    Ok(_) => {
                        if send_ws_snapshot(&mut socket, db.clone(), claims.clone()).await.is_err() {
                            tracing::debug!(user_id = %claims.sub, "Tracking websocket snapshot push failed");
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        tracing::warn!(user_id = %claims.sub, "Tracking event bus closed for websocket");
                        break;
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::debug!(user_id = %claims.sub, skipped, "Tracking websocket lagged on event bus");
                    }
                }
            }
        }
    }

    let active_remaining = active_ws_connections().fetch_sub(1, Ordering::Relaxed) - 1;
    tracing::info!(user_id = %claims.sub, active_connections = active_remaining, "Tracking websocket disconnected");
}

pub async fn get_guard_history(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(guard_id): Path<String>,
    Query(params): Query<GuardHistoryQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let token = utils::extract_bearer_token(&headers)?;
    let claims = utils::verify_token(&token)?;
    let role = utils::normalize_role(&claims.role);

    if role == "guard" && claims.sub != guard_id {
        return Err(AppError::Forbidden(
            "Guards can only view their own movement history".to_string(),
        ));
    }

    let limit = params.limit.unwrap_or(300).clamp(20, 1500);
    let from = parse_optional_rfc3339(params.from.as_deref(), "from")?;
    let to = parse_optional_rfc3339(params.to.as_deref(), "to")?;

    let rows = sqlx::query(
        r#"SELECT id, entity_type, entity_id, user_id, label, status, latitude, longitude,
                  heading, speed_kph, accuracy_meters, recorded_at
           FROM (
               SELECT id, entity_type, entity_id, user_id, label, status, latitude, longitude,
                      heading, speed_kph, accuracy_meters, recorded_at
               FROM tracking_points
               WHERE entity_type IN ('guard')
                 AND entity_id = $1
                 AND ($2::timestamptz IS NULL OR recorded_at >= $2)
                 AND ($3::timestamptz IS NULL OR recorded_at <= $3)
               ORDER BY recorded_at DESC
               LIMIT $4
           ) history
           ORDER BY recorded_at ASC"#,
    )
    .bind(&guard_id)
    .bind(from)
    .bind(to)
    .bind(limit)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch guard history: {}", e)))?;

    let points: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|row| {
            let recorded_at = row
                .try_get::<chrono::DateTime<chrono::Utc>, _>("recorded_at")
                .unwrap_or_else(|_| Utc::now());
            let status = row.try_get::<Option<String>, _>("status").unwrap_or(None);
            let speed_kph = row.try_get::<Option<f64>, _>("speed_kph").unwrap_or(None);

            json!({
                "id": row.try_get::<String, _>("id").unwrap_or_default(),
                "entityType": row.try_get::<String, _>("entity_type").unwrap_or_default(),
                "entityId": row.try_get::<String, _>("entity_id").unwrap_or_default(),
                "userId": row.try_get::<Option<String>, _>("user_id").unwrap_or(None),
                "label": row.try_get::<Option<String>, _>("label").unwrap_or(None),
                "status": status,
                "movementStatus": derive_movement_status(status.as_deref(), speed_kph, recorded_at),
                "latitude": row.try_get::<f64, _>("latitude").unwrap_or(0.0),
                "longitude": row.try_get::<f64, _>("longitude").unwrap_or(0.0),
                "heading": row.try_get::<Option<f64>, _>("heading").unwrap_or(None),
                "speedKph": speed_kph,
                "accuracyMeters": row.try_get::<Option<f64>, _>("accuracy_meters").unwrap_or(None),
                "recordedAt": recorded_at.to_rfc3339(),
                "ageSeconds": (Utc::now() - recorded_at).num_seconds().max(0),
            })
        })
        .collect();

    Ok(Json(json!({
        "guardId": guard_id,
        "points": points,
    })))
}

pub async fn get_guard_path(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(guard_id): Path<String>,
    Query(params): Query<GuardHistoryQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let token = utils::extract_bearer_token(&headers)?;
    let claims = utils::verify_token(&token)?;
    let role = utils::normalize_role(&claims.role);

    if role == "guard" && claims.sub != guard_id {
        return Err(AppError::Forbidden(
            "Guards can only view their own route path".to_string(),
        ));
    }

    let limit = params.limit.unwrap_or(600).clamp(30, 2000);
    let from = parse_optional_rfc3339(params.from.as_deref(), "from")?;
    let to = parse_optional_rfc3339(params.to.as_deref(), "to")?;

    let rows = sqlx::query(
        r#"SELECT latitude, longitude, speed_kph, status, recorded_at
           FROM (
               SELECT latitude, longitude, speed_kph, status, recorded_at
               FROM tracking_points
               WHERE entity_type IN ('guard')
                 AND entity_id = $1
                 AND ($2::timestamptz IS NULL OR recorded_at >= $2)
                 AND ($3::timestamptz IS NULL OR recorded_at <= $3)
               ORDER BY recorded_at DESC
               LIMIT $4
           ) route
           ORDER BY recorded_at ASC"#,
    )
    .bind(&guard_id)
    .bind(from)
    .bind(to)
    .bind(limit)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch guard path: {}", e)))?;

    let mut total_distance_km = 0.0_f64;
    let mut last_point: Option<(f64, f64)> = None;

    let coordinates: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|row| {
            let latitude = row.try_get::<f64, _>("latitude").unwrap_or(0.0);
            let longitude = row.try_get::<f64, _>("longitude").unwrap_or(0.0);
            let recorded_at = row
                .try_get::<chrono::DateTime<chrono::Utc>, _>("recorded_at")
                .unwrap_or_else(|_| Utc::now());
            let status = row.try_get::<Option<String>, _>("status").unwrap_or(None);
            let speed_kph = row.try_get::<Option<f64>, _>("speed_kph").unwrap_or(None);

            if let Some((last_lat, last_lon)) = last_point {
                total_distance_km += haversine_km(last_lat, last_lon, latitude, longitude);
            }
            last_point = Some((latitude, longitude));

            json!({
                "latitude": latitude,
                "longitude": longitude,
                "recordedAt": recorded_at.to_rfc3339(),
                "movementStatus": derive_movement_status(status.as_deref(), speed_kph, recorded_at),
                "speedKph": speed_kph,
            })
        })
        .collect();

    Ok(Json(json!({
        "guardId": guard_id,
        "pointCount": coordinates.len(),
        "distanceKm": total_distance_km,
        "coordinates": coordinates,
    })))
}

pub async fn get_active_guards(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Query(params): Query<ActiveGuardsQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let token = utils::extract_bearer_token(&headers)?;
    let claims = utils::verify_token(&token)?;
    let role = utils::normalize_role(&claims.role);

    let window_minutes = params
        .window_minutes
        .unwrap_or(ACTIVE_GUARD_WINDOW_MINUTES)
        .clamp(3, 120);

    let required_accuracy = required_accuracy_meters();

    let rows = if role == "guard" {
        sqlx::query(
            r#"WITH latest AS (
                   SELECT
                       tp.id,
                       tp.entity_id,
                       tp.user_id,
                       tp.label,
                       tp.status,
                       tp.latitude,
                       tp.longitude,
                       tp.heading,
                       tp.speed_kph,
                       tp.accuracy_meters,
                       tp.recorded_at,
                       ROW_NUMBER() OVER (PARTITION BY tp.entity_id ORDER BY tp.recorded_at DESC) AS rn
                   FROM tracking_points tp
                   WHERE tp.entity_type IN ('guard')
                     AND tp.entity_id = $1
                     AND tp.recorded_at >= (CURRENT_TIMESTAMP - ($2 || ' minutes')::interval)
                     AND tp.accuracy_meters IS NOT NULL
                     AND tp.accuracy_meters <= $3
               )
               SELECT
                   latest.id,
                   latest.entity_id,
                   latest.user_id,
                   latest.label,
                   latest.status,
                   latest.latitude,
                   latest.longitude,
                   latest.heading,
                   latest.speed_kph,
                   latest.accuracy_meters,
                   latest.recorded_at,
                   COALESCE(NULLIF(u.full_name, ''), u.username) AS guard_name,
                   u.role AS guard_role
               FROM latest
               LEFT JOIN users u ON u.id = latest.entity_id
               WHERE latest.rn = 1
               ORDER BY latest.recorded_at DESC"#,
        )
        .bind(&claims.sub)
        .bind(window_minutes.to_string())
        .bind(required_accuracy)
        .fetch_all(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to fetch active guard: {}", e)))?
    } else {
        sqlx::query(
            r#"WITH latest AS (
                   SELECT
                       tp.id,
                       tp.entity_id,
                       tp.user_id,
                       tp.label,
                       tp.status,
                       tp.latitude,
                       tp.longitude,
                       tp.heading,
                       tp.speed_kph,
                       tp.accuracy_meters,
                       tp.recorded_at,
                       ROW_NUMBER() OVER (PARTITION BY tp.entity_id ORDER BY tp.recorded_at DESC) AS rn
                   FROM tracking_points tp
                   WHERE tp.entity_type IN ('guard')
                     AND tp.recorded_at >= (CURRENT_TIMESTAMP - ($1 || ' minutes')::interval)
                     AND tp.accuracy_meters IS NOT NULL
                     AND tp.accuracy_meters <= $2
               )
               SELECT
                   latest.id,
                   latest.entity_id,
                   latest.user_id,
                   latest.label,
                   latest.status,
                   latest.latitude,
                   latest.longitude,
                   latest.heading,
                   latest.speed_kph,
                   latest.accuracy_meters,
                   latest.recorded_at,
                   COALESCE(NULLIF(u.full_name, ''), u.username) AS guard_name,
                   u.role AS guard_role
               FROM latest
               LEFT JOIN users u ON u.id = latest.entity_id
               WHERE latest.rn = 1
               ORDER BY latest.recorded_at DESC"#,
        )
        .bind(window_minutes.to_string())
        .bind(required_accuracy)
        .fetch_all(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to fetch active guards: {}", e)))?
    };

    let guards: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|row| {
            let recorded_at = row
                .try_get::<chrono::DateTime<chrono::Utc>, _>("recorded_at")
                .unwrap_or_else(|_| Utc::now());
            let status = row.try_get::<Option<String>, _>("status").unwrap_or(None);
            let speed_kph = row.try_get::<Option<f64>, _>("speed_kph").unwrap_or(None);

            json!({
                "id": row.try_get::<String, _>("id").unwrap_or_default(),
                "guardId": row.try_get::<String, _>("entity_id").unwrap_or_default(),
                "userId": row.try_get::<Option<String>, _>("user_id").unwrap_or(None),
                "guardName": row.try_get::<Option<String>, _>("guard_name").unwrap_or(None),
                "guardRole": row.try_get::<Option<String>, _>("guard_role").unwrap_or(None),
                "label": row.try_get::<Option<String>, _>("label").unwrap_or(None),
                "status": status,
                "movementStatus": derive_movement_status(status.as_deref(), speed_kph, recorded_at),
                "latitude": row.try_get::<f64, _>("latitude").unwrap_or(0.0),
                "longitude": row.try_get::<f64, _>("longitude").unwrap_or(0.0),
                "heading": row.try_get::<Option<f64>, _>("heading").unwrap_or(None),
                "speedKph": speed_kph,
                "accuracyMeters": row.try_get::<Option<f64>, _>("accuracy_meters").unwrap_or(None),
                "recordedAt": recorded_at.to_rfc3339(),
                "ageSeconds": (Utc::now() - recorded_at).num_seconds().max(0),
            })
        })
        .collect();

    Ok(Json(json!({
        "windowMinutes": window_minutes,
        "activeCount": guards.len(),
        "guards": guards,
    })))
}

pub async fn get_map_data(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let token = utils::extract_bearer_token(&headers)?;
    let claims = utils::verify_token(&token)?;

    if utils::normalize_role(&claims.role) != "guard" {
        if let Err(err) = evaluate_and_send_proximity_alerts(db.as_ref()).await {
            tracing::warn!("Failed to evaluate proximity alerts: {}", err);
        }
    }

    let snapshot = fetch_map_snapshot(db.as_ref(), &claims).await?;

    Ok(Json(snapshot))
}

pub async fn check_shift_proximity_alerts(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let (risky_shifts, notifications_created) =
        evaluate_and_send_proximity_alerts(db.as_ref()).await?;

    Ok(Json(json!({
        "message": "Proximity alert evaluation complete",
        "riskyShifts": risky_shifts,
        "notificationsCreated": notifications_created,
        "radiusKm": CLIENT_PROXIMITY_RADIUS_KM,
        "windowMinutes": PRE_SHIFT_ALERT_WINDOW_MINUTES,
    })))
}

pub async fn get_client_sites(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let sites = sqlx::query(
        r#"SELECT id, name, address, latitude, longitude, is_active, created_at, updated_at
           FROM client_sites
           ORDER BY created_at DESC"#,
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch client sites: {}", e)))?;

    let payload: Vec<serde_json::Value> = sites
        .into_iter()
        .map(|row| {
            json!({
                "id": row.try_get::<String, _>("id").unwrap_or_default(),
                "name": row.try_get::<String, _>("name").unwrap_or_default(),
                "address": row.try_get::<Option<String>, _>("address").unwrap_or(None),
                "latitude": row.try_get::<f64, _>("latitude").unwrap_or(0.0),
                "longitude": row.try_get::<f64, _>("longitude").unwrap_or(0.0),
                "isActive": row.try_get::<bool, _>("is_active").unwrap_or(true),
                "createdAt": row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
                "updatedAt": row.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
            })
        })
        .collect();

    Ok(Json(json!({ "sites": payload })))
}

pub async fn create_client_site(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<UpsertClientSiteRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let claims = utils::require_min_role(&headers, "supervisor")?;

    if payload.name.trim().is_empty() {
        return Err(AppError::BadRequest("Site name is required".to_string()));
    }

    validate_coordinates(payload.latitude, payload.longitude)?;

    let site_id = utils::generate_id();

    sqlx::query(
        r#"INSERT INTO client_sites (id, name, address, latitude, longitude, is_active, created_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(&site_id)
    .bind(payload.name.trim())
    .bind(payload.address.as_deref())
    .bind(payload.latitude)
    .bind(payload.longitude)
    .bind(payload.is_active.unwrap_or(true))
    .bind(&claims.sub)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create client site: {}", e)))?;

    publish_tracking_event("client_site_created");

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Client site created",
            "siteId": site_id,
        })),
    ))
}

pub async fn update_client_site(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(site_id): Path<String>,
    Json(payload): Json<UpsertClientSiteRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    if payload.name.trim().is_empty() {
        return Err(AppError::BadRequest("Site name is required".to_string()));
    }

    validate_coordinates(payload.latitude, payload.longitude)?;

    let updated = sqlx::query(
        r#"UPDATE client_sites
           SET name = $1,
               address = $2,
               latitude = $3,
               longitude = $4,
               is_active = $5,
               updated_at = CURRENT_TIMESTAMP
           WHERE id = $6"#,
    )
    .bind(payload.name.trim())
    .bind(payload.address.as_deref())
    .bind(payload.latitude)
    .bind(payload.longitude)
    .bind(payload.is_active.unwrap_or(true))
    .bind(&site_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to update client site: {}", e)))?;

    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound("Client site not found".to_string()));
    }

    publish_tracking_event("client_site_updated");

    Ok(Json(json!({
        "message": "Client site updated",
        "siteId": site_id,
    })))
}

pub async fn delete_client_site(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(site_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let deleted = sqlx::query("DELETE FROM client_sites WHERE id = $1")
        .bind(&site_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to delete client site: {}", e)))?;

    if deleted.rows_affected() == 0 {
        return Err(AppError::NotFound("Client site not found".to_string()));
    }

    publish_tracking_event("client_site_deleted");

    Ok(Json(json!({
        "message": "Client site deleted",
        "siteId": site_id,
    })))
}

pub async fn get_geofence_zones(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let rows = sqlx::query(
        r#"SELECT
               sg.id,
               sg.client_site_id,
               cs.name AS site_name,
               sg.zone_type,
               sg.radius_km,
               sg.polygon_points,
               sg.is_active,
               sg.created_at,
               sg.updated_at
           FROM site_geofences sg
           JOIN client_sites cs ON cs.id = sg.client_site_id
           ORDER BY sg.created_at DESC"#,
    )
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch geofence zones: {}", e)))?;

    let zones: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.try_get::<String, _>("id").unwrap_or_default(),
                "siteId": row.try_get::<String, _>("client_site_id").unwrap_or_default(),
                "siteName": row.try_get::<String, _>("site_name").unwrap_or_default(),
                "zoneType": row.try_get::<String, _>("zone_type").unwrap_or_default(),
                "radiusKm": row.try_get::<Option<f64>, _>("radius_km").unwrap_or(None),
                "polygonPoints": row.try_get::<Option<serde_json::Value>, _>("polygon_points").unwrap_or(None),
                "isActive": row.try_get::<bool, _>("is_active").unwrap_or(true),
                "createdAt": row
                    .try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
                "updatedAt": row
                    .try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
            })
        })
        .collect();

    Ok(Json(json!({ "zones": zones })))
}

pub async fn get_site_geofences(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(site_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let rows = sqlx::query(
        r#"SELECT
               sg.id,
               sg.client_site_id,
               cs.name AS site_name,
               sg.zone_type,
               sg.radius_km,
               sg.polygon_points,
               sg.is_active,
               sg.created_at,
               sg.updated_at
           FROM site_geofences sg
           JOIN client_sites cs ON cs.id = sg.client_site_id
           WHERE sg.client_site_id = $1
           ORDER BY sg.created_at DESC"#,
    )
    .bind(&site_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch site geofences: {}", e)))?;

    let zones: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.try_get::<String, _>("id").unwrap_or_default(),
                "siteId": row.try_get::<String, _>("client_site_id").unwrap_or_default(),
                "siteName": row.try_get::<String, _>("site_name").unwrap_or_default(),
                "zoneType": row.try_get::<String, _>("zone_type").unwrap_or_default(),
                "radiusKm": row.try_get::<Option<f64>, _>("radius_km").unwrap_or(None),
                "polygonPoints": row.try_get::<Option<serde_json::Value>, _>("polygon_points").unwrap_or(None),
                "isActive": row.try_get::<bool, _>("is_active").unwrap_or(true),
                "createdAt": row
                    .try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
                "updatedAt": row
                    .try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
            })
        })
        .collect();

    Ok(Json(json!({
        "siteId": site_id,
        "zones": zones,
    })))
}

pub async fn create_site_geofence(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(site_id): Path<String>,
    Json(payload): Json<UpsertGeofenceZoneRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let claims = utils::require_min_role(&headers, "supervisor")?;
    let (zone_type, radius_km, polygon_points, is_active) = validate_geofence_payload(&payload)?;

    let site_exists =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM client_sites WHERE id = $1")
            .bind(&site_id)
            .fetch_one(db.as_ref())
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to verify client site: {}", e)))?;

    if site_exists == 0 {
        return Err(AppError::NotFound("Client site not found".to_string()));
    }

    let zone_id = utils::generate_id();

    sqlx::query(
        r#"INSERT INTO site_geofences (
               id,
               client_site_id,
               zone_type,
               radius_km,
               polygon_points,
               is_active,
               created_by
           ) VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(&zone_id)
    .bind(&site_id)
    .bind(zone_type)
    .bind(radius_km)
    .bind(polygon_points)
    .bind(is_active)
    .bind(&claims.sub)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create geofence zone: {}", e)))?;

    publish_tracking_event("geofence_zone_created");

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Geofence zone created",
            "zoneId": zone_id,
            "siteId": site_id,
        })),
    ))
}

pub async fn update_geofence_zone(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(zone_id): Path<String>,
    Json(payload): Json<UpsertGeofenceZoneRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;
    let (zone_type, radius_km, polygon_points, is_active) = validate_geofence_payload(&payload)?;

    let updated = sqlx::query(
        r#"UPDATE site_geofences
           SET zone_type = $1,
               radius_km = $2,
               polygon_points = $3,
               is_active = $4,
               updated_at = CURRENT_TIMESTAMP
           WHERE id = $5"#,
    )
    .bind(zone_type)
    .bind(radius_km)
    .bind(polygon_points)
    .bind(is_active)
    .bind(&zone_id)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to update geofence zone: {}", e)))?;

    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound("Geofence zone not found".to_string()));
    }

    publish_tracking_event("geofence_zone_updated");

    Ok(Json(json!({
        "message": "Geofence zone updated",
        "zoneId": zone_id,
    })))
}

pub async fn delete_geofence_zone(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(zone_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let _claims = utils::require_min_role(&headers, "supervisor")?;

    let deleted = sqlx::query("DELETE FROM site_geofences WHERE id = $1")
        .bind(&zone_id)
        .execute(db.as_ref())
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to delete geofence zone: {}", e)))?;

    if deleted.rows_affected() == 0 {
        return Err(AppError::NotFound("Geofence zone not found".to_string()));
    }

    publish_tracking_event("geofence_zone_deleted");

    Ok(Json(json!({
        "message": "Geofence zone deleted",
        "zoneId": zone_id,
    })))
}

pub async fn guard_heartbeat(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<TrackPointRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let token = utils::extract_bearer_token(&headers)?;
    let claims = utils::verify_token(&token)?;
    let actor_role = utils::normalize_role(&claims.role);
    let entity_type = if actor_role == "guard" {
        "guard"
    } else {
        "user"
    };

    validate_coordinates(payload.latitude, payload.longitude)?;

    let sample_accuracy = payload.accuracy_meters.unwrap_or(f64::INFINITY);
    let required_accuracy = required_accuracy_meters();
    if sample_accuracy > required_accuracy {
        return Ok((
            StatusCode::ACCEPTED,
            Json(json!({
                "message": "Location sample ignored due to low precision",
                "accepted": false,
                "requiredAccuracyMeters": required_accuracy,
                "receivedAccuracyMeters": payload.accuracy_meters,
            })),
        ));
    }

    let tracking_id = utils::generate_id();
    let guard_label = if let Some(label) = payload.label.as_ref() {
        Some(label.as_str())
    } else {
        Some(claims.email.as_str())
    };

    sqlx::query(
        r#"INSERT INTO tracking_points (
            id, entity_type, entity_id, user_id, label, status, latitude, longitude, heading, speed_kph, accuracy_meters, created_by
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"#,
    )
    .bind(&tracking_id)
    .bind(entity_type)
    .bind(&claims.sub)
    .bind(&claims.sub)
    .bind(guard_label)
    .bind(payload.status.as_deref().or(Some("active")))
    .bind(payload.latitude)
    .bind(payload.longitude)
    .bind(payload.heading)
    .bind(payload.speed_kph)
    .bind(payload.accuracy_meters)
    .bind(&claims.sub)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to record guard heartbeat: {}", e)))?;

    let geofence_events =
        evaluate_geofence_transitions(db.as_ref(), entity_type, &claims.sub, guard_label).await?;

    publish_tracking_event("guard_heartbeat");
    if !geofence_events.is_empty() {
        publish_tracking_event("geofence_transition");
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Location heartbeat recorded",
            "trackingId": tracking_id,
            "geofenceEvents": geofence_events,
        })),
    ))
}

pub async fn create_tracking_point(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<TrackPointRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let token = utils::extract_bearer_token(&headers)?;
    let claims = utils::verify_token(&token)?;
    let actor_role = utils::normalize_role(&claims.role);
    let entity_type = payload.entity_type.trim().to_lowercase();

    if !matches!(entity_type.as_str(), "guard" | "vehicle" | "user") {
        return Err(AppError::BadRequest(
            "entityType must be 'guard', 'vehicle', or 'user'".to_string(),
        ));
    }

    if payload.entity_id.trim().is_empty() {
        return Err(AppError::BadRequest("entityId is required".to_string()));
    }

    if matches!(entity_type.as_str(), "guard" | "user") {
        let sample_accuracy = payload.accuracy_meters.unwrap_or(f64::INFINITY);
        let required_accuracy = required_accuracy_meters();
        if sample_accuracy > required_accuracy {
            return Ok((
                StatusCode::ACCEPTED,
                Json(json!({
                    "message": "Tracking sample ignored due to low precision",
                    "accepted": false,
                    "requiredAccuracyMeters": required_accuracy,
                    "receivedAccuracyMeters": payload.accuracy_meters,
                })),
            ));
        }
    }

    validate_coordinates(payload.latitude, payload.longitude)?;

    if actor_role == "guard" {
        if entity_type != "guard" || payload.entity_id != claims.sub {
            return Err(AppError::Forbidden(
                "Guards can only submit their own guard tracking points".to_string(),
            ));
        }
    }

    let tracking_id = utils::generate_id();
    let tracked_user_id = if is_guard_entity(&entity_type) {
        Some(payload.entity_id.trim())
    } else {
        None
    };

    sqlx::query(
        r#"INSERT INTO tracking_points (
            id, entity_type, entity_id, user_id, label, status, latitude, longitude, heading, speed_kph, accuracy_meters, created_by
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"#,
    )
    .bind(&tracking_id)
    .bind(&entity_type)
    .bind(payload.entity_id.trim())
    .bind(tracked_user_id)
    .bind(payload.label.as_deref())
    .bind(payload.status.as_deref())
    .bind(payload.latitude)
    .bind(payload.longitude)
    .bind(payload.heading)
    .bind(payload.speed_kph)
    .bind(payload.accuracy_meters)
    .bind(&claims.sub)
    .execute(db.as_ref())
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create tracking point: {}", e)))?;

    let geofence_events = evaluate_geofence_transitions(
        db.as_ref(),
        &entity_type,
        payload.entity_id.trim(),
        payload.label.as_deref(),
    )
    .await?;

    publish_tracking_event("tracking_point_created");
    if !geofence_events.is_empty() {
        publish_tracking_event("geofence_transition");
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Tracking point recorded",
            "trackingId": tracking_id,
            "geofenceEvents": geofence_events,
        })),
    ))
}

pub async fn tracking_ws(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Query(query): Query<TrackingWsAuthQuery>,
    ws: WebSocketUpgrade,
) -> AppResult<Response> {
    let protocol_token = extract_ws_token_from_protocols(&headers);
    let query_token = query
        .token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());

    let token = protocol_token.or(query_token).ok_or_else(|| {
        tracing::warn!("Rejected tracking websocket upgrade due to missing token");
        AppError::Unauthorized(
            "Missing websocket token".to_string(),
        )
    })?;

    let claims = match utils::verify_token(token.trim()) {
        Ok(claims) => claims,
        Err(error) => {
            tracing::warn!(error = %error, "Rejected tracking websocket upgrade due to invalid token");
            return Err(error);
        }
    };

    if !claims.legal_consent_accepted {
        tracing::warn!(user_id = %claims.sub, "Rejected tracking websocket upgrade due to missing legal consent");
        return Err(AppError::Forbidden(
            "Legal consent required. Please accept Terms of Agreement to continue.".to_string(),
        ));
    }

    let role = utils::normalize_role(&claims.role);
    if !crate::middleware::authz::has_tracking_access_role(&role) {
        tracing::warn!(
            user_id = %claims.sub,
            role = %role,
            "Rejected tracking websocket upgrade due to unauthorized role"
        );
        return Err(AppError::Forbidden(
            "Tracking endpoints are limited to authenticated operational roles".to_string(),
        ));
    }

    tracing::debug!(user_id = %claims.sub, role = %claims.role, "Tracking websocket upgrade accepted");

    let ws_upgrade = if has_requested_ws_protocol(&headers, "sentinel-tracking-v1") {
        ws.protocols(["sentinel-tracking-v1"])
    } else {
        ws
    };

    Ok(ws_upgrade.on_upgrade(move |socket| handle_tracking_ws(socket, db, claims)))
}

