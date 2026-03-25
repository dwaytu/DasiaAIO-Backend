use axum::{
    extract::{Path, Query, WebSocketUpgrade},
    response::Response,
    extract::ws::{Message, WebSocket},
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use sqlx::{PgPool, Row};
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
pub struct TrackingWsAuthQuery {
    pub token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertClientSiteRequest {
    pub name: String,
    pub address: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    pub is_active: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
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
        return Err(AppError::BadRequest("Invalid latitude or longitude".to_string()));
    }
    Ok(())
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
                 AND tp.entity_type IN ('guard', 'user')
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
    .map_err(|e| AppError::DatabaseError(format!("Failed to evaluate shift proximity candidates: {}", e)))?;

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
    .map_err(|e| AppError::DatabaseError(format!("Failed to fetch leadership recipients: {}", e)))?;

    if leadership.is_empty() {
        return Ok((0, 0));
    }

    let mut risky_shifts = 0usize;
    let mut notifications_created = 0usize;

    for candidate in candidates {
        let guard_distance_km = match (candidate.guard_latitude, candidate.guard_longitude) {
            (Some(guard_lat), Some(guard_lon)) => {
                haversine_km(guard_lat, guard_lon, candidate.client_latitude, candidate.client_longitude)
            }
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
            .map_err(|e| AppError::DatabaseError(format!("Failed to check duplicate proximity alerts: {}", e)))?;

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
                        r#"SELECT id, entity_type, entity_id, label, status, latitude, longitude, heading, speed_kph, accuracy_meters, recorded_at
                             FROM tracking_points
                             WHERE entity_type IN ('guard', 'user')
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
                                         entity_type IN ('guard', 'user')
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
                                 id, entity_type, entity_id, label, status, latitude, longitude, heading, speed_kph, accuracy_meters, recorded_at
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

    let points_payload: Vec<serde_json::Value> = tracking_points
        .into_iter()
        .map(|row| {
            json!({
                "id": row.try_get::<String, _>("id").unwrap_or_default(),
                "entityType": row.try_get::<String, _>("entity_type").unwrap_or_default(),
                "entityId": row.try_get::<String, _>("entity_id").unwrap_or_default(),
                "label": row.try_get::<Option<String>, _>("label").unwrap_or(None),
                "status": row.try_get::<Option<String>, _>("status").unwrap_or(None),
                "latitude": row.try_get::<f64, _>("latitude").unwrap_or(0.0),
                "longitude": row.try_get::<f64, _>("longitude").unwrap_or(0.0),
                "heading": row.try_get::<Option<f64>, _>("heading").unwrap_or(None),
                "speedKph": row.try_get::<Option<f64>, _>("speed_kph").unwrap_or(None),
                "accuracyMeters": row.try_get::<Option<f64>, _>("accuracy_meters").unwrap_or(None),
                "recordedAt": row
                    .try_get::<chrono::DateTime<chrono::Utc>, _>("recorded_at")
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
            })
        })
        .collect();

    Ok(json!({
        "clientSites": sites_payload,
        "trackingPoints": points_payload,
    }))
}

async fn send_ws_snapshot(
    socket: &mut WebSocket,
    db: Arc<PgPool>,
    claims: utils::TokenClaims,
) -> Result<(), ()> {
    let snapshot = fetch_map_snapshot(db.as_ref(), &claims)
        .await
        .map_err(|_| ())?;
    let payload = json!({ "type": "snapshot", "data": snapshot }).to_string();

    socket.send(Message::Text(payload)).await.map_err(|_| ())
}

async fn handle_tracking_ws(
    mut socket: WebSocket,
    db: Arc<PgPool>,
    claims: utils::TokenClaims,
) {
    if send_ws_snapshot(&mut socket, db.clone(), claims.clone()).await.is_err() {
        return;
    }

    let mut rx = tracking_bus().subscribe();

    loop {
        tokio::select! {
            recv_result = socket.recv() => {
                match recv_result {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
            bus_result = rx.recv() => {
                match bus_result {
                    Ok(_) => {
                        if send_ws_snapshot(&mut socket, db.clone(), claims.clone()).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                }
            }
        }
    }
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

    let (risky_shifts, notifications_created) = evaluate_and_send_proximity_alerts(db.as_ref()).await?;

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

pub async fn guard_heartbeat(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<TrackPointRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let token = utils::extract_bearer_token(&headers)?;
    let claims = utils::verify_token(&token)?;
    let actor_role = utils::normalize_role(&claims.role);
    let entity_type = if actor_role == "guard" { "guard" } else { "user" };

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
            id, entity_type, entity_id, label, status, latitude, longitude, heading, speed_kph, accuracy_meters, created_by
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
    )
    .bind(&tracking_id)
    .bind(entity_type)
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

    publish_tracking_event("guard_heartbeat");

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Location heartbeat recorded",
            "trackingId": tracking_id,
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
        return Err(AppError::BadRequest("entityType must be 'guard', 'vehicle', or 'user'".to_string()));
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
            return Err(AppError::Forbidden("Guards can only submit their own guard tracking points".to_string()));
        }
    }

    let tracking_id = utils::generate_id();

    sqlx::query(
        r#"INSERT INTO tracking_points (
            id, entity_type, entity_id, label, status, latitude, longitude, heading, speed_kph, accuracy_meters, created_by
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
    )
    .bind(&tracking_id)
    .bind(&entity_type)
    .bind(payload.entity_id.trim())
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

    publish_tracking_event("tracking_point_created");

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "Tracking point recorded",
            "trackingId": tracking_id,
        })),
    ))
}

pub async fn tracking_ws(
    State(db): State<Arc<PgPool>>,
    Query(query): Query<TrackingWsAuthQuery>,
    ws: WebSocketUpgrade,
) -> AppResult<Response> {
    if query.token.trim().is_empty() {
        return Err(AppError::Unauthorized("Missing websocket token".to_string()));
    }

    let claims = utils::verify_token(query.token.trim())?;

    Ok(ws.on_upgrade(move |socket| handle_tracking_ws(socket, db, claims)))
}
