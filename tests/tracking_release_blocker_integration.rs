use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use reqwest::{Client, StatusCode};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::env;
use uuid::Uuid;

#[derive(Debug, Serialize)]
struct Claims {
    sub: String,
    email: String,
    role: String,
    legal_consent_accepted: bool,
    exp: i64,
    iat: i64,
}

fn integration_enabled() -> bool {
    env::var("RUN_INTEGRATION_TESTS")
        .map(|value| matches!(value.trim().to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn integration_base_url() -> String {
    env::var("INTEGRATION_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:5000".to_string())
}

fn integration_database_url() -> Option<String> {
    env::var("INTEGRATION_DATABASE_URL")
        .ok()
        .or_else(|| env::var("DATABASE_URL").ok())
}

fn jwt_secret() -> String {
    env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key-change-in-production".to_string())
}

fn test_user_id() -> String {
    // users.id and related foreign keys are constrained to VARCHAR(36)
    Uuid::new_v4().to_string()
}

fn build_token(role: &str, subject: &str, legal_consent_accepted: bool) -> String {
    let now = Utc::now();
    let claims = Claims {
        sub: subject.to_string(),
        email: format!("{}@integration.local", subject),
        role: role.to_string(),
        legal_consent_accepted,
        exp: (now + Duration::hours(2)).timestamp(),
        iat: now.timestamp(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret().as_bytes()),
    )
    .expect("token generation should succeed")
}

async fn setup_context() -> Result<Option<(String, Client, PgPool)>, Box<dyn std::error::Error>> {
    if !integration_enabled() {
        eprintln!("Skipping integration test. Set RUN_INTEGRATION_TESTS=true to run.");
        return Ok(None);
    }

    let Some(database_url) = integration_database_url() else {
        eprintln!("Skipping integration test. Set INTEGRATION_DATABASE_URL or DATABASE_URL.");
        return Ok(None);
    };

    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&database_url)
        .await?;

    Ok(Some((integration_base_url(), Client::new(), pool)))
}

async fn upsert_test_user(
    pool: &PgPool,
    user_id: &str,
    role: &str,
    legal_consent_accepted: bool,
    location_tracking_consent: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let consent_accepted_at = if legal_consent_accepted {
        Some(Utc::now())
    } else {
        None
    };

    let location_tracking_consent_granted_at = if location_tracking_consent {
        Some(Utc::now())
    } else {
        None
    };

    let location_tracking_consent_revoked_at = if location_tracking_consent {
        None
    } else {
        Some(Utc::now())
    };

    sqlx::query(
        r#"INSERT INTO users (
               id,
               email,
               username,
               password,
               role,
               full_name,
               phone_number,
               verified,
               consent_accepted_at,
               consent_version,
               location_tracking_consent,
               location_tracking_consent_granted_at,
               location_tracking_consent_revoked_at,
               location_tracking_consent_updated_at,
               created_at,
               updated_at
           ) VALUES (
               $1,
               $2,
               $3,
               $4,
               $5,
               $6,
               $7,
               true,
               $8,
               'itest-v1',
               $9,
               $10,
               $11,
               CURRENT_TIMESTAMP,
               CURRENT_TIMESTAMP,
               CURRENT_TIMESTAMP
           )
           ON CONFLICT (id) DO UPDATE
           SET email = EXCLUDED.email,
               username = EXCLUDED.username,
               password = EXCLUDED.password,
               role = EXCLUDED.role,
               full_name = EXCLUDED.full_name,
               phone_number = EXCLUDED.phone_number,
               verified = true,
               consent_accepted_at = EXCLUDED.consent_accepted_at,
               consent_version = EXCLUDED.consent_version,
               location_tracking_consent = EXCLUDED.location_tracking_consent,
               location_tracking_consent_granted_at = EXCLUDED.location_tracking_consent_granted_at,
               location_tracking_consent_revoked_at = EXCLUDED.location_tracking_consent_revoked_at,
               location_tracking_consent_updated_at = CURRENT_TIMESTAMP,
               updated_at = CURRENT_TIMESTAMP"#,
    )
    .bind(user_id)
    .bind(format!("{}@integration.local", user_id))
    .bind(format!("{}-username", user_id))
    .bind("integration-password")
    .bind(role)
    .bind(format!("{} full name", user_id))
    .bind("09170000000")
    .bind(consent_accepted_at)
    .bind(location_tracking_consent)
    .bind(location_tracking_consent_granted_at)
    .bind(location_tracking_consent_revoked_at)
    .execute(pool)
    .await?;

    Ok(())
}

async fn insert_guard_tracking_point(
    pool: &PgPool,
    guard_id: &str,
    minutes_ago: i64,
    latitude: f64,
    longitude: f64,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query(
        r#"INSERT INTO tracking_points (
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
               created_by
           ) VALUES (
               $1,
               'guard',
               $2,
               $2,
               $3,
               'active',
               $4,
               $5,
               NULL,
               0.0,
               15.0,
               CURRENT_TIMESTAMP - ($6 * INTERVAL '1 minute'),
               $2
           )"#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(guard_id)
    .bind(format!("{} label", guard_id))
    .bind(latitude)
    .bind(longitude)
    .bind(minutes_ago)
    .execute(pool)
    .await?;

    Ok(())
}

async fn response_json(response: reqwest::Response) -> Value {
    response.json::<Value>().await.unwrap_or_else(|_| json!({}))
}

#[tokio::test]
async fn unscheduled_guard_heartbeat_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let Some((base_url, client, pool)) = setup_context().await? else {
        return Ok(());
    };

    let guard_id = test_user_id();
    upsert_test_user(&pool, &guard_id, "guard", true, false).await?;

    let guard_token = build_token("guard", &guard_id, true);

    let grant_response = client
        .post(format!("{}/api/tracking/consent/grant", base_url))
        .header("Authorization", format!("Bearer {}", guard_token))
        .send()
        .await?;
    let grant_status = grant_response.status();
    let grant_body = response_json(grant_response).await;

    assert_eq!(
        grant_status,
        StatusCode::OK,
        "expected consent grant to succeed, body: {}",
        grant_body
    );

    let heartbeat_response = client
        .post(format!("{}/api/tracking/heartbeat", base_url))
        .header("Authorization", format!("Bearer {}", guard_token))
        .json(&json!({
            "entityType": "guard",
            "entityId": guard_id,
            "status": "active",
            "latitude": 7.071,
            "longitude": 125.611,
            "accuracyMeters": 12.0
        }))
        .send()
        .await?;

    let heartbeat_status = heartbeat_response.status();
    let heartbeat_body = response_json(heartbeat_response).await;

    assert_eq!(
        heartbeat_status,
        StatusCode::CREATED,
        "expected unscheduled heartbeat to be accepted, body: {}",
        heartbeat_body
    );
    assert_eq!(
        heartbeat_body.get("accepted").and_then(Value::as_bool),
        Some(true)
    );

    Ok(())
}

#[tokio::test]
async fn unscheduled_guard_appears_in_map_data() -> Result<(), Box<dyn std::error::Error>> {
    let Some((base_url, client, pool)) = setup_context().await? else {
        return Ok(());
    };

    let supervisor_id = test_user_id();
    let guard_id = test_user_id();

    upsert_test_user(&pool, &supervisor_id, "supervisor", true, true).await?;
    upsert_test_user(&pool, &guard_id, "guard", true, true).await?;

    insert_guard_tracking_point(&pool, &guard_id, 1, 7.072, 125.613).await?;

    let supervisor_token = build_token("supervisor", &supervisor_id, true);
    let map_response = client
        .get(format!("{}/api/tracking/map-data", base_url))
        .header("Authorization", format!("Bearer {}", supervisor_token))
        .send()
        .await?;

    let map_status = map_response.status();
    let map_body = response_json(map_response).await;

    assert_eq!(
        map_status,
        StatusCode::OK,
        "expected map-data to succeed, body: {}",
        map_body
    );

    let found = map_body
        .get("trackingPoints")
        .and_then(Value::as_array)
        .and_then(|points| {
            points
                .iter()
                .find(|point| point.get("entityId").and_then(Value::as_str) == Some(guard_id.as_str()))
        })
        .cloned()
        .unwrap_or_else(|| json!({}));

    assert_eq!(
        found.get("scheduleStatus").and_then(Value::as_str),
        Some("unscheduled")
    );
    assert_eq!(
        found.get("heartbeatStatus").and_then(Value::as_str),
        Some("active")
    );
    assert!(found.get("ageSeconds").and_then(Value::as_i64).is_some());
    assert!(found.get("source").and_then(Value::as_str).is_some());
    assert!(found.get("accuracyMeters").is_some());
    assert!(found.get("approximate").is_some());

    Ok(())
}

#[tokio::test]
async fn stale_and_offline_classification_use_heartbeat_age() -> Result<(), Box<dyn std::error::Error>> {
    let Some((base_url, client, pool)) = setup_context().await? else {
        return Ok(());
    };

    let supervisor_id = test_user_id();
    let stale_guard_id = test_user_id();
    let offline_guard_id = test_user_id();

    upsert_test_user(&pool, &supervisor_id, "supervisor", true, true).await?;
    upsert_test_user(&pool, &stale_guard_id, "guard", true, true).await?;
    upsert_test_user(&pool, &offline_guard_id, "guard", true, true).await?;

    insert_guard_tracking_point(&pool, &stale_guard_id, 20, 7.073, 125.614).await?;
    insert_guard_tracking_point(&pool, &offline_guard_id, 200, 7.074, 125.615).await?;

    let supervisor_token = build_token("supervisor", &supervisor_id, true);

    let response = client
        .get(format!("{}/api/tracking/active-guards?windowMinutes=15", base_url))
        .header("Authorization", format!("Bearer {}", supervisor_token))
        .send()
        .await?;

    let status = response.status();
    let body = response_json(response).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "expected active-guards response, body: {}",
        body
    );

    let guards = body
        .get("guards")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let stale_guard = guards
        .iter()
        .find(|guard| guard.get("guardId").and_then(Value::as_str) == Some(stale_guard_id.as_str()))
        .cloned()
        .unwrap_or_else(|| json!({}));

    let offline_guard = guards
        .iter()
        .find(|guard| guard.get("guardId").and_then(Value::as_str) == Some(offline_guard_id.as_str()))
        .cloned()
        .unwrap_or_else(|| json!({}));

    assert_eq!(
        stale_guard.get("heartbeatStatus").and_then(Value::as_str),
        Some("stale")
    );
    assert_eq!(
        offline_guard.get("heartbeatStatus").and_then(Value::as_str),
        Some("offline")
    );

    Ok(())
}

#[tokio::test]
async fn heartbeat_is_rejected_when_server_location_consent_is_missing(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some((base_url, client, pool)) = setup_context().await? else {
        return Ok(());
    };

    let guard_id = test_user_id();
    upsert_test_user(&pool, &guard_id, "guard", true, false).await?;

    let guard_token = build_token("guard", &guard_id, true);

    let heartbeat_response = client
        .post(format!("{}/api/tracking/heartbeat", base_url))
        .header("Authorization", format!("Bearer {}", guard_token))
        .json(&json!({
            "entityType": "guard",
            "entityId": guard_id,
            "status": "active",
            "latitude": 7.071,
            "longitude": 125.611,
            "accuracyMeters": 8.0
        }))
        .send()
        .await?;

    let status = heartbeat_response.status();
    let body = response_json(heartbeat_response).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "expected heartbeat to be blocked when consent is missing, body: {}",
        body
    );
    assert_eq!(
        body.get("code").and_then(Value::as_str),
        Some("tracking_consent_required")
    );

    Ok(())
}

#[tokio::test]
async fn tracking_points_for_guard_entity_require_server_location_consent(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some((base_url, client, pool)) = setup_context().await? else {
        return Ok(());
    };

    let guard_id = test_user_id();
    upsert_test_user(&pool, &guard_id, "guard", true, false).await?;

    let guard_token = build_token("guard", &guard_id, true);

    let response = client
        .post(format!("{}/api/tracking/points", base_url))
        .header("Authorization", format!("Bearer {}", guard_token))
        .json(&json!({
            "entityType": "guard",
            "entityId": guard_id,
            "status": "active",
            "latitude": 7.071,
            "longitude": 125.611,
            "accuracyMeters": 8.0
        }))
        .send()
        .await?;

    let status = response.status();
    let body = response_json(response).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "expected tracking point write to be blocked when consent is missing, body: {}",
        body
    );
    assert_eq!(
        body.get("code").and_then(Value::as_str),
        Some("tracking_consent_required")
    );

    Ok(())
}

#[tokio::test]
async fn tracking_points_reject_admin_guard_user_producer_writes(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some((base_url, client, pool)) = setup_context().await? else {
        return Ok(());
    };

    let admin_id = test_user_id();
    upsert_test_user(&pool, &admin_id, "admin", true, true).await?;

    let admin_token = build_token("admin", &admin_id, true);

    let response = client
        .post(format!("{}/api/tracking/points", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .json(&json!({
            "entityType": "user",
            "entityId": admin_id,
            "status": "active",
            "latitude": 7.071,
            "longitude": 125.611,
            "accuracyMeters": 8.0
        }))
        .send()
        .await?;

    let status = response.status();
    let body = response_json(response).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "expected admin guard/user producer write to be rejected, body: {}",
        body
    );

    Ok(())
}

#[tokio::test]
async fn tracking_points_reject_guard_vehicle_producer_writes(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some((base_url, client, pool)) = setup_context().await? else {
        return Ok(());
    };

    let guard_id = test_user_id();
    upsert_test_user(&pool, &guard_id, "guard", true, true).await?;

    let guard_token = build_token("guard", &guard_id, true);
    let vehicle_id = format!("vehicle-{}", Uuid::new_v4());

    let response = client
        .post(format!("{}/api/tracking/points", base_url))
        .header("Authorization", format!("Bearer {}", guard_token))
        .json(&json!({
            "entityType": "vehicle",
            "entityId": vehicle_id,
            "status": "active",
            "latitude": 7.071,
            "longitude": 125.611,
            "accuracyMeters": 8.0
        }))
        .send()
        .await?;

    let status = response.status();
    let body = response_json(response).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "expected guard vehicle producer write to be rejected, body: {}",
        body
    );

    Ok(())
}

#[tokio::test]
async fn websocket_query_token_auth_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let Some((base_url, client, pool)) = setup_context().await? else {
        return Ok(());
    };

    let supervisor_id = test_user_id();
    upsert_test_user(&pool, &supervisor_id, "supervisor", true, true).await?;

    let supervisor_token = build_token("supervisor", &supervisor_id, true);

    let ws_response = client
        .get(format!("{}/api/tracking/ws?token={}", base_url, supervisor_token))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await?;

    let ws_status = ws_response.status();
    let ws_body = response_json(ws_response).await;

    assert_eq!(
        ws_status,
        StatusCode::UNAUTHORIZED,
        "expected websocket query token auth to be rejected, body: {}",
        ws_body
    );

    let error_message = ws_body
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_lowercase();

    assert!(
        error_message.contains("query-string websocket tokens are not allowed"),
        "expected explicit query-token rejection message, body: {}",
        ws_body
    );

    Ok(())
}

#[tokio::test]
async fn supervisor_heartbeat_is_accepted_with_consent() -> Result<(), Box<dyn std::error::Error>> {
    let Some((base_url, client, pool)) = setup_context().await? else {
        return Ok(());
    };

    let supervisor_id = test_user_id();
    upsert_test_user(&pool, &supervisor_id, "supervisor", true, true).await?;

    let supervisor_token = build_token("supervisor", &supervisor_id, true);

    let response = client
        .post(format!("{}/api/tracking/heartbeat", base_url))
        .header("Authorization", format!("Bearer {}", supervisor_token))
        .json(&json!({
            "entityType": "user",
            "entityId": supervisor_id,
            "status": "active",
            "latitude": 7.071,
            "longitude": 125.611,
            "accuracyMeters": 10.0
        }))
        .send()
        .await?;

    let status = response.status();
    let body = response_json(response).await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "expected supervisor heartbeat to be accepted, body: {}",
        body
    );

    Ok(())
}

#[tokio::test]
async fn admin_heartbeat_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let Some((base_url, client, pool)) = setup_context().await? else {
        return Ok(());
    };

    let admin_id = test_user_id();
    upsert_test_user(&pool, &admin_id, "admin", true, true).await?;

    let admin_token = build_token("admin", &admin_id, true);

    let response = client
        .post(format!("{}/api/tracking/heartbeat", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .json(&json!({
            "entityType": "user",
            "entityId": admin_id,
            "status": "active",
            "latitude": 7.071,
            "longitude": 125.611,
            "accuracyMeters": 10.0
        }))
        .send()
        .await?;

    let status = response.status();
    let body = response_json(response).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "expected admin heartbeat to be rejected, body: {}",
        body
    );

    Ok(())
}

#[tokio::test]
async fn superadmin_heartbeat_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let Some((base_url, client, pool)) = setup_context().await? else {
        return Ok(());
    };

    let sa_id = test_user_id();
    upsert_test_user(&pool, &sa_id, "superadmin", true, true).await?;

    let sa_token = build_token("superadmin", &sa_id, true);

    let response = client
        .post(format!("{}/api/tracking/heartbeat", base_url))
        .header("Authorization", format!("Bearer {}", sa_token))
        .json(&json!({
            "entityType": "user",
            "entityId": sa_id,
            "status": "active",
            "latitude": 7.071,
            "longitude": 125.611,
            "accuracyMeters": 10.0
        }))
        .send()
        .await?;

    let status = response.status();
    let body = response_json(response).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "expected superadmin heartbeat to be rejected, body: {}",
        body
    );

    Ok(())
}
