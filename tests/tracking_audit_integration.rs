use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use reqwest::{Client, StatusCode};
use serde::Serialize;
use serde_json::{json, Value};
use std::env;

#[derive(Debug, Serialize)]
struct Claims {
    sub: String,
    email: String,
    role: String,
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

fn jwt_secret() -> String {
    env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key-change-in-production".to_string())
}

fn build_token(role: &str, subject: &str) -> String {
    let now = Utc::now();
    let claims = Claims {
        sub: subject.to_string(),
        email: format!("{}@integration.local", subject),
        role: role.to_string(),
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

async fn response_json(response: reqwest::Response) -> Value {
    response.json::<Value>().await.unwrap_or_else(|_| json!({}))
}

#[tokio::test]
async fn geofence_zone_crud_and_rbac_scenarios() -> Result<(), Box<dyn std::error::Error>> {
    if !integration_enabled() {
        eprintln!("Skipping integration test. Set RUN_INTEGRATION_TESTS=true to run.");
        return Ok(());
    }

    let base_url = integration_base_url();
    let client = Client::new();

    let supervisor_token = build_token("supervisor", "itest-supervisor");
    let guard_token = build_token("guard", "itest-guard");

    let site_response = client
        .post(format!("{}/api/tracking/client-sites", base_url))
        .header("Authorization", format!("Bearer {}", supervisor_token))
        .json(&json!({
            "name": format!("itest-site-{}", Utc::now().timestamp()),
            "address": "Integration Lane",
            "latitude": 7.072,
            "longitude": 125.613,
            "isActive": true
        }))
        .send()
        .await?;

    let site_status = site_response.status();
    let site_body = response_json(site_response).await;
    assert_eq!(
        site_status,
        StatusCode::CREATED,
        "expected site creation to succeed, body: {}",
        site_body
    );

    let site_id = site_body
        .get("siteId")
        .and_then(Value::as_str)
        .expect("siteId is required for geofence test")
        .to_string();

    let guard_attempt = client
        .post(format!(
            "{}/api/tracking/client-sites/{}/geofences",
            base_url, site_id
        ))
        .header("Authorization", format!("Bearer {}", guard_token))
        .json(&json!({
            "zoneType": "radius",
            "radiusKm": 0.45,
            "isActive": true
        }))
        .send()
        .await?;

    assert_eq!(
        guard_attempt.status(),
        StatusCode::FORBIDDEN,
        "guard role must not manage geofences"
    );

    let zone_create = client
        .post(format!(
            "{}/api/tracking/client-sites/{}/geofences",
            base_url, site_id
        ))
        .header("Authorization", format!("Bearer {}", supervisor_token))
        .json(&json!({
            "zoneType": "radius",
            "radiusKm": 0.65,
            "isActive": true
        }))
        .send()
        .await?;

    let zone_status = zone_create.status();
    let zone_body = response_json(zone_create).await;
    assert_eq!(
        zone_status,
        StatusCode::CREATED,
        "expected geofence create to succeed, body: {}",
        zone_body
    );

    let zone_id = zone_body
        .get("zoneId")
        .and_then(Value::as_str)
        .expect("zoneId is required for update/delete assertions")
        .to_string();

    let list_response = client
        .get(format!(
            "{}/api/tracking/client-sites/{}/geofences",
            base_url, site_id
        ))
        .header("Authorization", format!("Bearer {}", supervisor_token))
        .send()
        .await?;

    let list_status = list_response.status();
    let list_body = response_json(list_response).await;
    assert_eq!(
        list_status,
        StatusCode::OK,
        "expected geofence listing to succeed, body: {}",
        list_body
    );

    let found_created_zone = list_body
        .get("zones")
        .and_then(Value::as_array)
        .map(|zones| {
            zones
                .iter()
                .any(|zone| zone.get("id").and_then(Value::as_str) == Some(zone_id.as_str()))
        })
        .unwrap_or(false);
    assert!(
        found_created_zone,
        "created zone should appear in site geofence listing"
    );

    let update_response = client
        .put(format!("{}/api/tracking/geofences/{}", base_url, zone_id))
        .header("Authorization", format!("Bearer {}", supervisor_token))
        .json(&json!({
            "zoneType": "polygon",
            "polygonPoints": [
                { "latitude": 7.0717, "longitude": 125.6127 },
                { "latitude": 7.0723, "longitude": 125.6132 },
                { "latitude": 7.0719, "longitude": 125.6138 }
            ],
            "isActive": true
        }))
        .send()
        .await?;

    let update_status = update_response.status();
    let update_body = response_json(update_response).await;
    assert_eq!(
        update_status,
        StatusCode::OK,
        "expected geofence update to succeed, body: {}",
        update_body
    );

    let delete_zone_response = client
        .delete(format!("{}/api/tracking/geofences/{}", base_url, zone_id))
        .header("Authorization", format!("Bearer {}", supervisor_token))
        .send()
        .await?;

    assert_eq!(
        delete_zone_response.status(),
        StatusCode::OK,
        "expected geofence delete to succeed"
    );

    let _ = client
        .delete(format!(
            "{}/api/tracking/client-sites/{}",
            base_url, site_id
        ))
        .header("Authorization", format!("Bearer {}", supervisor_token))
        .send()
        .await;

    Ok(())
}

#[tokio::test]
async fn tracking_and_audit_role_access_paths() -> Result<(), Box<dyn std::error::Error>> {
    if !integration_enabled() {
        eprintln!("Skipping integration test. Set RUN_INTEGRATION_TESTS=true to run.");
        return Ok(());
    }

    let base_url = integration_base_url();
    let client = Client::new();

    let guard_token = build_token("guard", "itest-guard-rbac");
    let supervisor_token = build_token("supervisor", "itest-supervisor-rbac");
    let admin_token = build_token("admin", "itest-admin-rbac");

    let guard_audit_logs = client
        .get(format!("{}/api/audit/logs", base_url))
        .header("Authorization", format!("Bearer {}", guard_token))
        .send()
        .await?;
    assert_eq!(guard_audit_logs.status(), StatusCode::FORBIDDEN);

    let admin_audit_logs = client
        .get(format!("{}/api/audit/logs", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await?;
    assert_eq!(admin_audit_logs.status(), StatusCode::OK);

    let guard_anomalies = client
        .get(format!("{}/api/audit/anomalies", base_url))
        .header("Authorization", format!("Bearer {}", guard_token))
        .send()
        .await?;
    assert_eq!(guard_anomalies.status(), StatusCode::FORBIDDEN);

    let admin_anomalies = client
        .get(format!("{}/api/audit/anomalies", base_url))
        .header("Authorization", format!("Bearer {}", admin_token))
        .send()
        .await?;
    assert_eq!(admin_anomalies.status(), StatusCode::OK);

    let guard_geofences = client
        .get(format!("{}/api/tracking/geofences", base_url))
        .header("Authorization", format!("Bearer {}", guard_token))
        .send()
        .await?;
    assert_eq!(guard_geofences.status(), StatusCode::FORBIDDEN);

    let supervisor_geofences = client
        .get(format!("{}/api/tracking/geofences", base_url))
        .header("Authorization", format!("Bearer {}", supervisor_token))
        .send()
        .await?;
    assert_eq!(supervisor_geofences.status(), StatusCode::OK);

    Ok(())
}
