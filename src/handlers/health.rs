use axum::{extract::State, Json};
use serde_json::json;
use sqlx::PgPool;
use std::{sync::Arc, sync::OnceLock, time::Instant};

static STARTED_AT: OnceLock<Instant> = OnceLock::new();

pub fn mark_started() {
    let _ = STARTED_AT.set(Instant::now());
}

fn uptime_seconds() -> u64 {
    STARTED_AT
        .get()
        .map(|started| started.elapsed().as_secs())
        .unwrap_or(0)
}

async fn database_status(db: &PgPool) -> &'static str {
    match sqlx::query("SELECT 1").execute(db).await {
        Ok(_) => "up",
        Err(_) => "down",
    }
}

pub async fn health_check(State(db): State<Arc<PgPool>>) -> Json<serde_json::Value> {
    let db_status = database_status(db.as_ref()).await;
    let ws_connections = crate::handlers::tracking::active_websocket_connections();

    let status = if db_status == "up" { "ok" } else { "degraded" };

    Json(json!({
        "status": status,
        "services": {
            "database": db_status,
            "api": "up",
            "websocket": {
                "status": "up",
                "activeConnections": ws_connections
            }
        },
        "uptimeSeconds": uptime_seconds(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

pub async fn system_health(State(db): State<Arc<PgPool>>) -> Json<serde_json::Value> {
    let db_status = database_status(db.as_ref()).await;
    let ws_connections = crate::handlers::tracking::active_websocket_connections();

    let status = if db_status == "up" { "ok" } else { "degraded" };

    Json(json!({
        "status": status,
        "services": {
            "database": db_status,
            "api": "up",
            "websocket": {
                "status": "up",
                "activeConnections": ws_connections
            }
        },
        "uptimeSeconds": uptime_seconds(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}
