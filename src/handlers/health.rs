use axum::{extract::State, Json};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

pub async fn health_check() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok"
    }))
}

pub async fn system_health(
    State(db): State<Arc<PgPool>>,
) -> Json<serde_json::Value> {
    let db_status = match sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(db.as_ref())
        .await
    {
        Ok(_) => "up",
        Err(_) => "down",
    };

    let status = if db_status == "up" { "ok" } else { "degraded" };

    Json(json!({
        "status": status,
        "services": {
            "database": db_status,
            "api": "up"
        },
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

