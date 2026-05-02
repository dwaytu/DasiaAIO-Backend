use axum::{
    body::Body,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::time::Duration;

use crate::error::AppError;

fn request_timeout_seconds() -> u64 {
    std::env::var("REQUEST_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.clamp(5, 120))
        .unwrap_or(30)
}

fn mdr_commit_timeout_seconds() -> u64 {
    std::env::var("REQUEST_TIMEOUT_MDR_COMMIT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.clamp(30, 300))
        .unwrap_or(120)
}

pub async fn enforce_request_timeout(request: Request<Body>, next: Next) -> Response {
    let path = request.uri().path().to_string();
    let timeout_secs = if path.starts_with("/api/mdr/batches/") && path.ends_with("/commit") {
        mdr_commit_timeout_seconds()
    } else {
        request_timeout_seconds()
    };

    match tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        next.run(request),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => AppError::GatewayTimeout("Request timed out. Please retry.".to_string())
            .into_response(),
    }
}
