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

pub async fn enforce_request_timeout(request: Request<Body>, next: Next) -> Response {
    match tokio::time::timeout(
        Duration::from_secs(request_timeout_seconds()),
        next.run(request),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => AppError::GatewayTimeout("Request timed out. Please retry.".to_string())
            .into_response(),
    }
}
