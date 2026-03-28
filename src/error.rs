use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde_json::json;
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    DatabaseError(String),
    NotFound(String),
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    RateLimited(String),
    GatewayTimeout(String),
    Conflict(String),
    InternalServerError(String),
    ValidationError(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
            AppError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            AppError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            AppError::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
            AppError::RateLimited(msg) => write!(f, "Rate limited: {}", msg),
            AppError::GatewayTimeout(msg) => write!(f, "Gateway timeout: {}", msg),
            AppError::Conflict(msg) => write!(f, "Conflict: {}", msg),
            AppError::InternalServerError(msg) => write!(f, "Internal server error: {}", msg),
            AppError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, error_message, log_message) = match self {
            AppError::DatabaseError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Internal server error".to_string(),
                Some(msg),
            ),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg, None),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg, None),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "unauthorized", msg, None),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg, None),
            AppError::RateLimited(msg) => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", msg, None),
            AppError::GatewayTimeout(msg) => (
                StatusCode::GATEWAY_TIMEOUT,
                "gateway_timeout",
                msg,
                None,
            ),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg, None),
            AppError::InternalServerError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_server_error",
                "Internal server error".to_string(),
                Some(msg),
            ),
            AppError::ValidationError(msg) => (
                StatusCode::BAD_REQUEST,
                "validation_error",
                msg,
                None,
            ),
        };

        if let Some(msg) = log_message {
            tracing::error!(code, status = status.as_u16(), error = %msg, "request failed");
        }

        let body = Json(json!({
            "error": error_message,
            "code": code,
            "status": status.as_u16(),
            "timestamp": Utc::now().to_rfc3339(),
        }));

        (status, body).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
