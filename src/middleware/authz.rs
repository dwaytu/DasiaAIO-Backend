use axum::{body::Body, http::Request, middleware::Next, response::Response};

use crate::{error::AppError, utils};

fn log_denied_access(path: &str, role: &str, reason: &str) {
    tracing::warn!(path = %path, role = %role, reason = %reason, "authorization denied");
}

fn is_legal_bootstrap_path(path: &str) -> bool {
    path == "/api/logout"
        || path == "/api/auth/logout"
        || path == "/api/legal/consent"
        || path == "/api/legal/consent/status"
}

fn enforce_legal_consent(path: &str, claims: &utils::TokenClaims) -> Result<(), AppError> {
    if claims.legal_consent_accepted || is_legal_bootstrap_path(path) {
        return Ok(());
    }

    Err(AppError::Forbidden(
        "Legal consent required. Please accept Terms of Agreement to continue.".to_string(),
    ))
}

async fn authorize_permission(
    req: Request<Body>,
    next: Next,
    permission: &'static str,
) -> Result<Response, AppError> {
    let path = req.uri().path().to_string();
    let token = utils::extract_bearer_token(req.headers())?;
    let claims = utils::verify_token(&token)?;

    enforce_legal_consent(&path, &claims)?;

    if !utils::has_permission(&claims.role, permission) {
        log_denied_access(
            &path,
            &utils::normalize_role(&claims.role),
            &format!("missing permission {}", permission),
        );
        return Err(AppError::Forbidden(format!(
            "Missing required permission: {}",
            permission
        )));
    }

    Ok(next.run(req).await)
}

pub async fn require_authenticated(req: Request<Body>, next: Next) -> Result<Response, AppError> {
    let path = req.uri().path().to_string();
    let token = utils::extract_bearer_token(req.headers())?;
    let claims = utils::verify_token(&token)?;
    enforce_legal_consent(&path, &claims)?;
    Ok(next.run(req).await)
}

pub async fn require_superadmin(req: Request<Body>, next: Next) -> Result<Response, AppError> {
    let path = req.uri().path().to_string();
    let token = utils::extract_bearer_token(req.headers())?;
    let claims = utils::verify_token(&token)?;
    enforce_legal_consent(&path, &claims)?;

    let role = utils::normalize_role(&claims.role);
    if role != "superadmin" {
        log_denied_access(&path, &role, "superadmin role required");
        return Err(AppError::Forbidden(
            "This endpoint is restricted to superadmin accounts".to_string(),
        ));
    }

    Ok(next.run(req).await)
}

pub async fn require_tracking_access(req: Request<Body>, next: Next) -> Result<Response, AppError> {
    let path = req.uri().path().to_string();
    let token = utils::extract_bearer_token(req.headers())?;
    let claims = utils::verify_token(&token)?;
    enforce_legal_consent(&path, &claims)?;

    let role = utils::normalize_role(&claims.role);
    if role != "supervisor" && role != "guard" {
        log_denied_access(&path, &role, "tracking scope requires supervisor or guard role");
        return Err(AppError::Forbidden(
            "Tracking endpoints are limited to supervisor and guard roles".to_string(),
        ));
    }

    Ok(next.run(req).await)
}

pub async fn require_manage_users(req: Request<Body>, next: Next) -> Result<Response, AppError> {
    authorize_permission(req, next, "create_user").await
}

pub async fn require_firearm_management(
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    authorize_permission(req, next, "manage_firearms").await
}

pub async fn require_firearm_allocation(
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    authorize_permission(req, next, "allocate_firearm").await
}

pub async fn require_armored_car_management(
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    authorize_permission(req, next, "manage_armored_cars").await
}

pub async fn require_mission_management(
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    authorize_permission(req, next, "manage_missions").await
}

pub async fn require_schedule_management(
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    authorize_permission(req, next, "manage_schedules").await
}

pub async fn require_analytics_view(req: Request<Body>, next: Next) -> Result<Response, AppError> {
    authorize_permission(req, next, "view_analytics").await
}

pub async fn require_trip_management(req: Request<Body>, next: Next) -> Result<Response, AppError> {
    authorize_permission(req, next, "manage_trip_status").await
}

pub async fn require_notifications_management(
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    authorize_permission(req, next, "manage_notifications").await
}

pub async fn require_merit_view(req: Request<Body>, next: Next) -> Result<Response, AppError> {
    authorize_permission(req, next, "view_merit").await
}

pub async fn require_merit_manage(req: Request<Body>, next: Next) -> Result<Response, AppError> {
    authorize_permission(req, next, "manage_merit").await
}
