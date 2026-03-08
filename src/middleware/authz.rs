use axum::{
    body::Body,
    http::Request,
    middleware::Next,
    response::Response,
};

use crate::{
    error::AppError,
    utils,
};

async fn authorize_permission(
    req: Request<Body>,
    next: Next,
    permission: &'static str,
) -> Result<Response, AppError> {
    let token = utils::extract_bearer_token(req.headers())?;
    let claims = utils::verify_token(&token)?;

    if !utils::has_permission(&claims.role, permission) {
        return Err(AppError::Forbidden(format!(
            "Missing required permission: {}",
            permission
        )));
    }

    Ok(next.run(req).await)
}

pub async fn require_authenticated(
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let token = utils::extract_bearer_token(req.headers())?;
    let _claims = utils::verify_token(&token)?;
    Ok(next.run(req).await)
}

pub async fn require_manage_users(
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
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

pub async fn require_analytics_view(
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    authorize_permission(req, next, "view_analytics").await
}

pub async fn require_trip_management(
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    authorize_permission(req, next, "manage_trip_status").await
}

pub async fn require_notifications_management(
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    authorize_permission(req, next, "manage_notifications").await
}

pub async fn require_merit_view(
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    authorize_permission(req, next, "view_merit").await
}

pub async fn require_merit_manage(
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    authorize_permission(req, next, "manage_merit").await
}

