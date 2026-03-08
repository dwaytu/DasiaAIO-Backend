mod db;
mod handlers;
mod models;
mod routes;
mod utils;
mod error;
mod config;
mod middleware;

use axum::{
    extract::DefaultBodyLimit,
    middleware as axum_middleware,
    routing::{get, post, put, delete},
    Router,
};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Load environment variables
    dotenv::dotenv().ok();
    let config = config::Config::from_env()?;

    // Initialize database pool
    let db_pool = db::init_db_pool(&config.database_url).await?;
    tracing::info!("✓ Connected to PostgreSQL");

    // Run migrations
    db::run_migrations(&db_pool).await?;
    tracing::info!("✓ Database migrations completed");

    let db = Arc::new(db_pool);

    // CORS configuration — allow all origins (no credentials, pure JWT via header)
    // Set CORS_ORIGIN env var in Railway to restrict to a specific frontend domain.
    let cors_layer = if let Ok(origin) = std::env::var("CORS_ORIGIN") {
        tracing::info!("CORS restricted to origin: {}", origin);
        origin
            .parse::<axum::http::HeaderValue>()
            .map(|hv| {
                CorsLayer::new()
                    .allow_origin(hv)
                    .allow_methods(tower_http::cors::Any)
                    .allow_headers(tower_http::cors::Any)
                    .max_age(std::time::Duration::from_secs(3600))
            })
            .unwrap_or_else(|_| CorsLayer::very_permissive())
    } else {
        CorsLayer::very_permissive()
    };

    // Build router
    let app = Router::new()
        // Auth routes
        .route("/api/register", post(handlers::auth::register))
        .route("/api/login", post(handlers::auth::login))
        .route("/api/verify", post(handlers::auth::verify_email))
        .route("/api/resend-code", post(handlers::auth::resend_verification_code))
        .route("/api/forgot-password", post(handlers::auth::forgot_password))
        .route("/api/verify-reset-code", post(handlers::auth::verify_reset_code))
        .route("/api/reset-password", post(handlers::auth::reset_password))
        // Auth routes with /auth prefix (alternative URIs)
        .route("/api/auth/register", post(handlers::auth::register))
        .route("/api/auth/login", post(handlers::auth::login))
        .route("/api/auth/verify", post(handlers::auth::verify_email))
        .route("/api/auth/resend-code", post(handlers::auth::resend_verification_code))
        .route("/api/auth/forgot-password", post(handlers::auth::forgot_password))
        .route("/api/auth/verify-reset-code", post(handlers::auth::verify_reset_code))
        .route("/api/auth/reset-password", post(handlers::auth::reset_password))
        
        // User routes
        .route(
            "/api/users",
            get(handlers::users::get_all_users)
                .post(handlers::users::create_user_by_actor)
                .route_layer(axum_middleware::from_fn(middleware::authz::require_manage_users))
                .route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)),
        )
        .route(
            "/api/users/pending-approvals",
            get(handlers::users::get_pending_guard_approvals)
                .route_layer(axum_middleware::from_fn(middleware::authz::require_manage_users)),
        )
        .route(
            "/api/users/:id/approval",
            put(handlers::users::update_guard_approval_status)
                .route_layer(axum_middleware::from_fn(middleware::authz::require_manage_users))
                .route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)),
        )
        .route(
            "/api/user/:id/profile-photo",
            put(handlers::users::update_profile_photo)
                .route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated))
                .route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)),
        )
        .route(
            "/api/user/:id/profile-photo",
            delete(handlers::users::delete_profile_photo)
                .route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated))
                .route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)),
        )
        .route(
            "/api/user/:id",
            get(handlers::users::get_user_by_id)
                .route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)),
        )
        .route(
            "/api/user/:id",
            put(handlers::users::update_user)
                .route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated))
                .route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)),
        )
        .route(
            "/api/user/:id",
            delete(handlers::users::delete_user)
                .route_layer(axum_middleware::from_fn(middleware::authz::require_manage_users))
                .route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)),
        )
        // User routes with /users prefix (alternative URIs)
        .route("/api/users/:id", get(handlers::users::get_user_by_id).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)))
        .route("/api/users/:id", put(handlers::users::update_user).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/users/:id", delete(handlers::users::delete_user).route_layer(axum_middleware::from_fn(middleware::authz::require_manage_users)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/users/:id/profile-photo", put(handlers::users::update_profile_photo).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/users/:id/profile-photo", delete(handlers::users::delete_profile_photo).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        
        // Firearm routes
        .route("/api/firearms", post(handlers::firearms::add_firearm).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/firearms", get(handlers::firearms::get_all_firearms).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_management)))
        .route("/api/firearms/:id", get(handlers::firearms::get_firearm_by_id).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_management)))
        .route("/api/firearms/:id", put(handlers::firearms::update_firearm).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/firearms/:id", delete(handlers::firearms::delete_firearm).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        
        // Firearm allocation routes
        .route("/api/firearm-allocation/issue", post(handlers::firearm_allocation::issue_firearm).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_allocation)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/firearm-allocation/return", post(handlers::firearm_allocation::return_firearm).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_allocation)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/firearm-allocation", post(handlers::firearm_allocation::issue_firearm).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_allocation)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests))) // Alias for issue
        .route("/api/guard-allocations/:guard_id", get(handlers::firearm_allocation::get_guard_allocations).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)))
        .route("/api/firearm-allocations/active", get(handlers::firearm_allocation::get_active_allocations).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_allocation)))
        .route("/api/firearm-allocations", get(handlers::firearm_allocation::get_all_allocations).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_allocation)))
        
        // Firearm maintenance routes
        .route("/api/firearm-maintenance", get(handlers::firearms::get_firearm_maintenance).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_management)))
        
        // Guard replacement routes
        .route("/api/guard-replacement/shifts", post(handlers::guard_replacement::create_shift).route_layer(axum_middleware::from_fn(middleware::authz::require_schedule_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/guard-replacement/shifts", get(handlers::guard_replacement::get_all_shifts).route_layer(axum_middleware::from_fn(middleware::authz::require_schedule_management)))
        .route("/api/guard-replacement/shifts/:shift_id", put(handlers::guard_replacement::update_shift).route_layer(axum_middleware::from_fn(middleware::authz::require_schedule_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/guard-replacement/shifts/:shift_id", delete(handlers::guard_replacement::delete_shift).route_layer(axum_middleware::from_fn(middleware::authz::require_schedule_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/guard-replacement/guard/:guard_id/shifts", get(handlers::guard_replacement::get_guard_shifts).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)))
        .route("/api/guard-replacement/attendance/check-in", post(handlers::guard_replacement::check_in).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/guard-replacement/attendance/check-out", post(handlers::guard_replacement::check_out).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/guard-replacement/check-in", post(handlers::guard_replacement::check_in).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests))) // Alias
        .route("/api/guard-replacement/check-out", post(handlers::guard_replacement::check_out).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests))) // Alias
        .route("/api/attendance/:guard_id", get(handlers::guard_replacement::get_guard_attendance).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)))
        .route("/api/guard-replacement/detect-no-shows", post(handlers::guard_replacement::detect_no_shows).route_layer(axum_middleware::from_fn(middleware::authz::require_schedule_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/guard-replacement/request-replacement", post(handlers::guard_replacement::request_replacement).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/guard-replacement/accept-replacement", post(handlers::guard_replacement::accept_replacement).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/guard-replacement/set-availability", post(handlers::guard_replacement::set_availability).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/guard-replacement/availability/:guard_id", get(handlers::guard_replacement::get_guard_availability).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)))
        
        // Notification routes (restructured to avoid route conflicts)
        .route("/api/notifications", post(handlers::notifications::create_notification).route_layer(axum_middleware::from_fn(middleware::authz::require_notifications_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/users/:user_id/notifications", get(handlers::notifications::get_user_notifications).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)))
        .route("/api/users/:user_id/notifications/unread-count", get(handlers::notifications::get_unread_count).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)))
        .route("/api/users/:user_id/notifications/mark-all-read", put(handlers::notifications::mark_all_read).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/notifications/:notification_id/read", put(handlers::notifications::mark_notification_read).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/notifications/:notification_id", delete(handlers::notifications::delete_notification).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))

        // Mission assignment routes (Integrated Workflow)
        .route("/api/missions/assign", post(handlers::missions::assign_mission).route_layer(axum_middleware::from_fn(middleware::authz::require_mission_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/missions", get(handlers::missions::get_missions).route_layer(axum_middleware::from_fn(middleware::authz::require_mission_management)))

        // Guard permits routes
        .route("/api/guard-firearm-permits", post(handlers::permits::create_guard_permit).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/guard-firearm-permits", get(handlers::permits::get_all_permits).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_management)))
        .route("/api/guard-firearm-permits/expiring", get(handlers::permits::get_expiring_permits).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_management)))
        .route("/api/guard-firearm-permits/auto-expire", post(handlers::permits::auto_expire_permits).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/guard-firearm-permits/:permit_id/revoke", put(handlers::permits::revoke_permit).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/guard-firearm-permits/:guard_id", get(handlers::permits::get_guard_permits).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_management)))

        // Firearm maintenance routes (Requirement 3)
        .route("/api/firearm-maintenance/schedule", post(handlers::firearm_maintenance::schedule_maintenance).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/firearm-maintenance/pending", get(handlers::firearm_maintenance::get_pending_maintenance).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_management)))
        .route("/api/firearm-maintenance/:maintenance_id/complete", post(handlers::firearm_maintenance::complete_maintenance).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/firearm-maintenance/:firearm_id", get(handlers::firearm_maintenance::get_firearm_maintenance).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_management)))

        // Training records routes (Requirement 3)
        .route("/api/training-records", post(handlers::training::create_training_record).route_layer(axum_middleware::from_fn(middleware::authz::require_schedule_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/training-records/expiring", get(handlers::training::get_expiring_training).route_layer(axum_middleware::from_fn(middleware::authz::require_schedule_management)))
        .route("/api/training-records/:guard_id", get(handlers::training::get_guard_training).route_layer(axum_middleware::from_fn(middleware::authz::require_schedule_management)))

        // Overdue allocations (Requirement 3)
        .route("/api/firearm-allocations/overdue", get(handlers::firearm_allocation::get_overdue_allocations).route_layer(axum_middleware::from_fn(middleware::authz::require_firearm_allocation)))

        // Support tickets routes
        .route("/api/support-tickets", post(handlers::support_tickets::create_ticket).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/support-tickets/:guard_id", get(handlers::support_tickets::get_guard_tickets).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)))
        
        // Merit score system routes (Requirement 2)
        .route("/api/merit/calculate", post(handlers::merit::calculate_merit_score).route_layer(axum_middleware::from_fn(middleware::authz::require_merit_manage)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/merit/:guard_id", get(handlers::merit::get_guard_merit_score).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)))
        .route("/api/merit/rankings/all", get(handlers::merit::get_ranked_guards).route_layer(axum_middleware::from_fn(middleware::authz::require_merit_view)))
        .route("/api/merit/evaluations/submit", post(handlers::merit::submit_client_evaluation).route_layer(axum_middleware::from_fn(middleware::authz::require_merit_manage)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/merit/evaluations/:guard_id", get(handlers::merit::get_guard_evaluations).route_layer(axum_middleware::from_fn(middleware::authz::require_authenticated)))
        .route("/api/merit/overtime-candidates", get(handlers::merit::get_overtime_candidates).route_layer(axum_middleware::from_fn(middleware::authz::require_merit_view)))
        
        // Armored car routes
        .route("/api/armored-cars", post(handlers::armored_cars::add_armored_car).route_layer(axum_middleware::from_fn(middleware::authz::require_armored_car_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/armored-cars", get(handlers::armored_cars::get_all_armored_cars).route_layer(axum_middleware::from_fn(middleware::authz::require_armored_car_management)))
        .route("/api/armored-cars/:id", get(handlers::armored_cars::get_armored_car_by_id).route_layer(axum_middleware::from_fn(middleware::authz::require_armored_car_management)))
        .route("/api/armored-cars/:id", put(handlers::armored_cars::update_armored_car).route_layer(axum_middleware::from_fn(middleware::authz::require_armored_car_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/armored-cars/:id", delete(handlers::armored_cars::delete_armored_car).route_layer(axum_middleware::from_fn(middleware::authz::require_armored_car_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        
        // Car allocation routes
        .route("/api/car-allocation/issue", post(handlers::armored_cars::issue_car).route_layer(axum_middleware::from_fn(middleware::authz::require_armored_car_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/car-allocation/return", post(handlers::armored_cars::return_car).route_layer(axum_middleware::from_fn(middleware::authz::require_armored_car_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/car-allocations/:car_id", get(handlers::armored_cars::get_car_allocations).route_layer(axum_middleware::from_fn(middleware::authz::require_armored_car_management)))
        .route("/api/car-allocations/active", get(handlers::armored_cars::get_active_car_allocations).route_layer(axum_middleware::from_fn(middleware::authz::require_armored_car_management)))
        
        // Car maintenance routes
        .route("/api/car-maintenance/schedule", post(handlers::armored_cars::schedule_maintenance).route_layer(axum_middleware::from_fn(middleware::authz::require_armored_car_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/car-maintenance/:maintenance_id/complete", post(handlers::armored_cars::complete_maintenance).route_layer(axum_middleware::from_fn(middleware::authz::require_armored_car_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/car-maintenance/:car_id", get(handlers::armored_cars::get_car_maintenance_records).route_layer(axum_middleware::from_fn(middleware::authz::require_armored_car_management)))
        
        // Driver assignment routes
        .route("/api/driver-assignment/assign", post(handlers::armored_cars::assign_driver).route_layer(axum_middleware::from_fn(middleware::authz::require_armored_car_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/driver-assignment/:assignment_id/unassign", post(handlers::armored_cars::unassign_driver).route_layer(axum_middleware::from_fn(middleware::authz::require_armored_car_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/car-drivers/:car_id", get(handlers::armored_cars::get_car_drivers).route_layer(axum_middleware::from_fn(middleware::authz::require_armored_car_management)))
        
        // Trip management routes
        .route("/api/trips", post(handlers::armored_cars::create_trip).route_layer(axum_middleware::from_fn(middleware::authz::require_trip_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/trips/end", post(handlers::armored_cars::end_trip).route_layer(axum_middleware::from_fn(middleware::authz::require_trip_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/trips/car/:car_id", get(handlers::armored_cars::get_car_trips).route_layer(axum_middleware::from_fn(middleware::authz::require_trip_management)))
        .route("/api/trips", get(handlers::armored_cars::get_all_trips).route_layer(axum_middleware::from_fn(middleware::authz::require_trip_management)))
        
        // Enhanced trip management routes
        .route("/api/trip-management/active", get(handlers::trip_management::get_active_trips).route_layer(axum_middleware::from_fn(middleware::authz::require_trip_management)))
        .route("/api/trip-management/:trip_id", get(handlers::trip_management::get_trip_details).route_layer(axum_middleware::from_fn(middleware::authz::require_trip_management)))
        .route("/api/trip-management/:trip_id/status", put(handlers::trip_management::update_trip_status).route_layer(axum_middleware::from_fn(middleware::authz::require_trip_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/trip-management/assign-driver", post(handlers::trip_management::assign_driver_to_trip).route_layer(axum_middleware::from_fn(middleware::authz::require_trip_management)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        .route("/api/trip-management/driver-assignments", get(handlers::trip_management::get_driver_assignments).route_layer(axum_middleware::from_fn(middleware::authz::require_trip_management)))
        
        // Analytics routes
        .route("/api/analytics", get(handlers::analytics::get_analytics).route_layer(axum_middleware::from_fn(middleware::authz::require_analytics_view)))
        .route("/api/analytics/trends", get(handlers::analytics::get_performance_trends).route_layer(axum_middleware::from_fn(middleware::authz::require_analytics_view)))
        .route("/api/analytics/mission-status", put(handlers::analytics::update_mission_status).route_layer(axum_middleware::from_fn(middleware::authz::require_analytics_view)).route_layer(axum_middleware::from_fn_with_state(db.clone(), middleware::audit::audit_write_requests)))
        
        // Health check
        .route("/api/health", get(handlers::health::health_check))
        
        .layer(cors_layer)
        .layer(TraceLayer::new_for_http())
        .layer(DefaultBodyLimit::max(1024 * 1024)) // 1MB limit
        .with_state(db);

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", config.server_host, config.server_port))
        .await?;
    
    tracing::info!("✓ Server running on http://{}:{}", config.server_host, config.server_port);
    
    axum::serve(listener, app).await?;

    Ok(())
}
