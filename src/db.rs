use crate::error::{AppError, AppResult};
use sqlx::postgres::{PgPool, PgPoolOptions};

pub async fn init_db_pool(
    database_url: &str,
    max_connections: u32,
    acquire_timeout_secs: u32,
) -> AppResult<PgPool> {
    const MAX_RETRIES: u32 = 10;
    const RETRY_DELAY_SECS: u64 = 5;

    for attempt in 1..=MAX_RETRIES {
        match PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(std::time::Duration::from_secs(acquire_timeout_secs as u64))
            .connect(database_url)
            .await
        {
            Ok(pool) => {
                tracing::info!(
                    "✓ Database connected on attempt {}/{}",
                    attempt,
                    MAX_RETRIES
                );
                return Ok(pool);
            }
            Err(e) if attempt < MAX_RETRIES => {
                tracing::warn!(
                    "DB connection attempt {}/{} failed: {}. Retrying in {}s...",
                    attempt,
                    MAX_RETRIES,
                    e,
                    RETRY_DELAY_SECS
                );
                tokio::time::sleep(std::time::Duration::from_secs(RETRY_DELAY_SECS)).await;
            }
            Err(e) => {
                return Err(AppError::DatabaseError(format!(
                    "Failed to connect to database after {} attempts: {}",
                    MAX_RETRIES, e
                )));
            }
        }
    }
    unreachable!()
}

pub async fn run_migrations(pool: &PgPool) -> AppResult<()> {
    // Create users table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id VARCHAR(36) PRIMARY KEY,
            email VARCHAR(255) NOT NULL UNIQUE,
            username VARCHAR(255) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL DEFAULT 'guard',
            full_name VARCHAR(255) NOT NULL,
            phone_number VARCHAR(20) NOT NULL,
            license_number VARCHAR(50),
            license_expiry_date TIMESTAMP WITH TIME ZONE,
            profile_photo TEXT,
            verified BOOLEAN DEFAULT false,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create users table: {}", e)))?;

    // Prevent fresh legacy role generation by enforcing canonical role default.
    sqlx::query("ALTER TABLE users ALTER COLUMN role SET DEFAULT 'guard'")
        .execute(pool)
        .await
        .map_err(|e| {
            AppError::DatabaseError(format!("Failed to set users.role default to guard: {}", e))
        })?;

    // Migrate legacy stored aliases to canonical role values.
    sqlx::query(
        r#"UPDATE users
           SET role = 'guard'
           WHERE LOWER(BTRIM(role)) = 'user'"#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to migrate legacy users.role aliases to guard: {}",
            e
        ))
    })?;

    // Backfill profile_photo column for databases created before this migration
    sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_photo TEXT")
        .execute(pool)
        .await
        .map_err(|e| {
            AppError::DatabaseError(format!("Failed to add profile_photo column: {}", e))
        })?;

    // Add license_issued_date column
    sqlx::query(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS license_issued_date TIMESTAMP WITH TIME ZONE",
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to add license_issued_date column: {}", e))
    })?;

    // Add address column
    sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS address TEXT")
        .execute(pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to add address column: {}", e)))?;

    // Add RBAC and approval workflow columns
    sqlx::query(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS approval_status VARCHAR(20) NOT NULL DEFAULT 'approved'"
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to add approval_status column: {}", e)))?;

    sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS approved_by VARCHAR(36)")
        .execute(pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to add approved_by column: {}", e)))?;

    sqlx::query(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS approval_date TIMESTAMP WITH TIME ZONE",
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to add approval_date column: {}", e)))?;

    sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS created_by VARCHAR(36)")
        .execute(pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to add created_by column: {}", e)))?;

    sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMP WITH TIME ZONE")
        .execute(pool)
        .await
        .map_err(|e| {
            AppError::DatabaseError(format!("Failed to add last_seen_at column: {}", e))
        })?;

    sqlx::query(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS consent_accepted_at TIMESTAMP WITH TIME ZONE",
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to add consent_accepted_at column: {}", e))
    })?;

    sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS consent_version VARCHAR(50)")
        .execute(pool)
        .await
        .map_err(|e| {
            AppError::DatabaseError(format!("Failed to add consent_version column: {}", e))
        })?;

    sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS consent_ip VARCHAR(64)")
        .execute(pool)
        .await
        .map_err(|e| {
            AppError::DatabaseError(format!("Failed to add consent_ip column: {}", e))
        })?;

    sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS consent_user_agent TEXT")
        .execute(pool)
        .await
        .map_err(|e| {
            AppError::DatabaseError(format!("Failed to add consent_user_agent column: {}", e))
        })?;

    sqlx::query(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS location_tracking_consent BOOLEAN NOT NULL DEFAULT false",
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to add location_tracking_consent column: {}",
            e
        ))
    })?;

    sqlx::query(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS location_tracking_consent_granted_at TIMESTAMP WITH TIME ZONE",
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to add location_tracking_consent_granted_at column: {}",
            e
        ))
    })?;

    sqlx::query(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS location_tracking_consent_revoked_at TIMESTAMP WITH TIME ZONE",
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to add location_tracking_consent_revoked_at column: {}",
            e
        ))
    })?;

    sqlx::query(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS location_tracking_consent_updated_at TIMESTAMP WITH TIME ZONE",
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to add location_tracking_consent_updated_at column: {}",
            e
        ))
    })?;

    sqlx::query(
        r#"UPDATE users
           SET location_tracking_consent_updated_at = COALESCE(
               location_tracking_consent_updated_at,
               location_tracking_consent_granted_at,
               location_tracking_consent_revoked_at,
               updated_at,
               created_at,
               CURRENT_TIMESTAMP
           )
           WHERE location_tracking_consent_updated_at IS NULL"#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to backfill location_tracking_consent_updated_at values: {}",
            e
        ))
    })?;

    // Operational tracking tables for real-time map monitoring.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS client_sites (
            id VARCHAR(36) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            address TEXT,
            latitude DOUBLE PRECISION NOT NULL,
            longitude DOUBLE PRECISION NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT true,
            created_by VARCHAR(36),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create client_sites table: {}", e)))?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tracking_points (
            id VARCHAR(36) PRIMARY KEY,
            entity_type VARCHAR(32) NOT NULL,
            entity_id VARCHAR(64) NOT NULL,
            user_id VARCHAR(36),
            label VARCHAR(255),
            status VARCHAR(50),
            latitude DOUBLE PRECISION NOT NULL,
            longitude DOUBLE PRECISION NOT NULL,
            heading DOUBLE PRECISION,
            speed_kph DOUBLE PRECISION,
            accuracy_meters DOUBLE PRECISION,
            recorded_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_by VARCHAR(36),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create tracking_points table: {}", e))
    })?;

    sqlx::query(
        "ALTER TABLE tracking_points ADD COLUMN IF NOT EXISTS accuracy_meters DOUBLE PRECISION",
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to add accuracy_meters column: {}", e)))?;

    sqlx::query("ALTER TABLE tracking_points ADD COLUMN IF NOT EXISTS user_id VARCHAR(36)")
        .execute(pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to add user_id column: {}", e)))?;

    sqlx::query(
        r#"DO $$
                     BEGIN
                         IF NOT EXISTS (
                             SELECT 1
                             FROM information_schema.table_constraints
                             WHERE constraint_name = 'tracking_points_user_id_fkey'
                                 AND table_name = 'tracking_points'
                         ) THEN
                             ALTER TABLE tracking_points
                                 ADD CONSTRAINT tracking_points_user_id_fkey
                                 FOREIGN KEY (user_id)
                                 REFERENCES users(id)
                                 ON DELETE SET NULL;
                         END IF;
                     END $$;"#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to ensure user_id foreign key: {}", e)))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_tracking_points_entity_time ON tracking_points (entity_type, entity_id, recorded_at DESC)"
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create tracking index: {}", e)))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_tracking_points_user_time ON tracking_points (user_id, recorded_at DESC)"
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create tracking user index: {}", e)))?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS geofence_events (
            id VARCHAR(36) PRIMARY KEY,
            guard_id VARCHAR(36) NOT NULL,
            client_site_id VARCHAR(36) NOT NULL,
            event_type VARCHAR(16) NOT NULL,
            latitude DOUBLE PRECISION,
            longitude DOUBLE PRECISION,
            distance_km DOUBLE PRECISION,
            message TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (guard_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (client_site_id) REFERENCES client_sites(id) ON DELETE CASCADE,
            CONSTRAINT geofence_events_type_check CHECK (event_type IN ('enter', 'exit'))
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create geofence_events table: {}", e))
    })?;

    for geofence_index in &[
        "CREATE INDEX IF NOT EXISTS idx_geofence_events_guard_created ON geofence_events(guard_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_geofence_events_site_created ON geofence_events(client_site_id, created_at DESC)",
    ] {
        sqlx::query(geofence_index)
            .execute(pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to create geofence index: {}", e)))?;
    }

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS site_geofences (
            id VARCHAR(36) PRIMARY KEY,
            client_site_id VARCHAR(36) NOT NULL,
            zone_type VARCHAR(16) NOT NULL,
            radius_km DOUBLE PRECISION,
            polygon_points JSONB,
            is_active BOOLEAN NOT NULL DEFAULT true,
            created_by VARCHAR(36),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_site_id) REFERENCES client_sites(id) ON DELETE CASCADE,
            CONSTRAINT site_geofences_zone_type_check CHECK (zone_type IN ('radius', 'polygon'))
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create site_geofences table: {}", e))
    })?;

    for geofence_zone_index in &[
        "CREATE INDEX IF NOT EXISTS idx_site_geofences_site_active ON site_geofences(client_site_id, is_active)",
        "CREATE INDEX IF NOT EXISTS idx_site_geofences_type_active ON site_geofences(zone_type, is_active)",
    ] {
        sqlx::query(geofence_zone_index)
            .execute(pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to create site geofence index: {}", e)))?;
    }

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS incidents (
            id VARCHAR(36) PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            location VARCHAR(255) NOT NULL,
            reported_by VARCHAR(36) NOT NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'open',
            priority VARCHAR(32) NOT NULL DEFAULT 'medium',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT incidents_status_check CHECK (status IN ('open', 'investigating', 'resolved')),
            CONSTRAINT incidents_priority_check CHECK (priority IN ('low', 'medium', 'high', 'critical')),
            FOREIGN KEY (reported_by) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create incidents table: {}", e)))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_incidents_status_priority_created ON incidents (status, priority, created_at DESC)"
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create incidents index: {}", e)))?;

    // Feedback table used by feedback handlers and dashboards.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS feedback (
            id VARCHAR(36) PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL,
            rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
            comments TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT feedback_user_unique UNIQUE (user_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create feedback table: {}", e)))?;

    for feedback_index in &[
        "CREATE INDEX IF NOT EXISTS idx_feedback_user_id ON feedback(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_feedback_created_at ON feedback(created_at DESC)",
    ] {
        sqlx::query(feedback_index)
            .execute(pool)
            .await
            .map_err(|e| {
                AppError::DatabaseError(format!("Failed to create feedback index: {}", e))
            })?;
    }

    // Create normalized RBAC tables for permission-based authorization.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS roles (
            id VARCHAR(36) PRIMARY KEY,
            role_key VARCHAR(50) NOT NULL UNIQUE,
            role_name VARCHAR(100) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create roles table: {}", e)))?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS permissions (
            id VARCHAR(36) PRIMARY KEY,
            permission_key VARCHAR(100) NOT NULL UNIQUE,
            description TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create permissions table: {}", e)))?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS role_permissions (
            id VARCHAR(36) PRIMARY KEY,
            role_id VARCHAR(36) NOT NULL,
            permission_id VARCHAR(36) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(role_id, permission_id),
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create role_permissions table: {}", e))
    })?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS user_roles (
            id VARCHAR(36) PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL,
            role_id VARCHAR(36) NOT NULL,
            is_primary BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, role_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create user_roles table: {}", e)))?;

    // Seed role catalog.
    for (role_key, role_name) in [
        ("superadmin", "Super Administrator"),
        ("admin", "Administrator"),
        ("supervisor", "Supervisor"),
        ("guard", "Guard"),
    ] {
        sqlx::query(
            "INSERT INTO roles (id, role_key, role_name) VALUES ($1, $2, $3) ON CONFLICT (role_key) DO NOTHING",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(role_key)
        .bind(role_name)
        .execute(pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to seed roles: {}", e)))?;
    }

    // Seed permission catalog.
    for (permission_key, description) in [
        ("create_user", "Create user accounts"),
        ("update_user", "Update user accounts"),
        ("delete_user", "Delete user accounts"),
        (
            "approve_guard_registration",
            "Approve or reject pending guard registrations",
        ),
        ("manage_firearms", "Manage firearm inventory"),
        ("allocate_firearm", "Issue and return firearm allocations"),
        ("manage_armored_cars", "Manage armored car fleet records"),
        (
            "assign_vehicle_driver",
            "Assign drivers to vehicles and trips",
        ),
        ("manage_missions", "Create and manage mission assignments"),
        ("manage_schedules", "Create and manage guard schedules"),
        ("view_analytics", "View analytics dashboards and trends"),
        ("manage_trip_status", "Update trip lifecycle status"),
        ("view_support_tickets", "View support tickets"),
        ("create_support_ticket", "Create support tickets"),
        ("manage_notifications", "Read/update notifications"),
        ("view_merit", "View merit scoring data"),
        ("manage_merit", "Calculate or update merit scoring data"),
    ] {
        sqlx::query(
            "INSERT INTO permissions (id, permission_key, description) VALUES ($1, $2, $3) ON CONFLICT (permission_key) DO NOTHING",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(permission_key)
        .bind(description)
        .execute(pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to seed permissions: {}", e)))?;
    }

    // Seed role -> permission relationships.
    for (role_key, permission_key) in [
        // superadmin
        ("superadmin", "create_user"),
        ("superadmin", "update_user"),
        ("superadmin", "delete_user"),
        ("superadmin", "approve_guard_registration"),
        ("superadmin", "manage_firearms"),
        ("superadmin", "allocate_firearm"),
        ("superadmin", "manage_armored_cars"),
        ("superadmin", "assign_vehicle_driver"),
        ("superadmin", "manage_missions"),
        ("superadmin", "manage_schedules"),
        ("superadmin", "view_analytics"),
        ("superadmin", "manage_trip_status"),
        ("superadmin", "view_support_tickets"),
        ("superadmin", "create_support_ticket"),
        ("superadmin", "manage_notifications"),
        ("superadmin", "view_merit"),
        ("superadmin", "manage_merit"),
        // admin
        ("admin", "create_user"),
        ("admin", "update_user"),
        ("admin", "delete_user"),
        ("admin", "approve_guard_registration"),
        ("admin", "manage_firearms"),
        ("admin", "allocate_firearm"),
        ("admin", "manage_armored_cars"),
        ("admin", "assign_vehicle_driver"),
        ("admin", "manage_missions"),
        ("admin", "manage_schedules"),
        ("admin", "view_analytics"),
        ("admin", "manage_trip_status"),
        ("admin", "view_support_tickets"),
        ("admin", "create_support_ticket"),
        ("admin", "manage_notifications"),
        ("admin", "view_merit"),
        ("admin", "manage_merit"),
        // supervisor
        ("supervisor", "update_user"),
        ("supervisor", "approve_guard_registration"),
        ("supervisor", "manage_firearms"),
        ("supervisor", "allocate_firearm"),
        ("supervisor", "manage_armored_cars"),
        ("supervisor", "assign_vehicle_driver"),
        ("supervisor", "manage_missions"),
        ("supervisor", "manage_schedules"),
        ("supervisor", "view_analytics"),
        ("supervisor", "manage_trip_status"),
        ("supervisor", "view_support_tickets"),
        ("supervisor", "create_support_ticket"),
        ("supervisor", "manage_notifications"),
        ("supervisor", "view_merit"),
        ("supervisor", "manage_merit"),
        // guard
        ("guard", "create_support_ticket"),
        ("guard", "manage_notifications"),
        ("guard", "view_merit"),
    ] {
        sqlx::query(
            r#"INSERT INTO role_permissions (id, role_id, permission_id)
               SELECT $1, r.id, p.id
               FROM roles r, permissions p
               WHERE r.role_key = $2 AND p.permission_key = $3
               ON CONFLICT (role_id, permission_id) DO NOTHING"#,
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(role_key)
        .bind(permission_key)
        .execute(pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to seed role permissions: {}", e)))?;
    }

    // Create verifications table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS verifications (
            id VARCHAR(36) PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL,
            code VARCHAR(6) NOT NULL,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create verifications table: {}", e)))?;

    // Create firearms table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS firearms (
            id VARCHAR(36) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            serial_number VARCHAR(255) NOT NULL UNIQUE,
            model VARCHAR(255) NOT NULL,
            caliber VARCHAR(50) NOT NULL,
            status VARCHAR(50) NOT NULL DEFAULT 'available',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create firearms table: {}", e)))?;

    // Create firearm_allocations table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS firearm_allocations (
            id VARCHAR(36) PRIMARY KEY,
            guard_id VARCHAR(36) NOT NULL,
            firearm_id VARCHAR(36) NOT NULL,
            allocation_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            return_date TIMESTAMP WITH TIME ZONE,
            status VARCHAR(50) NOT NULL DEFAULT 'active',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (guard_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (firearm_id) REFERENCES firearms(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create firearm_allocations table: {}", e))
    })?;

    // Create shifts table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS shifts (
            id VARCHAR(36) PRIMARY KEY,
            guard_id VARCHAR(36) NOT NULL,
            start_time TIMESTAMP WITH TIME ZONE NOT NULL,
            end_time TIMESTAMP WITH TIME ZONE NOT NULL,
            client_site VARCHAR(255) NOT NULL,
            status VARCHAR(50) NOT NULL DEFAULT 'scheduled',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (guard_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create shifts table: {}", e)))?;

    // Create attendance table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS attendance (
            id VARCHAR(36) PRIMARY KEY,
            guard_id VARCHAR(36) NOT NULL,
            shift_id VARCHAR(36) NOT NULL,
            check_in_time TIMESTAMP WITH TIME ZONE NOT NULL,
            check_out_time TIMESTAMP WITH TIME ZONE,
            status VARCHAR(50) NOT NULL DEFAULT 'checked_in',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (guard_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (shift_id) REFERENCES shifts(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create attendance table: {}", e)))?;

    // Create armored_cars table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS armored_cars (
            id VARCHAR(36) PRIMARY KEY,
            license_plate VARCHAR(50) NOT NULL UNIQUE,
            vin VARCHAR(100) NOT NULL UNIQUE,
            model VARCHAR(255) NOT NULL,
            manufacturer VARCHAR(255) NOT NULL,
            capacity_kg INTEGER NOT NULL,
            passenger_capacity INTEGER DEFAULT 4,
            status VARCHAR(50) NOT NULL DEFAULT 'available',
            registration_expiry TIMESTAMP WITH TIME ZONE,
            insurance_expiry TIMESTAMP WITH TIME ZONE,
            last_maintenance_date TIMESTAMP WITH TIME ZONE,
            mileage INTEGER DEFAULT 0,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create armored_cars table: {}", e)))?;

    // Create car_allocations table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS car_allocations (
            id VARCHAR(36) PRIMARY KEY,
            car_id VARCHAR(36) NOT NULL,
            client_id VARCHAR(255) NOT NULL,
            allocation_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            return_date TIMESTAMP WITH TIME ZONE,
            expected_return_date TIMESTAMP WITH TIME ZONE,
            status VARCHAR(50) NOT NULL DEFAULT 'active',
            notes VARCHAR(1000),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (car_id) REFERENCES armored_cars(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create car_allocations table: {}", e))
    })?;

    // Create car_maintenance table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS car_maintenance (
            id VARCHAR(36) PRIMARY KEY,
            car_id VARCHAR(36) NOT NULL,
            maintenance_type VARCHAR(100) NOT NULL,
            description VARCHAR(1000) NOT NULL,
            cost DECIMAL(10, 2),
            scheduled_date TIMESTAMP WITH TIME ZONE,
            completion_date TIMESTAMP WITH TIME ZONE,
            status VARCHAR(50) NOT NULL DEFAULT 'scheduled',
            notes VARCHAR(1000),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (car_id) REFERENCES armored_cars(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create car_maintenance table: {}", e))
    })?;

    // Create driver_assignments table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS driver_assignments (
            id VARCHAR(36) PRIMARY KEY,
            car_id VARCHAR(36) NOT NULL,
            guard_id VARCHAR(36) NOT NULL,
            assignment_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            end_date TIMESTAMP WITH TIME ZONE,
            status VARCHAR(50) NOT NULL DEFAULT 'active',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (car_id) REFERENCES armored_cars(id) ON DELETE CASCADE,
            FOREIGN KEY (guard_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create driver_assignments table: {}", e))
    })?;

    // Create trips table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS trips (
            id VARCHAR(36) PRIMARY KEY,
            car_id VARCHAR(36) NOT NULL,
            driver_id VARCHAR(36) NOT NULL,
            allocation_id VARCHAR(36),
            start_location VARCHAR(500),
            end_location VARCHAR(500),
            destination VARCHAR(500),
            start_time TIMESTAMP WITH TIME ZONE NOT NULL,
            end_time TIMESTAMP WITH TIME ZONE,
            distance_km DECIMAL(10, 2),
            status VARCHAR(50) NOT NULL DEFAULT 'in_transit',
            mission_details VARCHAR(1000),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (car_id) REFERENCES armored_cars(id) ON DELETE CASCADE,
            FOREIGN KEY (driver_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (allocation_id) REFERENCES car_allocations(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create trips table: {}", e)))?;

    // Create guard_firearm_permits table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS guard_firearm_permits (
            id VARCHAR(36) PRIMARY KEY,
            guard_id VARCHAR(36) NOT NULL,
            firearm_id VARCHAR(36),
            permit_type VARCHAR(100) NOT NULL,
            issued_date TIMESTAMP WITH TIME ZONE NOT NULL,
            expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,
            status VARCHAR(50) NOT NULL DEFAULT 'active',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (guard_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (firearm_id) REFERENCES firearms(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to create guard_firearm_permits table: {}",
            e
        ))
    })?;

    // Create support_tickets table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS support_tickets (
            id VARCHAR(36) PRIMARY KEY,
            guard_id VARCHAR(36) NOT NULL,
            subject VARCHAR(255) NOT NULL,
            message TEXT NOT NULL,
            status VARCHAR(50) NOT NULL DEFAULT 'open',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (guard_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create support_tickets table: {}", e))
    })?;

    // ── Schema migrations for existing databases ──────────────────────────────
    // Add columns that may be missing from DBs created before these schema updates.
    for migration in &[
        "ALTER TABLE trips ADD COLUMN IF NOT EXISTS destination VARCHAR(500)",
        "ALTER TABLE trips ALTER COLUMN start_location DROP NOT NULL",
        "ALTER TABLE armored_cars ADD COLUMN IF NOT EXISTS passenger_capacity INTEGER DEFAULT 4",
    ] {
        sqlx::query(migration).execute(pool).await.map_err(|e| {
            AppError::DatabaseError(format!("Migration failed '{}': {}", migration, e))
        })?;
    }

    // Create notifications table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS notifications (
            id VARCHAR(36) PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL,
            title VARCHAR(255) NOT NULL,
            message TEXT NOT NULL,
            type VARCHAR(50) NOT NULL DEFAULT 'info',
            related_shift_id VARCHAR(36),
            read BOOLEAN NOT NULL DEFAULT false,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create notifications table: {}", e)))?;

    // Create guard_availability table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS guard_availability (
            id VARCHAR(36) PRIMARY KEY,
            guard_id VARCHAR(36) NOT NULL UNIQUE,
            available BOOLEAN NOT NULL DEFAULT true,
            available_from TIMESTAMP WITH TIME ZONE,
            available_to TIMESTAMP WITH TIME ZONE,
            notes TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (guard_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create guard_availability table: {}", e))
    })?;

    // Create guard_shift_swaps table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS guard_shift_swaps (
            id VARCHAR(36) PRIMARY KEY,
            requester_id VARCHAR(36) NOT NULL,
            target_id VARCHAR(36) NOT NULL,
            shift_id VARCHAR(36) NOT NULL,
            reason TEXT,
            status VARCHAR(20) NOT NULL DEFAULT 'pending',
            responded_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (target_id) REFERENCES users(id) ON DELETE CASCADE,
            CONSTRAINT guard_shift_swaps_status_check CHECK (status IN ('pending', 'accepted', 'declined'))
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create guard_shift_swaps table: {}", e))
    })?;

    for swap_index in &[
        "CREATE INDEX IF NOT EXISTS idx_shift_swaps_requester ON guard_shift_swaps(requester_id)",
        "CREATE INDEX IF NOT EXISTS idx_shift_swaps_target ON guard_shift_swaps(target_id)",
        "CREATE INDEX IF NOT EXISTS idx_shift_swaps_status ON guard_shift_swaps(status)",
    ] {
        sqlx::query(swap_index)
            .execute(pool)
            .await
            .map_err(|e| {
                AppError::DatabaseError(format!("Failed to create shift swap index: {}", e))
            })?;
    }

    // Create guard_merit_scores table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS guard_merit_scores (
            id VARCHAR(36) PRIMARY KEY,
            guard_id VARCHAR(36) NOT NULL UNIQUE,
            attendance_score DOUBLE PRECISION NOT NULL DEFAULT 0,
            punctuality_score DOUBLE PRECISION NOT NULL DEFAULT 0,
            client_rating DOUBLE PRECISION NOT NULL DEFAULT 0,
            overall_score DOUBLE PRECISION NOT NULL DEFAULT 0,
            rank VARCHAR(50),
            total_shifts_completed INTEGER DEFAULT 0,
            on_time_count INTEGER DEFAULT 0,
            late_count INTEGER DEFAULT 0,
            no_show_count INTEGER DEFAULT 0,
            average_client_rating DOUBLE PRECISION,
            evaluation_count INTEGER DEFAULT 0,
            last_calculated_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (guard_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create guard_merit_scores table: {}", e))
    })?;

    // Create client_evaluations table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS client_evaluations (
            id VARCHAR(36) PRIMARY KEY,
            guard_id VARCHAR(36) NOT NULL,
            shift_id VARCHAR(36),
            mission_id VARCHAR(36),
            evaluator_name VARCHAR(255) NOT NULL,
            evaluator_role VARCHAR(100),
            rating DOUBLE PRECISION NOT NULL,
            comment TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (guard_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create client_evaluations table: {}", e))
    })?;

    // Create punctuality_records table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS punctuality_records (
            id VARCHAR(36) PRIMARY KEY,
            guard_id VARCHAR(36) NOT NULL,
            shift_id VARCHAR(36) NOT NULL,
            scheduled_start_time TIMESTAMP WITH TIME ZONE NOT NULL,
            actual_check_in_time TIMESTAMP WITH TIME ZONE,
            minutes_late INTEGER,
            is_on_time BOOLEAN NOT NULL DEFAULT true,
            status VARCHAR(50) NOT NULL DEFAULT 'present',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (guard_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create punctuality_records table: {}", e))
    })?;

    // Create training_records table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS training_records (
            id VARCHAR(36) PRIMARY KEY,
            guard_id VARCHAR(36) NOT NULL,
            training_type VARCHAR(100) NOT NULL,
            completed_date TIMESTAMP WITH TIME ZONE NOT NULL,
            expiry_date TIMESTAMP WITH TIME ZONE,
            certificate_number VARCHAR(100),
            status VARCHAR(50) NOT NULL DEFAULT 'valid',
            notes TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (guard_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create training_records table: {}", e))
    })?;

    // Create firearm_maintenance table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS firearm_maintenance (
            id VARCHAR(36) PRIMARY KEY,
            firearm_id VARCHAR(36) NOT NULL,
            maintenance_type VARCHAR(100) NOT NULL,
            description TEXT NOT NULL,
            scheduled_date TIMESTAMP WITH TIME ZONE NOT NULL,
            completion_date TIMESTAMP WITH TIME ZONE,
            performed_by VARCHAR(255),
            cost VARCHAR(50),
            status VARCHAR(50) NOT NULL DEFAULT 'pending',
            notes TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (firearm_id) REFERENCES firearms(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create firearm_maintenance table: {}", e))
    })?;

    // Create AI-assisted SOC intelligence tables (deterministic/explainable outputs).
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS guard_absence_predictions (
            id VARCHAR(36) PRIMARY KEY,
            guard_id VARCHAR(36) NOT NULL,
            prediction_window_hours INTEGER NOT NULL DEFAULT 24,
            risk_score DOUBLE PRECISION NOT NULL CHECK (risk_score >= 0 AND risk_score <= 1),
            risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
            confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0.75 CHECK (confidence_score >= 0 AND confidence_score <= 1),
            explanation JSONB NOT NULL DEFAULT '{}'::jsonb,
            contributing_factors JSONB NOT NULL DEFAULT '[]'::jsonb,
            source_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
            generated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            valid_until TIMESTAMP WITH TIME ZONE,
            feature_version VARCHAR(64) NOT NULL DEFAULT 'absence-heuristic-v1',
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (guard_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create guard_absence_predictions table: {}", e)))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_guard_absence_predictions_guard_generated ON guard_absence_predictions (guard_id, generated_at DESC)"
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create guard_absence_predictions index: {}", e)))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_guard_absence_predictions_level_valid ON guard_absence_predictions (risk_level, valid_until DESC)"
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create guard_absence_predictions level index: {}", e)))?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS smart_guard_replacements (
            id VARCHAR(36) PRIMARY KEY,
            shift_id VARCHAR(36) NOT NULL,
            absent_guard_id VARCHAR(36),
            recommended_guard_id VARCHAR(36),
            recommendation_rank INTEGER NOT NULL DEFAULT 1,
            compatibility_score DOUBLE PRECISION NOT NULL CHECK (compatibility_score >= 0 AND compatibility_score <= 1),
            confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0.75 CHECK (confidence_score >= 0 AND confidence_score <= 1),
            rationale TEXT NOT NULL,
            scoring_breakdown JSONB NOT NULL DEFAULT '{}'::jsonb,
            candidate_pool JSONB NOT NULL DEFAULT '[]'::jsonb,
            recommendation_status VARCHAR(20) NOT NULL DEFAULT 'proposed'
                CHECK (recommendation_status IN ('proposed', 'accepted', 'rejected', 'expired')),
            generated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP WITH TIME ZONE,
            feature_version VARCHAR(64) NOT NULL DEFAULT 'replacement-heuristic-v1',
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shift_id) REFERENCES shifts(id) ON DELETE CASCADE,
            FOREIGN KEY (absent_guard_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (recommended_guard_id) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create smart_guard_replacements table: {}", e)))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_smart_guard_replacements_shift_rank ON smart_guard_replacements (shift_id, recommendation_rank, generated_at DESC)"
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create smart_guard_replacements index: {}", e)))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_smart_guard_replacements_status ON smart_guard_replacements (recommendation_status, generated_at DESC)"
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create smart_guard_replacements status index: {}", e)))?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS incident_severity_classifications (
            id VARCHAR(36) PRIMARY KEY,
            incident_id VARCHAR(36) NOT NULL,
            predicted_severity VARCHAR(20) NOT NULL CHECK (predicted_severity IN ('low', 'medium', 'high', 'critical')),
            confidence_score DOUBLE PRECISION NOT NULL CHECK (confidence_score >= 0 AND confidence_score <= 1),
            requires_human_review BOOLEAN NOT NULL DEFAULT false,
            rationale TEXT NOT NULL,
            feature_scores JSONB NOT NULL DEFAULT '{}'::jsonb,
            supporting_signals JSONB NOT NULL DEFAULT '{}'::jsonb,
            classified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            classifier_version VARCHAR(64) NOT NULL DEFAULT 'severity-heuristic-v1',
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create incident_severity_classifications table: {}", e)))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_incident_severity_classifications_incident ON incident_severity_classifications (incident_id, classified_at DESC)"
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create incident_severity_classifications index: {}", e)))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_incident_severity_classifications_severity ON incident_severity_classifications (predicted_severity, classified_at DESC)"
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create incident_severity_classifications severity index: {}", e)))?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS predictive_vehicle_maintenance (
            id VARCHAR(36) PRIMARY KEY,
            car_id VARCHAR(36) NOT NULL,
            risk_score DOUBLE PRECISION NOT NULL CHECK (risk_score >= 0 AND risk_score <= 1),
            risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
            days_to_service INTEGER,
            predicted_failure_window_days INTEGER,
            recommended_action TEXT NOT NULL,
            rationale TEXT NOT NULL,
            signal_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
            maintenance_type_suggestion VARCHAR(100),
            generated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            valid_until TIMESTAMP WITH TIME ZONE,
            feature_version VARCHAR(64) NOT NULL DEFAULT 'vehicle-maintenance-heuristic-v1',
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (car_id) REFERENCES armored_cars(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create predictive_vehicle_maintenance table: {}", e)))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_predictive_vehicle_maintenance_car_generated ON predictive_vehicle_maintenance (car_id, generated_at DESC)"
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create predictive_vehicle_maintenance index: {}", e)))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_predictive_vehicle_maintenance_level ON predictive_vehicle_maintenance (risk_level, valid_until DESC)"
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create predictive_vehicle_maintenance level index: {}", e)))?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ai_incident_summaries (
            id VARCHAR(36) PRIMARY KEY,
            incident_id VARCHAR(36) NOT NULL,
            summary_kind VARCHAR(32) NOT NULL DEFAULT 'operational'
                CHECK (summary_kind IN ('operational', 'executive', 'handover')),
            summary_text TEXT NOT NULL,
            concise_headline VARCHAR(255),
            key_points JSONB NOT NULL DEFAULT '[]'::jsonb,
            action_items JSONB NOT NULL DEFAULT '[]'::jsonb,
            entities JSONB NOT NULL DEFAULT '{}'::jsonb,
            confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0.75 CHECK (confidence_score >= 0 AND confidence_score <= 1),
            explainability JSONB NOT NULL DEFAULT '{}'::jsonb,
            source_event_count INTEGER NOT NULL DEFAULT 0,
            generated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            summarizer_version VARCHAR(64) NOT NULL DEFAULT 'incident-summary-v1',
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create ai_incident_summaries table: {}", e)))?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_ai_incident_summaries_incident ON ai_incident_summaries (incident_id, generated_at DESC)"
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create ai_incident_summaries index: {}", e)))?;

    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_incident_summaries_incident_kind_generated ON ai_incident_summaries (incident_id, summary_kind, generated_at)"
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create ai_incident_summaries unique index: {}", e)))?;

    // Create password_reset_tokens table for forgot password feature
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id VARCHAR(36) NOT NULL,
            token VARCHAR(128) NOT NULL UNIQUE,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            is_used BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to create password_reset_tokens table: {}",
            e
        ))
    })?;

    // Expand token column to support hashed reset codes in upgraded databases.
    sqlx::query("ALTER TABLE password_reset_tokens ALTER COLUMN token TYPE VARCHAR(128)")
        .execute(pool)
        .await
        .map_err(|e| {
            AppError::DatabaseError(format!(
                "Failed to widen password_reset_tokens.token column: {}",
                e
            ))
        })?;

    // Create distributed login-attempt lockout table.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS auth_login_attempts (
            scope_key VARCHAR(255) PRIMARY KEY,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            first_failed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_failed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            locked_until TIMESTAMP WITH TIME ZONE,
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create auth_login_attempts table: {}", e))
    })?;

    // Persist refresh token sessions for revocation and rotation tracking.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS refresh_token_sessions (
            jti VARCHAR(64) PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL,
            token_hash VARCHAR(128) NOT NULL,
            issued_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            revoked_at TIMESTAMP WITH TIME ZONE,
            replaced_by_jti VARCHAR(64),
            last_used_at TIMESTAMP WITH TIME ZONE,
            source_ip VARCHAR(64),
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!(
            "Failed to create refresh_token_sessions table: {}",
            e
        ))
    })?;

    // Create audit logs table for centralized write-traceability.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS audit_logs (
            id VARCHAR(36) PRIMARY KEY,
            actor_user_id VARCHAR(36),
            action_key VARCHAR(255) NOT NULL,
            entity_type VARCHAR(100) NOT NULL,
            entity_id VARCHAR(255),
            result VARCHAR(50) NOT NULL,
            reason TEXT,
            source_ip VARCHAR(64),
            user_agent TEXT,
            metadata JSONB,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create audit_logs table: {}", e)))?;

    sqlx::query("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS source_ip VARCHAR(64)")
        .execute(pool)
        .await
        .map_err(|e| {
            AppError::DatabaseError(format!("Failed to add audit source_ip column: {}", e))
        })?;

    sqlx::query("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS user_agent TEXT")
        .execute(pool)
        .await
        .map_err(|e| {
            AppError::DatabaseError(format!("Failed to add audit user_agent column: {}", e))
        })?;

    for index in &[
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_created ON audit_logs(actor_user_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs(entity_type, entity_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_source_ip_created ON audit_logs(source_ip, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_result_created ON audit_logs(result, created_at DESC)",
    ] {
        sqlx::query(index)
            .execute(pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to create audit index: {}", e)))?;
    }

    // Create indexes for password_reset_tokens table
    for index in &[
        "CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token)",
        "CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at)",
        "CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_locked_until ON auth_login_attempts(locked_until)",
        "CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_last_failed ON auth_login_attempts(last_failed_at)",
        "CREATE INDEX IF NOT EXISTS idx_refresh_token_sessions_user_active ON refresh_token_sessions(user_id, revoked_at, expires_at)",
        "CREATE INDEX IF NOT EXISTS idx_refresh_token_sessions_expires_at ON refresh_token_sessions(expires_at)",
    ] {
        sqlx::query(index)
            .execute(pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to create index: {}", e)))?;
    }

    // Create push_subscriptions table for web push notifications
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS push_subscriptions (
            id VARCHAR(36) PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            endpoint TEXT NOT NULL,
            p256dh TEXT NOT NULL,
            auth TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT push_subscriptions_user_endpoint_unique UNIQUE (user_id, endpoint)
        )",
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create push_subscriptions table: {}", e))
    })?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user_id ON push_subscriptions(user_id)",
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::DatabaseError(format!("Failed to create push_subscriptions index: {}", e))
    })?;

    Ok(())
}
