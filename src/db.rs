use sqlx::postgres::{PgPool, PgPoolOptions};
use crate::error::{AppError, AppResult};

pub async fn init_db_pool(database_url: &str) -> AppResult<PgPool> {
    const MAX_RETRIES: u32 = 10;
    const RETRY_DELAY_SECS: u64 = 5;

    for attempt in 1..=MAX_RETRIES {
        match PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(std::time::Duration::from_secs(30))
            .connect(database_url)
            .await
        {
            Ok(pool) => {
                tracing::info!("✓ Database connected on attempt {}/{}", attempt, MAX_RETRIES);
                return Ok(pool);
            }
            Err(e) if attempt < MAX_RETRIES => {
                tracing::warn!(
                    "DB connection attempt {}/{} failed: {}. Retrying in {}s...",
                    attempt, MAX_RETRIES, e, RETRY_DELAY_SECS
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
            role VARCHAR(50) NOT NULL DEFAULT 'user',
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

    // Backfill profile_photo column for databases created before this migration
    sqlx::query(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_photo TEXT"
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to add profile_photo column: {}", e)))?;

    // Add license_issued_date column
    sqlx::query(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS license_issued_date TIMESTAMP WITH TIME ZONE"
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to add license_issued_date column: {}", e)))?;

    // Add address column
    sqlx::query(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS address TEXT"
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to add address column: {}", e)))?;

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
    .map_err(|e| AppError::DatabaseError(format!("Failed to create firearm_allocations table: {}", e)))?;

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
    .map_err(|e| AppError::DatabaseError(format!("Failed to create car_allocations table: {}", e)))?;

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
    .map_err(|e| AppError::DatabaseError(format!("Failed to create car_maintenance table: {}", e)))?;

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
    .map_err(|e| AppError::DatabaseError(format!("Failed to create driver_assignments table: {}", e)))?;

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
    .map_err(|e| AppError::DatabaseError(format!("Failed to create guard_firearm_permits table: {}", e)))?;

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
    .map_err(|e| AppError::DatabaseError(format!("Failed to create support_tickets table: {}", e)))?;

    // ── Schema migrations for existing databases ──────────────────────────────
    // Add columns that may be missing from DBs created before these schema updates.
    for migration in &[
        "ALTER TABLE trips ADD COLUMN IF NOT EXISTS destination VARCHAR(500)",
        "ALTER TABLE trips ALTER COLUMN start_location DROP NOT NULL",
        "ALTER TABLE armored_cars ADD COLUMN IF NOT EXISTS passenger_capacity INTEGER DEFAULT 4",
    ] {
        sqlx::query(migration)
            .execute(pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Migration failed '{}': {}", migration, e)))?;
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
    .map_err(|e| AppError::DatabaseError(format!("Failed to create guard_availability table: {}", e)))?;

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
    .map_err(|e| AppError::DatabaseError(format!("Failed to create guard_merit_scores table: {}", e)))?;

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
    .map_err(|e| AppError::DatabaseError(format!("Failed to create client_evaluations table: {}", e)))?;

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
    .map_err(|e| AppError::DatabaseError(format!("Failed to create punctuality_records table: {}", e)))?;

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
    .map_err(|e| AppError::DatabaseError(format!("Failed to create training_records table: {}", e)))?;

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
    .map_err(|e| AppError::DatabaseError(format!("Failed to create firearm_maintenance table: {}", e)))?;

    // Create password_reset_tokens table for forgot password feature
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id VARCHAR(36) NOT NULL,
            token VARCHAR(6) NOT NULL UNIQUE,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            is_used BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(format!("Failed to create password_reset_tokens table: {}", e)))?;

    // Create indexes for password_reset_tokens table
    for index in &[
        "CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token)",
        "CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at)",
    ] {
        sqlx::query(index)
            .execute(pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to create index: {}", e)))?;
    }

    Ok(())
}
