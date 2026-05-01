use std::env;

pub struct Config {
    pub app_env: String,
    pub server_host: String,
    pub server_port: u16,
    pub database_url: String,
    pub admin_code: String,
    pub db_pool_max_connections: u32,
    pub db_pool_acquire_timeout_secs: u32,
}

fn is_production_env(value: &str) -> bool {
    matches!(value, "production" | "prod")
}

fn validate_production_env(config: &Config) -> Result<(), String> {
    let jwt_secret = env::var("JWT_SECRET").unwrap_or_default();
    let jwt_secret_trimmed = jwt_secret.trim();

    if jwt_secret_trimmed.is_empty()
        || jwt_secret_trimmed == "your_secret_key_here"
        || jwt_secret_trimmed == "your-secret-key-change-in-production"
        || jwt_secret_trimmed.len() < 32
    {
        return Err(
            "JWT_SECRET must be set to a strong value (32+ chars) when APP_ENV=production."
                .to_string(),
        );
    }

    if config.admin_code == "122601" {
        return Err("ADMIN_CODE must be changed from the default in production.".to_string());
    }

    let cors_origins = env::var("CORS_ORIGINS")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let cors_origin = env::var("CORS_ORIGIN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    if cors_origins.is_none() && cors_origin.is_none() {
        return Err(
            "CORS_ORIGINS or CORS_ORIGIN must be configured when APP_ENV=production.".to_string(),
        );
    }

    Ok(())
}

fn parse_u32_env(name: &str, default_value: u32, min: u32, max: u32) -> Result<u32, String> {
    match env::var(name) {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Ok(default_value);
            }

            let parsed = trimmed
                .parse::<u32>()
                .map_err(|_| format!("{} must be a valid unsigned integer.", name))?;
            if parsed < min || parsed > max {
                return Err(format!(
                    "{} must be between {} and {}.",
                    name, min, max
                ));
            }
            Ok(parsed)
        }
        Err(_) => Ok(default_value),
    }
}

fn require_non_empty_env(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("{} must be set.", name))?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{} must not be empty.", name));
    }
    Ok(trimmed.to_string())
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        // Railway injects the assigned port as `PORT`.
        // `SERVER_PORT` is our own alias (set in railway.json as `$PORT`).
        // Check in order: PORT → SERVER_PORT → default 5000.
        let port_str = env::var("PORT")
            .or_else(|_| env::var("SERVER_PORT"))
            .unwrap_or_else(|_| "5000".to_string());

        let app_env = env::var("APP_ENV")
            .or_else(|_| env::var("NODE_ENV"))
            .unwrap_or_else(|_| "development".to_string())
            .trim()
            .to_lowercase();

        let admin_code = require_non_empty_env("ADMIN_CODE")?;
        if admin_code == "122601" {
            return Err("ADMIN_CODE must not use the insecure default value.".to_string());
        }

        let db_pool_max_connections = parse_u32_env("DB_POOL_MAX_CONNECTIONS", 10, 1, 100)?;
        let db_pool_acquire_timeout_secs =
            parse_u32_env("DB_POOL_ACQUIRE_TIMEOUT_SECS", 30, 1, 300)?;

        let config = Config {
            app_env,
            server_host: env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            server_port: port_str
                .parse()
                .map_err(|_| format!("PORT '{}' must be a valid number", port_str))?,
            database_url: env::var("DATABASE_URL")
                .map_err(|_| "DATABASE_URL must be set. In Railway dashboard: backend service → Variables → add DATABASE_URL and paste the value from the Postgres service Variables tab.".to_string())?,
            admin_code,
            db_pool_max_connections,
            db_pool_acquire_timeout_secs,
        };

        if is_production_env(&config.app_env) {
            validate_production_env(&config)?;
        }

        Ok(config)
    }
}
