use std::env;

pub struct Config {
    pub app_env: String,
    pub server_host: String,
    pub server_port: u16,
    pub database_url: String,
    pub gmail_user: String,
    pub gmail_password: String,
    pub admin_code: String,
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
            "CORS_ORIGINS or CORS_ORIGIN must be configured when APP_ENV=production."
                .to_string(),
        );
    }

    Ok(())
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

        let config = Config {
            app_env,
            server_host: env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            server_port: port_str
                .parse()
                .map_err(|_| format!("PORT '{}' must be a valid number", port_str))?,
            database_url: env::var("DATABASE_URL")
                .map_err(|_| "DATABASE_URL must be set. In Railway dashboard: backend service → Variables → add DATABASE_URL and paste the value from the Postgres service Variables tab.".to_string())?,
            gmail_user: env::var("GMAIL_USER").unwrap_or_else(|_| "no-reply@example.com".to_string()),
            gmail_password: env::var("GMAIL_PASSWORD").unwrap_or_else(|_| "dummy-password".to_string()),
            admin_code: env::var("ADMIN_CODE").unwrap_or_else(|_| "122601".to_string()),
        };

        if is_production_env(&config.app_env) {
            validate_production_env(&config)?;
        }

        Ok(config)
    }
}

