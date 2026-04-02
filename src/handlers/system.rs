use axum::Json;
use serde_json::json;

fn env_or_default(key: &str, fallback: &str) -> String {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

pub async fn system_version() -> Json<serde_json::Value> {
    let latest_version = env_or_default("APP_VERSION", "v1.0.0");
    let changelog = env_or_default(
        "APP_CHANGELOG",
        "Platform stability and security hardening improvements.",
    );

    let web_download = env_or_default(
        "WEB_DOWNLOAD_URL",
        "https://github.com/dwaytu/Capstone-Main/releases/latest",
    );
    let desktop_download = env_or_default(
        "DESKTOP_DOWNLOAD_URL",
        "https://github.com/dwaytu/Capstone-Main/releases/latest",
    );
    let mobile_download = env_or_default(
        "MOBILE_DOWNLOAD_URL",
        "https://github.com/dwaytu/Capstone-Main/releases/latest",
    );

    Json(json!({
        "latestVersion": latest_version,
        "changelog": changelog,
        "downloadLinks": {
            "web": web_download,
            "desktop": desktop_download,
            "mobile": mobile_download
        },
        "publishedAt": chrono::Utc::now().to_rfc3339()
    }))
}
