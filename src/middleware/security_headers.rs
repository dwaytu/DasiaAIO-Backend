use axum::{
    body::Body,
    http::{header, HeaderName, HeaderValue, Request},
    middleware::Next,
    response::Response,
};

fn is_production_env() -> bool {
    std::env::var("APP_ENV")
        .or_else(|_| std::env::var("NODE_ENV"))
        .map(|value| matches!(value.trim().to_lowercase().as_str(), "production" | "prod"))
        .unwrap_or(false)
}

fn content_security_policy() -> HeaderValue {
    let configured = std::env::var("SECURITY_CSP").ok();
    let value = configured
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'");

    HeaderValue::from_str(value).unwrap_or_else(|_| {
        HeaderValue::from_static(
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'",
        )
    })
}

pub async fn apply_security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CONTENT_SECURITY_POLICY, content_security_policy());

    if is_production_env() {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        );
    }

    response
}
