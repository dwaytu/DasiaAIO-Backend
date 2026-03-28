use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, HeaderValue, Method, Request},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone)]
pub struct RateLimiter {
    max_requests: usize,
    window: Duration,
    buckets: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
}

impl RateLimiter {
    fn from_limits(max_requests: usize, window_secs: u64) -> Self {
        Self {
            max_requests,
            window: Duration::from_secs(window_secs),
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn from_env() -> Self {
        let max_requests = std::env::var("AUTH_RATE_LIMIT_MAX")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(10);

        let window_secs = std::env::var("AUTH_RATE_LIMIT_WINDOW_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(60);

        Self::from_limits(max_requests, window_secs)
    }

    pub fn api_from_env() -> Self {
        let max_requests = std::env::var("API_RATE_LIMIT_MAX")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(240);

        let window_secs = std::env::var("API_RATE_LIMIT_WINDOW_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(60);

        Self::from_limits(max_requests, window_secs)
    }

    pub fn expensive_from_env() -> Self {
        let max_requests = std::env::var("EXPENSIVE_RATE_LIMIT_MAX")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(30);

        let window_secs = std::env::var("EXPENSIVE_RATE_LIMIT_WINDOW_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(60);

        Self::from_limits(max_requests, window_secs)
    }

    async fn check_request(&self, key: &str) -> Option<u64> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().await;

        let bucket = buckets.entry(key.to_string()).or_insert_with(VecDeque::new);

        while let Some(front) = bucket.front() {
            if now.duration_since(*front) > self.window {
                bucket.pop_front();
            } else {
                break;
            }
        }

        if bucket.len() >= self.max_requests {
            if let Some(oldest) = bucket.front() {
                let elapsed = now.duration_since(*oldest);
                let retry_after = self.window.saturating_sub(elapsed).as_secs().max(1);
                return Some(retry_after);
            }
            return Some(1);
        }

        bucket.push_back(now);
        None
    }
}

fn resolve_user_id(headers: &HeaderMap) -> Option<String> {
    if let Ok(token) = crate::utils::extract_bearer_token(headers) {
        if let Ok(claims) = crate::utils::verify_token(&token) {
            return Some(claims.sub);
        }
    }

    None
}

fn cors_safe_error_response(origin: Option<HeaderValue>, error: AppError) -> Response {
    let mut response = error.into_response();

    if let Some(origin) = origin {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);

        response.headers_mut().append(
            header::VARY,
            HeaderValue::from_static(
                "origin, access-control-request-method, access-control-request-headers",
            ),
        );
    }

    response
}

async fn enforce_bucket_limit(
    origin: Option<HeaderValue>,
    rate_limiter: &RateLimiter,
    key: &str,
    path: &str,
    principal: &str,
    scope: &str,
    message: &str,
) -> Option<Response> {
    if let Some(retry_after) = rate_limiter.check_request(key).await {
        tracing::warn!(
            path = %path,
            principal = %principal,
            scope = %scope,
            retry_after,
            "rate limit exceeded"
        );

        return Some(cors_safe_error_response(
            origin,
            AppError::RateLimited(format!(
                "{} Retry in {} second(s).",
                message, retry_after
            )),
        ));
    }

    None
}

pub async fn auth_rate_limit(
    State(rate_limiter): State<Arc<RateLimiter>>,
    request: Request<Body>,
    next: Next,
) -> AppResult<Response> {
    if request.method() == Method::OPTIONS {
        return Ok(next.run(request).await);
    }

    let path = request.uri().path().to_string();
    let request_origin = request.headers().get(header::ORIGIN).cloned();
    let source_ip = crate::utils::extract_requester(request.headers());

    if source_ip != "unknown-client" {
        let key = format!("auth:ip:{}:{}", path, source_ip);
        if let Some(response) = enforce_bucket_limit(
            request_origin.clone(),
            rate_limiter.as_ref(),
            &key,
            &path,
            &source_ip,
            "ip",
            "Too many requests.",
        )
        .await
        {
            return Ok(response);
        }
    }

    if let Some(user_id) = resolve_user_id(request.headers()) {
        let key = format!("auth:user:{}:{}", path, user_id);
        if let Some(response) = enforce_bucket_limit(
            request_origin.clone(),
            rate_limiter.as_ref(),
            &key,
            &path,
            &user_id,
            "user",
            "Too many requests.",
        )
        .await
        {
            return Ok(response);
        }
    }

    if source_ip == "unknown-client" {
        let key = format!("auth:fallback:{}:{}", path, source_ip);
        if let Some(response) = enforce_bucket_limit(
            request_origin,
            rate_limiter.as_ref(),
            &key,
            &path,
            &source_ip,
            "fallback",
            "Too many requests.",
        )
        .await
        {
            return Ok(response);
        }
    }

    Ok(next.run(request).await)
}

pub async fn api_rate_limit(
    State(rate_limiter): State<Arc<RateLimiter>>,
    request: Request<Body>,
    next: Next,
) -> AppResult<Response> {
    if request.method() == Method::OPTIONS {
        return Ok(next.run(request).await);
    }

    if request.uri().path().starts_with("/api/health") {
        return Ok(next.run(request).await);
    }

    let path = request.uri().path().to_string();
    let request_origin = request.headers().get(header::ORIGIN).cloned();
    let source_ip = crate::utils::extract_requester(request.headers());

    if source_ip != "unknown-client" {
        let key = format!("api:ip:{}:{}", source_ip, path);
        if let Some(response) = enforce_bucket_limit(
            request_origin.clone(),
            rate_limiter.as_ref(),
            &key,
            &path,
            &source_ip,
            "ip",
            "Too many API requests.",
        )
        .await
        {
            return Ok(response);
        }
    }

    if let Some(user_id) = resolve_user_id(request.headers()) {
        let key = format!("api:user:{}:{}", user_id, path);
        if let Some(response) = enforce_bucket_limit(
            request_origin.clone(),
            rate_limiter.as_ref(),
            &key,
            &path,
            &user_id,
            "user",
            "Too many API requests.",
        )
        .await
        {
            return Ok(response);
        }
    }

    if source_ip == "unknown-client" {
        let key = format!("api:fallback:{}:{}", source_ip, path);
        if let Some(response) = enforce_bucket_limit(
            request_origin,
            rate_limiter.as_ref(),
            &key,
            &path,
            &source_ip,
            "fallback",
            "Too many API requests.",
        )
        .await
        {
            return Ok(response);
        }
    }

    Ok(next.run(request).await)
}

pub async fn expensive_endpoint_rate_limit(
    State(rate_limiter): State<Arc<RateLimiter>>,
    request: Request<Body>,
    next: Next,
) -> AppResult<Response> {
    if request.method() == Method::OPTIONS {
        return Ok(next.run(request).await);
    }

    let path = request.uri().path().to_string();
    let request_origin = request.headers().get(header::ORIGIN).cloned();
    let source_ip = crate::utils::extract_requester(request.headers());

    if source_ip != "unknown-client" {
        let key = format!("expensive:ip:{}:{}", path, source_ip);
        if let Some(response) = enforce_bucket_limit(
            request_origin.clone(),
            rate_limiter.as_ref(),
            &key,
            &path,
            &source_ip,
            "ip",
            "Too many requests to this endpoint.",
        )
        .await
        {
            return Ok(response);
        }
    }

    if let Some(user_id) = resolve_user_id(request.headers()) {
        let key = format!("expensive:user:{}:{}", path, user_id);
        if let Some(response) = enforce_bucket_limit(
            request_origin.clone(),
            rate_limiter.as_ref(),
            &key,
            &path,
            &user_id,
            "user",
            "Too many requests to this endpoint.",
        )
        .await
        {
            return Ok(response);
        }
    }

    if source_ip == "unknown-client" {
        let key = format!("expensive:fallback:{}:{}", path, source_ip);
        if let Some(response) = enforce_bucket_limit(
            request_origin,
            rate_limiter.as_ref(),
            &key,
            &path,
            &source_ip,
            "fallback",
            "Too many requests to this endpoint.",
        )
        .await
        {
            return Ok(response);
        }
    }

    Ok(next.run(request).await)
}
