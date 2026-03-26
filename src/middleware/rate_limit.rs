use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request},
    middleware::Next,
    response::Response,
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

fn resolve_requester(headers: &HeaderMap) -> String {
    crate::utils::extract_requester(headers)
}

pub async fn auth_rate_limit(
    State(rate_limiter): State<Arc<RateLimiter>>,
    request: Request<Body>,
    next: Next,
) -> AppResult<Response> {
    let path = request.uri().path().to_string();
    let requester = resolve_requester(request.headers());
    let key = format!("auth:{}:{}", path, requester);

    if let Some(retry_after) = rate_limiter.check_request(&key).await {
        tracing::warn!(
            path = %path,
            requester = %requester,
            retry_after,
            "rate limit exceeded on sensitive auth endpoint"
        );
        return Err(AppError::RateLimited(format!(
            "Too many requests. Retry in {} second(s).",
            retry_after
        )));
    }

    Ok(next.run(request).await)
}

pub async fn api_rate_limit(
    State(rate_limiter): State<Arc<RateLimiter>>,
    request: Request<Body>,
    next: Next,
) -> AppResult<Response> {
    let path = request.uri().path().to_string();
    let requester = resolve_requester(request.headers());
    let key = format!("api:{}", requester);

    if let Some(retry_after) = rate_limiter.check_request(&key).await {
        tracing::warn!(
            path = %path,
            requester = %requester,
            retry_after,
            "global api rate limit exceeded"
        );
        return Err(AppError::RateLimited(format!(
            "Too many API requests. Retry in {} second(s).",
            retry_after
        )));
    }

    Ok(next.run(request).await)
}

pub async fn expensive_endpoint_rate_limit(
    State(rate_limiter): State<Arc<RateLimiter>>,
    request: Request<Body>,
    next: Next,
) -> AppResult<Response> {
    let path = request.uri().path().to_string();
    let requester = resolve_requester(request.headers());
    let key = format!("expensive:{}:{}", path, requester);

    if let Some(retry_after) = rate_limiter.check_request(&key).await {
        tracing::warn!(
            path = %path,
            requester = %requester,
            retry_after,
            "expensive endpoint rate limit exceeded"
        );
        return Err(AppError::RateLimited(format!(
            "Too many requests to this endpoint. Retry in {} second(s).",
            retry_after
        )));
    }

    Ok(next.run(request).await)
}
