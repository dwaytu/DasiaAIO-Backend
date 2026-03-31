use axum::{body::Body, extract::State, http::Request, middleware::Next, response::Response};
use sqlx::PgPool;
use std::sync::Arc;

use crate::utils;

pub async fn audit_authz_failures(
    State(db): State<Arc<PgPool>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();

    let actor_user_id = req
        .headers()
        .get("authorization")
        .and_then(|_| utils::extract_bearer_token(req.headers()).ok())
        .and_then(|token| utils::verify_token(&token).ok())
        .map(|claims| claims.sub);

    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());

    let source_ip = utils::extract_requester(req.headers());
    let response = next.run(req).await;

    let status_code = response.status().as_u16();
    let is_write = matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE");
    let is_authz_failure = status_code == 401 || status_code == 403;
    let is_api_request = path.starts_with("/api/");

    if !is_write && is_api_request && is_authz_failure {
        let action_key = format!("AUTHZ_DENIED {} {}", method, path);

        if let Err(err) = sqlx::query(
            r#"INSERT INTO audit_logs (
                    id, actor_user_id, action_key, entity_type, entity_id, result, reason, source_ip, user_agent, metadata
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
        )
        .bind(utils::generate_id())
        .bind(actor_user_id)
        .bind(action_key)
        .bind("authorization")
        .bind(Option::<String>::None)
        .bind("failed")
        .bind(format!("HTTP {}", status_code))
        .bind(source_ip)
        .bind(user_agent)
        .bind(serde_json::json!({
            "status": status_code,
            "path": path,
            "method": method,
        }))
        .execute(db.as_ref())
        .await
        {
            tracing::error!(
                error = %err,
                path = %path,
                status = status_code,
                "failed to persist authz failure audit log entry"
            );
        }
    }

    response
}

pub async fn audit_write_requests(
    State(db): State<Arc<PgPool>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();

    let actor_user_id = req
        .headers()
        .get("authorization")
        .and_then(|_| utils::extract_bearer_token(req.headers()).ok())
        .and_then(|token| utils::verify_token(&token).ok())
        .map(|claims| claims.sub);

    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());

    let is_write = matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE");
    let source_ip = utils::extract_requester(req.headers());

    let response = next.run(req).await;

    if is_write {
        let status_code = response.status().as_u16();
        let result = if status_code < 400 {
            "success"
        } else {
            "failed"
        };
        let action_key = format!("{} {}", method, path);

        let entity_type = path
            .trim_start_matches('/')
            .split('/')
            .nth(1)
            .unwrap_or("unknown")
            .to_string();

        let entity_id = path
            .trim_start_matches('/')
            .split('/')
            .nth(2)
            .map(|s| s.to_string());

        if let Err(err) = sqlx::query(
            r#"INSERT INTO audit_logs (
                    id, actor_user_id, action_key, entity_type, entity_id, result, reason, source_ip, user_agent, metadata
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
        )
        .bind(utils::generate_id())
        .bind(actor_user_id)
        .bind(action_key)
        .bind(entity_type)
        .bind(entity_id)
        .bind(result)
        .bind(format!("HTTP {}", status_code))
        .bind(source_ip)
        .bind(user_agent)
        .bind(serde_json::json!({
            "status": status_code,
            "path": path,
            "method": method,
        }))
        .execute(db.as_ref())
        .await
        {
            tracing::error!(
                error = %err,
                method = %method,
                path = %path,
                status = status_code,
                "failed to persist audit log entry"
            );
        }
    }

    response
}
