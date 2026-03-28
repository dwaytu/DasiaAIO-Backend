use axum::{body::Body, extract::State, http::Request, middleware::Next, response::Response};
use sqlx::PgPool;
use std::sync::Arc;

use crate::utils;

pub async fn touch_last_seen(
    State(db): State<Arc<PgPool>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let actor_user_id = req
        .headers()
        .get("authorization")
        .and_then(|_| utils::extract_bearer_token(req.headers()).ok())
        .and_then(|token| utils::verify_token(&token).ok())
        .map(|claims| claims.sub);

    if let Some(user_id) = actor_user_id {
        let _ = sqlx::query("UPDATE users SET last_seen_at = CURRENT_TIMESTAMP WHERE id = $1")
            .bind(user_id)
            .execute(db.as_ref())
            .await;
    }

    next.run(req).await
}
