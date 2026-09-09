use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    error::AppResult,
    models::{CreateOperationalRequest, OperationalRequestDecision, ResubmitOperationalRequest},
    services::operational_requests::{self, RequestListFilters},
    utils,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationalRequestQuery {
    pub status: Option<String>,
    pub request_type: Option<String>,
    pub priority: Option<String>,
    pub requester: Option<String>,
    pub date_from: Option<String>,
    pub date_to: Option<String>,
    pub page: Option<i64>,
    #[serde(alias = "page_size")]
    pub page_size: Option<i64>,
}

fn claims(headers: &HeaderMap) -> AppResult<utils::TokenClaims> {
    let token = utils::extract_bearer_token(headers)?;
    utils::verify_token(&token)
}

pub async fn create_request(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Json(payload): Json<CreateOperationalRequest>,
) -> AppResult<(StatusCode, Json<Value>)> {
    let actor = claims(&headers)?;
    let request =
        operational_requests::create_request(db.as_ref(), &actor.sub, &actor.role, payload).await?;
    Ok((StatusCode::CREATED, Json(json!({ "request": request }))))
}

pub async fn list_requests(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Query(query): Query<OperationalRequestQuery>,
) -> AppResult<Json<Value>> {
    let actor = claims(&headers)?;
    let response = operational_requests::list_requests(
        db.as_ref(),
        &actor.sub,
        &actor.role,
        RequestListFilters {
            status: query.status,
            request_type: query.request_type,
            priority: query.priority,
            requester: query.requester,
            date_from: query.date_from,
            date_to: query.date_to,
            page: query.page,
            page_size: query.page_size,
        },
    )
    .await?;
    Ok(Json(response))
}

pub async fn get_request(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> AppResult<Json<Value>> {
    let actor = claims(&headers)?;
    let request =
        operational_requests::get_request(db.as_ref(), &actor.sub, &actor.role, &request_id)
            .await?;
    let events =
        operational_requests::get_events(db.as_ref(), &actor.sub, &actor.role, &request_id).await?;
    Ok(Json(json!({ "request": request, "events": events })))
}

pub async fn get_events(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> AppResult<Json<Value>> {
    let actor = claims(&headers)?;
    let events =
        operational_requests::get_events(db.as_ref(), &actor.sub, &actor.role, &request_id).await?;
    Ok(Json(json!({ "events": events })))
}

pub async fn get_my_resources(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let actor = claims(&headers)?;
    Ok(Json(
        operational_requests::get_my_resources(db.as_ref(), &actor.sub, &actor.role).await?,
    ))
}

macro_rules! decision_handler {
    ($name:ident, $service:ident) => {
        pub async fn $name(
            State(db): State<Arc<PgPool>>,
            headers: HeaderMap,
            Path(request_id): Path<String>,
            Json(payload): Json<OperationalRequestDecision>,
        ) -> AppResult<Json<Value>> {
            let actor = claims(&headers)?;
            let request = operational_requests::$service(
                db.as_ref(),
                &actor.sub,
                &actor.role,
                &request_id,
                payload,
            )
            .await?;
            Ok(Json(json!({ "request": request })))
        }
    };
}

decision_handler!(approve_request, approve_request);
decision_handler!(reject_request, reject_request);
decision_handler!(return_for_correction, return_for_correction);
decision_handler!(cancel_request, cancel_request);
decision_handler!(start_request, start_request);
decision_handler!(complete_request, complete_request);

pub async fn resubmit_request(
    State(db): State<Arc<PgPool>>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
    Json(payload): Json<ResubmitOperationalRequest>,
) -> AppResult<Json<Value>> {
    let actor = claims(&headers)?;
    let request = operational_requests::resubmit_request(
        db.as_ref(),
        &actor.sub,
        &actor.role,
        &request_id,
        payload,
    )
    .await?;
    Ok(Json(json!({ "request": request })))
}
