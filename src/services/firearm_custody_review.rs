use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::PgPool;

use crate::{
    error::{AppError, AppResult},
    utils,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustodyReviewApproval {
    approved_at: DateTime<Utc>,
}

pub async fn approve(
    pool: &PgPool,
    firearm_id: &str,
    inventory_updated_at: DateTime<Utc>,
    actor_id: &str,
    source_reference: &str,
) -> AppResult<CustodyReviewApproval> {
    let source_reference = source_reference.trim();
    if source_reference.is_empty() || source_reference.encode_utf16().count() > 200 {
        return Err(AppError::BadRequest(
            "Enter a source document reference of 1 to 200 characters.".to_string(),
        ));
    }

    let mut tx = pool.begin().await.map_err(database_error)?;
    let (updated_at, marked_issued, serial_number) =
        sqlx::query_as::<_, (DateTime<Utc>, bool, String)>(
            r#"SELECT updated_at, LOWER(BTRIM(status)) IN ('allocated', 'deployed'), serial_number
               FROM firearms WHERE id = $1 FOR UPDATE"#,
        )
        .bind(firearm_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(database_error)?
        .ok_or_else(|| AppError::NotFound("Firearm not found".to_string()))?;

    let active_custody: bool = sqlx::query_scalar(
        r#"SELECT EXISTS (
            SELECT 1 FROM firearm_allocations
            WHERE firearm_id = $1 AND LOWER(BTRIM(status)) = 'active'
        )"#,
    )
    .bind(firearm_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(database_error)?;

    if updated_at != inventory_updated_at || !marked_issued || active_custody {
        return Err(AppError::Conflict(
            "The inventory record changed. Refresh the inventory before reviewing it.".to_string(),
        ));
    }

    let approved_at = sqlx::query_scalar(
        r#"INSERT INTO firearm_custody_review_approvals (firearm_id, inventory_updated_at)
           VALUES ($1, $2)
           ON CONFLICT (firearm_id, inventory_updated_at) DO NOTHING
           RETURNING approved_at"#,
    )
    .bind(firearm_id)
    .bind(updated_at)
    .fetch_optional(&mut *tx)
    .await
    .map_err(database_error)?
    .ok_or_else(|| {
        AppError::Conflict("This review was already approved. Refresh the inventory.".to_string())
    })?;

    sqlx::query(
        r#"INSERT INTO audit_logs (id, actor_user_id, action_key, entity_type, entity_id, result, metadata)
           VALUES ($1, $2, 'firearm.custody_review.approved', 'firearms', $3, 'success', $4)"#,
    )
    .bind(utils::generate_id())
    .bind(actor_id)
    .bind(firearm_id)
    .bind(json!({
        "sourceReference": source_reference,
        "serialNumber": serial_number,
        "inventoryUpdatedAt": updated_at,
    }))
    .execute(&mut *tx)
    .await
    .map_err(database_error)?;

    tx.commit().await.map_err(database_error)?;
    Ok(CustodyReviewApproval { approved_at })
}

fn database_error(error: sqlx::Error) -> AppError {
    AppError::DatabaseError(format!("Could not record custody review approval: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        Json,
    };
    use std::sync::Arc;

    #[sqlx::test(migrations = false)]
    #[ignore = "requires an isolated PostgreSQL instance"]
    async fn records_one_audited_approval_without_mutating_custody(pool: PgPool) {
        use crate::handlers::firearms::approve_custody_review;

        crate::db::run_migrations(&pool).await.unwrap();
        sqlx::query(
            r#"INSERT INTO users (id, email, username, password, role, full_name, phone_number)
               VALUES ('reviewer', 'reviewer@example.test', 'reviewer', 'fixture', 'supervisor', 'Fixture Reviewer', '')"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        let snapshot: DateTime<Utc> = sqlx::query_scalar(
            r#"INSERT INTO firearms (id, name, serial_number, model, caliber, status)
               VALUES ('fixture', 'Fixture', 'TEST-1', 'Fixture', 'Fixture', 'allocated')
               RETURNING updated_at"#,
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        assert!(matches!(
            approve(&pool, "fixture", snapshot, "reviewer", " ").await,
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            approve(&pool, "fixture", snapshot, "unknown", "Log 1").await,
            Err(AppError::DatabaseError(_))
        ));

        let submit = |role: &str| {
            let token =
                utils::generate_access_token("reviewer", "reviewer@example.test", role, true)
                    .unwrap();
            let mut headers = HeaderMap::new();
            headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());
            let payload = serde_json::from_value(json!({
                "inventoryUpdatedAt": snapshot,
                "sourceReference": " Log 1 ",
            }))
            .unwrap();
            approve_custody_review(
                State(Arc::new(pool.clone())),
                headers,
                Path("fixture".to_string()),
                Json(payload),
            )
        };
        assert!(matches!(submit("guard").await, Err(AppError::Forbidden(_))));
        let (first, second) = tokio::join!(submit("supervisor"), submit("supervisor"));
        let (status, Json(approval)) = match (first, second) {
            (Ok(approval), Err(AppError::Conflict(_)))
            | (Err(AppError::Conflict(_)), Ok(approval)) => approval,
            _ => panic!("Expected exactly one approval and one conflict"),
        };
        assert_eq!(status, StatusCode::CREATED);
        let audit: Vec<(Option<String>, String)> = sqlx::query_as(
            r#"SELECT actor_user_id, metadata->>'sourceReference' FROM audit_logs
               WHERE entity_id = 'fixture' AND action_key = 'firearm.custody_review.approved'"#,
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            audit,
            vec![(Some("reviewer".to_string()), "Log 1".to_string())]
        );
        let status_and_version: (String, DateTime<Utc>) =
            sqlx::query_as("SELECT status, updated_at FROM firearms WHERE id = 'fixture'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(status_and_version, ("allocated".to_string(), snapshot));
        let allocations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM firearm_allocations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(allocations, 0);

        let read_inventory = || {
            crate::handlers::firearms::get_all_firearms(
                axum::extract::State(std::sync::Arc::new(pool.clone())),
                axum::extract::Query(crate::handlers::firearms::FirearmListQuery {
                    page: None,
                    page_size: None,
                    state: Some("custody_review".to_string()),
                    search: None,
                }),
            )
        };
        let inventory = read_inventory().await.unwrap();
        assert_eq!(inventory["firearms"][0]["custodyReview"], true);
        assert_eq!(
            inventory["firearms"][0]["custodyReviewApprovedAt"],
            json!(approval.approved_at)
        );

        sqlx::query(
            r#"UPDATE firearms SET updated_at = updated_at + INTERVAL '1 second'
               WHERE id = 'fixture'"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(matches!(
            approve(&pool, "fixture", snapshot, "reviewer", "Log 1").await,
            Err(AppError::Conflict(_))
        ));
        let inventory = read_inventory().await.unwrap();
        assert!(inventory["firearms"][0]["custodyReviewApprovedAt"].is_null());
    }
}
