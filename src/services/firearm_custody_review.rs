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
    returned_to_stock: bool,
}

pub async fn approve(
    pool: &PgPool,
    firearm_id: &str,
    inventory_updated_at: DateTime<Utc>,
    actor_id: &str,
    source_reference: &str,
    confirm_in_stock: bool,
) -> AppResult<CustodyReviewApproval> {
    let source_reference = source_reference.trim();
    if source_reference.is_empty() || source_reference.encode_utf16().count() > 200 {
        return Err(AppError::BadRequest(
            "Enter a source document reference of 1 to 200 characters.".to_string(),
        ));
    }

    let mut tx = pool.begin().await.map_err(database_error)?;
    let (updated_at, status, serial_number) = sqlx::query_as::<_, (DateTime<Utc>, String, String)>(
        r#"SELECT updated_at, LOWER(BTRIM(status)), serial_number
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

    if updated_at != inventory_updated_at
        || !matches!(status.as_str(), "allocated" | "deployed")
        || active_custody
    {
        return Err(AppError::Conflict(
            "The inventory record changed. Refresh the inventory before reviewing it.".to_string(),
        ));
    }

    let new_approval = sqlx::query_scalar::<_, DateTime<Utc>>(
        r#"INSERT INTO firearm_custody_review_approvals (firearm_id, inventory_updated_at)
           VALUES ($1, $2)
           ON CONFLICT (firearm_id, inventory_updated_at) DO NOTHING
           RETURNING approved_at"#,
    )
    .bind(firearm_id)
    .bind(updated_at)
    .fetch_optional(&mut *tx)
    .await
    .map_err(database_error)?;

    let approved_at = if let Some(approved_at) = new_approval {
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
        approved_at
    } else if confirm_in_stock {
        sqlx::query_scalar(
            r#"SELECT approved_at FROM firearm_custody_review_approvals
               WHERE firearm_id = $1 AND inventory_updated_at = $2"#,
        )
        .bind(firearm_id)
        .bind(updated_at)
        .fetch_one(&mut *tx)
        .await
        .map_err(database_error)?
    } else {
        return Err(AppError::Conflict(
            "This review was already approved. Refresh the inventory.".to_string(),
        ));
    };

    if confirm_in_stock {
        let new_inventory_updated_at: DateTime<Utc> = sqlx::query_scalar(
            r#"UPDATE firearms SET status = 'available', updated_at = CURRENT_TIMESTAMP
               WHERE id = $1 RETURNING updated_at"#,
        )
        .bind(firearm_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(database_error)?;

        sqlx::query(
            r#"INSERT INTO audit_logs (id, actor_user_id, action_key, entity_type, entity_id, result, metadata)
               VALUES ($1, $2, 'firearm.custody_review.stock_confirmed', 'firearms', $3, 'success', $4)"#,
        )
        .bind(utils::generate_id())
        .bind(actor_id)
        .bind(firearm_id)
        .bind(json!({
            "sourceReference": source_reference,
            "serialNumber": serial_number,
            "inventoryUpdatedAt": updated_at,
            "newInventoryUpdatedAt": new_inventory_updated_at,
            "previousStatus": status,
            "newStatus": "available",
        }))
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
    }

    tx.commit().await.map_err(database_error)?;
    Ok(CustodyReviewApproval {
        approved_at,
        returned_to_stock: confirm_in_stock,
    })
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
        use crate::handlers::firearm_allocation::get_allocation_summary;
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

        let assert_review_counts = |pending: i64| {
            let pool = pool.clone();
            async move {
                let Json(summary) = get_allocation_summary(State(Arc::new(pool))).await.unwrap();
                assert_eq!(summary["custodyReviewFirearms"], 1);
                assert_eq!(summary["pendingCustodyReviewFirearms"], pending);
                assert_eq!(summary["activeCustody"], 0);
            }
        };
        assert_review_counts(1).await;

        assert!(matches!(
            approve(&pool, "fixture", snapshot, "reviewer", " ", false).await,
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            approve(&pool, "fixture", snapshot, "unknown", "Log 1", false).await,
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
        assert!(!approval.returned_to_stock);
        assert_review_counts(0).await;
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
        assert_review_counts(1).await;
        assert!(matches!(
            approve(&pool, "fixture", snapshot, "reviewer", "Log 1", false).await,
            Err(AppError::Conflict(_))
        ));
        let inventory = read_inventory().await.unwrap();
        assert!(inventory["firearms"][0]["custodyReviewApprovedAt"].is_null());
    }

    #[sqlx::test(migrations = false)]
    #[ignore = "requires an isolated PostgreSQL instance"]
    async fn confirmed_stock_reconciliation_reuses_approvals_and_preserves_custody(pool: PgPool) {
        use crate::handlers::firearm_allocation::get_allocation_summary;
        use crate::handlers::firearms::approve_custody_review;

        crate::db::run_migrations(&pool).await.unwrap();
        sqlx::query(
            r#"INSERT INTO users (id, email, username, password, role, full_name, phone_number)
               VALUES ('reviewer', 'reviewer@example.test', 'reviewer', 'fixture', 'supervisor', 'Fixture Reviewer', ''),
                      ('confirmer', 'confirmer@example.test', 'confirmer', 'fixture', 'supervisor', 'Fixture Confirmer', ''),
                      ('guard', 'guard@example.test', 'guard', 'fixture', 'guard', 'Fixture Guard', '')"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        let versions: Vec<(String, DateTime<Utc>)> = sqlx::query_as(
            r#"INSERT INTO firearms (id, name, serial_number, model, caliber, status)
               VALUES ('current', 'Fixture', 'STOCK-1', 'Fixture', 'Fixture', 'allocated'),
                      ('legacy', 'Fixture', 'STOCK-2', 'Fixture', 'Fixture', 'deployed'),
                      ('active', 'Fixture', 'ISSUED-1', 'Fixture', 'Fixture', 'allocated'),
                      ('maintenance', 'Fixture', 'MAINT-1', 'Fixture', 'Fixture', 'maintenance')
               RETURNING id, updated_at"#,
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        let version = |id: &str| versions.iter().find(|(item, _)| item == id).unwrap().1;
        sqlx::query(
            r#"INSERT INTO firearm_allocations (id, guard_id, firearm_id, allocation_date, status)
               VALUES ('existing-allocation', 'guard', 'active', CURRENT_TIMESTAMP, 'active')"#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let legacy = approve(
            &pool,
            "legacy",
            version("legacy"),
            "reviewer",
            "Old review",
            false,
        )
        .await
        .unwrap();
        assert!(!legacy.returned_to_stock);
        let submit = |role: &str| {
            let token =
                utils::generate_access_token("confirmer", "confirmer@example.test", role, true)
                    .unwrap();
            let mut headers = HeaderMap::new();
            headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());
            let payload = serde_json::from_value(json!({
                "inventoryUpdatedAt": version("current"),
                "sourceReference": "Return log 1",
                "confirmInStock": true,
            }))
            .unwrap();
            approve_custody_review(
                State(Arc::new(pool.clone())),
                headers,
                Path("current".into()),
                Json(payload),
            )
        };
        assert!(matches!(submit("guard").await, Err(AppError::Forbidden(_))));
        let (first, second) = tokio::join!(submit("supervisor"), submit("supervisor"));
        let current = match (first, second) {
            (Ok((StatusCode::CREATED, Json(approval))), Err(AppError::Conflict(_)))
            | (Err(AppError::Conflict(_)), Ok((StatusCode::CREATED, Json(approval)))) => approval,
            _ => panic!("Expected exactly one stock confirmation and one conflict"),
        };
        assert_eq!(json!(current)["returnedToStock"], true);

        assert!(matches!(
            approve(
                &pool,
                "legacy",
                version("legacy"),
                "unknown",
                "Unlogged stock confirmation",
                true
            )
            .await,
            Err(AppError::DatabaseError(_))
        ));
        let legacy_status: (String, DateTime<Utc>) =
            sqlx::query_as("SELECT status, updated_at FROM firearms WHERE id = 'legacy'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(legacy_status, ("deployed".to_string(), version("legacy")));
        let confirmed = approve(
            &pool,
            "legacy",
            version("legacy"),
            "confirmer",
            "Return log 2",
            true,
        )
        .await
        .unwrap();
        assert!(confirmed.returned_to_stock);
        assert_eq!(confirmed.approved_at, legacy.approved_at);
        for id in ["active", "maintenance"] {
            assert!(matches!(
                approve(&pool, id, version(id), "confirmer", "Return log", true).await,
                Err(AppError::Conflict(_))
            ));
        }

        let Json(summary) = get_allocation_summary(State(Arc::new(pool.clone())))
            .await
            .unwrap();
        assert_eq!(summary["availableFirearms"], 2);
        assert_eq!(summary["activeCustody"], 1);
        assert_eq!(summary["totalAllocationRecords"], 1);
        assert_eq!(summary["custodyReviewFirearms"], 0);
        assert_eq!(summary["pendingCustodyReviewFirearms"], 0);
        let audits: Vec<(String, Option<String>, String, Option<String>)> = sqlx::query_as(
            r#"SELECT action_key, actor_user_id, metadata->>'sourceReference', metadata->>'newStatus'
               FROM audit_logs WHERE entity_id = 'legacy' ORDER BY action_key"#,
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            audits,
            vec![
                (
                    "firearm.custody_review.approved".into(),
                    Some("reviewer".into()),
                    "Old review".into(),
                    None
                ),
                (
                    "firearm.custody_review.stock_confirmed".into(),
                    Some("confirmer".into()),
                    "Return log 2".into(),
                    Some("available".into())
                ),
            ]
        );
    }
}
