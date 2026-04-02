use sqlx::{PgPool, Row};
use std::sync::Arc;
use tracing::{error, info};

/// How often the geofence check runs (seconds). Override with GEOFENCE_ALERT_INTERVAL_SECS.
fn alert_interval_secs() -> u64 {
    std::env::var("GEOFENCE_ALERT_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300)
}

/// Entry point: runs forever, checking geofence violations on every tick.
pub async fn run_geofence_alert_loop(pool: Arc<PgPool>) {
    let interval_duration =
        std::time::Duration::from_secs(alert_interval_secs());
    let mut interval = tokio::time::interval(interval_duration);

    info!(
        interval_secs = interval_duration.as_secs(),
        "Geofence alert loop started"
    );

    loop {
        interval.tick().await;
        if let Err(e) = check_geofence_violations(&pool).await {
            error!("Geofence violation check failed: {e}");
        }
    }
}

/// Finds guards whose most recent geofence event is an 'exit' that occurred within the last
/// `lookback_minutes` and where no 'geofence_alert' notification has been sent within the last
/// `dedupe_minutes`. For each such guard, inserts a notification for every supervisor/admin.
async fn check_geofence_violations(pool: &PgPool) -> Result<(), sqlx::Error> {
    let lookback_minutes: i64 = 30;
    let dedupe_minutes: i64 = 15;

    // Guards with a recent 'exit' as their latest geofence event.
    let exits = sqlx::query(
        r#"
        SELECT DISTINCT ON (ge.guard_id)
            ge.guard_id,
            ge.client_site_id,
            u.full_name AS guard_name,
            cs.name    AS site_name
        FROM geofence_events ge
        JOIN users       u  ON u.id  = ge.guard_id
        JOIN client_sites cs ON cs.id = ge.client_site_id
        WHERE ge.created_at >= NOW() - ($1 || ' minutes')::INTERVAL
        ORDER BY ge.guard_id, ge.created_at DESC
        "#,
    )
    .bind(lookback_minutes.to_string())
    .fetch_all(pool)
    .await?;

    for row in exits {
        let guard_id: String = row.get("guard_id");
        let client_site_id: String = row.get("client_site_id");
        let guard_name_opt: Option<String> = row.get("guard_name");
        let site_name_opt: Option<String> = row.get("site_name");

        // Skip if the most recent event is not an exit.
        let is_exit = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT event_type = 'exit'
            FROM geofence_events
            WHERE guard_id = $1 AND client_site_id = $2
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(&guard_id)
        .bind(&client_site_id)
        .fetch_optional(pool)
        .await?
        .unwrap_or(false);

        if !is_exit {
            continue;
        }

        // Deduplicate: skip if we already sent an alert for this guard recently.
        let already_alerted = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM notifications
                WHERE type = 'geofence_alert'
                  AND related_shift_id = $1
                  AND created_at >= NOW() - ($2 || ' minutes')::INTERVAL
            )
            "#,
        )
        .bind(&guard_id)
        .bind(dedupe_minutes.to_string())
        .fetch_one(pool)
        .await?;

        if already_alerted {
            continue;
        }

        // Fetch all supervisors/admins to notify.
                let recipients = sqlx::query(
            r#"
            SELECT id FROM users
            WHERE LOWER(role) IN ('supervisor', 'admin', 'superadmin')
              AND COALESCE(approval_status, 'approved') = 'approved'
            "#
        )
        .fetch_all(pool)
        .await?;

                let guard_name = guard_name_opt.unwrap_or_else(|| guard_id.clone());
                let site_name = site_name_opt.unwrap_or_else(|| client_site_id.clone());
        let title = format!("Guard Outside Geofence: {guard_name}");
        let message = format!(
            "Guard {guard_name} has exited the designated geofence zone for site '{site_name}'. \
             Please verify their location."
        );

        for recipient in recipients {
            let recipient_id: String = recipient.get("id");
            let notif_id = uuid::Uuid::new_v4().to_string();
            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO notifications
                    (id, user_id, title, message, type, related_shift_id, read)
                VALUES ($1, $2, $3, $4, 'geofence_alert', $5, false)
                "#,
            )
            .bind(&notif_id)
            .bind(&recipient_id)
            .bind(&title)
            .bind(&message)
            .bind(&guard_id)
            .execute(pool)
            .await
            {
                error!(
                    guard_id = %guard_id,
                    recipient_id = %recipient_id,
                    err = %e,
                    "Failed to insert geofence alert notification"
                );
            }
        }

        info!(
            guard_id = %guard_id,
            site = %site_name,
            "Geofence exit alert dispatched"
        );
    }

    Ok(())
}
