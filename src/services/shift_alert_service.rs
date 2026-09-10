use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tracing::{error, info};

const DEFAULT_ALERT_INTERVAL_SECS: u64 = 60;
const DEFAULT_CHECK_IN_GRACE_MINUTES: i64 = 15;

fn alert_interval_secs() -> u64 {
    std::env::var("SHIFT_ALERT_INTERVAL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_ALERT_INTERVAL_SECS)
}

fn check_in_grace_minutes() -> i64 {
    std::env::var("SHIFT_CHECK_IN_GRACE_MINUTES")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| (0..=1440).contains(value))
        .unwrap_or(DEFAULT_CHECK_IN_GRACE_MINUTES)
}

/// Repeatedly alerts leadership when a scheduled guard has not checked in
/// after the configured grace period.
pub async fn run_shift_alert_loop(pool: Arc<PgPool>) {
    let interval_duration = std::time::Duration::from_secs(alert_interval_secs());
    let mut interval = tokio::time::interval(interval_duration);

    info!(
        interval_secs = interval_duration.as_secs(),
        grace_minutes = check_in_grace_minutes(),
        "Shift attendance alert loop started"
    );

    loop {
        interval.tick().await;
        match evaluate_missing_check_ins(&pool).await {
            Ok(created) if created > 0 => {
                info!(
                    notifications_created = created,
                    "Created missing check-in alerts"
                )
            }
            Ok(_) => {}
            Err(err) => error!("Missing check-in evaluation failed: {err}"),
        }
    }
}

async fn evaluate_missing_check_ins(pool: &PgPool) -> Result<usize, sqlx::Error> {
    let candidates = sqlx::query(
        r#"
        SELECT
            s.id AS shift_id,
            s.guard_id,
            COALESCE(NULLIF(g.full_name, ''), g.username) AS guard_name,
            s.client_site,
            s.start_time,
            leadership.id AS recipient_id
        FROM shifts s
        JOIN users g ON g.id = s.guard_id
        CROSS JOIN users leadership
        WHERE s.status = 'scheduled'
          AND s.start_time <= CURRENT_TIMESTAMP - ($1 || ' minutes')::interval
          AND s.end_time >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
          AND LOWER(BTRIM(leadership.role)) IN ('supervisor', 'admin', 'superadmin')
          AND COALESCE(leadership.verified, true) = true
          AND COALESCE(leadership.status, 'active') = 'active'
          AND NOT EXISTS (
              SELECT 1
              FROM attendance a
              WHERE a.shift_id = s.id
                AND a.guard_id = s.guard_id
                AND a.check_in_time IS NOT NULL
          )
          AND NOT EXISTS (
              SELECT 1
              FROM notifications n
              WHERE n.user_id = leadership.id
                AND n.type = 'missing_check_in'
                AND n.related_shift_id = s.id
          )
        ORDER BY s.start_time ASC, leadership.id ASC
        "#,
    )
    .bind(check_in_grace_minutes().to_string())
    .fetch_all(pool)
    .await?;

    let mut notifications_created = 0;
    for candidate in candidates {
        let shift_id: String = candidate.try_get("shift_id")?;
        let guard_name: String = candidate.try_get("guard_name")?;
        let client_site: String = candidate.try_get("client_site")?;
        let start_time: DateTime<Utc> = candidate.try_get("start_time")?;
        let recipient_id: String = candidate.try_get("recipient_id")?;

        sqlx::query(
            r#"INSERT INTO notifications
               (id, user_id, title, message, type, related_shift_id, read)
               VALUES ($1, $2, $3, $4, 'missing_check_in', $5, false)"#,
        )
        .bind(crate::utils::generate_id())
        .bind(recipient_id)
        .bind("Missed Check-In Alert")
        .bind(format!(
            "{} has not checked in for the scheduled shift at {}. The shift started at {} and passed the {}-minute grace period.",
            guard_name,
            client_site,
            start_time.format("%I:%M %p"),
            check_in_grace_minutes()
        ))
        .bind(shift_id)
        .execute(pool)
        .await?;

        notifications_created += 1;
    }

    Ok(notifications_created)
}
