//! Asynchronous email and Web Push delivery for persisted notifications.
//!
//! Notification writes are intentionally kept inside the feature workflows. This
//! worker polls the durable notification records after the transaction commits,
//! so provider failures never roll back approvals, schedules, or incidents.

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{PgPool, Row};
use std::{sync::Arc, time::Duration};
use web_push::{
    ContentEncoding, IsahcWebPushClient, SubscriptionInfo, Urgency, VapidSignatureBuilder,
    WebPushClient, WebPushMessageBuilder,
};

const POLL_INTERVAL: Duration = Duration::from_secs(15);
const RETRY_INTERVAL: &str = "15 minutes";
const LOOKBACK_INTERVAL: &str = "7 days";
const MAX_BATCH_SIZE: i64 = 50;

#[derive(Debug)]
struct PendingNotification {
    id: String,
    user_id: String,
    email: String,
    title: String,
    message: String,
    email_sent_at: Option<DateTime<Utc>>,
    push_sent_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
struct EmailConfig {
    api_key: String,
    from: String,
}

#[derive(Debug, Clone)]
struct PushConfig {
    private_key: String,
    subject: String,
}

pub async fn run_notification_delivery_loop(pool: Arc<PgPool>) {
    let email_config = email_config();
    let push_config = push_config();

    tracing::info!(
        email_enabled = email_config.is_some(),
        push_enabled = push_config.is_some(),
        "Notification delivery worker started"
    );

    if email_config.is_none() {
        tracing::warn!(
            "Email notification delivery is disabled: configure RESEND_API_KEY and NOTIFICATION_EMAIL_ENABLED=true"
        );
    }
    if push_config.is_none() {
        tracing::warn!(
            "Push notification delivery is disabled: configure VAPID_PRIVATE_KEY and VAPID_SUBJECT"
        );
    }

    let push_client = match IsahcWebPushClient::new() {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(error = ?error, "Failed to initialize push delivery client");
            return;
        }
    };
    loop {
        if let Err(error) = process_pending_notifications(
            pool.as_ref(),
            email_config.as_ref(),
            push_config.as_ref(),
            &push_client,
        )
        .await
        {
            tracing::error!(error = %error, "Notification delivery pass failed");
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn email_config() -> Option<EmailConfig> {
    if !env_bool("NOTIFICATION_EMAIL_ENABLED", true) {
        return None;
    }

    let api_key = std::env::var("RESEND_API_KEY").ok()?.trim().to_string();
    if api_key.is_empty() {
        return None;
    }

    let from = std::env::var("RESEND_FROM_EMAIL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "Sentinel DASIA <noreply@dasiasentinel.xyz>".to_string());

    Some(EmailConfig { api_key, from })
}

fn push_config() -> Option<PushConfig> {
    let private_key = std::env::var("VAPID_PRIVATE_KEY").ok()?.trim().to_string();
    if private_key.is_empty() {
        return None;
    }

    let subject = std::env::var("VAPID_SUBJECT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "mailto:noreply@dasiasentinel.xyz".to_string());

    Some(PushConfig {
        private_key,
        subject,
    })
}

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        Err(_) => default,
    }
}

async fn process_pending_notifications(
    pool: &PgPool,
    email: Option<&EmailConfig>,
    push: Option<&PushConfig>,
    push_client: &IsahcWebPushClient,
) -> Result<(), String> {
    if email.is_none() && push.is_none() {
        return Ok(());
    }

    let rows = sqlx::query(
        r#"SELECT n.id, n.user_id, u.email, n.title, n.message,
                  n.email_sent_at, n.push_sent_at
           FROM notifications n
           JOIN users u ON u.id = n.user_id
           WHERE n.created_at >= CURRENT_TIMESTAMP - $1::INTERVAL
             AND (n.email_sent_at IS NULL OR n.push_sent_at IS NULL)
             AND (n.delivery_last_attempt_at IS NULL
                  OR n.delivery_last_attempt_at < CURRENT_TIMESTAMP - $2::INTERVAL)
           ORDER BY n.created_at ASC
           LIMIT $3"#,
    )
    .bind(LOOKBACK_INTERVAL)
    .bind(RETRY_INTERVAL)
    .bind(MAX_BATCH_SIZE)
    .fetch_all(pool)
    .await
    .map_err(|error| format!("failed to query pending notifications: {error}"))?;

    for row in rows {
        let notification = PendingNotification {
            id: row
                .try_get("id")
                .map_err(|error| format!("invalid notification id: {error}"))?,
            user_id: row
                .try_get("user_id")
                .map_err(|error| format!("invalid notification user id: {error}"))?,
            email: row
                .try_get("email")
                .map_err(|error| format!("invalid notification email: {error}"))?,
            title: row
                .try_get("title")
                .map_err(|error| format!("invalid notification title: {error}"))?,
            message: row
                .try_get("message")
                .map_err(|error| format!("invalid notification message: {error}"))?,
            email_sent_at: row
                .try_get("email_sent_at")
                .map_err(|error| format!("invalid email delivery timestamp: {error}"))?,
            push_sent_at: row
                .try_get("push_sent_at")
                .map_err(|error| format!("invalid push delivery timestamp: {error}"))?,
        };

        deliver_notification(pool, &notification, email, push, push_client).await;
    }

    Ok(())
}

async fn deliver_notification(
    pool: &PgPool,
    notification: &PendingNotification,
    email: Option<&EmailConfig>,
    push: Option<&PushConfig>,
    push_client: &IsahcWebPushClient,
) {
    let mut attempted = false;
    let mut errors = Vec::new();

    if notification.email_sent_at.is_none() {
        if let Some(config) = email {
            attempted = true;
            match send_email(config, notification).await {
                Ok(()) => {
                    if let Err(error) = mark_email_sent(pool, &notification.id).await {
                        errors.push(error);
                    }
                }
                Err(error) => errors.push(format!("email: {error}")),
            }
        }
    }

    if notification.push_sent_at.is_none() {
        if let Some(config) = push {
            attempted = true;
            match send_push(pool, config, notification, push_client).await {
                Ok(()) => {
                    if let Err(error) = mark_push_sent(pool, &notification.id).await {
                        errors.push(error);
                    }
                }
                Err(error) => errors.push(format!("push: {error}")),
            }
        }
    }

    if attempted {
        let error_text = if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        };
        if let Err(error) = record_attempt(pool, &notification.id, error_text.as_deref()).await {
            tracing::error!(notification_id = %notification.id, error = %error, "Failed to record notification delivery attempt");
        }
    }
}

async fn send_email(
    config: &EmailConfig,
    notification: &PendingNotification,
) -> Result<(), String> {
    let html_body = format!(
        r#"<div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto">
             <h2>{}</h2>
             <p>{}</p>
             <p style="color:#667085;font-size:12px">This notification was generated by SENTINEL.</p>
           </div>"#,
        escape_html(&notification.title),
        escape_html(&notification.message)
    );

    let response = reqwest::Client::new()
        .post("https://api.resend.com/emails")
        .header("Authorization", format!("Bearer {}", config.api_key))
        .json(&json!({
            "from": config.from,
            "to": [notification.email],
            "subject": format!("[SENTINEL] {}", notification.title),
            "html": html_body,
        }))
        .send()
        .await
        .map_err(|error| format!("email provider request failed: {error}"))?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("email provider returned {}", response.status()))
    }
}

async fn send_push(
    pool: &PgPool,
    config: &PushConfig,
    notification: &PendingNotification,
    client: &IsahcWebPushClient,
) -> Result<(), String> {
    let subscriptions =
        sqlx::query("SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE user_id = $1")
            .bind(&notification.user_id)
            .fetch_all(pool)
            .await
            .map_err(|error| format!("failed to load push subscriptions: {error}"))?;

    if subscriptions.is_empty() {
        // There is nothing to deliver for this channel. Mark it complete so the
        // worker does not repeatedly scan users who have not enabled push.
        return Ok(());
    }

    let payload = serde_json::to_vec(&json!({
        "title": notification.title,
        "body": notification.message,
        "url": "/",
        "tag": format!("sentinel-{}", notification.id),
        "requireInteraction": false,
    }))
    .map_err(|error| format!("failed to encode push payload: {error}"))?;

    let mut delivered = 0usize;
    let mut failures = Vec::new();
    for subscription in subscriptions {
        let endpoint: String = subscription
            .try_get("endpoint")
            .map_err(|error| format!("invalid push endpoint: {error}"))?;
        let p256dh: String = subscription
            .try_get("p256dh")
            .map_err(|error| format!("invalid push key: {error}"))?;
        let auth: String = subscription
            .try_get("auth")
            .map_err(|error| format!("invalid push auth key: {error}"))?;

        let info = SubscriptionInfo::new(endpoint, p256dh, auth);
        let mut signature_builder = VapidSignatureBuilder::from_base64(&config.private_key, &info)
            .map_err(|error| format!("invalid VAPID private key: {error:?}"))?;
        signature_builder.add_claim("sub", config.subject.as_str());
        let signature = signature_builder
            .build()
            .map_err(|error| format!("failed to sign push message: {error:?}"))?;

        let mut message_builder = WebPushMessageBuilder::new(&info);
        message_builder.set_ttl(86_400);
        message_builder.set_urgency(Urgency::Normal);
        message_builder.set_payload(ContentEncoding::Aes128Gcm, &payload);
        message_builder.set_vapid_signature(signature);

        match client
            .send(
                message_builder
                    .build()
                    .map_err(|error| format!("failed to build push message: {error:?}"))?,
            )
            .await
        {
            Ok(()) => delivered += 1,
            Err(error) => failures.push(format!("{error:?}")),
        }
    }

    if delivered > 0 {
        if !failures.is_empty() {
            tracing::warn!(
                notification_id = %notification.id,
                delivered,
                failed = failures.len(),
                "Some push subscriptions rejected a notification"
            );
        }
        Ok(())
    } else {
        Err(format!(
            "all push subscriptions failed: {}",
            failures.join("; ")
        ))
    }
}

async fn mark_email_sent(pool: &PgPool, notification_id: &str) -> Result<(), String> {
    sqlx::query("UPDATE notifications SET email_sent_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1")
        .bind(notification_id)
        .execute(pool)
        .await
        .map_err(|error| format!("failed to mark email delivery: {error}"))?;
    Ok(())
}

async fn mark_push_sent(pool: &PgPool, notification_id: &str) -> Result<(), String> {
    sqlx::query("UPDATE notifications SET push_sent_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1")
        .bind(notification_id)
        .execute(pool)
        .await
        .map_err(|error| format!("failed to mark push delivery: {error}"))?;
    Ok(())
}

async fn record_attempt(
    pool: &PgPool,
    notification_id: &str,
    error: Option<&str>,
) -> Result<(), String> {
    sqlx::query(
        "UPDATE notifications
         SET delivery_attempts = delivery_attempts + 1,
             delivery_last_attempt_at = CURRENT_TIMESTAMP,
             delivery_last_error = $2,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = $1",
    )
    .bind(notification_id)
    .bind(error)
    .execute(pool)
    .await
    .map_err(|db_error| format!("failed to record delivery attempt: {db_error}"))?;
    Ok(())
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::escape_html;

    #[test]
    fn email_content_escapes_untrusted_notification_text() {
        assert_eq!(
            escape_html(r#"<script>alert('x')</script>"#),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"
        );
    }
}
