use std::{env, process};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Datelike, Duration, FixedOffset, TimeZone, Utc, Weekday};
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use uuid::Uuid;

const BATCH_ID: &str = "capstone-live-october-2026";
const REQUIRED_CONFIRMATION: &str = "LIVE_CAPSTONE_DATASET_CONFIRMED";
const MANILA_OFFSET_SECONDS: i32 = 8 * 60 * 60;

#[derive(Clone)]
struct SourceGuard {
    id: String,
    full_name: String,
}

#[derive(Clone)]
struct SourceSite {
    id: String,
    name: String,
    address: Option<String>,
    latitude: f64,
    longitude: f64,
}

#[derive(Clone)]
struct SeedActor {
    id: String,
    full_name: String,
    role: String,
}

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

fn require_env(name: &str) -> Result<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("{} must be set", name))
}

fn verify_live_target(command: &str) -> Result<String> {
    if env::var("CAPSTONE_DATASET_MODE").as_deref() != Ok("true") {
        bail!("CAPSTONE_DATASET_MODE=true is required")
    }
    if require_env("CAPSTONE_TARGET_ENVIRONMENT")?.to_ascii_lowercase() != "production" {
        bail!("CAPSTONE_TARGET_ENVIRONMENT must be production")
    }
    if require_env("CAPSTONE_SEED_CONFIRM")? != REQUIRED_CONFIRMATION {
        bail!("CAPSTONE_SEED_CONFIRM must equal {}", REQUIRED_CONFIRMATION)
    }
    // Production use must be explicit. Never fall back to DATABASE_URL.
    let target_url = require_env("CAPSTONE_TARGET_DATABASE_URL")?;
    if !target_url.starts_with("postgres") {
        bail!("CAPSTONE_TARGET_DATABASE_URL must be a PostgreSQL URL")
    }
    let _protected_superadmin = require_env("CAPSTONE_PROTECTED_SUPERADMIN_ID")?;

    if !matches!(command, "seed" | "reset" | "status") {
        bail!("Usage: cargo run --bin capstone-dataset -- <seed|reset|status>")
    }
    Ok(target_url)
}

async fn connect(url: &str, label: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(5)
        .connect(url)
        .await
        .with_context(|| format!("Unable to connect to {} database", label))
}

async fn ensure_ledger(pool: &PgPool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS capstone_seed_batches (
            batch_id VARCHAR(80) PRIMARY KEY,
            data_origin VARCHAR(80) NOT NULL,
            reference_at TIMESTAMPTZ NOT NULL,
            status VARCHAR(20) NOT NULL,
            seeded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMPTZ,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS capstone_seed_records (
            batch_id VARCHAR(80) NOT NULL REFERENCES capstone_seed_batches(batch_id) ON DELETE CASCADE,
            table_name VARCHAR(100) NOT NULL,
            record_id VARCHAR(100) NOT NULL,
            PRIMARY KEY (batch_id, table_name, record_id)
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn track(pool: &PgPool, table_name: &str, record_id: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO capstone_seed_records (batch_id, table_name, record_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(BATCH_ID)
    .bind(table_name)
    .bind(record_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn delete_marked(pool: &PgPool, table_name: &str, delete_sql: &str) -> Result<()> {
    sqlx::query(delete_sql).bind(BATCH_ID).execute(pool).await?;
    tracing::debug!(table_name, "Removed presentation seed records");
    Ok(())
}

async fn reset_batch(pool: &PgPool) -> Result<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM capstone_seed_batches WHERE batch_id = $1)",
    )
    .bind(BATCH_ID)
    .fetch_one(pool)
    .await?;
    if !exists {
        return Ok(());
    }

    // Dependents are deliberately removed before their parents. Every delete is scoped
    // through the immutable batch ledger rather than a timestamp or a display label.
    let deletions = [
        ("audit_logs", "DELETE FROM audit_logs WHERE id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'audit_logs')"),
        ("notifications", "DELETE FROM notifications WHERE id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'notifications')"),
        ("operational_request_events", "DELETE FROM operational_request_events WHERE id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'operational_request_events')"),
        ("operational_requests", "DELETE FROM operational_requests WHERE id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'operational_requests')"),
        ("support_tickets", "DELETE FROM support_tickets WHERE id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'support_tickets')"),
        ("incident_severity_classifications", "DELETE FROM incident_severity_classifications WHERE id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'incident_severity_classifications')"),
        ("incidents", "DELETE FROM incidents WHERE id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'incidents')"),
        ("tracking_points", "DELETE FROM tracking_points WHERE id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'tracking_points')"),
        ("guard_absence_predictions", "DELETE FROM guard_absence_predictions WHERE id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'guard_absence_predictions')"),
        ("smart_guard_replacements", "DELETE FROM smart_guard_replacements WHERE id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'smart_guard_replacements')"),
        ("guard_shift_readiness", "DELETE FROM guard_shift_readiness WHERE id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'guard_shift_readiness')"),
        ("punctuality_records", "DELETE FROM punctuality_records WHERE id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'punctuality_records')"),
        ("attendance", "DELETE FROM attendance WHERE id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'attendance')"),
        ("client_evaluations", "DELETE FROM client_evaluations WHERE id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'client_evaluations')"),
        ("guard_merit_scores", "DELETE FROM guard_merit_scores WHERE id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'guard_merit_scores')"),
        ("feedback", "DELETE FROM feedback WHERE id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'feedback')"),
        ("shifts", "DELETE FROM shifts WHERE id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'shifts')"),
    ];
    for (table_name, query) in deletions {
        delete_marked(pool, table_name, query).await?;
    }
    sqlx::query("DELETE FROM capstone_seed_batches WHERE batch_id = $1")
        .bind(BATCH_ID)
        .execute(pool)
        .await?;
    Ok(())
}

async fn read_live_guards(pool: &PgPool) -> Result<Vec<SourceGuard>> {
    let rows = sqlx::query(
        r#"
        SELECT id, full_name
        FROM users
        WHERE LOWER(BTRIM(role)) = 'guard'
          AND COALESCE(LOWER(BTRIM(status)), 'active') = 'active'
          AND NOT EXISTS (SELECT 1 FROM feedback WHERE feedback.user_id = users.id)
        ORDER BY guard_code NULLS LAST, full_name
        LIMIT 50
        "#,
    )
    .fetch_all(pool)
    .await?;
    if rows.len() < 50 {
        bail!(
            "Live database has only {} active guards without feedback; 50 are required",
            rows.len()
        )
    }
    rows.into_iter()
        .map(|row| {
            Ok(SourceGuard {
                id: row.try_get("id")?,
                full_name: row.try_get("full_name")?,
            })
        })
        .collect()
}

async fn read_live_sites(pool: &PgPool) -> Result<Vec<SourceSite>> {
    let rows = sqlx::query(
        r#"
        SELECT id, name, address, latitude, longitude
        FROM client_sites
        WHERE is_active = true
          AND (LOWER(name) LIKE '%tagum%' OR LOWER(COALESCE(address, '')) LIKE '%tagum%')
        ORDER BY name
        "#,
    )
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
        bail!("No active Tagum client sites were found in the live database")
    }
    rows.into_iter()
        .map(|row| {
            Ok(SourceSite {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                address: row.try_get("address")?,
                latitude: row.try_get("latitude")?,
                longitude: row.try_get("longitude")?,
            })
        })
        .collect()
}

fn manila_time(day: u32, hour: u32, minute: u32) -> Result<DateTime<Utc>> {
    let offset = FixedOffset::east_opt(MANILA_OFFSET_SECONDS)
        .ok_or_else(|| anyhow!("Invalid Manila offset"))?;
    offset
        .with_ymd_and_hms(2026, 10, day, hour, minute, 0)
        .single()
        .map(|value| value.with_timezone(&Utc))
        .ok_or_else(|| anyhow!("Invalid October 2026 timestamp"))
}

async fn seed_shift_activity(
    pool: &PgPool,
    guards: &[SourceGuard],
    sites: &[SourceSite],
    admin: &SeedActor,
    supervisor: &SeedActor,
) -> Result<()> {
    let completed_until = 16;
    for day in 1..=17_u32 {
        let weekday = manila_time(day, 12, 0)?.weekday();
        if weekday == Weekday::Sun {
            continue;
        }
        for (index, guard) in guards.iter().enumerate() {
            let site = &sites[(index + day as usize) % sites.len()];
            let night_shift = (index + day as usize) % 4 == 0;
            let (start_hour, start_minute) = if night_shift { (15, 0) } else { (7, 0) };
            let start = manila_time(day, start_hour, start_minute)?;
            let end = start + Duration::hours(8);
            let no_show = (day == 7 && index == 4) || (day == 13 && index == 18);
            let replacement = day == 7 && index == 4;
            let substitute = &guards[(index + 7) % guards.len()];
            let active_today = day == 17 && night_shift && index % 3 == 0;
            let shift_id = new_id();
            let scheduled_guard_id = if replacement {
                &substitute.id
            } else {
                &guard.id
            };
            let status = if active_today {
                "in_progress"
            } else if no_show && !replacement {
                "absent"
            } else {
                "completed"
            };
            let replacement_status = if replacement {
                "accepted"
            } else if no_show {
                "searching"
            } else {
                "not_needed"
            };
            let created_at = start
                - Duration::days(5 + (index % 7) as i64)
                - Duration::minutes((index * 3) as i64);

            sqlx::query(
                r#"INSERT INTO shifts (id, guard_id, start_time, end_time, client_site, status, grace_period_minutes, replacement_status, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, $5, $6, 15, $7, $8, $8)"#,
            )
            .bind(&shift_id).bind(scheduled_guard_id).bind(start).bind(end).bind(&site.name).bind(status).bind(replacement_status).bind(created_at)
            .execute(pool).await?;
            track(pool, "shifts", &shift_id).await?;

            if no_show {
                let punctuality_id = new_id();
                sqlx::query(
                    "INSERT INTO punctuality_records (id, guard_id, shift_id, scheduled_start_time, actual_check_in_time, minutes_late, is_on_time, status, created_at) VALUES ($1, $2, $3, $4, NULL, NULL, false, 'absent', $5)",
                )
                .bind(&punctuality_id).bind(&guard.id).bind(&shift_id).bind(start).bind(start + Duration::minutes(20)).execute(pool).await?;
                track(pool, "punctuality_records", &punctuality_id).await?;

                if replacement {
                    let recommendation_id = new_id();
                    sqlx::query(
                        r#"INSERT INTO smart_guard_replacements (id, shift_id, absent_guard_id, recommended_guard_id, recommendation_rank, compatibility_score, confidence_score, rationale, scoring_breakdown, candidate_pool, recommendation_status, generated_at, expires_at, created_at, updated_at)
                           VALUES ($1, $2, $3, $4, 1, 0.93, 0.89, 'Available nearby with recent on-time attendance and matching Tagum assignment history.', $5, $6, 'accepted', $7, $8, $7, $7)"#,
                    )
                    .bind(&recommendation_id).bind(&shift_id).bind(&guard.id).bind(&substitute.id)
                    .bind(json!({"availability": 0.35, "punctuality": 0.32, "site_history": 0.26}))
                    .bind(json!([{"guardId": substitute.id, "rank": 1, "score": 0.93}]))
                    .bind(start + Duration::minutes(18)).bind(start + Duration::minutes(40)).execute(pool).await?;
                    track(pool, "smart_guard_replacements", &recommendation_id).await?;
                } else {
                    continue;
                }
            }

            if !active_today {
                let check_in =
                    start + Duration::minutes(((index * 7 + day as usize * 3) % 9) as i64);
                let is_late = !replacement && !no_show && (index + day as usize) % 17 == 0;
                let actual_check_in = if is_late {
                    start + Duration::minutes(18 + (index % 13) as i64)
                } else {
                    check_in
                };
                let check_out = end + Duration::minutes(((index * 5 + day as usize) % 12) as i64);
                let attendance_id = new_id();
                sqlx::query("INSERT INTO attendance (id, guard_id, shift_id, check_in_time, check_out_time, status, check_in_source, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, 'completed', $6, $4, $5)")
                    .bind(&attendance_id).bind(scheduled_guard_id).bind(&shift_id).bind(actual_check_in).bind(check_out).bind(if index % 3 == 0 { "mobile" } else { "manual" }).execute(pool).await?;
                track(pool, "attendance", &attendance_id).await?;
                let punctuality_id = new_id();
                sqlx::query("INSERT INTO punctuality_records (id, guard_id, shift_id, scheduled_start_time, actual_check_in_time, minutes_late, is_on_time, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $5)")
                    .bind(&punctuality_id).bind(scheduled_guard_id).bind(&shift_id).bind(start).bind(actual_check_in).bind(if is_late { Some((actual_check_in - start).num_minutes() as i32) } else { Some(0) }).bind(!is_late).bind(if is_late { "late" } else { "present" }).execute(pool).await?;
                track(pool, "punctuality_records", &punctuality_id).await?;
            } else {
                let check_in = start - Duration::minutes(4 + (index % 5) as i64);
                let attendance_id = new_id();
                sqlx::query("INSERT INTO attendance (id, guard_id, shift_id, check_in_time, check_out_time, status, check_in_source, created_at, updated_at) VALUES ($1, $2, $3, $4, NULL, 'checked_in', 'mobile', $4, $4)")
                    .bind(&attendance_id).bind(&guard.id).bind(&shift_id).bind(check_in).execute(pool).await?;
                track(pool, "attendance", &attendance_id).await?;
            }

            if index % 5 == 0 && day <= completed_until {
                let readiness_id = new_id();
                sqlx::query("INSERT INTO guard_shift_readiness (id, shift_id, guard_id, checked_items, notes, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $6)")
                    .bind(&readiness_id).bind(&shift_id).bind(scheduled_guard_id).bind(json!(["radio", "identification", "site briefing"])).bind("Pre-shift readiness confirmed.").bind(start - Duration::minutes(20)).execute(pool).await?;
                track(pool, "guard_shift_readiness", &readiness_id).await?;
            }

            if replacement || (index + day as usize) % 23 == 0 {
                let audit_id = new_id();
                sqlx::query("INSERT INTO audit_logs (id, actor_user_id, action_key, entity_type, entity_id, result, reason, source_ip, user_agent, metadata, created_at) VALUES ($1, $2, $3, 'shift', $4, 'success', $5, '10.10.0.15', 'SENTINEL Operations Console', $6, $7)")
                    .bind(&audit_id).bind(if replacement { &supervisor.id } else { &admin.id }).bind(if replacement { "SHIFT_REPLACEMENT_ACCEPTED" } else { "SHIFT_SCHEDULE_CREATED" }).bind(&shift_id).bind(if replacement { "No-show replacement accepted after supervisor review." } else { "Schedule published for Tagum operations." }).bind(json!({"data_origin":"capstone_live_seed","batch_id":BATCH_ID})).bind(start - Duration::minutes(15)).execute(pool).await?;
                track(pool, "audit_logs", &audit_id).await?;
            }
        }
    }
    Ok(())
}

async fn seed_operational_records(
    pool: &PgPool,
    guards: &[SourceGuard],
    sites: &[SourceSite],
    admin: &SeedActor,
    supervisor: &SeedActor,
) -> Result<()> {
    let site = &sites[0];
    let incident_specs = [
        ("Visitor access verification", "A visitor reached the reception point without a matching appointment record. Identity was verified and entry was delayed.", "investigating", "medium", 8_u32),
        ("Perimeter lighting outage", "The north perimeter light was out during the evening patrol. Facilities were notified and temporary patrol frequency was increased.", "resolved", "low", 10_u32),
        ("Unattended delivery package", "A delivery package was left at the side entrance. The area was isolated until the client representative confirmed the delivery.", "resolved", "high", 14_u32),
        ("Gate access delay", "Vehicle gate access was delayed during the afternoon shift change. The guard recorded the queue and escalated to the site contact.", "open", "medium", 17_u32),
    ];
    for (index, (title, description, status, priority, day)) in incident_specs.iter().enumerate() {
        let id = new_id();
        let created_at = manila_time(*day, 10 + index as u32, 12 + index as u32 * 7)?;
        sqlx::query("INSERT INTO incidents (id, title, description, location, site_name, reported_by, status, priority, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)")
            .bind(&id).bind(title).bind(description).bind(&site.address).bind(&site.name).bind(&guards[index].id).bind(status).bind(priority).bind(created_at).bind(created_at + Duration::minutes(40)).execute(pool).await?;
        track(pool, "incidents", &id).await?;
        let classification_id = new_id();
        sqlx::query("INSERT INTO incident_severity_classifications (id, incident_id, predicted_severity, confidence_score, requires_human_review, rationale, feature_scores, supporting_signals, classified_at, created_at, updated_at) VALUES ($1, $2, $3, 0.86, $4, $5, $6, $7, $8, $8, $8)")
            .bind(&classification_id).bind(&id).bind(priority).bind(*priority == "high").bind("Classification reflects reported site impact and required supervisor follow-up.").bind(json!({"impact":0.7,"urgency":0.6})).bind(json!({"site":site.name,"workflow":"incident-review"})).bind(created_at + Duration::minutes(8)).execute(pool).await?;
        track(
            pool,
            "incident_severity_classifications",
            &classification_id,
        )
        .await?;
    }

    let request_specs = [
        (
            "service",
            "pending",
            "high",
            "Request additional radios",
            "Two handheld radios require replacement for the next Tagum night rotation.",
            15_u32,
        ),
        (
            "service",
            "approved",
            "normal",
            "Site lighting follow-up",
            "Request follow-up with the client on the reported north perimeter light.",
            10_u32,
        ),
        (
            "deposit",
            "completed",
            "normal",
            "Document turnover",
            "Turn over completed site incident documents to command records.",
            12_u32,
        ),
        (
            "return",
            "rejected",
            "normal",
            "Early equipment return",
            "Request to return assigned equipment before the scheduled shift end.",
            9_u32,
        ),
        (
            "service",
            "in_progress",
            "urgent",
            "Gate access review",
            "Request coordination with the client for recurring vehicle gate delays.",
            17_u32,
        ),
    ];
    for (index, (request_type, status, priority, subject, reason, day)) in
        request_specs.iter().enumerate()
    {
        let request_id = new_id();
        let created_at = manila_time(*day, 9 + index as u32, 18)?;
        let reviewer = if index % 2 == 0 {
            &supervisor.id
        } else {
            &admin.id
        };
        sqlx::query("INSERT INTO operational_requests (id, request_type, status, requester_id, subject, reason, details, priority, client_site_id, reviewer_id, reviewed_at, decision_reason, fulfilled_by, fulfilled_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)")
            .bind(&request_id).bind(request_type).bind(status).bind(&guards[(index + 9) % guards.len()].id).bind(subject).bind(reason).bind("Created through the operational request workflow.").bind(priority).bind(&site.id).bind(if *status == "pending" { None } else { Some(reviewer) }).bind(if *status == "pending" { None } else { Some(created_at + Duration::hours(2)) }).bind(if *status == "rejected" { Some("The equipment remains required for the assigned shift. Return after supervisor clearance.") } else { None }).bind(if *status == "completed" { Some(&admin.id) } else { None }).bind(if *status == "completed" { Some(created_at + Duration::hours(5)) } else { None }).bind(created_at).bind(created_at + Duration::hours(2)).execute(pool).await?;
        track(pool, "operational_requests", &request_id).await?;
        let event_id = new_id();
        sqlx::query("INSERT INTO operational_request_events (id, request_id, actor_user_id, from_status, to_status, comment, metadata, created_at) VALUES ($1, $2, $3, NULL, 'pending', 'Request submitted for operational review.', $4, $5)")
            .bind(&event_id).bind(&request_id).bind(&guards[(index + 9) % guards.len()].id).bind(json!({"data_origin":"capstone_live_seed","batch_id":BATCH_ID})).bind(created_at).execute(pool).await?;
        track(pool, "operational_request_events", &event_id).await?;
        if *status != "pending" {
            let decision_id = new_id();
            sqlx::query("INSERT INTO operational_request_events (id, request_id, actor_user_id, from_status, to_status, comment, metadata, created_at) VALUES ($1, $2, $3, 'pending', $4, $5, $6, $7)")
                .bind(&decision_id).bind(&request_id).bind(reviewer).bind(status).bind(if *status == "rejected" { "Request rejected with operational explanation." } else { "Request reviewed and routed for action." }).bind(json!({"data_origin":"capstone_live_seed","batch_id":BATCH_ID})).bind(created_at + Duration::hours(2)).execute(pool).await?;
            track(pool, "operational_request_events", &decision_id).await?;
        }
        let notification_id = new_id();
        sqlx::query("INSERT INTO notifications (id, user_id, title, message, type, related_request_id, read, created_at, updated_at) VALUES ($1, $2, $3, $4, 'operational_request', $5, $6, $7, $7)")
            .bind(&notification_id).bind(&guards[(index + 9) % guards.len()].id).bind(if *status == "pending" { "Request received" } else { "Request updated" }).bind(format!("{} is {}.", subject, status)).bind(&request_id).bind(*status != "pending").bind(created_at + Duration::hours(2)).execute(pool).await?;
        track(pool, "notifications", &notification_id).await?;
    }

    for index in 0..6 {
        let ticket_id = new_id();
        let created_at = manila_time(11 + index as u32, 13, 10 + index as u32 * 5)?;
        sqlx::query("INSERT INTO support_tickets (id, guard_id, subject, message, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $6)")
            .bind(&ticket_id).bind(&guards[index].id).bind(["Mobile check-in clarification", "Schedule visibility", "Notification preference", "Site instructions", "Replacement availability", "DTR review"][index]).bind("Submitted through the normal guard support workflow for supervisor follow-up.").bind(if index % 2 == 0 { "open" } else { "resolved" }).bind(created_at).execute(pool).await?;
        track(pool, "support_tickets", &ticket_id).await?;
    }
    Ok(())
}

async fn seed_performance_feedback_and_tracking(
    pool: &PgPool,
    guards: &[SourceGuard],
    sites: &[SourceSite],
    admin: &SeedActor,
    supervisor: &SeedActor,
) -> Result<()> {
    for (index, guard) in guards.iter().enumerate() {
        let merit_id = new_id();
        let late_count: i32 = if index % 9 == 0 {
            2
        } else {
            (index % 3) as i32
        };
        let no_show_count: i32 = if index == 4 || index == 18 { 1 } else { 0 };
        let overall =
            91.0 - (late_count as f64 * 2.1) - (no_show_count as f64 * 7.5) + (index % 5) as f64;
        let average_rating = 4.1 + (index % 8) as f64 / 10.0;
        sqlx::query("INSERT INTO guard_merit_scores (id, guard_id, attendance_score, punctuality_score, client_rating, overall_score, rank, total_shifts_completed, on_time_count, late_count, no_show_count, average_client_rating, evaluation_count, last_calculated_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, 14, $8, $9, $10, $11, 1, $12, $12, $12)")
            .bind(&merit_id).bind(&guard.id).bind(94.0 - no_show_count as f64 * 8.0).bind(95.0 - late_count as f64 * 3.0).bind(average_rating * 20.0).bind(overall).bind(if overall >= 94.0 { "Excellent" } else if overall >= 88.0 { "Good" } else { "For review" }).bind(12_i32 - late_count - no_show_count).bind(late_count).bind(no_show_count).bind(average_rating).bind(manila_time(17, 16, 30)?).execute(pool).await?;
        track(pool, "guard_merit_scores", &merit_id).await?;
        let evaluator = if index % 2 == 0 { supervisor } else { admin };
        let evaluation_id = new_id();
        sqlx::query("INSERT INTO client_evaluations (id, guard_id, shift_id, evaluator_name, evaluator_role, rating, comment, created_at) VALUES ($1, $2, NULL, $3, $4, $5, $6, $7)")
            .bind(&evaluation_id).bind(&guard.id).bind(&evaluator.full_name).bind(&evaluator.role).bind(average_rating).bind("October performance review based on recorded attendance and site conduct.").bind(manila_time(15 + (index % 2) as u32, 14, 20)?).execute(pool).await?;
        track(pool, "client_evaluations", &evaluation_id).await?;
    }

    let comments = [
        "Klaro ang proseso sa mobile check-in atol sa akong gitudlong duty.",
        "Mas sayon sundon ang mga update sa schedule kung una ipakita ang ngalan sa site.",
        "Nakatabang ang mga pahibalo aron mabantayan nako ang kausaban sa duty sa wala pa ang oras sa pag-report.",
        "Kinahanglan magpabilin nga makita ang pinakabag-ong kahimtang sa check-in sa attendance screen bisan hinay ang signal.",
        "Nakatabang ang status sa replacement request kung adunay kauban nga dili makasulod sa duty.",
        "Nakatabang ang mga rekord sa DTR sa pagsusi sa akong nahuman nga mga duty.",
        "Mapuslanon ang mapa, apan kinahanglan og mubo nga pasabot bahin sa pagtugot sa lokasyon.",
        "Nakaabot sayo ang pahinumdom sa duty aron makaandam ko sa akong kagamitan.",
        "Klaro ang mga instruksyon sa site para sa assignment sa Tagum.",
        "Gusto ko og mas klarong timailhan kung na-review na ang usa ka support request.",
        "Maayo ang schedule view sa pagsusi sa adlaw ug gabii nga mga assignment.",
        "Ang mga koreksyon sa attendance kinahanglan magpakita sa rason human sa pag-review sa supervisor.",
        "Nakatabang ang notification inbox kung daghan ang kausaban sa schedule.",
        "Mas klaro unta ang workflow kung adunay mubo nga kumpirmasyon human sa check-out.",
        "Sakto ang konteksto nga gihatag sa replacement recommendation para sa desisyon sa supervisor.",
        "Madumala ra ang mobile form bisan panahon sa pahulay sa patrol.",
        "Nakatabang ang DTR page sa pagtandi sa akong mga oras sa pag-report.",
        "Gusto ko nga makita ang kontak sa client site human makumpirma ang schedule.",
        "Nakatabang ang sistema sa pagkumpirma kung na-record na ba ang akong duty.",
        "Kinahanglan adunay paagi sa pag-filter sa nahuman nga mga request sumala sa petsa.",
    ];
    for (index, comment) in comments.iter().enumerate() {
        let feedback_id = new_id();
        sqlx::query("INSERT INTO feedback (id, user_id, rating, comments, created_at) VALUES ($1, $2, $3, $4, $5)")
            .bind(&feedback_id).bind(&guards[index].id).bind([5_i32, 4, 4, 3, 5, 4, 3, 4, 5, 3][index % 10]).bind(comment).bind(manila_time(8 + (index % 9) as u32, 17, 5 + (index % 10) as u32 * 3)?).execute(pool).await?;
        track(pool, "feedback", &feedback_id).await?;
    }
    for (actor, rating, comment, day) in [
        (admin, 4_i32, "Mapuslanon ang operational summaries sa pag-turnover sa duty. Kinahanglan magpabiling mubo ug klaro ang mga pasabot sa status sa request.", 16_u32),
        (supervisor, 4_i32, "Nakatabang ang impormasyon sa replacement ug mga rekord sa attendance sa pagdumala sa mga assignment sa Tagum.", 17_u32),
    ] {
        let feedback_id = new_id();
        sqlx::query("INSERT INTO feedback (id, user_id, rating, comments, created_at) VALUES ($1, $2, $3, $4, $5)")
            .bind(&feedback_id).bind(&actor.id).bind(rating).bind(comment).bind(manila_time(day, 16, 45)?).execute(pool).await?;
        track(pool, "feedback", &feedback_id).await?;
    }

    for index in 0..10 {
        let guard = &guards[index];
        let site = &sites[index % sites.len()];
        let tracking_id = new_id();
        sqlx::query("INSERT INTO tracking_points (id, entity_type, entity_id, user_id, label, status, latitude, longitude, heading, speed_kph, accuracy_meters, recorded_at, created_by, created_at) VALUES ($1, 'guard', $2, $2, $3, 'active', $4, $5, $6, 0, 8, $7, $8, $7)")
            .bind(&tracking_id).bind(&guard.id).bind(&guard.full_name).bind(site.latitude + index as f64 * 0.00007).bind(site.longitude + index as f64 * 0.00005).bind((index * 31) as f64).bind(manila_time(17, 16, 10 + index as u32 * 2)?).bind(&supervisor.id).execute(pool).await?;
        track(pool, "tracking_points", &tracking_id).await?;
    }
    for index in [4_usize, 18, 27] {
        let prediction_id = new_id();
        sqlx::query("INSERT INTO guard_absence_predictions (id, guard_id, prediction_window_hours, risk_score, risk_level, confidence_score, explanation, contributing_factors, source_snapshot, generated_at, valid_until, created_at, updated_at) VALUES ($1, $2, 24, $3, $4, 0.78, $5, $6, $7, $8, $9, $8, $8)")
            .bind(&prediction_id).bind(&guards[index].id).bind(if index == 4 { 0.76 } else { 0.48 }).bind(if index == 4 { "high" } else { "medium" }).bind(json!({"summary":"Recent attendance pattern requires supervisor review before the next assignment."})).bind(json!(["recent late arrival", "schedule change"])).bind(json!({"completed_shifts":14,"late_count":2})).bind(manila_time(17, 15, 30)?).bind(manila_time(18, 15, 30)?).execute(pool).await?;
        track(pool, "guard_absence_predictions", &prediction_id).await?;
    }
    Ok(())
}

async fn seed_audit_activity(
    pool: &PgPool,
    admin: &SeedActor,
    supervisor: &SeedActor,
) -> Result<()> {
    for index in 0..20 {
        let audit_id = new_id();
        let is_supervisor = index % 2 == 0;
        let created_at = manila_time(
            3 + (index % 15) as u32,
            9 + (index % 6) as u32,
            5 + (index % 10) as u32 * 4,
        )?;
        sqlx::query("INSERT INTO audit_logs (id, actor_user_id, action_key, entity_type, entity_id, result, reason, source_ip, user_agent, metadata, created_at) VALUES ($1, $2, $3, $4, $5, 'success', $6, '10.10.0.15', 'SENTINEL Operations Console', $7, $8)")
            .bind(&audit_id).bind(if is_supervisor { &supervisor.id } else { &admin.id }).bind(if is_supervisor { "SUPERVISOR_SHIFT_REVIEW" } else { "ADMIN_OPERATIONAL_REVIEW" }).bind(if is_supervisor { "attendance" } else { "operational_request" }).bind(format!("capstone-live-activity-{}", index + 1)).bind(if is_supervisor { "Supervisor reviewed an attendance or replacement workflow." } else { "Administrator reviewed an operational request workflow." }).bind(json!({"data_origin":"capstone_live_seed","batch_id":BATCH_ID})).bind(created_at).execute(pool).await?;
        track(pool, "audit_logs", &audit_id).await?;
    }
    Ok(())
}

async fn find_existing_actor(
    pool: &PgPool,
    full_name: &str,
    expected_role: &str,
) -> Result<SeedActor> {
    let row = sqlx::query(
        "SELECT id, full_name, username, role FROM users WHERE UPPER(BTRIM(full_name)) = UPPER($1) AND LOWER(BTRIM(role)) = $2 AND COALESCE(LOWER(BTRIM(status)), 'active') = 'active' LIMIT 1",
    )
    .bind(full_name)
    .bind(expected_role)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow!("Required active {} actor {} was not found", expected_role, full_name))?;

    Ok(SeedActor {
        id: row.try_get("id")?,
        full_name: row.try_get("full_name")?,
        role: row.try_get::<String, _>("role")?.to_ascii_lowercase(),
    })
}

async fn verify_protected_superadmin(pool: &PgPool) -> Result<()> {
    let protected_id = require_env("CAPSTONE_PROTECTED_SUPERADMIN_ID")?;
    let is_protected: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND LOWER(BTRIM(role)) = 'superadmin' AND COALESCE(LOWER(BTRIM(status)), 'active') = 'active')",
    )
    .bind(&protected_id)
    .fetch_one(pool)
    .await?;
    if !is_protected {
        bail!("Protected production Superadmin is missing, inactive, or no longer assigned the superadmin role")
    }
    Ok(())
}

async fn seed(pool: &PgPool) -> Result<()> {
    ensure_ledger(pool).await?;
    reset_batch(pool).await?;
    let guards = read_live_guards(pool).await?;
    let sites = read_live_sites(pool).await?;
    let admin = find_existing_actor(pool, "OSCAR GAGA-A", "admin").await?;
    let supervisor = find_existing_actor(pool, "SENDRICK SOLIS", "supervisor").await?;
    let reference_at =
        DateTime::parse_from_rfc3339(&require_env("CAPSTONE_REFERENCE_DATE")?)?.with_timezone(&Utc);
    sqlx::query("INSERT INTO capstone_seed_batches (batch_id, data_origin, reference_at, status, metadata) VALUES ($1, 'capstone_live_seed', $2, 'running', $3)")
        .bind(BATCH_ID).bind(reference_at).bind(json!({"scope":"Tagum City, Davao del Norte","dateRange":"2026-10-01 through 2026-10-17","source":"existing live master data","actors":{"admin":admin.id,"supervisor":supervisor.id}})).execute(pool).await?;

    seed_shift_activity(pool, &guards, &sites, &admin, &supervisor).await?;
    seed_operational_records(pool, &guards, &sites, &admin, &supervisor).await?;
    seed_performance_feedback_and_tracking(pool, &guards, &sites, &admin, &supervisor).await?;
    seed_audit_activity(pool, &admin, &supervisor).await?;
    sqlx::query("UPDATE capstone_seed_batches SET status = 'complete', completed_at = CURRENT_TIMESTAMP WHERE batch_id = $1")
        .bind(BATCH_ID).execute(pool).await?;
    Ok(())
}

async fn status(pool: &PgPool) -> Result<()> {
    ensure_ledger(pool).await?;
    let rows = sqlx::query(
        "SELECT table_name, COUNT(*)::BIGINT AS count FROM capstone_seed_records WHERE batch_id = $1 GROUP BY table_name ORDER BY table_name",
    )
    .bind(BATCH_ID)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
        println!("No {} dataset is present.", BATCH_ID);
        return Ok(());
    }
    for row in rows {
        println!(
            "{}={}",
            row.try_get::<String, _>("table_name")?,
            row.try_get::<i64, _>("count")?
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let command = env::args().nth(1).unwrap_or_else(|| "status".to_string());
    let result = async {
        let target_url = verify_live_target(&command)?;
        let target_pool = connect(&target_url, "explicit live target").await?;
        verify_protected_superadmin(&target_pool).await?;
        match command.as_str() {
            "seed" => {
                seed(&target_pool).await?;
                status(&target_pool).await?;
            }
            "reset" => {
                ensure_ledger(&target_pool).await?;
                reset_batch(&target_pool).await?;
                println!("Reset only batch {}.", BATCH_ID);
            }
            "status" => status(&target_pool).await?,
            _ => unreachable!(),
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(error) = result {
        eprintln!("Capstone dataset command failed: {error:#}");
        process::exit(1);
    }
}
