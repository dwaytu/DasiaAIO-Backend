use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env, process,
};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Duration, FixedOffset, TimeZone, Timelike, Utc};
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

const BATCH_ID: &str = "capstone-live-october-2026";
const ENRICHMENT_BATCH_ID: &str = "capstone-live-october-2026-enrichment-v1";
const AUDIT_ACTIVITY_BATCH_ID: &str = "capstone-live-october-2026-audit-activity-v1";
const REQUIRED_CONFIRMATION: &str = "LIVE_CAPSTONE_DATASET_CONFIRMED";
const MANILA_OFFSET_SECONDS: i32 = 8 * 60 * 60;
const DATA_ORIGIN: &str = "capstone_presentation_seed";
const ENRICHMENT_DATA_ORIGIN: &str = "capstone_presentation_enrichment";
const AUDIT_ACTIVITY_DATA_ORIGIN: &str = "capstone_presentation_synthetic_audit_activity";
const PRIMARY_ROSTER_SIZE: usize = 5;
const MAX_PARTICIPATING_GUARDS: usize = 55;
const MIN_REST_HOURS: i64 = 8;
const HISTORY_LAST_DAY: u32 = 16;
const PLANNED_DAY: u32 = 17;

#[derive(Clone)]
struct SourceGuard {
    id: String,
    full_name: String,
    guard_code: Option<String>,
    address: Option<String>,
    currently_available: bool,
}

#[derive(Clone)]
struct SourceSite {
    id: String,
    name: String,
    address: Option<String>,
    latitude: f64,
    longitude: f64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShiftRotation {
    Day,
    Evening,
    Night,
}

impl ShiftRotation {
    const ALL: [Self; 3] = [Self::Day, Self::Evening, Self::Night];

    fn label(self) -> &'static str {
        match self {
            Self::Day => "day",
            Self::Evening => "evening",
            Self::Night => "night",
        }
    }

    fn start(self, day: u32) -> Result<DateTime<Utc>> {
        match self {
            Self::Day => manila_time(day, 7, 0),
            Self::Evening => manila_time(day, 15, 0),
            Self::Night => manila_time(day, 23, 0),
        }
    }

    fn from_start(start: DateTime<Utc>) -> Result<Self> {
        let offset = FixedOffset::east_opt(MANILA_OFFSET_SECONDS)
            .ok_or_else(|| anyhow!("Invalid Manila offset"))?;
        match start.with_timezone(&offset).hour() {
            7 => Ok(Self::Day),
            15 => Ok(Self::Evening),
            23 => Ok(Self::Night),
            hour => bail!("Unsupported capstone shift start hour {hour}"),
        }
    }
}

#[derive(Clone, Debug)]
struct PlannedShift {
    site_index: usize,
    guard_index: usize,
    day: u32,
    rotation: ShiftRotation,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    is_cross_site: bool,
}

#[derive(Clone, Default)]
struct GuardPerformance {
    assigned: i32,
    completed: i32,
    on_time: i32,
    late: i32,
    absent: i32,
    replacements: i32,
}

#[derive(Clone)]
struct CapstoneShift {
    id: String,
    guard_id: String,
    site_id: String,
    site_name: String,
    latitude: f64,
    longitude: f64,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

#[derive(Default)]
struct EnrichmentMetrics {
    incidents: usize,
    incident_classifications: usize,
    operational_requests: usize,
    operational_request_events: usize,
    notifications: usize,
    readiness: BTreeMap<String, usize>,
    absence_predictions: usize,
    support_tickets: BTreeMap<String, usize>,
    client_evaluations: usize,
    tracking_points: usize,
    feedback: BTreeMap<i32, usize>,
    bisaya_guard_feedback: usize,
}

#[derive(Clone)]
struct WorkflowContext {
    id: String,
    guard_id: String,
    shift_id: String,
    occurred_at: DateTime<Utc>,
}

#[derive(Clone)]
struct SyntheticAuditActor {
    id: String,
    full_name: String,
    role: String,
    guard_code: Option<String>,
}

#[derive(Clone)]
struct AuditShiftContext {
    shift_id: String,
    guard_id: String,
    attendance_id: String,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

#[derive(Clone)]
struct AuditReference {
    id: String,
    actor_id: String,
    occurred_at: DateTime<Utc>,
    label: String,
}

struct SyntheticAuditEvent {
    actor_id: String,
    action_key: &'static str,
    entity_type: &'static str,
    entity_id: String,
    occurred_at: DateTime<Utc>,
    detail: String,
    related_label: String,
}

#[derive(Default)]
struct AuditActivityMetrics {
    guard_login_logout: usize,
    guard_operational: usize,
    supervisor_actions: usize,
    admin_actions: usize,
}

#[derive(Default)]
struct SeedMetrics {
    day_shifts: usize,
    evening_shifts: usize,
    night_shifts: usize,
    planned_october_17: usize,
    late_arrivals: usize,
    absences: usize,
    replacements: usize,
    cross_site_assignments: usize,
    guard_performance: HashMap<String, GuardPerformance>,
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
    let target_environment = require_env("CAPSTONE_TARGET_ENVIRONMENT")?.to_ascii_lowercase();
    if !matches!(
        target_environment.as_str(),
        "production" | "capstone_presentation"
    ) {
        bail!("CAPSTONE_TARGET_ENVIRONMENT must be production or capstone_presentation")
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

    if !matches!(
        command,
        "seed"
            | "reset"
            | "status"
            | "preflight"
            | "validate"
            | "enrich"
            | "enrich-preflight"
            | "audit-preflight"
            | "seed-audit-activity"
    ) {
        bail!("Usage: cargo run --bin capstone-dataset -- <seed|reset|status|preflight|validate|enrich|enrich-preflight|audit-preflight|seed-audit-activity>")
    }
    if matches!(command, "audit-preflight" | "seed-audit-activity") {
        if target_environment != "capstone_presentation" {
            bail!("Synthetic audit activity requires CAPSTONE_TARGET_ENVIRONMENT=capstone_presentation")
        }
        if env::var("CAPSTONE_PRESENTATION_ENVIRONMENT").as_deref() != Ok("true") {
            bail!("Synthetic audit activity requires CAPSTONE_PRESENTATION_ENVIRONMENT=true")
        }
        if env::var("CAPSTONE_ALLOW_SYNTHETIC_AUDIT_HISTORY").as_deref() != Ok("true") {
            bail!("Synthetic audit activity requires CAPSTONE_ALLOW_SYNTHETIC_AUDIT_HISTORY=true")
        }
    }
    Ok(target_url)
}

fn verify_backup_confirmation(command: &str) -> Result<()> {
    if !matches!(command, "seed" | "reset" | "enrich" | "seed-audit-activity") {
        return Ok(());
    }

    let value = require_env("CAPSTONE_BACKUP_VERIFIED_AT")?;
    DateTime::parse_from_rfc3339(&value)
        .with_context(|| "CAPSTONE_BACKUP_VERIFIED_AT must be an RFC 3339 timestamp")?;
    Ok(())
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
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS capstone_seed_actors (
            batch_id VARCHAR(80) NOT NULL REFERENCES capstone_seed_batches(batch_id) ON DELETE CASCADE,
            user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
            role VARCHAR(32) NOT NULL,
            registered_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (batch_id, user_id)
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn track_batch(
    pool: &PgPool,
    batch_id: &str,
    table_name: &str,
    record_id: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO capstone_seed_records (batch_id, table_name, record_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(batch_id)
    .bind(table_name)
    .bind(record_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn track(pool: &PgPool, table_name: &str, record_id: &str) -> Result<()> {
    track_batch(pool, BATCH_ID, table_name, record_id).await
}

async fn track_enrichment(pool: &PgPool, table_name: &str, record_id: &str) -> Result<()> {
    track_batch(pool, ENRICHMENT_BATCH_ID, table_name, record_id).await
}

async fn reset_tracked_batch(pool: &PgPool, batch_id: &str) -> Result<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM capstone_seed_batches WHERE batch_id = $1)",
    )
    .bind(batch_id)
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
        sqlx::query(query).bind(batch_id).execute(pool).await?;
        tracing::debug!(table_name, batch_id, "Removed presentation seed records");
    }
    sqlx::query("DELETE FROM capstone_seed_batches WHERE batch_id = $1")
        .bind(batch_id)
        .execute(pool)
        .await?;
    Ok(())
}

async fn reset_batch(pool: &PgPool) -> Result<()> {
    reset_tracked_batch(pool, AUDIT_ACTIVITY_BATCH_ID).await?;
    reset_tracked_batch(pool, ENRICHMENT_BATCH_ID).await?;
    reset_tracked_batch(pool, BATCH_ID).await
}

async fn read_live_guards(pool: &PgPool) -> Result<Vec<SourceGuard>> {
    let rows = sqlx::query(
        r#"
        SELECT users.id,
               users.full_name,
               users.guard_code,
               users.address,
               COALESCE(guard_availability.available, true) AS currently_available
        FROM users
        LEFT JOIN guard_availability ON guard_availability.guard_id = users.id
        WHERE LOWER(BTRIM(role)) = 'guard'
          AND COALESCE(LOWER(BTRIM(status)), 'active') = 'active'
          AND NOT EXISTS (
              SELECT 1
              FROM guard_merit_scores
              WHERE guard_merit_scores.guard_id = users.id
                AND NOT EXISTS (
                    SELECT 1
                    FROM capstone_seed_records
                    WHERE capstone_seed_records.batch_id = $1
                      AND capstone_seed_records.table_name = 'guard_merit_scores'
                      AND capstone_seed_records.record_id = guard_merit_scores.id
                )
          )
        ORDER BY guard_code NULLS LAST, full_name
        LIMIT $2
        "#,
    )
    .bind(BATCH_ID)
    .bind(MAX_PARTICIPATING_GUARDS as i64)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(SourceGuard {
                id: row.try_get("id")?,
                full_name: row.try_get("full_name")?,
                guard_code: row.try_get("guard_code")?,
                address: row.try_get("address")?,
                currently_available: row.try_get("currently_available")?,
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

async fn read_assignment_history(pool: &PgPool) -> Result<HashMap<(String, String), i64>> {
    let rows = sqlx::query(
        "SELECT shifts.guard_id, shifts.client_site, COUNT(*)::BIGINT AS assignment_count FROM shifts WHERE NOT EXISTS (SELECT 1 FROM capstone_seed_records WHERE capstone_seed_records.table_name = 'shifts' AND capstone_seed_records.record_id = shifts.id) GROUP BY shifts.guard_id, shifts.client_site",
    )
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            Ok((
                (row.try_get("guard_id")?, row.try_get("client_site")?),
                row.try_get("assignment_count")?,
            ))
        })
        .collect()
}

fn guard_has_rest(
    guard_index: usize,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    planned: &[PlannedShift],
) -> bool {
    planned
        .iter()
        .filter(|assignment| assignment.guard_index == guard_index)
        .all(|assignment| {
            if start < assignment.end && end > assignment.start {
                return false;
            }
            if assignment.end <= start {
                return start - assignment.end >= Duration::hours(MIN_REST_HOURS);
            }
            if end <= assignment.start {
                return assignment.start - end >= Duration::hours(MIN_REST_HOURS);
            }
            true
        })
}

fn assignment_count(guard_index: usize, planned: &[PlannedShift]) -> usize {
    planned
        .iter()
        .filter(|assignment| assignment.guard_index == guard_index)
        .count()
}

fn build_primary_rosters(
    guards: &[SourceGuard],
    sites: &[SourceSite],
    history: &HashMap<(String, String), i64>,
) -> Result<Vec<Vec<usize>>> {
    let required_guards = sites.len() * PRIMARY_ROSTER_SIZE;
    if required_guards > MAX_PARTICIPATING_GUARDS {
        bail!(
            "{} Tagum sites require {} primary guards, exceeding the approved {}-guard presentation pool",
            sites.len(), required_guards, MAX_PARTICIPATING_GUARDS
        )
    }

    let available_guards = guards
        .iter()
        .enumerate()
        .filter_map(|(index, guard)| guard.currently_available.then_some(index))
        .collect::<Vec<_>>();
    if available_guards.len() < required_guards {
        bail!(
            "Live database has only {} currently available eligible guards; {} are required for stable five-guard site rosters",
            available_guards.len(), required_guards
        )
    }

    let mut unassigned = available_guards;
    let mut rosters = Vec::with_capacity(sites.len());
    for site in sites {
        unassigned.sort_by(|left, right| {
            let left_guard = &guards[*left];
            let right_guard = &guards[*right];
            let left_history = history
                .get(&(left_guard.id.clone(), site.name.clone()))
                .copied()
                .unwrap_or_default();
            let right_history = history
                .get(&(right_guard.id.clone(), site.name.clone()))
                .copied()
                .unwrap_or_default();
            right_history
                .cmp(&left_history)
                .then_with(|| left_guard.guard_code.cmp(&right_guard.guard_code))
                .then_with(|| left_guard.full_name.cmp(&right_guard.full_name))
        });
        rosters.push(unassigned.drain(..PRIMARY_ROSTER_SIZE).collect());
    }
    Ok(rosters)
}

fn select_guard_for_slot(
    candidates: &[usize],
    site_index: usize,
    day: u32,
    rotation_index: usize,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    planned: &[PlannedShift],
) -> Option<usize> {
    let mut eligible = candidates
        .iter()
        .copied()
        .filter(|guard_index| guard_has_rest(*guard_index, start, end, planned))
        .collect::<Vec<_>>();
    let preferred_offset = (day as usize + rotation_index + site_index) % candidates.len();
    eligible.sort_by_key(|guard_index| {
        let roster_position = candidates
            .iter()
            .position(|candidate| candidate == guard_index)
            .unwrap_or_default();
        (
            assignment_count(*guard_index, planned),
            (roster_position + candidates.len() - preferred_offset) % candidates.len(),
            *guard_index,
        )
    });
    eligible.into_iter().next()
}

fn plan_shift_coverage(
    guards: &[SourceGuard],
    sites: &[SourceSite],
    rosters: &[Vec<usize>],
) -> Result<Vec<PlannedShift>> {
    let all_available = guards
        .iter()
        .enumerate()
        .filter_map(|(index, guard)| guard.currently_available.then_some(index))
        .collect::<Vec<_>>();
    let mut planned = Vec::with_capacity(sites.len() * ShiftRotation::ALL.len() * 17);

    for day in 1..=PLANNED_DAY {
        for (site_index, roster) in rosters.iter().enumerate() {
            for (rotation_index, rotation) in ShiftRotation::ALL.iter().enumerate() {
                let start = rotation.start(day)?;
                let end = start + Duration::hours(8);
                let primary_guard = select_guard_for_slot(
                    roster,
                    site_index,
                    day,
                    rotation_index,
                    start,
                    end,
                    &planned,
                );
                let (guard_index, is_cross_site) = match primary_guard {
                    Some(guard_index) => (guard_index, false),
                    None => (
                        select_guard_for_slot(
                            &all_available,
                            site_index,
                            day,
                            rotation_index,
                            start,
                            end,
                            &planned,
                        )
                        .ok_or_else(|| {
                            anyhow!(
                                "No rested available guard can cover {} shift at {} on October {}",
                                rotation.label(),
                                sites[site_index].name,
                                day
                            )
                        })?,
                        true,
                    ),
                };
                planned.push(PlannedShift {
                    site_index,
                    guard_index,
                    day,
                    rotation: *rotation,
                    start,
                    end,
                    is_cross_site,
                });
            }
        }
    }
    Ok(planned)
}

fn replacement_candidate(
    absent_guard_index: usize,
    site_index: usize,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    rosters: &[Vec<usize>],
    guards: &[SourceGuard],
    planned: &[PlannedShift],
) -> Option<(usize, bool)> {
    let mut same_site = rosters[site_index]
        .iter()
        .copied()
        .filter(|candidate| {
            *candidate != absent_guard_index && guards[*candidate].currently_available
        })
        .collect::<Vec<_>>();
    same_site.sort_by_key(|candidate| assignment_count(*candidate, planned));
    if let Some(candidate) = same_site
        .into_iter()
        .find(|candidate| guard_has_rest(*candidate, start, end, planned))
    {
        return Some((candidate, false));
    }

    let mut fallback = guards
        .iter()
        .enumerate()
        .filter_map(|(index, guard)| {
            (index != absent_guard_index && guard.currently_available).then_some(index)
        })
        .collect::<Vec<_>>();
    fallback.sort_by_key(|candidate| assignment_count(*candidate, planned));
    fallback
        .into_iter()
        .find(|candidate| guard_has_rest(*candidate, start, end, planned))
        .map(|candidate| (candidate, true))
}

fn is_absence_scenario(assignment: &PlannedShift) -> bool {
    matches!(
        (assignment.day, assignment.site_index, assignment.rotation),
        (7, 0, ShiftRotation::Day)
            | (12, 3, ShiftRotation::Evening)
            | (15, 6, ShiftRotation::Night)
    )
}

async fn seed_shift_activity(
    pool: &PgPool,
    guards: &[SourceGuard],
    sites: &[SourceSite],
    rosters: &[Vec<usize>],
    planned: &[PlannedShift],
) -> Result<SeedMetrics> {
    let mut metrics = SeedMetrics::default();

    for (index, assignment) in planned.iter().enumerate() {
        let guard = &guards[assignment.guard_index];
        let site = &sites[assignment.site_index];
        let historical = assignment.day <= HISTORY_LAST_DAY;
        let absence = historical && is_absence_scenario(assignment);
        let shift_id = new_id();
        let created_at = assignment.start - Duration::days(6);
        let status = if absence {
            "absent"
        } else if historical {
            "completed"
        } else {
            "scheduled"
        };
        let replacement_status = if absence { "accepted" } else { "not_needed" };

        sqlx::query(
            r#"INSERT INTO shifts (id, guard_id, start_time, end_time, client_site, status, grace_period_minutes, replacement_status, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, 15, $7, $8, $8)"#,
        )
        .bind(&shift_id)
        .bind(&guard.id)
        .bind(assignment.start)
        .bind(assignment.end)
        .bind(&site.name)
        .bind(status)
        .bind(replacement_status)
        .bind(created_at)
        .execute(pool)
        .await?;
        track(pool, "shifts", &shift_id).await?;

        match assignment.rotation {
            ShiftRotation::Day => metrics.day_shifts += 1,
            ShiftRotation::Evening => metrics.evening_shifts += 1,
            ShiftRotation::Night => metrics.night_shifts += 1,
        }
        metrics.cross_site_assignments += if assignment.is_cross_site { 1 } else { 0 };
        if !historical {
            metrics.planned_october_17 += 1;
            continue;
        }

        if absence {
            metrics.absences += 1;
            let performance = metrics
                .guard_performance
                .entry(guard.id.clone())
                .or_default();
            performance.assigned += 1;
            performance.absent += 1;
            let punctuality_id = new_id();
            sqlx::query(
                "INSERT INTO punctuality_records (id, guard_id, shift_id, scheduled_start_time, actual_check_in_time, minutes_late, is_on_time, status, created_at) VALUES ($1, $2, $3, $4, NULL, NULL, false, 'absent', $5)",
            )
            .bind(&punctuality_id)
            .bind(&guard.id)
            .bind(&shift_id)
            .bind(assignment.start)
            .bind(assignment.start + Duration::minutes(20))
            .execute(pool)
            .await?;
            track(pool, "punctuality_records", &punctuality_id).await?;

            let (replacement_index, cross_site) = replacement_candidate(
                assignment.guard_index,
                assignment.site_index,
                assignment.start,
                assignment.end,
                rosters,
                guards,
                planned,
            )
            .ok_or_else(|| {
                anyhow!(
                    "No rested relief guard is available for {} on October {}",
                    site.name,
                    assignment.day
                )
            })?;
            let replacement_guard = &guards[replacement_index];
            let replacement_shift_id = new_id();
            sqlx::query(
                r#"INSERT INTO shifts (id, guard_id, start_time, end_time, client_site, status, grace_period_minutes, replacement_status, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, $5, 'completed', 15, 'accepted', $6, $6)"#,
            )
            .bind(&replacement_shift_id)
            .bind(&replacement_guard.id)
            .bind(assignment.start)
            .bind(assignment.end)
            .bind(&site.name)
            .bind(created_at)
            .execute(pool)
            .await?;
            track(pool, "shifts", &replacement_shift_id).await?;

            let recommendation_id = new_id();
            let rationale = if cross_site {
                "Available Tagum relief guard with no conflicting shift and sufficient rest."
            } else {
                "Regular relief guard for this client site, currently off duty with no conflicting shift."
            };
            sqlx::query(
                r#"INSERT INTO smart_guard_replacements (id, shift_id, absent_guard_id, recommended_guard_id, recommendation_rank, compatibility_score, confidence_score, rationale, scoring_breakdown, candidate_pool, recommendation_status, generated_at, expires_at, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, 1, 0.93, 0.89, $5, $6, $7, 'accepted', $8, $9, $8, $8)"#,
            )
            .bind(&recommendation_id)
            .bind(&shift_id)
            .bind(&guard.id)
            .bind(&replacement_guard.id)
            .bind(rationale)
            .bind(json!({"availability": "confirmed", "rest_hours": MIN_REST_HOURS, "site_affinity": if cross_site {"Tagum relief"} else {"primary roster"}}))
            .bind(json!([{"guardId": replacement_guard.id, "rank": 1, "selection": if cross_site {"Tagum relief"} else {"same-site relief"}}]))
            .bind(assignment.start + Duration::minutes(18))
            .bind(assignment.start + Duration::minutes(40))
            .execute(pool)
            .await?;
            track(pool, "smart_guard_replacements", &recommendation_id).await?;

            record_completed_attendance(
                pool,
                replacement_guard,
                &replacement_shift_id,
                assignment.start,
                assignment.end,
                index + 11,
                false,
                &mut metrics,
                true,
            )
            .await?;
            metrics.replacements += 1;
            metrics.cross_site_assignments += if cross_site { 1 } else { 0 };
            continue;
        }

        let late = (index + assignment.day as usize) % 29 == 0;
        record_completed_attendance(
            pool,
            guard,
            &shift_id,
            assignment.start,
            assignment.end,
            index,
            late,
            &mut metrics,
            false,
        )
        .await?;
    }
    Ok(metrics)
}

async fn record_completed_attendance(
    pool: &PgPool,
    guard: &SourceGuard,
    shift_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    sequence: usize,
    late: bool,
    metrics: &mut SeedMetrics,
    replacement: bool,
) -> Result<()> {
    let early_offsets = [-13_i64, -8, -4, -1, 2, 4];
    let check_in = if late {
        start + Duration::minutes(17 + (sequence % 9) as i64)
    } else {
        start + Duration::minutes(early_offsets[sequence % early_offsets.len()])
    };
    let check_out = end + Duration::minutes(2 + (sequence % 11) as i64);
    let attendance_id = new_id();
    sqlx::query("INSERT INTO attendance (id, guard_id, shift_id, check_in_time, check_out_time, status, check_in_source, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, 'completed', $6, $4, $5)")
        .bind(&attendance_id)
        .bind(&guard.id)
        .bind(shift_id)
        .bind(check_in)
        .bind(check_out)
        .bind(if sequence % 3 == 0 { "mobile" } else { "manual" })
        .execute(pool)
        .await?;
    track(pool, "attendance", &attendance_id).await?;

    let punctuality_id = new_id();
    sqlx::query("INSERT INTO punctuality_records (id, guard_id, shift_id, scheduled_start_time, actual_check_in_time, minutes_late, is_on_time, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $5)")
        .bind(&punctuality_id)
        .bind(&guard.id)
        .bind(shift_id)
        .bind(start)
        .bind(check_in)
        .bind(if late { Some((check_in - start).num_minutes() as i32) } else { Some(0) })
        .bind(!late)
        .bind(if late { "late" } else { "present" })
        .execute(pool)
        .await?;
    track(pool, "punctuality_records", &punctuality_id).await?;

    let performance = metrics
        .guard_performance
        .entry(guard.id.clone())
        .or_default();
    performance.assigned += 1;
    performance.completed += 1;
    if late {
        metrics.late_arrivals += 1;
        performance.late += 1;
    } else {
        performance.on_time += 1;
    }
    if replacement {
        performance.replacements += 1;
    }
    Ok(())
}

async fn seed_derived_performance(
    pool: &PgPool,
    guards: &[SourceGuard],
    metrics: &SeedMetrics,
) -> Result<()> {
    let calculated_at = Utc::now();
    for guard in guards {
        let performance = metrics
            .guard_performance
            .get(&guard.id)
            .cloned()
            .unwrap_or_default();
        if performance.assigned == 0 {
            continue;
        }
        let attendance_score = (performance.completed as f64 / performance.assigned as f64) * 100.0;
        let reported_count = performance.on_time + performance.late;
        let punctuality_score = if reported_count == 0 {
            0.0
        } else {
            (performance.on_time as f64 / reported_count as f64) * 100.0
        };
        let overall_score = attendance_score * 0.65 + punctuality_score * 0.35;
        let rank = if overall_score >= 95.0 {
            "Excellent"
        } else if overall_score >= 85.0 {
            "Good"
        } else {
            "For review"
        };
        let merit_id = new_id();
        sqlx::query("INSERT INTO guard_merit_scores (id, guard_id, attendance_score, punctuality_score, client_rating, overall_score, rank, total_shifts_completed, on_time_count, late_count, no_show_count, average_client_rating, evaluation_count, last_calculated_at, created_at, updated_at) VALUES ($1, $2, $3, $4, 0, $5, $6, $7, $8, $9, $10, 0, 0, $11, $11, $11)")
            .bind(&merit_id)
            .bind(&guard.id)
            .bind(attendance_score)
            .bind(punctuality_score)
            .bind(overall_score)
            .bind(rank)
            .bind(performance.completed)
            .bind(performance.on_time)
            .bind(performance.late)
            .bind(performance.absent)
            .bind(calculated_at)
            .execute(pool)
            .await?;
        track(pool, "guard_merit_scores", &merit_id).await?;
    }
    Ok(())
}

async fn read_completed_capstone_shifts(pool: &PgPool) -> Result<Vec<CapstoneShift>> {
    let cutoff = manila_time(PLANNED_DAY, 0, 0)?;
    let rows = sqlx::query(
        r#"
        SELECT s.id, s.guard_id, cs.id AS site_id, s.client_site AS site_name,
               cs.latitude, cs.longitude, s.start_time, s.end_time
        FROM shifts s
        JOIN capstone_seed_records csr
          ON csr.batch_id = $1 AND csr.table_name = 'shifts' AND csr.record_id = s.id
        JOIN attendance a ON a.shift_id = s.id AND a.status = 'completed'
        JOIN client_sites cs ON cs.name = s.client_site
        WHERE s.status = 'completed'
          -- October 16 night duty ends on October 17 at 07:00, but was
          -- performed before the reference-day cutoff and has valid attendance.
          AND s.start_time < $2
        ORDER BY s.start_time, s.client_site, s.guard_id
        "#,
    )
    .bind(BATCH_ID)
    .bind(cutoff)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            Ok(CapstoneShift {
                id: row.try_get("id")?,
                guard_id: row.try_get("guard_id")?,
                site_id: row.try_get("site_id")?,
                site_name: row.try_get("site_name")?,
                latitude: row.try_get("latitude")?,
                longitude: row.try_get("longitude")?,
                start: row.try_get("start_time")?,
                end: row.try_get("end_time")?,
            })
        })
        .collect()
}

async fn verify_enrichment_schema(pool: &PgPool) -> Result<()> {
    let requirements = [
        ("support_tickets", "guard_id"),
        ("support_tickets", "subject"),
        ("support_tickets", "message"),
        ("notifications", "related_request_id"),
        ("notifications", "related_shift_id"),
    ];
    for (table_name, column_name) in requirements {
        let present: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2)",
        )
        .bind(table_name)
        .bind(column_name)
        .fetch_one(pool)
        .await?;
        if !present {
            bail!("Enrichment requires public.{table_name}.{column_name}; production schema does not provide it")
        }
    }
    Ok(())
}

async fn ensure_enrichment_ready(pool: &PgPool) -> Result<Vec<CapstoneShift>> {
    let base_status: Option<String> =
        sqlx::query_scalar("SELECT status FROM capstone_seed_batches WHERE batch_id = $1")
            .bind(BATCH_ID)
            .fetch_optional(pool)
            .await?;
    if base_status.as_deref() != Some("complete") {
        bail!("The validated base capstone schedule is not complete; enrichment will not run")
    }
    verify_enrichment_schema(pool).await?;
    validate_schedule_integrity(pool).await?;
    let shifts = read_completed_capstone_shifts(pool).await?;
    if shifts.len() != 528 {
        bail!(
            "Expected 528 completed capstone shifts with attendance before enrichment, found {}",
            shifts.len()
        )
    }
    Ok(shifts)
}

async fn read_synthetic_audit_actors(
    pool: &PgPool,
) -> Result<(
    Vec<SyntheticAuditActor>,
    SyntheticAuditActor,
    SyntheticAuditActor,
)> {
    let guard_rows = sqlx::query(
        r#"
        SELECT DISTINCT u.id, u.full_name, u.role, u.guard_code
        FROM users u
        JOIN shifts s ON s.guard_id = u.id
        JOIN capstone_seed_records csr
          ON csr.batch_id = $1 AND csr.table_name = 'shifts' AND csr.record_id = s.id
        WHERE LOWER(BTRIM(u.role)) = 'guard'
          AND s.status = 'completed'
        ORDER BY u.id
        "#,
    )
    .bind(BATCH_ID)
    .fetch_all(pool)
    .await?;
    let guards = guard_rows
        .into_iter()
        .map(|row| {
            Ok(SyntheticAuditActor {
                id: row.try_get("id")?,
                full_name: row.try_get("full_name")?,
                role: row.try_get::<String, _>("role")?.to_ascii_lowercase(),
                guard_code: row.try_get("guard_code")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    if guards.len() != MAX_PARTICIPATING_GUARDS {
        bail!(
            "Synthetic audit activity requires exactly {} capstone guards, found {}",
            MAX_PARTICIPATING_GUARDS,
            guards.len()
        )
    }

    async fn role_actor(pool: &PgPool, role: &str) -> Result<SyntheticAuditActor> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT u.id, u.full_name, u.role, u.guard_code
            FROM users u
            JOIN feedback f ON f.user_id = u.id
            JOIN capstone_seed_records csr
              ON csr.batch_id = $1 AND csr.table_name = 'feedback' AND csr.record_id = f.id
            WHERE LOWER(BTRIM(u.role)) = $2
            ORDER BY u.id
            "#,
        )
        .bind(ENRICHMENT_BATCH_ID)
        .bind(role)
        .fetch_all(pool)
        .await?;
        if rows.len() != 1 {
            bail!(
                "Synthetic audit activity requires exactly one ledger-tracked {} account, found {}",
                role,
                rows.len()
            )
        }
        let row = rows
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Synthetic audit actor query returned no {role} account"))?;
        Ok(SyntheticAuditActor {
            id: row.try_get("id")?,
            full_name: row.try_get("full_name")?,
            role: row.try_get::<String, _>("role")?.to_ascii_lowercase(),
            guard_code: row.try_get("guard_code")?,
        })
    }

    Ok((
        guards,
        role_actor(pool, "supervisor").await?,
        role_actor(pool, "admin").await?,
    ))
}

async fn read_audit_shift_contexts(pool: &PgPool) -> Result<Vec<AuditShiftContext>> {
    let cutoff = manila_time(PLANNED_DAY, 0, 0)?;
    let rows = sqlx::query(
        r#"
        SELECT s.id AS shift_id, s.guard_id, a.id AS attendance_id, s.start_time, s.end_time
        FROM shifts s
        JOIN attendance a ON a.shift_id = s.id AND a.status = 'completed'
        JOIN capstone_seed_records csr
          ON csr.batch_id = $1 AND csr.table_name = 'shifts' AND csr.record_id = s.id
        WHERE s.status = 'completed' AND s.start_time < $2
        ORDER BY s.guard_id, s.start_time, s.id
        "#,
    )
    .bind(BATCH_ID)
    .bind(cutoff)
    .fetch_all(pool)
    .await?;
    let contexts = rows
        .into_iter()
        .map(|row| {
            Ok(AuditShiftContext {
                shift_id: row.try_get("shift_id")?,
                guard_id: row.try_get("guard_id")?,
                attendance_id: row.try_get("attendance_id")?,
                start: row.try_get("start_time")?,
                end: row.try_get("end_time")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    if contexts.len() != 528 {
        bail!(
            "Synthetic audit activity requires 528 completed capstone shifts, found {}",
            contexts.len()
        )
    }
    Ok(contexts)
}

async fn read_audit_references(
    pool: &PgPool,
    batch_id: &str,
    table_name: &str,
    sql: &str,
) -> Result<Vec<AuditReference>> {
    let rows = sqlx::query(sql).bind(batch_id).fetch_all(pool).await?;
    let references = rows
        .into_iter()
        .map(|row| {
            Ok(AuditReference {
                id: row.try_get("id")?,
                actor_id: row.try_get("actor_id")?,
                occurred_at: row.try_get("occurred_at")?,
                label: row.try_get("label")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    if references.is_empty() {
        bail!("Synthetic audit activity requires ledger-tracked {table_name}")
    }
    Ok(references)
}

fn synthetic_audit_actions() -> &'static [&'static str] {
    &[
        "AUTH_LOGIN_ATTEMPT",
        "AUTH_LOGOUT",
        "GUARD_DASHBOARD_VIEWED",
        "SHIFT_SCHEDULE_VIEWED",
        "DTR_RECORD_VIEWED",
        "ATTENDANCE_HISTORY_VIEWED",
        "NOTIFICATION_VIEWED",
        "SHIFT_REPLACEMENT_STATUS_VIEWED",
        "SHIFT_REPLACEMENT_ACKNOWLEDGED",
        "OPERATIONAL_REQUEST_SUBMITTED",
        "OPERATIONAL_REQUEST_VIEWED",
        "INCIDENT_REPORT_OPENED",
        "INCIDENT_REPORT_ACKNOWLEDGED",
        "FEEDBACK_PAGE_VIEWED",
        "FEEDBACK_SUBMITTED",
        "SUPERVISOR_ATTENDANCE_EXCEPTION_REVIEWED",
        "SUPERVISOR_OPERATIONAL_REQUEST_REVIEWED",
        "SUPERVISOR_INCIDENT_REVIEWED",
        "SUPERVISOR_RELIEF_COVERAGE_APPROVED",
        "ADMIN_ANALYTICS_VIEWED",
        "ADMIN_DTR_SUMMARY_REVIEWED",
        "ADMIN_FEEDBACK_SUMMARY_REVIEWED",
        "ADMIN_SUPPORT_TICKET_REVIEWED",
        "ADMIN_REPORT_VIEWED",
    ]
}

async fn register_synthetic_audit_actor(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &SyntheticAuditActor,
    protected_superadmin_id: &str,
) -> Result<()> {
    if actor.id == protected_superadmin_id || actor.role == "superadmin" {
        bail!("Protected Superadmin accounts cannot be registered for synthetic audit activity")
    }
    let active_matching_actor: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND LOWER(BTRIM(role)) = $2 AND COALESCE(LOWER(BTRIM(status)), 'active') = 'active')",
    )
    .bind(&actor.id)
    .bind(&actor.role)
    .fetch_one(&mut **transaction)
    .await?;
    if !active_matching_actor {
        bail!("Synthetic audit actor is no longer active with its expected role")
    }
    sqlx::query(
        "INSERT INTO capstone_seed_actors (batch_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(AUDIT_ACTIVITY_BATCH_ID)
    .bind(&actor.id)
    .bind(&actor.role)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_synthetic_audit_event(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &SyntheticAuditActor,
    event: &SyntheticAuditEvent,
    protected_superadmin_id: &str,
    seeded_at: DateTime<Utc>,
) -> Result<()> {
    if actor.id != event.actor_id || !synthetic_audit_actions().contains(&event.action_key) {
        bail!("Synthetic audit event failed actor or action allow-list validation")
    }
    if event.occurred_at >= manila_time(PLANNED_DAY, 0, 0)? {
        bail!("Synthetic audit activity cannot occur on or after October 17")
    }
    let actor_allowed: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM capstone_seed_actors csa
            JOIN users u ON u.id = csa.user_id
            WHERE csa.batch_id = $1
              AND csa.user_id = $2
              AND LOWER(BTRIM(csa.role)) = $3
              AND LOWER(BTRIM(u.role)) = $3
              AND csa.user_id <> $4
              AND LOWER(BTRIM(u.role)) <> 'superadmin'
        )
        "#,
    )
    .bind(AUDIT_ACTIVITY_BATCH_ID)
    .bind(&actor.id)
    .bind(&actor.role)
    .bind(protected_superadmin_id)
    .fetch_one(&mut **transaction)
    .await?;
    if !actor_allowed {
        bail!("Synthetic audit event actor is not a registered capstone presentation account")
    }

    let audit_id = new_id();
    sqlx::query(
        "INSERT INTO audit_logs (id, actor_user_id, action_key, entity_type, entity_id, result, reason, source_ip, user_agent, metadata, source, actor_attribution_mode, capstone_batch_id, seeded_at, scenario_occurred_at, created_at) VALUES ($1, $2, $3, $4, $5, 'success', $6, NULL, 'SENTINEL CAPSTONE PRESENTATION RUNNER', $7, 'capstone_seed', 'synthetic_seeded', $8, $9, $10, $10)",
    )
    .bind(&audit_id)
    .bind(&actor.id)
    .bind(event.action_key)
    .bind(event.entity_type)
    .bind(&event.entity_id)
    .bind(&event.detail)
    .bind(json!({
        "data_origin": AUDIT_ACTIVITY_DATA_ORIGIN,
        "batch_id": AUDIT_ACTIVITY_BATCH_ID,
        "parent_batch_id": BATCH_ID,
        "presentation_context": true,
        "source": "capstone_seed",
        "actor_attribution_mode": "synthetic_seeded",
        "actor_role": actor.role,
        "actor_name": actor.full_name,
        "guard_code": actor.guard_code,
        "related_record_label": event.related_label,
        "scenario_occurred_at": event.occurred_at,
    }))
    .bind(AUDIT_ACTIVITY_BATCH_ID)
    .bind(seeded_at)
    .bind(event.occurred_at)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO capstone_seed_records (batch_id, table_name, record_id) VALUES ($1, 'audit_logs', $2)",
    )
    .bind(AUDIT_ACTIVITY_BATCH_ID)
    .bind(&audit_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn build_synthetic_audit_events(
    pool: &PgPool,
    guards: &[SyntheticAuditActor],
    supervisor: &SyntheticAuditActor,
    admin: &SyntheticAuditActor,
    shifts: &[AuditShiftContext],
) -> Result<(Vec<SyntheticAuditEvent>, AuditActivityMetrics)> {
    let cutoff = manila_time(PLANNED_DAY, 0, 0)?;
    let closed_shifts = shifts
        .iter()
        .filter(|shift| shift.end < cutoff)
        .collect::<Vec<_>>();
    if closed_shifts.len() < 500 {
        bail!("Synthetic audit activity requires at least 500 completed shifts ending before October 17")
    }
    let guard_by_id = guards
        .iter()
        .map(|guard| (guard.id.as_str(), guard))
        .collect::<HashMap<_, _>>();
    let mut shifts_by_guard = HashMap::<&str, Vec<&AuditShiftContext>>::new();
    for shift in &closed_shifts {
        shifts_by_guard
            .entry(shift.guard_id.as_str())
            .or_default()
            .push(*shift);
    }

    let mut events = Vec::new();
    let mut metrics = AuditActivityMetrics::default();
    for (index, guard) in guards.iter().enumerate() {
        let guard_shifts = shifts_by_guard
            .get(guard.id.as_str())
            .ok_or_else(|| anyhow!("Capstone guard has no completed shift for audit activity"))?;
        let session_count = if index < 10 { 2 } else { 1 };
        for session_index in 0..session_count {
            let shift = guard_shifts[(index * 3 + session_index * 5) % guard_shifts.len()];
            let login_at =
                shift.start - Duration::minutes(6 + ((index + session_index) % 9) as i64);
            let logout_at =
                shift.end + Duration::minutes(3 + ((index * 2 + session_index) % 12) as i64);
            events.push(SyntheticAuditEvent {
                actor_id: guard.id.clone(),
                action_key: "AUTH_LOGIN_ATTEMPT",
                entity_type: "auth",
                entity_id: shift.shift_id.clone(),
                occurred_at: login_at,
                detail: format!(
                    "Signed in before the assigned shift at the scheduled client site."
                ),
                related_label: "Assigned capstone shift".to_string(),
            });
            events.push(SyntheticAuditEvent {
                actor_id: guard.id.clone(),
                action_key: "AUTH_LOGOUT",
                entity_type: "auth",
                entity_id: shift.shift_id.clone(),
                occurred_at: logout_at,
                detail: "Signed out after completing the related scheduled duty activity."
                    .to_string(),
                related_label: "Assigned capstone shift".to_string(),
            });
            metrics.guard_login_logout += 2;
        }
    }

    let shift_event_specs = [
        (
            "GUARD_DASHBOARD_VIEWED",
            "Opened the guard dashboard before the assigned duty.",
        ),
        (
            "SHIFT_SCHEDULE_VIEWED",
            "Viewed the assigned shift schedule and site details.",
        ),
        (
            "DTR_RECORD_VIEWED",
            "Opened the DTR record for the completed duty.",
        ),
        (
            "ATTENDANCE_HISTORY_VIEWED",
            "Checked the completed attendance history for the duty.",
        ),
    ];
    for (offset, (action_key, detail)) in shift_event_specs.into_iter().enumerate() {
        for sequence in 0..3 {
            let shift = closed_shifts[(offset * 67 + sequence * 83 + 11) % closed_shifts.len()];
            let actor = guard_by_id
                .get(shift.guard_id.as_str())
                .ok_or_else(|| anyhow!("Audit shift actor is not a registered capstone guard"))?;
            events.push(SyntheticAuditEvent {
                actor_id: actor.id.clone(),
                action_key,
                entity_type: if matches!(
                    action_key,
                    "DTR_RECORD_VIEWED" | "ATTENDANCE_HISTORY_VIEWED"
                ) {
                    "attendance"
                } else {
                    "shift"
                },
                entity_id: if matches!(
                    action_key,
                    "DTR_RECORD_VIEWED" | "ATTENDANCE_HISTORY_VIEWED"
                ) {
                    shift.attendance_id.clone()
                } else {
                    shift.shift_id.clone()
                },
                occurred_at: shift.start
                    + Duration::minutes(14 + (offset * 9 + sequence * 5) as i64),
                detail: detail.to_string(),
                related_label: if matches!(
                    action_key,
                    "DTR_RECORD_VIEWED" | "ATTENDANCE_HISTORY_VIEWED"
                ) {
                    "Completed capstone attendance record".to_string()
                } else {
                    "Assigned capstone shift".to_string()
                },
            });
            metrics.guard_operational += 1;
        }
    }

    let notifications = read_audit_references(
        pool,
        ENRICHMENT_BATCH_ID,
        "notifications",
        "SELECT n.id, n.user_id AS actor_id, n.created_at AS occurred_at, n.title AS label FROM notifications n JOIN capstone_seed_records csr ON csr.batch_id = $1 AND csr.table_name = 'notifications' AND csr.record_id = n.id ORDER BY n.created_at, n.id",
    )
    .await?
    .into_iter()
    .filter(|reference| reference.occurred_at < cutoff - Duration::minutes(12))
    .collect::<Vec<_>>();
    let requests = read_audit_references(
        pool,
        ENRICHMENT_BATCH_ID,
        "operational requests",
        "SELECT r.id, r.requester_id AS actor_id, r.created_at AS occurred_at, r.subject AS label FROM operational_requests r JOIN capstone_seed_records csr ON csr.batch_id = $1 AND csr.table_name = 'operational_requests' AND csr.record_id = r.id ORDER BY r.created_at, r.id",
    )
    .await?
    .into_iter()
    .filter(|reference| reference.occurred_at < cutoff - Duration::minutes(43))
    .collect::<Vec<_>>();
    let replacements = read_audit_references(
        pool,
        BATCH_ID,
        "replacement scenarios",
        "SELECT r.id, r.recommended_guard_id AS actor_id, r.generated_at AS occurred_at, 'Relief coverage recommendation' AS label FROM smart_guard_replacements r JOIN capstone_seed_records csr ON csr.batch_id = $1 AND csr.table_name = 'smart_guard_replacements' AND csr.record_id = r.id WHERE r.recommended_guard_id IS NOT NULL ORDER BY r.generated_at, r.id",
    )
    .await?
    .into_iter()
    .filter(|reference| reference.occurred_at < cutoff - Duration::minutes(19))
    .collect::<Vec<_>>();
    let incidents = read_audit_references(
        pool,
        ENRICHMENT_BATCH_ID,
        "incidents",
        "SELECT i.id, i.reported_by AS actor_id, i.created_at AS occurred_at, i.title AS label FROM incidents i JOIN capstone_seed_records csr ON csr.batch_id = $1 AND csr.table_name = 'incidents' AND csr.record_id = i.id ORDER BY i.created_at, i.id",
    )
    .await?
    .into_iter()
    .filter(|reference| reference.occurred_at < cutoff - Duration::minutes(25))
    .collect::<Vec<_>>();
    let feedback = read_audit_references(
        pool,
        ENRICHMENT_BATCH_ID,
        "feedback records",
        "SELECT f.id, f.user_id AS actor_id, f.created_at AS occurred_at, 'Submitted feedback' AS label FROM feedback f JOIN users u ON u.id = f.user_id JOIN capstone_seed_records csr ON csr.batch_id = $1 AND csr.table_name = 'feedback' AND csr.record_id = f.id WHERE LOWER(BTRIM(u.role)) = 'guard' ORDER BY f.created_at, f.id",
    )
    .await?
    .into_iter()
    .filter(|reference| reference.occurred_at < cutoff - Duration::minutes(29))
    .collect::<Vec<_>>();
    let tickets = read_audit_references(
        pool,
        ENRICHMENT_BATCH_ID,
        "support tickets",
        "SELECT t.id, t.guard_id AS actor_id, t.updated_at AS occurred_at, t.subject AS label FROM support_tickets t JOIN capstone_seed_records csr ON csr.batch_id = $1 AND csr.table_name = 'support_tickets' AND csr.record_id = t.id ORDER BY t.updated_at, t.id",
    )
    .await?
    .into_iter()
    .filter(|reference| reference.occurred_at < cutoff - Duration::minutes(19))
    .collect::<Vec<_>>();
    let merit_scores = read_audit_references(
        pool,
        BATCH_ID,
        "merit scores",
        "SELECT m.id, m.guard_id AS actor_id, COALESCE(m.last_calculated_at, m.updated_at, m.created_at) AS occurred_at, 'Guard performance scorecard' AS label FROM guard_merit_scores m JOIN capstone_seed_records csr ON csr.batch_id = $1 AND csr.table_name = 'guard_merit_scores' AND csr.record_id = m.id ORDER BY COALESCE(m.last_calculated_at, m.updated_at, m.created_at), m.id",
    )
    .await?
    .into_iter()
    .filter(|reference| reference.occurred_at < cutoff - Duration::minutes(21))
    .collect::<Vec<_>>();

    if notifications.len() < 3
        || requests.len() < 3
        || replacements.len() < 3
        || incidents.len() < 3
        || feedback.len() < 4
        || tickets.len() < 2
        || merit_scores.len() < 2
    {
        bail!(
            "Synthetic audit activity does not have enough historical capstone workflow references"
        )
    }

    for (index, reference) in notifications.iter().take(3).enumerate() {
        events.push(SyntheticAuditEvent {
            actor_id: reference.actor_id.clone(),
            action_key: "NOTIFICATION_VIEWED",
            entity_type: "notification",
            entity_id: reference.id.clone(),
            occurred_at: reference.occurred_at + Duration::minutes(3 + index as i64 * 4),
            detail: "Viewed an operational notification related to current duty activity."
                .to_string(),
            related_label: reference.label.clone(),
        });
        metrics.guard_operational += 1;
    }
    for (index, reference) in requests.iter().take(3).enumerate() {
        events.push(SyntheticAuditEvent {
            actor_id: reference.actor_id.clone(),
            action_key: if index == 0 {
                "OPERATIONAL_REQUEST_SUBMITTED"
            } else {
                "OPERATIONAL_REQUEST_VIEWED"
            },
            entity_type: "operational_request",
            entity_id: reference.id.clone(),
            occurred_at: reference.occurred_at + Duration::minutes(4 + index as i64 * 3),
            detail: if index == 0 {
                "Submitted the linked operational request for supervisor review.".to_string()
            } else {
                "Viewed the current status and history of the linked operational request."
                    .to_string()
            },
            related_label: reference.label.clone(),
        });
        metrics.guard_operational += 1;
    }
    for (index, reference) in replacements.iter().take(3).enumerate() {
        events.push(SyntheticAuditEvent {
            actor_id: reference.actor_id.clone(),
            action_key: if index == 2 {
                "SHIFT_REPLACEMENT_ACKNOWLEDGED"
            } else {
                "SHIFT_REPLACEMENT_STATUS_VIEWED"
            },
            entity_type: "smart_guard_replacement",
            entity_id: reference.id.clone(),
            occurred_at: reference.occurred_at + Duration::minutes(6 + index as i64 * 5),
            detail: if index == 2 {
                "Acknowledged the linked relief coverage assignment.".to_string()
            } else {
                "Viewed the linked replacement and relief coverage status.".to_string()
            },
            related_label: reference.label.clone(),
        });
        metrics.guard_operational += 1;
    }
    for (index, reference) in incidents.iter().take(3).enumerate() {
        events.push(SyntheticAuditEvent {
            actor_id: reference.actor_id.clone(),
            action_key: if index == 0 {
                "INCIDENT_REPORT_OPENED"
            } else {
                "INCIDENT_REPORT_ACKNOWLEDGED"
            },
            entity_type: "incident",
            entity_id: reference.id.clone(),
            occurred_at: reference.occurred_at + Duration::minutes(8 + index as i64 * 4),
            detail: if index == 0 {
                "Opened the linked incident report during the assigned duty.".to_string()
            } else {
                "Acknowledged the linked incident report and its operational follow-up.".to_string()
            },
            related_label: reference.label.clone(),
        });
        metrics.guard_operational += 1;
    }
    for (index, reference) in feedback.iter().take(4).enumerate() {
        events.push(SyntheticAuditEvent {
            actor_id: reference.actor_id.clone(),
            action_key: if index < 2 {
                "FEEDBACK_PAGE_VIEWED"
            } else {
                "FEEDBACK_SUBMITTED"
            },
            entity_type: "feedback",
            entity_id: reference.id.clone(),
            occurred_at: reference.occurred_at - Duration::minutes(if index < 2 { 3 } else { 0 }),
            detail: if index < 2 {
                "Opened the feedback page after reviewing the completed duty experience."
                    .to_string()
            } else {
                "Submitted the linked presentation feedback entry.".to_string()
            },
            related_label: reference.label.clone(),
        });
        metrics.guard_operational += 1;
    }

    for (index, shift) in closed_shifts.iter().take(2).enumerate() {
        events.push(SyntheticAuditEvent {
            actor_id: supervisor.id.clone(),
            action_key: "SUPERVISOR_ATTENDANCE_EXCEPTION_REVIEWED",
            entity_type: "attendance",
            entity_id: shift.attendance_id.clone(),
            occurred_at: shift.end + Duration::minutes(35 + index as i64 * 12),
            detail: "Reviewed a completed attendance record requiring supervisor follow-up."
                .to_string(),
            related_label: "Completed capstone attendance record".to_string(),
        });
        metrics.supervisor_actions += 1;
    }
    for reference in requests.iter().take(2) {
        events.push(SyntheticAuditEvent {
            actor_id: supervisor.id.clone(),
            action_key: "SUPERVISOR_OPERATIONAL_REQUEST_REVIEWED",
            entity_type: "operational_request",
            entity_id: reference.id.clone(),
            occurred_at: reference.occurred_at + Duration::minutes(42),
            detail: "Reviewed the linked operational request and its next operational step."
                .to_string(),
            related_label: reference.label.clone(),
        });
        metrics.supervisor_actions += 1;
    }
    for reference in incidents.iter().take(2) {
        events.push(SyntheticAuditEvent {
            actor_id: supervisor.id.clone(),
            action_key: "SUPERVISOR_INCIDENT_REVIEWED",
            entity_type: "incident",
            entity_id: reference.id.clone(),
            occurred_at: reference.occurred_at + Duration::minutes(24),
            detail: "Reviewed and classified the linked incident for operational follow-up."
                .to_string(),
            related_label: reference.label.clone(),
        });
        metrics.supervisor_actions += 1;
    }
    for reference in replacements.iter().take(2) {
        events.push(SyntheticAuditEvent {
            actor_id: supervisor.id.clone(),
            action_key: "SUPERVISOR_RELIEF_COVERAGE_APPROVED",
            entity_type: "smart_guard_replacement",
            entity_id: reference.id.clone(),
            occurred_at: reference.occurred_at + Duration::minutes(18),
            detail: "Reviewed and approved the linked same-site relief coverage recommendation."
                .to_string(),
            related_label: reference.label.clone(),
        });
        metrics.supervisor_actions += 1;
    }

    for reference in merit_scores.iter().take(2) {
        events.push(SyntheticAuditEvent {
            actor_id: admin.id.clone(),
            action_key: "ADMIN_ANALYTICS_VIEWED",
            entity_type: "guard_merit_score",
            entity_id: reference.id.clone(),
            occurred_at: reference.occurred_at + Duration::minutes(20),
            detail: "Viewed the linked guard performance analytics scorecard.".to_string(),
            related_label: reference.label.clone(),
        });
        metrics.admin_actions += 1;
    }
    let dtr_reference = closed_shifts
        .get(12)
        .ok_or_else(|| anyhow!("Missing capstone attendance context for admin DTR review"))?;
    events.push(SyntheticAuditEvent {
        actor_id: admin.id.clone(),
        action_key: "ADMIN_DTR_SUMMARY_REVIEWED",
        entity_type: "attendance",
        entity_id: dtr_reference.attendance_id.clone(),
        occurred_at: dtr_reference.end + Duration::minutes(52),
        detail: "Reviewed the linked attendance record in the DTR summary.".to_string(),
        related_label: "Completed capstone attendance record".to_string(),
    });
    metrics.admin_actions += 1;
    for reference in feedback.iter().take(2) {
        events.push(SyntheticAuditEvent {
            actor_id: admin.id.clone(),
            action_key: "ADMIN_FEEDBACK_SUMMARY_REVIEWED",
            entity_type: "feedback",
            entity_id: reference.id.clone(),
            occurred_at: reference.occurred_at + Duration::minutes(28),
            detail: "Reviewed the linked feedback entry in the feedback summary.".to_string(),
            related_label: reference.label.clone(),
        });
        metrics.admin_actions += 1;
    }
    for reference in tickets.iter().take(2) {
        events.push(SyntheticAuditEvent {
            actor_id: admin.id.clone(),
            action_key: "ADMIN_SUPPORT_TICKET_REVIEWED",
            entity_type: "support_ticket",
            entity_id: reference.id.clone(),
            occurred_at: reference.occurred_at + Duration::minutes(18),
            detail: "Reviewed the linked support ticket and current resolution status.".to_string(),
            related_label: reference.label.clone(),
        });
        metrics.admin_actions += 1;
    }
    events.push(SyntheticAuditEvent {
        actor_id: admin.id.clone(),
        action_key: "ADMIN_REPORT_VIEWED",
        entity_type: "capstone_seed_batch",
        entity_id: BATCH_ID.to_string(),
        occurred_at: manila_time(16, 16, 30)?,
        detail: "Viewed the presentation operations report for the validated capstone batch."
            .to_string(),
        related_label: "Capstone presentation schedule batch".to_string(),
    });
    metrics.admin_actions += 1;

    let total = metrics.guard_login_logout
        + metrics.guard_operational
        + metrics.supervisor_actions
        + metrics.admin_actions;
    if !(120..=180).contains(&total) || events.len() != total {
        bail!("Synthetic audit activity plan must contain 120-180 events; planned {total}")
    }
    Ok((events, metrics))
}

async fn print_capstone_audit_counts(pool: &PgPool, label: &str) -> Result<()> {
    println!("{label} CAPSTONE AUDIT COUNTS BY ROLE AND ACTION:");
    let rows = sqlx::query(
        r#"
        SELECT COALESCE(LOWER(BTRIM(u.role)), 'system') AS actor_role,
               al.action_key,
               COUNT(*)::BIGINT AS count
        FROM audit_logs al
        LEFT JOIN users u ON u.id = al.actor_user_id
        JOIN capstone_seed_records csr
          ON csr.table_name = 'audit_logs'
         AND csr.record_id = al.id
         AND csr.batch_id IN ($1, $2, $3)
        GROUP BY actor_role, al.action_key
        ORDER BY actor_role, al.action_key
        "#,
    )
    .bind(BATCH_ID)
    .bind(ENRICHMENT_BATCH_ID)
    .bind(AUDIT_ACTIVITY_BATCH_ID)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
        println!("none");
    }
    for row in rows {
        println!(
            "{}|{}|{}",
            row.try_get::<String, _>("actor_role")?,
            row.try_get::<String, _>("action_key")?,
            row.try_get::<i64, _>("count")?
        );
    }
    Ok(())
}

async fn read_audit_activity_metrics(pool: &PgPool) -> Result<AuditActivityMetrics> {
    let row = sqlx::query(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE LOWER(BTRIM(u.role)) = 'guard' AND al.action_key IN ('AUTH_LOGIN_ATTEMPT', 'AUTH_LOGOUT'))::BIGINT AS guard_login_logout,
            COUNT(*) FILTER (WHERE LOWER(BTRIM(u.role)) = 'guard' AND al.action_key NOT IN ('AUTH_LOGIN_ATTEMPT', 'AUTH_LOGOUT'))::BIGINT AS guard_operational,
            COUNT(*) FILTER (WHERE LOWER(BTRIM(u.role)) = 'supervisor')::BIGINT AS supervisor_actions,
            COUNT(*) FILTER (WHERE LOWER(BTRIM(u.role)) = 'admin')::BIGINT AS admin_actions
        FROM audit_logs al
        JOIN capstone_seed_records csr
          ON csr.batch_id = $1 AND csr.table_name = 'audit_logs' AND csr.record_id = al.id
        LEFT JOIN users u ON u.id = al.actor_user_id
        "#,
    )
    .bind(AUDIT_ACTIVITY_BATCH_ID)
    .fetch_one(pool)
    .await?;
    Ok(AuditActivityMetrics {
        guard_login_logout: row.try_get::<i64, _>("guard_login_logout")? as usize,
        guard_operational: row.try_get::<i64, _>("guard_operational")? as usize,
        supervisor_actions: row.try_get::<i64, _>("supervisor_actions")? as usize,
        admin_actions: row.try_get::<i64, _>("admin_actions")? as usize,
    })
}

fn print_audit_activity_metrics(label: &str, metrics: &AuditActivityMetrics) {
    println!(
        "{label} AUDIT ACTIVITY: guard_login_logout={}, guard_operational={}, supervisor_actions={}, admin_actions={}, total={}",
        metrics.guard_login_logout,
        metrics.guard_operational,
        metrics.supervisor_actions,
        metrics.admin_actions,
        metrics.guard_login_logout
            + metrics.guard_operational
            + metrics.supervisor_actions
            + metrics.admin_actions,
    );
}

async fn audit_activity_preflight(pool: &PgPool) -> Result<()> {
    ensure_ledger(pool).await?;
    let shifts = ensure_enrichment_ready(pool).await?;
    let (guards, supervisor, admin) = read_synthetic_audit_actors(pool).await?;
    let audit_shifts = read_audit_shift_contexts(pool).await?;
    let (events, metrics) =
        build_synthetic_audit_events(pool, &guards, &supervisor, &admin, &audit_shifts).await?;
    if shifts.len() != audit_shifts.len() {
        bail!("Synthetic audit activity source shift count is inconsistent")
    }
    println!(
        "AUDIT PREFLIGHT: guards={}, supervisor={}, admin={}, planned_events={}, source_completed_shifts={}",
        guards.len(),
        supervisor.id,
        admin.id,
        events.len(),
        shifts.len()
    );
    print_audit_activity_metrics("PLANNED", &metrics);
    print_capstone_audit_counts(pool, "BEFORE").await?;
    Ok(())
}

async fn validate_audit_activity(pool: &PgPool) -> Result<()> {
    let batch_status: Option<String> =
        sqlx::query_scalar("SELECT status FROM capstone_seed_batches WHERE batch_id = $1")
            .bind(AUDIT_ACTIVITY_BATCH_ID)
            .fetch_optional(pool)
            .await?;
    if batch_status.is_none() {
        println!("AUDIT ACTIVITY VALIDATION: no audit activity batch is present.");
        return Ok(());
    }
    if batch_status.as_deref() != Some("complete") {
        bail!("Synthetic audit activity batch is not complete")
    }

    let cutoff = manila_time(PLANNED_DAY, 0, 0)?;
    let protected_id = require_env("CAPSTONE_PROTECTED_SUPERADMIN_ID")?;
    let invalid_rows: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::BIGINT
        FROM audit_logs al
        JOIN capstone_seed_records csr
          ON csr.batch_id = $1 AND csr.table_name = 'audit_logs' AND csr.record_id = al.id
        LEFT JOIN capstone_seed_actors csa
          ON csa.batch_id = $1 AND csa.user_id = al.actor_user_id
        LEFT JOIN users u ON u.id = al.actor_user_id
        WHERE al.source <> 'capstone_seed'
           OR al.actor_attribution_mode <> 'synthetic_seeded'
           OR al.capstone_batch_id <> $1
           OR al.seeded_at IS NULL
           OR al.scenario_occurred_at IS NULL
           OR al.created_at <> al.scenario_occurred_at
           OR al.created_at >= $2
           OR al.actor_user_id IS NULL
           OR csa.user_id IS NULL
           OR LOWER(BTRIM(COALESCE(csa.role, ''))) <> LOWER(BTRIM(COALESCE(u.role, '')))
           OR al.actor_user_id = $3
           OR LOWER(BTRIM(COALESCE(u.role, ''))) = 'superadmin'
           OR NOT (al.action_key = ANY($4))
           OR (
                NOT (al.entity_type = 'capstone_seed_batch' AND al.entity_id IN ($1, $5, $6))
                AND NOT EXISTS (
                    SELECT 1
                    FROM capstone_seed_records related
                    WHERE related.record_id = al.entity_id
                      AND related.batch_id IN ($1, $5, $6)
                )
           )
        "#,
    )
    .bind(AUDIT_ACTIVITY_BATCH_ID)
    .bind(cutoff)
    .bind(protected_id)
    .bind(synthetic_audit_actions())
    .bind(BATCH_ID)
    .bind(ENRICHMENT_BATCH_ID)
    .fetch_one(pool)
    .await?;
    if invalid_rows != 0 {
        bail!("Synthetic audit activity validation found {invalid_rows} invalid attributed rows")
    }

    let metrics = read_audit_activity_metrics(pool).await?;
    let total = metrics.guard_login_logout
        + metrics.guard_operational
        + metrics.supervisor_actions
        + metrics.admin_actions;
    if !(120..=180).contains(&total) {
        bail!("Synthetic audit activity validation expected 120-180 records, found {total}")
    }
    print_audit_activity_metrics("VALIDATED", &metrics);
    Ok(())
}

async fn seed_audit_activity(pool: &PgPool) -> Result<()> {
    ensure_ledger(pool).await?;
    let existing_status: Option<String> =
        sqlx::query_scalar("SELECT status FROM capstone_seed_batches WHERE batch_id = $1")
            .bind(AUDIT_ACTIVITY_BATCH_ID)
            .fetch_optional(pool)
            .await?;
    if existing_status.as_deref() == Some("complete") {
        if validate_audit_activity(pool).await.is_ok() {
            println!(
                "Synthetic audit activity batch is already complete; no records were duplicated."
            );
            status(pool).await?;
            validate(pool).await?;
            return Ok(());
        }
        println!("Synthetic audit activity batch failed validation; resetting only that child batch before retrying.");
        reset_tracked_batch(pool, AUDIT_ACTIVITY_BATCH_ID).await?;
    } else if existing_status.is_some() {
        reset_tracked_batch(pool, AUDIT_ACTIVITY_BATCH_ID).await?;
    }

    let shifts = ensure_enrichment_ready(pool).await?;
    let (guards, supervisor, admin) = read_synthetic_audit_actors(pool).await?;
    let audit_shifts = read_audit_shift_contexts(pool).await?;
    let (events, expected_metrics) =
        build_synthetic_audit_events(pool, &guards, &supervisor, &admin, &audit_shifts).await?;
    if shifts.len() != audit_shifts.len() {
        bail!("Synthetic audit activity source shift count is inconsistent")
    }
    let reference_at =
        DateTime::parse_from_rfc3339(&require_env("CAPSTONE_REFERENCE_DATE")?)?.with_timezone(&Utc);
    let protected_id = require_env("CAPSTONE_PROTECTED_SUPERADMIN_ID")?;
    let seeded_at = Utc::now();
    let actor_by_id = guards
        .iter()
        .chain(std::iter::once(&supervisor))
        .chain(std::iter::once(&admin))
        .map(|actor| (actor.id.as_str(), actor))
        .collect::<HashMap<_, _>>();

    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO capstone_seed_batches (batch_id, data_origin, reference_at, status, metadata) VALUES ($1, $2, $3, 'running', $4)",
    )
    .bind(AUDIT_ACTIVITY_BATCH_ID)
    .bind(AUDIT_ACTIVITY_DATA_ORIGIN)
    .bind(reference_at)
    .bind(json!({
        "parentBatchId": BATCH_ID,
        "enrichmentBatchId": ENRICHMENT_BATCH_ID,
        "presentationContext": true,
        "source": "capstone_seed",
        "actorAttributionMode": "synthetic_seeded",
        "historyThrough": "2026-10-16",
        "generatedBy": "capstone-dataset seed-audit-activity",
    }))
    .execute(&mut *transaction)
    .await?;
    for actor in guards
        .iter()
        .chain(std::iter::once(&supervisor))
        .chain(std::iter::once(&admin))
    {
        register_synthetic_audit_actor(&mut transaction, actor, &protected_id).await?;
    }
    for event in &events {
        let actor = actor_by_id
            .get(event.actor_id.as_str())
            .ok_or_else(|| anyhow!("Synthetic audit event refers to an unregistered actor"))?;
        insert_synthetic_audit_event(&mut transaction, actor, event, &protected_id, seeded_at)
            .await?;
    }
    sqlx::query("UPDATE capstone_seed_batches SET status = 'complete', completed_at = CURRENT_TIMESTAMP WHERE batch_id = $1")
        .bind(AUDIT_ACTIVITY_BATCH_ID)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;

    print_audit_activity_metrics("SEEDED", &expected_metrics);
    validate_audit_activity(pool).await?;
    Ok(())
}

fn scenario_shift<'a>(shifts: &'a [CapstoneShift], sequence: usize) -> &'a CapstoneShift {
    &shifts[(sequence * 71 + 17) % shifts.len()]
}

async fn seed_incident_scenarios(
    pool: &PgPool,
    shifts: &[CapstoneShift],
    metrics: &mut EnrichmentMetrics,
) -> Result<Vec<WorkflowContext>> {
    let scenarios = [
        ("Visitor verification concern", "A visitor arrived without the required authorization reference. Access was held while the site contact verified the visit.", "resolved", "low", 68_i64),
        ("Perimeter light outage", "One perimeter light was not operating during the scheduled inspection. The affected area was included in the guard's additional rounds.", "resolved", "medium", 96),
        ("Gate access congestion", "Delivery and visitor traffic briefly congested the gate. The guard coordinated a controlled entry sequence with the site contact.", "investigating", "medium", 112),
        ("Unattended package review", "An unattended package was observed near the entrance. The area was checked with the site contact before normal access resumed.", "resolved", "high", 144),
        ("Access card verification", "A staff access card did not match the visitor log. Entry was deferred pending confirmation from the authorized contact.", "open", "low", 74),
        ("Defective flashlight report", "The assigned flashlight intermittently failed during a routine patrol. The issue was reported for replacement before the next duty period.", "investigating", "medium", 88),
        ("Attempted unauthorized entry", "An individual attempted to enter through a restricted gate without clearance. The guard maintained the access boundary and requested a supervisor review.", "open", "high", 132),
    ];
    let mut contexts = Vec::with_capacity(scenarios.len());
    for (index, (title, description, status, priority, minute_offset)) in
        scenarios.into_iter().enumerate()
    {
        let shift = scenario_shift(shifts, index + 3);
        let created_at = shift.start + Duration::minutes(minute_offset);
        if created_at >= shift.end {
            bail!("Incident scenario timestamp falls outside its assigned shift")
        }
        let updated_at = match status {
            "resolved" => created_at + Duration::minutes(95),
            "investigating" => created_at + Duration::minutes(45),
            _ => created_at,
        };
        let incident_id = new_id();
        sqlx::query(
            "INSERT INTO incidents (id, title, description, location, site_name, reported_by, status, priority, created_at, updated_at) VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&incident_id)
        .bind(title)
        .bind(description)
        .bind(&shift.site_name)
        .bind(&shift.guard_id)
        .bind(status)
        .bind(priority)
        .bind(created_at)
        .bind(updated_at)
        .execute(pool)
        .await?;
        track_enrichment(pool, "incidents", &incident_id).await?;

        let classification_id = new_id();
        let confidence = match priority {
            "high" => 0.91,
            "medium" => 0.82,
            _ => 0.76,
        };
        sqlx::query(
            "INSERT INTO incident_severity_classifications (id, incident_id, predicted_severity, confidence_score, requires_human_review, rationale, feature_scores, supporting_signals, classified_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $9)",
        )
        .bind(&classification_id)
        .bind(&incident_id)
        .bind(priority)
        .bind(confidence)
        .bind(matches!(priority, "high"))
        .bind("Presentation scenario classification based on the reported operational condition and required follow-up.")
        .bind(json!({"operationalImpact": priority, "siteContext": "scheduled shift"}))
        .bind(json!({"dataOrigin": ENRICHMENT_DATA_ORIGIN, "workflow": "incident review"}))
        .bind(created_at + Duration::minutes(18))
        .execute(pool)
        .await?;
        track_enrichment(
            pool,
            "incident_severity_classifications",
            &classification_id,
        )
        .await?;

        metrics.incidents += 1;
        metrics.incident_classifications += 1;
        contexts.push(WorkflowContext {
            id: incident_id,
            guard_id: shift.guard_id.clone(),
            shift_id: shift.id.clone(),
            occurred_at: created_at,
        });
    }
    Ok(contexts)
}

async fn seed_operational_request_scenarios(
    pool: &PgPool,
    shifts: &[CapstoneShift],
    metrics: &mut EnrichmentMetrics,
) -> Result<Vec<WorkflowContext>> {
    let scenarios = [
        ("Additional radio request", "Request an additional radio for clearer gate coordination.", "A spare radio would reduce handoff delays during the busier entry period.", "pending", "normal"),
        ("Replacement rain gear", "Request replacement rain gear", "The current rain gear is worn and no longer reliable during extended perimeter rounds.", "approved", "normal"),
        ("Client-site instruction clarification", "Clarify visitor verification instruction", "Please confirm the required reference for after-hours visitor verification.", "in_progress", "normal"),
        ("Schedule correction review", "Review schedule end time", "The posted schedule needs a review because the handoff time differs from the site instruction.", "completed", "high"),
        ("Temporary relief request", "Request temporary relief coverage", "A short relief arrangement is requested after an urgent personal concern was reported before duty.", "rejected", "normal"),
        ("Defective flashlight follow-up", "Request flashlight replacement", "The assigned flashlight intermittently loses power during the patrol route.", "approved", "normal"),
        ("Gate access coordination", "Coordinate delivery gate access", "Please confirm the arrival window and contact process for the scheduled delivery.", "in_progress", "normal"),
        ("DTR correction review", "Request DTR check-in review", "Please review the recorded check-in after a delayed mobile signal at the site.", "completed", "high"),
        ("Site briefing materials", "Request updated site briefing", "The guard team needs the latest visitor and delivery handling reminder for this post.", "pending", "normal"),
    ];
    let mut contexts = Vec::with_capacity(scenarios.len());
    for (index, (subject, reason, details, status, priority)) in scenarios.into_iter().enumerate() {
        let shift = scenario_shift(shifts, index + 18);
        let created_at = shift.start + Duration::minutes(36 + (index as i64 * 7));
        let request_id = new_id();
        let reviewed_at =
            (!matches!(status, "pending")).then_some(created_at + Duration::minutes(42));
        let fulfilled_at = matches!(status, "completed").then_some(created_at + Duration::hours(3));
        sqlx::query(
            "INSERT INTO operational_requests (id, request_type, status, requester_id, resource_type, subject, reason, details, priority, client_site_id, shift_id, operational_event_key, reviewed_at, decision_reason, fulfilled_at, created_at, updated_at) VALUES ($1, 'service', $2, $3, 'guard_equipment', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, COALESCE($13, $11, $14))",
        )
        .bind(&request_id)
        .bind(status)
        .bind(&shift.guard_id)
        .bind(subject)
        .bind(reason)
        .bind(details)
        .bind(priority)
        .bind(&shift.site_id)
        .bind(&shift.id)
        .bind(format!("capstone-enrichment-request-{}", index + 1))
        .bind(reviewed_at)
        .bind(if status == "rejected" { Some("Presentation scenario: the requested temporary relief was not available for the stated period.") } else { None })
        .bind(fulfilled_at)
        .bind(created_at)
        .execute(pool)
        .await?;
        track_enrichment(pool, "operational_requests", &request_id).await?;

        let mut timeline = vec![(
            None,
            "pending",
            created_at,
            "Request submitted for operational review.",
        )];
        match status {
            "approved" => timeline.push((
                Some("pending"),
                "approved",
                created_at + Duration::minutes(42),
                "Request approved for the next available support cycle.",
            )),
            "in_progress" => {
                timeline.push((
                    Some("pending"),
                    "approved",
                    created_at + Duration::minutes(38),
                    "Request approved for coordinated follow-up.",
                ));
                timeline.push((
                    Some("approved"),
                    "in_progress",
                    created_at + Duration::minutes(70),
                    "Support coordination is in progress.",
                ));
            }
            "completed" => {
                timeline.push((
                    Some("pending"),
                    "approved",
                    created_at + Duration::minutes(38),
                    "Request approved for coordinated follow-up.",
                ));
                timeline.push((
                    Some("approved"),
                    "in_progress",
                    created_at + Duration::minutes(70),
                    "Support coordination is in progress.",
                ));
                timeline.push((
                    Some("in_progress"),
                    "completed",
                    created_at + Duration::hours(3),
                    "Requested review or equipment follow-up completed.",
                ));
            }
            "rejected" => timeline.push((
                Some("pending"),
                "rejected",
                created_at + Duration::minutes(42),
                "Requested temporary relief was unavailable for the stated period.",
            )),
            _ => {}
        }
        for (from_status, to_status, event_at, comment) in timeline {
            let event_id = new_id();
            sqlx::query(
                "INSERT INTO operational_request_events (id, request_id, actor_user_id, from_status, to_status, comment, metadata, created_at) VALUES ($1, $2, NULL, $3, $4, $5, $6, $7)",
            )
            .bind(&event_id)
            .bind(&request_id)
            .bind(from_status)
            .bind(to_status)
            .bind(comment)
            .bind(json!({"dataOrigin": ENRICHMENT_DATA_ORIGIN, "actorLabel": "CAPSTONE DATASET ENRICHER", "presentationContext": true}))
            .bind(event_at)
            .execute(pool)
            .await?;
            track_enrichment(pool, "operational_request_events", &event_id).await?;
            metrics.operational_request_events += 1;
        }
        metrics.operational_requests += 1;
        contexts.push(WorkflowContext {
            id: request_id,
            guard_id: shift.guard_id.clone(),
            shift_id: shift.id.clone(),
            occurred_at: created_at,
        });
    }
    Ok(contexts)
}

async fn seed_readiness(
    pool: &PgPool,
    shifts: &[CapstoneShift],
    metrics: &mut EnrichmentMetrics,
) -> Result<()> {
    for (index, shift) in shifts.iter().take(96).enumerate() {
        let checked_items = if index % 7 == 0 {
            json!(["uniform", "endorsement_form"])
        } else {
            json!(["uniform", "firearm", "endorsement_form"])
        };
        let recorded_at = shift.start - Duration::minutes(25 + (index % 18) as i64);
        let readiness_id = new_id();
        sqlx::query(
            "INSERT INTO guard_shift_readiness (id, shift_id, guard_id, checked_items, notes, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $6)",
        )
        .bind(&readiness_id)
        .bind(&shift.id)
        .bind(&shift.guard_id)
        .bind(checked_items)
        .bind(if index % 7 == 0 { "Equipment follow-up noted before duty." } else { "Pre-shift equipment and endorsement confirmation recorded." })
        .bind(recorded_at)
        .execute(pool)
        .await?;
        track_enrichment(pool, "guard_shift_readiness", &readiness_id).await?;
        *metrics
            .readiness
            .entry(ShiftRotation::from_start(shift.start)?.label().to_string())
            .or_default() += 1;
    }
    Ok(())
}

async fn seed_support_tickets(
    pool: &PgPool,
    shifts: &[CapstoneShift],
    metrics: &mut EnrichmentMetrics,
) -> Result<Vec<WorkflowContext>> {
    let scenarios = [
        ("Mobile check-in concern", "Naa koy concern sa mobile check-in kay usahay hinay ang signal sa gate area. Palihog ko check kung naa pa bay dapat buhaton sa app.", "open"),
        ("DTR clarification", "Palihog ko clarify sa akong DTR kay lahi ang oras sa akong handover ug sa na-record sa mobile.", "in_progress"),
        ("Schedule not refreshing", "Dili dayon makita ang updated schedule sa akong mobile human sa change. Need lang ko ug confirmation sa latest duty.", "resolved"),
        ("Notification clarification", "Naka-receive ko ug notification pero dili klaro kung kinahanglan ba ko mu-action dayon.", "resolved"),
        ("Site instruction question", "Pwede ko mangayo ug klaro nga instruction para sa after-hours visitor verification sa site?", "in_progress"),
        ("Attendance correction request", "Please review ang check-in record kay delayed ang signal sa akong shift.", "open"),
        ("Profile contact concern", "Need ko ug tabang sa pag-check sa contact information nga makita sa akong account.", "resolved"),
    ];
    let mut contexts = Vec::with_capacity(scenarios.len());
    for (index, (subject, message, status)) in scenarios.into_iter().enumerate() {
        let shift = scenario_shift(shifts, index + 33);
        let created_at = shift.end + Duration::minutes(25 + (index as i64 * 11));
        let updated_at = match status {
            "resolved" => created_at + Duration::hours(2),
            "in_progress" => created_at + Duration::minutes(55),
            _ => created_at,
        };
        let ticket_id = new_id();
        sqlx::query(
            "INSERT INTO support_tickets (id, guard_id, subject, message, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&ticket_id)
        .bind(&shift.guard_id)
        .bind(subject)
        .bind(message)
        .bind(status)
        .bind(created_at)
        .bind(updated_at)
        .execute(pool)
        .await?;
        track_enrichment(pool, "support_tickets", &ticket_id).await?;
        *metrics
            .support_tickets
            .entry(status.to_string())
            .or_default() += 1;
        contexts.push(WorkflowContext {
            id: ticket_id,
            guard_id: shift.guard_id.clone(),
            shift_id: shift.id.clone(),
            occurred_at: updated_at,
        });
    }
    Ok(contexts)
}

async fn insert_notification(
    pool: &PgPool,
    metrics: &mut EnrichmentMetrics,
    user_id: &str,
    title: &str,
    message: &str,
    notification_type: &str,
    related_shift_id: Option<&str>,
    related_request_id: Option<&str>,
    read: bool,
    created_at: DateTime<Utc>,
) -> Result<()> {
    let notification_id = new_id();
    sqlx::query(
        "INSERT INTO notifications (id, user_id, title, message, type, related_shift_id, related_request_id, read, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)",
    )
    .bind(&notification_id)
    .bind(user_id)
    .bind(title)
    .bind(message)
    .bind(notification_type)
    .bind(related_shift_id)
    .bind(related_request_id)
    .bind(read)
    .bind(created_at)
    .execute(pool)
    .await?;
    track_enrichment(pool, "notifications", &notification_id).await?;
    metrics.notifications += 1;
    Ok(())
}

async fn seed_workflow_notifications(
    pool: &PgPool,
    requests: &[WorkflowContext],
    incidents: &[WorkflowContext],
    tickets: &[WorkflowContext],
    metrics: &mut EnrichmentMetrics,
) -> Result<()> {
    for (index, request) in requests.iter().enumerate() {
        let read = index % 3 != 0;
        insert_notification(
            pool,
            metrics,
            &request.guard_id,
            "Operational request updated",
            "Your operational request has been recorded. Open Requests to review its current status and next step.",
            "operational_request",
            Some(&request.shift_id),
            Some(&request.id),
            read,
            request.occurred_at + Duration::minutes(8),
        )
        .await?;
    }
    for (index, incident) in incidents.iter().enumerate() {
        insert_notification(
            pool,
            metrics,
            &incident.guard_id,
            "Incident review recorded",
            "An incident reported during your duty has been recorded for operational review. Follow the site instruction until the review is complete.",
            "incident_review",
            Some(&incident.shift_id),
            None,
            index % 2 == 0,
            incident.occurred_at + Duration::minutes(24),
        )
        .await?;
    }
    for (index, ticket) in tickets.iter().enumerate() {
        insert_notification(
            pool,
            metrics,
            &ticket.guard_id,
            "Support ticket update",
            "Your support concern has an updated status. Open Support Tickets to review the latest response.",
            "support_ticket",
            Some(&ticket.shift_id),
            None,
            index % 2 != 0,
            ticket.occurred_at + Duration::minutes(12),
        )
        .await?;
    }
    Ok(())
}

async fn seed_client_evaluations(
    pool: &PgPool,
    shifts: &[CapstoneShift],
    metrics: &mut EnrichmentMetrics,
) -> Result<()> {
    let ratings = [
        4.6, 4.2, 3.8, 4.7, 4.4, 4.0, 4.9, 3.7, 4.3, 4.5, 3.9, 4.8, 4.1, 4.6, 3.6, 4.4, 4.7, 4.0,
        4.5, 3.4, 4.8, 4.2, 4.6, 3.9,
    ];
    let comments = [
        "Consistent attendance and professional site conduct during the observed duty period.",
        "Handled visitor verification calmly and followed the site access process.",
        "Needs a little more confidence when relaying handover details, but attendance remained consistent.",
        "Demonstrated good familiarity with the site's patrol and gate procedures.",
        "Professional communication during a busy entry period.",
        "Reliable attendance; continue improving the clarity of written handover notes.",
    ];
    let mut selected_guards = HashSet::new();
    for shift in shifts {
        if selected_guards.len() == ratings.len() {
            break;
        }
        if !selected_guards.insert(shift.guard_id.clone()) {
            continue;
        }
        let index = selected_guards.len() - 1;
        let evaluation_id = new_id();
        let created_at = shift.end + Duration::minutes(80 + (index % 5) as i64 * 9);
        sqlx::query(
            "INSERT INTO client_evaluations (id, guard_id, shift_id, evaluator_name, evaluator_role, rating, comment, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&evaluation_id)
        .bind(&shift.guard_id)
        .bind(&shift.id)
        .bind("Capstone presentation evaluation")
        .bind("presentation scenario")
        .bind(ratings[index])
        .bind(comments[index % comments.len()])
        .bind(created_at)
        .execute(pool)
        .await?;
        track_enrichment(pool, "client_evaluations", &evaluation_id).await?;
        metrics.client_evaluations += 1;
    }
    if metrics.client_evaluations != ratings.len() {
        bail!("Expected 24 distinct guards with completed shifts for client evaluation scenarios")
    }
    Ok(())
}

async fn seed_tracking_points(
    pool: &PgPool,
    shifts: &[CapstoneShift],
    metrics: &mut EnrichmentMetrics,
) -> Result<()> {
    for index in 0..18 {
        let shift = scenario_shift(shifts, index + 49);
        let point_id = new_id();
        let latitude = shift.latitude + ((index as f64 % 3.0) - 1.0) * 0.00011;
        let longitude = shift.longitude + (((index * 2) as f64 % 3.0) - 1.0) * 0.00010;
        let recorded_at = shift.start + Duration::minutes(105 + (index as i64 * 13 % 210));
        if recorded_at >= shift.end {
            bail!("Tracking point timestamp falls outside its assigned completed shift")
        }
        sqlx::query(
            "INSERT INTO tracking_points (id, entity_type, entity_id, user_id, label, status, latitude, longitude, heading, speed_kph, accuracy_meters, created_by, recorded_at, created_at) VALUES ($1, 'guard', $2, $2, $3, 'presentation_checkpoint', $4, $5, $6, $7, $8, NULL, $9, $9)",
        )
        .bind(&point_id)
        .bind(&shift.guard_id)
        .bind(format!("Presentation checkpoint near {}", shift.site_name))
        .bind(latitude)
        .bind(longitude)
        .bind((index as f64 * 37.0) % 360.0)
        .bind(2.2 + (index % 4) as f64 * 0.4)
        .bind(9.0 + (index % 3) as f64)
        .bind(recorded_at)
        .execute(pool)
        .await?;
        track_enrichment(pool, "tracking_points", &point_id).await?;
        metrics.tracking_points += 1;
    }
    Ok(())
}

async fn seed_absence_predictions(pool: &PgPool, metrics: &mut EnrichmentMetrics) -> Result<()> {
    let rows = sqlx::query(
        r#"
        SELECT s.guard_id,
               COUNT(DISTINCT s.id) FILTER (WHERE s.status = 'completed')::BIGINT AS completed_shifts,
               COUNT(DISTINCT s.id) FILTER (WHERE s.status = 'absent')::BIGINT AS prior_absences,
               COUNT(DISTINCT p.id) FILTER (WHERE p.status = 'late')::BIGINT AS late_checkins,
               COUNT(DISTINCT s.id) FILTER (WHERE EXTRACT(HOUR FROM s.start_time AT TIME ZONE 'Asia/Manila') = 23)::BIGINT AS night_shifts,
               COUNT(DISTINCT r.id) FILTER (WHERE r.recommended_guard_id = s.guard_id)::BIGINT AS replacement_assignments
        FROM shifts s
        JOIN capstone_seed_records csr
          ON csr.batch_id = $1 AND csr.table_name = 'shifts' AND csr.record_id = s.id
        LEFT JOIN punctuality_records p ON p.shift_id = s.id
        LEFT JOIN smart_guard_replacements r
          ON r.recommended_guard_id = s.guard_id
         AND EXISTS (
             SELECT 1 FROM capstone_seed_records rcsr
             WHERE rcsr.batch_id = $1 AND rcsr.table_name = 'smart_guard_replacements' AND rcsr.record_id = r.id
         )
        GROUP BY s.guard_id
        ORDER BY prior_absences DESC, late_checkins DESC, night_shifts DESC, s.guard_id
        LIMIT 4
        "#,
    )
    .bind(BATCH_ID)
    .fetch_all(pool)
    .await?;
    if rows.len() != 4 {
        bail!(
            "Expected four derived absence-prediction candidates, found {}",
            rows.len()
        )
    }
    for (index, row) in rows.into_iter().enumerate() {
        let guard_id: String = row.try_get("guard_id")?;
        let completed_shifts: i64 = row.try_get("completed_shifts")?;
        let prior_absences: i64 = row.try_get("prior_absences")?;
        let late_checkins: i64 = row.try_get("late_checkins")?;
        let night_shifts: i64 = row.try_get("night_shifts")?;
        let replacement_assignments: i64 = row.try_get("replacement_assignments")?;
        let risk_score = (0.16
            + (prior_absences as f64 * 0.42)
            + (late_checkins.min(3) as f64 * 0.10)
            + (replacement_assignments.min(2) as f64 * 0.06)
            + (night_shifts.min(4) as f64 * 0.02))
            .min(0.92);
        let risk_level = if risk_score >= 0.72 {
            "high"
        } else if risk_score >= 0.42 {
            "medium"
        } else {
            "low"
        };
        let generated_at = manila_time(16, 16 + index as u32, 20)?;
        let prediction_id = new_id();
        sqlx::query(
            "INSERT INTO guard_absence_predictions (id, guard_id, prediction_window_hours, risk_score, risk_level, confidence_score, explanation, contributing_factors, source_snapshot, generated_at, valid_until, feature_version, created_at, updated_at) VALUES ($1, $2, 24, $3, $4, $5, $6, $7, $8, $9, $10, 'capstone-enrichment-v1', $9, $9)",
        )
        .bind(&prediction_id)
        .bind(&guard_id)
        .bind(risk_score)
        .bind(risk_level)
        .bind(0.78)
        .bind(json!({
            "summary": "Presentation scenario derived from the current capstone attendance, punctuality, replacement, and night-rotation records.",
            "dataOrigin": ENRICHMENT_DATA_ORIGIN,
        }))
        .bind(json!({"priorAbsences": prior_absences, "lateCheckins": late_checkins, "replacementAssignments": replacement_assignments, "nightShifts": night_shifts}))
        .bind(json!({"dataOrigin": ENRICHMENT_DATA_ORIGIN, "completedShifts": completed_shifts, "priorAbsences": prior_absences, "lateCheckins": late_checkins, "replacementAssignments": replacement_assignments, "nightShifts": night_shifts, "calculatedAt": generated_at}))
        .bind(generated_at)
        .bind(generated_at + Duration::hours(24))
        .execute(pool)
        .await?;
        track_enrichment(pool, "guard_absence_predictions", &prediction_id).await?;
        metrics.absence_predictions += 1;
    }
    Ok(())
}

async fn read_feedback_participants(pool: &PgPool) -> Result<(Vec<String>, String, String)> {
    let rows = sqlx::query(
        r#"
        SELECT DISTINCT s.guard_id
        FROM shifts s
        JOIN capstone_seed_records csr
          ON csr.batch_id = $1 AND csr.table_name = 'shifts' AND csr.record_id = s.id
        LEFT JOIN feedback f ON f.user_id = s.guard_id
        WHERE s.status = 'completed' AND f.id IS NULL
        ORDER BY s.guard_id
        "#,
    )
    .bind(BATCH_ID)
    .fetch_all(pool)
    .await?;
    let mut guard_ids = rows
        .into_iter()
        .map(|row| row.try_get::<String, _>("guard_id"))
        .collect::<Result<Vec<_>, _>>()?;
    let replacement_guard: Option<String> = sqlx::query_scalar(
        "SELECT r.recommended_guard_id FROM smart_guard_replacements r JOIN capstone_seed_records csr ON csr.batch_id = $1 AND csr.table_name = 'smart_guard_replacements' AND csr.record_id = r.id LEFT JOIN feedback f ON f.user_id = r.recommended_guard_id WHERE f.id IS NULL ORDER BY r.generated_at LIMIT 1",
    )
    .bind(BATCH_ID)
    .fetch_optional(pool)
    .await?;
    if let Some(replacement_guard) = replacement_guard {
        if let Some(position) = guard_ids
            .iter()
            .position(|guard_id| guard_id == &replacement_guard)
        {
            let guard_id = guard_ids.remove(position);
            guard_ids.insert(0, guard_id);
        }
    }
    if guard_ids.len() < 20 {
        bail!(
            "Expected at least 20 capstone guards without existing feedback, found {}",
            guard_ids.len()
        )
    }

    async fn role_participant(pool: &PgPool, role_filter: &str) -> Result<String> {
        sqlx::query_scalar(
            "SELECT u.id FROM users u LEFT JOIN feedback f ON f.user_id = u.id WHERE LOWER(BTRIM(u.role)) = $1 AND COALESCE(LOWER(BTRIM(u.status)), 'active') = 'active' AND f.id IS NULL ORDER BY u.created_at, u.id LIMIT 1",
        )
        .bind(role_filter)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| anyhow!("No active {} account is eligible for a presentation feedback scenario", role_filter))
    }

    Ok((
        guard_ids.into_iter().take(20).collect(),
        role_participant(pool, "supervisor").await?,
        role_participant(pool, "admin").await?,
    ))
}

async fn seed_feedback(
    pool: &PgPool,
    shifts: &[CapstoneShift],
    metrics: &mut EnrichmentMetrics,
) -> Result<()> {
    let (guard_ids, supervisor_id, admin_id) = read_feedback_participants(pool).await?;
    let comments = [
        (4, "Mas sayon ang replacement kay makita dayon kung kinsa ang available kung naay kalit nga concern."),
        (4, "Okay ra ang check-in sa app. Mas dali kaysa magsulat pa sa logbook."),
        (3, "Usahay hinay mu-load kung weak ang signal sa gate, pero ma-record ra gihapon ang attendance."),
        (4, "Nakatabang ang schedule kay makita daan asa ko nga site ug unsa akong duty."),
        (4, "Okay ang DTR kay dali ra nako ma-check ang oras sa check-in ug check-out."),
        (3, "Mas maayo unta kung mas klaro ang notification kung nausab ang schedule."),
        (5, "Nindot kay dili na kinahanglan sige pangutana unsa akong duty ugma."),
        (4, "Maayo ang site details, pero helpful unta kung makita dayon ang contact person sa schedule."),
        (3, "Okay ra ang app pero medyo gamay ang text sa uban nga part sa mobile."),
        (4, "Kung night shift, helpful kaayo nga naa ang schedule ug DTR sa usa ka place."),
        (4, "Dali ra ko makakita sa akong duty history. Mas sayon na mag follow-up kung naay concern."),
        (5, "Mas klaro ang handover kay makita ang latest schedule update sa app."),
        (4, "Nakatabang ang notification kung naay request nga gi-review, pero kinahanglan ko usahay mag-open sa app para makita."),
        (3, "Kung hinay ang data, dugay gamay ang refresh sa schedule pero okay ra kung naa na ang signal."),
        (4, "Mas sayon nako ma-check kung complete ang DTR human sa duty."),
        (5, "Practical ang app para sa duty kay usa ra ka lugar ang schedule, check-in, ug update."),
        (4, "Okay ang replacement update kay kabalo dayon ko kung naay change sa assignment."),
        (4, "Mas maayo ang pagtan-aw sa duty kaysa sa old nga message-message lang."),
        (3, "Usahay wala ko kabantay sa alert. Basin pwede mas klaro kung important ang notification."),
        (4, "Okay ra ang paggamit sa mobile. Ang pinaka importante kay makita dayon ang schedule ug site."),
    ];
    for (index, guard_id) in guard_ids.iter().enumerate() {
        let feedback_at = manila_time(8 + (index % 9) as u32, 17, (index * 3 % 50) as u32)?;
        let has_prior_usage = shifts
            .iter()
            .any(|shift| shift.guard_id == *guard_id && shift.end < feedback_at);
        if !has_prior_usage {
            bail!("Feedback scenario guard has no completed capstone attendance before its feedback timestamp")
        }
        let feedback_id = new_id();
        sqlx::query("INSERT INTO feedback (id, user_id, rating, comments, created_at) VALUES ($1, $2, $3, $4, $5)")
            .bind(&feedback_id)
            .bind(guard_id)
            .bind(comments[index].0)
            .bind(comments[index].1)
            .bind(feedback_at)
            .execute(pool)
            .await?;
        track_enrichment(pool, "feedback", &feedback_id).await?;
        *metrics.feedback.entry(comments[index].0).or_default() += 1;
        metrics.bisaya_guard_feedback += 1;
    }
    for (user_id, rating, comment, created_at) in [
        (&supervisor_id, 4, "Mas dali na ang pagtan-aw sa schedule concerns ug operational requests. Helpful nga naa ang status ug history sa usa ka lugar.", manila_time(15, 16, 15)?),
        (&admin_id, 4, "Useful ang consolidated view sa DTR, requests, ug incident follow-up. Continue lang sa pagpa-klaro sa mobile notifications.", manila_time(16, 15, 40)?),
    ] {
        let feedback_id = new_id();
        sqlx::query("INSERT INTO feedback (id, user_id, rating, comments, created_at) VALUES ($1, $2, $3, $4, $5)")
            .bind(&feedback_id)
            .bind(user_id)
            .bind(rating)
            .bind(comment)
            .bind(created_at)
            .execute(pool)
            .await?;
        track_enrichment(pool, "feedback", &feedback_id).await?;
        *metrics.feedback.entry(rating).or_default() += 1;
    }
    Ok(())
}

async fn seed_presentation_audit(
    pool: &PgPool,
    metrics: &SeedMetrics,
    site_count: usize,
) -> Result<()> {
    let audit_id = new_id();
    sqlx::query("INSERT INTO audit_logs (id, actor_user_id, action_key, entity_type, entity_id, result, reason, source_ip, user_agent, metadata, created_at) VALUES ($1, NULL, 'CAPSTONE_PRESENTATION_SEED_CREATED', 'capstone_seed_batch', $2, 'success', $3, NULL, 'CAPSTONE DATASET SEEDER', $4, $5)")
        .bind(&audit_id)
        .bind(BATCH_ID)
        .bind("Presentation schedule generated with stable client-site rosters. No real-user audit activity was created.")
        .bind(json!({
            "data_origin": DATA_ORIGIN,
            "batch_id": BATCH_ID,
            "presentation_context": true,
            "actor_label": "CAPSTONE DATASET SEEDER",
            "history_through": "2026-10-16",
            "planned_from": "2026-10-17",
            "site_count": site_count,
            "scheduled_slots": metrics.day_shifts + metrics.evening_shifts + metrics.night_shifts,
        }))
        .bind(Utc::now())
        .execute(pool)
        .await?;
    track(pool, "audit_logs", &audit_id).await?;
    Ok(())
}

async fn seed_enrichment_audit(pool: &PgPool, metrics: &EnrichmentMetrics) -> Result<()> {
    let audit_id = new_id();
    sqlx::query(
        "INSERT INTO audit_logs (id, actor_user_id, action_key, entity_type, entity_id, result, reason, source_ip, user_agent, metadata, created_at) VALUES ($1, NULL, 'CAPSTONE_PRESENTATION_ENRICHED', 'capstone_seed_batch', $2, 'success', $3, NULL, 'CAPSTONE DATASET ENRICHER', $4, $5)",
    )
    .bind(&audit_id)
    .bind(ENRICHMENT_BATCH_ID)
    .bind("Presentation workflow scenarios added from the existing validated capstone schedule. No real-user audit activity was created.")
    .bind(json!({
        "data_origin": ENRICHMENT_DATA_ORIGIN,
        "batch_id": ENRICHMENT_BATCH_ID,
        "parent_batch_id": BATCH_ID,
        "presentation_context": true,
        "actor_label": "CAPSTONE DATASET ENRICHER",
        "incidents": metrics.incidents,
        "operational_requests": metrics.operational_requests,
        "notifications": metrics.notifications,
        "feedback": metrics.feedback.values().sum::<usize>(),
    }))
    .bind(Utc::now())
    .execute(pool)
    .await?;
    track_enrichment(pool, "audit_logs", &audit_id).await?;
    Ok(())
}

async fn validate_schedule_integrity(pool: &PgPool) -> Result<()> {
    let schedule_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'shifts'",
    )
    .bind(BATCH_ID)
    .fetch_one(pool)
    .await?;
    if schedule_count != 564 {
        bail!("Expected 564 tracked capstone shifts, found {schedule_count}")
    }

    let overlap_violations: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::BIGINT
        FROM shifts first_shift
        JOIN capstone_seed_records first_record
          ON first_record.batch_id = $1 AND first_record.table_name = 'shifts' AND first_record.record_id = first_shift.id
        JOIN shifts second_shift
          ON second_shift.guard_id = first_shift.guard_id
         AND second_shift.id > first_shift.id
         AND second_shift.start_time < first_shift.end_time
         AND second_shift.end_time > first_shift.start_time
        JOIN capstone_seed_records second_record
          ON second_record.batch_id = $1 AND second_record.table_name = 'shifts' AND second_record.record_id = second_shift.id
        "#,
    )
    .bind(BATCH_ID)
    .fetch_one(pool)
    .await?;
    if overlap_violations != 0 {
        bail!("Found {overlap_violations} capstone guard-overlap violations")
    }

    let rest_violations: i64 = sqlx::query_scalar(
        r#"
        WITH ordered AS (
            SELECT s.guard_id, s.start_time,
                   LAG(s.end_time) OVER (PARTITION BY s.guard_id ORDER BY s.start_time, s.id) AS previous_end
            FROM shifts s
            JOIN capstone_seed_records csr
              ON csr.batch_id = $1 AND csr.table_name = 'shifts' AND csr.record_id = s.id
        )
        SELECT COUNT(*)::BIGINT
        FROM ordered
        WHERE previous_end IS NOT NULL
          AND start_time - previous_end < INTERVAL '8 hours'
        "#,
    )
    .bind(BATCH_ID)
    .fetch_one(pool)
    .await?;
    if rest_violations != 0 {
        bail!("Found {rest_violations} capstone insufficient-rest violations")
    }
    Ok(())
}

async fn validate_enrichment_timing(pool: &PgPool) -> Result<()> {
    let readiness_after_start: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM guard_shift_readiness r JOIN shifts s ON s.id = r.shift_id JOIN capstone_seed_records csr ON csr.batch_id = $1 AND csr.table_name = 'guard_shift_readiness' AND csr.record_id = r.id WHERE r.created_at >= s.start_time",
    )
    .bind(ENRICHMENT_BATCH_ID)
    .fetch_one(pool)
    .await?;
    let classifications_before_incident: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM incident_severity_classifications c JOIN incidents i ON i.id = c.incident_id JOIN capstone_seed_records csr ON csr.batch_id = $1 AND csr.table_name = 'incident_severity_classifications' AND csr.record_id = c.id WHERE c.classified_at <= i.created_at",
    )
    .bind(ENRICHMENT_BATCH_ID)
    .fetch_one(pool)
    .await?;
    let invalid_tracking_points: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM tracking_points t JOIN capstone_seed_records csr ON csr.batch_id = $1 AND csr.table_name = 'tracking_points' AND csr.record_id = t.id WHERE NOT EXISTS (SELECT 1 FROM shifts s JOIN capstone_seed_records ssr ON ssr.batch_id = $2 AND ssr.table_name = 'shifts' AND ssr.record_id = s.id JOIN attendance a ON a.shift_id = s.id AND a.status = 'completed' WHERE s.guard_id = t.entity_id AND t.recorded_at > s.start_time AND t.recorded_at < s.end_time)",
    )
    .bind(ENRICHMENT_BATCH_ID)
    .bind(BATCH_ID)
    .fetch_one(pool)
    .await?;
    if readiness_after_start != 0
        || classifications_before_incident != 0
        || invalid_tracking_points != 0
    {
        bail!("Enrichment timing validation failed: readiness_after_start={readiness_after_start}, classifications_before_incident={classifications_before_incident}, invalid_tracking_points={invalid_tracking_points}")
    }
    Ok(())
}

fn print_enrichment_metrics(metrics: &EnrichmentMetrics) {
    println!(
        "ENRICHMENT REPORT: incidents={}, classifications={}, requests={}, request_events={}, notifications={}, readiness_day={}, readiness_evening={}, readiness_night={}, predictions={}, support_open={}, support_in_progress={}, support_resolved={}, evaluations={}, tracking_points={}, feedback_total={}, bisaya_guard_feedback={}, feedback_3={}, feedback_4={}, feedback_5={}",
        metrics.incidents,
        metrics.incident_classifications,
        metrics.operational_requests,
        metrics.operational_request_events,
        metrics.notifications,
        metrics.readiness.get("day").copied().unwrap_or_default(),
        metrics.readiness.get("evening").copied().unwrap_or_default(),
        metrics.readiness.get("night").copied().unwrap_or_default(),
        metrics.absence_predictions,
        metrics.support_tickets.get("open").copied().unwrap_or_default(),
        metrics.support_tickets.get("in_progress").copied().unwrap_or_default(),
        metrics.support_tickets.get("resolved").copied().unwrap_or_default(),
        metrics.client_evaluations,
        metrics.tracking_points,
        metrics.feedback.values().sum::<usize>(),
        metrics.bisaya_guard_feedback,
        metrics.feedback.get(&3).copied().unwrap_or_default(),
        metrics.feedback.get(&4).copied().unwrap_or_default(),
        metrics.feedback.get(&5).copied().unwrap_or_default(),
    );
}

async fn enrich_preflight(pool: &PgPool) -> Result<()> {
    let batch_complete: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM capstone_seed_batches WHERE batch_id = $1 AND status = 'complete')",
    )
    .bind(ENRICHMENT_BATCH_ID)
    .fetch_one(pool)
    .await?;
    if batch_complete {
        println!(
            "ENRICHMENT PREFLIGHT: batch already complete; existing ledger-tracked enrichment is idempotent."
        );
        return Ok(());
    }
    let shifts = ensure_enrichment_ready(pool).await?;
    let (_, supervisor_id, admin_id) = read_feedback_participants(pool).await?;
    println!("ENRICHMENT PREFLIGHT: source_completed_shifts={}, expected_incidents=7, expected_requests=9, expected_request_events=22, expected_notifications=23, expected_readiness=96, expected_predictions=4, expected_support_tickets=7, expected_evaluations=24, expected_tracking_points=18, expected_feedback=22, supervisor_feedback_user_present={}, admin_feedback_user_present={}", shifts.len(), !supervisor_id.is_empty(), !admin_id.is_empty());
    Ok(())
}

async fn enrich(pool: &PgPool) -> Result<()> {
    ensure_ledger(pool).await?;
    let existing_status: Option<String> =
        sqlx::query_scalar("SELECT status FROM capstone_seed_batches WHERE batch_id = $1")
            .bind(ENRICHMENT_BATCH_ID)
            .fetch_optional(pool)
            .await?;
    if existing_status.as_deref() == Some("complete") {
        println!(
            "Enrichment batch {} is already complete; no records were duplicated.",
            ENRICHMENT_BATCH_ID
        );
        status(pool).await?;
        return Ok(());
    }
    if existing_status.is_some() {
        reset_tracked_batch(pool, ENRICHMENT_BATCH_ID).await?;
    }

    let shifts = ensure_enrichment_ready(pool).await?;
    enrich_preflight(pool).await?;
    let reference_at =
        DateTime::parse_from_rfc3339(&require_env("CAPSTONE_REFERENCE_DATE")?)?.with_timezone(&Utc);
    sqlx::query("INSERT INTO capstone_seed_batches (batch_id, data_origin, reference_at, status, metadata) VALUES ($1, $2, $3, 'running', $4)")
        .bind(ENRICHMENT_BATCH_ID)
        .bind(ENRICHMENT_DATA_ORIGIN)
        .bind(reference_at)
        .bind(json!({
            "parentBatchId": BATCH_ID,
            "presentationContext": true,
            "source": "existing validated capstone shifts, attendance, replacements, and roster",
            "historyThrough": "2026-10-16",
            "auditActor": "CAPSTONE DATASET ENRICHER",
        }))
        .execute(pool)
        .await?;

    let mut metrics = EnrichmentMetrics::default();
    let incidents = seed_incident_scenarios(pool, &shifts, &mut metrics).await?;
    let requests = seed_operational_request_scenarios(pool, &shifts, &mut metrics).await?;
    seed_readiness(pool, &shifts, &mut metrics).await?;
    let tickets = seed_support_tickets(pool, &shifts, &mut metrics).await?;
    seed_workflow_notifications(pool, &requests, &incidents, &tickets, &mut metrics).await?;
    seed_absence_predictions(pool, &mut metrics).await?;
    seed_client_evaluations(pool, &shifts, &mut metrics).await?;
    seed_tracking_points(pool, &shifts, &mut metrics).await?;
    seed_feedback(pool, &shifts, &mut metrics).await?;
    seed_enrichment_audit(pool, &metrics).await?;
    validate_enrichment_timing(pool).await?;
    sqlx::query("UPDATE capstone_seed_batches SET status = 'complete', completed_at = CURRENT_TIMESTAMP WHERE batch_id = $1")
        .bind(ENRICHMENT_BATCH_ID)
        .execute(pool)
        .await?;
    print_enrichment_metrics(&metrics);
    Ok(())
}

fn validate_plan(planned: &[PlannedShift], sites: &[SourceSite]) -> Result<()> {
    let expected_slots = sites.len() * ShiftRotation::ALL.len() * PLANNED_DAY as usize;
    if planned.len() != expected_slots {
        bail!(
            "Expected {} coverage slots, generated {}",
            expected_slots,
            planned.len()
        )
    }

    let mut coverage = BTreeMap::new();
    let mut per_guard: HashMap<usize, Vec<&PlannedShift>> = HashMap::new();
    for assignment in planned {
        *coverage
            .entry((
                assignment.site_index,
                assignment.day,
                assignment.rotation.label(),
            ))
            .or_insert(0_usize) += 1;
        per_guard
            .entry(assignment.guard_index)
            .or_default()
            .push(assignment);
    }
    if coverage.values().any(|count| *count != 1) {
        bail!("At least one site/date/rotation has missing or duplicate planned coverage")
    }
    for day in [4_u32, 11] {
        let sunday_slots = planned
            .iter()
            .filter(|assignment| assignment.day == day)
            .count();
        if sunday_slots != sites.len() * ShiftRotation::ALL.len() {
            bail!("October {} does not have complete Sunday coverage", day)
        }
    }
    for assignments in per_guard.values() {
        for (index, current) in assignments.iter().enumerate() {
            for other in assignments.iter().skip(index + 1) {
                if current.start < other.end && current.end > other.start {
                    bail!("A guard has overlapping planned shifts")
                }
                let rest = if current.end <= other.start {
                    other.start - current.end
                } else {
                    current.start - other.end
                };
                if rest < Duration::hours(MIN_REST_HOURS) {
                    bail!("A guard has an insufficient-rest planned assignment")
                }
            }
        }
    }
    Ok(())
}

async fn build_seed_plan(
    pool: &PgPool,
) -> Result<(
    Vec<SourceGuard>,
    Vec<SourceSite>,
    Vec<Vec<usize>>,
    Vec<PlannedShift>,
)> {
    let guards = read_live_guards(pool).await?;
    let sites = read_live_sites(pool).await?;
    let history = read_assignment_history(pool).await?;
    let rosters = build_primary_rosters(&guards, &sites, &history)?;
    let planned = plan_shift_coverage(&guards, &sites, &rosters)?;
    validate_plan(&planned, &sites)?;
    Ok((guards, sites, rosters, planned))
}

fn print_seed_plan(
    guards: &[SourceGuard],
    sites: &[SourceSite],
    rosters: &[Vec<usize>],
    planned: &[PlannedShift],
) {
    let address_count = guards
        .iter()
        .filter(|guard| {
            guard
                .address
                .as_deref()
                .is_some_and(|address| !address.trim().is_empty())
        })
        .count();
    println!(
        "CAPSTONE PREFLIGHT: {} active Tagum sites; {} participating guards.",
        sites.len(),
        guards.len()
    );
    println!("Guard location fields: address present for {}/{} guards; no guard latitude/longitude fields are available, so geographic distance is not calculated.", address_count, guards.len());
    println!("Selected Tagum sites:");
    for site in sites {
        println!(
            "SITE|{}|{}|{}|{:.6}|{:.6}",
            site.id,
            site.name,
            site.address.as_deref().unwrap_or("No address"),
            site.latitude,
            site.longitude
        );
    }
    println!("SITE | PRIMARY GUARDS | RELIEF GUARDS | DAY | EVENING | NIGHT");
    for (site_index, roster) in rosters.iter().enumerate() {
        let primary = roster
            .iter()
            .map(|guard_index| {
                guards[*guard_index]
                    .guard_code
                    .as_deref()
                    .unwrap_or(&guards[*guard_index].full_name)
            })
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "{} | {} | Rotating off-duty members of this site roster | covered | covered | covered",
            sites[site_index].name, primary
        );
    }
    println!(
        "Coverage slots: {} ({} day, {} evening, {} night).",
        planned.len(),
        planned
            .iter()
            .filter(|assignment| assignment.rotation == ShiftRotation::Day)
            .count(),
        planned
            .iter()
            .filter(|assignment| assignment.rotation == ShiftRotation::Evening)
            .count(),
        planned
            .iter()
            .filter(|assignment| assignment.rotation == ShiftRotation::Night)
            .count()
    );
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
    let (guards, sites, rosters, planned) = build_seed_plan(pool).await?;
    reset_batch(pool).await?;
    print_seed_plan(&guards, &sites, &rosters, &planned);
    let reference_at =
        DateTime::parse_from_rfc3339(&require_env("CAPSTONE_REFERENCE_DATE")?)?.with_timezone(&Utc);
    sqlx::query("INSERT INTO capstone_seed_batches (batch_id, data_origin, reference_at, status, metadata) VALUES ($1, $2, $3, 'running', $4)")
        .bind(BATCH_ID)
        .bind(DATA_ORIGIN)
        .bind(reference_at)
        .bind(json!({
            "scope":"Tagum City, Davao del Norte",
            "dateRange":"2026-10-01 through 2026-10-17",
            "historyThrough":"2026-10-16",
            "plannedFrom":"2026-10-17",
            "source":"existing live master data",
            "presentationContext":true,
            "auditActor":"CAPSTONE DATASET SEEDER",
            "locationAssignment":"existing schedule history, then stable deterministic roster; no guard coordinates available"
        }))
        .execute(pool)
        .await?;

    let metrics = seed_shift_activity(pool, &guards, &sites, &rosters, &planned).await?;
    seed_derived_performance(pool, &guards, &metrics).await?;
    seed_presentation_audit(pool, &metrics, sites.len()).await?;
    sqlx::query("UPDATE capstone_seed_batches SET status = 'complete', completed_at = CURRENT_TIMESTAMP WHERE batch_id = $1")
        .bind(BATCH_ID).execute(pool).await?;
    print_seed_metrics(&metrics, &planned, &guards, &sites, &rosters);
    Ok(())
}

fn print_seed_metrics(
    metrics: &SeedMetrics,
    planned: &[PlannedShift],
    guards: &[SourceGuard],
    sites: &[SourceSite],
    rosters: &[Vec<usize>],
) {
    let historical_slots = planned
        .iter()
        .filter(|assignment| assignment.day <= HISTORY_LAST_DAY)
        .count();
    let shift_counts = metrics
        .guard_performance
        .values()
        .map(|performance| performance.assigned)
        .collect::<Vec<_>>();
    let average = if shift_counts.is_empty() {
        0.0
    } else {
        shift_counts.iter().sum::<i32>() as f64 / shift_counts.len() as f64
    };
    println!(
        "SEED REPORT: sites={}, guards={}, scheduled_slots={}, completed_history={}, october_17_planned={}, day={}, evening={}, night={}, sunday_slots={}, absences={}, replacements={}, late_arrivals={}, cross_site_assignments={}, average_historical_shifts={:.2}, minimum_historical_shifts={}, maximum_historical_shifts={}",
        sites.len(),
        guards.len(),
        planned.len(),
        historical_slots,
        metrics.planned_october_17,
        metrics.day_shifts,
        metrics.evening_shifts,
        metrics.night_shifts,
        planned.iter().filter(|assignment| matches!(assignment.day, 4 | 11)).count(),
        metrics.absences,
        metrics.replacements,
        metrics.late_arrivals,
        metrics.cross_site_assignments,
        average,
        shift_counts.iter().min().copied().unwrap_or_default(),
        shift_counts.iter().max().copied().unwrap_or_default(),
    );
    print_seed_plan(guards, sites, rosters, planned);
}

async fn preflight(pool: &PgPool) -> Result<()> {
    ensure_ledger(pool).await?;
    let (guards, sites, rosters, planned) = build_seed_plan(pool).await?;
    print_seed_plan(&guards, &sites, &rosters, &planned);
    Ok(())
}

async fn validate(pool: &PgPool) -> Result<()> {
    validate_schedule_integrity(pool).await?;
    let future_attendance: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM attendance WHERE shift_id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'shifts') AND check_in_time >= $2",
    )
    .bind(BATCH_ID)
    .bind(manila_time(PLANNED_DAY, 0, 0)?)
    .fetch_one(pool)
    .await?;
    if future_attendance != 0 {
        bail!(
            "Found {} attendance records for future October 17 shifts",
            future_attendance
        )
    }

    let scheduled_october_17: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM shifts WHERE id IN (SELECT record_id FROM capstone_seed_records WHERE batch_id = $1 AND table_name = 'shifts') AND start_time >= $2 AND status = 'scheduled'",
    )
    .bind(BATCH_ID)
    .bind(manila_time(PLANNED_DAY, 0, 0)?)
    .fetch_one(pool)
    .await?;
    println!(
        "VALIDATION: future_attendance=0, october_17_scheduled={}, overlap_violations=0, insufficient_rest_violations=0",
        scheduled_october_17
    );
    let enrichment_complete: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM capstone_seed_batches WHERE batch_id = $1 AND status = 'complete')",
    )
    .bind(ENRICHMENT_BATCH_ID)
    .fetch_one(pool)
    .await?;
    if enrichment_complete {
        validate_enrichment_timing(pool).await?;
        println!("ENRICHMENT VALIDATION: causal timestamps and completed-shift tracking points are valid.");
    }
    validate_audit_activity(pool).await?;
    Ok(())
}

async fn print_batch_status(pool: &PgPool, batch_id: &str) -> Result<bool> {
    let rows = sqlx::query(
        "SELECT table_name, COUNT(*)::BIGINT AS count FROM capstone_seed_records WHERE batch_id = $1 GROUP BY table_name ORDER BY table_name",
    )
    .bind(batch_id)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
        return Ok(false);
    }
    println!("BATCH={batch_id}");
    for row in rows {
        println!(
            "{}={}",
            row.try_get::<String, _>("table_name")?,
            row.try_get::<i64, _>("count")?
        );
    }
    Ok(true)
}

async fn status(pool: &PgPool) -> Result<()> {
    ensure_ledger(pool).await?;
    let base_present = print_batch_status(pool, BATCH_ID).await?;
    let enrichment_present = print_batch_status(pool, ENRICHMENT_BATCH_ID).await?;
    let audit_activity_present = print_batch_status(pool, AUDIT_ACTIVITY_BATCH_ID).await?;
    if !base_present && !enrichment_present && !audit_activity_present {
        println!("No {} dataset is present.", BATCH_ID);
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let command = env::args().nth(1).unwrap_or_else(|| "status".to_string());
    let result = async {
        let target_url = verify_live_target(&command)?;
        verify_backup_confirmation(&command)?;
        let target_pool = connect(&target_url, "explicit live target").await?;
        verify_protected_superadmin(&target_pool).await?;
        match command.as_str() {
            "seed" => {
                seed(&target_pool).await?;
                verify_protected_superadmin(&target_pool).await?;
                status(&target_pool).await?;
                validate(&target_pool).await?;
            }
            "reset" => {
                ensure_ledger(&target_pool).await?;
                reset_batch(&target_pool).await?;
                verify_protected_superadmin(&target_pool).await?;
                println!("Reset only batch {}.", BATCH_ID);
            }
            "status" => status(&target_pool).await?,
            "preflight" => preflight(&target_pool).await?,
            "enrich-preflight" => enrich_preflight(&target_pool).await?,
            "enrich" => {
                enrich(&target_pool).await?;
                verify_protected_superadmin(&target_pool).await?;
                status(&target_pool).await?;
                validate(&target_pool).await?;
            }
            "audit-preflight" => audit_activity_preflight(&target_pool).await?,
            "seed-audit-activity" => {
                audit_activity_preflight(&target_pool).await?;
                seed_audit_activity(&target_pool).await?;
                verify_protected_superadmin(&target_pool).await?;
                status(&target_pool).await?;
                validate(&target_pool).await?;
                print_capstone_audit_counts(&target_pool, "AFTER").await?;
            }
            "validate" => validate(&target_pool).await?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Timelike};

    fn guard(index: usize) -> SourceGuard {
        SourceGuard {
            id: format!("guard-{index}"),
            full_name: format!("Guard {index}"),
            guard_code: Some(format!("G-{index:04}")),
            address: None,
            currently_available: true,
        }
    }

    fn site(index: usize) -> SourceSite {
        SourceSite {
            id: format!("site-{index}"),
            name: format!("Tagum Site {index}"),
            address: Some("Tagum City, Davao del Norte".to_string()),
            latitude: 7.45 + index as f64 * 0.01,
            longitude: 125.80 + index as f64 * 0.01,
        }
    }

    #[test]
    fn stable_rosters_cover_all_rotations_without_overlap_or_short_rest() {
        let guards = (0..15).map(guard).collect::<Vec<_>>();
        let sites = (0..3).map(site).collect::<Vec<_>>();
        let rosters = build_primary_rosters(&guards, &sites, &HashMap::new()).expect("rosters");
        let planned = plan_shift_coverage(&guards, &sites, &rosters).expect("coverage plan");

        validate_plan(&planned, &sites).expect("valid schedule");
        assert_eq!(planned.len(), 3 * 3 * 17);
        assert!(planned.iter().all(|assignment| !assignment.is_cross_site));
        assert_eq!(
            planned
                .iter()
                .filter(|assignment| assignment.day == 4)
                .count(),
            9
        );
        assert_eq!(
            planned
                .iter()
                .filter(|assignment| assignment.day == 11)
                .count(),
            9
        );
    }

    #[test]
    fn night_rotation_ends_on_the_following_calendar_day() {
        let start = ShiftRotation::Night.start(10).expect("night start");
        let end = start + Duration::hours(8);
        let offset = FixedOffset::east_opt(MANILA_OFFSET_SECONDS).expect("Manila offset");
        let local_start = start.with_timezone(&offset);
        let local_end = end.with_timezone(&offset);

        assert_eq!(local_start.day(), 10);
        assert_eq!(local_start.hour(), 23);
        assert_eq!(local_end.day(), 11);
        assert_eq!(local_end.hour(), 7);
    }

    #[test]
    fn synthetic_audit_allow_list_excludes_sensitive_account_operations() {
        let actions = synthetic_audit_actions();

        assert!(actions.contains(&"AUTH_LOGIN_ATTEMPT"));
        assert!(actions.contains(&"SUPERVISOR_INCIDENT_REVIEWED"));
        assert!(actions.contains(&"ADMIN_REPORT_VIEWED"));
        assert!(!actions.iter().any(|action| action.contains("PASSWORD")));
        assert!(!actions.iter().any(|action| action.contains("MFA")));
        assert!(!actions.iter().any(|action| action.contains("DELETE")));
        assert!(!actions.iter().any(|action| action.contains("ROLE")));
    }
}
