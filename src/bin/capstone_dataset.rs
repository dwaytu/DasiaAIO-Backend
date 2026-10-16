use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env, process,
};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Duration, FixedOffset, TimeZone, Utc};
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use uuid::Uuid;

const BATCH_ID: &str = "capstone-live-october-2026";
const REQUIRED_CONFIRMATION: &str = "LIVE_CAPSTONE_DATASET_CONFIRMED";
const MANILA_OFFSET_SECONDS: i32 = 8 * 60 * 60;
const DATA_ORIGIN: &str = "capstone_presentation_seed";
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

    if !matches!(
        command,
        "seed" | "reset" | "status" | "preflight" | "validate"
    ) {
        bail!("Usage: cargo run --bin capstone-dataset -- <seed|reset|status|preflight|validate>")
    }
    Ok(target_url)
}

fn verify_backup_confirmation(command: &str) -> Result<()> {
    if !matches!(command, "seed" | "reset") {
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
        "VALIDATION: future_attendance=0, october_17_scheduled={}",
        scheduled_october_17
    );
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
}
