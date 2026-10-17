param(
  [ValidateSet("seed", "reset", "status", "preflight", "validate", "enrich", "enrich-preflight", "audit-preflight", "seed-audit-activity")]
  [string]$Command = "status"
)

$ErrorActionPreference = "Stop"

if ($env:CAPSTONE_DATASET_MODE -ne "true" -or $env:CAPSTONE_TARGET_ENVIRONMENT -notin @("production", "capstone_presentation")) {
  throw "Run only with CAPSTONE_DATASET_MODE=true and CAPSTONE_TARGET_ENVIRONMENT set to production or capstone_presentation."
}

if ($env:CAPSTONE_SEED_CONFIRM -ne "LIVE_CAPSTONE_DATASET_CONFIRMED") {
  throw "Set CAPSTONE_SEED_CONFIRM=LIVE_CAPSTONE_DATASET_CONFIRMED before running this command."
}

if ([string]::IsNullOrWhiteSpace($env:CAPSTONE_TARGET_DATABASE_URL)) {
  throw "Set CAPSTONE_TARGET_DATABASE_URL explicitly; the script will not fall back to DATABASE_URL."
}

if ([string]::IsNullOrWhiteSpace($env:CAPSTONE_PROTECTED_SUPERADMIN_ID)) {
  throw "Set CAPSTONE_PROTECTED_SUPERADMIN_ID to the active production Superadmin ID before running this command."
}

if ($Command -in @("seed", "reset", "enrich", "seed-audit-activity") -and [string]::IsNullOrWhiteSpace($env:CAPSTONE_BACKUP_VERIFIED_AT)) {
  throw "Set CAPSTONE_BACKUP_VERIFIED_AT to the RFC 3339 time of a verified target-database backup before $Command."
}

if ($Command -in @("audit-preflight", "seed-audit-activity")) {
  if ($env:CAPSTONE_TARGET_ENVIRONMENT -ne "capstone_presentation" -or $env:CAPSTONE_PRESENTATION_ENVIRONMENT -ne "true") {
    throw "Synthetic audit activity requires CAPSTONE_TARGET_ENVIRONMENT=capstone_presentation and CAPSTONE_PRESENTATION_ENVIRONMENT=true."
  }
  if ($env:CAPSTONE_ALLOW_SYNTHETIC_AUDIT_HISTORY -ne "true") {
    throw "Set CAPSTONE_ALLOW_SYNTHETIC_AUDIT_HISTORY=true for synthetic audit activity."
  }
}

cargo run --manifest-path "$PSScriptRoot/../Cargo.toml" --bin capstone-dataset -- $Command
