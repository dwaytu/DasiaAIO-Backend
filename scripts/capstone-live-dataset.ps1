param(
  [ValidateSet("seed", "reset", "status")]
  [string]$Command = "status"
)

$ErrorActionPreference = "Stop"

if ($env:CAPSTONE_DATASET_MODE -ne "true" -or $env:CAPSTONE_TARGET_ENVIRONMENT -ne "production") {
  throw "Run only with CAPSTONE_DATASET_MODE=true and CAPSTONE_TARGET_ENVIRONMENT=production."
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

cargo run --manifest-path "$PSScriptRoot/../Cargo.toml" --bin capstone-dataset -- $Command
