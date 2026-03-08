# Railway Live Account Provisioning Runbook

## Purpose
Use this runbook to:
- Promote Dwight to `superadmin`
- Add or update `admin`, `supervisor`, and `guard` accounts in production

## File
- `railway_live_account_provision.sql`

The SQL script is backward-compatible with older live schemas and will add missing user columns (`approval_status`, `created_by`, `license_*`, `address`) before account updates/inserts.

## Option A: Railway Web UI (recommended)
1. Open Railway project dashboard.
2. Open the Postgres service.
3. Open the SQL editor.
4. Paste the contents of `railway_live_account_provision.sql`.
5. Replace all `{{PLACEHOLDER}}` values.
6. Run the script.
7. Run the post-check query block at the bottom of the script.

## Option B: psql against Railway DB
1. Get the production `DATABASE_URL` from Railway service variables.
2. Save the filled SQL script locally (without placeholders).
3. Run:

```bash
psql "$DATABASE_URL" -f railway_live_account_provision.sql
```

## Required placeholder values
- `{{DWIGHT_EMAIL}}`
- `{{DWIGHT_USERNAME}}`
- `{{ADMIN_EMAIL}}`, `{{ADMIN_USERNAME}}`, `{{ADMIN_PASSWORD}}`, `{{ADMIN_FULL_NAME}}`, `{{ADMIN_PHONE}}`, `{{ADMIN_LICENSE_NUMBER}}`, `{{ADMIN_ADDRESS}}`
- `{{SUPERVISOR_EMAIL}}`, `{{SUPERVISOR_USERNAME}}`, `{{SUPERVISOR_PASSWORD}}`, `{{SUPERVISOR_FULL_NAME}}`, `{{SUPERVISOR_PHONE}}`, `{{SUPERVISOR_LICENSE_NUMBER}}`, `{{SUPERVISOR_ADDRESS}}`
- `{{GUARD_EMAIL}}`, `{{GUARD_USERNAME}}`, `{{GUARD_PASSWORD}}`, `{{GUARD_FULL_NAME}}`, `{{GUARD_PHONE}}`, `{{GUARD_LICENSE_NUMBER}}`, `{{GUARD_ADDRESS}}`

## Validation checklist
- Dwight row shows `role = superadmin`, `verified = true`, `approval_status = approved`.
- Admin/supervisor/guard rows exist and have expected roles.
- New users can log in from the production frontend.
- Admin/supervisor can open their dashboards and fetch protected data.
- Guard can log in and cannot access restricted elevated endpoints.
