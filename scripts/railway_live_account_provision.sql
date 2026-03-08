-- Railway production account provisioning script
-- Usage: run in Railway Postgres SQL console (or psql against Railway DATABASE_URL)
-- Replace placeholder values before execution.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Ensure newer user-account columns exist in older production schemas.
ALTER TABLE users ADD COLUMN IF NOT EXISTS approval_status VARCHAR(20) NOT NULL DEFAULT 'approved';
ALTER TABLE users ADD COLUMN IF NOT EXISTS created_by VARCHAR(36);
ALTER TABLE users ADD COLUMN IF NOT EXISTS license_number VARCHAR(50);
ALTER TABLE users ADD COLUMN IF NOT EXISTS license_issued_date TIMESTAMP WITH TIME ZONE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS license_expiry_date TIMESTAMP WITH TIME ZONE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS address TEXT;

-- 1) Promote Dwight to superadmin.
UPDATE users
SET
  role = 'superadmin',
  verified = TRUE,
  approval_status = 'approved',
  updated_at = NOW()
WHERE
  LOWER(email) = LOWER('{{DWIGHT_EMAIL}}')
  OR LOWER(username) = LOWER('{{DWIGHT_USERNAME}}');

-- 2) Ensure admin/supervisor/guard accounts exist and are active.
-- Passwords are bcrypt-hashed via pgcrypto crypt/gen_salt.
WITH seed_accounts AS (
  SELECT
    'admin'::text AS role,
    '{{ADMIN_EMAIL}}'::text AS email,
    '{{ADMIN_USERNAME}}'::text AS username,
    '{{ADMIN_PASSWORD}}'::text AS plain_password,
    '{{ADMIN_FULL_NAME}}'::text AS full_name,
    '{{ADMIN_PHONE}}'::text AS phone_number,
    '{{ADMIN_LICENSE_NUMBER}}'::text AS license_number,
    '{{ADMIN_ADDRESS}}'::text AS address
  UNION ALL
  SELECT
    'supervisor',
    '{{SUPERVISOR_EMAIL}}',
    '{{SUPERVISOR_USERNAME}}',
    '{{SUPERVISOR_PASSWORD}}',
    '{{SUPERVISOR_FULL_NAME}}',
    '{{SUPERVISOR_PHONE}}',
    '{{SUPERVISOR_LICENSE_NUMBER}}',
    '{{SUPERVISOR_ADDRESS}}'
  UNION ALL
  SELECT
    'guard',
    '{{GUARD_EMAIL}}',
    '{{GUARD_USERNAME}}',
    '{{GUARD_PASSWORD}}',
    '{{GUARD_FULL_NAME}}',
    '{{GUARD_PHONE}}',
    '{{GUARD_LICENSE_NUMBER}}',
    '{{GUARD_ADDRESS}}'
)
INSERT INTO users (
  id,
  email,
  username,
  password,
  role,
  full_name,
  phone_number,
  license_number,
  license_issued_date,
  license_expiry_date,
  address,
  verified,
  approval_status,
  created_by,
  created_at,
  updated_at
)
SELECT
  gen_random_uuid()::text,
  s.email,
  s.username,
  crypt(s.plain_password, gen_salt('bf', 12)),
  s.role,
  s.full_name,
  s.phone_number,
  NULLIF(s.license_number, ''),
  NOW(),
  NOW() + INTERVAL '2 years',
  NULLIF(s.address, ''),
  TRUE,
  'approved',
  NULL,
  NOW(),
  NOW()
FROM seed_accounts s
ON CONFLICT (email) DO UPDATE
SET
  username = EXCLUDED.username,
  role = EXCLUDED.role,
  full_name = EXCLUDED.full_name,
  phone_number = EXCLUDED.phone_number,
  license_number = EXCLUDED.license_number,
  address = EXCLUDED.address,
  verified = TRUE,
  approval_status = 'approved',
  updated_at = NOW();

COMMIT;

-- Post-check query:
-- SELECT email, username, role, verified, approval_status
-- FROM users
-- WHERE LOWER(email) IN (
--   LOWER('{{DWIGHT_EMAIL}}'),
--   LOWER('{{ADMIN_EMAIL}}'),
--   LOWER('{{SUPERVISOR_EMAIL}}'),
--   LOWER('{{GUARD_EMAIL}}')
-- )
-- ORDER BY role DESC, email;
