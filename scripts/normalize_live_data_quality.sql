-- Controlled live data-quality normalization.
-- Run only after a verified backup and only against the intended environment.
-- Every changed value is copied to data_quality_change_log in the same transaction.

BEGIN;

WITH candidates AS (
    SELECT
        id,
        full_name AS original_value,
        regexp_replace(
            regexp_replace(BTRIM(full_name), '\s+', ' ', 'g'),
            '\s*,\s*',
            ', ',
            'g'
        ) AS cleaned_value
    FROM users
    WHERE LOWER(BTRIM(COALESCE(role, ''))) = 'guard'
), updated AS (
    UPDATE users AS target
    SET full_name = candidates.cleaned_value, updated_at = NOW()
    FROM candidates
    WHERE target.id = candidates.id
      AND candidates.cleaned_value IS DISTINCT FROM candidates.original_value
    RETURNING target.id, candidates.original_value, candidates.cleaned_value
)
INSERT INTO data_quality_change_log (
    id, entity_type, entity_id, field_name, original_value, cleaned_value, change_source, metadata
)
SELECT
    md5(random()::TEXT || clock_timestamp()::TEXT || id),
    'user', id, 'full_name', original_value, cleaned_value,
    'controlled_live_data_quality_normalization',
    jsonb_build_object('rule', 'trim-collapse-space-and-normalize-comma-spacing')
FROM updated;

WITH candidates AS (
    SELECT
        id,
        phone_number AS original_value,
        CASE
            WHEN regexp_replace(phone_number, '[^0-9]', '', 'g') ~ '^0[0-9]{10}$'
                THEN '+63' || substring(regexp_replace(phone_number, '[^0-9]', '', 'g') FROM 2)
            WHEN regexp_replace(phone_number, '[^0-9]', '', 'g') ~ '^63[0-9]{10}$'
                THEN '+' || regexp_replace(phone_number, '[^0-9]', '', 'g')
            WHEN regexp_replace(phone_number, '[^0-9]', '', 'g') ~ '^9[0-9]{9}$'
                THEN '+63' || regexp_replace(phone_number, '[^0-9]', '', 'g')
            ELSE regexp_replace(BTRIM(phone_number), '\s+', ' ', 'g')
        END AS cleaned_value
    FROM users
    WHERE LOWER(BTRIM(COALESCE(role, ''))) = 'guard'
), updated AS (
    UPDATE users AS target
    SET phone_number = candidates.cleaned_value, updated_at = NOW()
    FROM candidates
    WHERE target.id = candidates.id
      AND candidates.cleaned_value IS DISTINCT FROM candidates.original_value
      AND candidates.cleaned_value <> ''
    RETURNING target.id, candidates.original_value, candidates.cleaned_value
)
INSERT INTO data_quality_change_log (
    id, entity_type, entity_id, field_name, original_value, cleaned_value, change_source, metadata
)
SELECT
    md5(random()::TEXT || clock_timestamp()::TEXT || id),
    'user', id, 'phone_number', original_value, cleaned_value,
    'controlled_live_data_quality_normalization',
    jsonb_build_object('rule', 'canonical-philippine-mobile-format-when-unambiguous')
FROM updated;

WITH candidates AS (
    SELECT
        id,
        license_number AS original_value,
        CASE
            WHEN LOWER(BTRIM(COALESCE(license_number, ''))) IN ('', '-', 'n/a', 'na', 'none', 'null') THEN NULL
            ELSE UPPER(regexp_replace(BTRIM(license_number), '\s+', '', 'g'))
        END AS cleaned_value
    FROM users
    WHERE LOWER(BTRIM(COALESCE(role, ''))) = 'guard'
), updated AS (
    UPDATE users AS target
    SET license_number = candidates.cleaned_value, updated_at = NOW()
    FROM candidates
    WHERE target.id = candidates.id
      AND candidates.cleaned_value IS DISTINCT FROM candidates.original_value
    RETURNING target.id, candidates.original_value, candidates.cleaned_value
)
INSERT INTO data_quality_change_log (
    id, entity_type, entity_id, field_name, original_value, cleaned_value, change_source, metadata
)
SELECT
    md5(random()::TEXT || clock_timestamp()::TEXT || id),
    'user', id, 'license_number', original_value, cleaned_value,
    'controlled_live_data_quality_normalization',
    jsonb_build_object('rule', 'uppercase-and-remove-whitespace-or-clear-placeholder')
FROM updated;

WITH candidates AS (
    SELECT
        id,
        make AS original_value,
        CASE regexp_replace(UPPER(BTRIM(COALESCE(make, ''))), '[^A-Z0-9]', '', 'g')
            WHEN 'ARMSCOR' THEN 'Armscor'
            WHEN 'ROCKISLAND' THEN 'Rock Island'
            WHEN 'SMITHWESSON' THEN 'Smith & Wesson'
            ELSE regexp_replace(BTRIM(COALESCE(make, '')), '\s+', ' ', 'g')
        END AS cleaned_value
    FROM firearms
), updated AS (
    UPDATE firearms AS target
    SET make = candidates.cleaned_value, updated_at = NOW()
    FROM candidates
    WHERE target.id = candidates.id
      AND candidates.cleaned_value IS DISTINCT FROM candidates.original_value
    RETURNING target.id, candidates.original_value, candidates.cleaned_value
)
INSERT INTO data_quality_change_log (
    id, entity_type, entity_id, field_name, original_value, cleaned_value, change_source, metadata
)
SELECT
    md5(random()::TEXT || clock_timestamp()::TEXT || id),
    'firearm', id, 'make', original_value, cleaned_value,
    'controlled_live_data_quality_normalization',
    jsonb_build_object('rule', 'canonical-known-brand-label')
FROM updated;

WITH candidates AS (
    SELECT
        id,
        serial_number AS original_value,
        UPPER(regexp_replace(BTRIM(serial_number), '\s+', '', 'g')) AS cleaned_value
    FROM firearms
    WHERE LOWER(BTRIM(COALESCE(serial_number, ''))) NOT IN ('', '-', 'n/a', 'na', 'none', 'null')
), updated AS (
    UPDATE firearms AS target
    SET serial_number = candidates.cleaned_value, updated_at = NOW()
    FROM candidates
    WHERE target.id = candidates.id
      AND candidates.cleaned_value IS DISTINCT FROM candidates.original_value
    RETURNING target.id, candidates.original_value, candidates.cleaned_value
)
INSERT INTO data_quality_change_log (
    id, entity_type, entity_id, field_name, original_value, cleaned_value, change_source, metadata
)
SELECT
    md5(random()::TEXT || clock_timestamp()::TEXT || id),
    'firearm', id, 'serial_number', original_value, cleaned_value,
    'controlled_live_data_quality_normalization',
    jsonb_build_object('rule', 'uppercase-and-remove-whitespace')
FROM updated;

WITH candidates AS (
    SELECT id, name AS original_value, regexp_replace(BTRIM(name), '\s+', ' ', 'g') AS cleaned_value
    FROM clients
), updated AS (
    UPDATE clients AS target
    SET name = candidates.cleaned_value, updated_at = NOW()
    FROM candidates
    WHERE target.id = candidates.id
      AND candidates.cleaned_value IS DISTINCT FROM candidates.original_value
    RETURNING target.id, candidates.original_value, candidates.cleaned_value
)
INSERT INTO data_quality_change_log (
    id, entity_type, entity_id, field_name, original_value, cleaned_value, change_source, metadata
)
SELECT
    md5(random()::TEXT || clock_timestamp()::TEXT || id),
    'client', id, 'name', original_value, cleaned_value,
    'controlled_live_data_quality_normalization',
    jsonb_build_object('rule', 'trim-and-collapse-whitespace')
FROM updated;

COMMIT;

-- Review-only report. Do not infer or rewrite these name orders automatically.
SELECT id, full_name
FROM users
WHERE LOWER(BTRIM(COALESCE(role, ''))) = 'guard'
  AND NULLIF(BTRIM(full_name), '') IS NOT NULL
  AND full_name NOT LIKE '%,%'
ORDER BY full_name;
