-- Human-readable, immutable operational identifiers for guard accounts.
ALTER TABLE users ADD COLUMN IF NOT EXISTS guard_code VARCHAR(32);

CREATE SEQUENCE IF NOT EXISTS guard_code_sequence START WITH 1;

CREATE OR REPLACE FUNCTION sentinel_assign_guard_code()
RETURNS TRIGGER AS $$
BEGIN
    IF LOWER(BTRIM(NEW.role)) IN ('guard', 'user') AND NEW.guard_code IS NULL THEN
        PERFORM pg_advisory_xact_lock(9042107);
        NEW.guard_code := 'G-' || LPAD(nextval('guard_code_sequence')::TEXT, 4, '0');
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_assign_guard_code ON users;
CREATE TRIGGER users_assign_guard_code
    BEFORE INSERT OR UPDATE OF role ON users
    FOR EACH ROW
    EXECUTE FUNCTION sentinel_assign_guard_code();

DO $$
DECLARE
    max_code BIGINT;
    sequence_value BIGINT;
    sequence_called BOOLEAN;
BEGIN
    PERFORM pg_advisory_xact_lock(9042107);
    SELECT COALESCE(MAX((substring(guard_code FROM '^G-([0-9]+)$'))::BIGINT), 0)
    INTO max_code
    FROM users
    WHERE guard_code ~ '^G-[0-9]+$';
    SELECT last_value, is_called INTO sequence_value, sequence_called
    FROM guard_code_sequence;
    PERFORM setval(
        'guard_code_sequence',
        GREATEST(max_code, sequence_value, 1),
        sequence_called OR max_code >= 1
    );
    UPDATE users
    SET guard_code = 'G-' || LPAD(nextval('guard_code_sequence')::TEXT, 4, '0')
    WHERE LOWER(BTRIM(role)) IN ('guard', 'user')
      AND guard_code IS NULL;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_guard_code_unique
    ON users (guard_code)
    WHERE guard_code IS NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.table_constraints
        WHERE table_name = 'users' AND constraint_name = 'users_guard_code_format_check'
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT users_guard_code_format_check
            CHECK (guard_code IS NULL OR guard_code ~ '^G-[0-9]{4,}$');
    END IF;
END $$;
