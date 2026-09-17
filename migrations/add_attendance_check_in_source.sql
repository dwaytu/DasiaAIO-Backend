ALTER TABLE attendance
    ADD COLUMN IF NOT EXISTS check_in_source VARCHAR(20) NOT NULL DEFAULT 'manual';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'attendance_check_in_source_check'
    ) THEN
        ALTER TABLE attendance
            ADD CONSTRAINT attendance_check_in_source_check
            CHECK (check_in_source IN ('manual', 'geofence'));
    END IF;
END $$;
