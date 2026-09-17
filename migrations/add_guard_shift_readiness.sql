-- Per-shift guard equipment readiness. The application bootstrap also creates
-- this table so existing deployments receive the schema automatically.
CREATE TABLE IF NOT EXISTS guard_shift_readiness (
    id VARCHAR(36) PRIMARY KEY,
    shift_id VARCHAR(36) NOT NULL REFERENCES shifts(id) ON DELETE CASCADE,
    guard_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    checked_items JSONB NOT NULL DEFAULT '[]'::jsonb,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT guard_shift_readiness_shift_guard_unique UNIQUE (shift_id, guard_id)
);

CREATE INDEX IF NOT EXISTS idx_guard_shift_readiness_guard
    ON guard_shift_readiness(guard_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_guard_shift_readiness_shift
    ON guard_shift_readiness(shift_id);
