-- Guard shift swap requests
CREATE TABLE IF NOT EXISTS guard_shift_swaps (
    id VARCHAR(36) PRIMARY KEY,
    requester_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    shift_id VARCHAR(36) NOT NULL,
    reason TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- pending | accepted | declined
    responded_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT guard_shift_swaps_status_check CHECK (status IN ('pending', 'accepted', 'declined'))
);

CREATE INDEX IF NOT EXISTS idx_shift_swaps_requester ON guard_shift_swaps(requester_id);
CREATE INDEX IF NOT EXISTS idx_shift_swaps_target    ON guard_shift_swaps(target_id);
CREATE INDEX IF NOT EXISTS idx_shift_swaps_status    ON guard_shift_swaps(status);
