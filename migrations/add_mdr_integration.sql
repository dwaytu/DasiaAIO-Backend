-- MDR Integration Migration
-- Created: 2026-04-09
-- Purpose: Add clients, guard_assignments, guard_status_transitions,
--          equipment, mdr_import_batches, mdr_staging_rows tables
--          and extend users, firearms, firearm_allocations, client_sites.

-- ═══════════════════════════════════════════════════════════════════
-- 1. NEW TABLES
-- ═══════════════════════════════════════════════════════════════════

-- 1a. Clients (first-class business entity)
CREATE TABLE IF NOT EXISTS clients (
    id              VARCHAR(36) PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    address         TEXT,
    phone           VARCHAR(50),
    client_number   INTEGER,
    branch          VARCHAR(100),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_name_branch
    ON clients (UPPER(name), COALESCE(branch, ''));

-- 1b. MDR import batch audit trail
CREATE TABLE IF NOT EXISTS mdr_import_batches (
    id              VARCHAR(36) PRIMARY KEY,
    filename        VARCHAR(255) NOT NULL,
    report_month    VARCHAR(20) NOT NULL,
    branch          VARCHAR(100),
    uploaded_by     VARCHAR(36) NOT NULL REFERENCES users(id),
    status          VARCHAR(50) NOT NULL DEFAULT 'staging',
    total_rows      INTEGER,
    matched_rows    INTEGER,
    new_rows        INTEGER,
    ambiguous_rows  INTEGER,
    error_rows      INTEGER,
    committed_at    TIMESTAMP WITH TIME ZONE,
    committed_by    VARCHAR(36) REFERENCES users(id),
    notes           TEXT,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 1c. MDR staging rows (raw parsed Excel data held for review)
CREATE TABLE IF NOT EXISTS mdr_staging_rows (
    id                  VARCHAR(36) PRIMARY KEY,
    batch_id            VARCHAR(36) NOT NULL REFERENCES mdr_import_batches(id) ON DELETE CASCADE,
    sheet_name          VARCHAR(50) NOT NULL,
    row_number          INTEGER NOT NULL,
    section             VARCHAR(50),
    client_number       INTEGER,
    client_name         VARCHAR(255),
    client_address      TEXT,
    guard_number        INTEGER,
    guard_name          VARCHAR(255),
    contact_number      VARCHAR(50),
    license_number      VARCHAR(100),
    license_expiry      VARCHAR(50),
    firearm_kind        VARCHAR(100),
    firearm_make        VARCHAR(100),
    caliber             VARCHAR(50),
    serial_number       VARCHAR(100),
    firearm_validity    VARCHAR(50),
    actual_ammo         VARCHAR(50),
    ammo_count          VARCHAR(50),
    lic_reg_name        VARCHAR(100),
    pullout_status      VARCHAR(50),
    fa_remarks          VARCHAR(255),
    match_status        VARCHAR(20) NOT NULL DEFAULT 'pending',
    matched_guard_id    VARCHAR(36),
    matched_firearm_id  VARCHAR(36),
    matched_client_id   VARCHAR(36),
    validation_errors   JSONB,
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_staging_batch
    ON mdr_staging_rows(batch_id);
CREATE INDEX IF NOT EXISTS idx_staging_match
    ON mdr_staging_rows(batch_id, match_status);

-- 1d. Guard assignments (guard-to-client posting)
CREATE TABLE IF NOT EXISTS guard_assignments (
    id                  VARCHAR(36) PRIMARY KEY,
    guard_id            VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id           VARCHAR(36) NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    client_site_id      VARCHAR(36) REFERENCES client_sites(id),
    post_label          VARCHAR(255),
    guard_number        INTEGER,
    assignment_start    TIMESTAMP WITH TIME ZONE,
    assignment_end      TIMESTAMP WITH TIME ZONE,
    status              VARCHAR(50) NOT NULL DEFAULT 'active',
    mdr_batch_id        VARCHAR(36) REFERENCES mdr_import_batches(id),
    mdr_row_ref         VARCHAR(50),
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_guard_assignments_guard
    ON guard_assignments(guard_id);
CREATE INDEX IF NOT EXISTS idx_guard_assignments_client
    ON guard_assignments(client_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_guard_assignments_active
    ON guard_assignments(guard_id, client_id, assignment_start)
    WHERE status = 'active';

-- 1e. Guard status transitions (pull-out history)
CREATE TABLE IF NOT EXISTS guard_status_transitions (
    id                  VARCHAR(36) PRIMARY KEY,
    guard_id            VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    transition_type     VARCHAR(50) NOT NULL,
    reason              TEXT,
    previous_client_id  VARCHAR(36) REFERENCES clients(id),
    effective_date      TIMESTAMP WITH TIME ZONE,
    mdr_batch_id        VARCHAR(36) REFERENCES mdr_import_batches(id),
    mdr_row_ref         VARCHAR(50),
    recorded_by         VARCHAR(36) REFERENCES users(id),
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_guard_transitions_guard
    ON guard_status_transitions(guard_id, created_at DESC);

-- 1f. Equipment (non-firearm gear)
CREATE TABLE IF NOT EXISTS equipment (
    id                      VARCHAR(36) PRIMARY KEY,
    equipment_type          VARCHAR(100) NOT NULL,
    description             VARCHAR(255),
    serial_number           VARCHAR(100),
    assigned_to_client_id   VARCHAR(36) REFERENCES clients(id),
    assigned_to_guard_id    VARCHAR(36) REFERENCES users(id),
    quantity                INTEGER NOT NULL DEFAULT 1,
    status                  VARCHAR(50) NOT NULL DEFAULT 'active',
    mdr_batch_id            VARCHAR(36) REFERENCES mdr_import_batches(id),
    created_at              TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ═══════════════════════════════════════════════════════════════════
-- 2. ALTER EXISTING TABLES
-- ═══════════════════════════════════════════════════════════════════

-- 2a. users — add MDR-sourced fields
ALTER TABLE users ADD COLUMN IF NOT EXISTS guard_number INTEGER;
ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'active';
ALTER TABLE users ADD COLUMN IF NOT EXISTS mdr_batch_id VARCHAR(36);
ALTER TABLE users ADD COLUMN IF NOT EXISTS lic_reg_name VARCHAR(100);

-- 2b. firearms — add MDR-sourced fields
ALTER TABLE firearms ADD COLUMN IF NOT EXISTS kind VARCHAR(100);
ALTER TABLE firearms ADD COLUMN IF NOT EXISTS make VARCHAR(100);
ALTER TABLE firearms ADD COLUMN IF NOT EXISTS validity_date TIMESTAMP WITH TIME ZONE;
ALTER TABLE firearms ADD COLUMN IF NOT EXISTS ammo_issued INTEGER;
ALTER TABLE firearms ADD COLUMN IF NOT EXISTS lic_reg_name VARCHAR(100);
ALTER TABLE firearms ADD COLUMN IF NOT EXISTS vault_status VARCHAR(50);
ALTER TABLE firearms ADD COLUMN IF NOT EXISTS return_remarks VARCHAR(255);
ALTER TABLE firearms ADD COLUMN IF NOT EXISTS mdr_batch_id VARCHAR(36);

-- 2c. firearm_allocations — add traceability
ALTER TABLE firearm_allocations ADD COLUMN IF NOT EXISTS mdr_batch_id VARCHAR(36);
ALTER TABLE firearm_allocations ADD COLUMN IF NOT EXISTS mdr_row_ref VARCHAR(50);

-- 2d. client_sites — link to business client
ALTER TABLE client_sites ADD COLUMN IF NOT EXISTS client_id VARCHAR(36);
