-- MDR data-cleansing provenance and controlled live-normalization audit log.

ALTER TABLE mdr_staging_rows ADD COLUMN IF NOT EXISTS raw_payload JSONB;
ALTER TABLE mdr_staging_rows ADD COLUMN IF NOT EXISTS cleansing_changes JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE mdr_staging_rows ADD COLUMN IF NOT EXISTS quality_flags JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE mdr_staging_rows ADD COLUMN IF NOT EXISTS cleansed_at TIMESTAMP WITH TIME ZONE;

CREATE TABLE IF NOT EXISTS data_quality_change_log (
    id VARCHAR(36) PRIMARY KEY,
    entity_type VARCHAR(50) NOT NULL,
    entity_id VARCHAR(36) NOT NULL,
    field_name VARCHAR(100) NOT NULL,
    original_value TEXT,
    cleaned_value TEXT,
    change_source VARCHAR(100) NOT NULL,
    applied_by VARCHAR(36) REFERENCES users(id),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_data_quality_change_log_entity
    ON data_quality_change_log(entity_type, entity_id, created_at DESC);
