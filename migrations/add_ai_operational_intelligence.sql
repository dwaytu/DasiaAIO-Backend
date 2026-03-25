-- Phase 1: AI-assisted operational intelligence schema
-- Deterministic + explainable artifacts for SOC analytics and heuristics.

CREATE TABLE IF NOT EXISTS guard_absence_predictions (
    id VARCHAR(36) PRIMARY KEY,
    guard_id VARCHAR(36) NOT NULL,
    prediction_window_hours INTEGER NOT NULL DEFAULT 24,
    risk_score DOUBLE PRECISION NOT NULL CHECK (risk_score >= 0 AND risk_score <= 1),
    risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0.75 CHECK (confidence_score >= 0 AND confidence_score <= 1),
    explanation JSONB NOT NULL DEFAULT '{}'::jsonb,
    contributing_factors JSONB NOT NULL DEFAULT '[]'::jsonb,
    source_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
    generated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    valid_until TIMESTAMP WITH TIME ZONE,
    feature_version VARCHAR(64) NOT NULL DEFAULT 'absence-heuristic-v1',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (guard_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_guard_absence_predictions_guard_generated
    ON guard_absence_predictions (guard_id, generated_at DESC);
CREATE INDEX IF NOT EXISTS idx_guard_absence_predictions_level_valid
    ON guard_absence_predictions (risk_level, valid_until DESC);

CREATE TABLE IF NOT EXISTS smart_guard_replacements (
    id VARCHAR(36) PRIMARY KEY,
    shift_id VARCHAR(36) NOT NULL,
    absent_guard_id VARCHAR(36),
    recommended_guard_id VARCHAR(36),
    recommendation_rank INTEGER NOT NULL DEFAULT 1,
    compatibility_score DOUBLE PRECISION NOT NULL CHECK (compatibility_score >= 0 AND compatibility_score <= 1),
    confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0.75 CHECK (confidence_score >= 0 AND confidence_score <= 1),
    rationale TEXT NOT NULL,
    scoring_breakdown JSONB NOT NULL DEFAULT '{}'::jsonb,
    candidate_pool JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommendation_status VARCHAR(20) NOT NULL DEFAULT 'proposed'
        CHECK (recommendation_status IN ('proposed', 'accepted', 'rejected', 'expired')),
    generated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    feature_version VARCHAR(64) NOT NULL DEFAULT 'replacement-heuristic-v1',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (shift_id) REFERENCES shifts(id) ON DELETE CASCADE,
    FOREIGN KEY (absent_guard_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (recommended_guard_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_smart_guard_replacements_shift_rank
    ON smart_guard_replacements (shift_id, recommendation_rank, generated_at DESC);
CREATE INDEX IF NOT EXISTS idx_smart_guard_replacements_status
    ON smart_guard_replacements (recommendation_status, generated_at DESC);

CREATE TABLE IF NOT EXISTS incident_severity_classifications (
    id VARCHAR(36) PRIMARY KEY,
    incident_id VARCHAR(36) NOT NULL,
    predicted_severity VARCHAR(20) NOT NULL CHECK (predicted_severity IN ('low', 'medium', 'high', 'critical')),
    confidence_score DOUBLE PRECISION NOT NULL CHECK (confidence_score >= 0 AND confidence_score <= 1),
    requires_human_review BOOLEAN NOT NULL DEFAULT false,
    rationale TEXT NOT NULL,
    feature_scores JSONB NOT NULL DEFAULT '{}'::jsonb,
    supporting_signals JSONB NOT NULL DEFAULT '{}'::jsonb,
    classified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    classifier_version VARCHAR(64) NOT NULL DEFAULT 'severity-heuristic-v1',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_incident_severity_classifications_incident
    ON incident_severity_classifications (incident_id, classified_at DESC);
CREATE INDEX IF NOT EXISTS idx_incident_severity_classifications_severity
    ON incident_severity_classifications (predicted_severity, classified_at DESC);

CREATE TABLE IF NOT EXISTS predictive_vehicle_maintenance (
    id VARCHAR(36) PRIMARY KEY,
    car_id VARCHAR(36) NOT NULL,
    risk_score DOUBLE PRECISION NOT NULL CHECK (risk_score >= 0 AND risk_score <= 1),
    risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    days_to_service INTEGER,
    predicted_failure_window_days INTEGER,
    recommended_action TEXT NOT NULL,
    rationale TEXT NOT NULL,
    signal_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
    maintenance_type_suggestion VARCHAR(100),
    generated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    valid_until TIMESTAMP WITH TIME ZONE,
    feature_version VARCHAR(64) NOT NULL DEFAULT 'vehicle-maintenance-heuristic-v1',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (car_id) REFERENCES armored_cars(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_predictive_vehicle_maintenance_car_generated
    ON predictive_vehicle_maintenance (car_id, generated_at DESC);
CREATE INDEX IF NOT EXISTS idx_predictive_vehicle_maintenance_level
    ON predictive_vehicle_maintenance (risk_level, valid_until DESC);

CREATE TABLE IF NOT EXISTS ai_incident_summaries (
    id VARCHAR(36) PRIMARY KEY,
    incident_id VARCHAR(36) NOT NULL,
    summary_kind VARCHAR(32) NOT NULL DEFAULT 'operational'
        CHECK (summary_kind IN ('operational', 'executive', 'handover')),
    summary_text TEXT NOT NULL,
    concise_headline VARCHAR(255),
    key_points JSONB NOT NULL DEFAULT '[]'::jsonb,
    action_items JSONB NOT NULL DEFAULT '[]'::jsonb,
    entities JSONB NOT NULL DEFAULT '{}'::jsonb,
    confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0.75 CHECK (confidence_score >= 0 AND confidence_score <= 1),
    explainability JSONB NOT NULL DEFAULT '{}'::jsonb,
    source_event_count INTEGER NOT NULL DEFAULT 0,
    generated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    summarizer_version VARCHAR(64) NOT NULL DEFAULT 'incident-summary-v1',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_incident_summaries_incident_kind_generated
    ON ai_incident_summaries (incident_id, summary_kind, generated_at);
CREATE INDEX IF NOT EXISTS idx_ai_incident_summaries_incident
    ON ai_incident_summaries (incident_id, generated_at DESC);
