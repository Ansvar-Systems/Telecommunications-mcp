PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS architecture_patterns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    components JSON NOT NULL,
    trust_boundaries JSON NOT NULL,
    data_flows JSON NOT NULL,
    known_weaknesses JSON,
    applicable_standards JSON,
    last_updated TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS data_categories (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    boundary_conditions TEXT,
    jurisdiction_protections JSON NOT NULL,
    deidentification_requirements JSON,
    cross_border_constraints JSON,
    last_updated TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_scenarios (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    attack_narrative TEXT,
    mitre_mapping JSON,
    affected_patterns JSON,
    affected_data_categories JSON,
    likelihood_factors JSON,
    impact_dimensions JSON,
    regulation_refs JSON,
    control_refs JSON,
    detection_indicators JSON,
    historical_incidents JSON,
    last_updated TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS technical_standards (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT,
    publisher TEXT NOT NULL,
    scope TEXT NOT NULL,
    key_clauses JSON,
    control_mappings JSON,
    regulation_mappings JSON,
    implementation_guidance TEXT,
    licensing_restrictions TEXT,
    last_updated TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS applicability_rules (
    id TEXT PRIMARY KEY,
    condition JSON NOT NULL,
    obligation JSON NOT NULL,
    rationale TEXT NOT NULL,
    last_updated TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_artifacts (
    id TEXT PRIMARY KEY,
    audit_type TEXT NOT NULL,
    artifact_name TEXT NOT NULL,
    description TEXT NOT NULL,
    mandatory BOOLEAN NOT NULL,
    retention_period TEXT,
    template_ref TEXT,
    regulation_basis JSON,
    last_updated TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS authoritative_sources (
    id TEXT PRIMARY KEY,
    source_name TEXT NOT NULL,
    content TEXT NOT NULL,
    license TEXT NOT NULL,
    refresh_cadence TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_url TEXT,
    last_updated TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS architecture_patterns_fts USING fts5(
    id UNINDEXED,
    name,
    description,
    components
);

CREATE VIRTUAL TABLE IF NOT EXISTS threat_scenarios_fts USING fts5(
    id UNINDEXED,
    name,
    description,
    attack_narrative
);

CREATE VIRTUAL TABLE IF NOT EXISTS technical_standards_fts USING fts5(
    id UNINDEXED,
    name,
    scope,
    key_clauses
);

CREATE VIRTUAL TABLE IF NOT EXISTS data_categories_fts USING fts5(
    id UNINDEXED,
    name,
    description,
    boundary_conditions
);

CREATE TABLE IF NOT EXISTS db_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exact_reference_overrides (
    jurisdiction TEXT NOT NULL,
    assertion_id TEXT NOT NULL,
    regulation_id TEXT NOT NULL,
    exact_reference TEXT NOT NULL,
    citations JSON,
    source_confidence TEXT,
    resolved_by TEXT,
    notes TEXT,
    resolved_at TEXT NOT NULL,
    PRIMARY KEY (jurisdiction, assertion_id)
);
