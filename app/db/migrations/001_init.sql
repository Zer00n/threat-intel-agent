-- Main analyses table
CREATE TABLE IF NOT EXISTS analyses (
    id              TEXT PRIMARY KEY,
    parent_id       TEXT REFERENCES analyses(id),
    query           TEXT NOT NULL,
    intent          TEXT,
    intent_entities TEXT,
    status          TEXT NOT NULL DEFAULT 'running',
    error_message   TEXT,
    report_md       TEXT,
    report_meta     TEXT,
    tlp             TEXT NOT NULL DEFAULT 'GREEN',
    overall_confidence TEXT,
    token_input     INTEGER NOT NULL DEFAULT 0,
    token_output    INTEGER NOT NULL DEFAULT 0,
    cost_usd        REAL NOT NULL DEFAULT 0.0,
    duration_s      INTEGER,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_intent ON analyses(intent);
CREATE INDEX IF NOT EXISTS idx_analyses_status ON analyses(status);

-- Agent step logs
CREATE TABLE IF NOT EXISTS agent_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id  TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    sequence     INTEGER NOT NULL,
    event_type   TEXT NOT NULL,
    agent_name   TEXT,
    payload      TEXT,
    created_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_logs_analysis ON agent_logs(analysis_id, sequence);

-- Findings
CREATE TABLE IF NOT EXISTS findings (
    id           TEXT PRIMARY KEY,
    analysis_id  TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    agent_name   TEXT NOT NULL,
    claim        TEXT NOT NULL,
    detail       TEXT,
    source_type  TEXT NOT NULL,
    source_url   TEXT,
    source_name  TEXT,
    confidence   TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_analysis ON findings(analysis_id);

-- IOCs
CREATE TABLE IF NOT EXISTS iocs (
    id           TEXT PRIMARY KEY,
    analysis_id  TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    ioc_type     TEXT NOT NULL,
    value        TEXT NOT NULL,
    value_defanged TEXT NOT NULL,
    context      TEXT,
    source_finding_id TEXT REFERENCES findings(id),
    confidence   TEXT NOT NULL,
    is_extracted_by TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    UNIQUE(analysis_id, ioc_type, value)
);

CREATE INDEX IF NOT EXISTS idx_iocs_analysis ON iocs(analysis_id);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);

-- CVE references
CREATE TABLE IF NOT EXISTS cve_refs (
    id           TEXT PRIMARY KEY,
    analysis_id  TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    cve_id       TEXT NOT NULL,
    cvss_v3_score REAL,
    cvss_v3_vector TEXT,
    cwe_ids      TEXT,
    cpe_matches  TEXT,
    nvd_published TEXT,
    nvd_modified TEXT,
    description  TEXT,
    is_in_kev    INTEGER NOT NULL DEFAULT 0,
    kev_added_date TEXT,
    epss_score   REAL,
    epss_percentile REAL,
    epss_date    TEXT,
    source_payload TEXT,
    created_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cve_refs_analysis ON cve_refs(analysis_id);
CREATE INDEX IF NOT EXISTS idx_cve_refs_cve_id ON cve_refs(cve_id);

-- ATT&CK technique mappings
CREATE TABLE IF NOT EXISTS attack_techniques (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id  TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    technique_id TEXT NOT NULL,
    technique_name TEXT,
    tactic       TEXT,
    confidence   TEXT NOT NULL,
    rationale    TEXT,
    created_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attack_analysis ON attack_techniques(analysis_id);

-- Sources used
CREATE TABLE IF NOT EXISTS sources_used (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id  TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    url          TEXT NOT NULL,
    domain       TEXT NOT NULL,
    source_type  TEXT NOT NULL,
    is_trusted   INTEGER NOT NULL DEFAULT 0,
    accessed_at  TEXT NOT NULL,
    UNIQUE(analysis_id, url)
);

-- Data source cache
CREATE TABLE IF NOT EXISTS data_source_cache (
    cache_key    TEXT PRIMARY KEY,
    source       TEXT NOT NULL,
    payload      TEXT NOT NULL,
    fetched_at   TEXT NOT NULL,
    ttl_seconds  INTEGER NOT NULL,
    expires_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cache_expires ON data_source_cache(expires_at);

-- Source health status
CREATE TABLE IF NOT EXISTS sources_health (
    source_name  TEXT PRIMARY KEY,
    status       TEXT NOT NULL,
    last_check_at TEXT NOT NULL,
    last_success_at TEXT,
    last_error   TEXT,
    response_time_ms INTEGER
);

-- Settings (KV store)
CREATE TABLE IF NOT EXISTS settings (
    key          TEXT PRIMARY KEY,
    value        TEXT NOT NULL,
    is_encrypted INTEGER NOT NULL DEFAULT 0,
    updated_at   TEXT NOT NULL
);

-- Trusted sources whitelist
CREATE TABLE IF NOT EXISTS trusted_sources (
    domain       TEXT PRIMARY KEY,
    note         TEXT,
    added_at     TEXT NOT NULL
);

-- Audit logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type   TEXT NOT NULL,
    detail       TEXT,
    created_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);

-- Token usage monthly aggregation
CREATE TABLE IF NOT EXISTS token_usage_monthly (
    year_month   TEXT PRIMARY KEY,
    total_input  INTEGER NOT NULL DEFAULT 0,
    total_output INTEGER NOT NULL DEFAULT 0,
    total_cost_usd REAL NOT NULL DEFAULT 0.0,
    analysis_count INTEGER NOT NULL DEFAULT 0,
    updated_at   TEXT NOT NULL
);
