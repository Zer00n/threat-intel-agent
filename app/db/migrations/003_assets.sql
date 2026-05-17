CREATE TABLE IF NOT EXISTS asset_spaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT,
    auto_action_on_expire TEXT NOT NULL DEFAULT 'notify_only',
    is_archived INTEGER NOT NULL DEFAULT 0,
    metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL REFERENCES asset_spaces(id) ON DELETE CASCADE,
    ip TEXT,
    hostname TEXT,
    os_name TEXT,
    os_version TEXT,
    os_cpe TEXT,
    os_cpe_confidence TEXT,
    criticality TEXT NOT NULL DEFAULT 'medium',
    environment TEXT NOT NULL DEFAULT 'unknown',
    owner TEXT,
    tags_json TEXT,
    notes TEXT,
    source TEXT NOT NULL,
    source_meta_json TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    product TEXT NOT NULL,
    version TEXT,
    vendor TEXT,
    cpe TEXT,
    cpe_confidence TEXT,
    service_type TEXT,
    detection_method TEXT,
    raw_banner TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exposures (
    id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    exposure_scope TEXT NOT NULL DEFAULT 'unknown',
    notes TEXT
);

CREATE TABLE IF NOT EXISTS asset_cve_matches (
    id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    match_confidence TEXT NOT NULL,
    cvss_score REAL,
    kev_flag INTEGER NOT NULL DEFAULT 0,
    epss_score REAL,
    risk_score REAL,
    summary TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    discovered_at TEXT NOT NULL,
    last_updated_at TEXT NOT NULL,
    user_notes TEXT,
    UNIQUE(service_id, cve_id)
);

CREATE TABLE IF NOT EXISTS cpe_dictionary (
    cpe TEXT PRIMARY KEY,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    version TEXT,
    update_field TEXT,
    edition TEXT,
    title TEXT,
    deprecated INTEGER NOT NULL DEFAULT 0,
    last_modified TEXT
);

CREATE TABLE IF NOT EXISTS nvd_cve_cache (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    cvss_v3_score REAL,
    cvss_v3_vector TEXT,
    is_in_kev INTEGER NOT NULL DEFAULT 0,
    epss_score REAL,
    published_at TEXT,
    modified_at TEXT,
    source_payload TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nvd_cpe_matches (
    id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES nvd_cve_cache(cve_id) ON DELETE CASCADE,
    cpe TEXT NOT NULL,
    vulnerable INTEGER NOT NULL DEFAULT 1,
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including TEXT,
    version_end_excluding TEXT,
    UNIQUE(cve_id, cpe)
);

CREATE INDEX IF NOT EXISTS idx_asset_spaces_type ON asset_spaces(type);
CREATE INDEX IF NOT EXISTS idx_asset_spaces_archived ON asset_spaces(is_archived);
CREATE INDEX IF NOT EXISTS idx_hosts_space ON hosts(space_id);
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(space_id, ip);
CREATE INDEX IF NOT EXISTS idx_hosts_hostname ON hosts(space_id, hostname);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_services_cpe ON services(cpe);
CREATE INDEX IF NOT EXISTS idx_services_product ON services(product);
CREATE INDEX IF NOT EXISTS idx_exposures_service ON exposures(service_id);
CREATE INDEX IF NOT EXISTS idx_exposures_scope ON exposures(exposure_scope);
CREATE INDEX IF NOT EXISTS idx_acm_service ON asset_cve_matches(service_id);
CREATE INDEX IF NOT EXISTS idx_acm_cve ON asset_cve_matches(cve_id);
CREATE INDEX IF NOT EXISTS idx_acm_status ON asset_cve_matches(status);
CREATE INDEX IF NOT EXISTS idx_acm_risk ON asset_cve_matches(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_cpe_product ON cpe_dictionary(product);
CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product ON cpe_dictionary(vendor, product);
CREATE INDEX IF NOT EXISTS idx_nvd_cpe ON nvd_cpe_matches(cpe);

