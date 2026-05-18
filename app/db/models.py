from __future__ import annotations

from sqlalchemy import (
    Boolean,
    Column,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(String(36), primary_key=True)
    parent_id = Column(String(36), ForeignKey("analyses.id"), nullable=True)
    query = Column(Text, nullable=False)
    intent = Column(String(32), nullable=True)
    intent_entities = Column(Text, nullable=True)  # JSON
    status = Column(String(20), nullable=False, default="running")
    error_message = Column(Text, nullable=True)
    report_md = Column(Text, nullable=True)
    report_meta = Column(Text, nullable=True)  # JSON
    tlp = Column(String(20), nullable=False, default="GREEN")
    overall_confidence = Column(String(10), nullable=True)
    token_input = Column(Integer, nullable=False, default=0)
    token_output = Column(Integer, nullable=False, default=0)
    cost_usd = Column(Float, nullable=False, default=0.0)
    duration_s = Column(Integer, nullable=True)
    created_at = Column(String(30), nullable=False)
    updated_at = Column(String(30), nullable=False)


class AgentLog(Base):
    __tablename__ = "agent_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String(36), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    sequence = Column(Integer, nullable=False)
    event_type = Column(String(32), nullable=False)
    agent_name = Column(String(32), nullable=True)
    payload = Column(Text, nullable=True)  # JSON
    created_at = Column(String(30), nullable=False)


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True)
    analysis_id = Column(String(36), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    agent_name = Column(String(32), nullable=False)
    claim = Column(Text, nullable=False)
    detail = Column(Text, nullable=True)
    source_type = Column(String(20), nullable=False)  # authoritative | open | llm_inference
    source_url = Column(Text, nullable=True)
    source_name = Column(String(64), nullable=True)
    confidence = Column(String(10), nullable=False)
    created_at = Column(String(30), nullable=False)


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(String(36), primary_key=True)
    analysis_id = Column(String(36), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    ioc_type = Column(String(16), nullable=False)
    value = Column(Text, nullable=False)
    value_defanged = Column(Text, nullable=False)
    context = Column(Text, nullable=True)
    source_finding_id = Column(String(36), ForeignKey("findings.id"), nullable=True)
    confidence = Column(String(10), nullable=False)
    is_extracted_by = Column(String(8), nullable=False)  # regex | llm
    created_at = Column(String(30), nullable=False)

    __table_args__ = (UniqueConstraint("analysis_id", "ioc_type", "value", name="uq_ioc_per_analysis"),)


class CVERef(Base):
    __tablename__ = "cve_refs"

    id = Column(String(36), primary_key=True)
    analysis_id = Column(String(36), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    cve_id = Column(String(20), nullable=False)
    cvss_v3_score = Column(Float, nullable=True)
    cvss_v3_vector = Column(String(128), nullable=True)
    cwe_ids = Column(Text, nullable=True)  # JSON array
    cpe_matches = Column(Text, nullable=True)  # JSON array
    nvd_published = Column(String(30), nullable=True)
    nvd_modified = Column(String(30), nullable=True)
    description = Column(Text, nullable=True)
    is_in_kev = Column(Boolean, nullable=False, default=False)
    kev_added_date = Column(String(10), nullable=True)
    epss_score = Column(Float, nullable=True)
    epss_percentile = Column(Float, nullable=True)
    epss_date = Column(String(10), nullable=True)
    source_payload = Column(Text, nullable=True)  # raw JSON for audit
    created_at = Column(String(30), nullable=False)


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String(36), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    technique_id = Column(String(16), nullable=False)
    technique_name = Column(String(128), nullable=True)
    tactic = Column(String(64), nullable=True)
    confidence = Column(String(10), nullable=False)
    rationale = Column(Text, nullable=True)
    created_at = Column(String(30), nullable=False)


class SourceUsed(Base):
    __tablename__ = "sources_used"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String(36), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    url = Column(Text, nullable=False)
    domain = Column(String(128), nullable=False)
    source_type = Column(String(16), nullable=False)  # authoritative | open
    is_trusted = Column(Boolean, nullable=False, default=False)
    accessed_at = Column(String(30), nullable=False)

    __table_args__ = (UniqueConstraint("analysis_id", "url", name="uq_source_per_analysis"),)


class DataSourceCache(Base):
    __tablename__ = "data_source_cache"

    cache_key = Column(String(128), primary_key=True)
    source = Column(String(16), nullable=False)
    payload = Column(Text, nullable=False)  # JSON
    fetched_at = Column(String(30), nullable=False)
    ttl_seconds = Column(Integer, nullable=False)
    expires_at = Column(String(30), nullable=False)


class SourceHealth(Base):
    __tablename__ = "sources_health"

    source_name = Column(String(32), primary_key=True)
    status = Column(String(10), nullable=False)  # ok | degraded | down
    last_check_at = Column(String(30), nullable=False)
    last_success_at = Column(String(30), nullable=True)
    last_error = Column(Text, nullable=True)
    response_time_ms = Column(Integer, nullable=True)


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=False)
    is_encrypted = Column(Boolean, nullable=False, default=False)
    updated_at = Column(String(30), nullable=False)


class TrustedSource(Base):
    __tablename__ = "trusted_sources"

    domain = Column(String(128), primary_key=True)
    note = Column(Text, nullable=True)
    added_at = Column(String(30), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(32), nullable=False)
    detail = Column(Text, nullable=True)  # JSON
    created_at = Column(String(30), nullable=False)


class TokenUsageMonthly(Base):
    __tablename__ = "token_usage_monthly"

    year_month = Column(String(7), primary_key=True)  # "2026-05"
    total_input = Column(Integer, nullable=False, default=0)
    total_output = Column(Integer, nullable=False, default=0)
    total_cost_usd = Column(Float, nullable=False, default=0.0)
    analysis_count = Column(Integer, nullable=False, default=0)
    updated_at = Column(String(30), nullable=False)


class AssetSpace(Base):
    __tablename__ = "asset_spaces"

    id = Column(String(36), primary_key=True)
    name = Column(String(128), nullable=False)
    type = Column(String(16), nullable=False)  # default | project
    description = Column(Text, nullable=True)
    created_at = Column(String(30), nullable=False)
    updated_at = Column(String(30), nullable=False)
    expires_at = Column(String(30), nullable=True)
    auto_action_on_expire = Column(String(16), nullable=False, default="notify_only")
    is_archived = Column(Boolean, nullable=False, default=False)
    metadata_json = Column(Text, nullable=True)


class Host(Base):
    __tablename__ = "hosts"

    id = Column(String(36), primary_key=True)
    space_id = Column(String(36), ForeignKey("asset_spaces.id", ondelete="CASCADE"), nullable=False)
    ip = Column(String(64), nullable=True)
    hostname = Column(String(255), nullable=True)
    os_name = Column(String(128), nullable=True)
    os_version = Column(String(128), nullable=True)
    os_cpe = Column(Text, nullable=True)
    os_cpe_confidence = Column(String(16), nullable=True)
    criticality = Column(String(16), nullable=False, default="medium")
    environment = Column(String(16), nullable=False, default="unknown")
    owner = Column(String(128), nullable=True)
    tags_json = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    source = Column(String(32), nullable=False, default="manual")
    source_meta_json = Column(Text, nullable=True)
    first_seen_at = Column(String(30), nullable=False)
    last_seen_at = Column(String(30), nullable=False)
    updated_at = Column(String(30), nullable=False)


class AssetService(Base):
    __tablename__ = "services"

    id = Column(String(36), primary_key=True)
    host_id = Column(String(36), ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    product = Column(String(128), nullable=False)
    version = Column(String(128), nullable=True)
    vendor = Column(String(128), nullable=True)
    cpe = Column(Text, nullable=True)
    cpe_confidence = Column(String(16), nullable=True)
    service_type = Column(String(32), nullable=True)
    detection_method = Column(String(32), nullable=True)
    raw_banner = Column(Text, nullable=True)
    first_seen_at = Column(String(30), nullable=False)
    last_seen_at = Column(String(30), nullable=False)


class Exposure(Base):
    __tablename__ = "exposures"

    id = Column(String(36), primary_key=True)
    service_id = Column(String(36), ForeignKey("services.id", ondelete="CASCADE"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(8), nullable=False)
    exposure_scope = Column(String(16), nullable=False, default="unknown")
    notes = Column(Text, nullable=True)


class AssetCVEMatch(Base):
    __tablename__ = "asset_cve_matches"

    id = Column(String(36), primary_key=True)
    service_id = Column(String(36), ForeignKey("services.id", ondelete="CASCADE"), nullable=False)
    cve_id = Column(String(20), nullable=False)
    match_confidence = Column(String(16), nullable=False)
    cvss_score = Column(Float, nullable=True)
    kev_flag = Column(Boolean, nullable=False, default=False)
    epss_score = Column(Float, nullable=True)
    risk_score = Column(Float, nullable=True)
    summary = Column(Text, nullable=True)
    status = Column(String(20), nullable=False, default="open")
    discovered_at = Column(String(30), nullable=False)
    last_updated_at = Column(String(30), nullable=False)
    user_notes = Column(Text, nullable=True)

    __table_args__ = (UniqueConstraint("service_id", "cve_id", name="uq_asset_cve_match"),)


class CpeDictionary(Base):
    __tablename__ = "cpe_dictionary"

    cpe = Column(Text, primary_key=True)
    vendor = Column(String(128), nullable=False)
    product = Column(String(128), nullable=False)
    version = Column(String(128), nullable=True)
    update_field = Column(String(64), nullable=True)
    edition = Column(String(64), nullable=True)
    title = Column(Text, nullable=True)
    deprecated = Column(Boolean, nullable=False, default=False)
    last_modified = Column(String(30), nullable=True)


class NvdCVECache(Base):
    __tablename__ = "nvd_cve_cache"

    cve_id = Column(String(20), primary_key=True)
    description = Column(Text, nullable=True)
    cvss_v3_score = Column(Float, nullable=True)
    cvss_v3_vector = Column(String(128), nullable=True)
    is_in_kev = Column(Boolean, nullable=False, default=False)
    epss_score = Column(Float, nullable=True)
    published_at = Column(String(30), nullable=True)
    modified_at = Column(String(30), nullable=True)
    source_payload = Column(Text, nullable=True)
    updated_at = Column(String(30), nullable=False)


class NvdCpeMatch(Base):
    __tablename__ = "nvd_cpe_matches"

    id = Column(String(36), primary_key=True)
    cve_id = Column(String(20), ForeignKey("nvd_cve_cache.cve_id", ondelete="CASCADE"), nullable=False)
    cpe = Column(Text, nullable=False)
    vulnerable = Column(Boolean, nullable=False, default=True)
    version_start_including = Column(String(128), nullable=True)
    version_start_excluding = Column(String(128), nullable=True)
    version_end_including = Column(String(128), nullable=True)
    version_end_excluding = Column(String(128), nullable=True)

    __table_args__ = (UniqueConstraint("cve_id", "cpe", name="uq_nvd_cpe_match"),)
