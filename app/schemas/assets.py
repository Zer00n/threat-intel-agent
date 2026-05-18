from __future__ import annotations

from pydantic import BaseModel, Field


class AssetSpaceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str | None = None
    expires_at: str | None = None
    auto_action_on_expire: str = "notify_only"


class AssetSpacePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = None
    expires_at: str | None = None
    auto_action_on_expire: str | None = None


class AssetSpaceOut(BaseModel):
    id: str
    name: str
    type: str
    description: str | None = None
    expires_at: str | None = None
    is_archived: bool = False
    asset_count: dict
    risk_summary: dict
    last_analyzed_at: str | None = None


class HostPatch(BaseModel):
    criticality: str | None = None
    environment: str | None = None
    owner: str | None = None
    tags: list[str] | None = None
    notes: str | None = None


class AssetManualCreate(BaseModel):
    space_id: str = "default"
    ip: str | None = None
    hostname: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    environment: str = "unknown"
    criticality: str = "medium"
    owner: str | None = None
    tags: list[str] = Field(default_factory=list)
    notes: str | None = None
    product: str = Field(..., min_length=1, max_length=128)
    version: str | None = None
    vendor: str | None = None
    cpe: str | None = None
    raw_banner: str | None = None
    port: int = Field(..., ge=1, le=65535)
    protocol: str = "tcp"
    exposure_scope: str = "unknown"


class AssetBatchDeleteRequest(BaseModel):
    ids: list[str] = Field(..., min_length=1)


class ServicePatch(BaseModel):
    cpe: str | None = None
    cpe_confidence: str | None = None
    service_type: str | None = None


class AssetImportTextRequest(BaseModel):
    space_id: str = "default"
    content: str
    mode: str = "merge"
    filename: str | None = None


class AssetImportSummary(BaseModel):
    hosts_created: int = 0
    hosts_updated: int = 0
    services_created: int = 0
    services_updated: int = 0
    exposures_created: int = 0
    exposures_updated: int = 0
    failed_rows: int = 0
    failed_reasons: list[dict] = Field(default_factory=list)
    cpe_normalization: dict = Field(default_factory=dict)


class CVEMatchStatusPatch(BaseModel):
    status: str
    user_notes: str | None = None
