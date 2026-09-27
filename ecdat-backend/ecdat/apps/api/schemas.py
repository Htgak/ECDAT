"""Shared Pydantic response/request schemas for the ECDAT API."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Standard paginated response envelope."""

    items: list[T]
    total: int
    page: int
    page_size: int
    pages: int


class ErrorResponse(BaseModel):
    """Standard error response."""

    code: str
    message: str
    detail: dict | None = None


class ScanCreateRequest(BaseModel):
    repository_id: str = Field(..., description="Repository UUID, repository name, or Git URL")
    repository_url: str | None = Field(None, description="Optional remote Git clone URL (https/ssh/file)")
    commit_ref: str | None = None
    collectors: list[str] | None = None  # None = all applicable collectors
    incremental: bool = Field(False, description="Scan only files changed since last scan")


class ScanResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    repository_id: uuid.UUID
    repository_name: str | None = None
    status: str
    commit_ref: str | None
    started_at: datetime | None
    completed_at: datetime | None
    is_complete: bool
    created_at: datetime
    asset_count: int = 0
    act_now_count: int = 0
    avg_qars_score: float | None = None

    model_config = {"from_attributes": True}


class AssetResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    stable_id: str
    asset_type: str
    algorithm: str | None
    key_size: int | None
    curve: str | None
    provider: str | None
    confidence: str
    analysis_status: str
    usage_evidence: str
    has_conflict: bool
    created_at: datetime

    qars_score: float | None = None
    mosca_verdict: str | None = None
    repository: str | None = None
    occurrences_count: int = 0

    model_config = {"from_attributes": True}


class FindingResponse(BaseModel):
    """Occurrence-level finding (asset + location + detection info)."""

    occurrence_id: uuid.UUID
    asset_id: uuid.UUID
    scan_id: uuid.UUID | None
    location_type: str
    repository: str | None
    file_path: str | None
    line: int | None
    observation_type: str | None
    detection_rule_id: str | None
    detection_rule_version: str | None
    collector_name: str
    collector_version: str
    confidence: str
    created_at: datetime

    model_config = {"from_attributes": True}


class PolicyEvaluateRequest(BaseModel):
    asset_id: uuid.UUID
    scan_id: uuid.UUID
    policy_pack_id: uuid.UUID


class PolicyResultResponse(BaseModel):
    id: uuid.UUID
    rule_id: str
    verdict: str
    offending_property: str | None
    offending_value: str | None
    explanation: str | None
    policy_pack_version: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ExportRequest(BaseModel):
    scan_id: uuid.UUID
    format: str = Field(..., description="cyclonedx17 | sarif | csv | json")
    include_evidence: bool = False


class SnapshotRequest(BaseModel):
    scan_id: uuid.UUID
    request_tsa_timestamp: bool = True


class SnapshotResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    canonical_hash: str
    merkle_root: str
    tsa_timestamp_at: datetime | None
    is_verified: bool
    created_at: datetime

    model_config = {"from_attributes": True}
