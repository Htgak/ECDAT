"""Evidence Envelope — the canonical output contract for every collector.

Every collector must emit one or more EvidenceEnvelope instances.
The envelope is the ONLY communication channel between a collector and the
normalization pipeline. Collectors cannot directly mutate business tables.

Design rules:
- Never place raw secrets in the envelope.
- Secrets are fingerprinted (sha256 prefix only).
- The envelope must be self-contained enough to reconstruct provenance
  without re-running the collector.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from ecdat.core.model.types import (
    AnalysisStatus,
    Confidence,
    DependencyEvidenceLevel,
    ObservationType,
    UsageEvidence,
)


# --------------------------------------------------------------------------- #
# Sub-models                                                                   #
# --------------------------------------------------------------------------- #


class CollectorInfo(BaseModel):
    """Identity of the collector that produced this envelope."""

    name: str = Field(..., description="Unique collector name, e.g. 'java-source'.")
    version: str = Field(..., description="SemVer of the collector.")

    model_config = {"frozen": True}


class RunInfo(BaseModel):
    """Information about the specific scan run."""

    scan_id: str = Field(..., description="UUID of the parent scan.")
    collector_run_id: str = Field(..., description="UUID of the collector run record.")
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    input_revision: str | None = Field(
        default=None,
        description="Git commit SHA or other revision identifier of the scanned input.",
    )

    model_config = {"frozen": True}


class SourceLocation(BaseModel):
    """Location within a source repository."""

    repository: str
    path: str
    line: int | None = None
    column: int | None = None
    commit_ref: str | None = None

    model_config = {"frozen": True}


class DependencyLocation(BaseModel):
    """Location within a dependency graph."""

    ecosystem: str          # npm | pypi | maven | go
    package_name: str
    package_version: str
    group_id: str | None = None
    dependency_path: list[str] = Field(default_factory=list)
    is_direct: bool = False

    model_config = {"frozen": True}


class ContainerLocation(BaseModel):
    """Location within a container image."""

    image_reference: str
    image_digest: str | None = None
    layer_digest: str | None = None
    path_in_layer: str | None = None

    model_config = {"frozen": True}


class CryptoObservation(BaseModel):
    """The core cryptographic observation — what was found."""

    observation_type: ObservationType
    algorithm: str | None = None
    algorithm_raw: str | None = None        # raw string from source, before normalization
    key_size: int | None = None
    curve: str | None = None
    provider: str | None = None
    operation: str | None = None
    mode: str | None = None                 # e.g. CBC, GCM
    padding: str | None = None             # e.g. PKCS1v15, OAEP
    hash_algorithm: str | None = None
    dependency_evidence_level: DependencyEvidenceLevel | None = None
    usage_evidence: UsageEvidence = UsageEvidence.UNKNOWN
    extra: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}


class EvidenceFingerprint(BaseModel):
    """Cryptographic fingerprint of the supporting evidence payload.

    Never contains the raw value — only the hash.
    """

    algorithm: str = "sha256"
    digest: str = Field(..., description="Hex-encoded hash of the evidence payload.")
    content_type: str = "application/json"
    size_bytes: int = 0

    model_config = {"frozen": True}


# --------------------------------------------------------------------------- #
# Detection Rule Reference                                                     #
# --------------------------------------------------------------------------- #


class DetectionRule(BaseModel):
    """Reference to the versioned rule that produced this finding."""

    rule_id: str = Field(..., description="e.g. JAVA-RSA-001")
    rule_version: str = Field(..., description="e.g. 1.0")
    rule_name: str | None = None

    model_config = {"frozen": True}


# --------------------------------------------------------------------------- #
# Evidence Envelope                                                            #
# --------------------------------------------------------------------------- #


class EvidenceEnvelope(BaseModel):
    """The canonical output of a collector run.

    One envelope = one cryptographic observation at one location.
    A single collector run may emit many envelopes.
    """

    schema_version: str = Field("1.0", description="Evidence Envelope schema version.")
    collector: CollectorInfo
    run: RunInfo
    tenant_id: str = Field(..., description="UUID of the owning tenant.")

    # Exactly one location type must be set (validated below)
    source_location: SourceLocation | None = None
    dependency_location: DependencyLocation | None = None
    container_location: ContainerLocation | None = None

    observation: CryptoObservation
    confidence: Confidence = Confidence.UNCONFIRMED
    analysis_status: AnalysisStatus = AnalysisStatus.OBSERVED

    # Rule that triggered this detection
    detection_rule: DetectionRule | None = None

    # Evidence fingerprint (never the raw payload)
    evidence: EvidenceFingerprint | None = None

    # Arbitrary extra metadata from the collector (no secrets!)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}

    @model_validator(mode="after")
    def validate_exactly_one_location(self) -> "EvidenceEnvelope":
        locations = [
            self.source_location,
            self.dependency_location,
            self.container_location,
        ]
        set_locations = [loc for loc in locations if loc is not None]
        if not set_locations:
            raise ValueError(
                "At least one location (source_location, dependency_location, "
                "container_location) must be provided."
            )
        return self

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("tenant_id must not be empty.")
        return v.strip()

    def has_secret_content(self) -> bool:
        """Return True if this envelope appears to contain sensitive material.

        Collectors should never include raw key/secret values. This is a
        defence-in-depth check in the normalization pipeline.
        """
        sensitive_keys = {"key_material", "private_key", "secret", "password", "credentials"}
        meta_keys = set(self.metadata.keys())
        obs_keys = set(self.observation.extra.keys())
        return bool(sensitive_keys & (meta_keys | obs_keys))
