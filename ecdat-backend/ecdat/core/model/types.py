"""Core Pydantic domain types shared across the entire ECDAT model.

These types are NOT SQLAlchemy models — they are pure Python/Pydantic
data classes used in memory, across the wire, and in Evidence Envelopes.
The ORM models in ecdat.core.model.* map to/from these types.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ======================================================================= #
# Enumerations                                                             #
# ======================================================================= #


class Confidence(str, Enum):
    """Detection confidence level.

    Rules:
    - CONFIRMED  : deterministic rule + exact evidence
    - PROBABLE   : correlated evidence or heuristic match
    - UNCONFIRMED: LLM hypothesis or weak signal only
    """

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    UNCONFIRMED = "unconfirmed"


class AnalysisStatus(str, Enum):
    """Explicit observation/analysis state — never conflated with 'secure'."""

    OBSERVED = "observed"
    NOT_OBSERVED = "not_observed"
    UNKNOWN = "unknown"
    INDETERMINATE = "indeterminate"
    UNSUPPORTED = "unsupported"


class UsageEvidence(str, Enum):
    """Evidence basis for a usage assertion."""

    STATIC = "static"       # AST / source-level evidence
    DYNAMIC = "dynamic"     # runtime observation
    INFERRED = "inferred"   # derived from indirect evidence
    UNKNOWN = "unknown"


class ObservationType(str, Enum):
    """Classification of the crypto observation."""

    ALGORITHM_USE = "algorithm_use"
    KEY_GENERATION = "key_generation"
    SIGNING = "signing"
    VERIFICATION = "verification"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    HASHING = "hashing"
    KEY_AGREEMENT = "key_agreement"
    KEY_DERIVATION = "key_derivation"
    RANDOM_GENERATION = "random_generation"
    CERTIFICATE_OPERATION = "certificate_operation"
    HARDCODED_MATERIAL = "hardcoded_material"


class DependencyEvidenceLevel(str, Enum):
    """Evidence level for dependency-sourced crypto findings.

    CAPABILITY   : package contains crypto functionality (does not imply use)
    IMPORT       : package is imported in application code
    STATIC_USE   : a specific crypto API is invoked in application code
    RUNTIME_USE  : a runtime observation confirms active use
    UNKNOWN      : insufficient evidence to classify
    """

    CAPABILITY = "capability"
    IMPORT = "import"
    STATIC_USE = "static_use"
    RUNTIME_USE = "runtime_use"
    UNKNOWN = "unknown"


class RelationshipType(str, Enum):
    """Typed edge between entities in the canonical model."""

    IMPLEMENTS = "implements"
    USES = "uses"
    DEPENDS_ON = "depends_on"
    CONTAINS = "contains"
    OBSERVED_ON = "observed_on"
    DERIVED_FROM = "derived_from"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CollectorStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"
    SKIPPED = "skipped"


class JobState(str, Enum):
    QUEUED = "queued"
    CLAIMED = "claimed"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED_RETRYABLE = "failed_retryable"
    FAILED_FINAL = "failed_final"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class JobType(str, Enum):
    SCAN_CREATE = "scan_create"
    COLLECT_SOURCE = "collect_source"
    COLLECT_DEPENDENCY = "collect_dependency"
    COLLECT_CONTAINER = "collect_container"
    NORMALIZE = "normalize"
    CORRELATE = "correlate"
    CALCULATE_RISK = "calculate_risk"
    EVALUATE_POLICY = "evaluate_policy"
    GENERATE_ADVISORY = "generate_advisory"
    GENERATE_CBOM = "generate_cbom"
    CREATE_SNAPSHOT = "create_snapshot"
    TIMESTAMP_SNAPSHOT = "timestamp_snapshot"
    GENERATE_EXPORT = "generate_export"


class ExposureClass(str, Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    DMZ = "dmz"
    UNKNOWN = "unknown"


class Criticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class PolicyVerdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    NOT_APPLICABLE = "not_applicable"


class StandardStatus(str, Enum):
    FINAL = "final"
    DRAFT = "draft"
    SELECTED_NOT_FINAL = "selected_not_final"
    DEPRECATED = "deprecated"
    EXPERIMENTAL = "experimental"


class AdvisoryConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class PolicyPackStatus(str, Enum):
    DRAFT = "draft"
    REVIEW = "review"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    RETIRED = "retired"


class ConflictResolutionState(str, Enum):
    UNRESOLVED = "unresolved"
    RESOLVED = "resolved"
    ACCEPTED_CONFLICT = "accepted_conflict"


class MatchType(str, Enum):
    STABLE_EXTERNAL_ID = "stable_external_id"
    CERTIFICATE_FINGERPRINT = "certificate_fingerprint"
    PACKAGE_COORDINATES = "package_coordinates"
    REPO_PATH_SEMANTIC = "repo_path_semantic"
    NORMALIZED_OBSERVATION = "normalized_observation"
    NEW_ASSET = "new_asset"
    POSSIBLE_DUPLICATE = "possible_duplicate"


class ErrorClass(str, Enum):
    RETRYABLE = "retryable"
    NON_RETRYABLE = "non_retryable"
    SECURITY = "security"
    CONFIGURATION = "configuration"
    UNSUPPORTED = "unsupported"


# ======================================================================= #
# Value Objects                                                            #
# ======================================================================= #


class SourceLocation(BaseModel):
    """File + position within a source repository."""

    repository: str
    path: str
    line: int | None = None
    column: int | None = None
    commit_ref: str | None = None

    model_config = {"frozen": True}


class PackageCoordinates(BaseModel):
    """Canonical identifier for a software package."""

    ecosystem: str          # npm | pypi | maven | go
    name: str
    version: str
    group: str | None = None   # Maven groupId

    model_config = {"frozen": True}

    def to_purl(self) -> str:
        """Return a Package URL (purl) string."""
        eco = self.ecosystem.lower()
        if self.group:
            return f"pkg:{eco}/{self.group}/{self.name}@{self.version}"
        return f"pkg:{eco}/{self.name}@{self.version}"
