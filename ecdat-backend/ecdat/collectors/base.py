"""Collector Interface — the contract that every ECDAT collector must implement.

Collectors are isolated processes/modules. They:
- Accept a scoped CollectorInput
- Emit a list of EvidenceEnvelope instances
- Cannot directly mutate business tables
- Cannot access unrelated tenant data
- Are resource-limited (enforced by the worker)
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CollectorCapabilities:
    """Declares what a collector can detect."""

    languages: list[str] = field(default_factory=list)        # e.g. ["java", "python"]
    ecosystems: list[str] = field(default_factory=list)       # e.g. ["npm", "pypi"]
    asset_types: list[str] = field(default_factory=list)      # e.g. ["algorithm", "certificate"]
    supports_incremental: bool = False
    requires_network: bool = False


@dataclass(frozen=True)
class CollectorInput:
    """Scoped input for a collector invocation."""

    scan_id: str
    collector_run_id: str
    tenant_id: str
    target_path: str              # local filesystem path of the cloned/mounted target
    repository_url: str | None = None
    commit_ref: str | None = None
    input_revision: str | None = None
    configuration: dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectorResult:
    """Return value from a collector run."""

    from ecdat.core.evidence.envelope import EvidenceEnvelope  # local import to avoid cycles

    envelopes: list["EvidenceEnvelope"] = field(default_factory=list)
    findings_count: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    is_partial: bool = False
    unsupported_reason: str | None = None


class CollectorInterface(abc.ABC):
    """Abstract base class for all ECDAT collectors.

    Subclasses must implement :meth:`scan` and declare their
    :attr:`name`, :attr:`version`, and :attr:`capabilities`.
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique, stable name of this collector, e.g. ``java-source``."""

    @property
    @abc.abstractmethod
    def version(self) -> str:
        """SemVer string of this collector, e.g. ``1.0.0``."""

    @property
    @abc.abstractmethod
    def capabilities(self) -> CollectorCapabilities:
        """Declared capabilities of this collector."""

    @abc.abstractmethod
    async def scan(self, inp: CollectorInput) -> CollectorResult:
        """Execute the collector and return its result.

        This method must NOT:
        - Write directly to any database table.
        - Read data belonging to other tenants.
        - Persist raw secret values.
        - Make arbitrary network calls unless :attr:`capabilities.requires_network` is True.

        Args:
            inp: Scoped collector input.

        Returns:
            CollectorResult containing zero or more EvidenceEnvelope instances.
        """

    def validate_input(self, inp: CollectorInput) -> None:
        """Validate that the input is sufficient for this collector.

        Raises ValueError if the input is invalid.
        Override for collector-specific validation.
        """
        if not inp.scan_id:
            raise ValueError("scan_id must not be empty.")
        if not inp.tenant_id:
            raise ValueError("tenant_id must not be empty.")
        if not inp.target_path:
            raise ValueError("target_path must not be empty.")
