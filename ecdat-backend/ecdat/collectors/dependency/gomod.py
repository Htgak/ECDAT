"""Go modules dependency scanner.

Parses go.mod and go.sum files to resolve Go module dependencies
with crypto capabilities.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ecdat.collectors.base import (
    CollectorCapabilities,
    CollectorInput,
    CollectorInterface,
    CollectorResult,
)
from ecdat.collectors.dependency import make_dependency_envelope
from ecdat.core.evidence.envelope import CollectorInfo, RunInfo

logger = logging.getLogger(__name__)

_REQUIRE_RE = re.compile(r"^\s+([^\s]+)\s+v([^\s]+)")


class GoModDependencyScanner(CollectorInterface):
    """Scanner for Go module dependencies via go.mod parsing."""

    @property
    def name(self) -> str:
        return "gomod-dependency"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> CollectorCapabilities:
        return CollectorCapabilities(
            ecosystems=["go"],
            asset_types=["library"],
            supports_incremental=False,
            requires_network=False,
        )

    async def scan(self, inp: CollectorInput) -> CollectorResult:
        self.validate_input(inp)

        collector_info = CollectorInfo(name=self.name, version=self.version)
        run_info = RunInfo(
            scan_id=inp.scan_id,
            collector_run_id=inp.collector_run_id,
            input_revision=inp.input_revision,
        )

        target = Path(inp.target_path)
        packages: list[tuple[str, str, bool]] = []
        errors: list[str] = []

        for gomod in target.rglob("go.mod"):
            try:
                packages.extend(self._parse_gomod(gomod))
            except Exception as e:
                errors.append(f"{gomod}: {e}")

        envelopes = []
        for module_path, version, is_direct in packages:
            env = make_dependency_envelope(
                ecosystem="go",
                package_name=module_path,
                package_version=version,
                dep_path=[],
                is_direct=is_direct,
                group_id=None,
                collector_info=collector_info,
                run_info=run_info,
                inp=inp,
            )
            if env:
                envelopes.append(env)

        return CollectorResult(
            envelopes=envelopes,
            findings_count=len(envelopes),
            errors=errors,
            is_partial=len(errors) > 0,
        )

    def _parse_gomod(self, path: Path) -> list[tuple[str, str, bool]]:
        """Parse go.mod and return (module, version, is_direct) tuples."""
        packages = []
        content = path.read_text(encoding="utf-8", errors="replace")

        in_require = False
        for line in content.splitlines():
            stripped = line.strip()

            if stripped.startswith("require ("):
                in_require = True
                continue
            if stripped == ")" and in_require:
                in_require = False
                continue

            if in_require:
                m = _REQUIRE_RE.match(line)
                if m:
                    module = m.group(1)
                    version = m.group(2)
                    is_indirect = "// indirect" in line
                    packages.append((module, version, not is_indirect))
            elif stripped.startswith("require "):
                # Single-line require: require module version
                parts = stripped.split()
                if len(parts) == 3:
                    packages.append((parts[1], parts[2].lstrip("v"), True))

        return packages
