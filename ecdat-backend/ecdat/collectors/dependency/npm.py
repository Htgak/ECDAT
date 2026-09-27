"""npm dependency scanner.

Parses package.json and package-lock.json to resolve direct and transitive
npm dependencies with crypto capabilities.
"""

from __future__ import annotations

import json
import logging
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


class NpmDependencyScanner(CollectorInterface):
    """Scanner for npm/Node.js dependencies."""

    @property
    def name(self) -> str:
        return "npm-dependency"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> CollectorCapabilities:
        return CollectorCapabilities(
            ecosystems=["npm"],
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

        # Prefer package-lock.json (has resolved versions and full tree)
        for lock_file in target.rglob("package-lock.json"):
            try:
                packages.extend(self._parse_lock(lock_file))
            except Exception as e:
                errors.append(f"{lock_file}: {e}")

        # Fall back to package.json if no lock file found
        if not packages:
            for pkg_json in target.rglob("package.json"):
                if "node_modules" in str(pkg_json):
                    continue
                try:
                    packages.extend(self._parse_package_json(pkg_json))
                except Exception as e:
                    errors.append(f"{pkg_json}: {e}")

        envelopes = []
        for pkg_name, pkg_version, is_direct in packages:
            env = make_dependency_envelope(
                ecosystem="npm",
                package_name=pkg_name,
                package_version=pkg_version,
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

    def _parse_lock(self, path: Path) -> list[tuple[str, str, bool]]:
        data = json.loads(path.read_text(encoding="utf-8"))
        packages = []
        # npm v2/v3 lockfile format
        for pkg_path, info in data.get("packages", {}).items():
            if not pkg_path:  # root package
                continue
            name = pkg_path.split("node_modules/")[-1]
            version = info.get("version", "unknown")
            is_direct = info.get("dev", False) is False and "/" not in pkg_path.replace(
                "node_modules/", "", 1
            )
            packages.append((name, version, is_direct))
        # npm v1 lockfile
        for name, info in data.get("dependencies", {}).items():
            version = info.get("version", "unknown")
            packages.append((name, version, True))
        return packages

    def _parse_package_json(self, path: Path) -> list[tuple[str, str, bool]]:
        data = json.loads(path.read_text(encoding="utf-8"))
        packages = []
        for section, is_direct in [("dependencies", True), ("devDependencies", False)]:
            for name, version in data.get(section, {}).items():
                # Strip semver prefix characters
                version = version.lstrip("^~>=<").strip() or "unknown"
                packages.append((name, version, is_direct))
        return packages
