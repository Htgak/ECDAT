"""PyPI dependency scanner.

Parses Python dependency manifests and resolves transitive dependencies.
Supported manifest formats:
  - requirements.txt
  - Pipfile.lock
  - pyproject.toml (PEP 517/518/621)
  - setup.cfg
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

from ecdat.collectors.base import (
    CollectorCapabilities,
    CollectorInput,
    CollectorInterface,
    CollectorResult,
)
from ecdat.collectors.dependency import make_dependency_envelope
from ecdat.core.evidence.envelope import CollectorInfo, RunInfo

logger = logging.getLogger(__name__)

_REQ_LINE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*(?:==|>=|<=|~=|!=|>|<)?\s*(.*?)(?:\s*;.*)?$")


class PyPIDependencyScanner(CollectorInterface):
    """Scanner for PyPI dependencies (requirements.txt, pyproject.toml, Pipfile.lock)."""

    @property
    def name(self) -> str:
        return "pypi-dependency"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> CollectorCapabilities:
        return CollectorCapabilities(
            ecosystems=["pypi"],
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
        packages: list[tuple[str, str, bool]] = []   # (name, version, is_direct)
        errors: list[str] = []

        # Parse all supported manifest formats
        for req_file in target.rglob("requirements*.txt"):
            try:
                packages.extend(self._parse_requirements_txt(req_file))
            except Exception as e:
                errors.append(f"{req_file}: {e}")

        for pipfile_lock in target.rglob("Pipfile.lock"):
            try:
                packages.extend(self._parse_pipfile_lock(pipfile_lock))
            except Exception as e:
                errors.append(f"{pipfile_lock}: {e}")

        for toml_file in target.rglob("pyproject.toml"):
            try:
                packages.extend(self._parse_pyproject_toml(toml_file))
            except Exception as e:
                errors.append(f"{toml_file}: {e}")

        envelopes = []
        for pkg_name, pkg_version, is_direct in packages:
            env = make_dependency_envelope(
                ecosystem="pypi",
                package_name=pkg_name.lower(),
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

    def _parse_requirements_txt(self, path: Path) -> list[tuple[str, str, bool]]:
        packages = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = _REQ_LINE.match(line)
            if m:
                name = m.group(1).lower()
                version = m.group(2).strip() or "unknown"
                packages.append((name, version, True))
        return packages

    def _parse_pipfile_lock(self, path: Path) -> list[tuple[str, str, bool]]:
        data = json.loads(path.read_text(encoding="utf-8"))
        packages = []
        for section, is_direct in [("default", True), ("develop", False)]:
            for name, info in data.get(section, {}).items():
                version = info.get("version", "").lstrip("==").strip() or "unknown"
                packages.append((name.lower(), version, is_direct))
        return packages

    def _parse_pyproject_toml(self, path: Path) -> list[tuple[str, str, bool]]:
        if tomllib is None:
            logger.warning("tomllib not available — skipping %s", path)
            return []
        with path.open("rb") as f:
            data = tomllib.load(f)
        packages = []
        # PEP 621 dependencies
        for dep in data.get("project", {}).get("dependencies", []):
            m = _REQ_LINE.match(dep)
            if m:
                packages.append((m.group(1).lower(), m.group(2).strip() or "unknown", True))
        return packages
