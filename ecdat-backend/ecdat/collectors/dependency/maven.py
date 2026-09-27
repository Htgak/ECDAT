"""Maven dependency scanner.

Parses pom.xml files to resolve direct Maven dependencies with crypto capabilities.
Uses XML parsing — does not require mvn to be installed for static analysis.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
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

_MVN_NS = "http://maven.apache.org/POM/4.0.0"


def _tag(local: str) -> str:
    return f"{{{_MVN_NS}}}{local}"


class MavenDependencyScanner(CollectorInterface):
    """Scanner for Maven/Java dependencies via pom.xml parsing."""

    @property
    def name(self) -> str:
        return "maven-dependency"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> CollectorCapabilities:
        return CollectorCapabilities(
            ecosystems=["maven"],
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
        packages: list[tuple[str, str, str, bool]] = []   # (group, artifact, version, direct)
        errors: list[str] = []

        for pom_file in target.rglob("pom.xml"):
            try:
                packages.extend(self._parse_pom(pom_file))
            except Exception as e:
                errors.append(f"{pom_file}: {e}")

        envelopes = []
        for group_id, artifact_id, version, is_direct in packages:
            env = make_dependency_envelope(
                ecosystem="maven",
                package_name=artifact_id,
                package_version=version,
                dep_path=[],
                is_direct=is_direct,
                group_id=group_id,
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

    def _parse_pom(self, path: Path) -> list[tuple[str, str, str, bool]]:
        packages = []
        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except ET.ParseError:
            # Try without namespace
            content = path.read_text(encoding="utf-8", errors="replace")
            content = content.replace(' xmlns="http://maven.apache.org/POM/4.0.0"', "")
            root = ET.fromstring(content)

        # Handle both namespaced and non-namespaced pom.xml
        def find_deps(parent: ET.Element) -> list[ET.Element]:
            deps = parent.findall(f".//{_tag('dependency')}")
            if not deps:
                deps = parent.findall(".//dependency")
            return deps

        for dep in find_deps(root):
            def text(tag: str) -> str:
                el = dep.find(_tag(tag)) or dep.find(tag)
                return el.text.strip() if el is not None and el.text else ""

            group_id = text("groupId")
            artifact_id = text("artifactId")
            version = text("version") or "unknown"
            scope = text("scope") or "compile"

            if not artifact_id:
                continue

            # test/provided scope means not bundled in production artifact
            is_direct = scope not in ("test", "provided")
            packages.append((group_id, artifact_id, version, is_direct))

        return packages
