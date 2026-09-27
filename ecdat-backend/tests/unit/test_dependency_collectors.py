"""Unit tests for npm, Maven, and Go dependency scanners."""

from __future__ import annotations

from pathlib import Path
import pytest

from ecdat.collectors.base import CollectorInput
from ecdat.collectors.dependency.gomod import GoModDependencyScanner
from ecdat.collectors.dependency.maven import MavenDependencyScanner
from ecdat.collectors.dependency.npm import NpmDependencyScanner


@pytest.mark.asyncio
class TestDependencyScanners:
    async def test_npm_scanner_package_json_and_lock(self, tmp_path: Path) -> None:
        pkg_json = """
{
  "name": "sample-app",
  "dependencies": {
    "crypto-js": "^4.2.0",
    "bcrypt": "^5.1.0"
  }
}
"""
        (tmp_path / "package.json").write_text(pkg_json)

        scanner = NpmDependencyScanner()
        inp = CollectorInput(
            scan_id="s-npm",
            collector_run_id="r-npm",
            tenant_id="t-npm",
            target_path=str(tmp_path),
        )
        res = await scanner.scan(inp)
        assert res.findings_count >= 2
        algs = [e.observation.algorithm for e in res.envelopes]
        assert "crypto-js" in algs or "bcrypt" in algs

    async def test_maven_scanner_pom_xml(self, tmp_path: Path) -> None:
        pom_xml = """<project>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78</version>
    </dependency>
  </dependencies>
</project>"""
        (tmp_path / "pom.xml").write_text(pom_xml)

        scanner = MavenDependencyScanner()
        inp = CollectorInput(
            scan_id="s-mvn",
            collector_run_id="r-mvn",
            tenant_id="t-mvn",
            target_path=str(tmp_path),
        )
        res = await scanner.scan(inp)
        assert res.findings_count >= 1
        pkg_names = [e.dependency_location.package_name for e in res.envelopes if e.dependency_location]
        assert "bcprov-jdk18on" in pkg_names

    async def test_gomod_scanner(self, tmp_path: Path) -> None:
        go_mod = """module sample

go 1.22

require (
    golang.org/x/crypto v0.21.0
)
"""
        (tmp_path / "go.mod").write_text(go_mod)

        scanner = GoModDependencyScanner()
        inp = CollectorInput(
            scan_id="s-go",
            collector_run_id="r-go",
            tenant_id="t-go",
            target_path=str(tmp_path),
        )
        res = await scanner.scan(inp)
        assert res.findings_count >= 1
