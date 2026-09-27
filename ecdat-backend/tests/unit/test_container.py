"""Unit tests for the Container scanner collector."""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from ecdat.collectors.base import CollectorInput
from ecdat.collectors.container.scanner import ContainerScanner


@pytest.mark.asyncio
class TestContainerScanner:
    async def test_container_scan_filesystem_artifacts(self, tmp_path: Path) -> None:
        # Create mock container filesystem layout
        lib_dir = tmp_path / "usr" / "lib"
        lib_dir.mkdir(parents=True)
        (lib_dir / "libcrypto.so.3").write_text("dummy elf")
        (lib_dir / "libsodium.so").write_text("dummy elf")

        certs_dir = tmp_path / "etc" / "ssl" / "certs"
        certs_dir.mkdir(parents=True)
        (certs_dir / "ca-certificates.crt").write_text("-----BEGIN CERTIFICATE-----\n...")

        scanner = ContainerScanner()
        inp = CollectorInput(
            scan_id="scan-c1",
            collector_run_id="run-c1",
            tenant_id="tenant-c1",
            target_path=str(tmp_path),
        )

        result = await scanner.scan(inp)
        assert result.findings_count >= 3
        algorithms = [e.observation.algorithm for e in result.envelopes]
        assert "OpenSSL-Crypto" in algorithms
        assert "Libsodium" in algorithms
        assert "X509-Certificate" in algorithms

    async def test_container_scan_nonexistent_path(self) -> None:
        scanner = ContainerScanner()
        inp = CollectorInput(
            scan_id="scan-c2",
            collector_run_id="run-c2",
            tenant_id="tenant-c2",
            target_path="/nonexistent/path/that/should/fail",
        )
        result = await scanner.scan(inp)
        assert result.findings_count == 0
        assert len(result.errors) > 0
