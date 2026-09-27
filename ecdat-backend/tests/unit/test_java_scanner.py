"""Unit tests for Java source AST scanner."""

from __future__ import annotations

from pathlib import Path
import pytest

from ecdat.collectors.base import CollectorInput
from ecdat.collectors.source.java.scanner import JavaSourceScanner


@pytest.mark.asyncio
class TestJavaScanner:
    async def test_java_scanner_detects_jca_instances(self, tmp_path: Path) -> None:
        java_code = """
package com.example.crypto;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import javax.crypto.Cipher;

public class SecurityManager {
    public void init() throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
    }
}
"""
        src_file = tmp_path / "SecurityManager.java"
        src_file.write_text(java_code)

        scanner = JavaSourceScanner()
        inp = CollectorInput(
            scan_id="s-java-1",
            collector_run_id="r-java-1",
            tenant_id="t-java-1",
            target_path=str(tmp_path),
        )
        res = await scanner.scan(inp)
        assert res.findings_count >= 2
        algs = [e.observation.algorithm for e in res.envelopes]
        assert any("AES" in a for a in algs)
