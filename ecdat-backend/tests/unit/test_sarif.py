"""Unit tests for SARIF 2.1 exporter."""

from __future__ import annotations

import pytest

from ecdat.integrations.sarif.exporter import SARIF21Exporter, SARIFExporter


class TestSARIFExporter:
    def setup_method(self) -> None:
        self.exporter = SARIF21Exporter()

    def test_export_basic_structure(self) -> None:
        findings = [
            {
                "rule_id": "ECDAT-RSA-001",
                "rule_name": "RSA key length check",
                "severity": "high",
                "analysis_status": "deprecated",
                "algorithm": "RSA-1024",
                "confidence": "confirmed",
                "location_type": "source",
                "file_path": "src/Security.java",
                "line": 42,
                "message": "Insecure RSA key size: 1024",
            }
        ]
        rules = [
            {
                "rule_id": "ECDAT-RSA-001",
                "name": "RSA key length check",
                "description": "Checks RSA key length is at least 2048",
                "severity": "high",
            }
        ]
        meta = {"scan_id": "s-123", "repository_url": "https://github.com/org/repo"}

        doc = self.exporter.export(findings=findings, rules=rules, scan_metadata=meta)
        assert doc["version"] == "2.1.0"
        assert len(doc["runs"]) == 1
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "ECDAT"
        assert len(run["results"]) == 1
        res = run["results"][0]
        assert res["ruleId"] == "ECDAT-RSA-001"
        assert res["level"] == "error"
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/Security.java"

    def test_export_from_assets_and_occurrences(self) -> None:
        assets = [
            {"id": "a-1", "algorithm": "MD5", "confidence": "confirmed", "analysis_status": "vulnerable"},
            {"id": "a-2", "algorithm": "AES-256", "confidence": "confirmed", "analysis_status": "approved"},
        ]
        occurrences = [
            {"asset_id": "a-1", "file_path": "auth.py", "start_line": 15},
            {"asset_id": "a-2", "file_path": "cipher.py", "start_line": 88},
        ]
        meta = {"scan_id": "scan-99"}

        doc = SARIFExporter().export(assets=assets, occurrences=occurrences, scan_metadata=meta)
        assert doc["version"] == "2.1.0"
        results = doc["runs"][0]["results"]
        assert len(results) == 2
        md5_res = [r for r in results if "MD5" in r["message"]["text"]][0]
        assert md5_res["level"] == "error"
