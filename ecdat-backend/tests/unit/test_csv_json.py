"""Unit tests for CSV and JSON exporters."""

from __future__ import annotations

import csv
import io
import pytest

from ecdat.integrations.csv_json.exporter import CSVExporter, JSONExporter


class TestCSVExporter:
    def test_csv_export_headers_and_rows(self) -> None:
        exporter = CSVExporter()
        assets = [
            {
                "id": "asset-1",
                "stable_id": "sha256:abcd",
                "algorithm": "RSA",
                "algorithm_normalized": "RSA",
                "asset_type": "algorithm",
                "confidence": "confirmed",
                "analysis_status": "confirmed",
            }
        ]
        occurrences = [
            {"asset_id": "asset-1", "file_path": "crypto.py", "start_line": 20}
        ]
        risk = {"asset-1": {"qars_score": 82.5}}
        advisory = {"asset-1": {"pqc_recommendation": "ML-KEM-768", "migration_effort": "medium"}}

        csv_text = exporter.export(
            assets=assets,
            occurrences=occurrences,
            risk_assessments=risk,
            advisories=advisory,
        )

        reader = csv.reader(io.StringIO(csv_text))
        rows = list(reader)
        assert len(rows) == 2  # header + 1 row
        assert rows[0] == CSVExporter.HEADERS
        assert rows[1][0] == "asset-1"
        assert rows[1][2] == "RSA"
        assert rows[1][7] == "crypto.py"
        assert rows[1][9] == "82.5"
        assert rows[1][10] == "ML-KEM-768"


class TestJSONExporter:
    def test_json_export_structure(self) -> None:
        exporter = JSONExporter()
        assets = [{"id": "a-1", "stable_id": "s-1", "algorithm": "AES"}]
        occurrences = [{"asset_id": "a-1", "file_path": "main.py"}]
        scan_meta = {"scan_id": "s-999"}

        data = exporter.export(scan_metadata=scan_meta, assets=assets, occurrences=occurrences)
        assert data["schema_version"] == "1.0"
        assert data["scan"]["scan_id"] == "s-999"
        assert data["total_assets"] == 1
        assert len(data["findings"]) == 1
        assert data["findings"][0]["asset"]["algorithm"] == "AES"
