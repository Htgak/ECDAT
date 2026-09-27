"""CSV and JSON exporters for ECDAT scan findings.

Exports cryptographic inventory, occurrences, QARS risk scores,
and PQC migration recommendations into CSV or JSON formats.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any


class CSVExporter:
    """Exports cryptographic inventory to CSV format."""

    HEADERS = [
        "asset_id",
        "stable_id",
        "algorithm",
        "algorithm_normalized",
        "asset_type",
        "confidence",
        "analysis_status",
        "file_path",
        "line_number",
        "qars_score",
        "pqc_recommendation",
        "migration_effort",
    ]

    def export(
        self,
        assets: list[dict[str, Any]],
        occurrences: list[dict[str, Any]] | None = None,
        risk_assessments: dict[str, dict[str, Any]] | None = None,
        advisories: dict[str, dict[str, Any]] | None = None,
    ) -> str:
        """Export assets to CSV string."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(self.HEADERS)

        # Build occurrence lookup by asset_id
        occ_by_asset: dict[str, list[dict[str, Any]]] = {}
        if occurrences:
            for occ in occurrences:
                aid = str(occ.get("asset_id", ""))
                occ_by_asset.setdefault(aid, []).append(occ)

        risk_by_asset = risk_assessments or {}
        adv_by_asset = advisories or {}

        for asset in assets:
            aid = str(asset.get("id", ""))
            sid = asset.get("stable_id", "")
            alg = asset.get("algorithm", "")
            alg_norm = asset.get("algorithm_normalized", "")
            asset_type = asset.get("asset_type", "")
            conf = asset.get("confidence", "")
            status = asset.get("analysis_status", "")

            risk = risk_by_asset.get(aid, {})
            qars = risk.get("qars_score", "")

            adv = adv_by_asset.get(aid, {})
            pqc = adv.get("pqc_recommendation", "")
            effort = adv.get("migration_effort", "")

            asset_occs = occ_by_asset.get(aid, [{}])
            for occ in asset_occs:
                fp = occ.get("file_path", "")
                line = occ.get("start_line", "")
                writer.writerow([
                    aid,
                    sid,
                    alg,
                    alg_norm,
                    asset_type,
                    conf,
                    status,
                    fp,
                    line,
                    qars,
                    pqc,
                    effort,
                ])

        return output.getvalue()


class JSONExporter:
    """Exports complete scan findings to structured JSON."""

    def export(
        self,
        scan_metadata: dict[str, Any],
        assets: list[dict[str, Any]],
        occurrences: list[dict[str, Any]] | None = None,
        risk_assessments: dict[str, dict[str, Any]] | None = None,
        advisories: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Export scan assets and context to JSON-serializable dict."""
        occ_by_asset: dict[str, list[dict[str, Any]]] = {}
        if occurrences:
            for occ in occurrences:
                aid = str(occ.get("asset_id", ""))
                occ_by_asset.setdefault(aid, []).append(occ)

        risk_by_asset = risk_assessments or {}
        adv_by_asset = advisories or {}

        items = []
        for asset in assets:
            aid = str(asset.get("id", ""))
            items.append({
                "asset": asset,
                "occurrences": occ_by_asset.get(aid, []),
                "risk": risk_by_asset.get(aid),
                "advisory": adv_by_asset.get(aid),
            })

        return {
            "schema_version": "1.0",
            "generator": "ECDAT JSON Exporter 1.0",
            "scan": scan_metadata,
            "total_assets": len(assets),
            "findings": items,
        }
