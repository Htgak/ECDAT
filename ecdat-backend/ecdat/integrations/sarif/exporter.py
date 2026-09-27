"""SARIF 2.1 exporter.

Produces a SARIF (Static Analysis Results Interchange Format) 2.1
document from ECDAT scan findings. SARIF is the standard format for
integration with GitHub Advanced Security, Azure DevOps, VS Code,
and other developer tooling.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any


_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

# Severity mapping: our levels → SARIF severity
_SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
    "unknown": "none",
}

# Analysis status → SARIF kind
_KIND_MAP = {
    "vulnerable": "fail",
    "quantum_vulnerable": "fail",
    "deprecated": "fail",
    "policy_violation": "fail",
    "observed": "review",
    "under_review": "review",
    "approved": "open",
    "excluded": "open",
}


class SARIF21Exporter:
    """Exports ECDAT findings to SARIF 2.1 format."""

    TOOL_NAME = "ECDAT"
    TOOL_VERSION = "1.0.0"
    TOOL_URI = "https://ecdat.example.com"
    TOOL_INFORMATION_URI = "https://ecdat.example.com/docs/sarif"

    def export(
        self,
        findings: list[dict[str, Any]] | None = None,
        rules: list[dict[str, Any]] | None = None,
        scan_metadata: dict[str, Any] | None = None,
        assets: list[dict[str, Any]] | None = None,
        occurrences: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Build a SARIF 2.1 document."""
        scan_meta = scan_metadata or {}
        if findings is None:
            findings = []
            occ_by_aid = {}
            for o in (occurrences or []):
                occ_by_aid.setdefault(str(o.get("asset_id", "")), []).append(o)
            for a in (assets or []):
                aid = str(a.get("id", ""))
                a_occs = occ_by_aid.get(aid, [{}])
                for occ in a_occs:
                    findings.append({
                        "rule_id": "ECDAT-CRYPTO-001",
                        "rule_name": "Cryptographic Asset Detected",
                        "severity": "high" if "MD5" in str(a.get("algorithm", "")) or "SHA1" in str(a.get("algorithm", "")) else "medium",
                        "analysis_status": a.get("analysis_status", "confirmed"),
                        "algorithm": a.get("algorithm_normalized") or a.get("algorithm", "UNKNOWN"),
                        "confidence": a.get("confidence", "confirmed"),
                        "location_type": "source",
                        "file_path": occ.get("file_path", "unknown"),
                        "line": occ.get("start_line", 1),
                        "message": f"Cryptographic primitive detected: {a.get('algorithm')}",
                    })

        if rules is None:
            rules = [
                {
                    "rule_id": "ECDAT-CRYPTO-001",
                    "name": "Cryptographic Asset Detected",
                    "description": "Detected cryptographic primitive usage in application source or dependencies.",
                    "severity": "medium",
                }
            ]

        sarif_rules = [self._build_rule(r) for r in rules]
        sarif_results = [self._build_result(f) for f in findings]


        return {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": self._build_tool(sarif_rules),
                    "originalUriBaseIds": {
                        "SRCROOT": {"uri": scan_metadata.get("repository_url", "file:///")},
                    },
                    "versionControlProvenance": [
                        {
                            "repositoryUri": scan_metadata.get("repository_url", ""),
                            "revisionId": scan_metadata.get("commit_ref", ""),
                            "branch": scan_metadata.get("branch", ""),
                        }
                    ],
                    "results": sarif_results,
                    "properties": {
                        "ecdat:scan_id": str(scan_metadata.get("scan_id", "")),
                        "ecdat:tenant_id": str(scan_metadata.get("tenant_id", "")),
                        "ecdat:completed_at": datetime.now(timezone.utc).isoformat(),
                    },
                }
            ],
        }

    def export_json(
        self,
        findings: list[dict],
        rules: list[dict],
        scan_metadata: dict,
    ) -> str:
        """Export as JSON string."""
        return json.dumps(
            self.export(findings, rules, scan_metadata),
            indent=2,
            default=str,
        )

    # ------------------------------------------------------------------ #
    # Internal builders                                                    #
    # ------------------------------------------------------------------ #

    def _build_tool(self, rules: list[dict]) -> dict:
        return {
            "driver": {
                "name": self.TOOL_NAME,
                "version": self.TOOL_VERSION,
                "informationUri": self.TOOL_INFORMATION_URI,
                "organization": "ECDAT Team",
                "rules": rules,
            }
        }

    def _build_rule(self, rule: dict) -> dict:
        rule_id = rule.get("rule_id", "UNKNOWN")
        severity = rule.get("severity", "info")
        level = _SEVERITY_MAP.get(severity.lower(), "none")
        return {
            "id": rule_id,
            "name": rule.get("name", rule_id),
            "shortDescription": {"text": rule.get("name", rule_id)},
            "fullDescription": {"text": rule.get("description", "")},
            "defaultConfiguration": {"level": level},
            "helpUri": rule.get("help_uri", self.TOOL_INFORMATION_URI),
            "help": {
                "text": rule.get("description", ""),
                "markdown": self._rule_markdown(rule),
            },
            "properties": {
                "ecdat:severity": severity,
                "ecdat:source_reference": rule.get("source_reference", ""),
            },
        }

    def _build_result(self, finding: dict) -> dict:
        rule_id = finding.get("rule_id", "UNKNOWN")
        severity = finding.get("severity", "info")
        level = _SEVERITY_MAP.get(severity.lower(), "none")
        analysis_status = finding.get("analysis_status", "observed")
        kind = _KIND_MAP.get(analysis_status.lower(), "review")

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "kind": kind,
            "level": level,
            "message": {
                "text": self._result_message(finding),
            },
            "properties": {
                "ecdat:algorithm": finding.get("algorithm", ""),
                "ecdat:confidence": finding.get("confidence", ""),
                "ecdat:analysis_status": analysis_status,
                "ecdat:stable_id": finding.get("stable_id", ""),
            },
        }

        # Location
        location = self._build_location(finding)
        if location:
            result["locations"] = [location]

        # Related locations (other occurrences of same asset)
        if finding.get("other_occurrences"):
            result["relatedLocations"] = [
                self._build_location(occ)
                for occ in finding["other_occurrences"]
                if self._build_location(occ)
            ]

        # Fixes / suggestions (PQC recommendations)
        if finding.get("pqc_recommendation"):
            result["fixes"] = [self._build_fix(finding["pqc_recommendation"])]

        return result

    def _build_location(self, finding: dict) -> dict | None:
        loc_type = finding.get("location_type", "source")
        if loc_type == "source":
            file_path = finding.get("file_path", "")
            line = finding.get("line")
            if not file_path:
                return None
            region: dict[str, Any] = {}
            if line:
                region = {"startLine": line, "startColumn": 1}
            return {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_path.replace("\\", "/"),
                        "uriBaseId": "SRCROOT",
                    },
                    "region": region,
                }
            }
        if loc_type == "dependency":
            pkg = finding.get("package_name", "")
            ecosystem = finding.get("ecosystem", "")
            return {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f"dependency:{ecosystem}/{pkg}",
                        "uriBaseId": "SRCROOT",
                    },
                    "region": {},
                },
                "logicalLocations": [
                    {
                        "name": pkg,
                        "kind": "module",
                        "fullyQualifiedName": f"{ecosystem}:{pkg}@{finding.get('package_version', '')}",
                    }
                ],
            }
        return None

    def _build_fix(self, recommendation: dict) -> dict:
        return {
            "description": {
                "text": (
                    f"Migrate to {recommendation.get('name', 'PQC algorithm')}. "
                    f"{recommendation.get('notes', '')}"
                )
            },
            "artifactChanges": [],
        }

    def _result_message(self, finding: dict) -> str:
        alg = finding.get("algorithm", "unknown")
        confidence = finding.get("confidence", "")
        analysis = finding.get("analysis_status", "")
        pqc_rec = finding.get("pqc_recommendation", {})
        rec_name = pqc_rec.get("name", "") if pqc_rec else ""

        msg = f"Cryptographic use of '{alg}' detected"
        if confidence:
            msg += f" (confidence: {confidence})"
        if analysis in ("vulnerable", "quantum_vulnerable", "deprecated"):
            msg += f". Status: {analysis.replace('_', ' ')}."
        if rec_name:
            msg += f" Recommended migration: {rec_name}."
        return msg

    def _rule_markdown(self, rule: dict) -> str:
        lines = [
            f"## {rule.get('name', rule.get('rule_id', ''))}",
            "",
            rule.get("description", ""),
            "",
        ]
        if src := rule.get("source_reference"):
            lines += [f"**Reference**: [{src}]({src})", ""]
        return "\n".join(lines)


def findings_from_normalized(
    normalized_findings,
    correlation_groups=None,
) -> list[dict[str, Any]]:
    """Convert NormalizedFinding objects to SARIF finding dicts."""
    results = []
    for nf in normalized_findings:
        obs = nf.envelope.observation
        env = nf.envelope

        loc_type = "source"
        file_path = None
        line = None
        ecosystem = None
        pkg_name = None
        pkg_version = None

        if env.source_location:
            loc_type = "source"
            file_path = env.source_location.path
            line = env.source_location.line
        elif env.dependency_location:
            loc_type = "dependency"
            ecosystem = env.dependency_location.ecosystem
            pkg_name = env.dependency_location.package_name
            pkg_version = env.dependency_location.package_version

        rule_id = "ECDAT-UNKNOWN-001"
        if env.detection_rule:
            rule_id = env.detection_rule.rule_id

        results.append({
            "rule_id": rule_id,
            "severity": "high" if nf.normalized_algorithm and nf.normalized_algorithm.is_deprecated else "info",
            "analysis_status": nf.analysis_status.value,
            "algorithm": obs.algorithm or "",
            "confidence": nf.confidence_decision.confidence.value,
            "stable_id": nf.identity.stable_id,
            "location_type": loc_type,
            "file_path": file_path,
            "line": line,
            "ecosystem": ecosystem,
            "package_name": pkg_name,
            "package_version": pkg_version,
        })
    return results


# Export alias
SARIFExporter = SARIF21Exporter

