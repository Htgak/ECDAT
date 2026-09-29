"""CycloneDX 1.7 CBOM (Cryptography Bill of Materials) exporter.

Produces a CycloneDX 1.7 JSON document with:
  - cryptoProperties on each component
  - occurrences as externalReferences
  - evidence block per component
  - SHA-256 Merkle root in metadata

References:
  - CycloneDX spec 1.7: https://cyclonedx.org/docs/1.7/json/
  - CycloneDX Cryptography Extension: https://cyclonedx.org/capabilities/cbom/
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid() -> str:
    return f"urn:uuid:{uuid.uuid4()}"


class CycloneDX17Exporter:
    """Exports normalized findings to CycloneDX 1.7 CBOM format."""

    SPEC_VERSION = "1.7"
    BOM_FORMAT = "CycloneDX"

    def export(
        self,
        assets: list[dict[str, Any]],
        occurrences: list[dict[str, Any]],
        scan_metadata: dict[str, Any],
        include_evidence: bool = False,
    ) -> dict[str, Any]:
        """Build a CycloneDX 1.7 CBOM document.

        Args:
            assets: List of canonical asset dicts from the database.
            occurrences: List of occurrence dicts linked to the assets.
            scan_metadata: Scan-level metadata (scan_id, commit_ref, repository, etc.).
            include_evidence: Whether to include raw evidence references.

        Returns:
            A dict representing the CycloneDX 1.7 JSON document.
        """
        serial_number = _uuid()
        timestamp = _now_iso()

        # Build occurrence index by asset_id
        occ_by_asset: dict[str, list[dict]] = {}
        for occ in occurrences:
            aid = str(occ.get("asset_id", ""))
            occ_by_asset.setdefault(aid, []).append(occ)

        components = [
            self._asset_to_component(asset, occ_by_asset.get(str(asset["id"]), []), include_evidence)
            for asset in assets
        ]

        doc: dict[str, Any] = {
            "bomFormat": self.BOM_FORMAT,
            "specVersion": self.SPEC_VERSION,
            "serialNumber": serial_number,
            "version": 1,
            "metadata": self._build_metadata(scan_metadata, timestamp),
            "components": components,
        }

        # Embed Merkle root if available
        if merkle := scan_metadata.get("merkle_root"):
            doc["metadata"]["properties"] = doc["metadata"].get("properties", []) + [
                {"name": "ecdat:merkle_root", "value": merkle}
            ]

        from ecdat.integrations.validation import validate_document
        validate_document(doc, 'bom-1.7.schema.json')
        return doc

    def export_json(
        self,
        assets: list[dict],
        occurrences: list[dict],
        scan_metadata: dict,
        include_evidence: bool = False,
    ) -> str:
        """Export as JSON string."""
        doc = self.export(assets, occurrences, scan_metadata, include_evidence)
        return json.dumps(doc, indent=2, default=str)

    # ------------------------------------------------------------------ #
    # Internal builders                                                    #
    # ------------------------------------------------------------------ #

    def _build_metadata(self, scan: dict, timestamp: str) -> dict:
        return {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "ECDAT",
                    "name": "Enterprise Cryptographic Discovery & Analysis Tool",
                    "version": scan.get("ecdat_version", "1.0.0"),
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": f"scan:{scan.get('scan_id', '')}",
                "name": scan.get("repository_name", "unknown"),
                "version": scan.get("commit_ref", "unknown"),
            },
            "properties": [
                {"name": "ecdat:scan_id", "value": str(scan.get("scan_id", ""))},
                {"name": "ecdat:tenant_id", "value": str(scan.get("tenant_id", ""))},
                {"name": "ecdat:canonical_model_version", "value": scan.get("canonical_model_version", "1.0")},
            ],
        }

    def _asset_to_component(
        self,
        asset: dict,
        occurrences: list[dict],
        include_evidence: bool,
    ) -> dict:
        """Convert a single asset to a CycloneDX component."""
        bom_ref = f"asset:{asset['id']}"
        component: dict[str, Any] = {
            "type": "cryptographic-asset",
            "bom-ref": bom_ref,
            "name": self._asset_display_name(asset),
            "description": self._asset_description(asset),
            "cryptoProperties": self._build_crypto_properties(asset),
        }

        # occurrences as externalReferences
        if occurrences:
            component["externalReferences"] = [
                self._occurrence_to_ext_ref(occ)
                for occ in occurrences
            ]

        # Evidence block
        if include_evidence and occurrences:
            component["evidence"] = {
                "occurrences": [
                    {
                        "location": self._occurrence_location_string(occ),
                        **({"line": occ["line"]} if occ.get("line") else {}),
                    }
                    for occ in occurrences
                ]
            }

        return component

    def _asset_display_name(self, asset: dict) -> str:
        parts = [asset.get("algorithm", "")]
        if asset.get("key_size"):
            parts.append(str(asset["key_size"]))
        if asset.get("curve"):
            parts.append(f"({asset['curve']})")
        return "-".join(p for p in parts if p) or asset.get("asset_type", "unknown")

    def _asset_description(self, asset: dict) -> str:
        return (
            f"Confidence: {asset.get('confidence', 'unknown')} | "
            f"Analysis: {asset.get('analysis_status', 'unknown')} | "
            f"Usage: {asset.get('usage_evidence', 'unknown')}"
        )

    def _build_crypto_properties(self, asset: dict) -> dict:
        props: dict[str, Any] = {
            "assetType": self._map_asset_type(asset.get("asset_type", "")),
        }
        alg = asset.get("algorithm_normalized") or asset.get("algorithm")
        if alg:
            props["algorithmProperties"] = {
                "primitive": self._map_primitive(alg),
                "executionEnvironment": "unknown",
                "implementationPlatform": "unknown",
                "certificationLevel": [],
            }
            if asset.get("key_size"):
                props["algorithmProperties"]["parameterSetIdentifier"] = str(asset["key_size"])
            if asset.get("curve"):
                props["algorithmProperties"]["curve"] = asset["curve"]

        oid = self._algorithm_oid(alg or "")
        if oid:
            props["oid"] = oid
        return props

    def _map_asset_type(self, asset_type: str) -> str:
        mapping = {
            "algorithm": "algorithm",
            "key": "related-crypto-material",
            "certificate": "certificate",
            "protocol": "protocol",
        }
        return mapping.get(asset_type, "algorithm")

    def _map_primitive(self, algorithm: str) -> str:
        alg_upper = algorithm.upper()
        if "RSA" in alg_upper:
            return "pke"
        if "AES" in alg_upper:
            return "block-cipher"
        if "ECDSA" in alg_upper or "DSA" in alg_upper or "ML-DSA" in alg_upper:
            return "signature"
        if "ML-KEM" in alg_upper:
            return "kem"
        if "ECDH" in alg_upper:
            return "key-agree"
        if ("SHA" in alg_upper or "MD" in alg_upper or "BLAKE" in alg_upper) and not ("HMAC" in alg_upper or "PBKDF" in alg_upper):
            return "hash"
        if "HMAC" in alg_upper or "CMAC" in alg_upper:
            return "mac"
        if "PBKDF" in alg_upper or "HKDF" in alg_upper or "SCRYPT" in alg_upper:
            return "kdf"
        return "unknown"

    def _algorithm_oid(self, algorithm: str) -> str | None:
        # Common OIDs for display purposes
        oids = {
            "RSA": "1.2.840.113549.1.1.1",

            "SHA-256": "2.16.840.1.101.3.4.2.1",
            "SHA-384": "2.16.840.1.101.3.4.2.2",
            "SHA-512": "2.16.840.1.101.3.4.2.3",
            "SHA-1": "1.3.14.3.2.26",
            "MD5": "1.2.840.113549.2.5",

        }
        return oids.get(algorithm)

    def _occurrence_to_ext_ref(self, occ: dict) -> dict:
        loc = self._occurrence_location_string(occ)
        return {
            "type": "other",
            "url": loc,
            "comment": f"Collector: {occ.get('collector_name', 'unknown')}",
        }

    def _occurrence_location_string(self, occ: dict) -> str:
        loc_type = occ.get("location_type", "source")
        if loc_type == "source":
            path = occ.get("file_path", "")
            line = occ.get("line")
            repo = occ.get("repository", "")
            return f"{repo}/{path}#{line}" if line else f"{repo}/{path}"
        if loc_type == "container":
            return occ.get("image_reference", "")
        return occ.get("repository", "unknown")
