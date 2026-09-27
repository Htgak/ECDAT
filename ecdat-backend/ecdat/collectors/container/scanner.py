"""Container collector — wrapper around cbomkit-theia / container image inspection.

Inspects container filesystems or extracted image layers for:
- Embedded cryptographic keys, certificates (.pem, .crt, .key, .p12, .jks)
- Cryptographic shared libraries (libcrypto.so, libssl.so, libsodium.so, etc.)
- Invokes cbomkit-theia CLI when installed, falling back to layer filesystem inspection.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ecdat.collectors.base import (
    CollectorCapabilities,
    CollectorInput,
    CollectorInterface,
    CollectorResult,
)
from ecdat.core.evidence.envelope import (
    CollectorInfo,
    ContainerLocation,
    CryptoObservation,
    DetectionRule,
    EvidenceEnvelope,
    EvidenceFingerprint,
    RunInfo,
)
from ecdat.core.model.types import (
    AnalysisStatus,
    Confidence,
    ObservationType,
    UsageEvidence,
)

logger = logging.getLogger(__name__)

# Known crypto binary/shared libraries in container layers
_CRYPTO_LIBRARIES: dict[str, dict[str, Any]] = {
    "libcrypto.so": {"family": "OpenSSL", "algorithm": "OpenSSL-Crypto", "role": "library"},
    "libssl.so": {"family": "OpenSSL", "algorithm": "OpenSSL-SSL", "role": "library"},
    "libsodium.so": {"family": "Libsodium", "algorithm": "Libsodium", "role": "library"},
    "libwolfssl.so": {"family": "wolfSSL", "algorithm": "wolfSSL", "role": "library"},
    "liboqs.so": {"family": "liboqs", "algorithm": "liboqs-PQC", "role": "pqc_library"},
    "libgnutls.so": {"family": "GnuTLS", "algorithm": "GnuTLS", "role": "library"},
    "libnettle.so": {"family": "Nettle", "algorithm": "Nettle", "role": "library"},
}

# Certificate and keystore file extensions
_CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".p12", ".pfx", ".jks", ".keystore"}


class ContainerScanner(CollectorInterface):
    """Collector that inspects container images or root filesystems."""

    @property
    def name(self) -> str:
        return "container-theia-collector"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def capabilities(self) -> CollectorCapabilities:
        return CollectorCapabilities(
            languages=["binary", "container"],
            ecosystems=["docker", "oci"],
            asset_types=["library", "certificate", "algorithm"],
            supports_incremental=False,
            requires_network=False,
        )

    async def scan(self, inp: CollectorInput) -> CollectorResult:
        """Scan target container directory or invoke cbomkit-theia."""
        envelopes: list[EvidenceEnvelope] = []
        errors: list[str] = []
        warnings: list[str] = []

        target_dir = Path(inp.target_path)
        if not target_dir.exists():
            return CollectorResult(
                envelopes=[],
                findings_count=0,
                errors=[f"Target path does not exist: {inp.target_path}"],
            )

        # 1. Try cbomkit-theia CLI if installed
        theia_bin = shutil.which("cbomkit-theia") or shutil.which("theia")
        if theia_bin:
            try:
                theia_envelopes = self._run_cbomkit_theia(theia_bin, target_dir, inp)
                envelopes.extend(theia_envelopes)
            except Exception as exc:
                warnings.append(f"cbomkit-theia execution failed: {exc}, falling back to layer scan")

        # 2. Inspect filesystem for crypto libraries and certificates
        fs_envelopes = self._scan_filesystem_artifacts(target_dir, inp)
        envelopes.extend(fs_envelopes)

        return CollectorResult(
            envelopes=envelopes,
            findings_count=len(envelopes),
            errors=errors,
            warnings=warnings,
        )

    def _run_cbomkit_theia(
        self, theia_bin: str, target_dir: Path, inp: CollectorInput
    ) -> list[EvidenceEnvelope]:
        """Invoke cbomkit-theia and parse output into EvidenceEnvelopes."""
        cmd = [theia_bin, "scan", "--format", "json", str(target_dir)]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"theia exited with code {proc.returncode}: {proc.stderr[:300]}")

        output_data = json.loads(proc.stdout)
        return self._parse_theia_json(output_data, inp)

    def _parse_theia_json(
        self, data: dict[str, Any], inp: CollectorInput
    ) -> list[EvidenceEnvelope]:
        """Convert cbomkit-theia output JSON to EvidenceEnvelopes."""
        envelopes = []
        components = data.get("components", [])
        for comp in components:
            alg_name = comp.get("name") or comp.get("cryptoProperties", {}).get("algorithmName", "UNKNOWN")
            location_path = comp.get("purl") or comp.get("bom-ref", "container:/")
            sha256 = hashlib.sha256(f"{alg_name}:{location_path}".encode()).hexdigest()

            env = EvidenceEnvelope(
                collector=CollectorInfo(
                    name=self.name,
                    version=self.version,
                ),
                run=RunInfo(
                    scan_id=inp.scan_id,
                    collector_run_id=inp.collector_run_id,
                ),
                tenant_id=inp.tenant_id,
                container_location=ContainerLocation(
                    image_reference=inp.repository_url or "container-image:latest",
                    path_in_layer=location_path,
                ),
                observation=CryptoObservation(
                    observation_type=ObservationType.ALGORITHM_USE,
                    algorithm=alg_name,
                    algorithm_raw=comp.get("name"),
                    usage_evidence=UsageEvidence.STATIC,
                ),
                confidence=Confidence.CONFIRMED,
                analysis_status=AnalysisStatus.OBSERVED,
                evidence=EvidenceFingerprint(
                    algorithm="sha256",
                    digest=sha256,
                ),
                detection_rule=DetectionRule(
                    rule_id="CBOMKIT-THEIA-001",
                    rule_version="1.0",
                    rule_name="cbomkit-theia component detection",
                ),
            )
            envelopes.append(env)
        return envelopes

    def _scan_filesystem_artifacts(
        self, target_dir: Path, inp: CollectorInput
    ) -> list[EvidenceEnvelope]:
        """Scan directory tree for crypto libraries and certificates."""
        envelopes = []
        for root, _, files in os.walk(target_dir):
            for file_name in files:
                file_path = Path(root) / file_name
                rel_path = str(file_path.relative_to(target_dir)).replace("\\", "/")

                # Check for cryptographic shared libraries
                for lib_prefix, meta in _CRYPTO_LIBRARIES.items():
                    if file_name == lib_prefix or file_name.startswith(lib_prefix):
                        file_hash = hashlib.sha256(rel_path.encode()).hexdigest()
                        envelopes.append(
                            EvidenceEnvelope(
                                collector=CollectorInfo(
                                    name=self.name,
                                    version=self.version,
                                ),
                                run=RunInfo(
                                    scan_id=inp.scan_id,
                                    collector_run_id=inp.collector_run_id,
                                ),
                                tenant_id=inp.tenant_id,
                                container_location=ContainerLocation(
                                    image_reference=inp.repository_url or "container-image:latest",
                                    path_in_layer=rel_path,
                                ),
                                observation=CryptoObservation(
                                    observation_type=ObservationType.ALGORITHM_USE,
                                    algorithm=meta["algorithm"],
                                    algorithm_raw=file_name,
                                    usage_evidence=UsageEvidence.STATIC,
                                ),
                                confidence=Confidence.CONFIRMED,
                                analysis_status=AnalysisStatus.OBSERVED,
                                evidence=EvidenceFingerprint(
                                    algorithm="sha256",
                                    digest=file_hash,
                                ),
                                detection_rule=DetectionRule(
                                    rule_id="CONTAINER-LIB-001",
                                    rule_version="1.0",
                                    rule_name="Container crypto shared library",
                                ),
                            )
                        )
                        break

                # Check for certificate / keystore files
                if any(file_name.lower().endswith(ext) for ext in _CERT_EXTENSIONS):
                    file_hash = hashlib.sha256(rel_path.encode()).hexdigest()
                    envelopes.append(
                        EvidenceEnvelope(
                            collector=CollectorInfo(
                                name=self.name,
                                version=self.version,
                            ),
                            run=RunInfo(
                                scan_id=inp.scan_id,
                                collector_run_id=inp.collector_run_id,
                            ),
                            tenant_id=inp.tenant_id,
                            container_location=ContainerLocation(
                                image_reference=inp.repository_url or "container-image:latest",
                                path_in_layer=rel_path,
                            ),
                            observation=CryptoObservation(
                                observation_type=ObservationType.CERTIFICATE_OPERATION,
                                algorithm="X509-Certificate",
                                algorithm_raw=file_name,
                                usage_evidence=UsageEvidence.STATIC,
                            ),
                            confidence=Confidence.PROBABLE,
                            analysis_status=AnalysisStatus.OBSERVED,
                            evidence=EvidenceFingerprint(
                                algorithm="sha256",
                                digest=file_hash,
                            ),
                            detection_rule=DetectionRule(
                                rule_id="CONTAINER-CERT-001",
                                rule_version="1.0",
                                rule_name="Container certificate or keystore file",
                            ),
                        )
                    )

        return envelopes

