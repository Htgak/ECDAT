"""Binary and compiled artifact collector.

Inspects compiled binaries, shared libraries, Java class/JAR archives,
and executables for cryptographic usage, symbols, and constant tables.

Supports:
- ELF, PE, Mach-O binary parsing via Ghidra headless (when available).
- APK / DEX / JAR decompilation via JADX (when available).
- JVM bytecode (.class / .jar) constant pool scanning for JCA/BouncyCastle crypto APIs.
- Cryptographic constant byte pattern recognition (AES S-box, MD5/SHA state vectors, DES tables).
- Symbol table string scanning (OpenSSL, libsodium, Windows CNG, liboqs).

Decompiler availability is probed once at module load.  When JADX or Ghidra
are absent the scanner falls back to string indicators and discloses the gap.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import zipfile
from pathlib import Path
from typing import Any

import structlog

from ecdat.collectors.base import (
    CollectorCapabilities,
    CollectorInput,
    CollectorInterface,
    CollectorResult,
)
from ecdat.collectors.binary.decompiler import (
    DecompileResult,
    decompile_and_scan,
)
from ecdat.core.evidence.envelope import (
    CollectorInfo,
    CryptoObservation,
    DetectionRule,
    EvidenceEnvelope,
    EvidenceFingerprint,
    RunInfo,
    SourceLocation,
)
from ecdat.core.model.types import (
    Confidence,
    ObservationType,
    UsageEvidence,
)

logger = structlog.get_logger(__name__)

# Known binary extensions
BINARY_EXTENSIONS = {
    ".so", ".dll", ".dylib", ".exe", ".bin", ".elf", ".o", ".a",
    ".jar", ".war", ".ear", ".class", ".pyc",
}

# Cryptographic symbols mapping to canonical algorithms and families
KNOWN_CRYPTO_SYMBOLS: dict[str, dict[str, str]] = {
    # OpenSSL / BoringSSL
    "EVP_aes_256_gcm": {"algorithm": "AES", "key_size": "256", "mode": "GCM", "family": "symmetric"},
    "EVP_aes_128_gcm": {"algorithm": "AES", "key_size": "128", "mode": "GCM", "family": "symmetric"},
    "EVP_aes_256_cbc": {"algorithm": "AES", "key_size": "256", "mode": "CBC", "family": "symmetric"},
    "EVP_des_ede3_cbc": {"algorithm": "3DES", "key_size": "168", "mode": "CBC", "family": "symmetric"},
    "RSA_generate_key_ex": {"algorithm": "RSA", "family": "asymmetric"},
    "RSA_new": {"algorithm": "RSA", "family": "asymmetric"},
    "RSA_public_encrypt": {"algorithm": "RSA", "family": "asymmetric"},
    "EC_KEY_new_by_curve_name": {"algorithm": "ECDSA", "family": "asymmetric"},
    "ECDSA_do_sign": {"algorithm": "ECDSA", "family": "asymmetric"},
    "MD5_Init": {"algorithm": "MD5", "family": "hash"},
    "SHA1_Init": {"algorithm": "SHA-1", "family": "hash"},
    "SHA256_Init": {"algorithm": "SHA-256", "family": "hash"},
    "SHA384_Init": {"algorithm": "SHA-384", "family": "hash"},
    "SHA512_Init": {"algorithm": "SHA-512", "family": "hash"},
    # Libsodium
    "crypto_secretbox_easy": {"algorithm": "XSalsa20", "family": "symmetric"},
    "crypto_box_easy": {"algorithm": "X25519", "family": "asymmetric"},
    "crypto_sign_ed25519": {"algorithm": "Ed25519", "family": "asymmetric"},
    # Post-Quantum (liboqs / FIPS 203 / 204)
    "OQS_KEM_ml_kem_768_encaps": {"algorithm": "ML-KEM-768", "family": "pqc_kem"},
    "OQS_SIG_ml_dsa_65_sign": {"algorithm": "ML-DSA-65", "family": "pqc_sig"},
    "OQS_KEM_kyber_768_encaps": {"algorithm": "Kyber-768", "family": "pqc_kem"},
    # Windows CNG / CAPI
    "BCryptEncrypt": {"algorithm": "CNG-Cipher", "family": "symmetric"},
    "BCryptCreateHash": {"algorithm": "CNG-Hash", "family": "hash"},
}

# Cryptographic constant byte signatures (e.g. S-boxes, initial vectors)
CRYPTO_BYTE_SIGNATURES: list[dict[str, Any]] = [
    {
        "name": "AES-S-Box",
        "algorithm": "AES",
        "bytes": bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]),
        "rule_id": "BIN-CONST-AES-SBOX",
    },
    {
        "name": "SHA-256-Initial-State",
        "algorithm": "SHA-256",
        # H[0..3] of SHA-256 in little-endian byte ordering
        "bytes": bytes([0x67, 0xE6, 0x09, 0x6A, 0x85, 0xAE, 0x67, 0xBB, 0x72, 0xF3, 0x6E, 0x3C, 0x3A, 0xA5, 0x4F, 0xA5]),
        "rule_id": "BIN-CONST-SHA256-IV",
    },
    {
        "name": "MD5-Initial-State",
        "algorithm": "MD5",
        # MD5 state words A, B, C, D in little-endian
        "bytes": bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]),
        "rule_id": "BIN-CONST-MD5-IV",
    },
]


class BinaryScanner(CollectorInterface):
    """Discovers cryptographic usage in compiled binaries, libraries, and bytecode."""

    @property
    def name(self) -> str:
        return "binary-decompile-scanner"

    @property
    def version(self) -> str:
        return "1.1.0"  # Added JADX/Ghidra decompiler integration

    @property
    def capabilities(self) -> CollectorCapabilities:
        return CollectorCapabilities(
            languages=["binary", "jvm", "c", "cpp"],
            ecosystems=["native", "maven"],
            asset_types=["algorithm", "library"],
            supports_incremental=False,
            requires_network=False,
        )

    async def scan(self, inp: CollectorInput) -> CollectorResult:
        self.validate_input(inp)
        target = Path(inp.target_path)
        if not target.exists():
            return CollectorResult(envelopes=[], findings_count=0)

        collector_info = CollectorInfo(name=self.name, version=self.version)
        run_info = RunInfo(
            scan_id=inp.scan_id,
            collector_run_id=inp.collector_run_id,
            input_revision=inp.input_revision,
        )

        envelopes: list[EvidenceEnvelope] = []
        warnings: list[str] = []
        repo_name = target.name

        # Walk filesystem for binary and archive files
        for root, _, files in os.walk(target):
            # Skip VCS directories
            if ".git" in root or "node_modules" in root or ".venv" in root:
                continue

            for fname in files:
                fpath = Path(root) / fname
                ext = fpath.suffix.lower()

                if ext in BINARY_EXTENSIONS:
                    try:
                        rel_path = str(fpath.relative_to(target)).replace("\\", "/")
                        file_envelopes, file_warnings = self._scan_binary_file(
                            fpath=fpath,
                            rel_path=rel_path,
                            repo_name=repo_name,
                            inp=inp,
                            collector_info=collector_info,
                            run_info=run_info,
                        )
                        envelopes.extend(file_envelopes)
                        warnings.extend(file_warnings)
                    except Exception as exc:
                        logger.warning("binary_scan_file_failed", file_path=str(fpath), error=str(exc))

        return CollectorResult(
            envelopes=envelopes,
            findings_count=len(envelopes),
            warnings=warnings,
        )

    def _scan_binary_file(
        self,
        fpath: Path,
        rel_path: str,
        repo_name: str,
        inp: CollectorInput,
        collector_info: CollectorInfo,
        run_info: RunInfo,
    ) -> tuple[list[EvidenceEnvelope], list[str]]:
        """Scan a single binary file; return (envelopes, warnings)."""
        envelopes: list[EvidenceEnvelope] = []
        scan_warnings: list[str] = []
        ext = fpath.suffix.lower()

        # -----------------------------------------------------------------
        # JADX decompilation path for JAR / WAR / APK
        # -----------------------------------------------------------------
        if ext in {".jar", ".war", ".ear", ".apk", ".aar", ".dex"}:
            work_dir = fpath.parent / f"_decompile_{fpath.name}"
            work_dir.mkdir(exist_ok=True)
            try:
                dr: DecompileResult = decompile_and_scan(
                    input_path=fpath,
                    kind="apk" if ext == ".apk" else "library",
                    work_dir=work_dir,
                )
                envelopes.extend(
                    self._decompile_findings_to_envelopes(
                        dr, rel_path, repo_name, inp, collector_info, run_info
                    )
                )
                scan_warnings.extend(dr.limitations)
            except Exception as exc:
                logger.warning(
                    "decompile_step_failed", file=rel_path, error=str(exc)
                )
                scan_warnings.append(
                    f"{rel_path}: decompilation step failed ({exc}); "
                    "falling back to constant pool scanning."
                )
            finally:
                import shutil as _shutil
                _shutil.rmtree(work_dir, ignore_errors=True)

            # Always also run constant-pool scan for JVM archives
            envelopes.extend(
                self._scan_jar_archive(
                    fpath, rel_path, repo_name, inp, collector_info, run_info
                )
            )
            return envelopes, scan_warnings

        # -----------------------------------------------------------------
        # Ghidra path for native binaries
        # -----------------------------------------------------------------
        from ecdat.collectors.binary.decompiler import GHIDRA_EXTENSIONS
        if ext in GHIDRA_EXTENSIONS:
            work_dir = fpath.parent / f"_decompile_{fpath.name}"
            work_dir.mkdir(exist_ok=True)
            try:
                dr = decompile_and_scan(
                    input_path=fpath,
                    kind="exe" if ext == ".exe" else "library",
                    work_dir=work_dir,
                )
                envelopes.extend(
                    self._decompile_findings_to_envelopes(
                        dr, rel_path, repo_name, inp, collector_info, run_info
                    )
                )
                scan_warnings.extend(dr.limitations)
            except Exception as exc:
                logger.warning(
                    "ghidra_step_failed", file=rel_path, error=str(exc)
                )
                scan_warnings.append(
                    f"{rel_path}: Ghidra analysis failed ({exc}); "
                    "falling back to string-indicator scanning."
                )
            finally:
                import shutil as _shutil
                _shutil.rmtree(work_dir, ignore_errors=True)

        # Always also run string/byte scanning regardless of tool availability
        # Limit raw file size for memory safety (50 MiB max per binary)
        if fpath.stat().st_size > 50 * 1024 * 1024:
            return envelopes, scan_warnings

        try:
            data = fpath.read_bytes()
        except Exception:
            return envelopes

        # 1. Cryptographic Constant byte pattern search
        for sig in CRYPTO_BYTE_SIGNATURES:
            if sig["bytes"] in data:
                evidence_payload = {
                    "file": rel_path,
                    "signature_name": sig["name"],
                    "matched_bytes": sig["bytes"].hex(),
                    "algorithm": sig["algorithm"],
                }
                ev_str = json.dumps(evidence_payload, sort_keys=True)
                digest = hashlib.sha256(ev_str.encode()).hexdigest()

                obs = CryptoObservation(
                    observation_type=ObservationType.ALGORITHM_USE,
                    algorithm=sig["algorithm"],
                    algorithm_raw=sig["name"],
                    usage_evidence=UsageEvidence.STATIC,
                    extra={"constant_signature": sig["name"]},
                )

                envelopes.append(
                    EvidenceEnvelope(
                        schema_version="1.0",
                        collector=collector_info,
                        run=run_info,
                        tenant_id=inp.tenant_id,
                        source_location=SourceLocation(
                            repository=repo_name,
                            path=rel_path,
                            line=1,
                            commit_ref=inp.commit_ref,
                        ),
                        observation=obs,
                        detection_rule=DetectionRule(
                            rule_id=sig["rule_id"],
                            rule_version="1.0",
                            rule_name=f"Binary Constant Signature: {sig['name']}",
                        ),
                        confidence=Confidence.CONFIRMED,
                        evidence=EvidenceFingerprint(
                            algorithm="sha256",
                            digest=digest,
                            content_type="application/json",
                            size_bytes=len(ev_str),
                        ),
                    )
                )

        # 2. String & Symbol search in binary (OpenSSL / Libsodium / CNG symbols)
        # Extract ASCII strings >= 6 chars
        strings_found = set(re.findall(rb"[A-Za-z0-9_]{6,64}", data))

        for sym_name, sym_info in KNOWN_CRYPTO_SYMBOLS.items():
            sym_bytes = sym_name.encode()
            if sym_bytes in strings_found:
                evidence_payload = {
                    "file": rel_path,
                    "symbol": sym_name,
                    "algorithm": sym_info["algorithm"],
                    "family": sym_info.get("family"),
                }
                ev_str = json.dumps(evidence_payload, sort_keys=True)
                digest = hashlib.sha256(ev_str.encode()).hexdigest()

                obs = CryptoObservation(
                    observation_type=ObservationType.ALGORITHM_USE,
                    algorithm=sym_info["algorithm"],
                    algorithm_raw=sym_name,
                    key_size=int(sym_info["key_size"]) if "key_size" in sym_info else None,
                    mode=sym_info.get("mode"),
                    usage_evidence=UsageEvidence.STATIC,
                    extra={"binary_symbol": sym_name, "family": sym_info.get("family")},
                )

                envelopes.append(
                    EvidenceEnvelope(
                        schema_version="1.0",
                        collector=collector_info,
                        run=run_info,
                        tenant_id=inp.tenant_id,
                        source_location=SourceLocation(
                            repository=repo_name,
                            path=rel_path,
                            line=1,
                            commit_ref=inp.commit_ref,
                        ),
                        observation=obs,
                        detection_rule=DetectionRule(
                            rule_id=f"BIN-SYM-{sym_name[:20]}",
                            rule_version="1.0",
                            rule_name=f"Cryptographic Exported/Imported Symbol {sym_name}",
                        ),
                        confidence=Confidence.PROBABLE,
                        evidence=EvidenceFingerprint(
                            algorithm="sha256",
                            digest=digest,
                            content_type="application/json",
                            size_bytes=len(ev_str),
                        ),
                    )
                )

        return envelopes, scan_warnings

    # -----------------------------------------------------------------------
    # Decompiler findings -> EvidenceEnvelope conversion
    # -----------------------------------------------------------------------

    def _decompile_findings_to_envelopes(
        self,
        dr: DecompileResult,
        rel_path: str,
        repo_name: str,
        inp: CollectorInput,
        collector_info: CollectorInfo,
        run_info: RunInfo,
    ) -> list[EvidenceEnvelope]:
        """Convert DecompileResult findings into EvidenceEnvelope objects."""
        envelopes: list[EvidenceEnvelope] = []

        for finding in dr.findings:
            algorithm: str = finding.get("algorithm", "unknown")
            evidence_text: str = finding.get("evidence", f"Decompiled ({dr.tool})")
            location: str = finding.get("location", rel_path)
            line: int | None = finding.get("line")
            snippet: str = finding.get("snippet", "")[:200]

            payload = {
                "file": location,
                "algorithm": algorithm,
                "tool": dr.tool,
                "tool_version": dr.tool_version,
                "evidence": evidence_text,
                "snippet": snippet,
            }
            ev_str = json.dumps(payload, sort_keys=True)
            digest = hashlib.sha256(ev_str.encode()).hexdigest()

            obs = CryptoObservation(
                observation_type=ObservationType.ALGORITHM_USE,
                algorithm=algorithm,
                algorithm_raw=algorithm,
                usage_evidence=UsageEvidence.STATIC,
                extra={
                    "decompiler": dr.tool,
                    "decompiler_version": dr.tool_version,
                    "snippet": snippet,
                },
            )

            envelopes.append(
                EvidenceEnvelope(
                    schema_version="1.0",
                    collector=collector_info,
                    run=run_info,
                    tenant_id=inp.tenant_id,
                    source_location=SourceLocation(
                        repository=repo_name,
                        path=location,
                        line=line or 1,
                        commit_ref=inp.commit_ref,
                    ),
                    observation=obs,
                    detection_rule=DetectionRule(
                        rule_id=f"DECOMP-{dr.tool.upper()}-{algorithm[:20]}",
                        rule_version="1.0",
                        rule_name=(
                            f"{dr.tool.upper()} Decompiled: {algorithm}"
                        ),
                    ),
                    confidence=Confidence.PROBABLE,
                    evidence=EvidenceFingerprint(
                        algorithm="sha256",
                        digest=digest,
                        content_type="application/json",
                        size_bytes=len(ev_str),
                    ),
                )
            )

        return envelopes

    def _scan_jar_archive(
        self,
        jar_path: Path,
        rel_path: str,
        repo_name: str,
        inp: CollectorInput,
        collector_info: CollectorInfo,
        run_info: RunInfo,
    ) -> list[EvidenceEnvelope]:
        """Scan compiled JAR archive entries and constant pools."""
        envelopes: list[EvidenceEnvelope] = []
        try:
            with zipfile.ZipFile(jar_path, "r") as z:
                for entry_name in z.namelist():
                    if entry_name.endswith(".class"):
                        class_bytes = z.read(entry_name)
                        # Scan class constant pool strings
                        for alg, rule_id in [
                            (b"RSA", "JVM-CONST-RSA"),
                            (b"DESede", "JVM-CONST-3DES"),
                            (b"AES", "JVM-CONST-AES"),
                            (b"MD5", "JVM-CONST-MD5"),
                            (b"SHA-1", "JVM-CONST-SHA1"),
                            (b"ML-KEM", "JVM-CONST-MLKEM"),
                        ]:
                            if alg in class_bytes and (b"javax/crypto" in class_bytes or b"java/security" in class_bytes):
                                alg_str = alg.decode("latin1")
                                evidence_payload = {
                                    "archive": rel_path,
                                    "class_entry": entry_name,
                                    "primitive": alg_str,
                                }
                                ev_str = json.dumps(evidence_payload, sort_keys=True)
                                digest = hashlib.sha256(ev_str.encode()).hexdigest()

                                obs = CryptoObservation(
                                    observation_type=ObservationType.ALGORITHM_USE,
                                    algorithm=alg_str,
                                    algorithm_raw=alg_str,
                                    usage_evidence=UsageEvidence.STATIC,
                                    extra={"jar_entry": entry_name},
                                )

                                envelopes.append(
                                    EvidenceEnvelope(
                                        schema_version="1.0",
                                        collector=collector_info,
                                        run=run_info,
                                        tenant_id=inp.tenant_id,
                                        source_location=SourceLocation(
                                            repository=repo_name,
                                            path=f"{rel_path}!/{entry_name}",
                                            line=1,
                                            commit_ref=inp.commit_ref,
                                        ),
                                        observation=obs,
                                        detection_rule=DetectionRule(
                                            rule_id=rule_id,
                                            rule_version="1.0",
                                            rule_name=f"JVM Bytecode Constant: {alg_str}",
                                        ),
                                        confidence=Confidence.PROBABLE,
                                        evidence=EvidenceFingerprint(
                                            algorithm="sha256",
                                            digest=digest,
                                            content_type="application/json",
                                            size_bytes=len(ev_str),
                                        ),
                                    )
                                )
        except Exception as exc:
            logger.warning("jar_archive_scan_error", path_str=str(jar_path), error=str(exc))

        return envelopes

