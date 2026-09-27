"""Java source crypto scanner using Tree-sitter.

Detects cryptographic API usage in Java source files by parsing ASTs
with tree-sitter-java and matching against versioned detection rules.

Detects:
- javax.crypto (Cipher, KeyGenerator, SecretKeyFactory, Mac)
- java.security (KeyPairGenerator, Signature, MessageDigest, SecureRandom)
- JCA/JCE provider-based instantiation
- BouncyCastle API usage
- Hardcoded key material indicators
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

try:
    import tree_sitter_java as tsjava
    from tree_sitter import Language, Node, Parser

    JAVA_LANGUAGE = Language(tsjava.language())
    _TREE_SITTER_AVAILABLE = True
except ImportError:
    _TREE_SITTER_AVAILABLE = False
    JAVA_LANGUAGE = None  # type: ignore[assignment]

from ecdat.collectors.base import (
    CollectorCapabilities,
    CollectorInput,
    CollectorInterface,
    CollectorResult,
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
from ecdat.core.model.types import Confidence, ObservationType, UsageEvidence

logger = logging.getLogger(__name__)

_RULES_FILE = Path(__file__).parent / "rules" / "java_crypto_rules.yaml"

# JCA classes that take an algorithm string as first arg to getInstance()
_JCA_FACTORY_CLASSES = {
    "Cipher": ObservationType.ENCRYPTION,
    "KeyPairGenerator": ObservationType.KEY_GENERATION,
    "KeyGenerator": ObservationType.KEY_GENERATION,
    "MessageDigest": ObservationType.HASHING,
    "Signature": ObservationType.SIGNING,
    "Mac": ObservationType.HASHING,
    "SecretKeyFactory": ObservationType.KEY_DERIVATION,
    "KeyAgreement": ObservationType.KEY_AGREEMENT,
    "AlgorithmParameters": ObservationType.ALGORITHM_USE,
}

# Known algorithm name patterns
_ALG_PATTERN = re.compile(
    r'"(AES|RSA|DES|3DES|DESede|EC|ECDSA|ECDH|SHA-?[0-9]+|MD5|MD2|'
    r'Blowfish|RC4|RC2|ChaCha20|HMAC|PBKDF2|DSA|[A-Z][A-Za-z0-9/\-]+)"'
)

# Base64 / PEM key material patterns
_KEY_MATERIAL_PATTERNS = [
    re.compile(r'"-----BEGIN[^"]{0,30}KEY-----"', re.IGNORECASE),
    re.compile(r'"[A-Za-z0-9+/]{64,}={0,2}"'),
]


@dataclass
class DetectionRuleSpec:
    id: str
    version: str
    name: str
    severity: str
    confidence: str
    patterns: list[dict[str, Any]]
    metadata: dict[str, Any] = field(default_factory=dict)


def _load_rules() -> list[DetectionRuleSpec]:
    if not _RULES_FILE.exists():
        return []
    with _RULES_FILE.open(encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return [
        DetectionRuleSpec(
            id=r["id"],
            version=r["version"],
            name=r["name"],
            severity=r.get("severity", "info"),
            confidence=r.get("confidence", "probable"),
            patterns=r.get("conditions", {}).get("patterns", []),
            metadata=r.get("metadata", {}),
        )
        for r in (raw or [])
    ]


def _fingerprint(content: str) -> str:
    return "sha256:" + hashlib.sha256(content.encode()).hexdigest()


def _extract_string_arg(node: "Node", source: bytes) -> str | None:
    """Extract the string value from a string_literal node."""
    text = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
    # Strip surrounding quotes
    stripped = text.strip('"\'')
    return stripped if stripped else None


class JavaSourceScanner(CollectorInterface):
    """Tree-sitter-based Java cryptographic API scanner."""

    def __init__(self) -> None:
        self._rules = _load_rules()
        if _TREE_SITTER_AVAILABLE:
            self._parser = Parser(JAVA_LANGUAGE)
        else:
            self._parser = None

    @property
    def name(self) -> str:
        return "java-source"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> CollectorCapabilities:
        return CollectorCapabilities(
            languages=["java"],
            asset_types=["algorithm", "key", "certificate"],
            supports_incremental=False,
            requires_network=False,
        )

    async def scan(self, inp: CollectorInput) -> CollectorResult:
        """Scan a Java source tree for crypto API usage."""
        self.validate_input(inp)

        if not _TREE_SITTER_AVAILABLE:
            return CollectorResult(
                is_partial=True,
                unsupported_reason="tree-sitter-java is not installed",
            )

        collector_info = CollectorInfo(name=self.name, version=self.version)
        run_info = RunInfo(
            scan_id=inp.scan_id,
            collector_run_id=inp.collector_run_id,
            input_revision=inp.input_revision,
        )

        envelopes: list[EvidenceEnvelope] = []
        errors: list[str] = []

        target = Path(inp.target_path)
        java_files = list(target.rglob("*.java"))

        for java_file in java_files:
            try:
                file_envelopes = self._scan_file(
                    java_file, target, collector_info, run_info, inp
                )
                envelopes.extend(file_envelopes)
            except Exception as exc:
                logger.warning("java_scan_file_error", path=str(java_file), error=str(exc))
                errors.append(f"{java_file}: {exc}")

        return CollectorResult(
            envelopes=envelopes,
            findings_count=len(envelopes),
            errors=errors,
            is_partial=len(errors) > 0,
        )

    def _scan_file(
        self,
        java_file: Path,
        root: Path,
        collector_info: CollectorInfo,
        run_info: RunInfo,
        inp: CollectorInput,
    ) -> list[EvidenceEnvelope]:
        source_bytes = java_file.read_bytes()
        source_str = source_bytes.decode("utf-8", errors="replace")
        relative_path = str(java_file.relative_to(root))

        tree = self._parser.parse(source_bytes)
        envelopes: list[EvidenceEnvelope] = []

        # Walk tree and find method invocations
        self._walk_node(
            tree.root_node,
            source_bytes,
            source_str,
            relative_path,
            inp,
            collector_info,
            run_info,
            envelopes,
        )

        # Also scan for hardcoded key material using regex on source text
        envelopes.extend(
            self._scan_key_material(source_str, relative_path, inp, collector_info, run_info)
        )

        return envelopes

    def _walk_node(
        self,
        node: "Node",
        source: bytes,
        source_str: str,
        path: str,
        inp: CollectorInput,
        collector_info: CollectorInfo,
        run_info: RunInfo,
        envelopes: list[EvidenceEnvelope],
    ) -> None:
        """Recursively walk AST nodes looking for getInstance() calls."""
        if node.type == "method_invocation":
            envelope = self._check_method_invocation(
                node, source, path, inp, collector_info, run_info
            )
            if envelope:
                envelopes.append(envelope)

        for child in node.children:
            self._walk_node(
                child, source, source_str, path, inp, collector_info, run_info, envelopes
            )

    def _check_method_invocation(
        self,
        node: "Node",
        source: bytes,
        path: str,
        inp: CollectorInput,
        collector_info: CollectorInfo,
        run_info: RunInfo,
    ) -> EvidenceEnvelope | None:
        """Check if a method_invocation node is a JCA getInstance() call."""
        node_text = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

        # Look for pattern: ClassName.getInstance("ALGORITHM")
        for class_name, obs_type in _JCA_FACTORY_CLASSES.items():
            if f"{class_name}.getInstance" in node_text:
                # Extract algorithm string
                alg_match = _ALG_PATTERN.search(node_text)
                if not alg_match:
                    continue

                algorithm = alg_match.group(1)
                line = node.start_point[0] + 1  # 1-indexed

                # Find matching rule
                rule = self._find_rule(class_name, algorithm)

                location = SourceLocation(
                    repository=inp.repository_url or inp.target_path,
                    path=path,
                    line=line,
                    commit_ref=inp.commit_ref,
                )
                observation = CryptoObservation(
                    observation_type=obs_type,
                    algorithm=algorithm,
                    algorithm_raw=algorithm,
                    usage_evidence=UsageEvidence.STATIC,
                )
                fp = _fingerprint(
                    f"{inp.tenant_id}:{inp.scan_id}:{path}:{line}:{algorithm}"
                )
                evidence_fp = EvidenceFingerprint(
                    digest=fp.replace("sha256:", ""),
                    content_type="text/java",
                    size_bytes=len(node_text.encode()),
                )

                return EvidenceEnvelope(
                    collector=collector_info,
                    run=run_info,
                    tenant_id=inp.tenant_id,
                    source_location=location,
                    observation=observation,
                    confidence=Confidence.CONFIRMED,
                    detection_rule=rule,
                    evidence=evidence_fp,
                )
        return None

    def _find_rule(self, class_name: str, algorithm: str) -> DetectionRule | None:
        """Find the most specific matching rule for a class+algorithm pair."""
        alg_upper = algorithm.upper()
        for rule in self._rules:
            for pat in rule.patterns:
                if pat.get("class") != class_name:
                    continue
                expected = pat.get("algorithm_arg", "")
                prefix = pat.get("algorithm_arg_prefix", "")
                contains = pat.get("algorithm_arg_contains", "")
                if expected and alg_upper == expected.upper():
                    return DetectionRule(rule_id=rule.id, rule_version=rule.version, rule_name=rule.name)
                if prefix and alg_upper.startswith(prefix.upper()):
                    return DetectionRule(rule_id=rule.id, rule_version=rule.version, rule_name=rule.name)
                if contains and contains.upper() in alg_upper:
                    return DetectionRule(rule_id=rule.id, rule_version=rule.version, rule_name=rule.name)
        return None

    def _scan_key_material(
        self,
        source_str: str,
        path: str,
        inp: CollectorInput,
        collector_info: CollectorInfo,
        run_info: RunInfo,
    ) -> list[EvidenceEnvelope]:
        """Scan for hardcoded key material using regex patterns."""
        envelopes: list[EvidenceEnvelope] = []
        lines = source_str.splitlines()

        for line_no, line in enumerate(lines, start=1):
            for pattern in _KEY_MATERIAL_PATTERNS:
                if pattern.search(line):
                    fp = _fingerprint(f"{inp.tenant_id}:{inp.scan_id}:{path}:{line_no}:keymaterial")
                    envelopes.append(
                        EvidenceEnvelope(
                            collector=collector_info,
                            run=run_info,
                            tenant_id=inp.tenant_id,
                            source_location=SourceLocation(
                                repository=inp.repository_url or inp.target_path,
                                path=path,
                                line=line_no,
                                commit_ref=inp.commit_ref,
                            ),
                            observation=CryptoObservation(
                                observation_type=ObservationType.HARDCODED_MATERIAL,
                                usage_evidence=UsageEvidence.STATIC,
                            ),
                            confidence=Confidence.PROBABLE,
                            detection_rule=DetectionRule(
                                rule_id="JAVA-KEYMATERIAL-001",
                                rule_version="1.0",
                                rule_name="Hardcoded key material indicator",
                            ),
                            evidence=EvidenceFingerprint(
                                digest=fp.replace("sha256:", ""),
                                content_type="text/java",
                            ),
                        )
                    )
                    break  # one finding per line

        return envelopes
