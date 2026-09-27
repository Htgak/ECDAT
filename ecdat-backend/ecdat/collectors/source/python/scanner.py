"""Python source crypto scanner using Tree-sitter.

Detects cryptographic API usage in Python source files by parsing ASTs
with tree-sitter-python and matching against versioned detection rules.

Detects:
- pyca/cryptography library (algorithm classes, key generation, serialization)
- hashlib usage (md5, sha1, sha256, etc.)
- PyCryptodome / pycryptodomex imports
- Hardcoded PEM key material
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

try:
    import tree_sitter_python as tspython
    from tree_sitter import Language, Node, Parser

    PYTHON_LANGUAGE = Language(tspython.language())
    _TREE_SITTER_AVAILABLE = True
except ImportError:
    _TREE_SITTER_AVAILABLE = False
    PYTHON_LANGUAGE = None  # type: ignore[assignment]

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

_RULES_FILE = Path(__file__).parent / "rules" / "python_crypto_rules.yaml"

# pyca/cryptography module → ObservationType mapping
_MODULE_OBS_MAP: dict[str, ObservationType] = {
    "cryptography.hazmat.primitives.asymmetric.rsa": ObservationType.KEY_GENERATION,
    "cryptography.hazmat.primitives.asymmetric.ec": ObservationType.KEY_GENERATION,
    "cryptography.hazmat.primitives.asymmetric.ed25519": ObservationType.KEY_GENERATION,
    "cryptography.hazmat.primitives.asymmetric.ed448": ObservationType.KEY_GENERATION,
    "cryptography.hazmat.primitives.asymmetric.x25519": ObservationType.KEY_AGREEMENT,
    "cryptography.hazmat.primitives.asymmetric.x448": ObservationType.KEY_AGREEMENT,
    "cryptography.hazmat.primitives.ciphers.algorithms": ObservationType.ENCRYPTION,
    "cryptography.hazmat.primitives.hashes": ObservationType.HASHING,
    "cryptography.hazmat.primitives.hmac": ObservationType.HASHING,
    "cryptography.hazmat.primitives.kdf.pbkdf2": ObservationType.KEY_DERIVATION,
    "cryptography.hazmat.primitives.kdf.hkdf": ObservationType.KEY_DERIVATION,
    "cryptography.hazmat.primitives.kdf.scrypt": ObservationType.KEY_DERIVATION,
    "cryptography.hazmat.primitives.serialization": ObservationType.KEY_GENERATION,
    "Crypto": ObservationType.ALGORITHM_USE,
    "hashlib": ObservationType.HASHING,
}

# Algorithm classes from pyca/cryptography
_PYCA_ALGO_CLASSES: dict[str, str] = {
    "AES": "AES",
    "ChaCha20": "ChaCha20",
    "TripleDES": "3DES",
    "Blowfish": "Blowfish",
    "ARC4": "RC4",
    "CAST5": "CAST5",
    "SHA1": "SHA-1",
    "SHA224": "SHA-224",
    "SHA256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA512": "SHA-512",
    "SHA3_256": "SHA3-256",
    "SHA3_512": "SHA3-512",
    "MD5": "MD5",
    "BLAKE2b": "BLAKE2b",
    "BLAKE2s": "BLAKE2s",
    "PBKDF2HMAC": "PBKDF2",
    "HKDF": "HKDF",
    "Scrypt": "scrypt",
    "HMAC": "HMAC",
}

_HASHLIB_FUNCS = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha3_256": "SHA3-256",
    "sha3_512": "SHA3-512",
    "blake2b": "BLAKE2b",
    "blake2s": "BLAKE2s",
    "new": None,   # dynamic — algorithm from arg
}

_PEM_PATTERNS = [
    re.compile(r"""['"]-----BEGIN[^'"]{0,30}KEY-----['"]""", re.IGNORECASE),
    re.compile(r"""['"]-----BEGIN CERTIFICATE-----['"]""", re.IGNORECASE),
]


def _fingerprint(content: str) -> str:
    return "sha256:" + hashlib.sha256(content.encode()).hexdigest()


class PythonSourceScanner(CollectorInterface):
    """Tree-sitter-based Python cryptographic API scanner."""

    def __init__(self) -> None:
        if _TREE_SITTER_AVAILABLE:
            self._parser = Parser(PYTHON_LANGUAGE)
        else:
            self._parser = None

    @property
    def name(self) -> str:
        return "python-source"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> CollectorCapabilities:
        return CollectorCapabilities(
            languages=["python"],
            asset_types=["algorithm", "key", "certificate"],
            supports_incremental=False,
            requires_network=False,
        )

    async def scan(self, inp: CollectorInput) -> CollectorResult:
        self.validate_input(inp)

        if not _TREE_SITTER_AVAILABLE:
            return CollectorResult(
                is_partial=True,
                unsupported_reason="tree-sitter-python is not installed",
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
        py_files = list(target.rglob("*.py"))

        for py_file in py_files:
            try:
                file_envelopes = self._scan_file(
                    py_file, target, collector_info, run_info, inp
                )
                envelopes.extend(file_envelopes)
            except Exception as exc:
                logger.warning("python_scan_file_error", path=str(py_file), error=str(exc))
                errors.append(f"{py_file}: {exc}")

        return CollectorResult(
            envelopes=envelopes,
            findings_count=len(envelopes),
            errors=errors,
            is_partial=len(errors) > 0,
        )

    def _scan_file(
        self,
        py_file: Path,
        root: Path,
        collector_info: CollectorInfo,
        run_info: RunInfo,
        inp: CollectorInput,
    ) -> list[EvidenceEnvelope]:
        source_bytes = py_file.read_bytes()
        source_str = source_bytes.decode("utf-8", errors="replace")
        relative_path = str(py_file.relative_to(root))

        tree = self._parser.parse(source_bytes)
        envelopes: list[EvidenceEnvelope] = []

        # Collect imports first for context
        imports = self._collect_imports(tree.root_node, source_bytes)

        # Walk AST for crypto calls
        self._walk_node(
            tree.root_node, source_bytes, relative_path, inp,
            collector_info, run_info, imports, envelopes,
        )

        # Regex scan for hardcoded PEM material
        envelopes.extend(
            self._scan_pem_material(source_str, relative_path, inp, collector_info, run_info)
        )

        return envelopes

    def _collect_imports(self, root: "Node", source: bytes) -> dict[str, str]:
        """Build alias→module mapping from import statements."""
        imports: dict[str, str] = {}

        def walk(node: "Node") -> None:
            if node.type in ("import_statement", "import_from_statement"):
                text = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
                # from X import Y → map Y to X
                if "from " in text:
                    parts = text.split()
                    if len(parts) >= 4 and parts[0] == "from" and parts[2] == "import":
                        module = parts[1]
                        for name in " ".join(parts[3:]).split(","):
                            name = name.strip().split(" as ")[-1].strip()
                            imports[name] = module
                else:
                    # import X as Y
                    parts = text.replace("import ", "").split(",")
                    for p in parts:
                        p = p.strip()
                        if " as " in p:
                            orig, alias = p.split(" as ")
                            imports[alias.strip()] = orig.strip()
                        else:
                            imports[p.strip()] = p.strip()
            for child in node.children:
                walk(child)

        walk(root)
        return imports

    def _walk_node(
        self,
        node: "Node",
        source: bytes,
        path: str,
        inp: CollectorInput,
        collector_info: CollectorInfo,
        run_info: RunInfo,
        imports: dict[str, str],
        envelopes: list[EvidenceEnvelope],
    ) -> None:
        if node.type == "call":
            env = self._check_call(node, source, path, inp, collector_info, run_info, imports)
            if env:
                envelopes.append(env)

        for child in node.children:
            self._walk_node(
                child, source, path, inp, collector_info, run_info, imports, envelopes
            )

    def _check_call(
        self,
        node: "Node",
        source: bytes,
        path: str,
        inp: CollectorInput,
        collector_info: CollectorInfo,
        run_info: RunInfo,
        imports: dict[str, str],
    ) -> EvidenceEnvelope | None:
        node_text = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
        line = node.start_point[0] + 1

        # Check for pyca algo class instantiation: AES(...), SHA256(), etc.
        for cls_name, canonical_alg in _PYCA_ALGO_CLASSES.items():
            if node_text.startswith(f"{cls_name}("):
                module = imports.get(cls_name, "")
                obs_type = _MODULE_OBS_MAP.get(module, ObservationType.ALGORITHM_USE)
                return self._make_envelope(
                    path, line, canonical_alg, obs_type, f"PY-{cls_name.upper()}-001",
                    collector_info, run_info, inp, node_text,
                )

        # hashlib calls: hashlib.sha256(), hashlib.md5(), etc.
        for func, alg in _HASHLIB_FUNCS.items():
            if f"hashlib.{func}(" in node_text or f".{func}(" in node_text:
                if alg:
                    rule_id = f"PY-{alg.replace('-', '').upper()}-001" if alg else "PY-HASH-001"
                    return self._make_envelope(
                        path, line, alg, ObservationType.HASHING, rule_id,
                        collector_info, run_info, inp, node_text,
                    )

        # generate_private_key: RSA, EC
        if "generate_private_key(" in node_text:
            alg = "RSA" if "rsa" in node_text.lower() else "ECDSA"
            return self._make_envelope(
                path, line, alg, ObservationType.KEY_GENERATION, "PY-RSA-001",
                collector_info, run_info, inp, node_text,
            )

        # PyCryptodome: from Crypto.X import Y
        if node_text.startswith("Crypto."):
            return self._make_envelope(
                path, line, None, ObservationType.ALGORITHM_USE, "PY-PYCRYPTODOME-001",
                collector_info, run_info, inp, node_text, confidence=Confidence.PROBABLE,
            )

        return None

    def _make_envelope(
        self,
        path: str,
        line: int,
        algorithm: str | None,
        obs_type: ObservationType,
        rule_id: str,
        collector_info: CollectorInfo,
        run_info: RunInfo,
        inp: CollectorInput,
        node_text: str,
        confidence: Confidence = Confidence.CONFIRMED,
    ) -> EvidenceEnvelope:
        fp = _fingerprint(f"{inp.tenant_id}:{inp.scan_id}:{path}:{line}:{algorithm}:{obs_type}")
        return EvidenceEnvelope(
            collector=collector_info,
            run=run_info,
            tenant_id=inp.tenant_id,
            source_location=SourceLocation(
                repository=inp.repository_url or inp.target_path,
                path=path,
                line=line,
                commit_ref=inp.commit_ref,
            ),
            observation=CryptoObservation(
                observation_type=obs_type,
                algorithm=algorithm,
                algorithm_raw=algorithm,
                usage_evidence=UsageEvidence.STATIC,
            ),
            confidence=confidence,
            detection_rule=DetectionRule(rule_id=rule_id, rule_version="1.0"),
            evidence=EvidenceFingerprint(
                digest=fp.replace("sha256:", ""),
                content_type="text/x-python",
                size_bytes=len(node_text.encode()),
            ),
        )

    def _scan_pem_material(
        self,
        source_str: str,
        path: str,
        inp: CollectorInput,
        collector_info: CollectorInfo,
        run_info: RunInfo,
    ) -> list[EvidenceEnvelope]:
        envelopes: list[EvidenceEnvelope] = []
        for line_no, line in enumerate(source_str.splitlines(), start=1):
            for pattern in _PEM_PATTERNS:
                if pattern.search(line):
                    fp = _fingerprint(f"{inp.tenant_id}:{inp.scan_id}:{path}:{line_no}:pem")
                    envelopes.append(EvidenceEnvelope(
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
                            rule_id="PY-KEYMATERIAL-001",
                            rule_version="1.0",
                        ),
                        evidence=EvidenceFingerprint(
                            digest=fp.replace("sha256:", ""),
                            content_type="text/x-python",
                        ),
                    ))
                    break
        return envelopes
