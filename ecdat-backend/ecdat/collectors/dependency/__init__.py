"""Dependency scanner registry and common utilities."""

from __future__ import annotations

import hashlib
import json

from ecdat.core.evidence.envelope import (
    CollectorInfo,
    CryptoObservation,
    DependencyLocation,
    DetectionRule,
    EvidenceEnvelope,
    EvidenceFingerprint,
    RunInfo,
)
from ecdat.core.model.types import (
    Confidence,
    DependencyEvidenceLevel,
    ObservationType,
    UsageEvidence,
)


def fp(content: str) -> str:
    return "sha256:" + hashlib.sha256(content.encode()).hexdigest()


# Known crypto packages and their canonical algorithm families
# Format: package_name → {algorithm, family}
KNOWN_CRYPTO_PACKAGES: dict[str, dict[str, str]] = {
    # PyPI
    "cryptography": {"algorithm": "multi", "family": "asymmetric,symmetric,hash"},
    "pycryptodome": {"algorithm": "multi", "family": "asymmetric,symmetric,hash"},
    "pycryptodomex": {"algorithm": "multi", "family": "asymmetric,symmetric,hash"},
    "pyopenssl": {"algorithm": "RSA,EC", "family": "asymmetric"},
    "bcrypt": {"algorithm": "bcrypt", "family": "kdf"},
    "argon2-cffi": {"algorithm": "Argon2", "family": "kdf"},
    "paramiko": {"algorithm": "RSA,ECDSA,Ed25519", "family": "asymmetric"},
    "pynacl": {"algorithm": "X25519,Ed25519,ChaCha20", "family": "asymmetric,symmetric"},
    "py-jwt": {"algorithm": "RSA,ECDSA,HMAC", "family": "asymmetric,symmetric"},
    "pyjwt": {"algorithm": "RSA,ECDSA,HMAC", "family": "asymmetric,symmetric"},
    "jwcrypto": {"algorithm": "RSA,EC,AES", "family": "asymmetric,symmetric"},
    "passlib": {"algorithm": "bcrypt,PBKDF2,scrypt,Argon2", "family": "kdf"},
    # npm
    "node-forge": {"algorithm": "RSA,AES,SHA", "family": "asymmetric,symmetric,hash"},
    "crypto-js": {"algorithm": "AES,SHA,HMAC", "family": "symmetric,hash"},
    "jsonwebtoken": {"algorithm": "RSA,ECDSA,HMAC", "family": "asymmetric,symmetric"},
    "bcryptjs": {"algorithm": "bcrypt", "family": "kdf"},
    "elliptic": {"algorithm": "ECDSA,ECDH", "family": "asymmetric"},
    "tweetnacl": {"algorithm": "Ed25519,X25519,ChaCha20", "family": "asymmetric,symmetric"},
    "noble-curves": {"algorithm": "ECDSA,Ed25519", "family": "asymmetric"},
    "noble-hashes": {"algorithm": "SHA,BLAKE2,HMAC", "family": "hash"},
    # Maven (artifactId)
    "bcprov-jdk18on": {"algorithm": "multi", "family": "asymmetric,symmetric,hash"},
    "bcprov-jdk15on": {"algorithm": "multi", "family": "asymmetric,symmetric,hash"},
    "nimbus-jose-jwt": {"algorithm": "RSA,EC,AES,HMAC", "family": "asymmetric,symmetric"},
    "tink": {"algorithm": "multi", "family": "asymmetric,symmetric"},
    # Go modules
    "golang.org/x/crypto": {"algorithm": "multi", "family": "asymmetric,symmetric,hash"},
    "github.com/golang-jwt/jwt": {"algorithm": "RSA,ECDSA,HMAC", "family": "asymmetric,symmetric"},
    "github.com/google/tink": {"algorithm": "multi", "family": "asymmetric,symmetric"},
    "golang.org/x/crypto/chacha20poly1305": {"algorithm": "ChaCha20", "family": "symmetric"},
    "golang.org/x/crypto/bcrypt": {"algorithm": "bcrypt", "family": "kdf"},
}


def make_dependency_envelope(
    ecosystem: str,
    package_name: str,
    package_version: str,
    dep_path: list[str],
    is_direct: bool,
    group_id: str | None,
    collector_info: CollectorInfo,
    run_info: RunInfo,
    inp,   # CollectorInput
) -> EvidenceEnvelope | None:
    """Create an EvidenceEnvelope for a dependency that has crypto capability."""
    key = package_name.lower()
    pkg_info = KNOWN_CRYPTO_PACKAGES.get(key)
    if pkg_info is None:
        return None

    algorithm = pkg_info.get("algorithm")
    fingerprint = fp(
        f"{inp.tenant_id}:{inp.scan_id}:{ecosystem}:{package_name}:{package_version}"
    )

    return EvidenceEnvelope(
        collector=collector_info,
        run=run_info,
        tenant_id=inp.tenant_id,
        dependency_location=DependencyLocation(
            ecosystem=ecosystem,
            package_name=package_name,
            package_version=package_version,
            group_id=group_id,
            dependency_path=dep_path,
            is_direct=is_direct,
        ),
        observation=CryptoObservation(
            observation_type=ObservationType.ALGORITHM_USE,
            algorithm=algorithm if algorithm != "multi" else None,
            dependency_evidence_level=DependencyEvidenceLevel.CAPABILITY,
            usage_evidence=UsageEvidence.UNKNOWN,
        ),
        confidence=Confidence.PROBABLE,
        detection_rule=DetectionRule(
            rule_id=f"DEP-{ecosystem.upper()}-CRYPTO-001",
            rule_version="1.0",
            rule_name=f"{ecosystem} crypto package capability",
        ),
        evidence=EvidenceFingerprint(
            digest=fingerprint.replace("sha256:", ""),
            content_type="application/json",
        ),
        metadata={"package_family": pkg_info.get("family", "")},
    )
