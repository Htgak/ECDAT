"""PQC Advisory Engine.

Maps classical crypto primitives to NIST-recommended post-quantum
replacements. This is a static knowledge base — data comes from:

  - NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
  - NSA CNSA 2.0
  - NIST IR 8547 (transition recommendations)

Usage::

    engine = AdvisoryEngine()
    advice = engine.recommend("RSA", use_case="key_establishment")
    print(advice.primary_recommendation.name)   # ML-KEM-768
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PQCAlgorithm:
    """A specific post-quantum algorithm variant."""

    name: str                          # e.g. "ML-KEM-768"
    family: str                        # e.g. "ML-KEM"
    fips_number: str | None            # e.g. "FIPS 203"
    nist_security_level: int           # 1–5
    use_cases: list[str]               # "kem", "signature", "hash"
    standard_status: str               # "final", "draft", "selected"
    production_ready: bool
    public_key_bytes: int | None = None
    signature_bytes: int | None = None
    ciphertext_bytes: int | None = None
    notes: str | None = None


@dataclass
class MigrationAdvice:
    """PQC migration recommendation for one classical primitive."""

    from_algorithm: str
    from_use_case: str
    primary_recommendation: PQCAlgorithm
    alternatives: list[PQCAlgorithm]
    hybrid_option: str | None               # e.g. "ECDH + ML-KEM-768"
    migration_effort: str                   # "low" | "medium" | "high"
    suggested_complexity: str
    cnsa2_compliant: bool  # Always false: this catalogue does not certify policy compliance
    urgency_note: str
    references: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Static PQC algorithm catalogue
# ---------------------------------------------------------------------------

_ML_KEM_512 = PQCAlgorithm(
    name="ML-KEM-512", family="ML-KEM", fips_number="FIPS 203",
    nist_security_level=1, use_cases=["kem", "key_establishment"],
    standard_status="final", production_ready=True,
    public_key_bytes=800, ciphertext_bytes=768,
    notes="NIST Level 1 (AES-128 equivalent). Suitable for low-security contexts.",
)
_ML_KEM_768 = PQCAlgorithm(
    name="ML-KEM-768", family="ML-KEM", fips_number="FIPS 203",
    nist_security_level=3, use_cases=["kem", "key_establishment"],
    standard_status="final", production_ready=True,
    public_key_bytes=1184, ciphertext_bytes=1088,
    notes="NIST Level 3 (AES-192 equivalent). Parameter selection is organization-dependent.",
)
_ML_KEM_1024 = PQCAlgorithm(
    name="ML-KEM-1024", family="ML-KEM", fips_number="FIPS 203",
    nist_security_level=5, use_cases=["kem", "key_establishment"],
    standard_status="final", production_ready=True,
    public_key_bytes=1568, ciphertext_bytes=1568,
    notes="NIST Level 5 (AES-256 equivalent). Highest security.",
)
_ML_DSA_44 = PQCAlgorithm(
    name="ML-DSA-44", family="ML-DSA", fips_number="FIPS 204",
    nist_security_level=2, use_cases=["signature", "signing"],
    standard_status="final", production_ready=True,
    public_key_bytes=1312, signature_bytes=2420,
)
_ML_DSA_65 = PQCAlgorithm(
    name="ML-DSA-65", family="ML-DSA", fips_number="FIPS 204",
    nist_security_level=3, use_cases=["signature", "signing"],
    standard_status="final", production_ready=True,
    public_key_bytes=1952, signature_bytes=3293,
    notes="Evaluate protocol, interoperability and organizational policy.",
)
_ML_DSA_87 = PQCAlgorithm(
    name="ML-DSA-87", family="ML-DSA", fips_number="FIPS 204",
    nist_security_level=5, use_cases=["signature", "signing"],
    standard_status="final", production_ready=True,
    public_key_bytes=2592, signature_bytes=4595,
)
_SLH_DSA_SHAKE_128S = PQCAlgorithm(
    name="SLH-DSA-SHAKE-128s", family="SLH-DSA", fips_number="FIPS 205",
    nist_security_level=1, use_cases=["signature", "signing"],
    standard_status="final", production_ready=True,
    signature_bytes=7856,
    notes="Hash-based — very conservative, large signatures.",
)
_SLH_DSA_SHAKE_256S = PQCAlgorithm(
    name="SLH-DSA-SHAKE-256s", family="SLH-DSA", fips_number="FIPS 205",
    nist_security_level=5, use_cases=["signature", "signing"],
    standard_status="final", production_ready=True,
    signature_bytes=49856,
    notes="Maximum security hash-based signature.",
)
_SHA3_256 = PQCAlgorithm(
    name="SHA3-256", family="SHA3", fips_number="FIPS 202",
    nist_security_level=2, use_cases=["hash"],
    standard_status="final", production_ready=True,
)
_SHA3_512 = PQCAlgorithm(
    name="SHA3-512", family="SHA3", fips_number="FIPS 202",
    nist_security_level=5, use_cases=["hash"],
    standard_status="final", production_ready=True,
)
_SHA_512 = PQCAlgorithm(
    name="SHA-512", family="SHA2", fips_number="FIPS 180-4",
    nist_security_level=5, use_cases=["hash"],
    standard_status="final", production_ready=True,
    notes="SHA-2 family is quantum-resistant with doubled output length.",
)
_AES_256 = PQCAlgorithm(
    name="AES-256", family="AES", fips_number="FIPS 197",
    nist_security_level=5, use_cases=["symmetric_encryption"],
    standard_status="final", production_ready=True,
    notes="AES-128, AES-192 and AES-256 may continue under current NIST guidance. Review mode and key management.",
)
_AES_128 = PQCAlgorithm(
    name="AES-128", family="AES", fips_number="FIPS 197",
    nist_security_level=1, use_cases=["symmetric_encryption"],
    standard_status="final", production_ready=True,
    notes="AES-128, AES-192 and AES-256 may continue under current NIST guidance. Review mode and key management.",
)


# ---------------------------------------------------------------------------
# Migration advice database
# Maps (from_algorithm.upper(), use_case) → MigrationAdvice
# ---------------------------------------------------------------------------

_NIST_REF = "https://csrc.nist.gov/pubs/fips/203/final"
_CNSA_REF = "https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF"
_IR8547_REF = "https://csrc.nist.gov/pubs/ir/8547/ipd"

_ADVICE: dict[tuple[str, str], MigrationAdvice] = {
    # ── Key establishment / key agreement ─────────────────────────────── #
    ("RSA", "key_establishment"): MigrationAdvice(
        from_algorithm="RSA", from_use_case="key_establishment",
        primary_recommendation=_ML_KEM_768,
        alternatives=[_ML_KEM_1024, _ML_KEM_512],
        hybrid_option="Evaluate protocol-supported standardized hybrid; for TLS 1.3 see RFC 10024 (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024).",
        migration_effort="high",
        suggested_complexity="REQUIRES ASSESSMENT",
        cnsa2_compliant=False,
        urgency_note="Candidate migration family; confirm operation, protocol, interoperability, performance and organizational policy. Timing requires organization-supplied X/Y/Z.",
        references=[_NIST_REF, _CNSA_REF],
    ),
    ("ECDH", "key_establishment"): MigrationAdvice(
        from_algorithm="ECDH", from_use_case="key_establishment",
        primary_recommendation=_ML_KEM_768,
        alternatives=[_ML_KEM_1024],
        hybrid_option="Evaluate protocol-supported standardized hybrid; for TLS 1.3 see RFC 10024 (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024).",
        migration_effort="medium",
        suggested_complexity="REQUIRES ASSESSMENT",
        cnsa2_compliant=False,
        urgency_note="Candidate migration family; confirm operation, protocol, interoperability, performance and organizational policy. Timing requires organization-supplied X/Y/Z.",
        references=[_NIST_REF, _CNSA_REF, _IR8547_REF],
    ),
    ("ECDH", "key_agreement"): MigrationAdvice(
        from_algorithm="ECDH", from_use_case="key_agreement",
        primary_recommendation=_ML_KEM_768,
        alternatives=[_ML_KEM_1024],
        hybrid_option="Evaluate protocol-supported standardized hybrid; for TLS 1.3 see RFC 10024 (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024).",
        migration_effort="medium",
        suggested_complexity="REQUIRES ASSESSMENT",
        cnsa2_compliant=False,
        urgency_note="Candidate migration family; confirm operation, protocol, interoperability, performance and organizational policy. Timing requires organization-supplied X/Y/Z.",
        references=[_NIST_REF, _CNSA_REF],
    ),
    ("X25519", "key_agreement"): MigrationAdvice(
        from_algorithm="X25519", from_use_case="key_agreement",
        primary_recommendation=_ML_KEM_768,
        alternatives=[_ML_KEM_512],
        hybrid_option="Evaluate protocol-supported standardized hybrid; for TLS 1.3 see RFC 10024 (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024).",
        migration_effort="medium",
        suggested_complexity="REQUIRES ASSESSMENT",
        cnsa2_compliant=False,
        urgency_note="Candidate migration family; confirm operation, protocol, interoperability, performance and organizational policy. Timing requires organization-supplied X/Y/Z.",
        references=[_NIST_REF],
    ),
    ("DH", "key_agreement"): MigrationAdvice(
        from_algorithm="DH", from_use_case="key_agreement",
        primary_recommendation=_ML_KEM_768,
        alternatives=[_ML_KEM_1024],
        hybrid_option=None,
        migration_effort="high",
        suggested_complexity="REQUIRES ASSESSMENT",
        cnsa2_compliant=False,
        urgency_note="Candidate migration family; confirm operation, protocol, interoperability, performance and organizational policy. Timing requires organization-supplied X/Y/Z.",
        references=[_NIST_REF, _CNSA_REF],
    ),
    # ── Digital signatures ─────────────────────────────────────────────── #
    ("RSA", "signing"): MigrationAdvice(
        from_algorithm="RSA", from_use_case="signing",
        primary_recommendation=_ML_DSA_65,
        alternatives=[_ML_DSA_87, _SLH_DSA_SHAKE_128S],
        hybrid_option="Evaluate protocol-supported standardized hybrid; for TLS 1.3 see RFC 10024 (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024).",
        migration_effort="high",
        suggested_complexity="REQUIRES ASSESSMENT",
        cnsa2_compliant=False,
        urgency_note="Candidate migration family; confirm operation, protocol, interoperability, performance and organizational policy. Timing requires organization-supplied X/Y/Z.",
        references=[_NIST_REF, _CNSA_REF],
    ),
    ("ECDSA", "signing"): MigrationAdvice(
        from_algorithm="ECDSA", from_use_case="signing",
        primary_recommendation=_ML_DSA_65,
        alternatives=[_ML_DSA_87, _SLH_DSA_SHAKE_256S],
        hybrid_option="Evaluate protocol-supported standardized hybrid; for TLS 1.3 see RFC 10024 (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024).",
        migration_effort="medium",
        suggested_complexity="REQUIRES ASSESSMENT",
        cnsa2_compliant=False,
        urgency_note="Candidate migration family; confirm operation, protocol, interoperability, performance and organizational policy. Timing requires organization-supplied X/Y/Z.",
        references=[_NIST_REF, _CNSA_REF, _IR8547_REF],
    ),
    ("ED25519", "signing"): MigrationAdvice(
        from_algorithm="Ed25519", from_use_case="signing",
        primary_recommendation=_ML_DSA_44,
        alternatives=[_ML_DSA_65, _SLH_DSA_SHAKE_128S],
        hybrid_option="Evaluate protocol-supported standardized hybrid; for TLS 1.3 see RFC 10024 (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024).",
        migration_effort="low",
        suggested_complexity="REQUIRES ASSESSMENT",
        cnsa2_compliant=False,
        urgency_note="Candidate migration family; confirm operation, protocol, interoperability, performance and organizational policy. Timing requires organization-supplied X/Y/Z.",
        references=[_NIST_REF],
    ),
    ("DSA", "signing"): MigrationAdvice(
        from_algorithm="DSA", from_use_case="signing",
        primary_recommendation=_ML_DSA_65,
        alternatives=[_SLH_DSA_SHAKE_256S],
        hybrid_option=None,
        migration_effort="high",
        suggested_complexity="REQUIRES ASSESSMENT",
        cnsa2_compliant=False,
        urgency_note="Candidate migration family; confirm operation, protocol, interoperability, performance and organizational policy. Timing requires organization-supplied X/Y/Z.",
        references=[_NIST_REF],
    ),
    # ── Hashing ────────────────────────────────────────────────────────── #
    ("SHA-1", "hashing"): MigrationAdvice(
        from_algorithm="SHA-1", from_use_case="hashing",
        primary_recommendation=_SHA3_256,
        alternatives=[_SHA_512],
        hybrid_option=None,
        migration_effort="medium",
        suggested_complexity="REQUIRES ASSESSMENT",
        cnsa2_compliant=False,  # SHA-1 disallowed
        urgency_note="Candidate migration family; confirm operation, protocol, interoperability, performance and organizational policy. Timing requires organization-supplied X/Y/Z.",
        references=["https://csrc.nist.gov/Projects/Hash-Functions"],
    ),
    ("MD5", "hashing"): MigrationAdvice(
        from_algorithm="MD5", from_use_case="hashing",
        primary_recommendation=_SHA3_256,
        alternatives=[_SHA_512],
        hybrid_option=None,
        migration_effort="low",
        suggested_complexity="REQUIRES ASSESSMENT",
        cnsa2_compliant=False,
        urgency_note="Candidate migration family; confirm operation, protocol, interoperability, performance and organizational policy. Timing requires organization-supplied X/Y/Z.",
        references=["https://csrc.nist.gov/Projects/Hash-Functions"],
    ),
    ("SHA-256", "hashing"): MigrationAdvice(
        from_algorithm="SHA-256", from_use_case="hashing",
        primary_recommendation=_SHA_512,
        alternatives=[_SHA3_256],
        hybrid_option=None,
        migration_effort="low",
        suggested_complexity="REQUIRES ASSESSMENT",
        cnsa2_compliant=False,
        urgency_note="Candidate migration family; confirm operation, protocol, interoperability, performance and organizational policy. Timing requires organization-supplied X/Y/Z.",
        references=[_CNSA_REF],
    ),
    # ── Symmetric encryption ───────────────────────────────────────────── #
    ("AES", "encryption"): MigrationAdvice(
        from_algorithm="AES", from_use_case="encryption",
        primary_recommendation=_AES_256,
        alternatives=[],
        hybrid_option=None,
        migration_effort="low",
        suggested_complexity="REQUIRES ASSESSMENT",
        cnsa2_compliant=False,
        urgency_note="Candidate migration family; confirm operation, protocol, interoperability, performance and organizational policy. Timing requires organization-supplied X/Y/Z.",
        references=[_CNSA_REF],
    ),
    ("DES", "encryption"): MigrationAdvice(
        from_algorithm="DES", from_use_case="encryption",
        primary_recommendation=_AES_256,
        alternatives=[],
        hybrid_option=None,
        migration_effort="high",
        suggested_complexity="REQUIRES ASSESSMENT",
        cnsa2_compliant=False,
        urgency_note="Candidate migration family; confirm operation, protocol, interoperability, performance and organizational policy. Timing requires organization-supplied X/Y/Z.",
        references=[_CNSA_REF],
    ),
}

# Aliases for alternate use case naming
_USE_CASE_ALIASES = {
    "key_agreement": "key_agreement",
    "key-agreement": "key_agreement",
    "key_establishment": "key_establishment",
    "key-establishment": "key_establishment",
    "signing": "signing",
    "digital_signature": "signing",
    "signature": "signing",
    "hashing": "hashing",
    "hash": "hashing",
    "digest": "hashing",
    "encryption": "encryption",
    "symmetric": "encryption",
    "key_generation": "signing",  # key gen → signing advice by default
}


class AdvisoryEngine:
    """Recommends PQC migration paths for classical crypto primitives."""

    def recommend(self, algorithm: str, use_case: str = "unknown") -> MigrationAdvice | None:
        """Recommend a PQC migration for a given algorithm and use case.

        Args:
            algorithm: Canonical algorithm name (e.g. "RSA", "ECDSA").
            use_case: Use case string (e.g. "signing", "key_agreement").

        Returns:
            MigrationAdvice or None if no specific advice is available.
        """
        if algorithm.upper() in {'AES', 'AES-128', 'AES-192', 'AES-256', 'SHA-256'}:
            return None  # No immediate PQ migration requirement under current guidance.
        normalized_use_case = _USE_CASE_ALIASES.get(use_case.lower(), use_case.lower())
        key = (algorithm.upper(), normalized_use_case)

        advice = _ADVICE.get(key)
        if advice:
            return advice

        # Only algorithm families with an unambiguous operation may use a fallback.
        inferred = {'ECDH': 'key_agreement', 'DH': 'key_agreement', 'X25519': 'key_agreement',
                    'ECDSA': 'signing', 'ED25519': 'signing', 'DSA': 'signing'}.get(algorithm.upper())
        if inferred and normalized_use_case == 'unknown':
            return _ADVICE.get((algorithm.upper(), inferred))

        return None

    def all_mappings(self) -> list[MigrationAdvice]:
        """Return all known migration mappings."""
        return list(_ADVICE.values())

    def catalogue(self) -> list[PQCAlgorithm]:
        """Return the full PQC algorithm catalogue."""
        return [
            _ML_KEM_512, _ML_KEM_768, _ML_KEM_1024,
            _ML_DSA_44, _ML_DSA_65, _ML_DSA_87,
            _SLH_DSA_SHAKE_128S, _SLH_DSA_SHAKE_256S,
            _SHA3_256, _SHA3_512, _SHA_512, _AES_256,
        ]
