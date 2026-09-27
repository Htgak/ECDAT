"""Algorithm name normalization.

Converts raw algorithm strings from collector output into canonical
normalized forms. This ensures that "RSA", "rsa", "RSA/ECB/PKCS1Padding",
and "RSA-OAEP" all resolve to the same canonical algorithm name, allowing
the identity resolver and confidence engine to work correctly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class NormalizedAlgorithm:
    """Result of algorithm normalization."""

    canonical: str          # e.g. "RSA"
    family: str             # e.g. "asymmetric"
    raw: str                # original string
    mode: str | None        # e.g. "CBC", "GCM"
    padding: str | None     # e.g. "PKCS1v15", "OAEP"
    hash_alg: str | None    # e.g. "SHA-256"
    is_pqc: bool = False    # is this a PQC algorithm?
    is_deprecated: bool = False


# ---------------------------------------------------------------------------
# Canonical name → family mapping
# ---------------------------------------------------------------------------

_ALGORITHM_FAMILIES: dict[str, str] = {
    # Asymmetric
    "RSA": "asymmetric",
    "ECDSA": "asymmetric",
    "ECDH": "asymmetric",
    "EdDSA": "asymmetric",
    "Ed25519": "asymmetric",
    "Ed448": "asymmetric",
    "X25519": "asymmetric",
    "X448": "asymmetric",
    "DSA": "asymmetric",
    "DH": "asymmetric",
    "ElGamal": "asymmetric",
    # Symmetric
    "AES": "symmetric",
    "DES": "symmetric",
    "3DES": "symmetric",
    "ChaCha20": "symmetric",
    "Blowfish": "symmetric",
    "Camellia": "symmetric",
    "RC4": "symmetric",
    "RC2": "symmetric",
    "IDEA": "symmetric",
    # Hash
    "SHA-1": "hash",
    "SHA-256": "hash",
    "SHA-384": "hash",
    "SHA-512": "hash",
    "SHA3-256": "hash",
    "SHA3-384": "hash",
    "SHA3-512": "hash",
    "MD5": "hash",
    "MD2": "hash",
    "RIPEMD-160": "hash",
    "BLAKE2b": "hash",
    "BLAKE2s": "hash",
    # MAC
    "HMAC": "mac",
    "CMAC": "mac",
    "GMAC": "mac",
    "Poly1305": "mac",
    # KDF
    "PBKDF2": "kdf",
    "HKDF": "kdf",
    "scrypt": "kdf",
    "bcrypt": "kdf",
    "Argon2": "kdf",
    # PQC (NIST finalized)
    "ML-KEM": "pqc_kem",
    "ML-DSA": "pqc_sign",
    "SLH-DSA": "pqc_sign",
    "FN-DSA": "pqc_sign",
    "HQC": "pqc_kem",
    # Other
    "CRC32": "checksum",
    "PRNG": "random",
    "DRBG": "random",
    "CTR-DRBG": "random",
    "HMAC-DRBG": "random",
}

_DEPRECATED = {"DES", "3DES", "RC4", "RC2", "MD2", "MD5", "SHA-1", "Blowfish", "IDEA", "DSA"}

_PQC = {"ML-KEM", "ML-DSA", "SLH-DSA", "FN-DSA", "HQC"}

# ---------------------------------------------------------------------------
# Raw → canonical alias table
# ---------------------------------------------------------------------------

_ALIASES: dict[str, str] = {
    # RSA variants
    "rsa": "RSA",
    "rsaencryption": "RSA",
    "rsa/ecb/pkcs1padding": "RSA",
    "rsa/ecb/oaepwithsha-1andmgf1padding": "RSA",
    "rsa/ecb/oaepwithsha-256andmgf1padding": "RSA",
    "rsa/none/pkcs1padding": "RSA",
    "rsa-oaep": "RSA",
    "rsa_oaep": "RSA",
    "rsassa-pkcs1-v1_5": "RSA",
    "rsassa_pss": "RSA",
    "pss": "RSA",
    # AES variants
    "aes": "AES",
    "aes-128-cbc": "AES",
    "aes-192-cbc": "AES",
    "aes-256-cbc": "AES",
    "aes-128-gcm": "AES",
    "aes-256-gcm": "AES",
    "aes-128-ecb": "AES",
    "aes-256-ecb": "AES",
    "aes/cbc/pkcs5padding": "AES",
    "aes/gcm/nopadding": "AES",
    "aes/ecb/pkcs5padding": "AES",
    "aesgcm": "AES",
    "aescbc": "AES",
    "aes_128_cbc": "AES",
    "aes_256_cbc": "AES",
    "aes_256_gcm": "AES",
    # DES / 3DES
    "des": "DES",
    "3des": "3DES",
    "tripledes": "3DES",
    "desede": "3DES",
    "desede/cbc/pkcs5padding": "3DES",
    "des-ede3-cbc": "3DES",
    # EC / ECDSA
    "ec": "ECDSA",
    "ecdsa": "ECDSA",
    "ecdh": "ECDH",
    "ecdhwithsha256": "ECDH",
    "secp256r1": "ECDSA",
    "prime256v1": "ECDSA",
    "secp384r1": "ECDSA",
    "secp521r1": "ECDSA",
    "curve25519": "X25519",
    # SHA
    "sha": "SHA-1",
    "sha1": "SHA-1",
    "sha-1": "SHA-1",
    "sha256": "SHA-256",
    "sha-256": "SHA-256",
    "sha384": "SHA-384",
    "sha-384": "SHA-384",
    "sha512": "SHA-512",
    "sha-512": "SHA-512",
    "sha3-256": "SHA3-256",
    "sha3-512": "SHA3-512",
    "sha_256": "SHA-256",
    # MD5
    "md5": "MD5",
    "md-5": "MD5",
    # ChaCha
    "chacha20": "ChaCha20",
    "chacha20-poly1305": "ChaCha20",
    "xchacha20": "ChaCha20",
    # HMAC
    "hmac": "HMAC",
    "hmacwithsha256": "HMAC",
    "hmacsha256": "HMAC",
    "hmacsha512": "HMAC",
    # DSA
    "dsa": "DSA",
    # EdDSA
    "eddsa": "EdDSA",
    "ed25519": "Ed25519",
    "ed448": "Ed448",
    # KDF
    "pbkdf2": "PBKDF2",
    "pbkdf2withhmacsha256": "PBKDF2",
    "pbkdf2withhmacsha512": "PBKDF2",
    "hkdf": "HKDF",
    "scrypt": "scrypt",
    "bcrypt": "bcrypt",
    "argon2id": "Argon2",
    "argon2i": "Argon2",
    # PQC
    "ml-kem": "ML-KEM",
    "mlkem": "ML-KEM",
    "kyber": "ML-KEM",
    "ml-dsa": "ML-DSA",
    "mldsa": "ML-DSA",
    "dilithium": "ML-DSA",
    "slh-dsa": "SLH-DSA",
    "sphincs": "SLH-DSA",
    "fn-dsa": "FN-DSA",
    "falcon": "FN-DSA",
    # RC4
    "rc4": "RC4",
    "arcfour": "RC4",
    # Blowfish
    "blowfish": "Blowfish",
    # DRBG
    "ctr-drbg": "CTR-DRBG",
    "hmac-drbg": "HMAC-DRBG",
    "drbg": "DRBG",
}

# ---------------------------------------------------------------------------
# Mode / padding extraction
# ---------------------------------------------------------------------------

_MODES = {"CBC", "ECB", "GCM", "CTR", "CFB", "OFB", "CCM", "SIV", "XTS"}
_PADDINGS = {"PKCS5Padding", "PKCS7Padding", "PKCS1Padding", "PKCS1v15",
             "OAEPWithSHA-256AndMGF1Padding", "NoPadding", "OAEP", "PSS"}


def _extract_jca_parts(raw: str) -> tuple[str | None, str | None]:
    """Extract mode and padding from JCA-style 'ALG/MODE/PADDING' strings."""
    parts = raw.split("/")
    if len(parts) < 2:
        return None, None
    mode = parts[1].upper() if len(parts) > 1 else None
    padding = parts[2] if len(parts) > 2 else None
    return mode if mode in _MODES else None, padding


def normalize_algorithm(raw: str) -> NormalizedAlgorithm:
    """Normalize a raw algorithm string to a canonical form.

    Args:
        raw: The raw algorithm string from collector output.

    Returns:
        A NormalizedAlgorithm with canonical name and metadata.
    """
    if not raw:
        return NormalizedAlgorithm(
            canonical="UNKNOWN",
            family="unknown",
            raw=raw,
            mode=None,
            padding=None,
            hash_alg=None,
        )

    mode, padding = _extract_jca_parts(raw)

    # Normalize: lowercase, strip spaces
    key = re.sub(r"\s+", "", raw.lower())
    canonical = _ALIASES.get(key)

    if canonical is None:
        # Try stripping the algorithm part from JCA notation
        base = key.split("/")[0]
        canonical = _ALIASES.get(base)

    if canonical is None:
        # Try uppercase match against known families
        upper = raw.upper().split("/")[0].strip()
        canonical = _ALGORITHM_FAMILIES.get(upper, None)
        if canonical is not None:
            canonical = upper
        else:
            # Preserve as-is but mark unknown family
            canonical = raw.strip()

    family = _ALGORITHM_FAMILIES.get(canonical, "unknown")
    is_pqc = canonical in _PQC
    is_deprecated = canonical in _DEPRECATED

    return NormalizedAlgorithm(
        canonical=canonical,
        family=family,
        raw=raw,
        mode=mode,
        padding=padding,
        hash_alg=None,
        is_pqc=is_pqc,
        is_deprecated=is_deprecated,
    )
