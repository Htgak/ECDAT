"""Unit tests for algorithm normalization."""

from __future__ import annotations

import pytest

from ecdat.core.normalization.algorithms import normalize_algorithm


class TestNormalizeAlgorithm:
    def test_empty_string_returns_unknown(self):
        result = normalize_algorithm("")
        assert result.canonical == "UNKNOWN"
        assert result.family == "unknown"

    def test_rsa_various_forms(self):
        cases = ["RSA", "rsa", "RSA/ECB/PKCS1Padding", "RSA-OAEP", "rsaEncryption"]
        for raw in cases:
            result = normalize_algorithm(raw)
            assert result.canonical == "RSA", f"Failed for: {raw}"
            assert result.family == "asymmetric"
            assert result.is_deprecated is False

    def test_aes_gcm_extracts_mode(self):
        result = normalize_algorithm("AES/GCM/NoPadding")
        assert result.canonical == "AES"
        assert result.mode == "GCM"

    def test_aes_cbc_extracts_mode(self):
        result = normalize_algorithm("AES/CBC/PKCS5Padding")
        assert result.canonical == "AES"
        assert result.mode == "CBC"

    def test_sha1_is_deprecated(self):
        result = normalize_algorithm("SHA-1")
        assert result.canonical == "SHA-1"
        assert result.is_deprecated is True
        assert result.family == "hash"

    def test_sha256_not_deprecated(self):
        result = normalize_algorithm("SHA-256")
        assert result.is_deprecated is False

    def test_md5_is_deprecated(self):
        result = normalize_algorithm("MD5")
        assert result.is_deprecated is True

    def test_des_is_deprecated(self):
        result = normalize_algorithm("DES")
        assert result.is_deprecated is True

    def test_3des_is_deprecated(self):
        result = normalize_algorithm("DESede")
        assert result.canonical == "3DES"
        assert result.is_deprecated is True

    def test_rc4_is_deprecated(self):
        result = normalize_algorithm("RC4")
        assert result.is_deprecated is True

    def test_ecdsa_is_asymmetric(self):
        result = normalize_algorithm("ECDSA")
        assert result.canonical == "ECDSA"
        assert result.family == "asymmetric"
        assert result.is_pqc is False

    def test_pqc_ml_kem(self):
        for raw in ["ML-KEM", "mlkem"]:
            result = normalize_algorithm(raw)
            assert result.canonical == "ML-KEM", f"Failed for: {raw}"
            assert result.is_pqc is True

    def test_pqc_ml_dsa(self):
        for raw in ["ML-DSA", "mldsa"]:
            result = normalize_algorithm(raw)
            assert result.canonical == "ML-DSA", f"Failed for: {raw}"
            assert result.is_pqc is True

    def test_pbkdf2_is_kdf(self):
        result = normalize_algorithm("PBKDF2WithHmacSHA256")
        assert result.canonical == "PBKDF2"
        assert result.family == "kdf"

    def test_chacha20_symmetric(self):
        result = normalize_algorithm("ChaCha20")
        assert result.canonical == "ChaCha20"
        assert result.family == "symmetric"

    def test_hmac_is_mac(self):
        result = normalize_algorithm("HMAC")
        assert result.family == "mac"

    def test_unknown_algorithm_preserved(self):
        result = normalize_algorithm("MyCustomCipher")
        assert result.canonical == "MyCustomCipher"
        assert result.family == "unknown"
