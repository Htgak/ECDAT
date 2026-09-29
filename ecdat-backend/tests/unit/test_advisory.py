"""Unit tests for the PQC Advisory Engine."""

from __future__ import annotations

import pytest

from ecdat.core.advisory.engine import AdvisoryEngine, PQCAlgorithm, MigrationAdvice


class TestAdvisoryEngine:
    def setup_method(self) -> None:
        self.engine = AdvisoryEngine()

    def test_rsa_signing_recommendation(self) -> None:
        advice = self.engine.recommend("RSA", use_case="signing")
        assert advice is not None
        assert advice.from_algorithm == "RSA"
        assert advice.primary_recommendation.family == "ML-DSA"
        assert advice.primary_recommendation.name == "ML-DSA-65"
        assert advice.migration_effort == "high"
        assert len(advice.alternatives) > 0

    def test_rsa_key_establishment_recommendation(self) -> None:
        advice = self.engine.recommend("RSA", use_case="key_establishment")
        assert advice is not None
        assert advice.primary_recommendation.family == "ML-KEM"
        assert advice.primary_recommendation.name == "ML-KEM-768"
        assert advice.hybrid_option is not None

    def test_ecdsa_recommendation(self) -> None:
        advice = self.engine.recommend("ECDSA", use_case="signing")
        assert advice is not None
        assert advice.primary_recommendation.name == "ML-DSA-65"
        assert advice.cnsa2_compliant is False

    def test_broken_hash_recommendations(self) -> None:
        sha1_advice = self.engine.recommend("SHA-1", use_case="hashing")
        assert sha1_advice is not None
        assert sha1_advice.primary_recommendation.name in ("SHA-384", "SHA3-256", "SHA3-512")
        assert sha1_advice.migration_effort == "medium"

        md5_advice = self.engine.recommend("MD5", use_case="hashing")
        assert md5_advice is not None
        assert md5_advice.cnsa2_compliant is False


    def test_fallback_use_case_resolution(self) -> None:
        # If use_case isn't specified or is generic, fallback finds advice
        advice = self.engine.recommend("ECDH")
        assert advice is not None
        assert advice.primary_recommendation.family == "ML-KEM"

    def test_unknown_algorithm_returns_none(self) -> None:
        advice = self.engine.recommend("SUPER_SECRET_CIPHER_99")
        assert advice is None

    def test_catalogue_contains_fips_algorithms(self) -> None:
        catalogue = self.engine.catalogue()
        names = [a.name for a in catalogue]
        assert "ML-KEM-768" in names
        assert "ML-DSA-65" in names
        assert "SLH-DSA-SHAKE-128s" in names
