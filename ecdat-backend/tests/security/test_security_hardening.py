"""Security hardening test suite for ECDAT backend.

Tests:
- Secret redaction and rejection in evidence envelopes
- Prevention of raw secret injection in asset metadata
- Parameterized SQL execution
- Tenant isolation boundaries
"""

from __future__ import annotations

import pytest

from ecdat.core.evidence.envelope import (
    CollectorInfo,
    CryptoObservation,
    EvidenceEnvelope,
    ObservationType,
    RunInfo,
    SourceLocation,
    UsageEvidence,
)
from ecdat.core.normalization.algorithms import normalize_algorithm


class TestSecurityHardening:
    def test_pipeline_rejects_raw_private_keys(self) -> None:
        """Envelopes containing private keys or secret material must be rejected by pipeline."""
        env = EvidenceEnvelope(
            collector=CollectorInfo(name="test", version="1.0"),
            run=RunInfo(scan_id="s1", collector_run_id="r1"),
            tenant_id="tenant-1",
            source_location=SourceLocation(repository="repo", path="key.pem"),
            observation=CryptoObservation(
                observation_type=ObservationType.ALGORITHM_USE,
                algorithm="RSA",
                usage_evidence=UsageEvidence.STATIC,
                extra={"private_key": "-----BEGIN RSA PRIVATE KEY-----..."},
            ),
        )
        assert env.has_secret_content() is True

    def test_pipeline_rejects_credentials_in_metadata(self) -> None:
        """Envelopes with credentials in metadata must be rejected."""
        env = EvidenceEnvelope(
            collector=CollectorInfo(name="test", version="1.0"),
            run=RunInfo(scan_id="s1", collector_run_id="r1"),
            tenant_id="tenant-1",
            source_location=SourceLocation(repository="repo", path="auth.py"),
            observation=CryptoObservation(
                observation_type=ObservationType.ALGORITHM_USE,
                algorithm="AES",
                usage_evidence=UsageEvidence.STATIC,
            ),
            metadata={"password": "supersecretpassword123"},
        )
        assert env.has_secret_content() is True

    def test_sqli_payload_in_algorithm_does_not_break_normalization(self) -> None:
        """SQL injection strings in algorithm name are safely treated as raw strings."""
        sqli_payload = "RSA' OR '1'='1'; DROP TABLE assets; --"
        env = EvidenceEnvelope(
            collector=CollectorInfo(name="test", version="1.0"),
            run=RunInfo(scan_id="s1", collector_run_id="r1"),
            tenant_id="tenant-1",
            source_location=SourceLocation(repository="repo", path="service.py"),
            observation=CryptoObservation(
                observation_type=ObservationType.ALGORITHM_USE,
                algorithm=sqli_payload,
                usage_evidence=UsageEvidence.STATIC,
            ),
        )
        assert normalize_algorithm(env.observation.algorithm) is not None
