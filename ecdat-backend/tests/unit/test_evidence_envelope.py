"""Unit tests for the Evidence Envelope."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ecdat.core.evidence.envelope import (
    CollectorInfo,
    ContainerLocation,
    CryptoObservation,
    DependencyLocation,
    DetectionRule,
    EvidenceEnvelope,
    EvidenceFingerprint,
    RunInfo,
    SourceLocation,
)
from ecdat.core.model.types import Confidence, ObservationType, UsageEvidence


def _make_collector() -> CollectorInfo:
    return CollectorInfo(name="java-source", version="1.0.0")


def _make_run() -> RunInfo:
    return RunInfo(
        scan_id="00000000-0000-0000-0000-000000000001",
        collector_run_id="00000000-0000-0000-0000-000000000002",
    )


def _make_source_location() -> SourceLocation:
    return SourceLocation(
        repository="https://github.com/example/app",
        path="src/main/java/com/example/CryptoService.java",
        line=42,
        commit_ref="abc123",
    )


def _make_observation() -> CryptoObservation:
    return CryptoObservation(
        observation_type=ObservationType.KEY_GENERATION,
        algorithm="RSA",
        key_size=2048,
        provider="SunRsaSign",
        usage_evidence=UsageEvidence.STATIC,
    )


class TestEvidenceEnvelope:
    def test_valid_source_envelope(self):
        env = EvidenceEnvelope(
            collector=_make_collector(),
            run=_make_run(),
            tenant_id="tenant-001",
            source_location=_make_source_location(),
            observation=_make_observation(),
            confidence=Confidence.CONFIRMED,
            detection_rule=DetectionRule(rule_id="JAVA-RSA-001", rule_version="1.0"),
        )
        assert env.schema_version == "1.0"
        assert env.observation.algorithm == "RSA"
        assert env.observation.key_size == 2048
        assert env.confidence == Confidence.CONFIRMED

    def test_requires_at_least_one_location(self):
        with pytest.raises(ValidationError, match="At least one location"):
            EvidenceEnvelope(
                collector=_make_collector(),
                run=_make_run(),
                tenant_id="tenant-001",
                observation=_make_observation(),
            )

    def test_empty_tenant_id_rejected(self):
        with pytest.raises(ValidationError, match="tenant_id must not be empty"):
            EvidenceEnvelope(
                collector=_make_collector(),
                run=_make_run(),
                tenant_id="   ",
                source_location=_make_source_location(),
                observation=_make_observation(),
            )

    def test_dependency_location(self):
        env = EvidenceEnvelope(
            collector=CollectorInfo(name="pypi-dep", version="1.0.0"),
            run=_make_run(),
            tenant_id="tenant-001",
            dependency_location=DependencyLocation(
                ecosystem="pypi",
                package_name="cryptography",
                package_version="44.0.0",
                is_direct=True,
            ),
            observation=_make_observation(),
            confidence=Confidence.PROBABLE,
        )
        assert env.dependency_location is not None
        assert env.dependency_location.ecosystem == "pypi"

    def test_container_location(self):
        env = EvidenceEnvelope(
            collector=CollectorInfo(name="container", version="1.0.0"),
            run=_make_run(),
            tenant_id="tenant-001",
            container_location=ContainerLocation(
                image_reference="nginx:1.27",
                image_digest="sha256:abc123",
                path_in_layer="/etc/ssl/openssl.cnf",
            ),
            observation=CryptoObservation(
                observation_type=ObservationType.CERTIFICATE_OPERATION,
            ),
        )
        assert env.container_location.path_in_layer == "/etc/ssl/openssl.cnf"

    def test_has_secret_content_detection(self):
        env = EvidenceEnvelope(
            collector=_make_collector(),
            run=_make_run(),
            tenant_id="tenant-001",
            source_location=_make_source_location(),
            observation=CryptoObservation(
                observation_type=ObservationType.HARDCODED_MATERIAL,
                extra={"key_material": "AAAAB3NzaC1yc2E..."},
            ),
        )
        assert env.has_secret_content() is True

    def test_no_secret_content_normally(self):
        env = EvidenceEnvelope(
            collector=_make_collector(),
            run=_make_run(),
            tenant_id="tenant-001",
            source_location=_make_source_location(),
            observation=_make_observation(),
        )
        assert env.has_secret_content() is False

    def test_envelope_is_immutable(self):
        env = EvidenceEnvelope(
            collector=_make_collector(),
            run=_make_run(),
            tenant_id="tenant-001",
            source_location=_make_source_location(),
            observation=_make_observation(),
        )
        with pytest.raises(ValidationError):
            env.tenant_id = "other-tenant"
