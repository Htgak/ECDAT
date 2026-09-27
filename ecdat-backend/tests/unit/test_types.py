"""Unit tests for domain types and enumerations."""

from __future__ import annotations

import pytest

from ecdat.core.model.types import (
    AnalysisStatus,
    Confidence,
    DependencyEvidenceLevel,
    ExposureClass,
    JobState,
    JobType,
    MatchType,
    ObservationType,
    PackageCoordinates,
    PolicyVerdict,
    RelationshipType,
    ScanStatus,
    StandardStatus,
    UsageEvidence,
)


class TestConfidence:
    def test_values(self):
        assert Confidence.CONFIRMED.value == "confirmed"
        assert Confidence.PROBABLE.value == "probable"
        assert Confidence.UNCONFIRMED.value == "unconfirmed"

    def test_from_string(self):
        assert Confidence("confirmed") is Confidence.CONFIRMED


class TestAnalysisStatus:
    def test_unknown_is_not_secure(self):
        """Verify UNKNOWN exists and is distinct from NOT_OBSERVED."""
        assert AnalysisStatus.UNKNOWN != AnalysisStatus.NOT_OBSERVED
        assert AnalysisStatus.INDETERMINATE != AnalysisStatus.NOT_OBSERVED

    def test_all_status_values_exist(self):
        statuses = {s.value for s in AnalysisStatus}
        assert "observed" in statuses
        assert "not_observed" in statuses
        assert "unknown" in statuses
        assert "indeterminate" in statuses
        assert "unsupported" in statuses


class TestDependencyEvidenceLevel:
    def test_capability_is_not_active_use(self):
        """Capability != active use — test the semantic separation."""
        assert DependencyEvidenceLevel.CAPABILITY != DependencyEvidenceLevel.STATIC_USE
        assert DependencyEvidenceLevel.CAPABILITY != DependencyEvidenceLevel.RUNTIME_USE


class TestPackageCoordinates:
    def test_purl_without_group(self):
        pkg = PackageCoordinates(ecosystem="pypi", name="cryptography", version="44.0.0")
        assert pkg.to_purl() == "pkg:pypi/cryptography@44.0.0"

    def test_purl_with_group(self):
        pkg = PackageCoordinates(
            ecosystem="maven",
            name="bcprov-jdk18on",
            version="1.78",
            group="org.bouncycastle",
        )
        assert pkg.to_purl() == "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78"

    def test_purl_npm(self):
        pkg = PackageCoordinates(ecosystem="npm", name="node-forge", version="1.3.1")
        assert pkg.to_purl() == "pkg:npm/node-forge@1.3.1"


class TestJobStateMachine:
    def test_all_job_states_present(self):
        states = {s.value for s in JobState}
        assert "queued" in states
        assert "claimed" in states
        assert "running" in states
        assert "succeeded" in states
        assert "failed_retryable" in states
        assert "failed_final" in states

    def test_all_job_types_present(self):
        types = {t.value for t in JobType}
        assert "scan_create" in types
        assert "collect_source" in types
        assert "generate_cbom" in types
        assert "create_snapshot" in types
        assert "timestamp_snapshot" in types


class TestExposureClass:
    def test_unknown_is_not_internal(self):
        assert ExposureClass.UNKNOWN != ExposureClass.INTERNAL
