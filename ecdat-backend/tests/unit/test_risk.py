"""Unit tests for Mosca + QARS risk engines."""

from __future__ import annotations

import pytest

from ecdat.core.risk.mosca import (
    DEFAULT_Z_CENTRAL,
    DEFAULT_Z_CONSERVATIVE,
    DEFAULT_Z_OPTIMISTIC,
    MoscaEngine,
    MoscaVerdict,
    QARSEngine,
    QARSWeights,
)


class TestMoscaEngine:
    def setup_method(self):
        self.engine = MoscaEngine()

    def test_three_scenarios_returned(self):
        result = self.engine.calculate("RSA", x_years=10.0)
        assert len(result.scenarios) == 3
        labels = [s.label for s in result.scenarios]
        assert "conservative" in labels
        assert "central" in labels
        assert "optimistic" in labels

    def test_act_now_when_x_plus_y_exceeds_z(self):
        # X=12, Y≈3 (RSA central) → X+Y=15 > Z_conservative=5 → ACT NOW
        result = self.engine.calculate("RSA", x_years=12.0)
        conservative = result.scenarios[0]
        assert conservative.verdict == MoscaVerdict.ACT_NOW

    def test_safe_when_large_margin(self):
        # X=1, Y≈1 (AES) → X+Y=2 << Z_optimistic=15 → SAFE
        result = self.engine.calculate("AES", x_years=1.0)
        optimistic = result.scenarios[2]
        assert optimistic.verdict == MoscaVerdict.SAFE

    def test_y_override(self):
        result = self.engine.calculate("RSA", x_years=5.0, y_override=0.5)
        assert result.y_value == 0.5
        assert result.y_source == "user_override"

    def test_result_stores_x_and_z_values(self):
        result = self.engine.calculate("ECDSA", x_years=8.0)
        assert result.x_value == 8.0
        assert result.z_conservative == DEFAULT_Z_CONSERVATIVE
        assert result.z_central == DEFAULT_Z_CENTRAL
        assert result.z_optimistic == DEFAULT_Z_OPTIMISTIC

    def test_margin_is_absolute(self):
        result = self.engine.calculate("RSA", x_years=3.0)
        for scenario in result.scenarios:
            assert scenario.margin_years >= 0


class TestQARSEngine:
    def setup_method(self):
        self.mosca = MoscaEngine()
        self.qars = QARSEngine()

    def test_score_range_0_to_1(self):
        mosca_result = self.mosca.calculate("RSA", x_years=10.0)
        score = self.qars.calculate(mosca_result, criticality="high", exposure="external")
        assert 0.0 <= score.qars_score <= 1.0

    def test_high_risk_asset_scores_high(self):
        # RSA, 10yr data, external exposure, critical criticality → should be high
        mosca_result = self.mosca.calculate("RSA", x_years=10.0)
        score = self.qars.calculate(mosca_result, criticality="critical", exposure="external")
        assert score.qars_score >= 0.7, f"Expected high score, got {score.qars_score}"

    def test_low_risk_asset_scores_low(self):
        # AES, 1yr data, internal, low criticality
        mosca_result = self.mosca.calculate("AES", x_years=1.0)
        score = self.qars.calculate(mosca_result, criticality="low", exposure="internal")
        assert score.qars_score <= 0.5, f"Expected low score, got {score.qars_score}"

    def test_custom_weights_applied(self):
        weights = QARSWeights(temporal=0.5, sensitivity=0.3, exposure=0.2)
        mosca_result = self.mosca.calculate("RSA", x_years=10.0)
        score = self.qars.calculate(
            mosca_result, criticality="high", exposure="external", weights=weights
        )
        assert score.weights.temporal == 0.5

    def test_weights_must_sum_to_one(self):
        with pytest.raises(ValueError, match="must sum to 1.0"):
            bad_weights = QARSWeights(temporal=0.5, sensitivity=0.5, exposure=0.5)
            bad_weights.validate()

    def test_individual_scores_returned(self):
        mosca_result = self.mosca.calculate("ECDSA", x_years=7.0)
        score = self.qars.calculate(mosca_result, criticality="medium", exposure="dmz")
        assert score.temporal_score is not None
        assert score.sensitivity_score is not None
        assert score.exposure_score is not None
