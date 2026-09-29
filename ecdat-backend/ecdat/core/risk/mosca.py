# Legacy research model, not used by the website or CLI discovery assessment.
# The authoritative product model is ecdat.core.discovery.assessment.
"""Mosca theorem and QARS (Quantum Asset Risk Score) implementation.

Mosca timing rule: If X + Y >= Z, act now.
  X = required protection lifetime (years protection needed)
  Y = migration time (years to deploy PQC)
  Z = organization-selected quantum threat horizon (not a prediction)

QARS = weighted combination of:
  - Temporal risk (Mosca verdict)
  - Data sensitivity / asset criticality
  - Network exposure class
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MoscaVerdict(str, Enum):
    """Mosca decision outcome."""

    ACT_NOW = "act_now"          # X + Y > Z: already urgent
    MONITOR = "monitor"          # X + Y <= Z but close
    SAFE = "safe"                # significant margin remaining


@dataclass(frozen=True)
class MoscaScenario:
    """A single Mosca scenario (conservative / central / optimistic)."""

    label: str             # "conservative" | "central" | "optimistic"
    z_years: float         # estimated years to CRQC
    x_years: float         # required protection lifetime (years)
    y_years: float         # migration time (years)
    result: float          # x + y - z (positive = act now)
    verdict: MoscaVerdict
    margin_years: float    # abs(z - (x + y))


@dataclass
class MoscaResult:
    """Full Mosca analysis across three Z scenarios."""

    # Z-value assumptions (years)
    z_conservative: float   # pessimistic: 5 years
    z_central: float        # central estimate: 10 years
    z_optimistic: float     # optimistic: 15 years

    x_value: float          # required protection lifetime (years)
    x_source: str           # e.g. "explicit", "default_HIPAA", "user_override"

    y_value: float          # migration time
    y_min: float
    y_max: float
    y_source: str           # e.g. "migration_estimate_v1.0", "user_override"

    scenarios: list[MoscaScenario] = field(default_factory=list)

    @property
    def conservative_verdict(self) -> MoscaVerdict:
        return self.scenarios[0].verdict if self.scenarios else MoscaVerdict.MONITOR

    @property
    def central_verdict(self) -> MoscaVerdict:
        return self.scenarios[1].verdict if len(self.scenarios) > 1 else MoscaVerdict.MONITOR


@dataclass(frozen=True)
class QARSWeights:
    """Weighting profile for QARS calculation.

    Weights must sum to 1.0.
    """

    temporal: float = 0.3333
    sensitivity: float = 0.3333
    exposure: float = 0.3334

    def validate(self) -> None:
        total = self.temporal + self.sensitivity + self.exposure
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"QARS weights must sum to 1.0, got {total}")


@dataclass(frozen=True)
class QARSResult:
    """QARS (Quantum Asset Risk Score) for a single asset."""

    temporal_score: float      # 0.0–1.0 derived from Mosca
    sensitivity_score: float   # 0.0–1.0 from criticality mapping
    exposure_score: float      # 0.0–1.0 from exposure class mapping
    weights: QARSWeights
    qars_score: float          # weighted combination, 0.0–1.0

    # Override tracking
    is_overridden: bool = False
    override_reason: str | None = None


# ---------------------------------------------------------------------------
# Z-value assumptions (configurable, used as defaults)
# ---------------------------------------------------------------------------

# No generic migration-duration estimates or quantum-arrival defaults.
# Callers must supply both Y and Z explicitly.

# ---------------------------------------------------------------------------
# Criticality → sensitivity score
# ---------------------------------------------------------------------------

SENSITIVITY_SCORES: dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.50,
    "low": 0.25,
    "unknown": 0.50,
}

# ---------------------------------------------------------------------------
# Exposure class → exposure score
# ---------------------------------------------------------------------------

EXPOSURE_SCORES: dict[str, float] = {
    "external": 1.0,
    "dmz": 0.75,
    "internal": 0.50,
    "unknown": 0.50,
}


class MoscaEngine:
    """Calculates Mosca risk across three Z scenarios."""

    def calculate(
        self,
        algorithm: str,
        x_years: float,
        x_source: str = "explicit",
        y_override: float | None = None,
        z_override: float | None = None,
    ) -> MoscaResult:
        """Calculate Mosca result for an asset.

        Args:
            algorithm: Canonical algorithm name (e.g. "RSA").
            x_years: Required protection lifetime in years.
            x_source: Source/justification for X value.
            y_override: Override Y value (years to migrate). Required; no default is inferred.

        Returns:
            MoscaResult with conservative/central/optimistic scenarios.
        """
        if y_override is None or z_override is None:
            raise ValueError('NOT ASSESSED: organization-supplied migration duration Y and planning horizon Z are required.')
        from math import isfinite
        if not all(isfinite(v) for v in (x_years, y_override, z_override)) or x_years < 0 or y_override < 0 or z_override <= 0:
            raise ValueError('X/Y must be finite and non-negative; Z must be finite and positive.')
        y_value = y_min = y_max = y_override
        scenarios = []
        # Retain three legacy result slots, all using the explicitly selected scenario.
        for label, z in [('conservative', z_override), ('central', z_override), ('optimistic', z_override)]:
            result = x_years + y_value - z
            margin = z - (x_years + y_value)

            if result >= 0:
                verdict = MoscaVerdict.ACT_NOW
            elif margin <= 2.0:
                verdict = MoscaVerdict.MONITOR
            else:
                verdict = MoscaVerdict.SAFE

            scenarios.append(MoscaScenario(
                label=label,
                z_years=z,
                x_years=x_years,
                y_years=y_value,
                result=result,
                verdict=verdict,
                margin_years=margin,
            ))

        return MoscaResult(
            z_conservative=z_override,
            z_central=z_override,
            z_optimistic=z_override,
            x_value=x_years,
            x_source=x_source,
            y_value=y_value,
            y_min=y_min,
            y_max=y_max,
            y_source="user_override",
            scenarios=scenarios,
        )


class QARSEngine:
    """Calculates QARS score for an asset."""

    def calculate(
        self,
        mosca_result: MoscaResult,
        criticality: str,
        exposure: str,
        weights: QARSWeights | None = None,
    ) -> QARSResult:
        """Calculate QARS score.

        Args:
            mosca_result: Mosca analysis result.
            criticality: Asset criticality string (critical/high/medium/low).
            exposure: Exposure class string (external/dmz/internal/unknown).
            weights: QARS weighting profile. Uses default equal weights if None.

        Returns:
            QARSResult with individual dimension scores and weighted total.
        """
        weights = weights or QARSWeights()
        weights.validate()

        # Temporal score: ACT_NOW=1.0, MONITOR=0.6, SAFE based on margin
        conservative_scenario = mosca_result.scenarios[0]
        central_scenario = mosca_result.scenarios[1]

        if conservative_scenario.verdict == MoscaVerdict.ACT_NOW:
            temporal_score = 1.0
        elif central_scenario.verdict == MoscaVerdict.ACT_NOW:
            temporal_score = 0.85
        elif central_scenario.verdict == MoscaVerdict.MONITOR:
            temporal_score = 0.6
        else:
            # Safe — score inversely proportional to margin
            margin = central_scenario.margin_years
            temporal_score = max(0.0, min(0.5, 1.0 - (margin / 10.0)))

        sensitivity_score = SENSITIVITY_SCORES.get(criticality.lower(), 0.5)
        exposure_score = EXPOSURE_SCORES.get(exposure.lower(), 0.5)

        qars_score = (
            weights.temporal * temporal_score
            + weights.sensitivity * sensitivity_score
            + weights.exposure * exposure_score
        )

        return QARSResult(
            temporal_score=round(temporal_score, 4),
            sensitivity_score=round(sensitivity_score, 4),
            exposure_score=round(exposure_score, 4),
            weights=weights,
            qars_score=round(qars_score, 4),
        )
