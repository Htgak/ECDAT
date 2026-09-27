"""Benchmark precision and recall runner for ECDAT discovery engines."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class MetricReport:
    category: str
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float


def compute_metrics(
    ground_truth: list[dict[str, str]],
    detected: list[dict[str, str]],
    category: str = "general",
) -> MetricReport:
    """Compute precision, recall, and F1 score against ground truth labeled findings."""
    gt_set = {(item["algorithm"].upper(), item.get("path", "")) for item in ground_truth}
    det_set = {(item["algorithm"].upper(), item.get("path", "")) for item in detected}

    tp = len(gt_set & det_set)
    fp = len(det_set - gt_set)
    fn = len(gt_set - det_set)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return MetricReport(
        category=category,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1_score=f1,
    )
