from __future__ import annotations

from collections.abc import Iterable

import numpy as np

from core.models import LogEvent
from detectors.baseline import FrequencyBaselineDetector
from detectors.isolation_forest import IsolationForestDetector
from detectors.registry import ModelRegistry
from services.features import FeatureExtractor


def train_model(
    events: Iterable[LogEvent],
    model_type: str,
    registry: ModelRegistry,
    feature_extractor: FeatureExtractor,
) -> dict[str, object]:
    events_list = list(events)
    detector = build_detector(model_type, feature_extractor)
    detector.train(events_list)

    scores = detector.score(events_list)
    threshold_quantile = 0.95 if model_type.lower() == "baseline" else 1.0 - float(
        detector.contamination
    )
    threshold = float(np.quantile(scores, threshold_quantile)) if scores else 0.0

    train_metrics = {
        "score_mean": float(np.mean(scores)) if scores else 0.0,
        "score_std": float(np.std(scores)) if scores else 0.0,
        "score_p90": float(np.quantile(scores, 0.90)) if scores else 0.0,
        "score_p95": float(np.quantile(scores, 0.95)) if scores else 0.0,
        "score_p99": float(np.quantile(scores, 0.99)) if scores else 0.0,
        "threshold": threshold,
        "threshold_quantile": threshold_quantile,
        "training_samples": len(events_list),
    }
    return registry.save(
        detector,
        model_type=model_type.lower(),
        feature_extractor=feature_extractor,
        train_metrics=train_metrics,
    )


def build_detector(model_type: str, feature_extractor: FeatureExtractor):
    normalized = model_type.lower()
    if normalized == "baseline":
        return FrequencyBaselineDetector(model_version="baseline")
    if normalized in {"isolation_forest", "iforest"}:
        return IsolationForestDetector(
            feature_extractor=feature_extractor,
            model_version="iforest",
        )
    raise ValueError(f"Unsupported model type: {model_type}")
