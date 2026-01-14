from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from services.features import FeatureExtractor
from detectors.base import IAnomalyDetector
from core.models import AnomalyResult, LogEvent


class IsolationForestDetector(IAnomalyDetector):
    def __init__(
        self,
        feature_extractor: FeatureExtractor,
        contamination: float = 0.05,
        random_state: int = 42,
        n_estimators: int = 200,
        model_version: str = "iforest",
    ) -> None:
        self.feature_extractor = feature_extractor
        self.contamination = contamination
        self.random_state = random_state
        self.model_version = model_version
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=n_estimators,
        )
        self.score_min: float | None = None
        self.score_max: float | None = None

    def train(self, events: list[LogEvent]) -> None:
        features = self.feature_extractor.transform(events)
        scaled = self.scaler.fit_transform(features)
        self.model.fit(scaled)
        raw_scores = -self.model.decision_function(scaled)
        self.score_min = float(np.min(raw_scores))
        self.score_max = float(np.max(raw_scores))

    def score(self, events: list[LogEvent]) -> list[float]:
        features = self.feature_extractor.transform(events)
        scaled = self.scaler.transform(features)
        raw_scores = -self.model.decision_function(scaled)
        return [_normalize_score(s, self.score_min, self.score_max) for s in raw_scores]

    def predict(self, events: list[LogEvent], threshold: float) -> list[AnomalyResult]:
        scores = self.score(events)
        return [
            AnomalyResult(
                event=event,
                score=score,
                is_anomaly=score >= threshold,
                model_version=self.model_version,
            )
            for event, score in zip(events, scores, strict=True)
        ]

    def save(self, path: str) -> None:
        Path(path).mkdir(parents=True, exist_ok=True)
        payload = {
            "scaler": self.scaler,
            "model": self.model,
            "score_min": self.score_min,
            "score_max": self.score_max,
            "model_version": self.model_version,
        }
        joblib.dump(payload, Path(path) / "iforest.joblib")

    @classmethod
    def load(cls, path: str) -> IsolationForestDetector:
        payload = joblib.load(Path(path) / "iforest.joblib")
        instance = cls(
            feature_extractor=FeatureExtractor(),
            contamination=payload["model"].contamination,
            random_state=payload["model"].random_state,
            model_version=payload.get("model_version", "iforest"),
        )
        instance.scaler = payload["scaler"]
        instance.model = payload["model"]
        instance.score_min = payload.get("score_min")
        instance.score_max = payload.get("score_max")
        return instance


def _normalize_score(score: float, score_min: float | None, score_max: float | None) -> float:
    if score_min is None or score_max is None:
        return float(score)
    if score_max - score_min == 0:
        return 0.0
    normalized = (score - score_min) / (score_max - score_min)
    return max(0.0, min(1.0, float(normalized)))
