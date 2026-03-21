from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from core.models import AnomalyResult, LogEvent
from core.normalization import normalize_message, normalize_path
from detectors.base import IAnomalyDetector


class FrequencyBaselineDetector(IAnomalyDetector):
    def __init__(self, model_version: str = "baseline") -> None:
        self.template_counts: Counter[str] = Counter()
        self.total: int = 0
        self.max_count: int = 0
        self.model_version = model_version

    def train(self, events: list[LogEvent]) -> None:
        templates = [_event_template(event) for event in events]
        self.template_counts = Counter(templates)
        self.total = sum(self.template_counts.values())
        self.max_count = max(self.template_counts.values(), default=0)

    def score(self, events: list[LogEvent]) -> list[float]:
        scores: list[float] = []
        for event in events:
            template = _event_template(event)
            count = self.template_counts.get(template, 0)
            if self.max_count == 0:
                scores.append(1.0)
            else:
                frequency = count / self.max_count
                scores.append(1.0 - frequency)
        return scores

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
        payload = {
            "template_counts": dict(self.template_counts),
            "total": self.total,
            "max_count": self.max_count,
            "model_version": self.model_version,
        }
        Path(path).mkdir(parents=True, exist_ok=True)
        with open(Path(path) / "baseline.json", "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=True, indent=2)

    @classmethod
    def load(cls, path: str) -> FrequencyBaselineDetector:
        with open(Path(path) / "baseline.json", encoding="utf-8") as f:
            payload = json.load(f)
        instance = cls(model_version=payload.get("model_version", "baseline"))
        instance.template_counts = Counter(payload.get("template_counts", {}))
        instance.total = int(payload.get("total", 0))
        instance.max_count = int(payload.get("max_count", 0))
        return instance


def _event_template(event: LogEvent) -> str:
    method = (event.method or "UNKNOWN").upper()
    status_class = str(event.status // 100) if event.status else "0"
    base = normalize_path(event.path or "")
    if not base:
        base = normalize_message(event.message or "")
    return f"{method}|{status_class}|{base}"
