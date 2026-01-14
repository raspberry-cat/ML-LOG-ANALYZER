from __future__ import annotations

import logging

from core.models import AnomalyResult, LogEvent
from core.settings import Settings
from detectors.registry import ModelRegistry
from services.mitre import classify
from services.parsers import LogParser
from services.storage import Storage

logger = logging.getLogger(__name__)


class AnomalyService:
    def __init__(
        self,
        settings: Settings,
        parser: LogParser,
        registry: ModelRegistry,
        storage: Storage,
    ) -> None:
        self.settings = settings
        self.parser = parser
        self.registry = registry
        self.storage = storage
        self.detector, self.metadata = self.registry.load_latest()

    @property
    def model_version(self) -> str:
        return str(self.metadata.get("version", "unknown"))

    @property
    def threshold(self) -> float:
        train_metrics = self.metadata.get("train_metrics") or {}
        calibrated = train_metrics.get("threshold")
        if isinstance(calibrated, (int, float)):
            return float(calibrated)
        if str(self.metadata.get("model_type", "")).lower() == "baseline":
            return self.settings.baseline_threshold
        return self.settings.anomaly_threshold

    def ingest(self, lines: list[str], fmt: str | None = None) -> list[AnomalyResult]:
        events = self.parser.parse_lines(lines, fmt)
        return self.ingest_events(events)

    def ingest_events(self, events: list[LogEvent]) -> list[AnomalyResult]:
        if not events:
            return []

        results = self.detector.predict(events, self.threshold)
        for result in results:
            if result.is_anomaly:
                result.mitre_techniques = classify(result.event)

        self.storage.save_results(results)
        logger.info(
            "events_ingested",
            extra={
                "received": len(results),
                "anomalies": sum(1 for result in results if result.is_anomaly),
                "model_version": self.model_version,
            },
        )
        return results

    def get_anomalies(self, limit: int = 50, min_score: float | None = None) -> list[dict]:
        return self.storage.get_anomalies(limit=limit, min_score=min_score)

    def get_metrics(self) -> dict:
        return self.storage.metrics()
