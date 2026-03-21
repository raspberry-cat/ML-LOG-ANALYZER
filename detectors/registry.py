from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from detectors.base import IAnomalyDetector
from detectors.baseline import FrequencyBaselineDetector
from detectors.isolation_forest import IsolationForestDetector
from services.features import FeatureExtractor


class ModelRegistry:
    def __init__(self, artifact_dir: str) -> None:
        self.base_path = Path(artifact_dir)
        self.base_path.mkdir(parents=True, exist_ok=True)

    def save(
        self,
        detector: IAnomalyDetector,
        model_type: str,
        feature_extractor: FeatureExtractor,
        train_metrics: dict[str, float] | None = None,
    ) -> dict[str, object]:
        version = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
        model_dir = self.base_path / f"{model_type}_{version}"
        detector.save(str(model_dir))

        metadata = {
            "model_type": model_type,
            "version": version,
            "trained_at": datetime.now(UTC).isoformat(),
            "feature_names": feature_extractor.feature_names,
            "train_metrics": train_metrics or {},
            "path": str(model_dir),
        }
        self._write_json(model_dir / "metadata.json", metadata)
        self._write_json(self.base_path / "latest.json", metadata)
        return metadata

    def load_latest(self) -> tuple[IAnomalyDetector, dict[str, object]]:
        latest_path = self.base_path / "latest.json"
        if not latest_path.exists():
            raise FileNotFoundError("No model artifacts found. Train a model first.")

        metadata = self._read_json(latest_path)
        model_type = str(metadata.get("model_type", "")).lower()
        model_path = metadata.get("path")
        if not model_type or not model_path:
            raise ValueError("Invalid model metadata")
        return _load_detector(model_type, str(model_path)), metadata

    @staticmethod
    def _read_json(path: Path) -> dict[str, object]:
        with path.open(encoding="utf-8") as file:
            return json.load(file)

    @staticmethod
    def _write_json(path: Path, payload: dict[str, object]) -> None:
        with path.open("w", encoding="utf-8") as file:
            json.dump(payload, file, ensure_ascii=True, indent=2)


def _load_detector(model_type: str, path: str) -> IAnomalyDetector:
    if model_type == "baseline":
        return FrequencyBaselineDetector.load(path)
    if model_type in {"isolation_forest", "iforest"}:
        return IsolationForestDetector.load(path)
    raise ValueError(f"Unsupported model type: {model_type}")
