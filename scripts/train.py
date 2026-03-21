#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from core.settings import settings
from detectors.registry import ModelRegistry
from services.features import FeatureExtractor
from services.parsers import LogParser
from services.training import train_model


def main():
    parser = argparse.ArgumentParser(description="Train anomaly detection model")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument(
        "--format",
        choices=["jsonl", "plain"],
        default=settings.log_source_format,
        help="Overrides LOG_SOURCE_FORMAT from .env",
    )
    parser.add_argument("--model", default=settings.model_type)
    args = parser.parse_args()

    lines = args.input.read_text(encoding="utf-8").splitlines()
    log_parser = LogParser(
        source_format=args.format,
        json_field_mapping=settings.log_field_mapping,
        plain_patterns=settings.log_plain_patterns,
    )
    events = log_parser.parse_lines(lines)

    registry = ModelRegistry(settings.artifact_dir)
    extractor = FeatureExtractor()
    metadata = train_model(events, args.model, registry, extractor)

    metrics = metadata.get("train_metrics", {})
    print(f"Model: {metadata['model_type']} v{metadata['version']}")
    print(f"Path: {metadata['path']}")
    print(f"Samples: {metrics.get('training_samples', 'N/A')}")
    print(f"Threshold: {metrics.get('threshold', 'N/A'):.4f}")
    print(f"Score mean: {metrics.get('score_mean', 0):.4f} std: {metrics.get('score_std', 0):.4f}")
    print(f"Score p95: {metrics.get('score_p95', 0):.4f} p99: {metrics.get('score_p99', 0):.4f}")


if __name__ == "__main__":
    main()
