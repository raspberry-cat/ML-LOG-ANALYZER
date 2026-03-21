#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from core.models import LogEvent
from core.settings import settings
from detectors.isolation_forest import IsolationForestDetector
from detectors.registry import ModelRegistry
from services.features import FeatureExtractor
from services.parsers import LogParser

BATCH_SIZE = 50_000


def count_lines(path: Path) -> int:
    n = 0
    with open(path, "rb") as f:
        buf = f.raw.read(1024 * 1024)
        while buf:
            n += buf.count(b"\n")
            buf = f.raw.read(1024 * 1024)
    return n


def stream_features(
    path: Path,
    fmt: str,
    parser: LogParser,
    extractor: FeatureExtractor,
    total_lines: int,
) -> np.ndarray:
    n_features = len(extractor.feature_names)
    matrix = np.empty((total_lines, n_features), dtype=np.float32)

    row = 0
    batch_lines: list[str] = []
    skipped = 0
    t0 = time.time()

    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            batch_lines.append(line)

            if len(batch_lines) >= BATCH_SIZE:
                parsed, bad = _parse_batch(batch_lines, fmt, parser)
                skipped += bad
                if parsed:
                    features = extractor.transform(parsed)
                    n = features.shape[0]
                    matrix[row : row + n] = features.astype(np.float32)
                    row += n
                batch_lines = []

                elapsed = time.time() - t0
                rate = row / elapsed if elapsed > 0 else 0
                print(
                    f"\r{row:,}/{total_lines:,} rows "
                    f"({row * 100 / total_lines:.1f}%) "
                    f"{rate:,.0f} rows/s, skipped {skipped:,}",
                    end="",
                    flush=True,
                )

    if batch_lines:
        parsed, bad = _parse_batch(batch_lines, fmt, parser)
        skipped += bad
        if parsed:
            features = extractor.transform(parsed)
            n = features.shape[0]
            matrix[row : row + n] = features.astype(np.float32)
            row += n

    print(f"\nDone: {row:,} rows, {skipped:,} skipped")
    return matrix[:row]


def _parse_batch(lines: list[str], fmt: str, parser: LogParser) -> tuple[list[LogEvent], int]:
    events: list[LogEvent] = []
    bad = 0
    for line in lines:
        try:
            if fmt == "jsonl":
                events.append(parser.parse_json_line(line))
            else:
                events.append(parser.parse_plain_text(line))
        except Exception:
            bad += 1
    return events, bad


def main():
    ap = argparse.ArgumentParser(description="Train on large log files (streaming)")
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument(
        "--format",
        choices=["jsonl", "plain"],
        default=settings.log_source_format,
        help="Overrides LOG_SOURCE_FORMAT from .env",
    )
    ap.add_argument("--contamination", type=float, default=0.05)
    ap.add_argument("--n-estimators", type=int, default=200)
    args = ap.parse_args()

    print(f"Counting lines in {args.input}")
    total = count_lines(args.input)
    print(f"{total:,} lines")

    print("Extracting features (streaming)")
    parser = LogParser(
        source_format=args.format,
        json_field_mapping=settings.log_field_mapping,
        plain_patterns=settings.log_plain_patterns,
    )
    extractor = FeatureExtractor()
    matrix = stream_features(args.input, args.format, parser, extractor, total)
    print(f"Matrix shape: {matrix.shape}, dtype: {matrix.dtype}")
    print(f"Memory: {matrix.nbytes / 1024**3:.2f} GB")

    print("Fitting StandardScaler")
    scaler = StandardScaler()
    scaled = scaler.fit_transform(matrix)

    print(
        f"Training IsolationForest ({args.n_estimators} trees, contamination={args.contamination})"
    )
    t0 = time.time()
    model = IsolationForest(
        contamination=args.contamination,
        random_state=42,
        n_estimators=args.n_estimators,
        n_jobs=-1,
    )
    model.fit(scaled)
    print(f"Fit done in {time.time() - t0:.1f}s")

    print("Computing scores")
    t0 = time.time()
    raw_scores = -model.decision_function(scaled)
    score_min = float(np.min(raw_scores))
    score_max = float(np.max(raw_scores))
    scores = (raw_scores - score_min) / (score_max - score_min)
    scores = np.clip(scores, 0.0, 1.0)
    print(f"Done in {time.time() - t0:.1f}s")

    quantile = 1.0 - args.contamination
    threshold = float(np.quantile(scores, quantile))

    train_metrics = {
        "score_mean": float(np.mean(scores)),
        "score_std": float(np.std(scores)),
        "score_p90": float(np.quantile(scores, 0.90)),
        "score_p95": float(np.quantile(scores, 0.95)),
        "score_p99": float(np.quantile(scores, 0.99)),
        "threshold": threshold,
        "threshold_quantile": quantile,
        "training_samples": matrix.shape[0],
    }

    detector = IsolationForestDetector(
        feature_extractor=extractor,
        contamination=args.contamination,
        random_state=42,
        n_estimators=args.n_estimators,
    )
    detector.scaler = scaler
    detector.model = model
    detector.score_min = score_min
    detector.score_max = score_max

    registry = ModelRegistry(settings.artifact_dir)
    metadata = registry.save(
        detector,
        model_type="isolation_forest",
        feature_extractor=extractor,
        train_metrics=train_metrics,
    )

    print()
    print(f"Model: isolation_forest v{metadata['version']}")
    print(f"Path: {metadata['path']}")
    print(f"Samples: {train_metrics['training_samples']:,}")
    print(f"Threshold: {threshold:.4f}")
    print(f"Score mean: {train_metrics['score_mean']:.4f} std: {train_metrics['score_std']:.4f}")
    print(
        f"Score p90: {train_metrics['score_p90']:.4f} p95: {train_metrics['score_p95']:.4f} p99: {train_metrics['score_p99']:.4f}"
    )

    anomaly_count = int(np.sum(scores >= threshold))
    print(f"Anomalies: {anomaly_count:,} ({anomaly_count * 100 / matrix.shape[0]:.2f}%)")


if __name__ == "__main__":
    main()
