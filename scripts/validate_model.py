#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve

from core.models import LogEvent
from core.settings import settings
from detectors.registry import ModelRegistry
from services.parsers import LogParser


def main():
    ap = argparse.ArgumentParser(description="Validate model on labeled dataset")
    ap.add_argument(
        "--input",
        type=Path,
        default=Path("data/logs/validation.jsonl"),
        help="Path to labeled JSONL (each line has _label field)",
    )
    ap.add_argument(
        "--batch-size",
        type=int,
        default=5000,
        help="Batch size for scoring",
    )
    args = ap.parse_args()

    if not args.input.exists():
        raise SystemExit(f"ERROR: {args.input} not found")

    registry = ModelRegistry(settings.artifact_dir)
    detector, metadata = registry.load_latest()
    threshold = metadata.get("train_metrics", {}).get("threshold", 0.5)
    print(f"model: {metadata.get('model_type')} v{metadata.get('version')}, threshold={threshold:.4f}")

    print(f"reading {args.input}")
    parser = LogParser(
        source_format=settings.log_source_format,
        json_field_mapping=settings.log_field_mapping,
        plain_patterns=settings.log_plain_patterns,
    )
    labels: list[str] = []  # "clean" or "attack:category"
    events: list[LogEvent] = []
    skipped = 0

    with open(args.input, encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                label = raw.pop("_label", "clean")
                labels.append(label)
                clean_line = json.dumps(raw, ensure_ascii=False)
                event = parser.parse_json_line(clean_line)
                events.append(event)
            except Exception as e:
                skipped += 1
                if skipped <= 5:
                    print(f"WARN: line {line_no}: {e}")

    n_total = len(events)
    n_clean = sum(1 for lb in labels if lb == "clean")
    n_attack = n_total - n_clean
    print(f"Parsed: {n_total:,} ({n_clean:,} clean + {n_attack:,} attack), skipped: {skipped}")

    cat_counts = Counter()
    for lb in labels:
        if lb.startswith("attack:"):
            cat_counts[lb.split(":", 1)[1]] += 1
    print(f"Attack categories: {dict(cat_counts.most_common())}")

    print("Scoring...")
    t0 = time.time()
    all_scores = []
    for i in range(0, n_total, args.batch_size):
        batch = events[i : i + args.batch_size]
        scores = detector.score(batch)
        all_scores.extend(scores)
        if (i // args.batch_size) % 5 == 0:
            print(f"{i + len(batch):,}/{n_total:,}", end="\r", flush=True)
    print(f"Scoring done in {time.time() - t0:.1f}s")

    scores_arr = np.array(all_scores)
    labels_binary = np.array([0 if lb == "clean" else 1 for lb in labels])

    print("\n=== SCORE DISTRIBUTION ===")
    clean_scores = scores_arr[labels_binary == 0]
    attack_scores = scores_arr[labels_binary == 1]
    print(f"Clean  scores: mean={clean_scores.mean():.4f} std={clean_scores.std():.4f} "
          f"min={clean_scores.min():.4f} p50={np.median(clean_scores):.4f} "
          f"p95={np.quantile(clean_scores, 0.95):.4f} p99={np.quantile(clean_scores, 0.99):.4f} "
          f"max={clean_scores.max():.4f}")
    print(f"Attack scores: mean={attack_scores.mean():.4f} std={attack_scores.std():.4f} "
          f"min={attack_scores.min():.4f} p50={np.median(attack_scores):.4f} "
          f"p95={np.quantile(attack_scores, 0.95):.4f} p99={np.quantile(attack_scores, 0.99):.4f} "
          f"max={attack_scores.max():.4f}")

    print(f"\n=== METRICS AT TRAINING THRESHOLD ({threshold:.4f}) ===")
    preds_train = (scores_arr >= threshold).astype(int)
    _print_metrics(labels_binary, preds_train, labels, scores_arr, threshold)

    auc = roc_auc_score(labels_binary, scores_arr)
    print(f"\nROC AUC: {auc:.4f}")

    print("\n=== THRESHOLD SWEEP ===")
    best_f1 = 0.0
    best_thr = threshold
    thresholds = np.arange(0.0, 1.001, 0.01)
    results = []
    for thr in thresholds:
        preds = (scores_arr >= thr).astype(int)
        tp = int(np.sum((preds == 1) & (labels_binary == 1)))
        fp = int(np.sum((preds == 1) & (labels_binary == 0)))
        fn = int(np.sum((preds == 0) & (labels_binary == 1)))
        tn = int(np.sum((preds == 0) & (labels_binary == 0)))
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        results.append((thr, precision, recall, f1, fpr, tp, fp, fn, tn))
        if f1 > best_f1:
            best_f1 = f1
            best_thr = thr

    # Print table for interesting thresholds
    print(f"{'Threshold':>9} {'Precision':>9} {'Recall':>9} {'F1':>9} {'FPR':>9} {'TP':>6} {'FP':>6} {'FN':>6} {'TN':>6}")
    print(f"{'-'*9} {'-'*9} {'-'*9} {'-'*9} {'-'*9} {'-'*6} {'-'*6} {'-'*6} {'-'*6}")
    for thr, prec, rec, f1, fpr, tp, fp, fn, tn in results:
        if thr % 0.05 < 0.005 or abs(thr - best_thr) < 0.005 or abs(thr - threshold) < 0.005:
            marker = " <-- BEST F1" if abs(thr - best_thr) < 0.005 else ""
            marker = " <-- TRAIN" if abs(thr - threshold) < 0.005 and not marker else marker
            print(f"{thr:9.2f} {prec:9.4f} {rec:9.4f} {f1:9.4f} {fpr:9.4f} {tp:6d} {fp:6d} {fn:6d} {tn:6d}{marker}")

    fpr_arr, tpr_arr, roc_thresholds = roc_curve(labels_binary, scores_arr)
    j_scores = tpr_arr - fpr_arr
    j_best_idx = np.argmax(j_scores)
    j_threshold = roc_thresholds[j_best_idx]
    print(f"\nYouden's J optimal threshold: {j_threshold:.4f} "
          f"(TPR={tpr_arr[j_best_idx]:.4f}, FPR={fpr_arr[j_best_idx]:.4f}, J={j_scores[j_best_idx]:.4f})")

    print(f"\n=== METRICS AT BEST F1 THRESHOLD ({best_thr:.4f}) ===")
    preds_best = (scores_arr >= best_thr).astype(int)
    _print_metrics(labels_binary, preds_best, labels, scores_arr, best_thr)

    print(f"\n=== METRICS AT YOUDEN THRESHOLD ({j_threshold:.4f}) ===")
    preds_j = (scores_arr >= j_threshold).astype(int)
    _print_metrics(labels_binary, preds_j, labels, scores_arr, j_threshold)

    print("\n=== PER-CATEGORY RECALL ===")
    cat_detected: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "detected_best": 0, "detected_youden": 0})
    for i, lb in enumerate(labels):
        if lb.startswith("attack:"):
            cat = lb.split(":", 1)[1]
            cat_detected[cat]["total"] += 1
            if scores_arr[i] >= best_thr:
                cat_detected[cat]["detected_best"] += 1
            if scores_arr[i] >= j_threshold:
                cat_detected[cat]["detected_youden"] += 1

    print(f"{'Category':<20} {'Total':>6} {'Det@BestF1':>10} {'Recall%':>8} {'Det@Youden':>10} {'Recall%':>8}")
    print(f"{'-'*20} {'-'*6} {'-'*10} {'-'*8} {'-'*10} {'-'*8}")
    for cat in sorted(cat_detected.keys()):
        d = cat_detected[cat]
        r_best = d["detected_best"] / d["total"] * 100 if d["total"] > 0 else 0
        r_youden = d["detected_youden"] / d["total"] * 100 if d["total"] > 0 else 0
        print(f"{cat:<20} {d['total']:>6} {d['detected_best']:>10} {r_best:>7.1f}% {d['detected_youden']:>10} {r_youden:>7.1f}%")

    print("\n=== SUMMARY ===")
    print(f"Dataset: {n_total:,} entries ({n_clean:,} clean + {n_attack:,} attack)")
    print(f"ROC AUC: {auc:.4f}")
    print(f"Training threshold: {threshold:.4f}")
    print(f"Best F1 threshold:  {best_thr:.4f} (F1={best_f1:.4f})")
    print(f"Youden threshold:   {j_threshold:.4f}")


def _print_metrics(labels_binary, preds, labels_raw, scores_arr, threshold):
    tp = int(np.sum((preds == 1) & (labels_binary == 1)))
    fp = int(np.sum((preds == 1) & (labels_binary == 0)))
    fn = int(np.sum((preds == 0) & (labels_binary == 1)))
    tn = int(np.sum((preds == 0) & (labels_binary == 0)))
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    accuracy = (tp + tn) / (tp + fp + fn + tn)

    print(f"TP={tp:,}  FP={fp:,}  FN={fn:,}  TN={tn:,}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1:        {f1:.4f}")
    print(f"FPR:       {fpr:.4f}")
    print(f"Accuracy:  {accuracy:.4f}")


if __name__ == "__main__":
    main()
