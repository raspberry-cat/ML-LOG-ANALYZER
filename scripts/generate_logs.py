#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from services.synthetic import generate_events, to_json_lines, to_plain_lines


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic nginx access logs")
    parser.add_argument("--total", type=int, default=500)
    parser.add_argument("--anomaly-ratio", type=float, default=0.05)
    parser.add_argument("--out-json", type=Path, default=Path("data/logs/with_anomalies.jsonl"))
    parser.add_argument("--out-plain", type=Path, default=Path("data/logs/with_anomalies.log"))
    parser.add_argument("--out-normal", type=Path, default=Path("data/logs/normal.jsonl"))
    args = parser.parse_args()

    events = generate_events(total=args.total, anomaly_ratio=args.anomaly_ratio)
    json_lines = to_json_lines(events)
    plain_lines = to_plain_lines(events)

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text("\n".join(json_lines) + "\n", encoding="utf-8")
    args.out_plain.write_text("\n".join(plain_lines) + "\n", encoding="utf-8")

    normal_events = generate_events(total=args.total, anomaly_ratio=0.0)
    normal_lines = to_json_lines(normal_events)
    args.out_normal.write_text("\n".join(normal_lines) + "\n", encoding="utf-8")

    print(f"Wrote {len(events)} mixed logs to {args.out_json}")
    print(f"Wrote {len(normal_events)} normal logs to {args.out_normal}")


if __name__ == "__main__":
    main()
