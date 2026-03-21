#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.request import Request, urlopen

from core.settings import settings


def main():
    parser = argparse.ArgumentParser(description="Ingest logs via API")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--url", default="http://localhost:8000/ingest")
    parser.add_argument("--batch-size", type=int, default=settings.ingest_batch_size)
    args = parser.parse_args()

    lines = args.input.read_text(encoding="utf-8").splitlines()

    for i in range(0, len(lines), args.batch_size):
        batch = lines[i : i + args.batch_size]
        payload = {"lines": batch}
        data = json.dumps(payload).encode("utf-8")
        request = Request(args.url, data=data, headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=60) as response:
            body = json.loads(response.read().decode("utf-8"))
            print(
                f"Batch {i // args.batch_size + 1}: received={body['received']} anomalies={body['anomalies']}"
            )


if __name__ == "__main__":
    main()
