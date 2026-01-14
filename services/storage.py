from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timezone

from core.models import AnomalyResult

_DEFAULT_MAX_ITEMS = 1000


class Storage:
    def __init__(self, max_items: int = _DEFAULT_MAX_ITEMS) -> None:
        self._lock = threading.Lock()
        self._anomalies: deque[dict] = deque(maxlen=max_items)
        self._total_events = 0
        self._total_anomalies = 0
        self._last_ingest: datetime | None = None

    def save_results(self, results: list[AnomalyResult]) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._total_events += len(results)
            for r in results:
                if r.is_anomaly:
                    self._total_anomalies += 1
                    self._anomalies.appendleft(_result_to_dict(r))
            self._last_ingest = now

    def get_anomalies(self, limit: int = 50, min_score: float | None = None) -> list[dict]:
        with self._lock:
            items = list(self._anomalies)
        if min_score is not None:
            items = [a for a in items if a["anomaly_score"] >= min_score]
        return items[:limit]

    def metrics(self) -> dict:
        with self._lock:
            total = self._total_events
            anomalies = self._total_anomalies
            last = self._last_ingest
        return {
            "total_events": total,
            "anomalies": anomalies,
            "anomaly_rate": anomalies / total if total else 0.0,
            "last_ingest": last.isoformat() if last else None,
        }


def _result_to_dict(result: AnomalyResult) -> dict:
    event = result.event
    mitre_data = None
    if result.mitre_techniques:
        mitre_data = [
            {
                "technique_id": t.technique_id,
                "name": t.name,
                "tactic": t.tactic,
                "confidence": t.confidence,
            }
            for t in result.mitre_techniques
        ]
    return {
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "level": event.level,
        "message": event.message,
        "host": event.host,
        "service": event.service,
        "remote_addr": event.remote_addr,
        "remote_user": event.remote_user,
        "method": event.method,
        "path": event.path,
        "protocol": event.protocol,
        "status": event.status,
        "bytes_sent": event.bytes_sent,
        "referrer": event.referrer,
        "user_agent": event.user_agent,
        "request_time": event.request_time,
        "request_length": event.request_length,
        "x_forwarded_for": event.x_forwarded_for,
        "attributes": event.attributes,
        "anomaly_score": result.score,
        "model_version": result.model_version,
        "mitre_techniques": mitre_data,
    }
