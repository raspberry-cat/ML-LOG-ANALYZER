from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from pydantic import BaseModel, ConfigDict, Field

from core.logging import configure_logging
from core.settings import settings
from detectors.registry import ModelRegistry
from services.anomaly_service import AnomalyService
from services.features import FeatureExtractor
from services.ingestion import LogIngestor
from services.parsers import LogParser
from services.storage import Storage
from services.training import train_model

logger = logging.getLogger(__name__)

_PROM_REGISTRY = CollectorRegistry()
_ENV_LABEL = settings.environment

_METRIC_TOTAL = Counter(
    "log_events_total",
    "Total ingested log events",
    ["environment"],
    registry=_PROM_REGISTRY,
)
_METRIC_ANOMALIES = Counter(
    "log_anomalies_total",
    "Detected anomalous log events",
    ["environment"],
    registry=_PROM_REGISTRY,
)
_METRIC_RATE = Gauge(
    "log_anomaly_rate",
    "Anomaly rate for the latest ingest batch",
    ["environment"],
    registry=_PROM_REGISTRY,
)
_LAST_INGEST_TS = Gauge(
    "log_last_ingest_timestamp",
    "Unix timestamp of last ingest",
    ["environment"],
    registry=_PROM_REGISTRY,
)
_SCORE_HISTOGRAM = Histogram(
    "log_anomaly_score",
    "Distribution of anomaly scores",
    ["environment"],
    buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0),
    registry=_PROM_REGISTRY,
)
_HTTP_STATUS = Counter(
    "log_http_status_total",
    "HTTP status class of ingested events",
    ["environment", "status_class"],
    registry=_PROM_REGISTRY,
)
_MITRE_TECHNIQUES = Counter(
    "log_mitre_technique_total",
    "MITRE ATT&CK technique detections",
    ["environment", "technique_id", "tactic"],
    registry=_PROM_REGISTRY,
)
_INGEST_DURATION = Histogram(
    "log_ingest_duration_seconds",
    "Time spent processing an ingest request",
    ["environment"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    registry=_PROM_REGISTRY,
)


def _status_class(code: int | None) -> str:
    if code is None:
        return "unknown"
    if code < 200:
        return "1xx"
    if code < 300:
        return "2xx"
    if code < 400:
        return "3xx"
    if code < 500:
        return "4xx"
    return "5xx"


def _build_parser() -> LogParser:
    return LogParser(
        source_format=settings.log_source_format,
        json_field_mapping=settings.log_field_mapping,
        plain_patterns=settings.log_plain_patterns,
    )


def _build_service(storage: Storage, registry: ModelRegistry) -> AnomalyService:
    return AnomalyService(
        settings=settings,
        parser=_build_parser(),
        registry=registry,
        storage=storage,
    )


def _record_ingest_metrics(results, elapsed: float) -> None:
    total = len(results)
    anomalies = sum(1 for result in results if result.is_anomaly)

    _METRIC_TOTAL.labels(_ENV_LABEL).inc(total)
    _METRIC_ANOMALIES.labels(_ENV_LABEL).inc(anomalies)
    _METRIC_RATE.labels(_ENV_LABEL).set(float(anomalies) / float(total) if total else 0.0)
    _INGEST_DURATION.labels(_ENV_LABEL).observe(elapsed)
    if total:
        _LAST_INGEST_TS.labels(_ENV_LABEL).set(time.time())

    for result in results:
        _SCORE_HISTOGRAM.labels(_ENV_LABEL).observe(result.score)
        _HTTP_STATUS.labels(_ENV_LABEL, _status_class(result.event.status)).inc()
        for technique in result.mitre_techniques:
            _MITRE_TECHNIQUES.labels(
                _ENV_LABEL,
                technique.technique_id,
                technique.tactic,
            ).inc()


def _bootstrap_model(registry: ModelRegistry) -> bool:
    if not settings.auto_train_on_startup:
        return False

    bootstrap_path = Path(settings.bootstrap_log_path).expanduser()
    if not bootstrap_path.exists():
        logger.warning("bootstrap_path_missing", extra={"path": str(bootstrap_path)})
        return False

    lines = bootstrap_path.read_text(encoding="utf-8").splitlines()
    parser = _build_parser()
    events, skipped = parser.parse_lines_safe(lines)
    if skipped:
        logger.warning(
            "bootstrap_lines_skipped",
            extra={"path": str(bootstrap_path), "skipped_lines": skipped},
        )
    if not events:
        logger.warning("bootstrap_events_empty", extra={"path": str(bootstrap_path)})
        return False

    registry.base_path.mkdir(parents=True, exist_ok=True)
    train_model(events, settings.model_type, registry, FeatureExtractor())
    logger.info(
        "model_bootstrapped",
        extra={"path": str(bootstrap_path), "training_samples": len(events)},
    )
    return True


def _auto_ingest_files(service: AnomalyService) -> None:
    if not settings.auto_ingest_log_files_on_startup:
        return
    if not settings.log_input_paths:
        logger.info("startup_file_ingest_skipped", extra={"reason": "no_paths_configured"})
        return

    ingestor = LogIngestor(service.parser)
    input_paths = [Path(raw_path).expanduser() for raw_path in settings.log_input_paths]

    total_received = 0
    total_anomalies = 0
    total_skipped = 0
    processed_files = 0

    for path in input_paths:
        if not path.exists():
            logger.warning("startup_log_path_missing", extra={"path": str(path)})
            continue
        if not path.is_file():
            logger.warning("startup_log_path_not_file", extra={"path": str(path)})
            continue

        processed_files += 1
        file_received = 0
        file_anomalies = 0
        file_skipped = 0

        for batch in ingestor.iter_parsed_batches([path], settings.ingest_batch_size):
            started_at = time.monotonic()
            results = service.ingest_events(batch.events)
            elapsed = time.monotonic() - started_at

            _record_ingest_metrics(results, elapsed)

            batch_anomalies = sum(1 for result in results if result.is_anomaly)
            file_received += len(results)
            file_anomalies += batch_anomalies
            file_skipped += batch.skipped_lines

        total_received += file_received
        total_anomalies += file_anomalies
        total_skipped += file_skipped

        logger.info(
            "startup_log_file_ingested",
            extra={
                "path": str(path),
                "received": file_received,
                "anomalies": file_anomalies,
                "skipped_lines": file_skipped,
            },
        )

    logger.info(
        "startup_file_ingest_complete",
        extra={
            "files": processed_files,
            "received": total_received,
            "anomalies": total_anomalies,
            "skipped_lines": total_skipped,
        },
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging(settings.log_level)
    storage = Storage(max_items=settings.max_stored_anomalies)
    registry = ModelRegistry(settings.artifact_dir)

    app.state.service = None
    app.state.model_loaded = False

    try:
        app.state.service = _build_service(storage, registry)
        app.state.model_loaded = True
    except FileNotFoundError:
        if _bootstrap_model(registry):
            app.state.service = _build_service(storage, registry)
            app.state.model_loaded = True
        else:
            logger.warning("model_not_loaded")

    if app.state.model_loaded and app.state.service is not None:
        _auto_ingest_files(app.state.service)

    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.state.service = None
app.state.model_loaded = False


class IngestRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    lines: list[str] = Field(default_factory=list)


class IngestResponse(BaseModel):
    received: int
    anomalies: int
    model_version: str


def _require_service() -> AnomalyService:
    service: AnomalyService | None = app.state.service
    if service is None:
        raise HTTPException(status_code=503, detail="Model not loaded. Train a model first.")
    return service


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "model_loaded": bool(app.state.model_loaded),
        "environment": settings.environment,
        "log_source_format": settings.log_source_format,
        "auto_ingest_log_files_on_startup": settings.auto_ingest_log_files_on_startup,
        "configured_log_input_paths": len(settings.log_input_paths),
    }


@app.post("/ingest", response_model=IngestResponse)
def ingest(request: IngestRequest) -> IngestResponse:
    service = _require_service()
    started_at = time.monotonic()
    try:
        results = service.ingest(request.lines)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    _record_ingest_metrics(results, time.monotonic() - started_at)
    anomalies = sum(1 for result in results if result.is_anomaly)

    return IngestResponse(
        received=len(results),
        anomalies=anomalies,
        model_version=service.model_version,
    )


@app.get("/anomalies")
def anomalies(
    limit: int = Query(default=50, ge=1, le=500),
    min_score: float | None = Query(default=None, ge=0.0, le=1.0),
) -> dict:
    service = _require_service()
    return {"items": service.get_anomalies(limit=limit, min_score=min_score)}


@app.get("/metrics")
def prometheus_metrics() -> Response:
    payload = generate_latest(_PROM_REGISTRY)
    return Response(content=payload, media_type=CONTENT_TYPE_LATEST)


@app.get("/metrics/json")
def json_metrics() -> dict:
    service = _require_service()
    return service.get_metrics()
