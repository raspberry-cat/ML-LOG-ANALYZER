from __future__ import annotations

import importlib
import json
from datetime import UTC, datetime

import pytest

from core.models import LogEvent


@pytest.fixture(autouse=True)
def _env_setup(tmp_path, monkeypatch):
    monkeypatch.setenv("ARTIFACT_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("MODEL_TYPE", "baseline")
    monkeypatch.setenv("AUTO_TRAIN_ON_STARTUP", "false")
    monkeypatch.setenv("AUTO_INGEST_LOG_FILES_ON_STARTUP", "false")
    monkeypatch.setenv("LOG_INPUT_PATHS", "")
    monkeypatch.setenv("LOG_LEVEL", "WARNING")


@pytest.fixture()
def trained_app(tmp_path):
    import core.settings as settings_mod

    importlib.reload(settings_mod)

    from detectors.registry import ModelRegistry
    from services.features import FeatureExtractor
    from services.training import train_model

    registry = ModelRegistry(str(tmp_path / "artifacts"))
    events = [
        LogEvent(
            timestamp=datetime(2026, 3, 10, 12, i, 0, tzinfo=UTC),
            method="GET",
            path="/index.html",
            status=200,
            bytes_sent=1024,
            user_agent="Mozilla/5.0",
            message="GET /index.html HTTP/1.1",
        )
        for i in range(30)
    ]
    train_model(events, "baseline", registry, FeatureExtractor())

    import api.main as api_mod

    importlib.reload(api_mod)
    from fastapi.testclient import TestClient

    from api.main import app

    with TestClient(app) as client:
        yield client


@pytest.fixture()
def trained_app_custom_mapping(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "LOG_FIELD_MAPPING",
        json.dumps(
            {
                "timestamp": ["ts"],
                "remote_addr": ["clientIp"],
                "path": ["requestPath"],
                "status": ["statusCode"],
                "bytes_sent": ["bytes"],
                "request_time": ["latency"],
            }
        ),
    )
    import core.settings as settings_mod

    importlib.reload(settings_mod)

    from detectors.registry import ModelRegistry
    from services.features import FeatureExtractor
    from services.training import train_model

    registry = ModelRegistry(str(tmp_path / "artifacts"))
    events = [
        LogEvent(
            timestamp=datetime(2026, 3, 10, 12, i, 0, tzinfo=UTC),
            method="GET",
            path="/index.html",
            status=200,
            bytes_sent=1024,
            user_agent="Mozilla/5.0",
            message="GET /index.html HTTP/1.1",
        )
        for i in range(30)
    ]
    train_model(events, "baseline", registry, FeatureExtractor())

    import api.main as api_mod

    importlib.reload(api_mod)
    from fastapi.testclient import TestClient

    from api.main import app

    with TestClient(app) as client:
        yield client


@pytest.fixture()
def trained_app_with_startup_file_ingest(tmp_path, monkeypatch):
    input_path = tmp_path / "startup_ingest.jsonl"
    input_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-03-10T14:00:00+00:00",
                        "remote_addr": "10.0.0.1",
                        "method": "GET",
                        "path": "/index.html",
                        "status": 200,
                        "bytes_sent": 512,
                        "user_agent": "Mozilla/5.0",
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-03-10T14:00:01+00:00",
                        "remote_addr": "10.0.0.99",
                        "method": "GET",
                        "path": "/../../etc/passwd",
                        "status": 404,
                        "bytes_sent": 0,
                        "user_agent": "sqlmap/1.6",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("AUTO_INGEST_LOG_FILES_ON_STARTUP", "true")
    monkeypatch.setenv("LOG_INPUT_PATHS", str(input_path))

    import core.settings as settings_mod

    importlib.reload(settings_mod)

    from detectors.registry import ModelRegistry
    from services.features import FeatureExtractor
    from services.training import train_model

    registry = ModelRegistry(str(tmp_path / "artifacts"))
    events = [
        LogEvent(
            timestamp=datetime(2026, 3, 10, 12, i, 0, tzinfo=UTC),
            method="GET",
            path="/index.html",
            status=200,
            bytes_sent=1024,
            user_agent="Mozilla/5.0",
            message="GET /index.html HTTP/1.1",
        )
        for i in range(30)
    ]
    train_model(events, "baseline", registry, FeatureExtractor())

    import api.main as api_mod

    importlib.reload(api_mod)
    from fastapi.testclient import TestClient

    from api.main import app

    with TestClient(app) as client:
        yield client


class TestHealthEndpoint:
    def test_health_returns_200(self, trained_app):
        response = trained_app.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    def test_health_shows_model_loaded(self, trained_app):
        response = trained_app.get("/health")
        data = response.json()
        assert data["model_loaded"] is True

    def test_health_exposes_configured_log_format(self, trained_app):
        response = trained_app.get("/health")
        data = response.json()
        assert data["log_source_format"] == "jsonl"

    def test_health_exposes_file_ingest_config(self, trained_app):
        response = trained_app.get("/health")
        data = response.json()
        assert "auto_ingest_log_files_on_startup" in data
        assert "configured_log_input_paths" in data


class TestIngestEndpoint:
    def test_ingest_jsonl(self, trained_app):
        log_line = json.dumps(
            {
                "timestamp": "2026-03-10T14:00:00+00:00",
                "remote_addr": "10.0.0.1",
                "method": "GET",
                "path": "/index.html",
                "status": 200,
                "bytes_sent": 512,
                "user_agent": "Mozilla/5.0",
            }
        )
        response = trained_app.post("/ingest", json={"lines": [log_line]})
        assert response.status_code == 200
        data = response.json()
        assert data["received"] == 1

    def test_ingest_counts_anomalies(self, trained_app):
        attack_line = json.dumps(
            {
                "timestamp": "2026-03-10T14:00:00+00:00",
                "remote_addr": "10.0.0.99",
                "method": "GET",
                "path": "/../../etc/passwd",
                "status": 404,
                "bytes_sent": 0,
                "user_agent": "sqlmap/1.6",
            }
        )
        response = trained_app.post("/ingest", json={"lines": [attack_line]})
        assert response.status_code == 200
        data = response.json()
        assert data["received"] == 1
        assert data["anomalies"] >= 0

    def test_ingest_ignores_legacy_format_field(self, trained_app):
        log_line = json.dumps(
            {
                "timestamp": "2026-03-10T14:00:00+00:00",
                "remote_addr": "10.0.0.1",
                "method": "GET",
                "path": "/index.html",
                "status": 200,
            }
        )
        response = trained_app.post("/ingest", json={"format": "xml", "lines": [log_line]})
        assert response.status_code == 200

    def test_ingest_uses_env_field_mapping(self, trained_app_custom_mapping):
        log_line = json.dumps(
            {
                "ts": "2026-03-10T14:00:00+00:00",
                "clientIp": "10.0.0.55",
                "method": "GET",
                "requestPath": "/mapped",
                "statusCode": 200,
                "bytes": 256,
                "latency": 0.02,
            }
        )
        response = trained_app_custom_mapping.post("/ingest", json={"lines": [log_line]})
        assert response.status_code == 200
        assert response.json()["received"] == 1


class TestAnomaliesEndpoint:
    def test_anomalies_returns_list(self, trained_app):
        response = trained_app.get("/anomalies")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    def test_anomalies_limit_param(self, trained_app):
        response = trained_app.get("/anomalies?limit=5")
        assert response.status_code == 200


class TestPrometheusMetrics:
    def test_metrics_returns_prometheus_format(self, trained_app):
        response = trained_app.get("/metrics")
        assert response.status_code == 200
        assert "log_events_total" in response.text
        assert "log_anomalies_total" in response.text

    def test_metrics_contains_all_counters(self, trained_app):
        log_line = json.dumps(
            {
                "timestamp": "2026-03-10T14:00:00+00:00",
                "remote_addr": "10.0.0.1",
                "method": "GET",
                "path": "/index.html",
                "status": 200,
                "bytes_sent": 512,
                "user_agent": "Mozilla/5.0",
            }
        )
        trained_app.post("/ingest", json={"lines": [log_line]})
        response = trained_app.get("/metrics")
        body = response.text
        assert "log_anomaly_score_bucket" in body
        assert "log_http_status_total" in body
        assert "log_ingest_duration_seconds" in body


class TestJsonMetrics:
    def test_json_metrics_returns_expected_keys(self, trained_app):
        response = trained_app.get("/metrics/json")
        assert response.status_code == 200
        data = response.json()
        assert "total_events" in data
        assert "anomalies" in data
        assert "anomaly_rate" in data

    def test_startup_file_ingest_updates_metrics(self, trained_app_with_startup_file_ingest):
        response = trained_app_with_startup_file_ingest.get("/metrics/json")
        assert response.status_code == 200
        data = response.json()
        assert data["total_events"] == 2
        assert data["anomalies"] >= 1


class TestSettingsParsing:
    def test_log_input_paths_accepts_comma_separated_string(self, monkeypatch):
        monkeypatch.setenv("LOG_INPUT_PATHS", "./one.log, ./two.log\n./three.log")

        import core.settings as settings_mod

        importlib.reload(settings_mod)

        assert settings_mod.settings.log_input_paths == [
            "./one.log",
            "./two.log",
            "./three.log",
        ]
