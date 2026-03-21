from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from core.models import LogEvent
from detectors.baseline import FrequencyBaselineDetector
from detectors.isolation_forest import IsolationForestDetector
from detectors.registry import ModelRegistry
from services.features import FeatureExtractor
from services.mitre import classify
from services.parsers import LogParser
from services.storage import Storage
from services.training import train_model


def _generate_normal_events(count: int = 100) -> list[LogEvent]:
    events = []
    paths = ["/api/v1/health", "/api/v1/users", "/api/v1/auth/login", "/static/app.js", "/"]
    statuses = [200, 200, 200, 200, 301]
    for i in range(count):
        events.append(
            LogEvent(
                timestamp=datetime(2026, 3, 10, 10 + (i % 8), i % 60, 0, tzinfo=UTC),
                host="api.example.com",
                remote_addr=f"192.168.1.{i % 50 + 10}",
                method="GET" if i % 3 != 0 else "POST",
                path=paths[i % len(paths)],
                protocol="HTTP/1.1",
                status=statuses[i % len(statuses)],
                bytes_sent=512 + i * 10,
                user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                request_time=0.01 + (i % 20) * 0.005,
                request_length=128 + i,
                message=f"GET {paths[i % len(paths)]} HTTP/1.1",
            )
        )
    return events


def _generate_attack_events() -> list[LogEvent]:
    base = datetime(2026, 3, 10, 3, 0, 0, tzinfo=UTC)
    return [
        LogEvent(
            timestamp=base,
            remote_addr="45.33.32.156",
            method="GET",
            path="/../../etc/passwd",
            status=404,
            user_agent="Mozilla/5.0",
            message="GET /../../etc/passwd HTTP/1.1",
        ),
        LogEvent(
            timestamp=base,
            remote_addr="45.33.32.156",
            method="GET",
            path="/search?q='+UNION+SELECT+*+FROM+users--",
            status=200,
            user_agent="sqlmap/1.6.12",
            message="GET /search?q=' UNION SELECT * FROM users-- HTTP/1.1",
        ),
        LogEvent(
            timestamp=base,
            remote_addr="45.33.32.156",
            method="GET",
            path="/page?x=<script>document.cookie</script>",
            status=200,
            user_agent="Mozilla/5.0",
            message="GET /page?x=<script>document.cookie</script> HTTP/1.1",
        ),
        LogEvent(
            timestamp=base,
            remote_addr="45.33.32.156",
            method="POST",
            path="/api?cmd=;cat+/etc/shadow",
            status=500,
            user_agent="curl/7.88.0",
            message="POST /api?cmd=;cat /etc/shadow HTTP/1.1",
        ),
        LogEvent(
            timestamp=base,
            remote_addr="45.33.32.156",
            method="GET",
            path="/.env",
            status=200,
            user_agent="Nikto/2.1.6",
            message="GET /.env HTTP/1.1",
        ),
    ]


class TestEndToEndBaseline:
    def test_train_score_predict_pipeline(self, tmp_path):
        registry = ModelRegistry(str(tmp_path / "artifacts"))
        extractor = FeatureExtractor()
        normal = _generate_normal_events(100)
        metadata = train_model(normal, "baseline", registry, extractor)

        assert "train_metrics" in metadata
        assert metadata["model_type"] == "baseline"

        detector, loaded_meta = registry.load_latest()
        assert isinstance(detector, FrequencyBaselineDetector)

        threshold = loaded_meta["train_metrics"]["threshold"]
        attacks = _generate_attack_events()
        results = detector.predict(attacks, threshold)
        anomaly_count = sum(1 for r in results if r.is_anomaly)
        assert anomaly_count >= 3

    def test_storage_round_trip(self):
        storage = Storage()

        detector = FrequencyBaselineDetector()
        normal = _generate_normal_events(50)
        detector.train(normal)
        results = detector.predict(normal[:5] + _generate_attack_events(), threshold=0.5)

        for r in results:
            if r.is_anomaly:
                r.mitre_techniques = classify(r.event)

        storage.save_results(results)
        anomalies = storage.get_anomalies(limit=10)
        assert len(anomalies) > 0

        for a in anomalies:
            assert a["anomaly_score"] >= 0.5

        metrics = storage.metrics()
        assert metrics["total_events"] == 10
        assert metrics["anomalies"] > 0


class TestEndToEndIsolationForest:
    def test_train_and_detect(self, tmp_path):
        registry = ModelRegistry(str(tmp_path / "artifacts"))
        extractor = FeatureExtractor()
        normal = _generate_normal_events(200)
        metadata = train_model(normal, "isolation_forest", registry, extractor)

        assert metadata["model_type"] in {"isolation_forest", "iforest"}
        metrics = metadata["train_metrics"]
        assert metrics["training_samples"] == 200
        assert 0.0 <= metrics["threshold"] <= 1.0

        detector, loaded_meta = registry.load_latest()
        assert isinstance(detector, IsolationForestDetector)

        threshold = loaded_meta["train_metrics"]["threshold"]
        attacks = _generate_attack_events()
        results = detector.predict(attacks, threshold)

        scores = [r.score for r in results]
        assert max(scores) > 0.0


class TestMitreIntegration:
    def test_classify_enriches_anomaly_results(self):
        attacks = _generate_attack_events()
        for event in attacks:
            techniques = classify(event)
            if event.path and "../" in event.path:
                ids = [t.technique_id for t in techniques]
                assert "T1190" in ids

    def test_normal_traffic_minimal_techniques(self):
        normal = _generate_normal_events(20)
        for event in normal:
            techniques = classify(event)
            high_confidence = [t for t in techniques if t.confidence >= 0.7]
            assert len(high_confidence) == 0


class TestParserToModelPipeline:
    def test_json_parse_to_feature_extraction(self):
        parser = LogParser()
        lines = [
            json.dumps(
                {
                    "time": "2026-03-10T12:00:00Z",
                    "remoteAddress": "10.0.0.1",
                    "host": "api.example.com",
                    "method": "GET",
                    "url": "/api/v1/data",
                    "protocol": "HTTP/1.1",
                    "statusCode": 200,
                    "userAgent": "Mozilla/5.0",
                    "referer": "-",
                    "xForwardedFor": "-",
                    "requestLength": 128,
                    "responseLength": 256,
                    "responseTime": 0.05,
                }
            ),
            json.dumps(
                {
                    "time": "2026-03-10T12:01:00Z",
                    "remoteAddress": "10.0.0.2",
                    "host": "api.example.com",
                    "method": "POST",
                    "url": "/api/v1/auth",
                    "protocol": "HTTP/1.1",
                    "statusCode": 401,
                    "userAgent": "Mozilla/5.0",
                    "referer": "-",
                    "xForwardedFor": "-",
                    "requestLength": 256,
                    "responseLength": 64,
                    "responseTime": 0.1,
                }
            ),
        ]
        events = parser.parse_lines(lines, "jsonl")
        assert len(events) == 2

        extractor = FeatureExtractor()
        features = extractor.transform(events)
        assert features.shape == (2, 26)

    def test_plain_parse_to_feature_extraction(self):
        parser = LogParser()
        lines = [
            "10.0.0.1 - - [10/Mar/2026:12:00:00 +0000] "
            '"GET /api/v1/data HTTP/1.1" 200 256 "-" "Mozilla/5.0" 0.050',
        ]
        events = parser.parse_lines(lines, "plain")
        assert len(events) == 1

        extractor = FeatureExtractor()
        features = extractor.transform(events)
        assert features.shape == (1, 26)


class TestModelPersistence:
    def test_baseline_save_load_consistency(self, tmp_path):
        detector = FrequencyBaselineDetector()
        events = _generate_normal_events(50)
        detector.train(events)

        path = str(tmp_path / "model")
        detector.save(path)
        loaded = FrequencyBaselineDetector.load(path)

        original = detector.score(events)
        restored = loaded.score(events)
        for o, r in zip(original, restored, strict=True):
            assert o == pytest.approx(r)

    def test_iforest_save_load_consistency(self, tmp_path):
        extractor = FeatureExtractor()
        detector = IsolationForestDetector(feature_extractor=extractor, n_estimators=50)
        events = _generate_normal_events(100)
        detector.train(events)

        path = str(tmp_path / "model")
        detector.save(path)
        loaded = IsolationForestDetector.load(path)

        original = detector.score(events)
        restored = loaded.score(events)
        for o, r in zip(original, restored, strict=True):
            assert o == pytest.approx(r, abs=1e-6)

    def test_registry_save_load_latest(self, tmp_path):
        registry = ModelRegistry(str(tmp_path / "artifacts"))
        extractor = FeatureExtractor()
        events = _generate_normal_events(50)
        metadata = train_model(events, "baseline", registry, extractor)

        assert "version" in metadata
        assert "path" in metadata

        detector, loaded_meta = registry.load_latest()
        assert loaded_meta["model_type"] == "baseline"
        assert "train_metrics" in loaded_meta
