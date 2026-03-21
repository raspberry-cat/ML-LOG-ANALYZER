from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.models import LogEvent
from detectors.baseline import FrequencyBaselineDetector
from detectors.isolation_forest import IsolationForestDetector
from services.features import FeatureExtractor


def _make_events(count: int, path: str = "/index.html", status: int = 200) -> list[LogEvent]:
    return [
        LogEvent(
            timestamp=datetime(2026, 3, 10, 10, i % 60, 0, tzinfo=UTC),
            remote_addr=f"192.168.1.{i % 256}",
            method="GET",
            path=path,
            status=status,
            bytes_sent=1024,
            user_agent="Mozilla/5.0 (X11; Linux x86_64)",
            message=f"GET {path} HTTP/1.1",
        )
        for i in range(count)
    ]


class TestFrequencyBaselineDetector:
    def test_scores_known_pattern_low(self):
        detector = FrequencyBaselineDetector()
        events = _make_events(50)
        detector.train(events)
        scores = detector.score(events[:5])
        for s in scores:
            assert s == pytest.approx(0.0)

    def test_scores_unseen_pattern_high(self):
        detector = FrequencyBaselineDetector()
        events = _make_events(50)
        detector.train(events)
        unseen = _make_events(3, path="/wp-admin/install.php", status=404)
        scores = detector.score(unseen)
        for s in scores:
            assert s == pytest.approx(1.0)

    def test_scores_between_zero_and_one(self):
        detector = FrequencyBaselineDetector()
        events = _make_events(30) + _make_events(10, path="/about", status=200)
        detector.train(events)
        scores = detector.score(events)
        for s in scores:
            assert 0.0 <= s <= 1.0

    def test_predict_flags_unseen(self):
        detector = FrequencyBaselineDetector()
        events = _make_events(50)
        detector.train(events)
        unseen = _make_events(2, path="/shell.php", status=404)
        results = detector.predict(unseen, threshold=0.5)
        assert all(r.is_anomaly for r in results)

    def test_predict_passes_known(self):
        detector = FrequencyBaselineDetector()
        events = _make_events(50)
        detector.train(events)
        results = detector.predict(events[:5], threshold=0.5)
        assert all(not r.is_anomaly for r in results)

    def test_save_and_load(self, tmp_path):
        detector = FrequencyBaselineDetector(model_version="test-v1")
        events = _make_events(20)
        detector.train(events)
        original_scores = detector.score(events)

        path = str(tmp_path / "baseline_model")
        detector.save(path)
        loaded = FrequencyBaselineDetector.load(path)

        assert loaded.model_version == "test-v1"
        loaded_scores = loaded.score(events)
        for orig, load in zip(original_scores, loaded_scores, strict=True):
            assert orig == pytest.approx(load)

    def test_empty_training_scores_one(self):
        detector = FrequencyBaselineDetector()
        detector.train([])
        event = _make_events(1)
        scores = detector.score(event)
        assert scores[0] == pytest.approx(1.0)


class TestIsolationForestDetector:
    def test_scores_between_zero_and_one(self):
        extractor = FeatureExtractor()
        detector = IsolationForestDetector(feature_extractor=extractor, n_estimators=50)
        events = _make_events(100)
        detector.train(events)
        scores = detector.score(events)
        for s in scores:
            assert 0.0 <= s <= 1.0

    def test_anomaly_scores_higher_for_outliers(self):
        extractor = FeatureExtractor()
        detector = IsolationForestDetector(feature_extractor=extractor, n_estimators=100)
        normal = _make_events(200)
        detector.train(normal)

        normal_scores = detector.score(normal[:10])
        outliers = _make_events(5, path="/../../etc/passwd%00", status=403)
        outlier_scores = detector.score(outliers)

        avg_normal = sum(normal_scores) / len(normal_scores)
        avg_outlier = sum(outlier_scores) / len(outlier_scores)
        assert avg_outlier > avg_normal

    def test_predict_returns_correct_count(self):
        extractor = FeatureExtractor()
        detector = IsolationForestDetector(feature_extractor=extractor, n_estimators=50)
        events = _make_events(50)
        detector.train(events)
        results = detector.predict(events, threshold=0.5)
        assert len(results) == 50

    def test_predict_result_structure(self):
        extractor = FeatureExtractor()
        detector = IsolationForestDetector(feature_extractor=extractor, n_estimators=50)
        events = _make_events(30)
        detector.train(events)
        results = detector.predict(events, threshold=0.5)
        for result in results:
            assert hasattr(result, "event")
            assert hasattr(result, "score")
            assert hasattr(result, "is_anomaly")
            assert hasattr(result, "model_version")
            assert isinstance(result.score, float)
            assert isinstance(result.is_anomaly, bool)

    def test_save_and_load(self, tmp_path):
        extractor = FeatureExtractor()
        detector = IsolationForestDetector(
            feature_extractor=extractor,
            n_estimators=50,
            model_version="test-iforest-v1",
        )
        events = _make_events(50)
        detector.train(events)
        original_scores = detector.score(events)

        path = str(tmp_path / "iforest_model")
        detector.save(path)
        loaded = IsolationForestDetector.load(path)

        assert loaded.model_version == "test-iforest-v1"
        loaded_scores = loaded.score(events)
        for orig, load in zip(original_scores, loaded_scores, strict=True):
            assert orig == pytest.approx(load, abs=1e-6)

    def test_score_normalization_edge_case(self):
        extractor = FeatureExtractor()
        detector = IsolationForestDetector(feature_extractor=extractor, n_estimators=50)
        identical = [
            LogEvent(
                timestamp=datetime(2026, 3, 10, 12, 0, 0, tzinfo=UTC),
                method="GET",
                path="/",
                status=200,
                bytes_sent=100,
            )
        ] * 100
        detector.train(identical)
        scores = detector.score(identical[:5])
        for s in scores:
            assert 0.0 <= s <= 1.0
