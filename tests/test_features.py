from __future__ import annotations

import math
from datetime import UTC, datetime

import numpy as np
import pytest

from core.models import LogEvent
from services.features import FEATURE_NAMES, FeatureExtractor


class TestFeatureExtractor:
    def test_output_shape(self, sample_event: LogEvent):
        extractor = FeatureExtractor()
        features = extractor.transform([sample_event])
        assert features.shape == (1, len(FEATURE_NAMES))

    def test_batch_shape(self, normal_events: list[LogEvent]):
        extractor = FeatureExtractor()
        features = extractor.transform(normal_events)
        assert features.shape == (len(normal_events), len(FEATURE_NAMES))

    def test_no_nan_values(self, sample_event: LogEvent):
        extractor = FeatureExtractor()
        features = extractor.transform([sample_event])
        assert not np.isnan(features).any()

    def test_status_code_feature(self, sample_event: LogEvent):
        extractor = FeatureExtractor()
        features = extractor.transform([sample_event])
        status_idx = FEATURE_NAMES.index("status_code")
        assert features[0, status_idx] == 200.0

    def test_status_class_feature(self, sample_event: LogEvent):
        extractor = FeatureExtractor()
        features = extractor.transform([sample_event])
        status_class_idx = FEATURE_NAMES.index("status_class")
        assert features[0, status_class_idx] == 2.0

    def test_method_code_known(self, sample_event: LogEvent):
        extractor = FeatureExtractor()
        features = extractor.transform([sample_event])
        method_idx = FEATURE_NAMES.index("method_code")
        assert features[0, method_idx] == 0.0

    def test_method_code_unknown(self):
        extractor = FeatureExtractor()
        event = LogEvent(
            timestamp=datetime(2026, 3, 10, tzinfo=UTC),
            method="PROPFIND",
            path="/",
            status=405,
        )
        features = extractor.transform([event])
        method_idx = FEATURE_NAMES.index("method_code")
        assert features[0, method_idx] == -1.0

    def test_has_query_flag(self, sample_event: LogEvent):
        extractor = FeatureExtractor()
        features = extractor.transform([sample_event])
        query_idx = FEATURE_NAMES.index("has_query")
        assert features[0, query_idx] == 1.0

    def test_is_static_flag(self, normal_events: list[LogEvent]):
        extractor = FeatureExtractor()
        features = extractor.transform(normal_events)
        static_idx = FEATURE_NAMES.index("is_static")
        assert features[2, static_idx] == 1.0
        assert features[0, static_idx] == 0.0

    def test_bytes_log1p(self, sample_event: LogEvent):
        extractor = FeatureExtractor()
        features = extractor.transform([sample_event])
        bytes_idx = FEATURE_NAMES.index("bytes_log1p")
        expected = math.log1p(1024.0)
        assert features[0, bytes_idx] == pytest.approx(expected)

    def test_request_length_log1p(self, sample_event: LogEvent):
        extractor = FeatureExtractor()
        features = extractor.transform([sample_event])
        rl_idx = FEATURE_NAMES.index("request_length_log1p")
        expected = math.log1p(256.0)
        assert features[0, rl_idx] == pytest.approx(expected)

    def test_suspicious_path_detection(self, attack_events: list[LogEvent]):
        extractor = FeatureExtractor()
        features = extractor.transform(attack_events)
        susp_idx = FEATURE_NAMES.index("suspicious_path")
        assert features[0, susp_idx] == 1.0

    def test_sql_keyword_detection(self):
        extractor = FeatureExtractor()
        event = LogEvent(
            timestamp=datetime(2026, 3, 10, 3, 0, 0, tzinfo=UTC),
            remote_addr="10.0.0.2",
            method="GET",
            path="/search?q=union select * from users",
            status=200,
            user_agent="Mozilla/5.0",
            message="GET /search?q=union select * from users HTTP/1.1",
        )
        features = extractor.transform([event])
        sql_idx = FEATURE_NAMES.index("sql_keyword")
        assert features[0, sql_idx] == 1.0

    def test_bot_ua_detection(self, attack_events: list[LogEvent]):
        extractor = FeatureExtractor()
        features = extractor.transform(attack_events)
        bot_idx = FEATURE_NAMES.index("bot_ua")
        assert features[1, bot_idx] == 1.0

    def test_time_features_range(self, sample_event: LogEvent):
        extractor = FeatureExtractor()
        features = extractor.transform([sample_event])
        hour_idx = FEATURE_NAMES.index("hour")
        hour_sin_idx = FEATURE_NAMES.index("hour_sin")
        hour_cos_idx = FEATURE_NAMES.index("hour_cos")
        assert 0.0 <= features[0, hour_idx] <= 23.0
        assert -1.0 <= features[0, hour_sin_idx] <= 1.0
        assert -1.0 <= features[0, hour_cos_idx] <= 1.0

    def test_weekend_flag(self):
        extractor = FeatureExtractor()
        saturday = LogEvent(
            timestamp=datetime(2026, 3, 14, 12, 0, 0, tzinfo=UTC),
            method="GET",
            path="/",
            status=200,
        )
        weekday = LogEvent(
            timestamp=datetime(2026, 3, 10, 12, 0, 0, tzinfo=UTC),
            method="GET",
            path="/",
            status=200,
        )
        sat_features = extractor.transform([saturday])
        wd_features = extractor.transform([weekday])
        we_idx = FEATURE_NAMES.index("is_weekend")
        assert sat_features[0, we_idx] == 1.0
        assert wd_features[0, we_idx] == 0.0

    def test_feature_count_matches(self):
        extractor = FeatureExtractor()
        assert len(extractor.feature_names) == len(FEATURE_NAMES)
        assert len(FEATURE_NAMES) == 26

    def test_none_fields_produce_valid_features(self):
        extractor = FeatureExtractor()
        event = LogEvent(
            timestamp=datetime(2026, 3, 10, tzinfo=UTC),
        )
        features = extractor.transform([event])
        assert features.shape == (1, 26)
        assert not np.isnan(features).any()
