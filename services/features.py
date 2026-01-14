from __future__ import annotations

import hashlib
import math
import re
from datetime import datetime

import numpy as np

from core.models import LogEvent
from core.normalization import normalize_path, path_extension, referrer_domain

_METHOD_MAP = {
    "GET": 0,
    "POST": 1,
    "PUT": 2,
    "DELETE": 3,
    "PATCH": 4,
    "HEAD": 5,
    "OPTIONS": 6,
}

_SUSPICIOUS_PATH_RE = re.compile(
    r"(\.\./|/\.env|/wp-admin|/wp-login|/phpmyadmin|/etc/passwd|/\.git|/admin|/login)",
    re.IGNORECASE,
)
_SQLI_RE = re.compile(r"(union|select|insert|drop|or%201=1|sleep\()", re.IGNORECASE)
_BOT_RE = re.compile(r"(bot|crawler|spider|scrapy|curl|wget|sqlmap|nikto)", re.IGNORECASE)
_STATIC_EXTENSIONS = {
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".woff",
    ".woff2",
}

FEATURE_NAMES = [
    "status_code",
    "status_class",
    "method_code",
    "path_length",
    "path_depth",
    "path_tokens",
    "has_query",
    "is_static",
    "bytes_log1p",
    "request_time_log1p",
    "referrer_hash",
    "user_agent_hash",
    "ip_hash",
    "hour",
    "hour_sin",
    "hour_cos",
    "weekday",
    "is_weekend",
    "has_user",
    "user_length",
    "message_length",
    "suspicious_path",
    "sql_keyword",
    "bot_ua",
    "path_template_hash",
    "request_length_log1p",
]


class FeatureExtractor:
    def __init__(self) -> None:
        self.feature_names = list(FEATURE_NAMES)

    def transform(self, events: list[LogEvent]) -> np.ndarray:
        rows = [self._extract(event) for event in events]
        return np.array(rows, dtype=float)

    def _extract(self, event: LogEvent) -> list[float]:
        status = int(event.status) if event.status is not None else 0
        status_class = status // 100 if status else 0
        method = (event.method or "").upper()
        method_code = _METHOD_MAP.get(method, -1)
        path = event.path or ""

        path_length = float(len(path))
        path_depth = float(path.count("/"))
        path_tokens = float(len([t for t in path.split("/") if t]))
        has_query = 1.0 if "?" in path else 0.0
        is_static = 1.0 if path_extension(path) in _STATIC_EXTENSIONS else 0.0

        bytes_log1p = math.log1p(float(event.bytes_sent or 0))
        request_time_log1p = math.log1p(float(event.request_time or 0.0))
        request_length_log1p = math.log1p(float(event.request_length or 0))

        referrer_hash = _hash_bucket(referrer_domain(event.referrer))
        user_agent_hash = _hash_bucket(event.user_agent or "")
        ip_hash = _hash_bucket(event.remote_addr or "")

        hour, hour_sin, hour_cos, weekday, is_weekend = _time_features(event.timestamp)

        has_user = 1.0 if event.remote_user else 0.0
        user_length = float(len(event.remote_user)) if event.remote_user else 0.0
        message_length = float(len(event.message or ""))

        suspicious_path = 1.0 if _SUSPICIOUS_PATH_RE.search(path) else 0.0
        sql_keyword = 1.0 if _SQLI_RE.search(path) else 0.0
        bot_ua = 1.0 if _BOT_RE.search(event.user_agent or "") else 0.0

        path_template_hash = _hash_bucket(normalize_path(path))

        return [
            float(status),
            float(status_class),
            float(method_code),
            path_length,
            path_depth,
            path_tokens,
            has_query,
            is_static,
            bytes_log1p,
            request_time_log1p,
            referrer_hash,
            user_agent_hash,
            ip_hash,
            hour,
            hour_sin,
            hour_cos,
            weekday,
            is_weekend,
            has_user,
            user_length,
            message_length,
            suspicious_path,
            sql_keyword,
            bot_ua,
            path_template_hash,
            request_length_log1p,
        ]


def _time_features(timestamp: datetime) -> tuple[float, float, float, float, float]:
    hour = float(timestamp.hour)
    weekday = float(timestamp.weekday())
    radians = 2 * math.pi * hour / 24.0
    hour_sin = float(math.sin(radians))
    hour_cos = float(math.cos(radians))
    is_weekend = 1.0 if weekday >= 5 else 0.0
    return hour, hour_sin, hour_cos, weekday, is_weekend


def _hash_bucket(value: str, buckets: int = 1000) -> float:
    if not value:
        return 0.0
    digest = hashlib.md5(value.encode("utf-8")).hexdigest()
    bucket = int(digest, 16) % buckets
    return float(bucket) / float(buckets)
