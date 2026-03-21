from __future__ import annotations

import json
import random
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from core.models import LogEvent

HOSTS = ["edge-01", "edge-02", "web-01", "web-02"]
REMOTE_USERS = ["-", "-", "-", "alice", "bob", "service"]
METHODS = ["GET", "POST"]
PATHS = [
    "/",
    "/index.html",
    "/about",
    "/pricing",
    "/api/v1/items",
    "/api/v1/cart",
    "/login",
    "/logout",
    "/static/app.js",
    "/static/styles.css",
    "/images/logo.png",
]
NORMAL_STATUSES = [200, 200, 200, 204, 301, 302, 304, 404]
NORMAL_UA = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36",
]
NORMAL_REFERRERS = [
    "-",
    "https://example.com/",
    "https://google.com/search?q=shop",
    "https://news.ycombinator.com/",
]
ANOMALY_PATHS = [
    "/wp-admin",
    "/wp-login.php",
    "/.env",
    "/phpmyadmin",
    "/etc/passwd",
    "/admin",
    "/cgi-bin/.%2e/.%2e/.%2e/etc/passwd",
]
ANOMALY_UA = ["sqlmap/1.7.2", "nikto/2.5", "curl/8.4.0", "python-requests/2.32"]
ANOMALY_METHODS = ["PUT", "DELETE", "TRACE"]


def generate_events(
    total: int = 500,
    anomaly_ratio: float = 0.05,
    start_time: datetime | None = None,
) -> list[LogEvent]:
    start_time = start_time or datetime.now(UTC) - timedelta(minutes=total)
    events: list[LogEvent] = []
    anomaly_count = int(total * anomaly_ratio)
    normal_count = total - anomaly_count

    events.extend(_generate_normal_events(normal_count, start_time))
    events.extend(
        _generate_anomaly_events(anomaly_count, start_time + timedelta(minutes=normal_count))
    )
    random.shuffle(events)
    return events


def to_json_lines(events: Iterable[LogEvent]) -> list[str]:
    lines: list[str] = []
    for event in events:
        payload = event.model_dump()
        payload["timestamp"] = event.timestamp.isoformat()
        lines.append(json.dumps(payload, ensure_ascii=True))
    return lines


def to_plain_lines(events: Iterable[LogEvent]) -> list[str]:
    lines: list[str] = []
    for event in events:
        timestamp = event.timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")
        remote_addr = event.remote_addr or "-"
        remote_user = event.remote_user or "-"
        request_line = _build_message(event.method, event.path, event.protocol)
        status = event.status or 0
        bytes_sent = event.bytes_sent or 0
        referrer = event.referrer or "-"
        user_agent = event.user_agent or "-"
        request_time = event.request_time if event.request_time is not None else 0.0
        line = (
            f'{remote_addr} - {remote_user} [{timestamp}] "{request_line}" '
            f'{status} {bytes_sent} "{referrer}" "{user_agent}" {request_time:.3f}'
        )
        lines.append(line)
    return lines


def _generate_normal_events(count: int, start_time: datetime) -> list[LogEvent]:
    events: list[LogEvent] = []
    for i in range(count):
        timestamp = start_time + timedelta(seconds=i)
        host = random.choice(HOSTS)
        remote_addr = f"10.0.0.{random.randint(2, 250)}"
        remote_user = random.choice(REMOTE_USERS)
        method = random.choice(METHODS)
        path = random.choice(PATHS)
        status = random.choice(NORMAL_STATUSES)
        bytes_sent = random.randint(300, 8000)
        request_time = random.uniform(0.02, 0.4)
        referrer = random.choice(NORMAL_REFERRERS)
        user_agent = random.choice(NORMAL_UA)
        message = _build_message(method, path, "HTTP/1.1")
        events.append(
            LogEvent(
                timestamp=timestamp,
                host=host,
                service="nginx",
                remote_addr=remote_addr,
                remote_user=None if remote_user == "-" else remote_user,
                method=method,
                path=path,
                protocol="HTTP/1.1",
                status=status,
                bytes_sent=bytes_sent,
                referrer=None if referrer == "-" else referrer,
                user_agent=user_agent,
                request_time=request_time,
                message=message,
                level=_status_to_level(status),
                attributes={"upstream_time": round(request_time * 0.6, 3)},
            )
        )
    return events


def _generate_anomaly_events(count: int, start_time: datetime) -> list[LogEvent]:
    events: list[LogEvent] = []
    for i in range(count):
        timestamp = start_time + timedelta(seconds=i)
        host = random.choice(HOSTS)
        remote_addr = f"203.0.113.{random.randint(1, 250)}"
        remote_user = random.choice(["-", "-", "intruder"])
        method = random.choice(ANOMALY_METHODS)
        path = random.choice(ANOMALY_PATHS)
        status = random.choice([401, 403, 404, 405, 500, 502, 504])
        bytes_sent = random.randint(50, 30000)
        request_time = random.uniform(1.2, 5.0)
        user_agent = random.choice(ANOMALY_UA)
        message = _build_message(method, path, "HTTP/1.1")
        events.append(
            LogEvent(
                timestamp=timestamp,
                host=host,
                service="nginx",
                remote_addr=remote_addr,
                remote_user=None if remote_user == "-" else remote_user,
                method=method,
                path=path,
                protocol="HTTP/1.1",
                status=status,
                bytes_sent=bytes_sent,
                referrer=None,
                user_agent=user_agent,
                request_time=request_time,
                message=message,
                level=_status_to_level(status),
                attributes={"upstream_time": round(request_time * 0.8, 3)},
            )
        )
    return events


def _build_message(method: str | None, path: str | None, protocol: str | None) -> str:
    parts = [part for part in (method, path, protocol) if part]
    return " ".join(parts)


def _status_to_level(status: int) -> str:
    if status >= 500:
        return "ERROR"
    if status >= 400:
        return "WARNING"
    if status >= 300:
        return "NOTICE"
    return "INFO"
