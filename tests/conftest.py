from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.models import LogEvent


@pytest.fixture()
def sample_event() -> LogEvent:
    return LogEvent(
        timestamp=datetime(2026, 3, 10, 14, 30, 0, tzinfo=UTC),
        host="api.example.com",
        remote_addr="198.51.100.42",
        method="GET",
        path="/api/v1/users/42?page=2",
        protocol="HTTP/1.1",
        status=200,
        bytes_sent=1024,
        referrer="https://example.com/home",
        user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        request_time=0.045,
        request_length=256,
        level="INFO",
        message="GET /api/v1/users/42?page=2 HTTP/1.1",
    )


@pytest.fixture()
def attack_events() -> list[LogEvent]:
    base = datetime(2026, 3, 10, 3, 0, 0, tzinfo=UTC)
    return [
        LogEvent(
            timestamp=base,
            remote_addr="10.0.0.1",
            method="GET",
            path="/etc/passwd",
            status=403,
            user_agent="Mozilla/5.0",
            message="GET /etc/passwd HTTP/1.1",
        ),
        LogEvent(
            timestamp=base,
            remote_addr="10.0.0.2",
            method="GET",
            path="/search?q=1'+OR+1=1--",
            status=200,
            user_agent="sqlmap/1.6",
            message="GET /search?q=1'+OR+1=1-- HTTP/1.1",
        ),
        LogEvent(
            timestamp=base,
            remote_addr="10.0.0.3",
            method="GET",
            path="/page?input=<script>alert(1)</script>",
            status=200,
            user_agent="Mozilla/5.0",
            message="GET /page?input=<script>alert(1)</script> HTTP/1.1",
        ),
        LogEvent(
            timestamp=base,
            remote_addr="10.0.0.4",
            method="GET",
            path="/../../etc/shadow",
            status=404,
            user_agent="Mozilla/5.0",
            message="GET /../../etc/shadow HTTP/1.1",
        ),
        LogEvent(
            timestamp=base,
            remote_addr="10.0.0.5",
            method="POST",
            path="/upload/cmd.php",
            status=200,
            user_agent="Mozilla/5.0",
            message="POST /upload/cmd.php HTTP/1.1",
        ),
    ]


@pytest.fixture()
def normal_events() -> list[LogEvent]:
    base = datetime(2026, 3, 10, 10, 0, 0, tzinfo=UTC)
    return [
        LogEvent(
            timestamp=base,
            host="api.example.com",
            remote_addr="192.168.1.10",
            method="GET",
            path="/api/v1/health",
            protocol="HTTP/1.1",
            status=200,
            bytes_sent=128,
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            request_time=0.005,
            message="GET /api/v1/health HTTP/1.1",
        ),
        LogEvent(
            timestamp=base,
            host="api.example.com",
            remote_addr="192.168.1.11",
            method="POST",
            path="/api/v1/auth/login",
            protocol="HTTP/1.1",
            status=200,
            bytes_sent=512,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            request_time=0.120,
            request_length=384,
            message="POST /api/v1/auth/login HTTP/1.1",
        ),
        LogEvent(
            timestamp=base,
            host="api.example.com",
            remote_addr="192.168.1.12",
            method="GET",
            path="/static/app.js",
            protocol="HTTP/1.1",
            status=200,
            bytes_sent=65536,
            user_agent="Mozilla/5.0 (X11; Linux x86_64)",
            request_time=0.002,
            message="GET /static/app.js HTTP/1.1",
        ),
    ]


@pytest.fixture()
def json_log_line_camelcase() -> str:
    return (
        '{"time":"2026-03-10T14:30:00Z","remoteAddress":"198.51.100.42",'
        '"host":"web.example.com","method":"GET","url":"/api/v1/status",'
        '"protocol":"HTTP/1.1","statusCode":200,'
        '"userAgent":"Mozilla/5.0 (X11; Linux x86_64)",'
        '"referer":"-","xForwardedFor":"-",'
        '"requestLength":128,"responseLength":256,"responseTime":0.012}'
    )


@pytest.fixture()
def plain_log_line() -> str:
    return (
        "198.51.100.42 - admin [10/Mar/2026:14:30:00 +0000] "
        '"POST /api/v1/data HTTP/1.1" 201 512 '
        '"https://example.com" "Mozilla/5.0" 0.150'
    )
