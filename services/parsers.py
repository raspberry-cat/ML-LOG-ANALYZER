from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime

from core.models import LogEvent

DEFAULT_JSON_FIELD_MAPPING: dict[str, list[str]] = {
    "timestamp": ["timestamp", "time", "time_local", "@timestamp"],
    "host": ["host"],
    "service": ["service"],
    "remote_addr": ["remote_addr", "remoteAddress", "ip", "client_ip"],
    "remote_user": ["remote_user", "user"],
    "request": ["request"],
    "method": ["method"],
    "path": ["path", "uri", "request_uri", "url"],
    "protocol": ["protocol"],
    "status": ["status", "statusCode"],
    "bytes_sent": ["bytes_sent", "body_bytes_sent", "responseLength"],
    "referrer": ["referrer", "referer"],
    "user_agent": ["user_agent", "http_user_agent", "userAgent"],
    "request_time": ["request_time", "responseTime"],
    "request_length": ["request_length", "requestLength"],
    "x_forwarded_for": ["x_forwarded_for", "xForwardedFor"],
    "message": ["message"],
    "level": ["level"],
}

DEFAULT_PLAIN_PATTERNS = [
    (
        r"(?P<remote_addr>\S+) (?P<ident>\S+) (?P<remote_user>\S+) "
        r'\[(?P<time_local>[^\]]+)\] "(?P<request>[^"]*)" '
        r'(?P<status>\d{3}) (?P<bytes_sent>\S+) "(?P<referrer>[^"]*)" '
        r'"(?P<user_agent>[^"]*)"'
        r"(?: (?P<request_time>[\d.]+))?$"
    )
]

_REQUEST_RE = re.compile(r"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<protocol>HTTP/[0-9.]+))?")


class LogParser:
    def __init__(
        self,
        source_format: str = "jsonl",
        json_field_mapping: Mapping[str, Sequence[str] | str] | None = None,
        plain_patterns: Iterable[str] | None = None,
    ) -> None:
        self.source_format = source_format.lower()
        self.json_field_mapping = _normalize_field_mapping(json_field_mapping)
        patterns = list(plain_patterns) if plain_patterns else DEFAULT_PLAIN_PATTERNS
        self.plain_regexes = [re.compile(pattern) for pattern in patterns]

    def parse_line(self, line: str, fmt: str | None = None) -> LogEvent:
        source_format = (fmt or self.source_format).lower()
        if source_format == "jsonl":
            return self.parse_json_line(line)
        if source_format == "plain":
            return self.parse_plain_text(line)
        raise ValueError(f"Unsupported format: {source_format}")

    def parse_json_line(self, line: str) -> LogEvent:
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError("JSON log line must contain an object")
        mapped = _apply_field_mapping(payload, self.json_field_mapping)
        return LogEvent.model_validate(_normalize_payload(mapped))

    def parse_plain_text(self, line: str) -> LogEvent:
        for regex in self.plain_regexes:
            match = regex.match(line)
            if not match:
                continue
            data = match.groupdict()
            method, path, protocol = _parse_request_line(data.get("request"))
            status = _parse_int(data.get("status"))
            payload = {
                "timestamp": _parse_nginx_time(data["time_local"]),
                "remote_addr": _clean_dash(data.get("remote_addr")),
                "remote_user": _clean_dash(data.get("remote_user")),
                "method": method,
                "path": path,
                "protocol": protocol,
                "status": status,
                "bytes_sent": _parse_int(data.get("bytes_sent")),
                "referrer": _clean_dash(data.get("referrer")),
                "user_agent": _clean_dash(data.get("user_agent")),
                "request_time": _parse_float(data.get("request_time")),
                "message": _build_message(method, path, protocol, data.get("request")),
                "level": _status_to_level(status),
                "service": "nginx",
            }
            return LogEvent.model_validate(payload)
        raise ValueError("Plain text log did not match nginx access log format")

    def parse_lines(self, lines: Iterable[str], fmt: str | None = None) -> list[LogEvent]:
        events: list[LogEvent] = []
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue
            events.append(self.parse_line(line, fmt))
        return events

    def parse_lines_safe(self, lines: Iterable[str], fmt: str | None = None) -> tuple[list[LogEvent], int]:
        events: list[LogEvent] = []
        skipped = 0
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue
            try:
                events.append(self.parse_line(line, fmt))
            except Exception:
                skipped += 1
        return events, skipped


def _normalize_field_mapping(
    mapping: Mapping[str, Sequence[str] | str] | None,
) -> dict[str, list[str]]:
    normalized = {key: list(aliases) for key, aliases in DEFAULT_JSON_FIELD_MAPPING.items()}
    if not mapping:
        return normalized

    for field_name, aliases in mapping.items():
        if isinstance(aliases, str):
            normalized[str(field_name)] = [aliases]
        else:
            normalized[str(field_name)] = [str(alias) for alias in aliases if str(alias)]
    return normalized


def _apply_field_mapping(
    payload: Mapping[str, object],
    field_mapping: Mapping[str, Sequence[str]],
) -> dict[str, object]:
    normalized = dict(payload)
    for canonical_name, aliases in field_mapping.items():
        for alias in aliases:
            if alias in payload:
                normalized[canonical_name] = payload[alias]
                break
    return normalized


def _normalize_payload(payload: Mapping[str, object]) -> dict[str, object]:
    data = dict(payload)

    timestamp_value = data.get("timestamp") or data.get("time_local") or data.get("time") or data.get(
        "@timestamp"
    )
    if timestamp_value is not None:
        data["timestamp"] = _parse_nginx_time(str(timestamp_value))

    request = _clean_dash(data.get("request"))
    method, path, protocol = _parse_request_line(request)
    data.setdefault("method", method)
    data.setdefault("path", path)
    data.setdefault("protocol", protocol)

    data["status"] = _parse_int(data.get("status") or data.get("statusCode"))
    data["bytes_sent"] = _parse_int(
        data.get("bytes_sent") or data.get("body_bytes_sent") or data.get("responseLength")
    )
    data["request_time"] = _parse_float(data.get("request_time") or data.get("responseTime"))
    data["request_length"] = _parse_int(data.get("request_length") or data.get("requestLength"))

    data["remote_addr"] = _clean_dash(
        data.get("remote_addr") or data.get("remoteAddress") or data.get("ip")
    )
    data["remote_user"] = _clean_dash(data.get("remote_user") or data.get("user"))
    data["path"] = _clean_dash(
        data.get("path") or data.get("uri") or data.get("request_uri") or data.get("url")
    )
    data["user_agent"] = _clean_dash(
        data.get("user_agent") or data.get("userAgent") or data.get("http_user_agent")
    )
    data["referrer"] = _clean_dash(data.get("referrer") or data.get("referer"))
    data["x_forwarded_for"] = _clean_dash(data.get("x_forwarded_for") or data.get("xForwardedFor"))

    if not data.get("message"):
        data["message"] = _build_message(
            _clean_dash(data.get("method")),
            _clean_dash(data.get("path")),
            _clean_dash(data.get("protocol")),
            request,
        )
    if not data.get("level"):
        data["level"] = _status_to_level(_parse_int(data.get("status")))
    if not data.get("service") and not data.get("host"):
        data["service"] = "nginx"
    return data


def _parse_nginx_time(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)


def _parse_request_line(request: str | None) -> tuple[str | None, str | None, str | None]:
    if not request or request == "-":
        return None, None, None
    match = _REQUEST_RE.match(request)
    if not match:
        return None, None, None
    return match.group("method"), match.group("path"), match.group("protocol")


def _build_message(
    method: str | None,
    path: str | None,
    protocol: str | None,
    request: str | None,
) -> str:
    if request and request != "-":
        return request
    return " ".join(part for part in (method, path, protocol) if part)


def _status_to_level(status: int | None) -> str:
    if status is None:
        return "INFO"
    if status >= 500:
        return "ERROR"
    if status >= 400:
        return "WARNING"
    if status >= 300:
        return "NOTICE"
    return "INFO"


def _parse_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text in {"", "-"}:
        return None
    return int(float(text))


def _parse_float(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, float):
        return value
    text = str(value).strip()
    if text in {"", "-"}:
        return None
    return float(text)


def _clean_dash(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if text in {"", "-"}:
        return None
    return text
