from __future__ import annotations

import json
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _default_log_field_mapping() -> dict[str, list[str]]:
    return {
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


def _default_plain_patterns() -> list[str]:
    return [
        (
            r"(?P<remote_addr>\S+) (?P<ident>\S+) (?P<remote_user>\S+) "
            r'\[(?P<time_local>[^\]]+)\] "(?P<request>[^"]*)" '
            r'(?P<status>\d{3}) (?P<bytes_sent>\S+) "(?P<referrer>[^"]*)" '
            r'"(?P<user_agent>[^"]*)"'
            r"(?: (?P<request_time>[\d.]+))?$"
        )
    ]


def _normalize_mapping_value(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if str(item)]
    raise TypeError(f"Unsupported mapping value: {value!r}")


def _normalize_string_list(value: object, *, field_name: str) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("["):
            value = json.loads(text)
        else:
            items: list[str] = []
            for line in text.splitlines():
                items.extend(part.strip() for part in line.split(","))
            return [item for item in items if item]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    raise TypeError(f"{field_name} must be a JSON array or a comma-separated string")


class Settings(BaseSettings):
    app_name: str = "Nginx Log Anomaly Detection"
    environment: str = "dev"
    artifact_dir: str = "./artifacts"
    model_type: str = "isolation_forest"
    anomaly_threshold: float = 0.5
    baseline_threshold: float = 0.85
    log_level: str = "INFO"
    ingest_batch_size: int = 500
    max_stored_anomalies: int = 1000
    log_source_format: str = "jsonl"
    log_field_mapping: dict[str, list[str]] = Field(default_factory=_default_log_field_mapping)
    log_plain_patterns: list[str] = Field(default_factory=_default_plain_patterns)
    auto_train_on_startup: bool = False
    bootstrap_log_path: str = "./data/logs/bootstrap.jsonl"
    auto_ingest_log_files_on_startup: bool = False
    log_input_paths: Annotated[list[str], NoDecode] = Field(default_factory=list)

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @field_validator("log_source_format")
    @classmethod
    def validate_log_source_format(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"jsonl", "plain"}:
            raise ValueError("LOG_SOURCE_FORMAT must be 'jsonl' or 'plain'")
        return normalized

    @field_validator("log_field_mapping", mode="before")
    @classmethod
    def normalize_log_field_mapping(cls, value: object) -> dict[str, list[str]]:
        if value in (None, ""):
            return _default_log_field_mapping()
        if isinstance(value, str):
            value = json.loads(value)
        if not isinstance(value, dict):
            raise TypeError("LOG_FIELD_MAPPING must be a JSON object")

        mapping = _default_log_field_mapping()
        for key, aliases in value.items():
            mapping[str(key)] = _normalize_mapping_value(aliases)
        return mapping

    @field_validator("log_plain_patterns", mode="before")
    @classmethod
    def normalize_log_plain_patterns(cls, value: object) -> list[str]:
        if value in (None, ""):
            return _default_plain_patterns()
        if isinstance(value, str):
            value = json.loads(value)
        if not isinstance(value, list):
            raise TypeError("LOG_PLAIN_PATTERNS must be a JSON array")
        return [str(pattern) for pattern in value]

    @field_validator("log_input_paths", mode="before")
    @classmethod
    def normalize_log_input_paths(cls, value: object) -> list[str]:
        return _normalize_string_list(value, field_name="LOG_INPUT_PATHS")


settings = Settings()
