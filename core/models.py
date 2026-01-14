from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import AliasChoices, BaseModel, Field, model_validator


class LogEvent(BaseModel):
    timestamp: datetime
    host: str | None = None
    service: str | None = None
    remote_addr: str | None = Field(
        default=None,
        validation_alias=AliasChoices("remote_addr", "ip", "client_ip", "remoteAddress"),
    )
    remote_user: str | None = Field(
        default=None,
        validation_alias=AliasChoices("remote_user", "user"),
    )
    method: str | None = None
    path: str | None = Field(
        default=None,
        validation_alias=AliasChoices("path", "uri", "request_uri", "url"),
    )
    protocol: str | None = None
    status: int | None = Field(
        default=None,
        validation_alias=AliasChoices("status", "statusCode"),
    )
    bytes_sent: int | None = Field(
        default=None,
        validation_alias=AliasChoices("bytes_sent", "body_bytes_sent", "responseLength"),
    )
    referrer: str | None = Field(
        default=None,
        validation_alias=AliasChoices("referrer", "referer"),
    )
    user_agent: str | None = Field(
        default=None,
        validation_alias=AliasChoices("user_agent", "http_user_agent", "userAgent"),
    )
    request_time: float | None = Field(
        default=None,
        validation_alias=AliasChoices("request_time", "responseTime"),
    )
    request_length: int | None = Field(
        default=None,
        validation_alias=AliasChoices("request_length", "requestLength"),
    )
    x_forwarded_for: str | None = Field(
        default=None,
        validation_alias=AliasChoices("x_forwarded_for", "xForwardedFor"),
    )
    message: str = ""
    level: str = "INFO"
    attributes: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def ensure_source(self) -> LogEvent:
        if not self.host and not self.service:
            self.service = "nginx"
        return self

    @property
    def source(self) -> str:
        return self.host or self.service or "unknown"


class MitreTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str
    confidence: float = 0.0


class AnomalyResult(BaseModel):
    event: LogEvent
    score: float
    is_anomaly: bool
    model_version: str
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
