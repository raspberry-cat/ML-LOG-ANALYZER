from __future__ import annotations

from abc import ABC, abstractmethod

from core.models import AnomalyResult, LogEvent


class IAnomalyDetector(ABC):
    @abstractmethod
    def train(self, events: list[LogEvent]) -> None: ...

    @abstractmethod
    def score(self, events: list[LogEvent]) -> list[float]: ...

    @abstractmethod
    def predict(self, events: list[LogEvent], threshold: float) -> list[AnomalyResult]: ...

    @abstractmethod
    def save(self, path: str) -> None: ...

    @classmethod
    @abstractmethod
    def load(cls, path: str) -> IAnomalyDetector: ...
