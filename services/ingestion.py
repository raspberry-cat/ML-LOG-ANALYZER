from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from core.models import LogEvent
from services.parsers import LogParser


@dataclass(slots=True)
class ParsedBatch:
    path: Path
    events: list[LogEvent]
    line_count: int
    skipped_lines: int


class LogIngestor:
    def __init__(self, parser: LogParser) -> None:
        self.parser = parser

    def ingest_file(self, path: Path, fmt: str | None = None) -> list[LogEvent]:
        lines = self.read_lines(path)
        return self.parser.parse_lines(lines, fmt)

    def read_lines(self, path: Path) -> list[str]:
        return path.read_text(encoding="utf-8").splitlines()

    def iter_line_batches(self, path: Path, batch_size: int) -> Iterator[list[str]]:
        if batch_size <= 0:
            raise ValueError("batch_size must be greater than zero")

        batch: list[str] = []
        with path.open(encoding="utf-8") as source:
            for raw_line in source:
                line = raw_line.strip()
                if not line:
                    continue
                batch.append(line)
                if len(batch) >= batch_size:
                    yield batch
                    batch = []

        if batch:
            yield batch

    def iter_parsed_batches(
        self,
        paths: Iterable[Path],
        batch_size: int,
        fmt: str | None = None,
    ) -> Iterator[ParsedBatch]:
        for path in paths:
            for lines in self.iter_line_batches(path, batch_size):
                events, skipped_lines = self.parser.parse_lines_safe(lines, fmt)
                yield ParsedBatch(
                    path=path,
                    events=events,
                    line_count=len(lines),
                    skipped_lines=skipped_lines,
                )
