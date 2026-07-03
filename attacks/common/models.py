from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class APInfo:
    bssid: str
    ssid: str
    channel: int | None
    capabilities: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class TimingSample:
    password_group: str
    attempt: int
    response_time_ns: int
    timestamp: float


@dataclass
class ReconResult:
    bssid: str
    ssid: str
    channel: int
    capabilities: list[str] = field(default_factory=list)


@dataclass
class RawResults:
    attack_name: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def item_count(self) -> int:
        return 0


@dataclass
class TimingRawResults(RawResults):
    samples: list[TimingSample] = field(default_factory=list)

    def item_count(self) -> int:
        return len(self.samples)


@dataclass
class CaptureRawResults(RawResults):
    captures: list[bytes] = field(default_factory=list)

    def item_count(self) -> int:
        return len(self.captures)


@dataclass
class AnalysisReport:
    attack_name: str
    success: bool
    summary: str
    raw_csv_path: Path
    plots: list[Path] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
