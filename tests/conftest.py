from __future__ import annotations

from pathlib import Path

import pytest

from attacks.common.models import AnalysisReport, APInfo, ReconResult, TimingSample
from attacks.common.wireless.backend import MockWirelessBackend


def make_timing_sample(**overrides) -> TimingSample:
    """Factory for TimingSample with sensible defaults."""
    defaults = {
        "password_group": "test_group",
        "attempt": 1,
        "response_time_ns": 500_000,
        "timestamp": 1700000000.0,
    }
    defaults.update(overrides)
    return TimingSample(**defaults)


def make_timing_samples(count: int, group: str = "test_group") -> list[TimingSample]:
    """Factory returning a list of N timing samples for a given group."""
    return [
        make_timing_sample(
            password_group=group,
            attempt=index,
            response_time_ns=500_000 + index * 100,
            timestamp=1700000000.0 + index,
        )
        for index in range(count)
    ]


def make_recon_result(**overrides) -> ReconResult:
    """Factory for ReconResult with sensible defaults."""
    defaults = {
        "bssid": "00:11:22:33:44:55",
        "ssid": "TestNetwork",
        "channel": 6,
    }
    defaults.update(overrides)
    return ReconResult(**defaults)


def make_analysis_report(**overrides) -> AnalysisReport:
    """Factory for AnalysisReport with sensible defaults."""
    defaults = {
        "attack_name": "test_attack",
        "success": True,
        "summary": "Test completed successfully",
        "raw_csv_path": Path("/tmp/test_results.csv"),
    }
    defaults.update(overrides)
    return AnalysisReport(**defaults)


def make_ap_info(**overrides) -> APInfo:
    defaults = {
        "bssid": "00:11:22:33:44:55",
        "ssid": "TestNetwork",
        "channel": 6,
        "capabilities": ["RSN"],
    }
    defaults.update(overrides)
    return APInfo(**defaults)


@pytest.fixture
def mock_backend() -> MockWirelessBackend:
    return MockWirelessBackend()


@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    return tmp_path
