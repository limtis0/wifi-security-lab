from __future__ import annotations

from pathlib import Path

import pytest

from attacks.common.base_attack import BaseAttack
from attacks.common.config import AttackConfig
from attacks.common.models import AnalysisReport, RawResults, ReconResult
from attacks.common.wireless.backend import MockWirelessBackend


class ConcreteAttack(BaseAttack):
    """Test double with controllable return values."""

    def __init__(
        self,
        interface: str = "wlan0",
        target_bssid: str = "00:11:22:33:44:55",
        output_dir: Path = Path("/tmp"),
        recon_result: ReconResult | None = None,
        raw_results: RawResults | None = None,
        analysis_report: AnalysisReport | None = None,
        recon_error: Exception | None = None,
        execute_error: Exception | None = None,
    ):
        super().__init__(
            interface,
            target_bssid,
            target_ssid="TestAP",
            output_dir=output_dir,
            backend=MockWirelessBackend(),
        )
        self._recon_result = recon_result or ReconResult(
            bssid="00:11:22:33:44:55", ssid="TestAP", channel=6,
        )
        self._raw_results = raw_results or RawResults(attack_name="test")
        self._analysis_report = analysis_report or AnalysisReport(
            attack_name="test",
            success=True,
            summary="Test passed",
            raw_csv_path=Path("/tmp/results.csv"),
        )
        self._recon_error = recon_error
        self._execute_error = execute_error

    def recon(self) -> ReconResult:
        if self._recon_error is not None:
            raise self._recon_error
        return self._recon_result

    def execute(self, config: AttackConfig) -> RawResults:
        if self._execute_error is not None:
            raise self._execute_error
        return self._raw_results

    def analyze(self, raw_results: RawResults) -> AnalysisReport:
        return self._analysis_report


# --- run() pipeline ---


class TestRunPipeline:
    def test_returns_analysis_report(self):
        expected_report = AnalysisReport(
            attack_name="timing",
            success=True,
            summary="Timing leak detected",
            raw_csv_path=Path("/tmp/data.csv"),
        )
        attack = ConcreteAttack(analysis_report=expected_report)

        result = attack.run(AttackConfig())

        assert result.attack_name == expected_report.attack_name
        assert result.success == expected_report.success
        assert result.summary == expected_report.summary

    def test_report_matches_analyze_output(self):
        expected_report = AnalysisReport(
            attack_name="custom",
            success=False,
            summary="No leak found",
            raw_csv_path=Path("/tmp/no_leak.csv"),
            metadata={"note": "clean run"},
        )
        attack = ConcreteAttack(analysis_report=expected_report)

        result = attack.run(AttackConfig())

        assert result is expected_report


# --- error propagation ---


class TestErrorPropagation:
    def test_recon_error_propagates(self):
        attack = ConcreteAttack(recon_error=ConnectionError("No AP found"))

        with pytest.raises(ConnectionError, match="No AP found"):
            attack.run(AttackConfig())

    def test_execute_error_propagates(self):
        attack = ConcreteAttack(execute_error=TimeoutError("Handshake timeout"))

        with pytest.raises(TimeoutError, match="Handshake timeout"):
            attack.run(AttackConfig())


# --- empty data ---


class TestEmptyData:
    def test_analyze_with_empty_samples_returns_valid_report(self):
        empty_results = RawResults(attack_name="test")
        attack = ConcreteAttack(raw_results=empty_results)

        report = attack.run(AttackConfig())

        assert isinstance(report, AnalysisReport)
        assert report.success is True
