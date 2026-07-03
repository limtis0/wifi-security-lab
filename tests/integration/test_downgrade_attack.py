from __future__ import annotations

from pathlib import Path

from attacks.common.config import DowngradeAttackConfig
from attacks.common.wireless.backend import MockWirelessBackend
from attacks.dragonblood.downgrade import DowngradeAttack


def make_downgrade_attack(
    output_dir: Path,
    backend: MockWirelessBackend | None = None,
) -> DowngradeAttack:
    if backend is None:
        backend = MockWirelessBackend()
    return DowngradeAttack(
        interface="wlan0",
        target_bssid="00:11:22:33:44:55",
        target_ssid="DragonbloodLab",
        output_dir=output_dir,
        backend=backend,
    )


SHORT_CONFIG = DowngradeAttackConfig(
    target_bssid="00:11:22:33:44:55",
    target_ssid="DragonbloodLab",
    monitor_duration_seconds=0.1,
    beacon_injection_rate_ms=20,
)


class TestDowngradeExecute:
    def test_captures_handshakes_when_available(self, tmp_path: Path):
        backend = MockWirelessBackend(handshake_capture_count=3)
        attack = make_downgrade_attack(tmp_path, backend)

        results = attack.execute(SHORT_CONFIG)

        assert len(results.captures) == 3

    def test_no_captures_when_none_available(self, tmp_path: Path):
        backend = MockWirelessBackend(handshake_capture_count=0)
        attack = make_downgrade_attack(tmp_path, backend)

        results = attack.execute(SHORT_CONFIG)

        assert len(results.captures) == 0

    def test_beacons_are_injected(self, tmp_path: Path):
        backend = MockWirelessBackend()
        attack = make_downgrade_attack(tmp_path, backend)

        results = attack.execute(SHORT_CONFIG)

        assert results.metadata["beacon_count"] > 0
        assert len(backend.injected_frames) == results.metadata["beacon_count"]


class TestDowngradeAnalyze:
    def test_success_when_captures_present(self, tmp_path: Path):
        backend = MockWirelessBackend(handshake_capture_count=2)
        attack = make_downgrade_attack(tmp_path, backend)

        raw_results = attack.execute(SHORT_CONFIG)
        report = attack.analyze(raw_results)

        assert report.success is True
        assert "Downgrade successful" in report.summary

    def test_failure_when_no_captures(self, tmp_path: Path):
        backend = MockWirelessBackend(handshake_capture_count=0)
        attack = make_downgrade_attack(tmp_path, backend)

        raw_results = attack.execute(SHORT_CONFIG)
        report = attack.analyze(raw_results)

        assert report.success is False
        assert "not detected" in report.summary


class TestDowngradeFullPipeline:
    def test_run_produces_report(self, tmp_path: Path):
        backend = MockWirelessBackend(handshake_capture_count=1)
        attack = make_downgrade_attack(tmp_path, backend)

        report = attack.run(SHORT_CONFIG)

        assert report.attack_name == "dragonblood-downgrade"
        assert report.success is True
        assert backend.channel_changes == [6, 6]

    def test_run_with_no_captures_reports_failure(self, tmp_path: Path):
        backend = MockWirelessBackend(handshake_capture_count=0)
        attack = make_downgrade_attack(tmp_path, backend)

        report = attack.run(SHORT_CONFIG)

        assert report.success is False
