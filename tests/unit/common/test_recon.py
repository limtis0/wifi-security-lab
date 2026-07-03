from __future__ import annotations

from pathlib import Path

import pytest

from attacks.common.base_attack import BaseAttack
from attacks.common.config import AttackConfig
from attacks.common.models import AnalysisReport, APInfo, RawResults, ReconResult
from attacks.common.wireless.backend import MockWirelessBackend


class MinimalAttack(BaseAttack):
    def execute(self, config: AttackConfig) -> RawResults:
        return RawResults(attack_name="test")

    def analyze(self, raw_results: RawResults) -> AnalysisReport:
        return AnalysisReport(
            attack_name="test", success=True, summary="ok", raw_csv_path=Path("/tmp/x.csv"),
        )


def make_attack(backend: MockWirelessBackend) -> MinimalAttack:
    return MinimalAttack(
        interface="wlan0",
        target_bssid="00:11:22:33:44:55",
        target_ssid="DragonbloodLab",
        output_dir=Path("/tmp"),
        backend=backend,
    )


class TestReconAPFound:
    def test_returns_recon_result_with_correct_fields(self):
        backend = MockWirelessBackend()
        attack = make_attack(backend)

        result = attack.recon()

        assert result.bssid == "00:11:22:33:44:55"
        assert result.ssid == "DragonbloodLab"
        assert result.channel == 6
        assert "RSN" in result.capabilities

    def test_set_channel_called_with_ap_channel(self):
        backend = MockWirelessBackend(
            ap_config=APInfo(bssid="aa:bb:cc:dd:ee:ff", ssid="DragonbloodLab", channel=11, capabilities=["RSN"]),
        )
        attack = make_attack(backend)

        attack.recon()

        assert backend.channel_changes == [11]


class TestReconAPNotFound:
    def test_raises_connection_error_when_ap_not_found(self):
        backend = MockWirelessBackend(
            ap_config=APInfo(bssid="aa:bb:cc:dd:ee:ff", ssid="WrongSSID", channel=6),
        )
        attack = make_attack(backend)

        with pytest.raises(ConnectionError, match="Could not find AP"):
            attack.recon()


class TestReconEdgeCases:
    def test_channel_none_skips_set_channel(self):
        backend = MockWirelessBackend(
            ap_config=APInfo(bssid="00:11:22:33:44:55", ssid="DragonbloodLab", channel=None, capabilities=["RSN"]),
        )
        attack = make_attack(backend)

        result = attack.recon()

        assert result.channel == 0
        assert backend.channel_changes == []

    def test_no_rsn_still_returns_result(self):
        backend = MockWirelessBackend(
            ap_config=APInfo(bssid="00:11:22:33:44:55", ssid="DragonbloodLab", channel=6, capabilities=[]),
        )
        attack = make_attack(backend)

        result = attack.recon()

        assert result.capabilities == []
