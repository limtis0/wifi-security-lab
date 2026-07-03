from __future__ import annotations

from pathlib import Path

from attacks.common.wireless.backend import MockWirelessBackend, VulnerableMockBackend
from attacks.dragonblood.live_recovery import FieldVerdict, run_live_recovery

from tests.conftest import make_ap_info


SMALL_DICTIONARY = [
    "password123", "letmein", "admin2024", "wifi_secure",
    "hunter2", "12345678", "monkey", "master",
    "dragon", "qwerty", "abc123", "trustno1",
    "iloveyou", "sunshine", "princess", "football",
    "shadow", "michael", "jennifer", "dr4gonfly",
]


def write_dictionary(directory: Path) -> str:
    dictionary_path = directory / "wordlist.txt"
    dictionary_path.write_text("\n".join(SMALL_DICTIONARY) + "\n")
    return str(dictionary_path)


class TestLiveRecoveryVerdicts:
    def test_vulnerable_ap_is_recovered(self, tmp_path: Path):
        backend = VulnerableMockBackend(target_password="dr4gonfly")
        backend.ap_config = make_ap_info(ssid="DragonbloodLab", channel=6)

        outcome = run_live_recovery(
            backend=backend,
            interface="wlan0",
            target_ssid="DragonbloodLab",
            dictionary_path=write_dictionary(tmp_path),
            output_dir=tmp_path,
            samples_per_mac=100,
            max_macs=15,
            skip_monitor_setup=True,
        )

        assert outcome.verdict is FieldVerdict.VULNERABLE_RECOVERED
        assert outcome.report is not None
        assert outcome.report.metadata["recovered_password"] == "dr4gonfly"

    def test_patched_ap_reports_no_signal(self, tmp_path: Path):
        # Constant response time regardless of MAC models a constant-time
        # (patched) SAE implementation: no per-iteration signal to calibrate.
        backend = MockWirelessBackend(
            ap_config=make_ap_info(ssid="DragonbloodLab", channel=6),
            response_time_ns_range=(500_000, 500_000),
        )

        outcome = run_live_recovery(
            backend=backend,
            interface="wlan0",
            target_ssid="DragonbloodLab",
            dictionary_path=write_dictionary(tmp_path),
            output_dir=tmp_path,
            samples_per_mac=50,
            max_macs=15,
            skip_monitor_setup=True,
        )

        assert outcome.verdict is FieldVerdict.PATCHED_NO_SIGNAL
        assert outcome.report is None

    def test_missing_ssid_reports_target_not_found(self, tmp_path: Path):
        backend = MockWirelessBackend(
            ap_config=make_ap_info(ssid="DragonbloodLab")
        )

        outcome = run_live_recovery(
            backend=backend,
            interface="wlan0",
            target_ssid="NonexistentNetwork",
            dictionary_path=write_dictionary(tmp_path),
            output_dir=tmp_path,
            channels=[1, 6, 11],
            skip_monitor_setup=True,
        )

        assert outcome.verdict is FieldVerdict.TARGET_NOT_FOUND
        assert outcome.discovered_ap is None
