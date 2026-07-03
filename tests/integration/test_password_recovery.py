from __future__ import annotations

from pathlib import Path

from attacks.common.config import PasswordRecoveryConfig
from attacks.common.wireless.backend import VulnerableMockBackend
from attacks.dragonblood.password_recovery import PasswordRecoveryAttack


SMALL_DICTIONARY = [
    "password123", "letmein", "admin2024", "wifi_secure",
    "hunter2", "12345678", "monkey", "master",
    "dragon", "qwerty", "abc123", "trustno1",
    "iloveyou", "sunshine", "princess", "football",
    "shadow", "michael", "jennifer", "dr4gonfly",
]

MOCK_BSSID = "00:11:22:33:44:55"


def make_recovery_attack(
    output_dir: Path,
    backend: VulnerableMockBackend | None = None,
) -> PasswordRecoveryAttack:
    if backend is None:
        backend = VulnerableMockBackend()
    return PasswordRecoveryAttack(
        interface="wlan0",
        target_bssid=MOCK_BSSID,
        target_ssid="DragonbloodLab",
        output_dir=output_dir,
        backend=backend,
    )


def make_recovery_config(**overrides) -> PasswordRecoveryConfig:
    defaults = {
        "target_bssid": MOCK_BSSID,
        "samples_per_group": 50,
        "inter_sample_delay_ms": 0,
        "dictionary_words": SMALL_DICTIONARY,
        "max_mac_addresses": 15,
    }
    defaults.update(overrides)
    return PasswordRecoveryConfig(**defaults)


class TestPasswordRecoveryExecute:
    def test_collects_samples_for_multiple_macs(self, tmp_path: Path):
        backend = VulnerableMockBackend()
        attack = make_recovery_attack(tmp_path, backend)
        config = make_recovery_config(max_mac_addresses=3, samples_per_group=10)

        results = attack.execute(config)

        assert results.item_count() == 30
        mac_groups = {sample.password_group for sample in results.samples}
        assert len(mac_groups) == 3


class TestPasswordRecoveryAnalyze:
    def test_recovers_correct_password(self, tmp_path: Path):
        backend = VulnerableMockBackend(target_password="dr4gonfly")
        attack = make_recovery_attack(tmp_path, backend)
        config = make_recovery_config(samples_per_group=100)

        attack._recovery_config = config
        raw_results = attack.execute(config)
        report = attack.analyze(raw_results)

        assert report.success is True
        assert report.metadata["recovered_password"] == "dr4gonfly"

    def test_reports_failure_with_empty_dictionary(self, tmp_path: Path):
        backend = VulnerableMockBackend(target_password="dr4gonfly")
        attack = make_recovery_attack(tmp_path, backend)
        config = make_recovery_config(
            samples_per_group=50,
            dictionary_words=["xyzzy_no_match_aaa", "xyzzy_no_match_bbb", "xyzzy_no_match_ccc"],
            max_mac_addresses=15,
        )

        attack._recovery_config = config
        raw_results = attack.execute(config)
        report = attack.analyze(raw_results)

        assert report.success is False
        assert report.metadata["recovered_password"] is None


class TestPasswordRecoveryFullPipeline:
    def test_run_produces_complete_output(self, tmp_path: Path):
        backend = VulnerableMockBackend(target_password="dr4gonfly")
        attack = make_recovery_attack(tmp_path, backend)
        config = make_recovery_config(samples_per_group=100)

        report = attack.run(config)

        assert report.attack_name == "dragonblood-recovery"
        assert report.success is True
        assert report.metadata["recovered_password"] == "dr4gonfly"
        assert report.raw_csv_path.exists()
        assert len(report.plots) == 3
        assert report.metadata["dictionary_size"] == len(SMALL_DICTIONARY)
