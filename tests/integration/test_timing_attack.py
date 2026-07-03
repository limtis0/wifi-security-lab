from __future__ import annotations

from pathlib import Path

from attacks.common.config import TimingAttackConfig
from attacks.common.wireless.backend import MockWirelessBackend
from attacks.dragonblood.timing_sidechannel import TimingSideChannelAttack


def make_timing_attack(
    output_dir: Path,
    backend: MockWirelessBackend | None = None,
) -> TimingSideChannelAttack:
    if backend is None:
        backend = MockWirelessBackend()
    return TimingSideChannelAttack(
        interface="wlan0",
        target_bssid="00:11:22:33:44:55",
        target_ssid="DragonbloodLab",
        output_dir=output_dir,
        backend=backend,
    )


class TestTimingExecute:
    def test_collects_correct_sample_count(self, tmp_path: Path):
        backend = MockWirelessBackend(response_time_ns_range=(500_000, 500_000))
        attack = make_timing_attack(tmp_path, backend)
        config = TimingAttackConfig(
            target_bssid="00:11:22:33:44:55",
            samples_per_group=5,
            password_groups=["short", "long"],
            inter_sample_delay_ms=0,
        )

        results = attack.execute(config)

        assert len(results.samples) == 10
        short_samples = [sample for sample in results.samples if sample.password_group == "short"]
        long_samples = [sample for sample in results.samples if sample.password_group == "long"]
        assert len(short_samples) == 5
        assert len(long_samples) == 5

    def test_handles_dropped_responses(self, tmp_path: Path):
        backend = MockWirelessBackend(response_drop_rate=1.0)
        attack = make_timing_attack(tmp_path, backend)
        config = TimingAttackConfig(
            target_bssid="00:11:22:33:44:55",
            samples_per_group=5,
            inter_sample_delay_ms=0,
        )

        results = attack.execute(config)

        assert len(results.samples) == 0

    def test_samples_have_correct_response_time_range(self, tmp_path: Path):
        backend = MockWirelessBackend(response_time_ns_range=(100, 200))
        attack = make_timing_attack(tmp_path, backend)
        config = TimingAttackConfig(
            target_bssid="00:11:22:33:44:55",
            samples_per_group=10,
            password_groups=["group_a"],
            inter_sample_delay_ms=0,
        )

        results = attack.execute(config)

        for sample in results.samples:
            assert 100 <= sample.response_time_ns <= 200


class TestTimingAnalyze:
    def test_produces_csv_and_plots(self, tmp_path: Path):
        attack = make_timing_attack(tmp_path)
        config = TimingAttackConfig(
            target_bssid="00:11:22:33:44:55",
            samples_per_group=20,
            password_groups=["group_a", "group_b"],
            inter_sample_delay_ms=0,
        )

        raw_results = attack.execute(config)
        report = attack.analyze(raw_results)

        assert report.raw_csv_path.exists()
        assert len(report.plots) == 3
        for plot_path in report.plots:
            assert plot_path.exists()

    def test_report_contains_group_statistics(self, tmp_path: Path):
        attack = make_timing_attack(tmp_path)
        config = TimingAttackConfig(
            target_bssid="00:11:22:33:44:55",
            samples_per_group=10,
            password_groups=["alpha", "beta"],
            inter_sample_delay_ms=0,
        )

        raw_results = attack.execute(config)
        report = attack.analyze(raw_results)

        assert "alpha" in report.metadata["group_statistics"]
        assert "beta" in report.metadata["group_statistics"]


class TestTimingFullPipeline:
    def test_run_produces_complete_output(self, tmp_path: Path):
        backend = MockWirelessBackend()
        attack = make_timing_attack(tmp_path, backend)
        config = TimingAttackConfig(
            target_bssid="00:11:22:33:44:55",
            samples_per_group=10,
            password_groups=["short", "long"],
            inter_sample_delay_ms=0,
        )

        report = attack.run(config)

        assert report.attack_name == "dragonblood-timing"
        assert report.raw_csv_path.exists()
        assert backend.channel_changes == [6, 6]
