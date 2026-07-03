from __future__ import annotations

from tests.e2e.conftest import container_exec


class TestTimingAttackRun:
    def test_attack_exits_without_crash(self, attacker_container, ap_bssid):
        exit_code, output = container_exec(
            attacker_container,
            f"timing-attack --interface wlan2 --bssid {ap_bssid} --channel 6 --samples 10 --output-dir /results",
        )
        assert exit_code in (0, 1), f"Unexpected exit code {exit_code}: {output}"


class TestTimingAttackOutput:
    def test_produces_raw_csv(self, attacker_container):
        exit_code, _ = container_exec(
            attacker_container,
            "sh -c 'ls /results/dragonblood-timing/*/raw_samples.csv'",
        )
        assert exit_code == 0

    def test_csv_has_data_rows(self, attacker_container):
        exit_code, output = container_exec(
            attacker_container,
            "sh -c 'wc -l /results/dragonblood-timing/*/raw_samples.csv'",
        )
        assert exit_code == 0
        row_count = int(output.strip().split()[0])
        assert row_count > 1

    def test_produces_analysis_json(self, attacker_container):
        exit_code, _ = container_exec(
            attacker_container,
            "sh -c 'ls /results/dragonblood-timing/*/analysis.json'",
        )
        assert exit_code == 0

    def test_produces_metadata_json(self, attacker_container):
        exit_code, _ = container_exec(
            attacker_container,
            "sh -c 'ls /results/dragonblood-timing/*/metadata.json'",
        )
        assert exit_code == 0

    def test_produces_plots(self, attacker_container):
        exit_code, output = container_exec(
            attacker_container,
            "sh -c 'ls /results/dragonblood-timing/*/plots/*.png'",
        )
        assert exit_code == 0
        plot_files = [line for line in output.strip().splitlines() if line.endswith(".png")]
        assert len(plot_files) >= 3
