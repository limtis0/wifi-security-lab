from __future__ import annotations

import json

from tests.e2e.conftest import container_exec


class TestDowngradeAttackRun:
    def test_attack_exits_without_crash(self, attacker_container, ap_bssid):
        exit_code, output = container_exec(
            attacker_container,
            f"downgrade-attack --interface wlan2 --bssid {ap_bssid} --channel 6 --duration 5 --output-dir /results",
        )
        assert exit_code in (0, 1), f"Unexpected exit code {exit_code}: {output}"


class TestDowngradeAttackOutput:
    def test_produces_analysis_json(self, attacker_container):
        exit_code, _ = container_exec(
            attacker_container,
            "sh -c 'ls /results/dragonblood-downgrade/*/analysis.json'",
        )
        assert exit_code == 0

    def test_produces_metadata_json(self, attacker_container):
        exit_code, _ = container_exec(
            attacker_container,
            "sh -c 'ls /results/dragonblood-downgrade/*/metadata.json'",
        )
        assert exit_code == 0

    def test_analysis_reports_capture_count(self, attacker_container):
        exit_code, output = container_exec(
            attacker_container,
            "sh -c 'cat /results/dragonblood-downgrade/*/analysis.json'",
        )
        assert exit_code == 0
        report = json.loads(output)
        assert report["metadata"]["captured_frame_count"] >= 0
