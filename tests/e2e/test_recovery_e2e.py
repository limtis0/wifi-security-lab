from __future__ import annotations

import json

from tests.e2e.conftest import container_exec


class TestRecoveryAttackRun:
    def test_attack_exits_successfully(self, attacker_container, ap_bssid):
        exit_code, output = container_exec(
            attacker_container,
            f"recovery-attack --dry-run --interface wlan2 --bssid {ap_bssid} --channel 6 "
            f"--samples 200 --max-macs 15 "
            f"--dictionary /opt/attacks/dragonblood/rockyou_100k.txt "
            f"--output-dir /results",
        )
        assert exit_code == 0, f"Attack failed with exit code {exit_code}: {output}"


class TestRecoveryAttackOutput:
    def test_produces_analysis_json(self, attacker_container):
        exit_code, _ = container_exec(
            attacker_container,
            "sh -c 'ls /results/dragonblood-recovery/*/analysis.json'",
        )
        assert exit_code == 0

    def test_produces_metadata_json(self, attacker_container):
        exit_code, _ = container_exec(
            attacker_container,
            "sh -c 'ls /results/dragonblood-recovery/*/metadata.json'",
        )
        assert exit_code == 0

    def test_recovers_correct_password(self, attacker_container):
        exit_code, output = container_exec(
            attacker_container,
            "sh -c 'cat /results/dragonblood-recovery/*/analysis.json'",
        )
        assert exit_code == 0
        report = json.loads(output)
        assert report["metadata"]["recovered_password"] == "dr4gonfly"
