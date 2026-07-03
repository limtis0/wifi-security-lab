from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from attacks.common.base_attack import BaseAttack
from attacks.common.config import AttackConfig
from attacks.common.logging_setup import configure_logging
from attacks.common.wireless.backend import WirelessBackend

logger = logging.getLogger(__name__)


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--interface", required=True, help="Monitor-mode wireless interface")
    parser.add_argument("--bssid", required=True, help="Target AP BSSID")
    parser.add_argument("--ssid", default="DragonbloodLab", help="Target AP SSID")
    parser.add_argument("--channel", type=int, default=6, help="Wi-Fi channel")
    parser.add_argument("--output-dir", type=Path, default=Path("/results"), help="Output directory")
    parser.add_argument("--dry-run", action="store_true", help="Run with mock wireless backend (no real hardware needed)")
    parser.add_argument("--ns-per-iteration", type=int, default=500_000, help="Nanoseconds per iteration for mock backend (dry-run only)")


def create_backend(arguments: argparse.Namespace) -> WirelessBackend:
    if arguments.dry_run:
        from attacks.common.wireless.backend import MockWirelessBackend
        return MockWirelessBackend()

    from attacks.common.wireless.backend import ScapyWirelessBackend
    return ScapyWirelessBackend()


def run_attack(attack_name: str, attack: BaseAttack, config: AttackConfig) -> None:
    configure_logging(attack_name, output_dir=attack.output_dir)
    report = attack.run(config)
    logger.info("Attack complete: %s", report.summary)
    sys.exit(0 if report.success else 1)
