from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path

from .config import AttackConfig
from .models import AnalysisReport, RawResults, ReconResult
from .wireless.backend import WirelessBackend


class AttackPhase(Enum):
    RECON = "recon"
    EXECUTE = "execute"
    ANALYZE = "analyze"


class BaseAttack(ABC):
    def __init__(
        self,
        interface: str,
        target_bssid: str,
        target_ssid: str,
        output_dir: Path,
        backend: WirelessBackend,
    ):
        self.interface = interface
        self.target_bssid = target_bssid
        self.target_ssid = target_ssid
        self.output_dir = output_dir
        self.backend = backend
        self.logger = logging.getLogger(self.__class__.__name__)

    def recon(self) -> ReconResult:
        """Scan for the target AP and return its info."""
        ap_info = self.backend.scan_for_ap(self.interface, self.target_ssid)
        if ap_info is None:
            raise ConnectionError(
                f"Could not find AP with SSID {self.target_ssid}"
            )

        if "RSN" not in ap_info.capabilities:
            self.logger.warning("AP does not advertise RSN")

        if ap_info.channel is not None:
            self.backend.set_channel(self.interface, ap_info.channel)

        return ReconResult(
            bssid=ap_info.bssid,
            ssid=ap_info.ssid,
            channel=ap_info.channel or 0,
            capabilities=ap_info.capabilities,
        )

    @abstractmethod
    def execute(self, config: AttackConfig) -> RawResults:
        """Run the attack, collect raw data."""

    @abstractmethod
    def analyze(self, raw_results: RawResults) -> AnalysisReport:
        """Statistical analysis and visualization."""

    def run(self, config: AttackConfig) -> AnalysisReport:
        """Full pipeline: recon -> execute -> analyze."""
        if config.channel:
            self.logger.info("Setting channel %d before recon", config.channel)
            self.backend.set_channel(self.interface, config.channel)

        self.logger.info("Phase: %s", AttackPhase.RECON.value)
        recon_result = self.recon()
        self.logger.info(
            "Recon complete: BSSID=%s SSID=%s channel=%d capabilities=%s",
            recon_result.bssid,
            recon_result.ssid,
            recon_result.channel,
            recon_result.capabilities,
        )

        self.logger.info("Phase: %s", AttackPhase.EXECUTE.value)
        raw_results = self.execute(config)
        self.logger.info(
            "Execution complete: %d items collected",
            raw_results.item_count(),
        )

        self.logger.info("Phase: %s", AttackPhase.ANALYZE.value)
        report = self.analyze(raw_results)
        self.logger.info("Analysis complete: success=%s", report.success)

        return report
