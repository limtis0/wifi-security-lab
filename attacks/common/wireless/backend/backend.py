from __future__ import annotations

from abc import ABC, abstractmethod

from attacks.common.models import APInfo


class WirelessBackend(ABC):
    @abstractmethod
    def scan_for_ap(self, interface: str, target_ssid: str, timeout: float = 10.0) -> APInfo | None:
        """Scan for an AP by SSID and return its info."""

    @abstractmethod
    def set_channel(self, interface: str, channel: int) -> None:
        """Tune a wireless interface to a specific channel."""

    @abstractmethod
    def set_monitor_mode(self, interface: str) -> None:
        """Put a wireless interface into monitor mode."""

    @abstractmethod
    def inject_frame(self, interface: str, frame) -> None:
        """Inject a raw 802.11 frame."""

    @abstractmethod
    def inject_beacon(
        self,
        interface: str,
        source_bssid: str,
        ssid: str,
        channel: int,
        rsn_info: bytes | None = None,
    ) -> None:
        """Inject a forged beacon frame."""

    @abstractmethod
    def measure_response_time(
        self,
        interface: str,
        frame_to_send,
        response_filter,
        timeout: float = 5.0,
    ) -> int | None:
        """Send a frame and measure response time in nanoseconds."""

    def send_deauth(
        self,
        interface: str,
        target_bssid: str,
        station_mac: str,
    ) -> None:
        """Send a deauthentication frame to reset station state on the AP."""

    @abstractmethod
    def sniff_handshakes(
        self,
        interface: str,
        target_bssid: str,
        timeout: float = 30.0,
    ) -> list:
        """Capture authentication frames from a target AP."""
