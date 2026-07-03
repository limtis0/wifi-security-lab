from __future__ import annotations

import random
from dataclasses import dataclass, field

from attacks.common.models import APInfo
from attacks.common.wireless.backend import WirelessBackend
from attacks.common.wireless.sae_crypto import sae_hash_to_element_iteration_count


@dataclass
class MockWirelessBackend(WirelessBackend):
    ap_config: APInfo = field(default_factory=lambda: APInfo(
        bssid="00:11:22:33:44:55",
        ssid="DragonbloodLab",
        channel=6,
        capabilities=["RSN"],
    ))
    response_time_ns_range: tuple[int, int] = (400_000, 600_000)
    response_drop_rate: float = 0.0
    handshake_capture_count: int = 0
    injected_frames: list = field(default_factory=list)
    channel_changes: list[int] = field(default_factory=list)
    monitor_mode_interfaces: list[str] = field(default_factory=list)

    def scan_for_ap(self, interface: str, target_ssid: str, timeout: float = 10.0) -> APInfo | None:
        if target_ssid == self.ap_config.ssid:
            return self.ap_config
        return None

    def set_channel(self, interface: str, channel: int) -> None:
        self.channel_changes.append(channel)

    def set_monitor_mode(self, interface: str) -> None:
        self.monitor_mode_interfaces.append(interface)

    def inject_frame(self, interface: str, frame) -> None:
        self.injected_frames.append(("frame", interface, frame))

    def inject_beacon(
        self,
        interface: str,
        source_bssid: str,
        ssid: str,
        channel: int,
        rsn_info: bytes | None = None,
    ) -> None:
        self.injected_frames.append(("beacon", source_bssid, ssid, channel))

    def measure_response_time(
        self,
        interface: str,
        frame_to_send,
        response_filter,
        timeout: float = 5.0,
    ) -> int | None:
        if random.random() < self.response_drop_rate:
            return None
        return random.randint(*self.response_time_ns_range)

    def sniff_handshakes(
        self,
        interface: str,
        target_bssid: str,
        timeout: float = 30.0,
    ) -> list:
        return [b"fake_handshake"] * self.handshake_capture_count


@dataclass
class VulnerableMockBackend(MockWirelessBackend):
    target_password: str = "dr4gonfly"
    nanoseconds_per_iteration: int = 500_000
    timing_noise_std_ns: int = 50_000

    def measure_response_time(
        self,
        interface: str,
        frame_to_send,
        response_filter,
        timeout: float = 5.0,
    ) -> int | None:
        if random.random() < self.response_drop_rate:
            return None

        source_mac = self._extract_source_mac(frame_to_send)
        iteration_count = sae_hash_to_element_iteration_count(
            self.target_password,
            self.ap_config.bssid,
            source_mac,
        )

        base_time_ns = iteration_count * self.nanoseconds_per_iteration
        noise_ns = int(random.gauss(0, self.timing_noise_std_ns))
        return max(1, base_time_ns + noise_ns)

    def _extract_source_mac(self, frame) -> str:
        try:
            from scapy.all import Dot11
            if hasattr(frame, "haslayer") and frame.haslayer(Dot11):
                return frame[Dot11].addr2
        except ImportError:
            pass
        return "02:00:00:00:00:01"
