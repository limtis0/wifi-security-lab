from __future__ import annotations

import logging

from attacks.common.models import APInfo
from attacks.common.wireless.backend import WirelessBackend

logger = logging.getLogger(__name__)

DEFAULT_CHANNELS = [1, 6, 11]


def sweep_for_ap(
    backend: WirelessBackend,
    interface: str,
    target_ssid: str,
    channels: list[int],
    dwell_seconds: float = 3.0,
) -> APInfo | None:
    """Find an AP by SSID by tuning through a list of channels.

    In the emulated lab the AP sits on a known fixed channel, but a real AP can
    be on any channel, so we tune to each candidate channel and listen for the
    target beacon. Returns the first matching AP, or None if none is seen on any
    channel. Backend-agnostic: works with the real Scapy backend or a mock.
    """
    for channel in channels:
        logger.info("Sweeping channel %d for SSID '%s'", channel, target_ssid)
        backend.set_channel(interface, channel)
        ap_info = backend.scan_for_ap(interface, target_ssid, timeout=dwell_seconds)
        if ap_info is not None:
            logger.info(
                "Found '%s' on channel %d (BSSID %s)",
                target_ssid,
                ap_info.channel if ap_info.channel is not None else channel,
                ap_info.bssid,
            )
            return ap_info

    logger.warning(
        "SSID '%s' not found after sweeping %d channels", target_ssid, len(channels)
    )
    return None
