from __future__ import annotations

from attacks.common.wireless.backend import MockWirelessBackend
from attacks.common.wireless.discovery import sweep_for_ap

from tests.conftest import make_ap_info


class TestSweepForAp:
    def test_finds_ap_on_swept_channel(self):
        backend = MockWirelessBackend(
            ap_config=make_ap_info(ssid="HomeWiFi", channel=11)
        )

        result = sweep_for_ap(backend, "wlan0", "HomeWiFi", channels=[1, 6, 11])

        assert result is not None
        assert result.ssid == "HomeWiFi"

    def test_returns_none_when_ssid_absent(self):
        backend = MockWirelessBackend(
            ap_config=make_ap_info(ssid="SomeOtherNetwork")
        )

        result = sweep_for_ap(backend, "wlan0", "HomeWiFi", channels=[1, 6, 11])

        assert result is None

    def test_visits_channels_in_order(self):
        backend = MockWirelessBackend(
            ap_config=make_ap_info(ssid="NoSuchNetwork")
        )

        sweep_for_ap(backend, "wlan0", "HomeWiFi", channels=[1, 6, 11])

        assert backend.channel_changes == [1, 6, 11]

    def test_stops_sweeping_after_match(self):
        backend = MockWirelessBackend(
            ap_config=make_ap_info(ssid="HomeWiFi")
        )

        sweep_for_ap(backend, "wlan0", "HomeWiFi", channels=[1, 6, 11])

        assert len(backend.channel_changes) == 1
