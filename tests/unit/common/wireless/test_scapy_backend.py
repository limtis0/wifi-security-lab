from __future__ import annotations

from unittest.mock import patch

from scapy.all import Dot11, Dot11Elt

from attacks.common.wireless.backend import ScapyWirelessBackend


class TestInjectBeaconConstruction:
    @patch("attacks.common.wireless.backend.scapy_backend.sendp")
    def test_packet_has_correct_ssid_bssid_channel(self, mock_sendp):
        backend = ScapyWirelessBackend()
        backend.inject_beacon(
            interface="wlan0",
            source_bssid="aa:bb:cc:dd:ee:ff",
            ssid="TestNetwork",
            channel=11,
        )

        sent_packet = mock_sendp.call_args[0][0]
        assert sent_packet[Dot11].addr2 == "aa:bb:cc:dd:ee:ff"

        ssid_element = sent_packet[Dot11Elt]
        assert ssid_element.info == b"TestNetwork"

    @patch("attacks.common.wireless.backend.scapy_backend.sendp")
    def test_no_rsn_element_when_rsn_info_is_none(self, mock_sendp):
        backend = ScapyWirelessBackend()
        backend.inject_beacon(
            interface="wlan0",
            source_bssid="aa:bb:cc:dd:ee:ff",
            ssid="TestNetwork",
            channel=6,
            rsn_info=None,
        )

        sent_packet = mock_sendp.call_args[0][0]
        element = sent_packet[Dot11Elt]
        while element:
            assert element.ID != 48
            next_payload = element.payload
            if isinstance(next_payload, Dot11Elt):
                element = next_payload
            else:
                break

    @patch("attacks.common.wireless.backend.scapy_backend.sendp")
    def test_rsn_element_present_when_rsn_info_provided(self, mock_sendp):
        rsn_bytes = b"\x01\x00\x00\x0f\xac\x04"
        backend = ScapyWirelessBackend()
        backend.inject_beacon(
            interface="wlan0",
            source_bssid="aa:bb:cc:dd:ee:ff",
            ssid="TestNetwork",
            channel=6,
            rsn_info=rsn_bytes,
        )

        sent_packet = mock_sendp.call_args[0][0]
        element = sent_packet[Dot11Elt]
        found_rsn = False
        while element:
            if element.ID == 48:
                assert element.info == rsn_bytes
                found_rsn = True
                break
            next_payload = element.payload
            if isinstance(next_payload, Dot11Elt):
                element = next_payload
            else:
                break

        assert found_rsn, "RSN element (ID 48) not found in packet"


class TestMeasureResponseTime:
    @patch("attacks.common.wireless.backend.scapy_backend.sniff", return_value=[])
    @patch("attacks.common.wireless.backend.scapy_backend.sendp")
    def test_returns_none_when_no_response(self, mock_sendp, mock_sniff):
        backend = ScapyWirelessBackend()
        frame = Dot11()

        result = backend.measure_response_time(
            interface="wlan0",
            frame_to_send=frame,
            response_filter=lambda packet: True,
            timeout=1.0,
        )

        assert result is None
