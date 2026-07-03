from __future__ import annotations

from tests.e2e.conftest import container_exec


class TestContainersRunning:
    def test_ap_running(self, ap_container):
        ap_container.reload()
        assert ap_container.status == "running"

    def test_client_running(self, client_container):
        client_container.reload()
        assert client_container.status == "running"

    def test_attacker_running(self, attacker_container):
        attacker_container.reload()
        assert attacker_container.status == "running"


class TestServices:
    def test_hostapd_running(self, ap_container):
        exit_code, _ = container_exec(ap_container, "pgrep hostapd")
        assert exit_code == 0

    def test_wpa_supplicant_running(self, client_container):
        exit_code, _ = container_exec(client_container, "pgrep wpa_supplicant")
        assert exit_code == 0


class TestWirelessConnectivity:
    def test_client_associated_via_sae(self, client_container):
        exit_code, output = container_exec(client_container, "wpa_cli -i wlan1 status")
        assert exit_code == 0
        assert "wpa_state=COMPLETED" in output

    def test_client_can_ping_ap(self, client_container):
        exit_code, _ = container_exec(client_container, "ping -c 1 -W 2 192.168.42.1")
        assert exit_code == 0

    def test_attacker_monitor_mode(self, attacker_container):
        exit_code, output = container_exec(attacker_container, "iw dev wlan2 info")
        assert exit_code == 0
        assert "type monitor" in output
