from __future__ import annotations

import docker
import pytest

pytestmark = pytest.mark.e2e


def container_exec(container, command: str) -> tuple[int, str]:
    """Run command in container, return (exit_code, stdout_str)."""
    exit_code, output = container.exec_run(command)
    return exit_code, output.decode()


@pytest.fixture(scope="session")
def docker_client():
    return docker.from_env()


@pytest.fixture(scope="session")
def ap_container(docker_client):
    return docker_client.containers.get("wifi-lab-ap")


@pytest.fixture(scope="session")
def client_container(docker_client):
    return docker_client.containers.get("wifi-lab-client")


@pytest.fixture(scope="session")
def attacker_container(docker_client):
    return docker_client.containers.get("wifi-lab-attacker")


@pytest.fixture(scope="session")
def ap_bssid(ap_container):
    exit_code, output = container_exec(ap_container, "hostapd_cli -i wlan0 status")
    assert exit_code == 0, f"hostapd_cli failed: {output}"
    for line in output.splitlines():
        if line.startswith("bssid[0]="):
            return line.split("=", 1)[1]
        if line.startswith("bssid="):
            return line.split("=", 1)[1]
    pytest.fail("Could not extract BSSID from hostapd_cli status")


@pytest.fixture(scope="session", autouse=True)
def clean_previous_results(attacker_container):
    """Remove old results before running e2e tests."""
    attacker_container.exec_run("sh -c 'rm -rf /results/dragonblood-timing /results/dragonblood-downgrade'")
