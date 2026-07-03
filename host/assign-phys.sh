#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
ENV_FILE="${PROJECT_DIR}/.env"

WIFI_LAB_LOG_PREFIX="assign-phys"
source "${PROJECT_DIR}/images/base/lib.sh"

require_root

if [ ! -f "${ENV_FILE}" ]; then
    log_error ".env not found at ${ENV_FILE}. Run 'make setup' first."
    exit 1
fi

source "${ENV_FILE}"

for required_variable in AP_PHY CLIENT_PHY ATTACKER_PHY; do
    if [ -z "${!required_variable:-}" ]; then
        log_error "${required_variable} not set in .env. Run 'make setup' to regenerate."
        exit 1
    fi
done

wait_for_container() {
    local container_name="$1"
    local max_wait=15
    local elapsed=0

    while [ "${elapsed}" -lt "${max_wait}" ]; do
        local container_pid
        container_pid=$(docker inspect --format '{{.State.Pid}}' "${container_name}" 2>/dev/null || echo "0")
        if [ "${container_pid}" != "0" ] && [ -n "${container_pid}" ]; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    log_error "Container '${container_name}' not running after ${max_wait}s. Run 'make up' first."
    return 1
}

assign_phy_to_container() {
    local container_name="$1"
    local phy_name="$2"

    wait_for_container "${container_name}" || return 1

    local container_pid
    container_pid=$(docker inspect --format '{{.State.Pid}}' "${container_name}" 2>/dev/null)

    log_info "Assigning ${phy_name} to ${container_name} (PID ${container_pid})"
    iw phy "${phy_name}" set netns "${container_pid}"
    log_info "Successfully assigned ${phy_name} to ${container_name}"
}

assign_phy_to_container "wifi-lab-ap" "${AP_PHY}" || exit 1
assign_phy_to_container "wifi-lab-client" "${CLIENT_PHY}" || exit 1
assign_phy_to_container "wifi-lab-attacker" "${ATTACKER_PHY}" || exit 1

log_info "All phys assigned"
