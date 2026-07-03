#!/usr/bin/env bash
# Shared shell utilities for all container entrypoints.
# Source this file: source /usr/local/lib/wifi-lab/lib.sh

set -euo pipefail

WIFI_LAB_LOG_PREFIX="${WIFI_LAB_LOG_PREFIX:-wifi-lab}"
WIFI_LAB_IFACE_TIMEOUT="${WIFI_LAB_IFACE_TIMEOUT:-30}"

log_info() {
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [${WIFI_LAB_LOG_PREFIX}] [INFO] $*"
}

log_error() {
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [${WIFI_LAB_LOG_PREFIX}] [ERROR] $*" >&2
}

log_warn() {
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [${WIFI_LAB_LOG_PREFIX}] [WARN] $*" >&2
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Wait for a wireless interface to become available.
# Usage: wait_for_interface <interface_name> [timeout_seconds]
wait_for_interface() {
    local interface_name="$1"
    local timeout="${2:-${WIFI_LAB_IFACE_TIMEOUT}}"
    local elapsed=0

    log_info "Waiting for interface ${interface_name} (timeout: ${timeout}s)"

    while ! ip link show "${interface_name}" &>/dev/null; do
        if [ "${elapsed}" -ge "${timeout}" ]; then
            log_error "Timed out waiting for interface ${interface_name} after ${timeout}s"
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    log_info "Interface ${interface_name} is available"
}

# Configure an IP address on an interface.
# Usage: configure_ip <interface> <ip_address_cidr>
configure_ip() {
    local interface="$1"
    local ip_address="$2"

    ip link set "${interface}" up
    ip addr add "${ip_address}" dev "${interface}"
    log_info "Configured ${interface} with ${ip_address}"
}

# Put an interface into monitor mode.
# Usage: enable_monitor_mode <interface>
enable_monitor_mode() {
    local interface="$1"

    ip link set "${interface}" down
    iw dev "${interface}" set type monitor
    ip link set "${interface}" up
    log_info "Enabled monitor mode on ${interface}"
}
