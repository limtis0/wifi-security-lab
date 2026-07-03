#!/usr/bin/env bash
set -euo pipefail

source /usr/local/lib/wifi-lab/lib.sh
WIFI_LAB_LOG_PREFIX="client"

IFACE="${IFACE:-wlan1}"
IP_ADDR="${IP_ADDR:-192.168.42.2/24}"
WPA_SUPPLICANT_CONF="${WPA_SUPPLICANT_CONF:-/etc/wpa_supplicant/wpa_supplicant_sae.conf}"

wait_for_interface "${IFACE}"

WPA_PID_FILE="/var/run/wpa_supplicant.pid"

log_info "Starting wpa_supplicant with config ${WPA_SUPPLICANT_CONF}"
wpa_supplicant -i "${IFACE}" -c "${WPA_SUPPLICANT_CONF}" -B -P "${WPA_PID_FILE}"

trap 'kill "$(cat "${WPA_PID_FILE}" 2>/dev/null)" 2>/dev/null || true' EXIT

# Wait for association
log_info "Waiting for SAE association"
max_attempts=30
attempt=0
while ! wpa_cli -i "${IFACE}" status 2>/dev/null | grep -q "wpa_state=COMPLETED"; do
    if [ "${attempt}" -ge "${max_attempts}" ]; then
        log_error "Failed to associate after ${max_attempts} attempts"
        wpa_cli -i "${IFACE}" status
        exit 1
    fi
    sleep 1
    attempt=$((attempt + 1))
done

log_info "Associated with AP via SAE"

configure_ip "${IFACE}" "${IP_ADDR}"

log_info "Client ready"

# Keep container alive
exec tail -f /dev/null
