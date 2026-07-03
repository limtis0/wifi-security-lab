#!/usr/bin/env bash
set -euo pipefail

source /usr/local/lib/wifi-lab/lib.sh
WIFI_LAB_LOG_PREFIX="ap"

IFACE="${IFACE:-wlan0}"
IP_ADDR="${IP_ADDR:-192.168.42.1/24}"
HOSTAPD_CONF="${HOSTAPD_CONF:-/etc/hostapd/hostapd_sae.conf}"

wait_for_interface "${IFACE}"
configure_ip "${IFACE}" "${IP_ADDR}"

# Start dnsmasq as a lightweight DHCP server
log_info "Starting dnsmasq DHCP server"
dnsmasq \
    --interface="${IFACE}" \
    --dhcp-range=192.168.42.10,192.168.42.50,24h \
    --no-daemon &
DNSMASQ_PID=$!

trap 'kill ${DNSMASQ_PID} 2>/dev/null || true' EXIT

log_info "Starting hostapd with config ${HOSTAPD_CONF}"
exec hostapd "${HOSTAPD_CONF}"
