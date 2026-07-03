#!/usr/bin/env bash
set -euo pipefail

source /usr/local/lib/wifi-lab/lib.sh
WIFI_LAB_LOG_PREFIX="attacker"

IFACE="${IFACE:-wlan2}"
PHY="${PHY:-phy2}"
ATTACK_CMD="${ATTACK_CMD:-}"
JUPYTER="${JUPYTER:-false}"

wait_for_interface "${IFACE}"
enable_monitor_mode "${IFACE}"

log_info "Attacker interface ready in monitor mode"

if [ "${JUPYTER}" = "true" ]; then
    log_info "Starting Jupyter notebook on port 8888"
    exec jupyter notebook \
        --ip=0.0.0.0 \
        --port=8888 \
        --no-browser \
        --allow-root \
        --notebook-dir=/opt/notebooks
fi

if [ -n "${ATTACK_CMD}" ]; then
    log_info "Running attack: ${ATTACK_CMD}"
    exec sh -c "${ATTACK_CMD}"
fi

log_info "No ATTACK_CMD set — dropping to interactive shell"
exec /bin/bash
