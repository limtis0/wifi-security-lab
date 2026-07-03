#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

WIFI_LAB_LOG_PREFIX="teardown"
source "${PROJECT_DIR}/images/base/lib.sh"

main() {
    log_info "=== Wi-Fi Security Lab — Teardown ==="

    require_root

    log_info "Stopping containers"
    cd "${PROJECT_DIR}"
    docker compose down 2>/dev/null || true

    log_info "Removing netem qdiscs"
    tc qdisc del dev hwsim0 root 2>/dev/null || true

    if lsmod | grep -q mac80211_hwsim; then
        log_info "Unloading mac80211_hwsim"
        modprobe -r mac80211_hwsim
    else
        log_info "mac80211_hwsim not loaded, skipping"
    fi

    log_info "=== Teardown complete ==="
}

main "$@"
