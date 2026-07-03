#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

WIFI_LAB_LOG_PREFIX="netem"
source "${PROJECT_DIR}/images/base/lib.sh"

HWSIM_IFACE="${HWSIM_IFACE:-hwsim0}"
PROFILE="${1:-}"

usage() {
    cat <<EOF
Usage: $(basename "$0") <profile>

Profiles:
  clean   — Remove all netem rules (no added delay/loss)
  mild    — 5ms delay +/- 2ms, normal distribution
  noisy   — 20ms delay +/- 15ms, 1% packet loss, normal distribution
  custom  — Set via NETEM_DELAY, NETEM_JITTER, NETEM_LOSS env vars

Environment variables (for custom profile):
  NETEM_DELAY=10ms      Mean delay
  NETEM_JITTER=5ms      Delay variation
  NETEM_LOSS=0.5        Packet loss percentage
  HWSIM_IFACE=hwsim0   Interface to apply netem on
EOF
    exit 1
}

apply_clean() {
    tc qdisc del dev "${HWSIM_IFACE}" root 2>/dev/null || true
    log_info "Removed all netem rules from ${HWSIM_IFACE}"
}

apply_netem() {
    local delay="$1"
    local jitter="$2"
    local loss="$3"

    tc qdisc del dev "${HWSIM_IFACE}" root 2>/dev/null || true
    tc qdisc add dev "${HWSIM_IFACE}" root netem \
        delay "${delay}" "${jitter}" distribution normal \
        loss "${loss}%"

    log_info "Applied netem on ${HWSIM_IFACE}: delay=${delay} jitter=${jitter} loss=${loss}%"
}

if [ -z "${PROFILE}" ]; then
    usage
fi

require_root

case "${PROFILE}" in
    clean)
        apply_clean
        ;;
    mild)
        apply_netem "5ms" "2ms" "0"
        ;;
    noisy)
        apply_netem "20ms" "15ms" "1"
        ;;
    custom)
        apply_netem "${NETEM_DELAY:-10ms}" "${NETEM_JITTER:-5ms}" "${NETEM_LOSS:-0}"
        ;;
    *)
        log_info "Unknown profile: ${PROFILE}"
        usage
        ;;
esac
