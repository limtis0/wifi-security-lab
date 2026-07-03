#!/usr/bin/env bash
set -euo pipefail

VM_NAME="wifi-lab"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

WIFI_LAB_LOG_PREFIX="vm-teardown"
source "${PROJECT_DIR}/images/base/lib.sh"

if ! command -v limactl &>/dev/null; then
    log_info "Lima not installed, nothing to do"
    exit 0
fi

if limactl list --format '{{.Name}}' 2>/dev/null | grep -q "^${VM_NAME}$"; then
    log_info "Stopping and deleting VM '${VM_NAME}'"
    limactl stop "${VM_NAME}" 2>/dev/null || true
    limactl delete "${VM_NAME}"

    log_info "VM '${VM_NAME}' deleted"
else
    log_info "VM '${VM_NAME}' does not exist"
fi
