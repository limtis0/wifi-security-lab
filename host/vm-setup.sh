#!/usr/bin/env bash
set -euo pipefail

VM_NAME="wifi-lab"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
LIMA_CONFIG="${PROJECT_DIR}/lima/wifi-lab.yaml"

WIFI_LAB_LOG_PREFIX="vm-setup"
source "${PROJECT_DIR}/images/base/lib.sh"

if ! command -v limactl &>/dev/null; then
    log_error "Lima is not installed. Install with: brew install lima"
    exit 1
fi

# Create VM if it doesn't exist
if ! limactl list --format '{{.Name}}' 2>/dev/null | grep -q "^${VM_NAME}$"; then
    log_info "Creating VM '${VM_NAME}' from ${LIMA_CONFIG}"
    limactl start --name="${VM_NAME}" "${LIMA_CONFIG}"
else
    local_status=$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | awk -v vm="${VM_NAME}" '$1 == vm {print $2}')
    if [ "${local_status}" != "Running" ]; then
        log_info "Starting stopped VM '${VM_NAME}'"
        limactl start "${VM_NAME}"
    else
        log_info "VM '${VM_NAME}' already running"
    fi
fi

# Post-start verification
log_info "Verifying VM..."

if ! limactl shell "${VM_NAME}" sudo docker info --format '{{.ServerVersion}}' &>/dev/null; then
    log_error "Docker is not accessible inside the VM"
    exit 1
fi
log_info "Docker OK"

if ! limactl shell "${VM_NAME}" sudo modinfo mac80211_hwsim &>/dev/null; then
    log_error "mac80211_hwsim kernel module not available in VM"
    exit 1
fi
log_info "mac80211_hwsim OK"

if ! limactl shell "${VM_NAME}" bash -c "test -w '${PROJECT_DIR}'" &>/dev/null; then
    log_error "Project directory is not writable inside the VM"
    exit 1
fi
log_info "Writable mount OK"

log_info "VM '${VM_NAME}' ready"
