#!/usr/bin/env bash
set -euo pipefail

VM_NAME="wifi-lab"

if [ $# -eq 0 ]; then
    echo "Usage: $(basename "$0") <command>"
    echo "Runs a command as root inside the wifi-lab Lima VM."
    exit 1
fi

if ! limactl list --format '{{.Name}}' 2>/dev/null | grep -q "^${VM_NAME}$"; then
    echo "[vm-exec] ERROR: VM '${VM_NAME}' does not exist. Run host/vm-setup.sh first." >&2
    exit 1
fi

limactl shell "${VM_NAME}" sudo bash -c "export PATH=/opt/wifi-lab-venv/bin:\$PATH; $*"
