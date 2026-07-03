#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
VENV_DIR="/opt/wifi-lab-venv"

WIFI_LAB_LOG_PREFIX="vm-venv"
source "${PROJECT_DIR}/images/base/lib.sh"

if [ -d "${VENV_DIR}" ] && [ -x "${VENV_DIR}/bin/python" ]; then
    log_info "VM venv already exists at ${VENV_DIR}, updating"
else
    log_info "Creating VM venv at ${VENV_DIR}"
    python3 -m venv "${VENV_DIR}"
fi

log_info "Installing attack package and test dependencies"
"${VENV_DIR}/bin/pip" install --quiet -e "${PROJECT_DIR}"
"${VENV_DIR}/bin/pip" install --quiet docker pytest

log_info "VM venv ready at ${VENV_DIR}"
