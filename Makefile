SHELL := /bin/bash
.DEFAULT_GOAL := help

IS_LINUX := $(shell [ "$$(uname -s)" = "Linux" ] && echo 1 || echo 0)
VM_EXEC := host/vm-exec.sh
PROJECT_DIR := $(shell pwd)
PROFILE ?= clean

# --- Help ---

.PHONY: help
help:
	@echo "Wi-Fi Security Lab — Makefile Targets"
	@echo ""
	@echo "  Infrastructure:"
	@echo "    make vm              Create/start Lima VM (macOS only)"
	@echo "    make vm-teardown     Delete Lima VM"
	@echo "    make venv-vm         Create Python venv inside Lima VM (macOS only)"
	@echo "    make setup           Load mac80211_hwsim kernel module"
	@echo "    make build           Build Docker images"
	@echo "    make up              Full startup: VM (if macOS) + setup + build + run"
	@echo "    make down            Stop containers"
	@echo "    make teardown        Full teardown: containers + kernel module"
	@echo ""
	@echo "  Attacks:"
	@echo "    make attack-timing      Run Dragonblood timing side-channel"
	@echo "    make attack-downgrade   Run Dragonblood WPA3->WPA2 downgrade"
	@echo "    make attack-live IFACE=wlan0 SSID='Name' DICT=/path/wordlist.txt"
	@echo "                            Run against a REAL router (physical phase, bare-metal host)"
	@echo ""
	@echo "  Tools:"
	@echo "    make jupyter         Start Jupyter notebook on port 8888"
	@echo "    make shell-ap        Shell into AP container"
	@echo "    make shell-client    Shell into client container"
	@echo "    make shell-attacker  Shell into attacker container"
	@echo "    make netem PROFILE=noisy  Apply netem noise profile"
	@echo ""
	@echo "  Testing:"
	@echo "    make test            Run connectivity tests (requires running lab)"
	@echo "    make test-e2e        Run all e2e tests: starts lab + attacks (single command)"
	@echo "    make test-unit       Run Python unit + integration tests (local, no VM needed)"
	@echo ""

# --- VM (macOS only) ---

.PHONY: vm
vm:
ifeq ($(IS_LINUX),1)
	@echo "Already on Linux — no VM needed"
else
	host/vm-setup.sh
endif

.PHONY: vm-teardown
vm-teardown:
	host/vm-teardown.sh

.PHONY: venv-vm
venv-vm:
ifeq ($(IS_LINUX),1)
	@echo "On Linux — use local .venv instead"
else
	$(VM_EXEC) "$(PROJECT_DIR)/host/vm-venv.sh"
endif

# --- Infrastructure ---

.PHONY: setup
setup:
ifeq ($(IS_LINUX),1)
	sudo host/setup.sh
else
	$(VM_EXEC) "$(PROJECT_DIR)/host/setup.sh"
endif

.PHONY: build
build:
ifeq ($(IS_LINUX),1)
	docker compose build base
	docker compose build builder
	docker compose build
else
	$(VM_EXEC) "cd $(PROJECT_DIR) && docker compose build base && docker compose build builder && docker compose build"
endif

.PHONY: up
up: vm venv-vm setup build
ifeq ($(IS_LINUX),1)
	docker compose up -d
	sudo host/assign-phys.sh
else
	$(VM_EXEC) "cd $(PROJECT_DIR) && docker compose up -d"
	$(VM_EXEC) "$(PROJECT_DIR)/host/assign-phys.sh"
endif
	@echo ""
	@echo "Lab is running. Use 'make test' to verify connectivity."

.PHONY: up-e2e
up-e2e: vm venv-vm setup build
ifeq ($(IS_LINUX),1)
	COMPOSE_FILE=docker-compose.yml:docker-compose.downgrade.yml docker compose up -d
	sudo host/assign-phys.sh
else
	$(VM_EXEC) "cd $(PROJECT_DIR) && COMPOSE_FILE=docker-compose.yml:docker-compose.downgrade.yml docker compose up -d"
	$(VM_EXEC) "$(PROJECT_DIR)/host/assign-phys.sh"
endif
	@echo ""
	@echo "Lab is running in transition mode for e2e tests."

.PHONY: down
down:
ifeq ($(IS_LINUX),1)
	docker compose down
else
	$(VM_EXEC) "cd $(PROJECT_DIR) && docker compose down"
endif

.PHONY: teardown
teardown:
ifeq ($(IS_LINUX),1)
	sudo host/teardown.sh
else
	$(VM_EXEC) "$(PROJECT_DIR)/host/teardown.sh"
endif

# --- Attacks ---
# Usage: make run-attack CMD=timing-attack
# Convenience aliases below.

.PHONY: run-attack
run-attack:
ifndef CMD
	$(error CMD is required. Example: make run-attack CMD=timing-attack)
endif
ifeq ($(IS_LINUX),1)
	@BSSID=$$(docker exec wifi-lab-ap hostapd_cli -i wlan0 status 2>/dev/null | grep -oP 'bssid\[0\]=\K.*'); \
	if [ -z "$$BSSID" ]; then echo "ERROR: Could not get AP BSSID — is the lab running?"; exit 1; fi; \
	docker exec wifi-lab-attacker $(CMD) --interface wlan2 --bssid "$$BSSID" --output-dir /results $(ARGS)
else
	$(VM_EXEC) "BSSID=\$$(docker exec wifi-lab-ap hostapd_cli -i wlan0 status 2>/dev/null | grep -oP 'bssid\[0\]=\K.*'); \
	if [ -z \"\$$BSSID\" ]; then echo 'ERROR: Could not get AP BSSID'; exit 1; fi; \
	docker exec wifi-lab-attacker $(CMD) --interface wlan2 --bssid \"\$$BSSID\" --output-dir /results $(ARGS)"
endif

.PHONY: attack-timing
attack-timing:
	$(MAKE) run-attack CMD=timing-attack

.PHONY: attack-downgrade
attack-downgrade:
	$(MAKE) run-attack CMD=downgrade-attack

.PHONY: attack-recovery
attack-recovery:
	$(MAKE) run-attack CMD="recovery-attack --dictionary /opt/attacks/dragonblood/rockyou_100k.txt"

# Physical phase: run against a REAL router. Runs directly on a bare-metal Linux
# host with a monitor-mode-capable adapter — NOT via Docker or the Lima VM, which
# cannot reach physical Wi-Fi hardware.
# Usage: sudo make attack-live IFACE=wlan0 SSID='HomeWiFi' [DICT=/path/wordlist.txt]
DICT ?= attacks/dragonblood/rockyou_100k.txt

.PHONY: attack-live
attack-live:
	@if [ -z "$(IFACE)" ] || [ -z "$(SSID)" ]; then \
		echo "Usage: sudo make attack-live IFACE=wlan0 SSID='HomeWiFi' [DICT=/path/wordlist.txt]"; \
		exit 1; \
	fi
	sudo PYTHONPATH=. python -m attacks.dragonblood.live_recovery \
		--interface $(IFACE) --ssid "$(SSID)" --dictionary $(DICT) --output-dir results

# --- Tools ---

.PHONY: jupyter
jupyter:
ifeq ($(IS_LINUX),1)
	JUPYTER=true docker compose up attacker
else
	$(VM_EXEC) "cd $(PROJECT_DIR) && JUPYTER=true docker compose up attacker"
endif

.PHONY: shell-ap
shell-ap:
ifeq ($(IS_LINUX),1)
	docker exec -it wifi-lab-ap /bin/bash
else
	$(VM_EXEC) "docker exec -it wifi-lab-ap /bin/bash"
endif

.PHONY: shell-client
shell-client:
ifeq ($(IS_LINUX),1)
	docker exec -it wifi-lab-client /bin/bash
else
	$(VM_EXEC) "docker exec -it wifi-lab-client /bin/bash"
endif

.PHONY: shell-attacker
shell-attacker:
ifeq ($(IS_LINUX),1)
	docker exec -it wifi-lab-attacker /bin/bash
else
	$(VM_EXEC) "docker exec -it wifi-lab-attacker /bin/bash"
endif

.PHONY: netem
netem:
ifeq ($(IS_LINUX),1)
	sudo host/netem.sh $(PROFILE)
else
	$(VM_EXEC) "$(PROJECT_DIR)/host/netem.sh $(PROFILE)"
endif

# --- Testing ---

.PHONY: test
test:
ifeq ($(IS_LINUX),1)
	PYTHONPATH=. python -m pytest tests/e2e/test_connectivity_e2e.py -v
else
	$(VM_EXEC) "cd $(PROJECT_DIR) && PYTHONPATH=. python -m pytest tests/e2e/test_connectivity_e2e.py -v"
endif

.PHONY: test-e2e
test-e2e: up-e2e
ifeq ($(IS_LINUX),1)
	PYTHONPATH=. python -m pytest tests/e2e/ -v
else
	$(VM_EXEC) "cd $(PROJECT_DIR) && PYTHONPATH=. python -m pytest tests/e2e/ -v"
endif

.PHONY: test-unit
test-unit:
	PYTHONPATH=. python -m pytest tests/unit/ tests/integration/ -v
