# Makefile for NetworkMapper v2
# Provides streamlined workflows for both local and Docker environments.

# --- Variables ---
PROJECT_DIR := $(shell pwd)
VENV_PYTHON = $(PROJECT_DIR)/venv/bin/python3
INSTALL_CMD_NAME = mapper
INSTALL_PATH = /usr/local/bin/$(INSTALL_CMD_NAME)
RUNNER_SCRIPT = $(PROJECT_DIR)/mapper-runner.sh

# User-facing scan variables
TARGET ?= 192.168.1.0/24
TYPE ?= discovery

.PHONY: help install uninstall \
        setup run scan test lint clean update-oui \
        docker docker-install docker-build docker-run docker-clean

# ==============================================================================
#                              MAIN COMMANDS
# ==============================================================================
# Default target: Show help message
help:
	@echo "NetworkMapper v2 - Makefile"
	@echo "---------------------------------------------------------------------"
	@echo "Usage: make [command]"
	@echo ""
	@echo "  --- DOCKER WORKFLOW (Recommended for all users) ---"
	@echo "    make docker          => Run full Docker setup: install, build, and run."
	@echo "    make docker-install  => (First time only) Install Docker & Docker Compose on your system."
	@echo "    make docker-build    => Build the NetworkMapper Docker image."
	@echo "    make docker-run      => Start the NetworkMapper interactive menu inside Docker."
	@echo "    make docker-clean    => Remove the NetworkMapper Docker image and stopped containers."
	@echo ""
	@echo "  --- LOCAL PYTHON WORKFLOW (For developers & power users) ---"
	@echo "    make install         => (Recommended) Set up local environment and create the global 'mapper' command."
	@echo "    make setup           => (First step) Run the initial setup script for a local virtual environment."
	@echo "    make run             => Run the application using the local Python venv."
	@echo "    make uninstall       => Remove the global 'mapper' command."
	@echo ""
	@echo "  --- UTILITY COMMANDS ---"
	@echo "    make test            => Run the test suite in the local venv."
	@echo "    make lint            => Run code formatters and linters."
	@echo "    make clean           => Remove all generated files (cache, logs, venv, etc.)."
	@echo "    make update-oui      => Download the latest MAC vendor database."
	@echo "---------------------------------------------------------------------"


# ==============================================================================
#                           DOCKER WORKFLOW TARGETS
# ==============================================================================

# Meta-target to set up and run everything with Docker
docker: docker-install docker-build docker-run

# Step 1: Install Docker and Docker Compose on the host system
docker-install:
	@echo "▶️  Ensuring Docker and Docker Compose are installed..."
	@if [ ! -f ./scripts/docker.sh ]; then \
		echo "ERROR: scripts/docker.sh not found!"; exit 1; \
	fi
	@chmod +x ./scripts/docker.sh
	@./scripts/docker.sh

# Step 2: Build the NetworkMapper Docker image
docker-build:
	@echo "▶️  Building the NetworkMapper Docker image..."
	@docker-compose build

# Step 3: Run the interactive application inside the Docker container
docker-run:
	@echo "🚀 Starting NetworkMapper in Docker..."
	@docker-compose run --rm networkmapper

# Clean up Docker resources related to this project
docker-clean:
	@echo "🧹 Removing NetworkMapper Docker image and containers..."
	@docker-compose down --rmi local --volumes


# ==============================================================================
#                        LOCAL PYTHON WORKFLOW TARGETS
# ==============================================================================

# Run the local setup script
setup:
	@echo "▶️  Making setup script executable..."
	@chmod +x ./scripts/setup.sh
	@echo "▶️  Running setup script..."
	@./scripts/setup.sh

# Set up everything locally and create the global 'mapper' command
install: setup
	@echo "▶️  Creating the global command '$(INSTALL_CMD_NAME)' at $(INSTALL_PATH)..."
	@echo '#!/bin/bash\nset -e\nPROJECT_DIR="$$(cd "$$(dirname "$${BASH_SOURCE[0]}")" && pwd)"\nVENV_PYTHON="$$PROJECT_DIR/venv/bin/python3"\ncd "$$PROJECT_DIR"\nif [ -f "$$VENV_PYTHON" ]; then $$VENV_PYTHON "$$PROJECT_DIR/mapper.py" "$$@"; else echo "Error: Virtual environment not found. Please run make setup."; exit 1; fi' > $(RUNNER_SCRIPT)
	@chmod +x $(RUNNER_SCRIPT)
	@echo "▶️  Creating system-wide symbolic link. This may require your password."
	@sudo ln -sf "$(RUNNER_SCRIPT)" "$(INSTALL_PATH)"
	@echo ""
	@echo "✅  Success! You can now run '$(INSTALL_CMD_NAME)' from anywhere in your terminal."
	@echo "   Try it now by typing: mapper"

# Remove the global 'mapper' command
uninstall:
	@echo "▶️  Removing global command '$(INSTALL_CMD_NAME)'..."
	@if [ -L "$(INSTALL_PATH)" ]; then \
		echo "   You may be prompted for your password to remove the symlink."; \
		sudo rm -f "$(INSTALL_PATH)"; \
	fi
	@rm -f $(RUNNER_SCRIPT)
	@echo "✅  '$(INSTALL_CMD_NAME)' command has been removed."

# Run the application using the local venv (for development)
run:
	@echo "🚀 Starting NetworkMapper from local venv..."
	@$(VENV_PYTHON) mapper.py


# ==============================================================================
#                             UTILITY TARGETS
# ==============================================================================

# Run a non-interactive scan (uses local venv)
scan:
	@echo "🎯 Scanning target: $(TARGET) with type: $(TYPE)"
	@if [ "$(TYPE)" = "deeper" ] || [ "$(TYPE)" = "fast" ] || [ "$(TYPE)" = "arp" ]; then \
		echo "🔐 Scan type '$(TYPE)' requires sudo privileges..."; \
		sudo $(VENV_PYTHON) mapper.py --target $(TARGET) --scan-type $(TYPE); \
	else \
		$(VENV_PYTHON) mapper.py --target $(TARGET) --scan-type $(TYPE); \
	fi

# Run the test suite
test:
	@echo "🧪 Running test suite..."
	@$(VENV_PYTHON) -m pytest tests/ -v

# Run linters and formatters
lint:
	@echo "🎨 Formatting with black..."
	@$(VENV_PYTHON) -m black . --line-length=100
	@echo "🔬 Linting with flake8..."
	@$(VENV_PYTHON) -m flake8 .

# Clean up all generated files
clean:
	@echo "🧹 Cleaning up project directory..."
	@rm -rf venv output .pytest_cache htmlcov .coverage
	@find . -type d -name "__pycache__" -exec rm -r {} +
	@echo "✅ Cleanup complete."

# Update the OUI database
update-oui:
	@echo "🌐 Updating OUI database..."
	@$(VENV_PYTHON) -c "from utils.mac_lookup import MACLookup; MACLookup().update_database()"
