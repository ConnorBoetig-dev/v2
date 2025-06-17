# Makefile for NetworkMapper v2 - Local Development
# Provides simple shortcuts for common tasks.

# --- Variables ---
# Use the python executable from the virtual environment
VENV_PYTHON = ./venv/bin/python3
TARGET ?= 192.168.1.0/24
TYPE ?= discovery

# --- Phony Targets (commands that don't produce files) ---
.PHONY: help setup run scan test lint clean update-oui

# --- Main Commands ---

# Default target: Show help message
help:
	@echo "NetworkMapper v2 - Makefile"
	@echo "--------------------------------"
	@echo "Usage: make [command]"
	@echo ""
	@echo "Commands:"
	@echo "  help          Show this help message."
	@echo "  setup         Run the initial setup script (setup.sh)."
	@echo "  run           Start the NetworkMapper interactive interface."
	@echo "  scan          Run a non-interactive scan. Ex: make scan TARGET=10.0.0.0/16 TYPE=fast"
	@echo "  test          Run the full pytest test suite."
	@echo "  lint          Run code formatters and linters (black, flake8)."
	@echo "  clean         Remove all generated files (cache, logs, venv)."
	@echo "  update-oui    Download the latest MAC vendor database."
	@echo ""

# Run the setup script
# This target ensures setup.sh is executable and then runs it.
# A new user only needs to run `make setup`.
setup:
	@echo "▶️  Making setup script executable..."
	@chmod +x ./setup.sh
	@echo "▶️  Running setup script..."
	@./setup.sh

# Run the main application
mapper:
	@echo "🚀 Starting NetworkMapper..."
	@$(VENV_PYTHON) mapper.py

# Run a non-interactive scan
scan:
	@echo "🎯 Scanning target: $(TARGET) with type: $(TYPE)"
	@# Check if the scan type requires sudo
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

# Clean up generated files
clean:
	@echo "🧹 Cleaning up project directory..."
	@rm -rf venv
	@rm -rf output
	@rm -rf .pytest_cache
	@rm -rf htmlcov
	@rm -f .coverage
	@find . -type d -name "__pycache__" -exec rm -r {} +
	@echo "✅ Cleanup complete."

# Update the OUI database
update-oui:
	@echo "🌐 Updating OUI database..."
	@$(VENV_PYTHON) -c "from utils.mac_lookup import MACLookup; MACLookup().update_database()"
