# Makefile for NetworkMapper v2
# This file provides simple commands to build and run the project
# Usage: make [command]

# Variables (you can change these)
IMAGE_NAME = networkmapper
CONTAINER_NAME = networkmapper-scanner
OUTPUT_DIR = $(shell pwd)/output

# Default command when you just type 'make'
.PHONY: help
help:
	@echo "NetworkMapper v2 - Available Commands:"
	@echo "======================================"
	@echo "  make setup         - Install everything locally (no Docker)"
	@echo "  make docker-build  - Build the Docker image"
	@echo "  make docker-run    - Run NetworkMapper in Docker"
	@echo "  make docker-shell  - Open a shell in the Docker container"
	@echo "  make clean         - Clean up output files"
	@echo "  make test          - Run the test suite"
	@echo "  make lint          - Check code formatting"
	@echo ""
	@echo "Quick Start:"
	@echo "  1. Run 'make setup' for local installation"
	@echo "  OR"
	@echo "  2. Run 'make docker-build' then 'make docker-run'"

# Install everything locally (for development)
.PHONY: setup
setup:
	@echo "Setting up NetworkMapper locally..."
	# Check if Python 3 is installed
	@which python3 > /dev/null || (echo "Error: Python 3 not found. Please install Python 3.8+" && exit 1)
	# Create virtual environment if it doesn't exist
	@if [ ! -d "venv" ]; then \
		echo "Creating virtual environment..."; \
		python3 -m venv venv; \
	fi
	# Activate venv and install requirements
	@echo "Installing Python packages..."
	@./venv/bin/pip install --upgrade pip
	@./venv/bin/pip install -r requirements.txt
	# Create output directories
	@mkdir -p output/{scans,reports,changes,annotations,cache,config,exports}
	# Check for required system tools
	@echo ""
	@echo "Checking system dependencies..."
	@which nmap > /dev/null && echo "✓ nmap found" || echo "✗ nmap not found - install with: sudo apt install nmap"
	@which masscan > /dev/null && echo "✓ masscan found" || echo "✗ masscan not found (optional) - see README for installation"
	@which arp-scan > /dev/null && echo "✓ arp-scan found" || echo "✗ arp-scan not found (optional) - install with: sudo apt install arp-scan"
	@echo ""
	@echo "Setup complete! Run with: ./venv/bin/python mapper.py"

# Build the Docker image
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t $(IMAGE_NAME) .
	@echo "Docker image built successfully!"

# Run NetworkMapper in Docker (interactive mode)
.PHONY: docker-run
docker-run:
	@echo "Starting NetworkMapper in Docker..."
	@echo "Note: This will mount ./output to save scan results"
	docker run -it --rm \
		--name $(CONTAINER_NAME) \
		--network host \
		--privileged \
		-v $(OUTPUT_DIR):/app/output \
		$(IMAGE_NAME) \
		python3 mapper.py

# Run a specific network scan in Docker
# Usage: make docker-scan TARGET=192.168.1.0/24
.PHONY: docker-scan
docker-scan:
	@if [ -z "$(TARGET)" ]; then \
		echo "Error: Please specify TARGET"; \
		echo "Usage: make docker-scan TARGET=192.168.1.0/24"; \
		exit 1; \
	fi
	@echo "Scanning $(TARGET) with Docker..."
	docker run -it --rm \
		--network host \
		--privileged \
		-v $(OUTPUT_DIR):/app/output \
		$(IMAGE_NAME) \
		python3 -c "from mapper import NetworkMapper; nm = NetworkMapper(); nm.run_scan('$(TARGET)')"

# Open a shell inside the Docker container (for debugging)
.PHONY: docker-shell
docker-shell:
	@echo "Opening shell in Docker container..."
	docker run -it --rm \
		--network host \
		--privileged \
		-v $(OUTPUT_DIR):/app/output \
		$(IMAGE_NAME) \
		/bin/bash

# Clean up output files (be careful!)
.PHONY: clean
clean:
	@echo "Cleaning output directory..."
	@read -p "Are you sure? This will delete all scan results! (y/N) " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		rm -rf output/*; \
		mkdir -p output/{scans,reports,changes,annotations,cache,config,exports}; \
		echo "Output directory cleaned"; \
	else \
		echo "Cancelled"; \
	fi

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	@if [ -d "venv" ]; then \
		./venv/bin/pytest tests/ -v; \
	else \
		echo "Error: Virtual environment not found. Run 'make setup' first"; \
		exit 1; \
	fi

# Run linting
.PHONY: lint
lint:
	@echo "Running code quality checks..."
	@if [ -f "scripts/lint.sh" ]; then \
		./scripts/lint.sh; \
	else \
		echo "Checking with Black..."; \
		./venv/bin/black --check .; \
	fi

# Remove Docker image
.PHONY: docker-clean
docker-clean:
	@echo "Removing Docker image..."
	docker rmi $(IMAGE_NAME) || true

# Show Docker image size
.PHONY: docker-size
docker-size:
	@docker images $(IMAGE_NAME) --format "Image: {{.Repository}}\nSize: {{.Size}}"