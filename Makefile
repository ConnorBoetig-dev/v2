# NetworkMapper v2 - Docker Makefile
# Convenient shortcuts for Docker operations

.PHONY: help build run scan shell test clean logs web stop setup

# Default target
help:
	@echo "NetworkMapper Docker Commands:"
	@echo ""
	@echo "  make setup      - Initial setup (directories, env file, build)"
	@echo "  make build      - Build Docker image"
	@echo "  make run        - Run interactive mode"
	@echo "  make scan       - Quick scan example (edit TARGET in Makefile)"
	@echo "  make shell      - Open shell in container"
	@echo "  make test       - Run test suite"
	@echo "  make logs       - View container logs"
	@echo "  make web        - Start web interface"
	@echo "  make stop       - Stop all containers"
	@echo "  make clean      - Remove containers and images"
	@echo ""
	@echo "Examples:"
	@echo "  make scan TARGET=192.168.1.0/24"
	@echo "  make scan TARGET=10.0.0.0/16 TYPE=fast"

# Initial setup
setup:
	@echo "Setting up NetworkMapper Docker environment..."
	@./docker-setup.sh

# Build Docker image
build:
	docker-compose build

# Run interactive mode
run:
	docker-compose run --rm networkmapper

# Run a scan (requires TARGET variable)
TARGET ?= 192.168.1.0/24
TYPE ?= discovery
scan:
	docker-compose run --rm networkmapper --target $(TARGET) --scan-type $(TYPE)

# Open shell in container
shell:
	docker-compose run --rm networkmapper shell

# Run tests
test:
	docker-compose run --rm networkmapper test

# View logs
logs:
	docker-compose logs -f

# Start web interface
web:
	docker-compose --profile web up -d networkmapper-web
	@echo "Web interface available at http://localhost:5000"

# Stop all containers
stop:
	docker-compose down

# Clean up Docker resources
clean:
	docker-compose down -v --rmi local

# Quick scan shortcuts
scan-local:
	@$(MAKE) scan TARGET=192.168.1.0/24 TYPE=fast

scan-deep:
	@$(MAKE) scan TARGET=$(TARGET) TYPE=deeper

# Development helpers
rebuild:
	docker-compose build --no-cache

exec:
	docker-compose exec networkmapper bash

# Check network capabilities
check:
	docker-compose run --rm networkmapper check

# Update from git and rebuild
update:
	git pull
	docker-compose build --no-cache

# Show image size
size:
	docker images networkmapper:v2 --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"

# Prune unused Docker resources
prune:
	docker system prune -f