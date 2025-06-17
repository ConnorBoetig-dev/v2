#!/bin/bash
# NetworkMapper Docker Setup Script
# Automated setup for Docker environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ASCII Art Banner
print_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
    _   _      _                      _    __  __                            
   | \ | | ___| |___      _____  _ __| | _|  \/  | __ _ _ __  _ __   ___ _ __ 
   |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ / |\/| |/ _` | '_ \| '_ \ / _ \ '__|
   | |\  |  __/ |_ \ V  V / (_) | |  |   <| |  | | (_| | |_) | |_) |  __/ |   
   |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\_|  |_|\__,_| .__/| .__/ \___|_|   
                                                        |_|   |_|              
                               Docker Edition v2
EOF
    echo -e "${NC}"
}

# Logging functions
log_info() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[→]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Docker installation
check_docker() {
    log_step "Checking Docker installation..."
    
    if ! command_exists docker; then
        log_error "Docker is not installed!"
        echo "Please install Docker first: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker daemon is not running or you don't have permissions!"
        echo "Try: sudo systemctl start docker"
        echo "Or add your user to docker group: sudo usermod -aG docker $USER"
        exit 1
    fi
    
    log_info "Docker is installed and running"
}

# Check Docker Compose installation
check_docker_compose() {
    log_step "Checking Docker Compose installation..."
    
    if command_exists docker-compose; then
        log_info "Docker Compose is installed"
    elif docker compose version >/dev/null 2>&1; then
        log_info "Docker Compose (plugin) is installed"
        # Create alias for consistency
        alias docker-compose='docker compose'
    else
        log_error "Docker Compose is not installed!"
        echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
        exit 1
    fi
}

# Create necessary directories
setup_directories() {
    log_step "Setting up directories..."
    
    mkdir -p output/{scans,reports,exports,logs,cache}
    
    log_info "Created output directories"
}

# Setup environment file
setup_env() {
    log_step "Setting up environment configuration..."
    
    if [ ! -f .env ]; then
        if [ -f .env.example ]; then
            cp .env.example .env
            log_info "Created .env file from template"
        else
            log_warn ".env.example not found, skipping environment setup"
        fi
    else
        log_info ".env file already exists"
    fi
}

# Build Docker image
build_image() {
    log_step "Building Docker image (this may take a few minutes)..."
    
    if docker-compose build; then
        log_info "Docker image built successfully"
    else
        log_error "Failed to build Docker image"
        exit 1
    fi
}

# Test the setup
test_setup() {
    log_step "Testing NetworkMapper setup..."
    
    if docker-compose run --rm networkmapper check; then
        log_info "NetworkMapper is ready to use!"
    else
        log_warn "Some features may not work correctly"
    fi
}

# Print usage instructions
print_usage() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Setup Complete! 🎉${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "To start using NetworkMapper:"
    echo ""
    echo -e "${BLUE}Interactive mode:${NC}"
    echo "  docker-compose run --rm networkmapper"
    echo ""
    echo -e "${BLUE}Scan a network:${NC}"
    echo "  docker-compose run --rm networkmapper --target 192.168.1.0/24"
    echo ""
    echo -e "${BLUE}Quick scan:${NC}"
    echo "  docker-compose run --rm networkmapper scan 192.168.1.0/24 --scan-type fast"
    echo ""
    echo -e "${BLUE}View help:${NC}"
    echo "  docker-compose run --rm networkmapper --help"
    echo ""
    echo "For more information, see DOCKER_README.md"
}

# Main setup flow
main() {
    clear
    print_banner
    
    echo "Starting NetworkMapper Docker setup..."
    echo ""
    
    # Run checks
    check_docker
    check_docker_compose
    
    # Setup
    setup_directories
    setup_env
    
    # Build
    echo ""
    read -p "Build Docker image now? (y/N) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        build_image
        test_setup
    else
        echo ""
        log_warn "Skipping build. Run 'docker-compose build' when ready."
    fi
    
    # Done
    print_usage
}

# Run main function
main