#!/bin/bash
#
# Universal Docker & Docker Compose Installer
# Detects OS and installs Docker Engine and the Compose plugin if missing.
#

set -e

# --- Colors & Logging ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
log_info() { echo -e "${GREEN}${BOLD}[✓]${NC} $1"; }
log_warn() { echo -e "${YELLOW}${BOLD}[!]${NC} $1"; }
log_error() { echo -e "${RED}${BOLD}[✗]${NC} $1"; }
log_step() { echo -e "\n${BLUE}==>${NC} ${BOLD}$1${NC}"; }

# --- Banner ---
print_banner() { 
    clear; echo -e "${BLUE}"; cat << "EOF"
 __  __                               ____             _             
|  \/  | __ _ _ __  _ __   ___ _ __  |  _ \  ___   ___| | _____ _ __ 
| |\/| |/ _` | '_ \| '_ \ / _ \ '__| | | | |/ _ \ / __| |/ / _ \ '__|
| |  | | (_| | |_) | |_) |  __/ |    | |_| | (_) | (__|   <  __/ |   
|_|  |_|\__,_| .__/| .__/ \___|_|    |____/ \___/ \___|_|\_\___|_|   
             |_|   |_|                                               
EOF
    echo -e "${BOLD}                     Docker Environment Setup Utility${NC}"; echo ""
}

# --- Installation Logic ---
install_docker_linux() {
    log_step "Installing Docker Engine for Linux..."; echo "Using the official script from get.docker.com."
    curl -fsSL https://get.docker.com -o get-docker.sh; sudo sh get-docker.sh; rm get-docker.sh
    log_step "Configuring user permissions for Docker...";
    if sudo usermod -aG docker "$USER"; then
        log_info "Added '$USER' to the 'docker' group."
        log_warn "You must log out and log back in for this to take effect!"
        log_warn "Or run 'newgrp docker' in your current terminal."
    else log_error "Failed to add user to docker group. You may need to run 'docker' commands with 'sudo'."; fi
}
install_docker_macos() {
    log_step "Installing Docker Desktop for macOS...";
    if ! command -v brew >/dev/null 2>&1; then log_error "Homebrew not found. Please install it: https://brew.sh/"; exit 1; fi
    brew install --cask docker; log_info "Docker Desktop installed."
    log_warn "You must now open Docker Desktop from your Applications folder and complete setup."
    open /Applications/Docker.app
}
install_compose_plugin_linux() {
    log_step "Installing Docker Compose plugin for Linux...";
    LATEST_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$LATEST_COMPOSE_VERSION" ]; then log_error "Could not determine latest Docker Compose version."; exit 1; fi
    log_info "Latest Docker Compose version is ${LATEST_COMPOSE_VERSION}."
    ARCH=$(uname -m); case $ARCH in x86_64) ARCH="x86_64";; aarch64|arm64) ARCH="aarch64";; *) log_error "Unsupported arch: $ARCH"; exit 1;; esac
    DOCKER_CONFIG_PATH=/usr/local/lib/docker/cli-plugins; DOWNLOAD_URL="https://github.com/docker/compose/releases/download/${LATEST_COMPOSE_VERSION}/docker-compose-linux-${ARCH}"
    sudo mkdir -p "$DOCKER_CONFIG_PATH"; echo "Downloading from: $DOWNLOAD_URL"
    sudo curl -SL "$DOWNLOAD_URL" -o "${DOCKER_CONFIG_PATH}/docker-compose"; sudo chmod +x "${DOCKER_CONFIG_PATH}/docker-compose";
    log_info "Docker Compose plugin installed successfully."
}

# --- Main Execution ---
main() {
    print_banner; echo "This script will check for and install Docker and Docker Compose."
    OS_TYPE=$(uname -s | tr '[:upper:]' '[:lower:]')
    log_step "Checking for Docker..."; if command -v docker >/dev/null 2>&1; then
        log_info "Docker is already installed.";
        if ! docker info >/dev/null 2>&1; then log_error "Docker is installed but the daemon is not running."; log_warn "Please start the Docker service/daemon."; if [[ "$OS_TYPE" == "linux" ]]; then echo "Try: sudo systemctl start docker"; fi; exit 1; fi
        log_info "Docker daemon is running."
    else
        log_warn "Docker is not installed."; if [[ "$OS_TYPE" == "linux" ]]; then install_docker_linux; elif [[ "$OS_TYPE" == "darwin" ]]; then install_docker_macos; else log_error "Unsupported OS for auto install."; exit 1; fi
    fi
    log_step "Checking for Docker Compose..."; if docker compose version >/dev/null 2>&1; then
        log_info "Docker Compose plugin is already installed."
    else
        log_warn "Docker Compose plugin is not installed.";
        if [[ "$OS_TYPE" == "linux" ]]; then install_compose_plugin_linux;
        elif [[ "$OS_TYPE" == "darwin" ]]; then log_error "Docker Compose should be included with Docker Desktop. Please ensure it is running."; exit 1;
        else log_error "Unsupported OS for auto Compose install."; exit 1; fi
    fi
    echo -e "\n${GREEN}====================================================${NC}";
    echo -e "${GREEN}${BOLD}      ✅  Docker Environment is Ready!${NC}";
    echo -e "${GREEN}====================================================${NC}";
    echo ""; echo "You can now build and run the NetworkMapper application using Docker."
    echo "Next steps:"; echo -e "  1. Build image: ${CYAN}make docker-build${NC}"; echo -e "  2. Run the app: ${CYAN}make docker-run${NC}"; echo ""
}

main
