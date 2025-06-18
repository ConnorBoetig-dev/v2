# NetworkMapper Docker Setup Guide

This guide explains how to deploy NetworkMapper on a fresh Linux system using Docker.

## Prerequisites
- Fresh Linux system (Debian/Ubuntu recommended)
- Git installed (`apt-get install git`)
- Internet connection for downloading Docker and dependencies

## Quick Start (3 Commands)

```bash
# 1. Clone the repository
git clone <repository-url> v2
cd v2

# 2. Install Docker and build the application
make docker-install

**Note**: After installation, run `newgrp docker` to activate Docker permissions in your current terminal

# 3. Build and run NetworkMapper
make docker-build
```

That's it! NetworkMapper is now running in a Docker container.

## What Each Command Does

### `make docker-install`
- Installs Docker Engine and Docker Compose on your system
- Adds your user to the docker group for permission management
- Verifies Docker is running correctly
- **Note**: After installation, run `newgrp docker` to activate Docker permissions in your current terminal

### `make docker-build`
- Builds a Docker image containing:
  - All network scanning tools (nmap, masscan, arp-scan)
  - Python 3.11 and all required libraries
  - Proper permissions for network operations
- **Important**: This command builds the image AND automatically starts NetworkMapper
- The application runs interactively in your terminal

### `make docker-run`
- Use this to re-enter NetworkMapper after exiting
- Starts a fresh container from the built image
- Your scan results are saved to the `./output` folder on your host system

## Understanding the Docker Workflow

### Why Docker?
Docker packages NetworkMapper with all its dependencies into a portable container. This means:
- No conflicts with system packages
- Identical behavior across different systems
- Network tools are isolated from your host system
- Easy cleanup when done

### Container Behavior
1. **First Run**: `make docker-build` creates the container image and launches NetworkMapper
2. **Exiting**: Press Ctrl+C to exit the application and stop the container
3. **Re-entering**: Run `make docker-run` to start a new container session
4. **Output Files**: All scan results are saved to `./output` on your host (not inside the container)

### What's Happening Behind the Scenes

When you run `make docker-build`:
1. Docker downloads a minimal Python 3.11 Linux image
2. Installs system tools: nmap, masscan, arp-scan, libpcap-dev
3. Installs Python packages from requirements.txt
4. Creates a secure user environment with sudo permissions
5. Starts NetworkMapper with host network access

The container runs with:
- `--network=host`: Uses your host's network interface for scanning
- `--privileged`: Required for low-level network operations
- Volume mount: `./output:/app/output` saves results to your host

## Common Operations

### Running NetworkMapper
```bash
# After initial setup, this is all you need:
make docker-run
```

### Cleaning Up
```bash
# Remove Docker image and containers
make docker-clean

# Remove everything including output files
make clean
```

### Updating the OUI Database
The MAC vendor database is included in the Docker image. To update it:
1. Run NetworkMapper: `make docker-run`
2. Select option 9 from the main menu
3. Follow the prompts to download the latest database

## Troubleshooting

### "Permission denied" errors
```bash
# Activate Docker group permissions
newgrp docker
```

### "Cannot connect to Docker daemon"
```bash
# Start Docker service
sudo systemctl start docker
```

### Build fails with network errors
- Check your internet connection
- Verify Docker can access external repositories
- Try again - some package repositories may be temporarily unavailable

### Container exits immediately
- Ensure you're using `make docker-run` (not `docker run` directly)
- Check for error messages in the output

## Technical Notes

- The Dockerfile uses a two-stage build for efficiency
- All network tools run as a non-root user with sudo permissions
- The container is ephemeral - each run starts fresh
- Only the output directory persists between runs
- Host network mode is required for accurate network scanning

## For Developers

If you need to modify the Docker setup:
- `ops/Dockerfile` - Container build instructions
- `docker-compose.yml` - Container runtime configuration
- `Makefile` - All automation commands
- `ops/requirements.txt` - Python dependencies