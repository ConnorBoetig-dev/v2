# NetworkMapper v2 - Docker Setup Guide

This guide explains how to run NetworkMapper using Docker, which eliminates all setup complexities and dependency issues.

## 🚀 Quick Start

### Prerequisites
- Docker installed ([Get Docker](https://docs.docker.com/get-docker/))
- Docker Compose installed (usually comes with Docker)
- Linux host (required for network scanning capabilities)

### One-Line Setup & Run

```bash
# Clone the repository
git clone <your-repo-url>
cd NetworkMapper

# Build and run
docker-compose run --rm networkmapper
```

That's it! No Python setup, no dependency installation, no permission configuration needed.

## 📦 What's Included

The Docker image includes:
- Python 3.11 environment
- All Python dependencies from requirements.txt
- Network tools: nmap, masscan, arp-scan, tcpdump
- Proper permissions for network scanning
- Automated network interface detection

## 🎯 Common Usage Examples

### Interactive Mode (Default)
```bash
docker-compose run --rm networkmapper
```

### Scan a Specific Network
```bash
docker-compose run --rm networkmapper --target 192.168.1.0/24 --scan-type fast
```

### Quick Discovery Scan
```bash
docker-compose run --rm networkmapper scan 192.168.1.0/24
```

### Deep Security Scan
```bash
docker-compose run --rm networkmapper --target 10.0.0.0/16 --scan-type deeper
```

### Use Specific Network Interface
```bash
docker-compose run --rm -e INTERFACE=eth1 networkmapper
```

### View Previous Reports
```bash
# Reports are saved in ./output directory
ls -la ./output/reports/
```

### Run Tests
```bash
docker-compose run --rm networkmapper test
```

### Interactive Shell (for debugging)
```bash
docker-compose run --rm networkmapper shell
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file from the example:
```bash
cp .env.example .env
```

Key variables:
- `INTERFACE`: Network interface (auto-detected if not set)
- `TZ`: Timezone for accurate timestamps
- `LOGLEVEL`: Logging verbosity (DEBUG, INFO, WARNING, ERROR)

### Custom Configuration

Mount your custom `config.yaml`:
```yaml
# docker-compose.override.yml
services:
  networkmapper:
    volumes:
      - ./my-config.yaml:/app/config.yaml:ro
```

## 📁 Data Persistence

Scan results are automatically saved to the `./output` directory on your host:
```
./output/
├── scans/          # Raw scan data
├── reports/        # HTML reports
├── exports/        # CSV, JSON, PDF exports
└── logs/           # Application logs
```

## 🌐 Web Interface

To view reports through a web browser:

```bash
# Start the web server
docker-compose --profile web up -d networkmapper-web

# Access at http://localhost:5000
```

## 🔍 Troubleshooting

### Permission Denied Errors
The container needs privileged mode for network scanning:
```yaml
privileged: true  # Already set in docker-compose.yml
```

### Cannot Find Network Interface
Specify interface manually:
```bash
docker-compose run --rm -e INTERFACE=docker0 networkmapper
```

### Out of Memory
Adjust resource limits in docker-compose.yml:
```yaml
deploy:
  resources:
    limits:
      memory: 4G  # Increase as needed
```

### Scan Hanging
Check if you're using host network mode:
```yaml
network_mode: host  # Required for scanning
```

## 🏗️ Building the Image

### Build Locally
```bash
docker-compose build
```

### Build with No Cache
```bash
docker-compose build --no-cache
```

### Tag for Distribution
```bash
docker tag networkmapper:v2 myregistry/networkmapper:v2
docker push myregistry/networkmapper:v2
```

## 🔒 Security Considerations

The container runs with:
- Non-root user (`netmapper`) by default
- Capabilities only for network operations
- Minimal required privileges
- No persistent root access

For production use:
1. Review and limit network access
2. Use read-only mounts where possible
3. Implement resource limits
4. Regular image updates

## 📊 Performance Tips

### Large Networks
For networks with 10k+ hosts:
```bash
docker-compose run --rm \
  -e PREFER_MASSCAN=true \
  networkmapper --target 10.0.0.0/8 --scan-type fast
```

### Memory Optimization
```bash
# Limit memory usage
docker-compose run --rm --memory="1g" networkmapper
```

### CPU Limits
```bash
# Limit to 2 CPUs
docker-compose run --rm --cpus="2.0" networkmapper
```

## 🆘 Getting Help

### Check Capabilities
```bash
docker-compose run --rm networkmapper check
```

### View Logs
```bash
docker-compose logs networkmapper
```

### Debug Mode
```bash
docker-compose run --rm -e LOGLEVEL=DEBUG networkmapper
```

## 🔄 Updates

To update NetworkMapper:
```bash
# Pull latest code
git pull

# Rebuild image
docker-compose build --no-cache

# Run updated version
docker-compose run --rm networkmapper
```

## 🎉 Benefits of Docker Setup

1. **Zero Manual Setup** - Everything just works
2. **Consistent Environment** - Same behavior everywhere  
3. **Easy Distribution** - Share the image with your team
4. **Isolation** - No conflicts with host system
5. **Version Control** - Pin specific versions easily
6. **Quick Cleanup** - Just remove the container

## 📝 Advanced Usage

### Custom Dockerfile
Create `Dockerfile.custom` for your modifications:
```dockerfile
FROM networkmapper:v2
# Your customizations here
```

### Multi-Architecture Builds
```bash
docker buildx build --platform linux/amd64,linux/arm64 -t networkmapper:v2 .
```

### Kubernetes Deployment
See `k8s/` directory for Kubernetes manifests (if applicable).

---

With Docker, NetworkMapper runs anywhere with zero setup hassle. Happy scanning! 🚀