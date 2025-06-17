# Docker Troubleshooting Guide for NetworkMapper

## Common Issues and Solutions

### 🚫 "Cannot connect to Docker daemon"

**Error:**
```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock
```

**Solutions:**
1. Start Docker service:
   ```bash
   sudo systemctl start docker
   ```

2. Add user to docker group:
   ```bash
   sudo usermod -aG docker $USER
   newgrp docker
   ```

### 🚫 "Permission denied" during scanning

**Error:**
```
[Errno 1] Operation not permitted
```

**Solution:**
Ensure container is running with proper privileges:
```yaml
# In docker-compose.yml (already configured)
privileged: true
network_mode: host
```

### 🚫 "No network interface found"

**Error:**
```
[WARN] No network interface detected
```

**Solutions:**
1. Specify interface manually:
   ```bash
   docker-compose run --rm -e INTERFACE=eth0 networkmapper
   ```

2. List available interfaces:
   ```bash
   docker-compose run --rm networkmapper bash -c "ip link show"
   ```

### 🚫 "Scans are very slow"

**Causes & Solutions:**

1. **Resource limits**: Increase in docker-compose.yml:
   ```yaml
   deploy:
     resources:
       limits:
         cpus: '4'
         memory: 4G
   ```

2. **DNS resolution issues**: Add DNS servers:
   ```bash
   docker-compose run --rm --dns 8.8.8.8 networkmapper
   ```

3. **Use faster scan type**:
   ```bash
   docker-compose run --rm networkmapper --target 192.168.1.0/24 --scan-type fast
   ```

### 🚫 "Cannot access web reports"

**Error:**
```
localhost:5000 refused to connect
```

**Solutions:**
1. Start web service:
   ```bash
   docker-compose --profile web up -d networkmapper-web
   ```

2. Check if port is already in use:
   ```bash
   sudo lsof -i :5000
   ```

3. Use different port:
   ```yaml
   # docker-compose.override.yml
   services:
     networkmapper-web:
       ports:
         - "8080:5000"
   ```

### 🚫 "Output files not persisting"

**Issue:** Scan results disappear after container stops

**Solution:**
Ensure volume is properly mounted:
```bash
# Check volume
docker-compose run --rm networkmapper ls -la /app/output

# Verify host directory
ls -la ./output
```

### 🚫 "Build fails with package errors"

**Error:**
```
E: Unable to locate package masscan
```

**Solutions:**
1. Update base image:
   ```dockerfile
   FROM python:3.11-slim-bookworm  # Use latest stable
   ```

2. Clear Docker cache:
   ```bash
   docker-compose build --no-cache
   ```

### 🚫 "Container exits immediately"

**Debugging steps:**

1. Check logs:
   ```bash
   docker-compose logs networkmapper
   ```

2. Run with debug:
   ```bash
   docker-compose run --rm -e LOGLEVEL=DEBUG networkmapper
   ```

3. Interactive debug:
   ```bash
   docker-compose run --rm --entrypoint /bin/bash networkmapper
   ```

### 🚫 "Masscan not working"

**Error:**
```
[WARN] Masscan may not work properly
```

**Solutions:**
1. Check capabilities:
   ```bash
   docker-compose run --rm networkmapper check
   ```

2. Fallback to nmap:
   ```bash
   docker-compose run --rm -e PREFER_MASSCAN=false networkmapper
   ```

### 🚫 "Memory errors on large networks"

**Error:**
```
MemoryError
```

**Solutions:**
1. Scan in chunks:
   ```bash
   # Instead of /16, scan /24 subnets
   for i in {0..255}; do
     docker-compose run --rm networkmapper --target 10.0.$i.0/24
   done
   ```

2. Increase swap:
   ```bash
   # On host system
   sudo swapon --show
   sudo fallocate -l 4G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   ```

## Debug Commands

### Container Information
```bash
# Inspect container
docker-compose ps
docker inspect networkmapper

# Resource usage
docker stats networkmapper

# Network info
docker-compose run --rm networkmapper ip addr
```

### File System
```bash
# Check permissions
docker-compose run --rm networkmapper ls -la /app
docker-compose run --rm networkmapper whoami

# Check capabilities
docker-compose run --rm networkmapper getcap /usr/bin/nmap
```

### Testing Components
```bash
# Test nmap
docker-compose run --rm networkmapper sudo nmap --version

# Test masscan
docker-compose run --rm networkmapper sudo masscan --version

# Test Python imports
docker-compose run --rm networkmapper python3 -c "import nmap; print('OK')"
```

## Performance Optimization

### For Large Networks

1. **Use dedicated Docker network**:
   ```yaml
   networks:
     scanning:
       driver: bridge
       driver_opts:
         com.docker.network.bridge.host_binding: "0.0.0.0"
   ```

2. **Disable logging for scans**:
   ```yaml
   logging:
     driver: none
   ```

3. **Use tmpfs for temporary files**:
   ```yaml
   tmpfs:
     - /tmp
   ```

### Resource Monitoring

```bash
# Monitor during scan
docker stats networkmapper

# Check disk usage
docker system df

# Clean up
docker system prune -a
```

## Emergency Recovery

### Reset Everything
```bash
# Stop all containers
docker-compose down

# Remove all data
docker system prune -a --volumes

# Rebuild fresh
docker-compose build --no-cache
```

### Backup Important Data
```bash
# Before reset
tar -czf networkmapper-backup.tar.gz output/
```

## Getting More Help

1. **Enable maximum debugging**:
   ```bash
   docker-compose run --rm \
     -e LOGLEVEL=DEBUG \
     -e PYTHONDEBUG=1 \
     networkmapper
   ```

2. **Check system requirements**:
   - Linux kernel 3.10+
   - Docker 20.10+
   - 2GB+ RAM
   - Network capabilities enabled

3. **File an issue** with:
   - Docker version: `docker --version`
   - Compose version: `docker-compose --version`
   - Host OS: `uname -a`
   - Error logs: `docker-compose logs`

Remember: Most issues are related to permissions or network configuration. The container needs privileged access for network scanning to work properly.