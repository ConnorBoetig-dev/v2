# Network Scanner Architecture

## Overview

The NetworkMapper scanner subsystem is a sophisticated multi-tool orchestration engine that combines the strengths of different network scanning tools (nmap, masscan, arp-scan) to achieve optimal performance and accuracy. The architecture employs an async-first design wrapped in a sync-compatible interface, enabling massive performance improvements through parallelization while maintaining backward compatibility.

## Architecture & Design

### Component Structure

```
scanner.py (Sync Wrapper)
    └── scanner_async.py (Async Implementation)
            ├── nmap integration
            ├── masscan integration
            ├── arp-scan integration
            └── SNMP enrichment
```

### Key Design Decisions

1. **Async/Sync Dual Architecture**
   - Core logic implemented as async (`scanner_async.py`) for maximum performance
   - Synchronous wrapper (`scanner.py`) for CLI compatibility
   - Event loop detection automatically chooses the right execution model

2. **Multi-Scanner Strategy**
   - **masscan**: Ultra-fast host discovery (100k packets/second)
   - **nmap**: Detailed service/OS fingerprinting
   - **arp-scan**: Layer 2 discovery for local networks
   - Each tool used for its strengths, results merged intelligently

3. **Parallel Execution Model**
   - Large networks split into /24 subnets, scanned concurrently
   - Enrichment (detailed nmap scans) parallelized per chunk
   - SNMP queries executed asynchronously
   - Semaphores prevent resource exhaustion

## Key Concepts

### Scan Profiles

The system defines two primary scan profiles optimized for different use cases:

1. **Fast Scan** (`scan_type="fast"`)
   - Uses masscan for rapid discovery
   - Light nmap enrichment (version intensity 0)
   - Optimized for speed: 2-5 minutes for /16 networks
   - Best for: Daily monitoring, quick inventory

2. **Deeper Scan** (`scan_type="deeper"`)
   - Extended port list for masscan
   - Thorough nmap enrichment (version intensity 5)
   - Better OS/service detection accuracy
   - Duration: 5-15 minutes for /16 networks
   - Best for: Security assessments, detailed inventory

### Performance Optimization Techniques

1. **Subnet Parallelization**
   - Networks larger than /24 automatically split
   - Default: 32 concurrent subnet scans
   - Prevents masscan from overwhelming the network

2. **Chunked Enrichment**
   - Discovered hosts enriched in batches
   - Fast scan: 25 hosts per chunk
   - Deeper scan: 10 hosts per chunk (more intensive)

3. **Smart Tool Selection**
   - masscan used only when beneficial (>100 hosts)
   - Local networks use ARP discovery first
   - Fallback chains ensure reliability

## Usage & Integration

### Basic Usage

```python
from core.scanner import NetworkScanner

scanner = NetworkScanner()

# Simple scan
devices = scanner.scan("192.168.1.0/24", scan_type="fast")

# With SNMP enrichment
devices = scanner.scan(
    "10.0.0.0/16",
    scan_type="deeper",
    use_masscan=True,
    snmp_config={"community": "public", "version": "v2c"}
)
```

### Async Usage (Future Web Integration)

```python
async def scan_network():
    scanner = NetworkScanner()
    devices = await scanner.scan("192.168.1.0/24")
    return devices
```

## Assumptions & Limitations

### Assumptions
- Target networks are reachable from the scanning host
- User has necessary permissions (sudo for certain operations)
- Standard ports indicate standard services (can be overridden)

### Limitations
- masscan requires root privileges
- Some OS detection requires open ports
- Virtual machines may have generic MAC addresses
- Firewall/IDS may block or alter scan results

### Performance Characteristics
- Memory usage scales with network size (roughly 1MB per 1000 hosts)
- CPU usage primarily during result parsing
- Network bandwidth: configurable via masscan rate limiting
- Typical /16 network scan: 100-500MB of traffic

## Troubleshooting

### Common Issues

1. **"Scanner not found" errors**
   - Ensure nmap/masscan are installed: `sudo apt install nmap masscan`
   - Check PATH includes scanner locations

2. **Slow performance**
   - Verify masscan is enabled for large networks
   - Check network latency to targets
   - Reduce version intensity for faster scans

3. **Incomplete results**
   - Some devices may have strict firewalls
   - Try deeper scan profile for better detection
   - Enable SNMP for additional device info

4. **Permission errors**
   - SYN scans require root: use `sudo`
   - Alternative: disable masscan for unprivileged scanning

## Future Considerations

1. **IPv6 Support**
   - Currently IPv4-focused
   - masscan supports IPv6, needs integration work

2. **Custom Scan Profiles**
   - Allow user-defined profiles via configuration
   - Per-subnet custom settings

3. **Real-time Streaming**
   - Stream results as discovered vs. batch return
   - WebSocket support for live updates

4. **Distributed Scanning**
   - Coordinate multiple scanner nodes
   - Useful for geographically distributed networks

5. **Machine Learning Integration**
   - ML-based service identification
   - Anomaly detection in scan results