# Device Classifier Architecture

## Overview

The Device Classifier is a pattern-matching engine that identifies network device types based on their observable characteristics. It uses a signature-based approach with confidence scoring to handle ambiguous cases and provides accurate device categorization even with limited information.

## Architecture & Design

### Classification Pipeline

```
Device Data → Feature Extraction → Signature Matching → Confidence Scoring → Type Assignment
     ↓              ↓                    ↓                    ↓                   ↓
  [IP, Ports]   [Normalize]      [Compare to DB]      [Weight scores]    [Select best]
```

### Key Components

1. **DeviceType Enum**: Comprehensive taxonomy of network devices
2. **DeviceSignature**: Pattern definitions for each device type
3. **Scoring Engine**: Weighted matching with confidence calculation
4. **Service Hints**: Fast-path classification for obvious cases

### Design Principles

1. **Priority-Based Evaluation**
   - Higher priority signatures checked first
   - Prevents misclassification (e.g., router vs switch)
   - Configurable per signature

2. **Multi-Factor Analysis**
   - Port patterns
   - Service names
   - Vendor information
   - OS fingerprints
   - Hostname patterns

3. **Confidence Scoring**
   - 0.0-1.0 scale
   - Minimum thresholds per device type
   - Transparency in classification method

## Key Concepts

### Signature Matching

Each device type has a signature containing:
- **Characteristic ports**: Common open ports for this device type
- **Expected services**: Service names typically found
- **Keywords**: Patterns in hostname/OS/vendor strings
- **Exclusion rules**: Ports that should NOT be present
- **Vendor patterns**: Manufacturer indicators

### Scoring Algorithm

```python
score = base_score * (
    port_matches * 0.3 +
    service_matches * 0.3 +
    vendor_match * 0.2 +
    keyword_matches * 0.2
) * priority_multiplier
```

### Classification Confidence

Confidence indicates how well a device matches its assigned type:
- **>0.8**: Strong match, multiple indicators align
- **0.5-0.8**: Good match, primary indicators present
- **0.3-0.5**: Weak match, few indicators
- **<0.3**: Fallback classification

## Usage & Integration

### Basic Usage

```python
from core.classifier import DeviceClassifier

classifier = DeviceClassifier()
devices = [
    {
        'ip': '192.168.1.1',
        'open_ports': [22, 80, 443, 161],
        'services': ['ssh', 'http', 'https', 'snmp'],
        'vendor': 'Cisco'
    }
]

classified = classifier.classify_devices(devices)
# Result: {'type': 'router', 'confidence': 0.85, ...}
```

### Adding New Device Types

1. Add to DeviceType enum
2. Create signature in _build_signatures()
3. Optional: Add service hints for quick identification
4. Test with representative device data

## Assumptions & Limitations

### Assumptions
- Devices with similar functions have similar network signatures
- Standard ports typically run standard services
- Vendor information from MAC addresses is reliable
- Higher port counts indicate more complex devices

### Limitations
- Cannot distinguish between similar devices (e.g., web server vs application server)
- Relies on observable characteristics only
- Firewalled devices may be misclassified
- Custom applications on standard ports can cause confusion

### Edge Cases
- Devices with no open ports: Classified as 'unknown'
- Multi-function devices: Classified by primary function
- Virtual machines: May inherit hypervisor characteristics
- Containers: Limited distinguishing features

## Troubleshooting

### Common Issues

1. **Routers classified as switches**
   - Both have similar management ports
   - Check for BGP (179) or routing protocols
   - Vendor info helps differentiate

2. **Servers misclassified**
   - Many servers run multiple services
   - Check primary service ports
   - OS fingerprint provides hints

3. **Low confidence scores**
   - Limited open ports due to firewall
   - Try deeper scan for more data
   - Enable SNMP for additional info

4. **IoT devices as 'unknown'**
   - Often have minimal signatures
   - Check for vendor-specific ports
   - May need custom signatures

## Future Considerations

1. **Machine Learning Enhancement**
   - Train on large datasets
   - Improve ambiguous classifications
   - Adapt to new device types

2. **Behavioral Classification**
   - Analyze traffic patterns
   - Identify by network behavior
   - Complement port-based approach

3. **Custom Signatures**
   - User-defined device types
   - Industry-specific devices
   - Private cloud services

4. **Confidence Improvement**
   - Weighted voting system
   - Historical data integration
   - Correlation with other tools

## Classification Method Transparency

The classifier tracks how each device was classified:
- **signature_match**: Primary signature matching
- **service_hint**: Quick identification via service
- **vendor_match**: Strong vendor correlation
- **fallback**: Default classification

This transparency helps in:
- Debugging misclassifications
- Improving signatures
- Understanding edge cases