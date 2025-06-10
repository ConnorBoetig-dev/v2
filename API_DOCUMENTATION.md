# NetworkMapper v2 API Documentation

## Vulnerability APIs

NetworkMapper uses multiple free, keyless vulnerability APIs to provide comprehensive security assessment without requiring registration or API keys.

### 1. OSV (Open Source Vulnerabilities) - Primary API

**Overview**: Google's Open Source Vulnerabilities database providing CVE and vulnerability data for major ecosystems.

**Endpoint**: `https://api.osv.dev/v1/query`

**Method**: POST

**Request Format**:
```json
{
    "query": "apache",
    "version": "2.4.41"  // optional
}
```

**Response Format**:
```json
{
    "vulns": [
        {
            "id": "CVE-2023-12345",
            "summary": "Apache HTTP Server vulnerability",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": 7.5
                }
            ],
            "published": "2023-01-15T00:00:00Z",
            "database_specific": {
                "severity": "HIGH"
            }
        }
    ]
}
```

**Usage in NetworkMapper**:
- Primary API for vulnerability lookups
- Searches by service name and version
- Caches results for 24 hours to minimize API calls
- No rate limiting required for normal usage

### 2. CIRCL CVE Search - Fallback API

**Overview**: Community-maintained mirror of the full CVE dataset by CIRCL (Computer Incident Response Center Luxembourg).

**Endpoint**: `https://cve.circl.lu/api/search/{keyword}`

**Method**: GET

**Example**: `https://cve.circl.lu/api/search/apache`

**Response Format**:
```json
[
    {
        "id": "CVE-2023-12345",
        "summary": "Apache HTTP Server allows remote attackers...",
        "cvss": 7.5,
        "Published": "2023-01-15",
        "references": ["https://nvd.nist.gov/..."]
    }
]
```

**Usage in NetworkMapper**:
- Fallback when OSV returns no results
- Simple keyword-based search
- Returns up to 10 most relevant CVEs
- No authentication required

### 3. Local Vulnerability Patterns

When APIs are unavailable or return no results, NetworkMapper uses built-in vulnerability patterns:

**Coverage**:
- Telnet (port 23): Clear text transmission vulnerability
- FTP (port 21): Clear text credentials
- HTTP (port 80): Unencrypted traffic
- SNMP (port 161): Default community strings
- SSH (port 22): Brute force exposure
- RLogin (port 513): Weak authentication
- Finger (port 79): Information disclosure
- NetBIOS (ports 135, 137-139, 445): Lateral movement risks

**Example Pattern**:
```python
{
    'telnet': {
        'cve_id': 'LOCAL-TELNET-001',
        'description': 'Telnet transmits data in clear text...',
        'cvss_score': 7.5,
        'severity': 'HIGH',
        'source': 'Local Security Assessment'
    }
}
```

## API Testing

### Testing OSV API

```bash
# Test with curl
curl -X POST https://api.osv.dev/v1/query \
  -H "Content-Type: application/json" \
  -d '{"query": "apache"}'

# Python test
import requests

response = requests.post(
    'https://api.osv.dev/v1/query',
    json={'query': 'apache', 'version': '2.4.41'}
)
print(response.json())
```

### Testing CIRCL API

```bash
# Test with curl
curl https://cve.circl.lu/api/search/apache

# Python test
import requests

response = requests.get('https://cve.circl.lu/api/search/apache')
print(response.json()[:3])  # First 3 results
```

## Integration Flow

1. **Service Detection**: NetworkMapper identifies services during scan
2. **Service Parsing**: Extracts service name and version from scan results
3. **API Query Order**:
   - Check local cache first (24-hour TTL)
   - Query OSV API
   - If no results, query CIRCL API
   - If still no results, use local patterns
4. **Result Processing**: 
   - Calculate relevance scores
   - Normalize severity ratings
   - Cache results for future use
5. **Report Integration**: Vulnerability data added to all exports

## Error Handling

- **Network Errors**: Gracefully falls back to next API or local patterns
- **Rate Limiting**: 2-second delay between API requests
- **Invalid Responses**: Logged and skipped, continues with next source
- **Cache Failures**: Non-blocking, continues with API queries

## Performance Considerations

- **Caching**: 24-hour cache reduces API calls by ~90%
- **Parallel Processing**: Devices scanned independently
- **Result Limits**: Maximum 10 vulnerabilities per service
- **Timeout**: 10-second timeout per API request

## Security Notes

- No API keys stored or transmitted
- All APIs use HTTPS
- No sensitive data sent to APIs (only service names)
- Results validated before display

## Usage Examples

### Basic Vulnerability Scan
```python
from utils.vulnerability_scanner import VulnerabilityScanner

scanner = VulnerabilityScanner()
devices = [
    {
        'ip': '192.168.1.1',
        'services': ['apache:80 (Apache 2.4.41)'],
        'open_ports': [80]
    }
]

enriched = scanner.scan_devices(devices)
for device in enriched:
    print(f"{device['ip']}: {device.get('vulnerability_count', 0)} vulnerabilities")
```

### Generate Vulnerability Report
```python
report = scanner.generate_vulnerability_report(enriched)
print(f"Total vulnerabilities: {report['total_vulnerabilities']}")
print(f"Critical: {report['critical_vulnerabilities']}")
print(f"High: {report['high_vulnerabilities']}")
```

## Troubleshooting

**No vulnerabilities found**:
- Service may be too new for vulnerability databases
- Service name might not match API keywords
- Try manual search on https://osv.dev or https://cve.circl.lu

**API timeouts**:
- Check internet connectivity
- APIs may be temporarily unavailable
- Local patterns will be used as fallback

**Incorrect severity ratings**:
- CVSS scores are estimates when not provided by API
- Check original CVE for authoritative scores