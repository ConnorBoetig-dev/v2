# NetworkMapper v2 - Comparison CSV Export Feature

## Feature Added
Added the ability to download network comparison data as a CSV file from the comparison report page.

## Implementation Details

### 1. New Button Added
- Added a "Download CSV" button to the comparison report page
- Placed alongside the existing "Print Comparison" button
- Uses the same styling as other secondary buttons

### 2. CSV Export Functionality
The CSV file includes:

#### Header Information
- Report generation timestamp
- Previous scan date/time and device count
- Current scan date/time and device count

#### Change Summary
- Total counts for each type of change:
  - New devices
  - Missing devices  
  - Modified devices
  - Unchanged devices

#### Detailed Device Lists

**New Devices Section**:
- IP Address
- Hostname
- Device Type
- Vendor
- Operating System
- Services (semicolon-separated)
- Open Ports (semicolon-separated)

**Missing Devices Section**:
- IP Address
- Hostname
- Device Type
- Vendor
- Last Seen timestamp

**Modified Devices Section**:
- IP Address
- Hostname
- Device Type
- All changes in a single field (semicolon-separated)
  - Format: "field: old → new" for changes
  - Format: "field added: values" for additions
  - Format: "field removed: values" for removals
  - Format: "Ports opened: port list" for opened ports
  - Format: "Ports closed: port list" for closed ports

### 3. CSV Format Features
- Proper CSV escaping for fields containing commas, quotes, or newlines
- Human-readable format with section headers
- Timestamp in filename for easy organization
- Downloads with filename format: `network_comparison_YYYY-MM-DDTHH-MM-SS.csv`

## How to Use

1. Run at least two scans of the same network
2. Go to the comparison report (either via option 3 in the menu or by clicking "Compare to Last Scan" in a report)
3. Click the "Download CSV" button at the bottom of the comparison report
4. The CSV file will download automatically to your browser's download folder

## Example CSV Output

```csv
Network Comparison Report - Generated 1/10/2025, 3:45:00 PM

Previous Scan,2025-01-10 15:30:00
Current Scan,2025-01-10 15:45:00
Previous Device Count,45
Current Device Count,48

Change Summary
Type,Count
New Devices,3
Missing Devices,0
Modified Devices,5
Unchanged Devices,40

NEW DEVICES
IP,Hostname,Type,Vendor,OS,Services,Open Ports
10.1.100.55,web-server-03,linux_server,Dell Inc.,Ubuntu 20.04,ssh:22; http:80; https:443,22; 80; 443
10.1.100.56,db-server-02,database,Oracle,Oracle Linux 8,ssh:22; mysql:3306,22; 3306
10.1.100.57,workstation-15,workstation,HP,Windows 10,rdp:3389,3389

MODIFIED DEVICES
IP,Hostname,Type,Changes
10.1.100.24,app-server-01,server,Ports opened: 8080; services added: http:8080
10.1.100.25,web-server-02,server,hostname: web-02 → web-server-02
```

## Files Modified
- `/home/connorboetig/v2/templates/comparison_report.html` - Added download button and JavaScript function