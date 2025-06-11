# NetworkMapper v2 - Compare Last Scan Button Fix

## Issue Fixed
The "Compare Last Scan" button in HTML reports was not working correctly. It needed to:
1. Automatically compare to the last scan of the same subnet
2. Display changes clearly
3. Open the comparison report when clicked

## Solution Implemented

### 1. Backend Changes (mapper.py)
- Modified `generate_html_report()` to pass comparison file information to the template:
  ```python
  "comparison_file": comparison_file_name,
  "has_changes": bool(self.last_changes and self.last_changes.get("summary", {}).get("total_changes", 0) > 0),
  ```

### 2. Frontend Changes (report.html)
- Updated the JavaScript `compareToLastScan()` function to use the template variables:
  ```javascript
  function compareToLastScan() {
      // Check if comparison file is available from template
      {% if comparison_file %}
          window.location.href = '{{ comparison_file }}';
      {% else %}
          // Fallback to checking if comparison file exists
          const comparisonUrl = `comparison_${scanTimestamp}.html`;
          fetch(comparisonUrl, { method: 'HEAD' })
              .then(response => {
                  if (response.ok) {
                      window.location.href = comparisonUrl;
                  } else {
                      alert('No comparison report available. Run at least 2 scans of the same network to see comparisons.');
                  }
              })
              .catch(() => {
                  alert('No comparison report available. Run at least 2 scans of the same network to see comparisons.');
              });
      {% endif %}
  }
  ```

### 3. Visual Enhancements
- Added a "Changes!" badge to the button when changes are detected
- Added pulsing animation for the button when changes exist
- Improved error messages to be more user-friendly

### 4. CSS Styling
- Added special styling for the button when changes are detected:
  ```css
  .btn-info.has-changes {
      background: #ce9178;
      animation: pulse 2s ease-in-out infinite;
  }
  
  @keyframes pulse {
      0% { transform: scale(1); }
      50% { transform: scale(1.02); }
      100% { transform: scale(1); }
  }
  ```

## How It Works Now

1. **During Scan**: When a scan completes, the system automatically checks for changes and generates a comparison report if changes are detected.

2. **Button Behavior**: 
   - If changes exist, the button shows a "Changes!" badge and pulses
   - When clicked, it immediately opens the comparison report
   - If no comparison exists, it shows a helpful message

3. **Subnet Detection**: The comparison automatically uses the last scan of the same subnet (this was already working in the backend)

## Testing
To test the fix:
1. Run a scan of a network
2. Make some changes (add/remove devices)
3. Run another scan of the same network
4. Open the HTML report
5. The "Compare to Last Scan" button should:
   - Show a "Changes!" badge
   - Have a pulsing animation
   - Open the comparison report when clicked

## Related Files Modified
- `/home/connorboetig/v2/mapper.py` - Added comparison file info to report data
- `/home/connorboetig/v2/templates/report.html` - Updated JavaScript and added visual enhancements