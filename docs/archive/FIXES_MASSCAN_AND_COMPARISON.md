# NetworkMapper v2 - Fixes for Masscan Display and Comparison Report

## Issues Fixed

### 1. Masscan Not Shown in Available Tools
**Problem**: The dashboard only displayed `nmap` and `arp-scan` in the Available Tools list, even though masscan is supported.

**Solution**: Added masscan check to the tools status in `modern_interface.py`:
```python
# Check for masscan
try:
    subprocess.run(["masscan", "--version"], capture_output=True, check=True)
    tools_branch.add("[green]✓[/green] masscan")
except:
    tools_branch.add("[yellow]○[/yellow] masscan (optional)")
```

### 2. Comparison Report Error
**Problem**: When running option 3 (Compare to Last Scan), the comparison report generation failed with:
```
TypeError: 'builtin_function_or_method' object is not iterable
```

**Root Cause**: The comparison template was trying to access `change.values` which Python interprets as the dictionary's built-in `.values()` method instead of a dictionary key.

**Solution**: Modified the comparison report template to handle both `port_list` (used by tracker.py) and `values` (used by mapper.py) attributes:
```jinja2
{% if change.port_list is defined %}{{ change.port_list|join(', ') }}
{% elif change.values is defined %}{{ change.values|join(', ') }}{% endif %}
```

## How to Test

1. **Check Masscan Display**:
   - Run `python3 mapper.py`
   - Look at the dashboard on the right side
   - Under "Available Tools" you should now see:
     - ✓ nmap
     - ✓ arp-scan (or ○ if not installed)
     - ✓ masscan (or ○ if not installed)

2. **Test Comparison Report**:
   - Run a scan of a network
   - Run another scan of the same network
   - Select option 3 "Change Detection"
   - The comparison report should now generate without errors
   - It will automatically open in your browser

## Files Modified
- `/home/connorboetig/v2/modern_interface.py` - Added masscan availability check
- `/home/connorboetig/v2/templates/comparison_report.html` - Fixed template to handle both attribute names