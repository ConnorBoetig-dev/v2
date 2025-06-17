# NetworkMapper Templates Documentation

## Overview

NetworkMapper uses Jinja2 templates to generate HTML reports and visualizations. The templates combine modern web technologies (D3.js, Three.js) with a cohesive dark theme design system to provide interactive network analysis interfaces.

## Template Files

### 1. report.html - Main Network Scan Report

**Purpose**: Primary report interface showing scan results in a tabbed layout

**Key Sections**:
- **Header**: Scan metadata and quick actions
- **Summary Tab**: Dashboard with key metrics and statistics cards
- **Devices Tab**: Searchable/sortable device inventory table
- **Security Tab**: Vulnerability analysis and risk assessment
- **Services Tab**: Network service distribution and details
- **Changes Tab**: Comparison with previous scans (if available)

**Template Variables**:
```python
{
    'scan_date': str,           # Scan timestamp
    'total_devices': int,       # Device count
    'device_types': dict,       # Type distribution
    'critical_count': int,      # Critical devices
    'new_devices': list,        # Recently discovered
    'vulnerability_summary': dict,  # Security metrics
    'devices': list,           # Complete device data
    'subnet_summary': dict,    # Network segmentation
    'traffic_analysis': dict   # Traffic flow data (optional)
}
```

**Features**:
- Responsive dark theme design
- Interactive data tables with search
- Export functionality (PDF, Excel, CSV)
- Print-optimized CSS
- Accessibility considerations

### 2. network_visualization.html - Interactive Network Maps

**Purpose**: Dedicated visualization interface with 2D and 3D network views

**Visualization Types**:
1. **2D Force-Directed Graph** (D3.js)
   - Node positioning by force simulation
   - Color coding by device type
   - Link thickness by connection importance
   - Interactive tooltips and sidebars
   - PNG export capability

2. **3D Layered Network** (Three.js)
   - Vertical stratification by device role
   - Orbital camera controls
   - Glowing effects for critical nodes
   - Curved connection paths
   - Auto-rotation option

**Data Format**:
```javascript
networkData = {
    nodes: [
        {
            id: "192.168.1.1",
            name: "router-01",
            type: "router",
            group: 1,
            critical: true,
            services: ["ssh", "https"],
            vendor: "Cisco"
        }
    ],
    links: [
        {
            source: "192.168.1.1",
            target: "192.168.1.10",
            value: 3,
            type: "uplink"
        }
    ],
    metadata: {
        total_devices: 50,
        subnets: 3,
        device_types: {...}
    }
}
```

### 3. comparison_report.html - Scan Comparison View

**Purpose**: Side-by-side comparison of two network scans

**Features**:
- Visual diff highlighting (new, missing, changed)
- Device movement tracking
- Service changes detection
- Summary statistics
- Export comparison results

**Template Variables**:
```python
{
    'scan1_date': str,
    'scan2_date': str,
    'new_devices': list,      # Added devices
    'missing_devices': list,  # Removed devices
    'changed_devices': list,  # Modified devices
    'unchanged_count': int,
    'summary_stats': dict
}
```

### 4. traffic_flow_report.html - Passive Analysis Results

**Purpose**: Visualize traffic patterns from passive monitoring

**Unique Elements**:
- Flow-based visualization (actual traffic vs logical topology)
- Stealth device highlighting
- Traffic volume indicators
- Service correlation matrix
- Communication peer analysis

**Data Structure**:
```python
{
    'capture_duration': int,
    'total_flows': int,
    'discovered_devices': list,
    'stealth_devices': list,
    'flow_matrix': dict,      # Source->Dest traffic counts
    'service_usage': dict,
    'top_talkers': list
}
```

## Design System

### Color Palette

The templates use CSS custom properties for consistent theming:

```css
/* Background Hierarchy */
--bg-primary: #0a0e1a;      /* Main background */
--bg-secondary: #1a1f2e;    /* Cards/sections */
--bg-tertiary: #242938;     /* Nested elements */

/* Device Type Colors */
--device-router: #f59e0b;    /* Orange */
--device-switch: #3b82f6;    /* Blue */
--device-server: #10b981;    /* Green */
--device-workstation: #06b6d4; /* Cyan */
/* ... and 20+ more device types */

/* State Colors */
--state-new: #10b981;        /* Green for new */
--state-missing: #ef4444;    /* Red for missing */
--state-changed: #f59e0b;    /* Yellow for modified */
```

### Component Patterns

#### Status Cards
```html
<div class="status-card">
    <div class="card-header">
        <h3>{{ title }}</h3>
        <span class="badge badge-{{ status }}">{{ value }}</span>
    </div>
    <div class="card-body">
        {{ content }}
    </div>
</div>
```

#### Data Tables
```html
<table class="data-table sortable searchable">
    <thead>
        <tr>
            <th data-sort="ip">IP Address</th>
            <th data-sort="hostname">Hostname</th>
            <th data-sort="type">Type</th>
            <th>Actions</th>
        </tr>
    </thead>
    <tbody>
        <!-- Rows populated by JavaScript -->
    </tbody>
</table>
```

#### Interactive Controls
```html
<div class="control-group">
    <button class="control-btn" data-action="zoom-in">
        <i class="icon-zoom-in"></i> Zoom In
    </button>
    <button class="control-btn" data-action="export">
        <i class="icon-download"></i> Export
    </button>
</div>
```

## JavaScript Architecture

### Module Structure

```javascript
// Namespace for application code
const NetworkMapper = {
    // Core modules
    DataTable: {},      // Table management
    Visualization: {},  // D3/Three.js code
    Export: {},        // Export functionality
    Search: {},        // Search/filter logic
    
    // Utilities
    Utils: {},         // Helper functions
    Config: {},        // Configuration
    
    // State
    State: {
        currentView: '2d',
        selectedDevice: null,
        filters: {}
    }
};
```

### Event Handling

Templates use delegated event handling for dynamic content:

```javascript
document.addEventListener('click', (e) => {
    // Handle control buttons
    if (e.target.matches('[data-action]')) {
        const action = e.target.dataset.action;
        NetworkMapper.handleAction(action, e.target);
    }
    
    // Handle tab switching
    if (e.target.matches('.tab-btn')) {
        NetworkMapper.switchTab(e.target.dataset.tab);
    }
});
```

### Data Loading

```javascript
// Templates receive data through global variables
const networkData = {{ network_data | tojson }};
const deviceList = {{ devices | tojson }};

// Initialize visualizations after DOM ready
document.addEventListener('DOMContentLoaded', () => {
    NetworkMapper.init(networkData);
});
```

## Performance Optimizations

### 1. Lazy Loading
- Device details loaded on-demand
- Visualization renders visible nodes first
- Images use loading="lazy"

### 2. Virtual Scrolling
- Large tables use virtual scrolling
- Only visible rows are rendered
- Smooth scrolling maintained

### 3. Debounced Updates
```javascript
// Search debouncing
let searchTimeout;
searchInput.addEventListener('input', (e) => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
        NetworkMapper.Search.filter(e.target.value);
    }, 300);
});
```

### 4. Canvas Fallback
- 3D visualization falls back to 2D canvas for older browsers
- WebGL detection and graceful degradation

## Accessibility

### ARIA Labels
```html
<button aria-label="Open device details for {{ device.hostname }}">
    <i class="icon-info" aria-hidden="true"></i>
</button>
```

### Keyboard Navigation
- Tab order follows logical flow
- All controls keyboard accessible
- Focus indicators visible

### Screen Reader Support
- Meaningful alt text
- ARIA live regions for updates
- Semantic HTML structure

## Responsive Design

### Breakpoints
```css
/* Mobile: < 768px */
@media (max-width: 767px) {
    .sidebar { width: 100%; }
    .visualization { height: 50vh; }
}

/* Tablet: 768px - 1024px */
@media (min-width: 768px) and (max-width: 1024px) {
    .container { padding: 1rem; }
}

/* Desktop: > 1024px */
@media (min-width: 1025px) {
    .container { max-width: 1400px; }
}
```

## Template Extension

### Adding New Device Types

1. Update CSS color variable:
```css
--device-newtype: #hexcolor;
```

2. Add to device type mapping:
```javascript
deviceTypeColors['newtype'] = 'var(--device-newtype)';
```

3. Update icon mapping:
```javascript
deviceIcons['newtype'] = 'icon-newtype';
```

### Custom Visualizations

Templates support custom visualization modules:

```javascript
// Register custom visualization
NetworkMapper.Visualization.register('custom', {
    init: (container, data) => {
        // Custom D3/Three.js code
    },
    update: (data) => {
        // Update visualization
    },
    destroy: () => {
        // Cleanup
    }
});
```

## Best Practices

### 1. Data Sanitization
Always escape user data:
```jinja2
{{ device.hostname | e }}
{{ device.notes | safe }}  <!-- Only if HTML is intended -->
```

### 2. Error Handling
Graceful error states:
```javascript
try {
    NetworkMapper.Visualization.render(data);
} catch (error) {
    console.error('Visualization error:', error);
    showErrorMessage('Unable to render visualization');
}
```

### 3. Loading States
Show progress during operations:
```html
<div class="loading-overlay" id="loadingOverlay">
    <div class="spinner"></div>
    <p>Loading visualization...</p>
</div>
```

### 4. Memory Management
Clean up resources:
```javascript
// Remove event listeners
window.removeEventListener('resize', handleResize);

// Clear references
networkData = null;

// Dispose Three.js resources
renderer.dispose();
```

## Troubleshooting

### Common Issues

1. **Visualization not rendering**
   - Check browser console for errors
   - Verify data format is correct
   - Ensure WebGL is enabled (for 3D)

2. **Export not working**
   - Check browser download permissions
   - Verify canvas rendering completed
   - Try different export format

3. **Performance issues**
   - Reduce node count with filters
   - Disable animations
   - Use 2D view for large networks

4. **Template not loading**
   - Check Flask route configuration
   - Verify template path is correct
   - Look for Jinja2 syntax errors