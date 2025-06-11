"""
Scan Status Indicator - Simple visual indication that scan is running

This module provides a lightweight status indicator that works alongside
the existing Rich progress bars in the scanner module.
"""

import time
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.text import Text


class ScanStatusIndicator:
    """Simple scan status indicator that shows scan is in progress"""
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self._panel = None
        
    def show_scan_starting(self, target: str, scan_type: str):
        """Show scan is starting"""
        # Create status text
        status_text = Text()
        status_text.append("🔍 SCAN IN PROGRESS\n\n", style="bold cyan blink")
        status_text.append(f"Target: ", style="dim")
        status_text.append(f"{target}\n", style="white")
        status_text.append(f"Type: ", style="dim")
        status_text.append(f"{scan_type.title()} Scan\n", style="white")
        status_text.append(f"\nStarted: ", style="dim")
        status_text.append(f"{time.strftime('%H:%M:%S')}", style="white")
        
        # Create panel
        self._panel = Panel(
            Align.center(status_text, vertical="middle"),
            title="[bold]Network Scanner Active[/bold]",
            border_style="cyan",
            height=9,
            width=50,
            padding=(1, 2)
        )
        
        # Display the panel
        self.console.print("\n")
        self.console.print(self._panel)
        self.console.print("\n")
        
        # Add note about progress
        self.console.print(
            "[dim]Progress details will appear below as the scan proceeds...[/dim]\n"
        )
    
    def show_scan_complete(self, device_count: int = 0):
        """Show scan completed"""
        self.console.print(f"\n[bold green]✅ Scan Complete![/bold green] Found {device_count} devices.\n")


class ScanPhaseTracker:
    """Track and display current scan phase"""
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.current_phase = None
        
    def update_phase(self, phase: str, details: str = ""):
        """Update current scan phase"""
        if phase != self.current_phase:
            self.current_phase = phase
            
            # Map phases to user-friendly descriptions
            phase_descriptions = {
                "discovery": "🔍 Discovering hosts on the network",
                "port_scan": "🔌 Scanning for open ports",
                "service_detection": "🔧 Detecting services and versions",
                "os_detection": "💻 Identifying operating systems",
                "script_scan": "📝 Running detection scripts",
                "enrichment": "📊 Enriching device information",
                "snmp": "📡 Querying SNMP data",
                "complete": "✅ Finalizing results"
            }
            
            description = phase_descriptions.get(phase, f"⚡ {phase}")
            
            # Print phase update
            if details:
                self.console.print(f"\n{description} - {details}")
            else:
                self.console.print(f"\n{description}")


def integrate_with_scanner(scanner_class):
    """Decorator to add scan status indication to scanner"""
    original_scan = scanner_class.scan
    
    def scan_with_status(self, *args, **kwargs):
        # Create status indicator
        console = getattr(self, 'console', Console())
        status = ScanStatusIndicator(console)
        
        # Extract target and scan type
        target = args[0] if args else kwargs.get('target', 'unknown')
        scan_type = kwargs.get('scan_type', 'discovery')
        
        # Show scan starting
        status.show_scan_starting(target, scan_type)
        
        # Run original scan
        try:
            result = original_scan(self, *args, **kwargs)
            
            # Show completion
            device_count = len(result) if result else 0
            status.show_scan_complete(device_count)
            
            return result
            
        except Exception as e:
            console.print(f"\n[red]❌ Scan failed: {e}[/red]\n")
            raise
    
    scanner_class.scan = scan_with_status
    return scanner_class