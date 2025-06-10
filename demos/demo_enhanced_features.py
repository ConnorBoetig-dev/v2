#!/usr/bin/env python3
"""
Demo script showcasing enhanced NetworkMapper v2 features:
1. Per-subnet auto-tagging
2. Scan summary footers
3. Modern sudo handling
"""

import json
import time
from datetime import datetime
from pathlib import Path

# Add parent directory to path
import sys
sys.path.append(str(Path(__file__).parent.parent))

from modern_interface import ModernInterface
from mapper import NetworkMapper
from rich.console import Console
from rich.panel import Panel

console = Console()

def demo_subnet_tagging():
    """Demonstrate subnet auto-tagging feature"""
    console.print(Panel(
        "🏷️ Subnet Auto-Tagging Demo\n"
        "Automatically tags devices by subnet and VLAN",
        title="[bold cyan]Feature 1: Per-Subnet Auto-Naming[/bold cyan]",
        border_style="cyan"
    ))
    
    # Create sample devices across multiple subnets
    sample_devices = [
        {'ip': '10.0.1.1', 'hostname': 'router01', 'type': 'router', 'open_ports': [22, 80, 443]},
        {'ip': '10.0.1.10', 'hostname': 'server01', 'type': 'server', 'open_ports': [22, 80]},
        {'ip': '10.0.2.5', 'hostname': 'workstation01', 'type': 'workstation', 'open_ports': [135, 445]},
        {'ip': '10.0.2.15', 'hostname': 'printer01', 'type': 'printer', 'open_ports': [9100, 631]},
        {'ip': '192.168.1.1', 'hostname': 'home-router', 'type': 'router', 'open_ports': [80, 443]},
        {'ip': '192.168.1.100', 'hostname': 'laptop', 'type': 'workstation', 'open_ports': [22]},
    ]
    
    # Initialize interface and apply subnet tagging
    mapper = NetworkMapper()
    interface = ModernInterface(mapper)
    
    tagged_devices = interface._add_subnet_tags(sample_devices)
    
    console.print("\n[bold green]✅ Subnet tagging applied successfully![/bold green]\n")
    
    # Show results
    for device in tagged_devices:
        console.print(f"[cyan]Device:[/cyan] {device['ip']} ({device['hostname']})")
        console.print(f"[yellow]  Subnet:[/yellow] {device.get('subnet', 'Unknown')}")
        console.print(f"[yellow]  Tags:[/yellow] {', '.join(device.get('tags', []))}")
        console.print(f"[yellow]  Description:[/yellow] {device.get('subnet_description', 'N/A')}")
        console.print()
    
    return tagged_devices

def demo_scan_metadata():
    """Demonstrate scan summary metadata"""
    console.print(Panel(
        "📊 Scan Summary Footer Demo\n"
        "Comprehensive scan metadata in reports",
        title="[bold green]Feature 2: Scan Summary Footer[/bold green]",
        border_style="green"
    ))
    
    # Create mock scan configuration
    config = {
        'target': '10.0.1.0/24',
        'scan_name': 'Inventory Scan',
        'scan_duration': '2m 35s',
        'snmp_enabled': True,
        'vuln_enabled': True,
        'passive_enabled': False
    }
    
    # Use devices from previous demo
    mapper = NetworkMapper()
    interface = ModernInterface(mapper)
    
    sample_devices = [
        {'ip': '10.0.1.1', 'hostname': 'router01', 'type': 'router', 'services': ['ssh', 'http', 'https'], 'vulnerabilities': []},
        {'ip': '10.0.1.10', 'hostname': 'server01', 'type': 'server', 'services': ['ssh', 'http'], 'vulnerabilities': [{'cve_id': 'CVE-2023-1234', 'severity': 'HIGH'}]},
        {'ip': '10.0.1.20', 'hostname': 'workstation01', 'type': 'workstation', 'services': ['smb'], 'vulnerabilities': []},
    ]
    
    # Apply subnet tagging
    sample_devices = interface._add_subnet_tags(sample_devices)
    
    # Save metadata
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    interface._save_scan_with_metadata(sample_devices, timestamp, config)
    
    console.print("[bold green]✅ Scan metadata saved successfully![/bold green]\n")
    
    # Show what would appear in the report footer
    console.print("[bold blue]📄 Report Footer Preview:[/bold blue]")
    console.print(f"[cyan]• Scan Start Time:[/cyan] {timestamp}")
    console.print(f"[cyan]• Duration:[/cyan] {config['scan_duration']}")
    console.print(f"[cyan]• Devices Found:[/cyan] {len(sample_devices)}")
    console.print(f"[cyan]• Services Scanned:[/cyan] {interface._count_services(sample_devices)}")
    console.print(f"[cyan]• Vulnerabilities:[/cyan] {interface._count_vulnerabilities(sample_devices)}")
    console.print(f"[cyan]• Target Range:[/cyan] {config['target']}")
    console.print(f"[cyan]• Discovered Subnets:[/cyan] {', '.join(interface._get_discovered_subnets(sample_devices))}")
    
    return timestamp

def demo_modern_sudo():
    """Demonstrate improved sudo handling"""
    console.print(Panel(
        "🔐 Modern Sudo Handling Demo\n"
        "Enhanced authentication with better UX",
        title="[bold yellow]Feature 3: Improved Sudo Integration[/bold yellow]",
        border_style="yellow"
    ))
    
    console.print("[bold green]✅ Sudo handling improvements:[/bold green]\n")
    console.print("[cyan]1.[/cyan] Pre-authentication check before scan starts")
    console.print("[cyan]2.[/cyan] Clear progress feedback during authentication")
    console.print("[cyan]3.[/cyan] No interference with password prompts")
    console.print("[cyan]4.[/cyan] Graceful fallback for failed authentication")
    console.print("[cyan]5.[/cyan] Better error messages and user guidance")
    
    console.print("\n[yellow]🔍 How it works:[/yellow]")
    console.print("• Checks existing sudo access first")
    console.print("• Prompts for password only when needed")
    console.print("• No progress bars during authentication")
    console.print("• Clear success/failure feedback")
    console.print("• Allows scan cancellation on auth failure")

def demo_report_generation():
    """Show how reports now include enhanced metadata"""
    console.print(Panel(
        "📄 Enhanced Report Generation\n"
        "Reports now include comprehensive scan summaries",
        title="[bold magenta]Feature 4: Report Enhancement[/bold magenta]",
        border_style="magenta"
    ))
    
    # Show what's new in reports
    console.print("[bold green]✅ Report enhancements:[/bold green]\n")
    console.print("[cyan]📊 Scan Summary Footer includes:[/cyan]")
    console.print("  • Scan start time and duration")
    console.print("  • Number of devices and services found")
    console.print("  • Vulnerability count and severity")
    console.print("  • Target range and subnet breakdown")
    console.print("  • Scan parameters (SNMP, vuln scan, etc.)")
    
    console.print("\n[cyan]🏷️ Subnet Information includes:[/cyan]")
    console.print("  • Automatic subnet detection and tagging")
    console.print("  • Visual subnet grouping in device tables")
    console.print("  • Subnet-based device organization")
    console.print("  • Network topology visualization")
    
    console.print("\n[cyan]📈 Better Context for:[/cyan]")
    console.print("  • Comparing reports over time")
    console.print("  • Multi-site network management")
    console.print("  • Audit trails and compliance")
    console.print("  • Change tracking and analysis")

def main():
    """Run all feature demonstrations"""
    console.clear()
    
    header = Panel.fit(
        "[bold cyan]NetworkMapper v2 - Enhanced Features Demo[/bold cyan]\n"
        "Showcasing new subnet tagging and scan metadata features",
        border_style="cyan"
    )
    console.print(header)
    console.print()
    
    # Demo 1: Subnet tagging
    devices = demo_subnet_tagging()
    input("\nPress Enter to continue to next demo...")
    console.clear()
    
    # Demo 2: Scan metadata
    timestamp = demo_scan_metadata()
    input("\nPress Enter to continue to next demo...")
    console.clear()
    
    # Demo 3: Sudo handling
    demo_modern_sudo()
    input("\nPress Enter to continue to final demo...")
    console.clear()
    
    # Demo 4: Report generation
    demo_report_generation()
    
    # Final summary
    console.print("\n" + "="*60)
    console.print(Panel(
        "[bold green]🎉 Demo Complete![/bold green]\n\n"
        "All enhanced features are now active:\n"
        "• ✅ Per-subnet auto-naming and tagging\n"
        "• ✅ Comprehensive scan summary footers\n"
        "• ✅ Improved sudo password handling\n"
        "• ✅ Enhanced report generation\n\n"
        "[cyan]Run 'python3 mapper.py' to experience the new interface![/cyan]",
        border_style="green",
        padding=(1, 2)
    ))
    
    # Show file locations
    console.print(f"\n[dim]Demo files saved to output/scans/[/dim]")
    console.print(f"[dim]Check output/reports/ for generated HTML reports[/dim]")

if __name__ == "__main__":
    main()