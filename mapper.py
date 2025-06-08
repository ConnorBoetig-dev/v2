#!/usr/bin/env python3
"""
NetworkMapper 2.0 - Network Discovery and Mapping Tool
"""

import typer
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from pathlib import Path
import json
import csv
from datetime import datetime
from typing import Optional
import subprocess
import os

from core.scanner import NetworkScanner
from core.parser import ScanParser
from core.classifier import DeviceClassifier
from core.tracker import ChangeTracker
from core.annotator import DeviceAnnotator
from utils.visualization import MapGenerator

app = typer.Typer()
console = Console()

class NetworkMapper:
    def __init__(self):
        self.base_path = Path(__file__).parent
        self.output_path = self.base_path / "output"
        self.ensure_directories()
        self.scanner = NetworkScanner()
        self.parser = ScanParser()
        self.classifier = DeviceClassifier()
        self.tracker = ChangeTracker()
        self.annotator = DeviceAnnotator()
        self.map_gen = MapGenerator()
        
    def ensure_directories(self):
        """Create output directories if they don't exist"""
        dirs = [
            self.output_path / "scans",
            self.output_path / "reports", 
            self.output_path / "changes"
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)
    
    def interactive_menu(self):
        """Main interactive menu"""
        while True:
            console.clear()
            console.print(Panel.fit(
                "[bold cyan]NetworkMapper 2.0[/bold cyan]\n"
                "Network Discovery & Asset Management",
                border_style="cyan"
            ))
            
            choices = {
                "1": "🔍 Run Network Scan",
                "2": "📊 View Recent Scans",
                "3": "🔄 Check Changes",
                "4": "✏️  Annotate Devices",
                "5": "📈 Generate Reports",
                "6": "🗺️  View Network Map",
                "7": "📤 Export Data",
                "8": "❌ Exit"
            }
            
            for key, value in choices.items():
                console.print(f"  {key}. {value}")
            
            choice = Prompt.ask("\nSelect option", choices=list(choices.keys()))
            
            if choice == "1":
                self.run_scan_wizard()
            elif choice == "2":
                self.view_recent_scans()
            elif choice == "3":
                self.check_changes()
            elif choice == "4":
                self.annotate_devices()
            elif choice == "5":
                self.generate_reports()
            elif choice == "6":
                self.view_network_map()
            elif choice == "7":
                self.export_data()
            elif choice == "8":
                if Confirm.ask("Exit NetworkMapper?"):
                    break
    
    def run_scan_wizard(self):
        """Interactive scan wizard"""
        console.print("\n[bold]Network Scan Wizard[/bold]")
        
        # Get target
        target = Prompt.ask("Enter target network", default="192.168.1.0/24")
        
        # Select scan type
        scan_types = {
            "1": ("discovery", "Discovery Scan", "~30 seconds", False),
            "2": ("inventory", "Inventory Scan", "~5 minutes", True),
            "3": ("deep", "Deep Scan", "~15 minutes", True)
        }
        
        console.print("\n[bold]Scan Types:[/bold]")
        for key, (_, name, time, root) in scan_types.items():
            root_txt = " [red](requires sudo)[/red]" if root else ""
            console.print(f"  {key}. {name} ({time}){root_txt}")
        
        scan_choice = Prompt.ask("Select scan type", choices=list(scan_types.keys()))
        scan_type, scan_name, _, needs_root = scan_types[scan_choice]
        
        # Use masscan for discovery?
        use_masscan = False
        if scan_type == "discovery":
            use_masscan = Confirm.ask("Use masscan for faster discovery?", default=False)
        
        # Run scan
        console.print(f"\n[yellow]Starting {scan_name} on {target}...[/yellow]")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results = self.scanner.scan(
            target=target,
            scan_type=scan_type,
            use_masscan=use_masscan,
            needs_root=needs_root
        )
        
        # Parse and classify
        devices = self.parser.parse_results(results)
        devices = self.classifier.classify_devices(devices)
        
        # Save results
        scan_file = self.output_path / "scans" / f"scan_{timestamp}.json"
        csv_file = self.output_path / "scans" / f"scan_{timestamp}.csv"
        
        with open(scan_file, 'w') as f:
            json.dump(devices, f, indent=2)
        
        self.save_csv(devices, csv_file)
        
        # Check for changes
        changes = self.tracker.detect_changes(devices)
        if changes:
            self.save_changes(changes, timestamp)
        
        # Summary
        console.print(f"\n[green]✓ Scan complete![/green]")
        console.print(f"Found {len(devices)} devices")
        console.print(f"Results saved to: {scan_file}")
        
        if Confirm.ask("\nGenerate HTML report?"):
            self.generate_html_report(devices, timestamp)
        
        input("\nPress Enter to continue...")
    
    def save_csv(self, devices, filepath):
        """Save devices to CSV"""
        if not devices:
            return
            
        with open(filepath, 'w', newline='') as f:
            fieldnames = [
                'ip', 'hostname', 'mac', 'vendor', 'type', 
                'os', 'services', 'open_ports', 'critical', 
                'notes', 'last_seen'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for device in devices:
                row = {
                    'ip': device.get('ip'),
                    'hostname': device.get('hostname', ''),
                    'mac': device.get('mac', ''),
                    'vendor': device.get('vendor', ''),
                    'type': device.get('type', 'unknown'),
                    'os': device.get('os', ''),
                    'services': ';'.join(device.get('services', [])),
                    'open_ports': ';'.join(map(str, device.get('open_ports', []))),
                    'critical': device.get('critical', False),
                    'notes': device.get('notes', ''),
                    'last_seen': device.get('last_seen', datetime.now().isoformat())
                }
                writer.writerow(row)

mapper = NetworkMapper()

@app.command()
def main():
    """NetworkMapper 2.0 - Network Discovery & Mapping Tool"""
    try:
        mapper.interactive_menu()
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user[/red]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")

if __name__ == "__main__":
    app()
