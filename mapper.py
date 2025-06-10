#!/usr/bin/env python3
"""
NetworkMapper 2.0 - Network Discovery and Mapping Tool
"""

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from core.annotator import DeviceAnnotator
from core.classifier import DeviceClassifier
from core.parser import ScanParser
from core.scanner import NetworkScanner
from core.tracker import ChangeTracker
from utils.visualization import MapGenerator
from utils.export_manager import ExportManager
from utils.snmp_config import SNMPConfig
from utils.vulnerability_scanner import VulnerabilityScanner

app = typer.Typer()
console = Console()
logger = logging.getLogger(__name__)


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
        self.export_mgr = ExportManager(self.output_path)
        self.snmp_config = SNMPConfig(self.output_path / "config")
        self.vuln_scanner = VulnerabilityScanner(self.output_path / "cache")
        self.cli_overrides = {}
        self.last_changes = None

    def ensure_directories(self):
        """Create output directories if they don't exist"""
        dirs = [
            self.output_path / "scans",
            self.output_path / "reports",
            self.output_path / "changes",
            self.output_path / "config",
            self.output_path / "cache",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

    def interactive_menu(self):
        """Main interactive menu"""
        while True:
            console.clear()
            console.print(
                Panel.fit(
                    "[bold cyan]NetworkMapper 2.0[/bold cyan]\n"
                    "Network Discovery & Asset Management",
                    border_style="cyan",
                )
            )

            choices = {
                "1": "🔍 Run Network Scan",
                "2": "📊 View Recent Scans",
                "3": "🔄 Check Changes",
                "4": "✏️  Annotate Devices",
                "5": "📈 Generate Reports",
                "6": "🗺️  View Network Map",
                "7": "📤 Export Data",
                "8": "❌ Exit",
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
        """Interactive scan wizard with improved UX"""
        console.print("\n[bold cyan]Network Scan Wizard[/bold cyan]")

        # Get target with validation
        target = self._get_scan_target()

        # Select scan type with clear descriptions
        scan_type, scan_name, needs_root, use_masscan = self._select_scan_type()

        # Interactive SNMP setup (unless disabled via CLI)
        snmp_enabled, snmp_config = self._handle_snmp_setup()
        
        # Interactive vulnerability scanning setup
        vuln_enabled = self._handle_vulnerability_setup()

        # Run scan
        console.print(f"\n[yellow]Starting {scan_name} on {target}...[/yellow]\n")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Handle ARP scan separately
        if scan_type == "arp":
            results = self.scanner._run_arp_scan(target)
        else:
            results = self.scanner.scan(
                target=target, 
                scan_type=scan_type, 
                use_masscan=use_masscan, 
                needs_root=needs_root,
                snmp_config=snmp_config if snmp_enabled else None
            )

        # Parse and classify
        devices = self.parser.parse_results(results)
        devices = self.classifier.classify_devices(devices)
        
        # Vulnerability scanning if enabled
        if vuln_enabled:
            console.print("\n[cyan]Scanning for vulnerabilities...[/cyan]")
            try:
                devices = self.vuln_scanner.scan_devices(devices)
                
                # Generate vulnerability report
                vuln_report = self.vuln_scanner.generate_vulnerability_report(devices)
                self._display_vulnerability_summary(vuln_report)
            except Exception as e:
                console.print(f"[yellow]Warning: Vulnerability scanning failed: {e}[/yellow]")
                logger.error(f"Vulnerability scanning error: {e}")

        # Save results
        scan_file = self.output_path / "scans" / f"scan_{timestamp}.json"
        csv_file = self.output_path / "scans" / f"scan_{timestamp}.csv"

        with open(scan_file, "w") as f:
            json.dump(devices, f, indent=2)

        self.save_csv(devices, csv_file)

        # Check for changes
        changes = self.tracker.detect_changes(devices)
        if changes:
            self.save_changes(changes, timestamp)
            # Store changes for report generation
            self.last_changes = changes
        else:
            self.last_changes = None

        # Summary with aligned file paths
        console.print("\n[green]✓ Scan complete![/green]")
        console.print(f"Found {len(devices)} devices")
        console.print(f"\n[bold]Generated Files:[/bold]")

        # Create a table for file paths
        file_table = Table(show_header=False, box=None, padding=(0, 2))
        file_table.add_column("Type", style="cyan")
        file_table.add_column("Path", style="yellow")

        file_table.add_row("Scan data:", str(scan_file))
        file_table.add_row("CSV export:", str(csv_file))

        if changes:
            changes_json = self.output_path / "changes" / f"changes_{timestamp}.json"
            changes_txt = self.output_path / "changes" / f"changes_{timestamp}.txt"
            file_table.add_row("Changes JSON:", str(changes_json))
            file_table.add_row("Changes text:", str(changes_txt))

        console.print(file_table)

        # Automatically generate and open visualization
        console.print("\n[yellow]Generating interactive network visualization...[/yellow]")
        report_file, comparison_file = self.generate_html_report(devices, timestamp)

        # Show report paths
        console.print(f"\n[bold]Generated Files:[/bold]")
        report_table = Table(show_header=False, box=None, padding=(0, 2))
        report_table.add_column("Type", style="cyan")
        report_table.add_column("Path", style="yellow")

        report_table.add_row("Network Map:", str(report_file))
        if comparison_file:
            report_table.add_row("Comparison:", str(comparison_file))

        console.print(report_table)

        input("\nPress Enter to continue...")

    def save_csv(self, devices, filepath):
        """Save devices to CSV"""
        if not devices:
            return

        with open(filepath, "w", newline="") as f:
            fieldnames = [
                "ip",
                "hostname",
                "mac",
                "vendor",
                "type",
                "os",
                "services",
                "open_ports",
                "vulnerability_count",
                "critical_vulns",
                "high_vulns",
                "vulnerability_summary",
                "critical",
                "notes",
                "last_seen",
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for device in devices:
                # Create vulnerability summary
                vulns = device.get('vulnerabilities', [])
                vuln_summary = ""
                if vulns:
                    high_severity = [v for v in vulns if v.get('severity') in ['CRITICAL', 'HIGH']]
                    if high_severity:
                        vuln_summary = f"{len(high_severity)} high-risk issues: " + "; ".join([v.get('cve_id', 'Unknown') for v in high_severity[:3]])
                    else:
                        vuln_summary = f"{len(vulns)} issues detected"
                else:
                    vuln_summary = "No vulnerabilities detected"
                
                row = {
                    "ip": device.get("ip"),
                    "hostname": device.get("hostname", ""),
                    "mac": device.get("mac", ""),
                    "vendor": device.get("vendor", ""),
                    "type": device.get("type", "unknown"),
                    "os": device.get("os", ""),
                    "services": ";".join(device.get("services", [])),
                    "open_ports": ";".join(map(str, device.get("open_ports", []))),
                    "vulnerability_count": device.get("vulnerability_count", 0),
                    "critical_vulns": device.get("critical_vulns", 0),
                    "high_vulns": device.get("high_vulns", 0),
                    "vulnerability_summary": vuln_summary,
                    "critical": device.get("critical", False),
                    "notes": device.get("notes", ""),
                    "last_seen": device.get("last_seen", datetime.now().isoformat()),
                }
                writer.writerow(row)

    def save_changes(self, changes, timestamp):
        """Save change report"""
        if not changes:
            return

        changes_file = self.output_path / "changes" / f"changes_{timestamp}.json"
        with open(changes_file, "w") as f:
            json.dump(changes, f, indent=2)

        # Also save human-readable summary
        summary_file = self.output_path / "changes" / f"changes_{timestamp}.txt"
        with open(summary_file, "w") as f:
            f.write(f"Network Changes Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")

            if changes.get("new_devices"):
                f.write(f"NEW DEVICES ({len(changes['new_devices'])})\n")
                f.write("-" * 30 + "\n")
                for device in changes["new_devices"]:
                    f.write(
                        f"  • {device['ip']} - {device.get('hostname', 'N/A')} "
                        f"({device.get('type', 'unknown')})\n"
                    )
                f.write("\n")

            if changes.get("missing_devices"):
                f.write(f"MISSING DEVICES ({len(changes['missing_devices'])})\n")
                f.write("-" * 30 + "\n")
                for device in changes["missing_devices"]:
                    f.write(
                        f"  • {device['ip']} - {device.get('hostname', 'N/A')} "
                        f"({device.get('type', 'unknown')})\n"
                    )
                f.write("\n")

            if changes.get("changed_devices"):
                f.write(f"CHANGED DEVICES ({len(changes['changed_devices'])})\n")
                f.write("-" * 30 + "\n")
                for device in changes["changed_devices"]:
                    f.write(f"  • {device['ip']} - {device.get('hostname', 'N/A')}\n")
                    for change in device["changes"]:
                        f.write(f"    - {change['field']}: {change.get('action', 'changed')}\n")
                f.write("\n")

    def generate_html_report(self, devices, timestamp):
        """Generate HTML report with network visualization"""
        import webbrowser

        from jinja2 import Environment, FileSystemLoader

        # Apply annotations
        devices = self.annotator.apply_annotations(devices)

        # Generate visualization data
        d3_data = self.map_gen.generate_d3_data(devices)
        three_data = self.map_gen.generate_threejs_data(devices)

        # Setup Jinja2
        env = Environment(loader=FileSystemLoader(self.base_path / "templates"))
        
        # Get changes if available
        changes = {}
        if self.last_changes:
            changes = self.last_changes

        # Prepare report data
        report_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_timestamp": timestamp,
            "scan_date": datetime.now().strftime("%B %d, %Y"),
            "total_devices": len(devices),
            "devices": devices,
            "device_types": self._count_device_types(devices),
            "critical_devices": [d for d in devices if d.get("critical", False)],
            "d3_data": json.dumps(d3_data),
            "three_data": json.dumps(three_data),
            "subnet_summary": self._get_subnet_summary(devices),
            "changes": changes,  # Include changes data
        }

        # Generate BOTH reports
        generated_files = []
        
        # 1. Generate original detailed report
        original_template = env.get_template("report.html")
        original_report_file = self.output_path / "reports" / f"report_{timestamp}.html"
        original_html = original_template.render(**report_data)
        
        with open(original_report_file, "w") as f:
            f.write(original_html)
        
        generated_files.append(("Detailed Report", original_report_file))
        
        # 2. Generate new interactive visualization
        viz_template = env.get_template("network_visualization.html")
        viz_report_file = self.output_path / "reports" / f"network_map_{timestamp}.html"
        viz_html = viz_template.render(**report_data)
        
        with open(viz_report_file, "w") as f:
            f.write(viz_html)
            
        generated_files.append(("Network Map", viz_report_file))

        # Open BOTH in browser (visualization first, then report)
        viz_url = f"file://{viz_report_file.absolute()}"
        original_url = f"file://{original_report_file.absolute()}"
        
        # Open visualization first
        webbrowser.open(viz_url)
        # Small delay then open report
        import time
        time.sleep(0.5)
        webbrowser.open(original_url)

        # Show clickable links in terminal
        console.print("\n[green]✓ Reports generated and opened in browser![/green]")
        console.print(f"\n[bold cyan]Generated files:[/bold cyan]")
        console.print(f"[yellow]Network Visualization:[/yellow] [underline]{viz_url}[/underline]")
        console.print(f"[yellow]Detailed Report:[/yellow] [underline]{original_url}[/underline]\n")

        # Also generate comparison report if we have changes
        comparison_file = None
        scan_files = sorted((self.output_path / "scans").glob("scan_*.json"), reverse=True)
        if len(scan_files) >= 2:
            # Get changes for comparison
            with open(scan_files[0]) as f:
                current = json.load(f)
            changes = self.tracker.detect_changes(current)
            if changes:
                comparison_file = self.generate_comparison_report(devices, changes, timestamp)

        return viz_report_file, comparison_file

    def generate_comparison_report(self, current_devices, changes, timestamp):
        """Generate comparison report HTML"""
        if not changes or not changes.get("summary"):
            return None

        from jinja2 import Environment, FileSystemLoader

        # Get previous scan timestamp for comparison report naming
        scan_files = sorted((self.output_path / "scans").glob("scan_*.json"), reverse=True)
        if len(scan_files) < 2:
            return None

        # Load previous scan info
        previous_scan_file = scan_files[1]
        previous_timestamp = previous_scan_file.stem.replace("scan_", "")
        previous_time = datetime.strptime(previous_timestamp, "%Y%m%d_%H%M%S")
        current_time = datetime.strptime(timestamp, "%Y%m%d_%H%M%S")

        # Calculate unchanged devices
        total_current = len(current_devices)
        new_count = len(changes.get("new_devices", []))
        changed_count = len(changes.get("changed_devices", []))
        unchanged_count = total_current - new_count - changed_count

        # Setup Jinja2
        env = Environment(loader=FileSystemLoader(self.base_path / "templates"))
        template = env.get_template("comparison_report.html")

        # Prepare comparison data
        comparison_data = {
            "comparison_date": datetime.now().strftime("%B %d, %Y"),
            "previous_scan_time": previous_time.strftime("%Y-%m-%d %H:%M:%S"),
            "current_scan_time": current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "previous_device_count": changes["summary"].get("total_previous", 0),
            "current_device_count": changes["summary"].get("total_current", 0),
            "new_devices": changes.get("new_devices", []),
            "missing_devices": changes.get("missing_devices", []),
            "changed_devices": changes.get("changed_devices", []),
            "unchanged_count": unchanged_count,
            "current_scan_timestamp": timestamp,
        }

        # Render and save comparison report
        comparison_file = self.output_path / "reports" / f"comparison_{timestamp}.html"
        html_content = template.render(**comparison_data)

        with open(comparison_file, "w") as f:
            f.write(html_content)

        console.print(f"[green]✓ Comparison report generated[/green]")
        return comparison_file

    def _count_device_types(self, devices):
        """Count devices by type"""
        counts = {}
        for device in devices:
            dtype = device.get("type", "unknown")
            counts[dtype] = counts.get(dtype, 0) + 1
        return counts

    def _get_subnet_summary(self, devices):
        """Get subnet summary"""
        subnets = {}
        for device in devices:
            ip_parts = device["ip"].split(".")
            subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

            if subnet not in subnets:
                subnets[subnet] = {"network": subnet, "device_count": 0, "types": {}}

            subnets[subnet]["device_count"] += 1
            dtype = device.get("type", "unknown")
            subnets[subnet]["types"][dtype] = subnets[subnet]["types"].get(dtype, 0) + 1

        return list(subnets.values())

    def view_recent_scans(self):
        """View recent scan results"""
        scan_files = sorted((self.output_path / "scans").glob("scan_*.json"), reverse=True)

        if not scan_files:
            console.print("[yellow]No scans found[/yellow]")
            input("\nPress Enter to continue...")
            return

        table = Table(title="Recent Scans")
        table.add_column("Date/Time", style="cyan")
        table.add_column("Devices", style="green")
        table.add_column("File", style="yellow")

        for scan_file in scan_files[:10]:  # Show last 10
            timestamp = scan_file.stem.replace("scan_", "")
            with open(scan_file) as f:
                devices = json.load(f)

            date_str = datetime.strptime(timestamp, "%Y%m%d_%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
            table.add_row(date_str, str(len(devices)), scan_file.name)

        console.print(table)
        input("\nPress Enter to continue...")

    def check_changes(self):
        """Check for network changes"""
        # Get most recent scan
        scan_files = sorted((self.output_path / "scans").glob("scan_*.json"), reverse=True)
        if not scan_files:
            console.print("[yellow]No scans found[/yellow]")
            input("\nPress Enter to continue...")
            return

        with open(scan_files[0]) as f:
            current_devices = json.load(f)

        changes = self.tracker.detect_changes(current_devices)

        if not changes:
            console.print("[yellow]Need at least 2 scans to detect changes[/yellow]")
            input("\nPress Enter to continue...")
            return

        # Display changes
        console.print("\n[bold]Network Changes Summary[/bold]\n")

        if changes.get("new_devices"):
            console.print(f"[green]NEW DEVICES ({len(changes['new_devices'])})[/green]")
            for device in changes["new_devices"]:
                console.print(
                    f"  • {device['ip']} - {device.get('hostname', 'N/A')} "
                    f"({device.get('type', 'unknown')})"
                )

        if changes.get("missing_devices"):
            console.print(f"\n[red]MISSING DEVICES ({len(changes['missing_devices'])})[/red]")
            for device in changes["missing_devices"]:
                console.print(
                    f"  • {device['ip']} - {device.get('hostname', 'N/A')} "
                    f"({device.get('type', 'unknown')})"
                )

        if changes.get("changed_devices"):
            console.print(f"\n[yellow]CHANGED DEVICES ({len(changes['changed_devices'])})[/yellow]")
            for device in changes["changed_devices"]:
                console.print(f"  • {device['ip']} - {device.get('hostname', 'N/A')}")

        input("\nPress Enter to continue...")

    def annotate_devices(self):
        """Annotate devices"""
        # Get most recent scan
        scan_files = sorted((self.output_path / "scans").glob("scan_*.json"), reverse=True)
        if not scan_files:
            console.print("[yellow]No scans found[/yellow]")
            input("\nPress Enter to continue...")
            return

        with open(scan_files[0]) as f:
            devices = json.load(f)

        self.annotator.bulk_annotate(devices)

    def generate_reports(self):
        """Generate reports menu"""
        scan_files = sorted((self.output_path / "scans").glob("scan_*.json"), reverse=True)
        if not scan_files:
            console.print("[yellow]No scans found[/yellow]")
            input("\nPress Enter to continue...")
            return

        # Select scan
        console.print("\n[bold]Select scan to generate report:[/bold]")
        for i, scan_file in enumerate(scan_files[:5]):
            timestamp = scan_file.stem.replace("scan_", "")
            date_str = datetime.strptime(timestamp, "%Y%m%d_%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
            console.print(f"  {i+1}. {date_str}")

        choice = Prompt.ask(
            "Select scan", choices=[str(i + 1) for i in range(min(5, len(scan_files)))]
        )
        scan_file = scan_files[int(choice) - 1]

        with open(scan_file) as f:
            devices = json.load(f)

        timestamp = scan_file.stem.replace("scan_", "")
        self.generate_html_report(devices, timestamp)
        input("\nPress Enter to continue...")

    def view_network_map(self):
        """Launch network map viewer"""
        # Get most recent network map
        report_files = sorted((self.output_path / "reports").glob("network_map_*.html"), reverse=True)
        
        # Fall back to old report format if no new maps found
        if not report_files:
            report_files = sorted((self.output_path / "reports").glob("report_*.html"), reverse=True)
            
        if report_files:
            import webbrowser

            file_url = f"file://{report_files[0].absolute()}"
            webbrowser.open(file_url)
            console.print("[green]Opening network map in browser...[/green]")
            console.print(f"\n[bold cyan]Network map location:[/bold cyan]")
            console.print(f"[yellow underline]{file_url}[/yellow underline]")
        else:
            console.print("[yellow]No network maps found. Run a scan first to generate a visualization.[/yellow]")
        input("\nPress Enter to continue...")

    def _handle_snmp_setup(self) -> Tuple[bool, Dict]:
        """Handle SNMP setup with CLI override support
        
        Returns:
            Tuple of (enabled, config_dict)
        """
        # Check for CLI override to disable SNMP
        if self.cli_overrides.get('disable_snmp'):
            console.print("\n[dim]SNMP enrichment disabled via CLI argument[/dim]")
            return False, {}
            
        # Check for CLI override with specific settings
        if self.cli_overrides.get('snmp_community') or self.cli_overrides.get('snmp_version'):
            config = {}
            
            version = self.cli_overrides.get('snmp_version', 'v2c')
            if version not in ['v1', 'v2c', 'v3']:
                console.print(f"[red]Invalid SNMP version '{version}'. Using v2c.[/red]")
                version = 'v2c'
                
            config['version'] = version
            
            if version in ['v1', 'v2c']:
                community = self.cli_overrides.get('snmp_community', 'public')
                config['community'] = community
                console.print(f"\n[green]✓ SNMP enrichment enabled via CLI: {version} with community '{community}'[/green]")
            else:
                console.print(f"\n[yellow]SNMPv3 specified via CLI but credentials missing. Using interactive setup.[/yellow]")
                return self.snmp_config.interactive_setup()
                
            config['timeout'] = 2
            config['retries'] = 1
            return True, config
            
        # Use interactive setup
        return self.snmp_config.interactive_setup()

    def _get_scan_target(self) -> str:
        """Get and validate scan target with helpful examples"""
        console.print("\n[bold]Scan Target[/bold]")
        console.print("Enter the network or host you want to scan:")
        console.print("[dim]• Single host: 192.168.1.10[/dim]")
        console.print("[dim]• Network range: 192.168.1.0/24[/dim]")
        console.print("[dim]• IP range: 192.168.1.1-50[/dim]")
        console.print("[dim]• Hostname: example.com[/dim]")
        
        while True:
            target = Prompt.ask("\nTarget").strip()
            
            if not target:
                console.print("[red]Target cannot be empty[/red]")
                continue
                
            # Basic validation
            if self._validate_target(target):
                return target
            else:
                console.print("[red]Invalid target format. Please check your input.[/red]")
                
    def _validate_target(self, target: str) -> bool:
        """Basic validation for scan targets"""
        import re
        
        if not target or target.isspace():
            return False
            
        # IP address patterns with proper range validation
        def is_valid_ip_octet(octet):
            try:
                num = int(octet)
                return 0 <= num <= 255
            except ValueError:
                return False
        
        # Single IP address
        ip_match = re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', target)
        if ip_match:
            return all(is_valid_ip_octet(octet) for octet in ip_match.groups())
            
        # CIDR notation
        cidr_match = re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$', target)
        if cidr_match:
            octets = cidr_match.groups()[:4]
            prefix = int(cidr_match.group(5))
            return all(is_valid_ip_octet(octet) for octet in octets) and 0 <= prefix <= 32
            
        # IP range
        range_match = re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})-(\d{1,3})$', target)
        if range_match:
            octets = range_match.groups()[:4]
            end_range = int(range_match.group(5))
            return (all(is_valid_ip_octet(octet) for octet in octets) and 
                    0 <= end_range <= 255 and 
                    end_range >= int(octets[3]))
        
        # Hostname pattern (basic but more restrictive)
        hostname_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9\.-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$'
        if re.match(hostname_pattern, target):
            # Additional hostname validation
            if len(target) > 253:  # Max hostname length
                return False
            if '..' in target:  # No consecutive dots
                return False
            if target.startswith('.') or target.endswith('.'):  # No leading/trailing dots
                return False
            return True
            
        return False
        
    def _select_scan_type(self) -> Tuple[str, str, bool, bool]:
        """Select scan type with improved UX"""
        console.print("\n[bold]Scan Type[/bold]")
        
        scan_options = [
            ("discovery", "Discovery Scan", "Quick host discovery", "30 seconds", False),
            ("inventory", "Inventory Scan", "Service detection and OS fingerprinting", "5 minutes", True),
            ("deep", "Deep Scan", "Comprehensive analysis with scripts", "15 minutes", True),
            ("arp", "ARP Scan", "Layer 2 discovery for local networks", "10 seconds", True),
        ]
        
        for i, (_, name, desc, time, needs_root) in enumerate(scan_options, 1):
            sudo_text = " (requires sudo)" if needs_root else ""
            console.print(f"{i}. [bold]{name}[/bold] – {desc}")
            console.print(f"   [dim]Duration: ~{time}{sudo_text}[/dim]")
            
        while True:
            try:
                choice = Prompt.ask("\nSelect scan type", choices=["1", "2", "3", "4"], default="1")
                choice_idx = int(choice) - 1
                scan_type, scan_name, _, _, needs_root = scan_options[choice_idx]
                
                # Handle masscan option for discovery scans
                use_masscan = False
                if scan_type == "discovery":
                    console.print("\n[bold]Speed Option[/bold]")
                    use_masscan = Confirm.ask("Use masscan for faster discovery", default=False)
                    if use_masscan:
                        console.print("[green]→ Using masscan for faster scanning[/green]")
                    else:
                        console.print("[dim]→ Using standard nmap discovery[/dim]")
                
                return scan_type, scan_name, needs_root, use_masscan
                
            except (ValueError, IndexError):
                console.print("[red]Please select a valid option (1-4)[/red]")
                
    def _handle_vulnerability_setup(self) -> bool:
        """Handle vulnerability scanning setup"""
        console.print("\n[bold]Vulnerability Analysis[/bold]")
        console.print("Check discovered services against multiple CVE databases")
        console.print("[dim]Uses OSV (Google) and CIRCL APIs - no registration required[/dim]")
        
        enabled = Confirm.ask("Enable vulnerability scanning", default=True)
        
        if enabled:
            console.print("[green]→ Vulnerability scanning enabled (OSV + CIRCL + Local patterns)[/green]")
        else:
            console.print("[dim]→ Vulnerability scanning disabled[/dim]")
            
        return enabled

    def _display_vulnerability_summary(self, vuln_report: Dict):
        """Display vulnerability scan summary"""
        if vuln_report['total_vulnerabilities'] == 0:
            console.print("[green]✓ No vulnerabilities found[/green]")
            return
            
        console.print(f"\n[bold red]Vulnerability Summary[/bold red]")
        
        # Create summary table
        summary_table = Table(show_header=False, box=None, padding=(0, 2))
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Count", style="yellow")
        
        summary_table.add_row("Total vulnerabilities", str(vuln_report['total_vulnerabilities']))
        summary_table.add_row("Vulnerable devices", f"{vuln_report['vulnerable_devices']}/{vuln_report['total_devices']}")
        summary_table.add_row("Critical severity", str(vuln_report['critical_vulnerabilities']))
        summary_table.add_row("High severity", str(vuln_report['high_vulnerabilities']))
        
        console.print(summary_table)
        
        # Show top vulnerabilities
        top_vulns = vuln_report['top_vulnerabilities'][:3]  # Show top 3
        if top_vulns:
            console.print("\n[bold]Top Vulnerabilities:[/bold]")
            for vuln in top_vulns:
                severity_color = {
                    'CRITICAL': 'red',
                    'HIGH': 'orange1',
                    'MEDIUM': 'yellow',
                    'LOW': 'blue'
                }.get(vuln.get('severity'), 'white')
                
                console.print(f"• [{severity_color}]{vuln.get('cve_id')}[/{severity_color}] "
                            f"(CVSS: {vuln.get('cvss_score', 0):.1f}) - {vuln.get('device_ip')}")

    def export_data(self):
        """Export data menu"""
        console.print("\n[bold]Export Options:[/bold]")
        console.print("  1. Export to PDF Report")
        console.print("  2. Export to Excel (with formatting)")
        console.print("  3. Export to Enhanced JSON")
        console.print("  4. Export to CSV (all devices)")
        console.print("  5. Export critical devices only")
        console.print("  6. Export by device type")

        choice = Prompt.ask("Select export option", choices=["1", "2", "3", "4", "5", "6"])

        # Get most recent scan
        scan_files = sorted((self.output_path / "scans").glob("scan_*.json"), reverse=True)
        if not scan_files:
            console.print("[yellow]No scans found[/yellow]")
            input("\nPress Enter to continue...")
            return

        with open(scan_files[0]) as f:
            devices = json.load(f)

        devices = self.annotator.apply_annotations(devices)

        # Get recent changes if available
        changes = None
        if len(scan_files) >= 2:
            changes = self.tracker.detect_changes(devices)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        try:
            if choice == "1":
                # Export to PDF
                console.print("[yellow]Generating PDF report...[/yellow]")
                export_file = self.export_mgr.export_to_pdf(devices, changes)
                console.print(f"[green]✓ PDF report exported to: {export_file}[/green]")
                
            elif choice == "2":
                # Export to Excel
                console.print("[yellow]Generating Excel workbook...[/yellow]")
                export_file = self.export_mgr.export_to_excel(devices, changes)
                console.print(f"[green]✓ Excel workbook exported to: {export_file}[/green]")
                
            elif choice == "3":
                # Export to Enhanced JSON
                console.print("[yellow]Generating enhanced JSON export...[/yellow]")
                export_file = self.export_mgr.export_to_json(devices, changes)
                console.print(f"[green]✓ JSON export saved to: {export_file}[/green]")
                
            elif choice == "4":
                # Export to CSV (enhanced)
                console.print("[yellow]Generating CSV export...[/yellow]")
                export_file = self.export_mgr.export_to_csv_enhanced(devices)
                console.print(f"[green]✓ CSV exported to: {export_file}[/green]")
                
            elif choice == "5":
                # Export critical devices only
                critical = [d for d in devices if d.get("critical", False)]
                if critical:
                    export_file = self.output_path / "exports" / f"critical_devices_{timestamp}.csv"
                    self.output_path.joinpath("exports").mkdir(exist_ok=True)
                    self.save_csv(critical, export_file)
                    console.print(f"[green]✓ Critical devices exported to: {export_file}[/green]")
                else:
                    console.print("[yellow]No critical devices found.[/yellow]")
                    
            elif choice == "6":
                # Export by device type
                device_type = Prompt.ask("Enter device type (router/switch/server/etc)")
                filtered = [d for d in devices if d.get("type") == device_type]
                if filtered:
                    export_file = self.output_path / "exports" / f"{device_type}_devices_{timestamp}.csv"
                    self.output_path.joinpath("exports").mkdir(exist_ok=True)
                    self.save_csv(filtered, export_file)
                    console.print(f"[green]✓ {device_type} devices exported to: {export_file}[/green]")
                else:
                    console.print(f"[yellow]No {device_type} devices found.[/yellow]")

            # Ask if user wants to open the export
            if 'export_file' in locals() and Confirm.ask("\nOpen exported file?"):
                import webbrowser
                file_url = f"file://{export_file.absolute()}"
                webbrowser.open(file_url)
                
        except Exception as e:
            console.print(f"[red]Export failed: {e}[/red]")
            
        input("\nPress Enter to continue...")


mapper = NetworkMapper()


@app.command()
def main(
    disable_snmp: bool = typer.Option(False, "--disable-snmp", help="Disable SNMP enrichment"),
    snmp_community: str = typer.Option(None, "--snmp-community", help="SNMP community string"),
    snmp_version: str = typer.Option(None, "--snmp-version", help="SNMP version (v1, v2c, v3)"),
):
    """NetworkMapper 2.0 - Network Discovery & Mapping Tool"""
    try:
        # Set CLI overrides
        mapper.cli_overrides = {
            'disable_snmp': disable_snmp,
            'snmp_community': snmp_community,
            'snmp_version': snmp_version
        }
        
        mapper.interactive_menu()
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user[/red]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")


if __name__ == "__main__":
    app()