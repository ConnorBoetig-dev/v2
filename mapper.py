#!/usr/bin/env python3
"""
NetworkMapper 2.0 - Network Discovery and Mapping Tool
"""

import csv
import json
import logging
import time
from collections import defaultdict
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
from utils.export_manager import ExportManager
from utils.snmp_config import SNMPConfig
from utils.traffic_analyzer import PassiveTrafficAnalyzer
from utils.visualization import MapGenerator
from utils.vulnerability_scanner import VulnerabilityScanner
from utils.scan_status import ScanStatusIndicator
from modern_interface import ModernInterface

# Import friendly error handling
try:
    from utils.friendly_errors import FriendlyError, format_error_for_user
except ImportError:
    FriendlyError = Exception
    format_error_for_user = str

app = typer.Typer()
console = Console()
logger = logging.getLogger(__name__)


class NetworkMapper:
    def __init__(self):
        self.base_path = Path(__file__).parent
        self.output_path = self.base_path / "output"
        self.ensure_directories()
        self.scanner = NetworkScanner()
        self.parser = ScanParser()  # Will be reconfigured based on CLI args
        self.classifier = DeviceClassifier()
        self.tracker = ChangeTracker()
        self.annotator = DeviceAnnotator()
        self.map_gen = MapGenerator()
        self.export_mgr = ExportManager(self.output_path)
        self.cli_overrides = {}  # Will be set from main()
        self.snmp_config = SNMPConfig(self.output_path / "config")
        self.vuln_scanner = VulnerabilityScanner(self.output_path / "cache")
        self.modern_ui = ModernInterface(self)
        self.traffic_analyzer = PassiveTrafficAnalyzer(output_path=self.output_path)
        self.cli_overrides = {}
        self.last_changes = None
        self.passive_analysis_results = None

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
                "3": "🔄 Compare to Last Scan (Auto-opens Report)",
                "4": "🔀 Compare Any Two Scans",
                "5": "✏️  Annotate Devices",
                "6": "📈 Generate Reports",
                "7": "🗺️  View Network Map",
                "8": "📤 Export Data",
                "9": "❌ Exit",
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
                self.compare_scans_interactive()
            elif choice == "5":
                self.annotate_devices()
            elif choice == "6":
                self.generate_reports()
            elif choice == "7":
                self.view_network_map()
            elif choice == "8":
                self.export_data()
            elif choice == "9":
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

        # Passive traffic analysis setup
        passive_enabled, passive_duration = self._handle_passive_analysis_setup()

        # Run scan
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create status indicator
        status_indicator = ScanStatusIndicator(console)
        
        # Handle ARP scan separately
        if scan_type == "arp":
            # ARP scans are quick, use simple indicator
            console.print(f"\n[yellow]Starting ARP scan on {target}...[/yellow]\n")
            with console.status("[cyan]Running ARP scan...[/cyan]", spinner="dots"):
                results = self.scanner._run_arp_scan(target)
        else:
            # Show scan status
            status_indicator.show_scan_starting(target, scan_type)
            
            # Run scan (scanner has its own progress bars)
            results = self.scanner.scan(
                target=target,
                scan_type=scan_type,
                use_masscan=use_masscan,
                needs_root=needs_root,
                snmp_config=snmp_config if snmp_enabled else None,
            )
            
            # Show completion
            device_count = len(results) if results else 0
            status_indicator.show_scan_complete(device_count)

        # Parse and classify
        devices = self.parser.parse_results(results)
        devices = self.classifier.classify_devices(devices)

        # Run passive traffic analysis if enabled
        if passive_enabled:
            console.print("\n[cyan]Starting passive traffic analysis...[/cyan]")
            console.print("[dim]This will discover stealth devices and map traffic flows[/dim]")

            try:
                # Start passive capture
                self.traffic_analyzer.start_capture(duration=passive_duration)

                # Show progress
                with console.status(
                    f"[cyan]Analyzing network traffic for {passive_duration} seconds...[/cyan]"
                ) as status:
                    start_time = time.time()
                    while (
                        self.traffic_analyzer.running
                        and (time.time() - start_time) < passive_duration + 5
                    ):
                        elapsed = int(time.time() - start_time)
                        discovered = self.traffic_analyzer.stats["devices_discovered"]
                        flows = self.traffic_analyzer.stats["flows_tracked"]
                        status.update(
                            f"[cyan]Passive analysis: {elapsed}s elapsed, {discovered} devices, {flows} flows[/cyan]"
                        )
                        time.sleep(1)

                # Stop capture
                self.traffic_analyzer.stop_capture()

                # Export passive results
                devices_file, flows_file = self.traffic_analyzer.export_results(timestamp)

                # Merge with active scan results
                devices = self.traffic_analyzer.merge_with_active_scan(devices)

                # Display summary
                passive_summary = {
                    "stealth_devices": len([d for d in devices if d.get("stealth_device", False)]),
                    "total_flows": len(self.traffic_analyzer.flows),
                    "top_talkers": self.traffic_analyzer.get_top_talkers(3),
                }
                self._display_passive_analysis_summary(passive_summary)

                # Store results for later use
                self.passive_analysis_results = {
                    "devices_file": devices_file,
                    "flows_file": flows_file,
                    "flow_matrix": self.traffic_analyzer.get_flow_matrix(),
                    "service_usage": self.traffic_analyzer.get_service_usage(),
                    "duration": passive_duration,
                }

            except Exception as e:
                error_msg = format_error_for_user(e)
                console.print(f"[yellow]⚠️  Passive analysis couldn't complete: {error_msg}[/yellow]")
                if "permission" in str(e).lower():
                    console.print("[yellow]💡 Tip: This feature requires administrator privileges (sudo)[/yellow]")
                logger.error(f"Passive analysis error: {e}")

        # Vulnerability scanning if enabled
        if vuln_enabled:
            console.print("\n[cyan]Scanning for vulnerabilities...[/cyan]")
            try:
                devices = self.vuln_scanner.scan_devices(devices)

                # Generate vulnerability report
                vuln_report = self.vuln_scanner.generate_vulnerability_report(devices)
                self._display_vulnerability_summary(vuln_report)
            except Exception as e:
                error_msg = format_error_for_user(e)
                console.print(f"[yellow]⚠️  Vulnerability scanning couldn't complete: {error_msg}[/yellow]")
                if "connection" in str(e).lower() or "timeout" in str(e).lower():
                    console.print("[yellow]💡 Tip: Check your internet connection for API access[/yellow]")
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

            # Display change summary immediately
            if changes.get("summary", {}).get("total_changes", 0) > 0:
                console.print("\n[bold yellow]🔄 Network Changes Detected![/bold yellow]")
                change_table = Table(show_header=False, box=None, padding=(0, 2))
                change_table.add_column("Type", style="cyan")
                change_table.add_column("Count", style="yellow")

                if changes.get("new_devices"):
                    change_table.add_row("New devices:", f"+{len(changes['new_devices'])}")
                if changes.get("missing_devices"):
                    change_table.add_row("Missing devices:", f"-{len(changes['missing_devices'])}")
                if changes.get("changed_devices"):
                    change_table.add_row("Modified devices:", f"~{len(changes['changed_devices'])}")

                console.print(change_table)
                console.print("[dim]A detailed comparison report will be generated...[/dim]")
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
        console.print(f"\n[bold]Generated Reports:[/bold]")
        report_table = Table(show_header=False, box=None, padding=(0, 2))
        report_table.add_column("Type", style="cyan")
        report_table.add_column("Path", style="yellow")

        # Check which reports were generated
        network_map = self.output_path / "reports" / f"network_map_{timestamp}.html"
        detailed_report = self.output_path / "reports" / f"report_{timestamp}.html"
        traffic_flow = self.output_path / "reports" / f"traffic_flow_{timestamp}.html"

        if network_map.exists():
            report_table.add_row("Network Map (2D/3D):", str(network_map))
        if detailed_report.exists():
            report_table.add_row("Detailed Report:", str(detailed_report))
        if traffic_flow.exists():
            report_table.add_row("Traffic Flow:", str(traffic_flow))
        if comparison_file:
            report_table.add_row("Comparison:", str(comparison_file))

        console.print(report_table)

        # Show tips for viewing
        if not traffic_flow.exists() and not passive_enabled:
            console.print(
                "\n[dim]💡 Tip: Enable passive traffic analysis to generate the traffic flow report[/dim]"
            )

        console.print(
            "\n[dim]💡 Tip: In the Network Map, use the 2D/3D toggle buttons to switch views[/dim]"
        )

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
                "stealth_device",
                "discovery_method",
                "traffic_flows",
                "communication_peers",
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for device in devices:
                # Create vulnerability summary
                vulns = device.get("vulnerabilities", [])
                vuln_summary = ""
                if vulns:
                    high_severity = [v for v in vulns if v.get("severity") in ["CRITICAL", "HIGH"]]
                    if high_severity:
                        vuln_summary = f"{len(high_severity)} high-risk issues: " + "; ".join(
                            [v.get("cve_id", "Unknown") for v in high_severity[:3]]
                        )
                    else:
                        vuln_summary = f"{len(vulns)} issues detected"
                else:
                    vuln_summary = "No vulnerabilities detected"

                # Get passive analysis data if available
                passive_data = device.get("passive_analysis", {})

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
                    "stealth_device": "Yes" if device.get("stealth_device", False) else "No",
                    "discovery_method": device.get("discovery_method", "active"),
                    "traffic_flows": passive_data.get("traffic_flows", 0),
                    "communication_peers": passive_data.get("communication_peers", 0),
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
        if self.passive_analysis_results and self.passive_analysis_results.get("flow_matrix"):
            # Use traffic flow enhanced visualization
            d3_data = self.map_gen.generate_traffic_flow_data(
                devices, self.passive_analysis_results["flow_matrix"]
            )
        else:
            d3_data = self.map_gen.generate_d3_data(devices)

        three_data = self.map_gen.generate_threejs_data(devices)

        # Setup Jinja2
        env = Environment(loader=FileSystemLoader(self.base_path / "templates"))

        # Get changes if available
        changes = {}
        if self.last_changes:
            changes = self.last_changes

        # Ensure all devices have required fields for templates
        for device in devices:
            if "vulnerability_count" not in device:
                device["vulnerability_count"] = 0
            if "vulnerabilities" not in device:
                device["vulnerabilities"] = []
            if "critical_vulns" not in device:
                device["critical_vulns"] = 0
            if "high_vulns" not in device:
                device["high_vulns"] = 0
            if "dependent_count" not in device:
                device["dependent_count"] = 0
            if "uptime_days" not in device:
                device["uptime_days"] = 0

        # Load scan metadata if available
        metadata_file = self.output_path / "scans" / f"summary_{timestamp}.json"
        scan_metadata = {}
        if metadata_file.exists():
            try:
                with open(metadata_file) as f:
                    scan_metadata = json.load(f)
            except:
                pass

        # Check if comparison report exists
        comparison_file_name = None
        if self.last_changes and self.last_changes.get("summary", {}).get("total_changes", 0) > 0:
            comparison_file_name = f"comparison_{timestamp}.html"
        
        # Prepare report data with enhanced metadata
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
            "scan_metadata": scan_metadata,  # Include scan metadata for footer
            "comparison_file": comparison_file_name,  # Include comparison file name
            "has_changes": bool(self.last_changes and self.last_changes.get("summary", {}).get("total_changes", 0) > 0),
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

        # 3. Generate traffic flow report if passive analysis was performed
        if self.passive_analysis_results:
            traffic_template = env.get_template("traffic_flow_report.html")
            traffic_report_file = self.output_path / "reports" / f"traffic_flow_{timestamp}.html"

            # Prepare traffic flow data
            flow_data = self.passive_analysis_results.get("flow_matrix", {})
            service_usage = self.passive_analysis_results.get("service_usage", {})

            # Check if we have real traffic data
            real_traffic_captured = False
            if hasattr(self.traffic_analyzer, "stats"):
                real_traffic_captured = self.traffic_analyzer.stats.get("packets_captured", 0) > 0

            # Calculate statistics
            stealth_devices = len([d for d in devices if d.get("stealth_device", False)])
            total_flows = sum(len(flows) for flows in flow_data.values())
            services_count = len(service_usage)

            # Get top talkers with enhanced info
            top_talkers = []
            if flow_data:
                traffic_totals = defaultdict(int)
                for src, destinations in flow_data.items():
                    for dst, packets in destinations.items():
                        traffic_totals[src] += packets
                        traffic_totals[dst] += packets

                # Get device info for top talkers
                for ip, traffic_volume in sorted(
                    traffic_totals.items(), key=lambda x: x[1], reverse=True
                )[:10]:
                    device = next((d for d in devices if d["ip"] == ip), None)
                    if device:
                        color_map = {
                            "router": "#F44336",
                            "server": "#2196F3",
                            "workstation": "#4CAF50",
                            "unknown": "#9E9E9E",
                        }
                        top_talkers.append(
                            {
                                "ip": ip,
                                "hostname": device.get("hostname", ""),
                                "type": device.get("type", "unknown"),
                                "stealth": device.get("stealth_device", False),
                                "traffic_volume": traffic_volume
                                * 1500,  # Estimate bytes from packets
                                "color": color_map.get(device.get("type", "unknown"), "#9E9E9E"),
                            }
                        )

            # Calculate max service count for visualization
            max_service_count = 1
            if service_usage:
                for ips in service_usage.values():
                    if isinstance(ips, list):
                        max_service_count = max(max_service_count, len(ips))
                    else:
                        max_service_count = max(max_service_count, ips)

            # Check if scapy is available
            from utils.traffic_analyzer import SCAPY_AVAILABLE

            traffic_report_data = {
                **report_data,
                "devices": devices,  # Add full devices data for risk analysis
                "stealth_devices": stealth_devices,
                "total_flows": total_flows,
                "services_count": services_count,
                "flow_matrix": json.dumps(flow_data),
                "service_usage": service_usage,
                "max_service_count": max_service_count,
                "top_talkers": top_talkers,
                "real_traffic_captured": real_traffic_captured,
                "scapy_available": SCAPY_AVAILABLE,
                "stats": {
                    "packets_captured": getattr(self.traffic_analyzer, "stats", {}).get(
                        "packets_captured", 0
                    ),
                    "duration": self.passive_analysis_results.get("duration", 0),
                },
            }

            traffic_html = traffic_template.render(**traffic_report_data)

            with open(traffic_report_file, "w") as f:
                f.write(traffic_html)

            generated_files.append(("Traffic Flow Analysis", traffic_report_file))

        # Open all reports in browser
        viz_url = f"file://{viz_report_file.absolute()}"
        original_url = f"file://{original_report_file.absolute()}"

        # Open visualization first
        webbrowser.open(viz_url)
        # Small delay then open report
        import time

        time.sleep(0.5)
        webbrowser.open(original_url)

        # Open traffic flow report if generated
        traffic_url = None
        if self.passive_analysis_results and len(generated_files) > 2:
            traffic_report_file = generated_files[2][1]  # Get the traffic report file
            traffic_url = f"file://{traffic_report_file.absolute()}"
            time.sleep(0.5)
            webbrowser.open(traffic_url)

        # Show clickable links in terminal
        console.print("\n[green]✓ Reports generated and opened in browser![/green]")
        console.print(f"\n[bold cyan]Generated files:[/bold cyan]")
        console.print(f"[yellow]Network Visualization:[/yellow] [underline]{viz_url}[/underline]")
        console.print(f"[yellow]Detailed Report:[/yellow] [underline]{original_url}[/underline]")

        if self.passive_analysis_results and traffic_url:
            console.print(
                f"[yellow]Traffic Flow Analysis:[/yellow] [underline]{traffic_url}[/underline]"
            )

        console.print("\n")

        # Generate comparison report if we have previous scans and changes
        comparison_file = None
        scan_files = sorted((self.output_path / "scans").glob("scan_*.json"), reverse=True)
        if len(scan_files) >= 2 and self.last_changes:
            # Always generate comparison report if we have changes
            if self.last_changes.get("summary", {}).get("total_changes", 0) > 0:
                console.print(
                    "\n[bold yellow]🔄 Network changes detected! Generating comparison report...[/bold yellow]"
                )
                comparison_file = self.generate_comparison_report(
                    devices, self.last_changes, timestamp
                )

                if comparison_file and comparison_file.exists():
                    comparison_url = f"file://{comparison_file.absolute()}"
                    time.sleep(0.5)
                    webbrowser.open(comparison_url)
                    console.print(
                        f"\n[bold green]✓ Comparison Report Generated and Opened![/bold green]"
                    )
                    console.print(
                        f"[yellow]📊 Comparison Report:[/yellow] [underline]{comparison_url}[/underline]"
                    )
                    console.print(
                        f"[cyan]Summary: {len(self.last_changes.get('new_devices', []))} new, "
                        f"{len(self.last_changes.get('missing_devices', []))} missing, "
                        f"{len(self.last_changes.get('changed_devices', []))} changed devices[/cyan]"
                    )
                else:
                    console.print("[red]⚠ Failed to generate comparison report[/red]")
            else:
                console.print("\n[green]✓ No changes detected since last scan[/green]")

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
        """Check for network changes and generate comparison report"""
        import webbrowser

        # Get most recent scans
        scan_files = sorted((self.output_path / "scans").glob("scan_*.json"), reverse=True)
        if len(scan_files) < 2:
            console.print("[yellow]Need at least 2 scans to detect changes[/yellow]")
            input("\nPress Enter to continue...")
            return

        # Load current scan
        with open(scan_files[0]) as f:
            current_devices = json.load(f)

        # Detect changes
        changes = self.tracker.detect_changes(current_devices)

        if not changes:
            console.print("[yellow]No previous scan found for comparison[/yellow]")
            input("\nPress Enter to continue...")
            return

        # Display changes summary
        self._display_changes_summary(changes)

        # Generate comparison report if there are changes
        if changes.get("summary", {}).get("total_changes", 0) > 0:
            console.print("\n[yellow]Generating comparison report...[/yellow]")

            try:
                # Get timestamp from most recent scan
                timestamp = scan_files[0].stem.replace("scan_", "")

                # Generate the comparison report
                comparison_file = self.generate_comparison_report(current_devices, changes, timestamp)

                if comparison_file and comparison_file.exists():
                    # Open in browser
                    comparison_url = f"file://{comparison_file.absolute()}"
                    webbrowser.open(comparison_url)
                    console.print(f"\n[bold green]✓ Comparison report opened in browser![/bold green]")
                    console.print(
                        f"[yellow]Report location:[/yellow] [underline]{comparison_url}[/underline]"
                    )
                else:
                    console.print("[red]Failed to generate comparison report[/red]")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                import traceback
                logger.error(f"Error generating comparison report: {traceback.format_exc()}")
        else:
            console.print("\n[green]No changes detected between scans[/green]")

        input("\nPress Enter to continue...")

    def compare_scans_interactive(self):
        """Interactive scan comparison with subnet detection"""
        scan_files = sorted((self.output_path / "scans").glob("scan_*.json"), reverse=True)

        if len(scan_files) < 2:
            console.print("[yellow]Need at least 2 scans to compare[/yellow]")
            input("\nPress Enter to continue...")
            return

        # Group scans by subnet
        subnet_scans = self._group_scans_by_subnet(scan_files[:20])  # Last 20 scans

        if not subnet_scans:
            console.print("[yellow]No valid scans found[/yellow]")
            input("\nPress Enter to continue...")
            return

        # Let user choose subnet if multiple available
        subnet = self._select_subnet_for_comparison(subnet_scans)
        if not subnet:
            return

        # Get scans for selected subnet
        available_scans = subnet_scans[subnet]

        if len(available_scans) < 2:
            console.print(f"[yellow]Only one scan found for subnet {subnet}[/yellow]")
            input("\nPress Enter to continue...")
            return

        # Display available scans
        console.print(f"\n[bold cyan]Available scans for subnet {subnet}:[/bold cyan]")
        scan_table = Table()
        scan_table.add_column("#", style="cyan", width=4)
        scan_table.add_column("Date/Time", style="yellow")
        scan_table.add_column("Devices", style="green", justify="right")
        scan_table.add_column("Filename", style="dim")

        for i, (scan_file, info) in enumerate(available_scans[:10]):  # Show max 10
            scan_table.add_row(
                str(i + 1), info["date_str"], str(info["device_count"]), scan_file.name
            )

        console.print(scan_table)

        # Select scans to compare
        console.print("\n[bold]Select two scans to compare:[/bold]")

        try:
            older_idx = int(Prompt.ask("Older scan number")) - 1
            newer_idx = int(Prompt.ask("Newer scan number")) - 1

            if not (
                0 <= older_idx < len(available_scans) and 0 <= newer_idx < len(available_scans)
            ):
                raise ValueError("Invalid selection")

            if older_idx == newer_idx:
                console.print("[red]Cannot compare a scan with itself[/red]")
                input("\nPress Enter to continue...")
                return

        except (ValueError, KeyboardInterrupt):
            console.print("[red]Invalid selection[/red]")
            input("\nPress Enter to continue...")
            return

        # Load the selected scans
        older_scan_file = available_scans[older_idx][0]
        newer_scan_file = available_scans[newer_idx][0]

        with open(older_scan_file) as f:
            older_devices = json.load(f)
        with open(newer_scan_file) as f:
            newer_devices = json.load(f)

        # Perform comparison
        console.print("\n[yellow]Analyzing changes...[/yellow]")
        changes = self._compare_device_lists(older_devices, newer_devices)

        # Display results
        self._display_detailed_comparison(changes, older_scan_file, newer_scan_file)

        # Export options
        if Confirm.ask("\nExport comparison results?"):
            self._export_comparison_results(changes, older_scan_file, newer_scan_file)

        input("\nPress Enter to continue...")

    def _group_scans_by_subnet(self, scan_files):
        """Group scan files by subnet"""
        subnet_scans = {}

        for scan_file in scan_files:
            try:
                with open(scan_file) as f:
                    devices = json.load(f)

                if not devices:
                    continue

                # Detect subnet from device IPs
                subnet = self._detect_subnet(devices)
                if subnet:
                    timestamp = scan_file.stem.replace("scan_", "")
                    date_str = datetime.strptime(timestamp, "%Y%m%d_%H%M%S").strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )

                    if subnet not in subnet_scans:
                        subnet_scans[subnet] = []

                    subnet_scans[subnet].append(
                        (
                            scan_file,
                            {
                                "timestamp": timestamp,
                                "date_str": date_str,
                                "device_count": len(devices),
                            },
                        )
                    )

            except Exception as e:
                logger.error(f"Error processing scan file {scan_file}: {e}")
                continue

        return subnet_scans

    def _detect_subnet(self, devices):
        """Detect the primary subnet from a list of devices"""
        if not devices:
            return None

        # Count devices per subnet
        subnet_counts = {}
        for device in devices:
            ip = device.get("ip", "")
            if ip:
                # Extract /24 subnet
                parts = ip.split(".")
                if len(parts) == 4:
                    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                    subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1

        # Return the most common subnet
        if subnet_counts:
            return max(subnet_counts, key=subnet_counts.get)
        return None

    def _select_subnet_for_comparison(self, subnet_scans):
        """Let user select subnet if multiple available"""
        if len(subnet_scans) == 1:
            return list(subnet_scans.keys())[0]

        console.print("\n[bold]Multiple subnets found. Select one:[/bold]")
        subnet_list = list(subnet_scans.keys())

        for i, subnet in enumerate(subnet_list):
            scan_count = len(subnet_scans[subnet])
            console.print(f"  {i + 1}. {subnet} ({scan_count} scans)")

        try:
            choice = int(Prompt.ask("Select subnet", default="1")) - 1
            if 0 <= choice < len(subnet_list):
                return subnet_list[choice]
        except ValueError:
            pass

        console.print("[red]Invalid selection[/red]")
        return None

    def _compare_device_lists(self, older_devices, newer_devices):
        """Compare two device lists and return detailed changes"""
        # Create lookup maps
        older_map = {d["ip"]: d for d in older_devices}
        newer_map = {d["ip"]: d for d in newer_devices}

        # Find changes
        new_ips = set(newer_map.keys()) - set(older_map.keys())
        missing_ips = set(older_map.keys()) - set(newer_map.keys())
        common_ips = set(older_map.keys()) & set(newer_map.keys())

        # Build change data
        changes = {
            "new_devices": [newer_map[ip] for ip in new_ips],
            "missing_devices": [older_map[ip] for ip in missing_ips],
            "modified_devices": [],
            "unchanged_devices": [],
        }

        # Check for modifications in common devices
        for ip in common_ips:
            older = older_map[ip]
            newer = newer_map[ip]

            modifications = self._detect_device_changes(older, newer)
            if modifications:
                changes["modified_devices"].append(
                    {"ip": ip, "older": older, "newer": newer, "changes": modifications}
                )
            else:
                changes["unchanged_devices"].append(newer)

        # Add summary
        changes["summary"] = {
            "total_older": len(older_devices),
            "total_newer": len(newer_devices),
            "new_count": len(changes["new_devices"]),
            "missing_count": len(changes["missing_devices"]),
            "modified_count": len(changes["modified_devices"]),
            "unchanged_count": len(changes["unchanged_devices"]),
        }

        return changes

    def _detect_device_changes(self, older, newer):
        """Detect specific changes between two device records"""
        changes = []

        # Fields to compare
        fields = ["hostname", "mac", "vendor", "type", "os", "services", "open_ports"]

        for field in fields:
            old_val = older.get(field, "")
            new_val = newer.get(field, "")

            # Special handling for lists
            if isinstance(old_val, list) and isinstance(new_val, list):
                old_set = set(old_val)
                new_set = set(new_val)

                if old_set != new_set:
                    added = new_set - old_set
                    removed = old_set - new_set

                    if added:
                        changes.append({"field": field, "type": "added", "values": list(added)})
                    if removed:
                        changes.append({"field": field, "type": "removed", "values": list(removed)})
            else:
                # Simple field comparison
                if old_val != new_val:
                    changes.append(
                        {
                            "field": field,
                            "type": "changed",
                            "old_value": old_val,
                            "new_value": new_val,
                        }
                    )

        return changes

    def _display_detailed_comparison(self, changes, older_scan_file, newer_scan_file):
        """Display detailed comparison results with color coding"""
        # Extract timestamps for display
        older_timestamp = older_scan_file.stem.replace("scan_", "")
        newer_timestamp = newer_scan_file.stem.replace("scan_", "")
        older_date = datetime.strptime(older_timestamp, "%Y%m%d_%H%M%S").strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        newer_date = datetime.strptime(newer_timestamp, "%Y%m%d_%H%M%S").strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # Header
        console.print("\n[bold cyan]Network Comparison Results[/bold cyan]")
        console.print(f"[dim]Older scan: {older_date}[/dim]")
        console.print(f"[dim]Newer scan: {newer_date}[/dim]")

        # Summary table
        summary_table = Table(show_header=False, box=None, padding=(0, 2))
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Count", style="yellow")

        summary = changes["summary"]
        summary_table.add_row("Devices in older scan", str(summary["total_older"]))
        summary_table.add_row("Devices in newer scan", str(summary["total_newer"]))
        summary_table.add_row("New devices", f"[green]+{summary['new_count']}[/green]")
        summary_table.add_row("Missing devices", f"[red]-{summary['missing_count']}[/red]")
        summary_table.add_row("Modified devices", f"[yellow]~{summary['modified_count']}[/yellow]")
        summary_table.add_row("Unchanged devices", str(summary["unchanged_count"]))

        console.print("\n[bold]Summary:[/bold]")
        console.print(summary_table)

        # New devices
        if changes["new_devices"]:
            console.print("\n[bold green]NEW DEVICES[/bold green]")
            new_table = Table()
            new_table.add_column("IP", style="green")
            new_table.add_column("Hostname", style="green")
            new_table.add_column("Type", style="green")
            new_table.add_column("Vendor", style="green")
            new_table.add_column("Services", style="green")

            for device in changes["new_devices"]:
                services = ", ".join(device.get("services", [])[:3])
                if len(device.get("services", [])) > 3:
                    services += "..."

                new_table.add_row(
                    device["ip"],
                    device.get("hostname", "N/A"),
                    device.get("type", "unknown"),
                    device.get("vendor", "N/A"),
                    services or "None",
                )

            console.print(new_table)

        # Missing devices
        if changes["missing_devices"]:
            console.print("\n[bold red]MISSING DEVICES[/bold red]")
            missing_table = Table()
            missing_table.add_column("IP", style="red")
            missing_table.add_column("Hostname", style="red")
            missing_table.add_column("Type", style="red")
            missing_table.add_column("Last Known Services", style="red")

            for device in changes["missing_devices"]:
                services = ", ".join(device.get("services", [])[:3])
                if len(device.get("services", [])) > 3:
                    services += "..."

                missing_table.add_row(
                    device["ip"],
                    device.get("hostname", "N/A"),
                    device.get("type", "unknown"),
                    services or "None",
                )

            console.print(missing_table)

        # Modified devices
        if changes["modified_devices"]:
            console.print("\n[bold yellow]MODIFIED DEVICES[/bold yellow]")
            for device_change in changes["modified_devices"]:
                ip = device_change["ip"]
                hostname = device_change["newer"].get("hostname", "N/A")

                console.print(f"\n[yellow]• {ip} - {hostname}[/yellow]")

                for change in device_change["changes"]:
                    field = change["field"]
                    change_type = change["type"]

                    if change_type == "changed":
                        old_val = change["old_value"] or "None"
                        new_val = change["new_value"] or "None"
                        console.print(f"  {field}: [red]{old_val}[/red] → [green]{new_val}[/green]")
                    elif change_type == "added":
                        values = ", ".join(str(v) for v in change["values"])
                        console.print(f"  {field}: [green]+{values}[/green]")
                    elif change_type == "removed":
                        values = ", ".join(str(v) for v in change["values"])
                        console.print(f"  {field}: [red]-{values}[/red]")

    def _export_comparison_results(self, changes, older_scan_file, newer_scan_file):
        """Export comparison results to multiple formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Extract scan timestamps for filename
        older_timestamp = older_scan_file.stem.replace("scan_", "")
        newer_timestamp = newer_scan_file.stem.replace("scan_", "")

        # Ensure exports directory exists
        export_dir = self.output_path / "exports"
        export_dir.mkdir(exist_ok=True)

        console.print("\n[bold]Export Format Options:[/bold]")
        console.print("  1. JSON (complete data)")
        console.print("  2. CSV (summary format)")
        console.print("  3. HTML report")
        console.print("  4. All formats")

        choice = Prompt.ask("Select export format", choices=["1", "2", "3", "4"], default="4")

        exported_files = []

        # JSON Export
        if choice in ["1", "4"]:
            json_file = export_dir / f"comparison_{older_timestamp}_to_{newer_timestamp}.json"
            export_data = {
                "comparison_timestamp": datetime.now().isoformat(),
                "older_scan": {
                    "file": older_scan_file.name,
                    "timestamp": older_timestamp,
                    "date": datetime.strptime(older_timestamp, "%Y%m%d_%H%M%S").isoformat(),
                },
                "newer_scan": {
                    "file": newer_scan_file.name,
                    "timestamp": newer_timestamp,
                    "date": datetime.strptime(newer_timestamp, "%Y%m%d_%H%M%S").isoformat(),
                },
                "changes": changes,
            }

            with open(json_file, "w") as f:
                json.dump(export_data, f, indent=2)

            exported_files.append(("JSON", json_file))

        # CSV Export
        if choice in ["2", "4"]:
            csv_file = export_dir / f"comparison_{older_timestamp}_to_{newer_timestamp}.csv"

            with open(csv_file, "w", newline="") as f:
                writer = csv.writer(f)

                # Write header info
                writer.writerow(["Network Comparison Report"])
                writer.writerow(
                    [
                        "Older Scan",
                        datetime.strptime(older_timestamp, "%Y%m%d_%H%M%S").strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                    ]
                )
                writer.writerow(
                    [
                        "Newer Scan",
                        datetime.strptime(newer_timestamp, "%Y%m%d_%H%M%S").strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                    ]
                )
                writer.writerow([])

                # Summary
                writer.writerow(["Summary"])
                writer.writerow(["Type", "Count"])
                writer.writerow(["Total devices (older)", changes["summary"]["total_older"]])
                writer.writerow(["Total devices (newer)", changes["summary"]["total_newer"]])
                writer.writerow(["New devices", changes["summary"]["new_count"]])
                writer.writerow(["Missing devices", changes["summary"]["missing_count"]])
                writer.writerow(["Modified devices", changes["summary"]["modified_count"]])
                writer.writerow(["Unchanged devices", changes["summary"]["unchanged_count"]])
                writer.writerow([])

                # New devices
                if changes["new_devices"]:
                    writer.writerow(["NEW DEVICES"])
                    writer.writerow(["IP", "Hostname", "Type", "Vendor", "Services"])
                    for device in changes["new_devices"]:
                        writer.writerow(
                            [
                                device["ip"],
                                device.get("hostname", "N/A"),
                                device.get("type", "unknown"),
                                device.get("vendor", "N/A"),
                                "; ".join(device.get("services", [])),
                            ]
                        )
                    writer.writerow([])

                # Missing devices
                if changes["missing_devices"]:
                    writer.writerow(["MISSING DEVICES"])
                    writer.writerow(["IP", "Hostname", "Type", "Last Known Services"])
                    for device in changes["missing_devices"]:
                        writer.writerow(
                            [
                                device["ip"],
                                device.get("hostname", "N/A"),
                                device.get("type", "unknown"),
                                "; ".join(device.get("services", [])),
                            ]
                        )
                    writer.writerow([])

                # Modified devices
                if changes["modified_devices"]:
                    writer.writerow(["MODIFIED DEVICES"])
                    writer.writerow(["IP", "Hostname", "Field", "Change Type", "Details"])
                    for device_change in changes["modified_devices"]:
                        ip = device_change["ip"]
                        hostname = device_change["newer"].get("hostname", "N/A")

                        for change in device_change["changes"]:
                            if change["type"] == "changed":
                                details = f"{change['old_value']} → {change['new_value']}"
                            elif change["type"] == "added":
                                details = f"+{', '.join(str(v) for v in change['values'])}"
                            else:  # removed
                                details = f"-{', '.join(str(v) for v in change['values'])}"

                            writer.writerow(
                                [ip, hostname, change["field"], change["type"], details]
                            )

            exported_files.append(("CSV", csv_file))

        # HTML Export
        if choice in ["3", "4"]:
            # Use the existing comparison report generator
            comparison_file = self.generate_comparison_report(
                changes.get("unchanged_devices", []) + changes.get("modified_devices", []),
                changes,
                newer_timestamp,
            )
            if comparison_file:
                exported_files.append(("HTML", comparison_file))

        # Display results
        if exported_files:
            console.print("\n[green]✓ Export complete![/green]")
            console.print("\n[bold]Exported files:[/bold]")

            for format_name, file_path in exported_files:
                console.print(f"  {format_name}: [yellow]{file_path}[/yellow]")

            if Confirm.ask("\nOpen exported files?"):
                import webbrowser

                for _, file_path in exported_files:
                    webbrowser.open(f"file://{file_path.absolute()}")

    def _display_changes_summary(self, changes):
        """Display a summary of changes"""
        console.print("\n[bold]Network Changes Summary[/bold]\n")

        if changes.get("new_devices"):
            console.print(f"[green]NEW DEVICES ({len(changes['new_devices'])})[/green]")
            for device in changes["new_devices"]:
                hostname = device.get('hostname', '')
                if not hostname:
                    hostname = ''
                console.print(
                    f"  • {device['ip']} - {hostname} "
                    f"({device.get('type', 'unknown')})"
                )

        if changes.get("missing_devices"):
            console.print(f"\n[red]MISSING DEVICES ({len(changes['missing_devices'])})[/red]")
            for device in changes["missing_devices"]:
                hostname = device.get('hostname', '')
                if not hostname:
                    hostname = ''
                console.print(
                    f"  • {device['ip']} - {hostname} "
                    f"({device.get('type', 'unknown')})"
                )

        if changes.get("changed_devices"):
            console.print(f"\n[yellow]CHANGED DEVICES ({len(changes['changed_devices'])})[/yellow]")
            for device in changes["changed_devices"]:
                hostname = device.get('hostname', '')
                if not hostname:
                    hostname = ''
                console.print(f"  • {device['ip']} - {hostname}")

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
        report_files = sorted(
            (self.output_path / "reports").glob("network_map_*.html"), reverse=True
        )

        # Fall back to old report format if no new maps found
        if not report_files:
            report_files = sorted(
                (self.output_path / "reports").glob("report_*.html"), reverse=True
            )

        if report_files:
            import webbrowser

            file_url = f"file://{report_files[0].absolute()}"
            webbrowser.open(file_url)
            console.print("[green]Opening network map in browser...[/green]")
            console.print(f"\n[bold cyan]Network map location:[/bold cyan]")
            console.print(f"[yellow underline]{file_url}[/yellow underline]")
        else:
            console.print(
                "[yellow]No network maps found. Run a scan first to generate a visualization.[/yellow]"
            )
        input("\nPress Enter to continue...")

    def _handle_snmp_setup(self) -> Tuple[bool, Dict]:
        """Handle SNMP setup with CLI override support

        Returns:
            Tuple of (enabled, config_dict)
        """
        # Check for CLI override to disable SNMP
        if self.cli_overrides.get("disable_snmp"):
            console.print("\n[dim]SNMP enrichment disabled via CLI argument[/dim]")
            return False, {}

        # Check for CLI override with specific settings
        if self.cli_overrides.get("snmp_community") or self.cli_overrides.get("snmp_version"):
            config = {}

            version = self.cli_overrides.get("snmp_version", "v2c")
            if version not in ["v1", "v2c", "v3"]:
                console.print(f"[red]Invalid SNMP version '{version}'. Using v2c.[/red]")
                version = "v2c"

            config["version"] = version

            if version in ["v1", "v2c"]:
                community = self.cli_overrides.get("snmp_community", "public")
                config["community"] = community
                console.print(
                    f"\n[green]✓ SNMP enrichment enabled via CLI: {version} with community '{community}'[/green]"
                )
            else:
                console.print(
                    f"\n[yellow]SNMPv3 specified via CLI but credentials missing. Using interactive setup.[/yellow]"
                )
                return self.snmp_config.interactive_setup()

            config["timeout"] = 2
            config["retries"] = 1
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
        ip_match = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", target)
        if ip_match:
            return all(is_valid_ip_octet(octet) for octet in ip_match.groups())

        # CIDR notation
        cidr_match = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$", target)
        if cidr_match:
            octets = cidr_match.groups()[:4]
            prefix = int(cidr_match.group(5))
            return all(is_valid_ip_octet(octet) for octet in octets) and 0 <= prefix <= 32

        # IP range
        range_match = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})-(\d{1,3})$", target)
        if range_match:
            octets = range_match.groups()[:4]
            end_range = int(range_match.group(5))
            return (
                all(is_valid_ip_octet(octet) for octet in octets)
                and 0 <= end_range <= 255
                and end_range >= int(octets[3])
            )

        # Hostname pattern (basic but more restrictive)
        hostname_pattern = r"^[a-zA-Z0-9][a-zA-Z0-9\.-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$"
        if re.match(hostname_pattern, target):
            # Additional hostname validation
            if len(target) > 253:  # Max hostname length
                return False
            if ".." in target:  # No consecutive dots
                return False
            if target.startswith(".") or target.endswith("."):  # No leading/trailing dots
                return False
            return True

        return False

    def _select_scan_type(self) -> Tuple[str, str, bool, bool]:
        """Select scan type with improved UX"""
        console.print("\n[bold]Scan Type[/bold]")

        # Two scan options: Deep (fast) and Deeper (more accurate)
        scan_options = [
            (
                "fast",
                "Deep Scan",
                "Fast scan for large networks using masscan + light nmap enrichment",
                "2-5 minutes",
                True,
            ),
            (
                "deeper",
                "Deeper Scan",
                "More accurate scan with comprehensive OS/service detection",
                "5-15 minutes",
                True,
            ),
        ]

        for i, (_, name, desc, time, needs_root) in enumerate(scan_options, 1):
            sudo_text = " (requires sudo)" if needs_root else ""
            console.print(f"{i}. [bold]{name}[/bold] – {desc}")
            console.print(f"   [dim]Duration: ~{time}{sudo_text}[/dim]")

        while True:
            try:
                choice = Prompt.ask(
                    "\nSelect scan type", choices=["1", "2"], default="1"
                )
                choice_idx = int(choice) - 1
                scan_type, scan_name, _, _, needs_root = scan_options[choice_idx]

                # Both scan types use masscan for discovery
                use_masscan = True
                
                if scan_type == "fast":
                    console.print("\n[cyan]⚡ Deep Scan selected[/cyan]")
                    console.print("[cyan]📊 Will use masscan for discovery + light nmap enrichment[/cyan]")
                    console.print("[cyan]💡 Perfect for quick scans of large networks[/cyan]")
                else:  # deeper
                    console.print("\n[cyan]🔬 Deeper Scan selected[/cyan]")
                    console.print("[cyan]📊 Will use masscan for discovery + comprehensive nmap enrichment[/cyan]")
                    console.print("[cyan]🎯 More accurate OS detection and service identification[/cyan]")
                    console.print("[cyan]⏱️  Takes longer but provides better results[/cyan]")

                return scan_type, scan_name, needs_root, use_masscan

            except (ValueError, IndexError):
                console.print("[red]Please select a valid option (1 or 2)[/red]")

    def _handle_vulnerability_setup(self) -> bool:
        """Handle vulnerability scanning setup"""
        console.print("\n[bold]Vulnerability Analysis[/bold]")
        console.print("Check discovered services against multiple CVE databases")
        console.print("[dim]Uses OSV (Google) and CIRCL APIs - no registration required[/dim]")

        enabled = Confirm.ask("Enable vulnerability scanning", default=True)

        if enabled:
            console.print(
                "[green]→ Vulnerability scanning enabled (OSV + CIRCL + Local patterns)[/green]"
            )
        else:
            console.print("[dim]→ Vulnerability scanning disabled[/dim]")

        return enabled

    def _handle_passive_analysis_setup(self) -> Tuple[bool, int]:
        """Handle passive traffic analysis setup"""
        console.print("\n[bold]Passive Traffic Analysis[/bold]")
        console.print("Discover stealth devices and map real-time traffic flows")
        console.print("[dim]Requires root/sudo privileges - captures network packets[/dim]")

        enabled = Confirm.ask("Enable passive traffic analysis", default=False)
        duration = 30  # Default duration

        if enabled:
            console.print("\n[bold]Capture Duration[/bold]")
            console.print("How long to analyze traffic? (longer = more accurate)")
            console.print("  1. Quick (30 seconds)")
            console.print("  2. Standard (60 seconds)")
            console.print("  3. Extended (120 seconds)")
            console.print("  4. Custom duration")

            choice = Prompt.ask("Select duration", choices=["1", "2", "3", "4"], default="2")

            if choice == "1":
                duration = 30
            elif choice == "2":
                duration = 60
            elif choice == "3":
                duration = 120
            elif choice == "4":
                duration = int(Prompt.ask("Enter duration in seconds", default="60"))

            console.print(f"[green]→ Passive analysis enabled for {duration} seconds[/green]")
        else:
            console.print("[dim]→ Passive analysis disabled[/dim]")

        return enabled, duration

    def _display_passive_analysis_summary(self, summary: Dict):
        """Display passive analysis summary"""
        console.print("\n[bold cyan]Passive Analysis Results[/bold cyan]")

        # Summary table
        summary_table = Table(show_header=False, box=None, padding=(0, 2))
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="yellow")

        summary_table.add_row("Stealth devices found", str(summary["stealth_devices"]))
        summary_table.add_row("Traffic flows captured", str(summary["total_flows"]))

        console.print(summary_table)

        # Top talkers
        if summary.get("top_talkers"):
            console.print("\n[bold]Top Traffic Generators:[/bold]")
            for ip, bytes_count in summary["top_talkers"]:
                console.print(f"  • {ip}: {bytes_count:,} bytes")

    def _display_vulnerability_summary(self, vuln_report: Dict):
        """Display vulnerability scan summary"""
        if vuln_report["total_vulnerabilities"] == 0:
            console.print("[green]✓ No vulnerabilities found[/green]")
            return

        console.print(f"\n[bold red]Vulnerability Summary[/bold red]")

        # Create summary table
        summary_table = Table(show_header=False, box=None, padding=(0, 2))
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Count", style="yellow")

        summary_table.add_row("Total vulnerabilities", str(vuln_report["total_vulnerabilities"]))
        summary_table.add_row(
            "Vulnerable devices",
            f"{vuln_report['vulnerable_devices']}/{vuln_report['total_devices']}",
        )
        summary_table.add_row("Critical severity", str(vuln_report["critical_vulnerabilities"]))
        summary_table.add_row("High severity", str(vuln_report["high_vulnerabilities"]))

        console.print(summary_table)

        # Show top vulnerabilities
        top_vulns = vuln_report["top_vulnerabilities"][:3]  # Show top 3
        if top_vulns:
            console.print("\n[bold]Top Vulnerabilities:[/bold]")
            for vuln in top_vulns:
                severity_color = {
                    "CRITICAL": "red",
                    "HIGH": "orange1",
                    "MEDIUM": "yellow",
                    "LOW": "blue",
                }.get(vuln.get("severity"), "white")

                console.print(
                    f"• [{severity_color}]{vuln.get('cve_id')}[/{severity_color}] "
                    f"(CVSS: {vuln.get('cvss_score', 0):.1f}) - {vuln.get('device_ip')}"
                )

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
                    export_file = (
                        self.output_path / "exports" / f"{device_type}_devices_{timestamp}.csv"
                    )
                    self.output_path.joinpath("exports").mkdir(exist_ok=True)
                    self.save_csv(filtered, export_file)
                    console.print(
                        f"[green]✓ {device_type} devices exported to: {export_file}[/green]"
                    )
                else:
                    console.print(f"[yellow]No {device_type} devices found.[/yellow]")

            # Ask if user wants to open the export
            if "export_file" in locals() and Confirm.ask("\nOpen exported file?"):
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
            "disable_snmp": disable_snmp,
            "snmp_community": snmp_community,
            "snmp_version": snmp_version,
        }

        # Use modern interface
        mapper.modern_ui.interactive_menu()
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user[/red]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")


if __name__ == "__main__":
    app()
