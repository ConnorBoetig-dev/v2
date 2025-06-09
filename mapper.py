#!/usr/bin/env python3
"""
NetworkMapper 2.0 - Network Discovery and Mapping Tool
"""

import csv
import json
from datetime import datetime
from pathlib import Path

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
        self.last_changes = None

    def ensure_directories(self):
        """Create output directories if they don't exist"""
        dirs = [
            self.output_path / "scans",
            self.output_path / "reports",
            self.output_path / "changes",
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
        """Interactive scan wizard"""
        console.print("\n[bold]Network Scan Wizard[/bold]")

        # Get target
        target = Prompt.ask("Enter target network (example: 192.168.1.0/24)")

        # Select scan type
        scan_types = {
            "1": ("discovery", "Discovery Scan", "~30 seconds", False),
            "2": ("inventory", "Inventory Scan", "~5 minutes", True),
            "3": ("deep", "Deep Scan", "~15 minutes", True),
            "4": ("arp", "ARP Scan (Layer 2)", "~10 seconds", True),
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
        console.print(f"\n[yellow]Starting {scan_name} on {target}...[/yellow]\n")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Handle ARP scan separately
        if scan_type == "arp":
            results = self.scanner._run_arp_scan(target)
        else:
            results = self.scanner.scan(
                target=target, scan_type=scan_type, use_masscan=use_masscan, needs_root=needs_root
            )

        # Parse and classify
        devices = self.parser.parse_results(results)
        devices = self.classifier.classify_devices(devices)

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

        if Confirm.ask("\nGenerate HTML report?"):
            report_file, comparison_file = self.generate_html_report(devices, timestamp)

            # Show report paths
            console.print(f"\n[bold]Report Files:[/bold]")
            report_table = Table(show_header=False, box=None, padding=(0, 2))
            report_table.add_column("Type", style="cyan")
            report_table.add_column("Path", style="yellow")

            report_table.add_row("Main report:", str(report_file))
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
                "critical",
                "notes",
                "last_seen",
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for device in devices:
                row = {
                    "ip": device.get("ip"),
                    "hostname": device.get("hostname", ""),
                    "mac": device.get("mac", ""),
                    "vendor": device.get("vendor", ""),
                    "type": device.get("type", "unknown"),
                    "os": device.get("os", ""),
                    "services": ";".join(device.get("services", [])),
                    "open_ports": ";".join(map(str, device.get("open_ports", []))),
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
        template = env.get_template("report.html")

        # Prepare report data - IMPORTANT: pass the actual scan timestamp
        report_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_timestamp": timestamp,  # Add this for the JavaScript
            "scan_date": datetime.now().strftime("%B %d, %Y"),
            "total_devices": len(devices),
            "devices": devices,
            "device_types": self._count_device_types(devices),
            "critical_devices": [d for d in devices if d.get("critical", False)],
            "d3_data": json.dumps(d3_data),
            "three_data": json.dumps(three_data),
            "subnet_summary": self._get_subnet_summary(devices),
        }

        # Render and save report
        report_file = self.output_path / "reports" / f"report_{timestamp}.html"
        html_content = template.render(**report_data)

        with open(report_file, "w") as f:
            f.write(html_content)

        # Open in browser
        file_url = f"file://{report_file.absolute()}"
        webbrowser.open(file_url)

        # Show clickable link in terminal
        console.print("\n[green]✓ Report generated and opened in browser![/green]")

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

        return report_file, comparison_file

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
        # Get most recent report
        report_files = sorted((self.output_path / "reports").glob("report_*.html"), reverse=True)
        if report_files:
            import webbrowser

            file_url = f"file://{report_files[0].absolute()}"
            webbrowser.open(file_url)
            console.print("[green]Opening network map in browser...[/green]")
        else:
            console.print("[yellow]No reports found. Generate a report first.[/yellow]")
        input("\nPress Enter to continue...")

    def export_data(self):
        """Export data menu"""
        console.print("\n[bold]Export Options:[/bold]")
        console.print("  1. Export all devices (CSV)")
        console.print("  2. Export critical devices only")
        console.print("  3. Export by device type")

        choice = Prompt.ask("Select export option", choices=["1", "2", "3"])

        # Get most recent scan
        scan_files = sorted((self.output_path / "scans").glob("scan_*.json"), reverse=True)
        if not scan_files:
            console.print("[yellow]No scans found[/yellow]")
            input("\nPress Enter to continue...")
            return

        with open(scan_files[0]) as f:
            devices = json.load(f)

        devices = self.annotator.apply_annotations(devices)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if choice == "1":
            export_file = self.output_path / f"export_all_{timestamp}.csv"
            self.save_csv(devices, export_file)
        elif choice == "2":
            critical = [d for d in devices if d.get("critical", False)]
            export_file = self.output_path / f"export_critical_{timestamp}.csv"
            self.save_csv(critical, export_file)
        elif choice == "3":
            device_type = Prompt.ask("Enter device type (router/switch/server/etc)")
            filtered = [d for d in devices if d.get("type") == device_type]
            export_file = self.output_path / f"export_{device_type}_{timestamp}.csv"
            self.save_csv(filtered, export_file)

        console.print(f"[green]✓ Exported to: {export_file}[/green]")
        input("\nPress Enter to continue...")


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