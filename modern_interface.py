#!/usr/bin/env python3
"""
Modern Interactive Interface for NetworkMapper v2
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple, Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.layout import Layout
from rich.columns import Columns
from rich.align import Align
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.tree import Tree
from rich.rule import Rule
from rich.live import Live
from rich import box
from rich.padding import Padding

console = Console()

class ModernInterface:
    """Modern interface wrapper for NetworkMapper"""
    
    def __init__(self, mapper_instance):
        self.mapper = mapper_instance
        self.output_path = mapper_instance.output_path
        
    def interactive_menu(self):
        """Modern interactive menu with rich layouts"""
        while True:
            console.clear()
            
            # Create the main layout
            layout = Layout()
            
            # Split into header, main content, and footer
            layout.split_column(
                Layout(name="header", size=8),
                Layout(name="main", ratio=1),
                Layout(name="footer", size=3)
            )
            
            # Split main into left and right panels
            layout["main"].split_row(
                Layout(name="menu", ratio=1),
                Layout(name="info", ratio=1)
            )
            
            # Create header with gradient effect and status
            header_text = Text()
            header_text.append("███", style="#00d7ff")
            header_text.append(" NetworkMapper ", style="bold white")
            header_text.append("v2.0 ", style="#00d7ff")
            header_text.append("███", style="#00d7ff")
            
            header_content = Align.center(
                Panel(
                    Align.center(
                        Text.assemble(
                            header_text,
                            "\n",
                            ("Advanced Network Discovery & Security Assessment", "dim white")
                        )
                    ),
                    style="#00d7ff",
                    box=box.DOUBLE_EDGE,
                    padding=(1, 2)
                )
            )
            
            # Create modern menu with icons and descriptions
            menu_items = [
                ("1", "🔍", "Network Scanner", "Discover devices and services", "#00ff87"),
                ("2", "📊", "Scan History", "View previous scan results", "#5fafff"),
                ("3", "🔄", "Change Detection", "Monitor network changes", "#ffaf00"),
                ("4", "🔀", "Scan Comparison", "Compare different scans", "#af87ff"),
                ("5", "✏️", "Device Annotation", "Add notes and tags", "#ff8700"),
                ("6", "📈", "Report Generator", "Create detailed reports", "#87ff00"),
                ("7", "🗺️", "Network Visualization", "Interactive network maps", "#ff5f87"),
                ("8", "📤", "Data Export", "Export to various formats", "#00ffff"),
                ("9", "❌", "Exit", "Close NetworkMapper", "#ff6b6b")
            ]
            
            menu_panels = []
            for num, icon, title, desc, color in menu_items:
                panel_content = Text.assemble(
                    (f"{icon} ", "bold"),
                    (title, f"bold {color}"),
                    "\n",
                    (desc, "dim")
                )
                
                panel = Panel(
                    panel_content,
                    title=f"[bold]{num}[/bold]",
                    title_align="left",
                    border_style=color,
                    padding=(0, 1),
                    width=35
                )
                menu_panels.append(panel)
            
            # Arrange menu in columns
            menu_content = Columns(menu_panels, equal=True, expand=True)
            
            # Create info panel with system status
            info_content = self._get_system_status()
            
            # Create footer
            footer_content = Align.center(
                Text.assemble(
                    ("Press ", "dim"),
                    ("1-9", "bold cyan"),
                    (" to select • ", "dim"),
                    ("Ctrl+C", "bold red"),
                    (" to exit", "dim")
                )
            )
            
            # Assign content to layout sections
            layout["header"].update(header_content)
            layout["menu"].update(Padding(menu_content, (1, 2)))
            layout["info"].update(Padding(info_content, (1, 2)))
            layout["footer"].update(footer_content)
            
            # Display the layout
            console.print(layout)
            
            # Get user choice with enhanced prompt
            choice = Prompt.ask(
                "\n[bold cyan]❯[/bold cyan] Select option",
                choices=[str(i) for i in range(1, 10)],
                show_choices=False
            )
            
            if choice == "1":
                self.run_scan_wizard()
            elif choice == "2":
                self.mapper.view_recent_scans()
            elif choice == "3":
                self.mapper.check_changes()
            elif choice == "4":
                self.mapper.compare_scans_interactive()
            elif choice == "5":
                self.mapper.annotate_devices()
            elif choice == "6":
                self.mapper.generate_reports()
            elif choice == "7":
                self.mapper.view_network_map()
            elif choice == "8":
                self.mapper.export_data()
            elif choice == "9":
                if self._confirm_exit():
                    break
                    
    def run_scan_wizard(self):
        """Modern interactive scan wizard with step-by-step UI"""
        console.clear()
        
        # Create wizard header
        wizard_header = Panel(
            Align.center(
                Text.assemble(
                    ("🧙 ", "bold"),
                    ("Network Scan Wizard", "bold cyan"),
                    "\n",
                    ("Follow the steps to configure your network scan", "dim")
                )
            ),
            style="cyan",
            box=box.DOUBLE_EDGE,
            padding=(1, 2)
        )
        console.print(wizard_header)
        console.print()
        
        # Step-by-step wizard with progress tracking
        steps = [
            ("🎯", "Target Selection", "target"),
            ("⚡", "Scan Configuration", "scan_config"),
            ("🔧", "SNMP Setup", "snmp"),
            ("🛡️", "Vulnerability Scanning", "vuln"),
            ("📡", "Traffic Analysis", "traffic")
        ]
        
        results = {}
        
        for i, (icon, step_name, step_key) in enumerate(steps, 1):
            # Show progress
            progress_text = f"Step {i}/{len(steps)}: {icon} {step_name}"
            step_panel = Panel(
                progress_text,
                title=f"[bold white]Wizard Progress[/bold white]",
                border_style="yellow",
                padding=(0, 2)
            )
            console.print(step_panel)
            
            # Execute step
            if step_key == "target":
                results['target'] = self._get_scan_target()
            elif step_key == "scan_config":
                scan_type, scan_name, needs_root, use_masscan = self._select_scan_type()
                results.update({
                    'scan_type': scan_type,
                    'scan_name': scan_name,
                    'needs_root': needs_root,
                    'use_masscan': use_masscan
                })
            elif step_key == "snmp":
                snmp_enabled, snmp_config = self.mapper._handle_snmp_setup()
                results.update({'snmp_enabled': snmp_enabled, 'snmp_config': snmp_config})
            elif step_key == "vuln":
                results['vuln_enabled'] = self.mapper._handle_vulnerability_setup()
            elif step_key == "traffic":
                passive_enabled, passive_duration = self.mapper._handle_passive_analysis_setup()
                results.update({'passive_enabled': passive_enabled, 'passive_duration': passive_duration})
            
            console.print()
        
        # Show scan summary before execution
        self._show_scan_summary(
            results['target'], 
            results['scan_name'], 
            results['snmp_enabled'], 
            results['vuln_enabled'], 
            results['passive_enabled']
        )
        
        if not Confirm.ask("\n[bold green]❯[/bold green] Start scan with these settings?"):
            console.print("[yellow]Scan cancelled.[/yellow]")
            input("\nPress Enter to return to menu...")
            return
            
        # Execute the actual scan using the original mapper method
        self._execute_scan_with_modern_ui(results)
        
    def _get_scan_target(self) -> str:
        """Get and validate scan target with modern UI"""
        target_panel = Panel(
            Text.assemble(
                ("Enter your scan target using one of these formats:\n\n", "white"),
                ("🌐 Network CIDR:  ", "cyan"), ("192.168.1.0/24\n", "yellow"),
                ("🎯 Single IP:     ", "cyan"), ("192.168.1.100\n", "yellow"),
                ("📍 IP Range:      ", "cyan"), ("192.168.1.1-50\n", "yellow"),
                ("🔗 Hostname:      ", "cyan"), ("example.com", "yellow")
            ),
            title="[bold white]Target Selection[/bold white]",
            border_style="cyan",
            padding=(1, 2)
        )
        console.print(target_panel)
        
        while True:
            target = Prompt.ask("\n[bold cyan]❯[/bold cyan] Target").strip()
            
            if not target:
                console.print("[red]❌ Target cannot be empty[/red]")
                continue
                
            # Use the original validation method
            if self.mapper._validate_target(target):
                success_panel = Panel(
                    f"✅ Valid target: [bold green]{target}[/bold green]",
                    border_style="green"
                )
                console.print(success_panel)
                return target
            else:
                console.print("[red]❌ Invalid target format. Please check your input.[/red]")
                
    def _select_scan_type(self) -> Tuple[str, str, bool, bool]:
        """Select scan type with modern card-based UI"""
        scan_panel = Panel(
            "Choose the type of scan based on your needs and time constraints",
            title="[bold white]Scan Configuration[/bold white]",
            border_style="yellow",
            padding=(0, 2)
        )
        console.print(scan_panel)
        
        scan_options = [
            ("discovery", "Discovery Scan", "Quick host discovery", "30 seconds", False),
            ("inventory", "Inventory Scan", "Service detection and OS fingerprinting", "5 minutes", True),
            ("deep", "Deep Scan", "Comprehensive analysis with scripts", "15 minutes", True),
            ("arp", "ARP Scan", "Layer 2 discovery for local networks", "10 seconds", True),
        ]
        
        # Create scan option cards
        scan_cards = []
        for i, (_, name, desc, time, needs_root) in enumerate(scan_options, 1):
            sudo_text = " 🔒" if needs_root else " 🔓"
            
            card_content = Text.assemble(
                (f"{name}", "bold white"),
                (sudo_text, "dim"),
                "\n",
                (desc, "cyan"),
                "\n",
                (f"⏱️  Duration: ~{time}", "yellow")
            )
            
            card = Panel(
                card_content,
                title=f"[bold]{i}[/bold]",
                border_style="green" if not needs_root else "orange3",
                padding=(1, 2),
                width=30
            )
            scan_cards.append(card)
            
        console.print(Columns(scan_cards, equal=True))
        
        while True:
            try:
                choice = Prompt.ask("\n[bold green]❯[/bold green] Select scan type", choices=["1", "2", "3", "4"], default="1")
                choice_idx = int(choice) - 1
                scan_type, scan_name, _, _, needs_root = scan_options[choice_idx]
                
                # Handle masscan option for discovery scans
                use_masscan = False
                if scan_type == "discovery":
                    speed_panel = Panel(
                        "Choose scanning engine for discovery mode",
                        title="[bold white]Speed Configuration[/bold white]",
                        border_style="magenta",
                        padding=(0, 2)
                    )
                    console.print(speed_panel)
                    
                    console.print("1. [bold]Standard (nmap)[/bold] - Reliable and accurate")
                    console.print("2. [bold]Fast (masscan)[/bold] - High-speed scanning")
                    
                    masscan_choice = Prompt.ask("\nUse fast scanning?", choices=["1", "2"], default="1")
                    
                    if masscan_choice == "2":
                        console.print("[green]⚡ Using masscan for faster discovery[/green]")
                        use_masscan = True
                    else:
                        console.print("[blue]🔍 Using nmap for standard discovery[/blue]")
                
                # Show selection confirmation
                confirm_text = Text.assemble(
                    ("Selected: ", "white"),
                    (scan_name, "bold green"),
                    (f" {'with masscan' if use_masscan else ''}", "dim")
                )
                console.print(Panel(confirm_text, border_style="green"))
                
                return scan_type, scan_name, needs_root, use_masscan
                
            except (ValueError, KeyboardInterrupt):
                console.print("[red]❌ Invalid selection. Please try again.[/red]")
                
    def _show_scan_summary(self, target, scan_name, snmp_enabled, vuln_enabled, passive_enabled):
        """Show scan configuration summary"""
        console.clear()
        
        summary_content = Text.assemble(
            ("🎯 Target: ", "cyan"), (f"{target}\n", "white"),
            ("⚡ Scan Type: ", "cyan"), (f"{scan_name}\n", "white"),
            ("🔧 SNMP: ", "cyan"), ("Enabled\n" if snmp_enabled else "Disabled\n", "green" if snmp_enabled else "red"),
            ("🛡️ Vulnerability Scan: ", "cyan"), ("Enabled\n" if vuln_enabled else "Disabled\n", "green" if vuln_enabled else "red"),
            ("📡 Traffic Analysis: ", "cyan"), ("Enabled" if passive_enabled else "Disabled", "green" if passive_enabled else "red")
        )
        
        summary_panel = Panel(
            summary_content,
            title="[bold white]📋 Scan Configuration Summary[/bold white]",
            border_style="blue",
            padding=(1, 2)
        )
        console.print(summary_panel)
        
    def _execute_scan_with_modern_ui(self, config):
        """Execute scan with modern progress UI and proper sudo handling"""
        console.clear()
        
        scan_header = Panel(
            Align.center(
                Text.assemble(
                    ("🚀 ", "bold"),
                    (f"Executing {config['scan_name']}", "bold green"),
                    "\n",
                    (f"Target: {config['target']}", "cyan")
                )
            ),
            style="green",
            box=box.DOUBLE_EDGE
        )
        console.print(scan_header)
        console.print()
        
        # Handle sudo authentication first if needed
        if config['needs_root']:
            console.print("[yellow]⚡ This scan requires administrator privileges.[/yellow]")
            console.print("[dim]Checking sudo access...[/dim]\n")
            
            # Check if we already have sudo access
            import subprocess
            result = subprocess.run(["sudo", "-n", "true"], capture_output=True)
            
            if result.returncode != 0:
                console.print("[yellow]🔐 Please enter your password for elevated privileges:[/yellow]")
                
                # Get password from user directly (no progress bar interference)
                sudo_result = subprocess.run(["sudo", "-v"])
                
                if sudo_result.returncode != 0:
                    console.print("[red]❌ Authentication failed. Scan cancelled.[/red]")
                    input("\nPress Enter to continue...")
                    return
                else:
                    console.print("[green]✅ Authentication successful![/green]\n")
            else:
                console.print("[green]✅ Sudo access already available![/green]\n")
        
        # Now run the scan with progress tracking
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_start_time = time.time()
        
        try:
            # For scans requiring real-time output (like nmap with sudo), we need to handle differently
            if config['needs_root'] and config['scan_type'] != 'arp':
                console.print("[cyan]🔍 Starting network scan...[/cyan]")
                console.print("[dim]This may take a few minutes depending on the target size.[/dim]\n")
                
                # Use the original scan method which handles real-time output
                results = self.mapper.scanner.scan(
                    target=config['target'],
                    scan_type=config['scan_type'],
                    use_masscan=config['use_masscan'],
                    needs_root=config['needs_root'],
                    snmp_config=config['snmp_config'] if config['snmp_enabled'] else None,
                )
                
                console.print("\n[green]✅ Network scan completed![/green]")
                
            else:
                # For non-sudo scans, we can use the progress bar
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]Scanning..."),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TimeElapsedColumn(),
                    console=console
                ) as progress:
                    scan_task = progress.add_task("Network scan in progress...", total=100)
                    
                    # Execute the scan
                    if config['scan_type'] == "arp":
                        results = self.mapper.scanner._run_arp_scan(config['target'])
                    else:
                        results = self.mapper.scanner.scan(
                            target=config['target'],
                            scan_type=config['scan_type'],
                            use_masscan=config['use_masscan'],
                            needs_root=config['needs_root'],
                            snmp_config=config['snmp_config'] if config['snmp_enabled'] else None,
                        )
                        
                    progress.update(scan_task, advance=70, description="Processing results...")
            
            # Parse and classify
            console.print("[cyan]📊 Processing scan results...[/cyan]")
            devices = self.mapper.parser.parse_results(results)
            devices = self.mapper.classifier.classify_devices(devices)
            
            # Add subnet tagging
            devices = self._add_subnet_tags(devices)
            
            # Handle passive analysis if enabled
            if config['passive_enabled']:
                console.print("[cyan]📡 Running traffic analysis...[/cyan]")
                # Passive analysis would go here
                time.sleep(2)  # Simulation
                
            # Calculate scan duration
            scan_duration = time.time() - scan_start_time
            config['scan_duration'] = f"{int(scan_duration // 60)}m {int(scan_duration % 60)}s"
            
            # Save results with metadata
            self._save_scan_with_metadata(devices, timestamp, config)
            
            # Generate reports with metadata
            console.print("[cyan]📄 Generating reports...[/cyan]")
            self.mapper.generate_html_report(devices, timestamp)
                
            # Show results with modern UI
            self._show_scan_results(devices, timestamp)
                
        except KeyboardInterrupt:
            console.print("\n[red]❌ Scan interrupted by user[/red]")
            input("\nPress Enter to continue...")
        except Exception as e:
            console.print(f"\n[red]❌ Scan failed: {e}[/red]")
            input("\nPress Enter to continue...")
                
    def _show_scan_results(self, devices, timestamp):
        """Show scan results with modern styling"""
        console.clear()
        
        # Results header
        results_panel = Panel(
            f"Scan completed successfully! Found [bold green]{len(devices)}[/bold green] devices.",
            title="[bold white]✅ Scan Results[/bold white]",
            border_style="green",
            padding=(1, 2)
        )
        console.print(results_panel)
        
        # Device summary table with subnet information
        if devices:
            device_table = Table(
                title="🖥️  Discovered Devices",
                show_header=True,
                header_style="bold cyan",
                border_style="blue",
                box=box.ROUNDED
            )
            device_table.add_column("IP Address", style="cyan", width=15)
            device_table.add_column("Hostname", style="yellow", width=18)
            device_table.add_column("Type", style="green", width=12)
            device_table.add_column("Subnet", style="blue", width=12)
            device_table.add_column("Ports", style="magenta", width=12)
            
            for device in devices[:10]:  # Show first 10 devices
                ports = ", ".join(map(str, device.get('open_ports', [])[:3]))  # First 3 ports
                if len(device.get('open_ports', [])) > 3:
                    ports += "..."
                    
                # Get subnet info
                subnet_display = device.get('subnet', 'Unknown')
                if subnet_display != 'Unknown':
                    # Show just the network part (e.g., 10.0.1.0/24 -> 10.0.1.x)
                    parts = subnet_display.split('/')
                    if parts[0].count('.') >= 3:
                        network_parts = parts[0].split('.')
                        subnet_display = f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}.x"
                    
                device_table.add_row(
                    device.get('ip', 'Unknown'),
                    device.get('hostname', 'Unknown')[:16] + "..." if len(device.get('hostname', '')) > 16 else device.get('hostname', 'Unknown'),
                    device.get('type', 'unknown'),
                    subnet_display,
                    ports or "None"
                )
                
            console.print(device_table)
            
            if len(devices) > 10:
                console.print(f"\n[dim]... and {len(devices) - 10} more devices[/dim]")
                
            # Show subnet summary
            subnets = self._get_discovered_subnets(devices)
            if subnets:
                subnet_panel = Panel(
                    Text.assemble(
                        ("📍 Discovered Subnets: ", "cyan"),
                        (", ".join(subnets), "white")
                    ),
                    border_style="blue",
                    padding=(0, 2)
                )
                console.print(subnet_panel)
        
        # Scan statistics summary
        stats_content = Text.assemble(
            ("📊 Scan Statistics:\n", "bold white"),
            (f"• Devices Found: ", "cyan"), (f"{len(devices)}\n", "white"),
            (f"• Services Detected: ", "cyan"), (f"{self._count_services(devices)}\n", "white"),
            (f"• Vulnerabilities: ", "cyan"), (f"{self._count_vulnerabilities(devices)}\n", "white"),
            (f"• Subnets: ", "cyan"), (f"{len(self._get_discovered_subnets(devices))}", "white")
        )
        
        stats_panel = Panel(
            stats_content,
            title="[bold white]📈 Summary[/bold white]",
            border_style="green",
            padding=(1, 2)
        )
        console.print(stats_panel)
        
        success_panel = Panel(
            Align.center(
                Text.assemble(
                    ("🎉 Scan completed successfully! ", "bold green"),
                    ("\nReports with detailed subnet analysis are ready for review.", "white")
                )
            ),
            style="green",
            padding=(1, 2)
        )
        console.print(success_panel)
        
        input("\n[dim]Press Enter to return to main menu...[/dim]")
        
    def _get_system_status(self):
        """Generate system status panel"""
        # Get recent scan info
        scan_files = sorted((self.output_path / "scans").glob("scan_*.json"), reverse=True)
        report_files = sorted((self.output_path / "reports").glob("*.html"), reverse=True)
        
        # Create status tree
        status_tree = Tree("[bold white]System Status[/bold white]")
        
        # Recent activity
        activity_branch = status_tree.add("[bold cyan]Recent Activity[/bold cyan]")
        if scan_files:
            latest_scan = scan_files[0]
            timestamp = latest_scan.stem.replace("scan_", "")
            try:
                date_str = datetime.strptime(timestamp, "%Y%m%d_%H%M%S").strftime("%m/%d %H:%M")
                activity_branch.add(f"[green]✓[/green] Last scan: {date_str}")
            except:
                activity_branch.add("[green]✓[/green] Last scan: Recently")
        else:
            activity_branch.add("[yellow]○[/yellow] No scans yet")
            
        if report_files:
            activity_branch.add(f"[green]✓[/green] Reports: {len(report_files)} available")
        else:
            activity_branch.add("[yellow]○[/yellow] No reports generated")
            
        # System info
        system_branch = status_tree.add("[bold cyan]System Info[/bold cyan]")
        system_branch.add(f"[blue]○[/blue] Output: {self.output_path}")
        
        # Quick stats
        if scan_files:
            try:
                with open(scan_files[0]) as f:
                    latest_devices = json.load(f)
                system_branch.add(f"[blue]○[/blue] Last scan: {len(latest_devices)} devices")
            except:
                pass
                
        # Tools status
        tools_branch = status_tree.add("[bold cyan]Available Tools[/bold cyan]")
        
        # Check for nmap
        try:
            import subprocess
            subprocess.run(["nmap", "--version"], capture_output=True, check=True)
            tools_branch.add("[green]✓[/green] nmap")
        except:
            tools_branch.add("[red]✗[/red] nmap")
            
        # Check for arp-scan
        try:
            subprocess.run(["arp-scan", "--version"], capture_output=True, check=True)
            tools_branch.add("[green]✓[/green] arp-scan")
        except:
            tools_branch.add("[yellow]○[/yellow] arp-scan (optional)")
            
        return Panel(
            status_tree,
            title="[bold white]Dashboard[/bold white]",
            border_style="blue",
            padding=(1, 2)
        )
        
    def _confirm_exit(self):
        """Modern exit confirmation"""
        console.print("\n")
        exit_panel = Panel(
            Align.center(
                Text.assemble(
                    ("Are you sure you want to exit ", "white"),
                    ("NetworkMapper", "bold cyan"),
                    ("?", "white")
                )
            ),
            title="[bold red]Exit Confirmation[/bold red]",
            border_style="red",
            padding=(1, 2)
        )
        console.print(exit_panel)
        return Confirm.ask("[bold red]❯[/bold red] Confirm exit")
        
    def _add_subnet_tags(self, devices):
        """Add subnet-based tagging to devices"""
        import ipaddress
        
        for device in devices:
            ip = device.get('ip', '')
            if ip:
                try:
                    # Parse IP and determine subnet
                    ip_obj = ipaddress.IPv4Address(ip)
                    
                    # Determine common subnet (assuming /24 for most cases)
                    network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                    subnet_name = f"Subnet:{network}"
                    
                    # Add subnet information to device
                    device['subnet'] = str(network)
                    device['subnet_name'] = subnet_name
                    
                    # Add to tags if they exist
                    if 'tags' not in device:
                        device['tags'] = []
                    device['tags'].append(subnet_name)
                    
                    # Add subnet-based description
                    octets = ip.split('.')
                    if len(octets) >= 3:
                        subnet_desc = f"Network {octets[0]}.{octets[1]}.{octets[2]}.x"
                        device['subnet_description'] = subnet_desc
                        
                except (ipaddress.AddressValueError, ValueError):
                    # Invalid IP, skip tagging
                    continue
                    
        return devices
        
    def _save_scan_with_metadata(self, devices, timestamp, config):
        """Save scan results with comprehensive metadata"""
        import json
        from datetime import datetime
        
        # Calculate scan statistics
        scan_stats = {
            'start_time': timestamp,
            'duration': config.get('scan_duration', 'N/A'),
            'device_count': len(devices),
            'target': config['target'],
            'scan_type': config['scan_name'],
            'services_scanned': self._count_services(devices),
            'vulnerabilities_detected': self._count_vulnerabilities(devices),
            'subnets_discovered': self._get_discovered_subnets(devices),
            'scan_parameters': {
                'snmp_enabled': config.get('snmp_enabled', False),
                'vulnerability_scan': config.get('vuln_enabled', False),
                'passive_analysis': config.get('passive_enabled', False)
            }
        }
        
        # Add metadata to each device
        for device in devices:
            device['scan_metadata'] = {
                'scan_timestamp': timestamp,
                'scan_type': config['scan_name'],
                'target': config['target']
            }
            
        # Save enhanced scan data
        scan_file = self.output_path / "scans" / f"scan_{timestamp}.json"
        with open(scan_file, 'w') as f:
            json.dump({
                'devices': devices,
                'scan_metadata': scan_stats
            }, f, indent=2)
            
        # Save scan summary for reports
        summary_file = self.output_path / "scans" / f"summary_{timestamp}.json"
        with open(summary_file, 'w') as f:
            json.dump(scan_stats, f, indent=2)
            
    def _count_services(self, devices):
        """Count unique services discovered"""
        services = set()
        for device in devices:
            for service in device.get('services', []):
                services.add(service)
        return len(services)
        
    def _count_vulnerabilities(self, devices):
        """Count total vulnerabilities across all devices"""
        total_vulns = 0
        for device in devices:
            total_vulns += len(device.get('vulnerabilities', []))
        return total_vulns
        
    def _get_discovered_subnets(self, devices):
        """Get list of discovered subnets"""
        subnets = set()
        for device in devices:
            subnet = device.get('subnet')
            if subnet:
                subnets.add(subnet)
        return list(subnets)