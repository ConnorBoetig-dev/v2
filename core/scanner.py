import json
import logging
import os
import re
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
import yaml
from pathlib import Path
import sys
import threading

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

# Configure logging
logger = logging.getLogger(__name__)

# Import SNMP manager if available
try:
    from utils.snmp_manager import SNMPManager
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False
    logger.warning("SNMP support not available - install pysnmp to enable")


class NetworkScanner:
    def __init__(self):
        self.scan_profiles = {
            "discovery": {
                "nmap": ["-sn"],
                "masscan": ["-p0", "--rate=10000"],
                "description": "Host discovery only",
            },
            "inventory": {
                "nmap": ["-sS", "-sV", "-O", "--top-ports", "1000"],
                "description": "Service and OS detection",
            },
            "deep": {
                # Added -PR for ARP discovery to ensure all hosts are found
                "nmap": ["-PR", "-sS", "-sV", "-O", "--top-ports", "5000", "--script", "default"],
                "description": "Deep scan with top 5000 ports + ARP discovery",
            },
        }
        self.console = Console()
        self.config = self._load_config()
        self.last_progress_update = time.time()
        self.hang_detected = False
        self.total_hosts = 0
        self.hosts_completed = 0
        self._scanner_availability = {}  # Cache for scanner availability checks

    def _load_config(self):
        """Load configuration from config.yaml"""
        config_path = Path(__file__).parent.parent / "config.yaml"
        if config_path.exists():
            with open(config_path) as f:
                return yaml.safe_load(f)
        else:
            # Default config if file doesn't exist
            return {
                "scan": {
                    "timeout": 300
                },
                "scanners": {
                    "progress_details": False,
                    "hang_threshold": 30,
                    "nmap_stats_interval": "1s",
                    "progress_refresh_rate": 4,
                    "nmap_timing": "-T4"
                }
            }

    def scan(
        self,
        target: str,
        scan_type: str = "discovery",
        use_masscan: bool = False,
        needs_root: bool = False,
        snmp_config: Dict = None,
    ) -> List[Dict]:
        """Execute network scan with progress feedback"""
        if use_masscan and scan_type == "discovery":
            devices = self._run_masscan(target)
        else:
            devices = self._run_nmap(target, scan_type, needs_root)
            
        # Enrich with SNMP data if requested and available
        if snmp_config and SNMP_AVAILABLE and devices:
            devices = self._enrich_with_snmp(devices, snmp_config)
            
        return devices

    def _check_hang(self, current_time: float, progress_task, progress) -> bool:
        """Check if scan appears to be hung"""
        time_since_update = current_time - self.last_progress_update
        hang_threshold = self.config["scanners"].get("hang_threshold", 30)
        
        if time_since_update > hang_threshold and not self.hang_detected:
            self.hang_detected = True
            if self.config["scanners"].get("progress_details", False):
                self.console.print(f"[yellow]Warning: No progress for {int(time_since_update)}s - scan may be hung[/yellow]")
            progress.update(progress_task, description="[yellow]⚠ Scan may be hung[/yellow]")
            return True
        return False

    def _estimate_total_hosts(self, target: str) -> int:
        """Estimate number of hosts in target range"""
        if "/" in target:
            # CIDR notation
            try:
                prefix = int(target.split("/")[1])
                if prefix == 32:
                    return 1  # Single host
                elif prefix == 31:
                    return 2  # Point-to-point link
                else:
                    return 2 ** (32 - prefix) - 2  # Subtract network and broadcast
            except:
                return 256  # Default to /24
        else:
            return 1  # Single host

    def _ensure_sudo_access(self):
        """Ensure we have sudo access before starting scan"""
        try:
            # First check if we already have sudo cached
            result = subprocess.run(["sudo", "-n", "true"], capture_output=True)
            if result.returncode == 0:
                return True
            
            # We need to authenticate
            self.console.print("\n[yellow]This scan requires administrator privileges.[/yellow]")
            self.console.print("[dim]You may be prompted for your password.[/dim]\n")
            
            # IMPORTANT: Don't capture output so password prompt shows
            result = subprocess.run(["sudo", "-v"])
            
            if result.returncode != 0:
                return False
                
            # Verify it worked
            result = subprocess.run(["sudo", "-n", "true"], capture_output=True)
            return result.returncode == 0
            
        except Exception as e:
            self.console.print(f"[red]Error checking sudo access: {e}[/red]")
            return False

    def _run_nmap(self, target: str, scan_type: str, needs_root: bool) -> List[Dict]:
        """Run nmap scan with real-time progress"""
        profile = self.scan_profiles[scan_type]
        show_details = self.config["scanners"].get("progress_details", False)
        stats_interval = self.config["scanners"].get("nmap_stats_interval", "1s")
        refresh_rate = self.config["scanners"].get("progress_refresh_rate", 4)

        # Check if nmap is available
        try:
            subprocess.run(["which", "nmap"], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            raise Exception("nmap not found. Please install nmap: sudo apt install nmap")

        # For scans that need root, ensure we have sudo access
        if needs_root:
            if not self._ensure_sudo_access():
                raise Exception("Failed to obtain sudo access. Please try again.")

        # Estimate total hosts for better progress tracking
        self.total_hosts = self._estimate_total_hosts(target)
        self.hosts_completed = 0

        # Generate a unique temp filename
        temp_path = self._create_temp_file("nmap", ".xml")

        try:
            # Build command with stats output
            cmd = ["nmap", "-oX", temp_path, "--stats-every", stats_interval]
            
            # Add timing template from config
            timing = self.config["scanners"].get("nmap_timing", "-T4")
            cmd.append(timing)
            
            # DNS resolution is now enabled for all scan types
            if scan_type in ["deep", "inventory"]:
                self.console.print("[dim]Note: DNS resolution enabled for hostname discovery[/dim]")
            
            # Add profile options
            cmd.extend(profile["nmap"])
            
            # Add target
            cmd.append(target)

            if needs_root:
                cmd = ["sudo", "-n"] + cmd  # -n flag means non-interactive
                
            # Always show the command for transparency
            self.console.print(f"[dim]Command: {' '.join(cmd)}[/dim]\n")

            # Add scan type description to progress
            scan_desc = {
                "discovery": "Quick host discovery",
                "inventory": "Service detection (1000 ports)",
                "deep": "Deep scan (5000 ports + scripts)"
            }.get(scan_type, scan_type.capitalize())
            
            # Show initial scan information
            if scan_type == "deep":
                self.console.print(f"[yellow]Deep Scan Information:[/yellow]")
                self.console.print(f"  • Target: {target}")
                self.console.print(f"  • Estimated hosts: {self.total_hosts}")
                self.console.print(f"  • Ports to scan: {'All 65535' if '-p-' in cmd else 'Top 5000'}")
                self.console.print(f"  • Scripts enabled: Yes")
                self.console.print(f"  • ARP discovery: Yes")
                self.console.print(f"  • DNS resolution: Yes")
                self.console.print(f"  • This scan will take time, progress will update as hosts complete\n")

            # Create progress display
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.fields[scan_desc]}[/bold blue]"),
                BarColumn(complete_style="green", finished_style="green"),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                TextColumn("• {task.fields[status]}"),
                console=self.console,
                refresh_per_second=refresh_rate,
                transient=False
            ) as progress:
                
                task = progress.add_task(
                    f"Scanning {target}",
                    total=100,
                    scan_desc=scan_desc,
                    status="Starting nmap..."
                )

                # Progress tracking variables
                start_time = time.time()
                devices_found = 0
                current_host = ""
                last_percent = 0
                self.last_progress_update = start_time
                self.hang_detected = False
                current_phase = "init"
                ports_found = 0
                
                # Start the nmap process with line buffering
                try:
                    self.console.print(f"[dim]Starting process at {datetime.now().strftime('%H:%M:%S')}[/dim]")
                    
                    # Use line buffering for real-time output
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        universal_newlines=True,
                        bufsize=1,  # Line buffered
                        env={**os.environ, 'PYTHONUNBUFFERED': '1'}  # Force unbuffered
                    )
                    
                    # Check if process started
                    time.sleep(0.5)
                    if proc.poll() is not None:
                        stderr_output = proc.stderr.read()
                        if "sudo:" in stderr_output:
                            raise Exception("Sudo authentication failed. Please run the scan again.")
                        else:
                            raise Exception(f"Nmap failed to start: {stderr_output}")
                    
                except Exception as e:
                    raise Exception(f"Failed to start nmap: {e}")

                # Track scan phases for better progress
                discovery_complete = False
                hosts_discovered = 0
                lines_processed = 0
                output_started = False
                
                # Create a thread to monitor stderr
                def monitor_stderr():
                    try:
                        for line in proc.stderr:
                            if line.strip():
                                self.console.print(f"[red]Nmap error: {line.strip()}[/red]")
                    except:
                        pass
                
                stderr_thread = threading.Thread(target=monitor_stderr, daemon=True)
                stderr_thread.start()
                
                # Process output line by line
                while True:
                    line = proc.stdout.readline()
                    
                    # Check if process has ended
                    if not line:
                        if proc.poll() is not None:
                            break
                        # No line but process still running
                        time.sleep(0.1)
                        
                        # Check for timeout on first output
                        if not output_started and (time.time() - start_time) > 10:
                            progress.update(task, status=f"Waiting for nmap output... ({int(time.time() - start_time)}s)")
                            
                            # Provide troubleshooting after 30 seconds
                            if (time.time() - start_time) > 30:
                                self._show_scan_troubleshooting()
                                output_started = True  # Prevent repeating message
                        continue
                    
                    line = line.strip()
                    if not line:
                        continue
                        
                    current_time = time.time()
                    lines_processed += 1
                    
                    # Mark that we've received output
                    if not output_started:
                        output_started = True
                        progress.update(task, status="Nmap is running...")
                    
                    # Detailed output if enabled
                    if show_details:
                        self.console.print(f"[dim]{line}[/dim]")
                    
                    # Parse various nmap output patterns
                    
                    # Host discovery completion
                    if "Nmap done:" in line and "IP address" in line:
                        discovery_complete = True
                        match = re.search(r'(\d+)\s+IP\s+address(?:es)?\s+\((\d+)\s+host(?:s)?\s+up\)', line)
                        if match:
                            total_scanned = int(match.group(1))
                            hosts_discovered = int(match.group(2))
                            if hosts_discovered == 0:
                                progress.update(task, completed=100, status="No hosts found")
                                break
                            else:
                                progress.update(task, completed=10, status=f"Discovery complete: {hosts_discovered} hosts up • Starting detailed scan...")
                                self.last_progress_update = current_time
                    
                    # Progress stats
                    elif "Stats:" in line and "done" in line:
                        match = re.search(r'(\d+\.\d+)%.*done', line)
                        if match:
                            percent = float(match.group(1))
                            if percent > last_percent:
                                last_percent = percent
                                self.last_progress_update = current_time
                                self.hang_detected = False
                            
                            # Extract timing info
                            time_match = re.search(r'(\d+:\d+:\d+)\s+remaining', line)
                            time_remaining = time_match.group(1) if time_match else ""
                            
                            # Adjust percentage if past discovery
                            if discovery_complete and percent < 10:
                                percent = 10 + (percent * 0.9)
                            
                            status_msg = f"Progress: {percent:.1f}%"
                            if time_remaining:
                                status_msg += f" • ETA: {time_remaining}"
                            if devices_found > 0:
                                status_msg += f" • {devices_found} hosts"
                            
                            progress.update(task, completed=percent, status=status_msg)
                    
                    # Starting Nmap
                    elif "Starting Nmap" in line:
                        current_phase = "discovery"
                        progress.update(task, status="Nmap started • Beginning scan...")
                        self.last_progress_update = current_time
                    
                    # Scan phase detection
                    elif "Initiating" in line:
                        if "Ping Scan" in line:
                            current_phase = "discovery"
                            progress.update(task, status="Phase: Host discovery")
                        elif "ARP Ping Scan" in line:
                            current_phase = "arp"
                            progress.update(task, status="Phase: ARP discovery")
                        elif "SYN Stealth Scan" in line:
                            current_phase = "portscan"
                            progress.update(task, status="Phase: Port scanning")
                        elif "Service scan" in line:
                            current_phase = "service"
                            progress.update(task, status="Phase: Service detection")
                        elif "OS detection" in line:
                            current_phase = "os"
                            progress.update(task, status="Phase: OS detection")
                        elif "NSE" in line:
                            current_phase = "scripts"
                            progress.update(task, status="Phase: Running scripts")
                        self.last_progress_update = current_time
                    
                    # Host discovery
                    elif "Host is up" in line:
                        if not discovery_complete:
                            hosts_discovered += 1
                            if self.total_hosts > 0:
                                discovery_progress = min((hosts_discovered / self.total_hosts) * 10, 10)
                                progress.update(
                                    task,
                                    completed=discovery_progress,
                                    status=f"Discovering hosts: {hosts_discovered} found..."
                                )
                        self.last_progress_update = current_time
                    
                    # Currently scanning host
                    elif "Scanning" in line:
                        match = re.search(r'Scanning\s+([^\s\[]+)', line)
                        if match:
                            current_host = match.group(1)
                            self.hosts_completed += 1
                            
                            status_msg = f"Scanning {current_host}"
                            if current_phase == "portscan":
                                status_msg += " • Checking ports"
                            elif current_phase == "service":
                                status_msg += " • Identifying services"
                            
                            progress.update(task, status=status_msg)
                            self.last_progress_update = current_time
                    
                    # Port discovered
                    elif "Discovered open port" in line:
                        match = re.search(r'port\s+(\d+)/(\w+)\s+on\s+(.+)', line)
                        if match:
                            ports_found += 1
                            port_info = f"{match.group(1)}/{match.group(2)}"
                            host = match.group(3)
                            progress.update(task, status=f"Found port {port_info} on {host}")
                            self.last_progress_update = current_time
                    
                    # Host report
                    elif "Nmap scan report for" in line:
                        devices_found += 1
                        elapsed = time.time() - start_time
                        
                        # Update progress
                        if not discovery_complete or last_percent < 10:
                            estimated_progress = min(10 + (devices_found / max(hosts_discovered, 1)) * 80, 90)
                            progress.update(task, completed=estimated_progress)
                        
                        if scan_type == "deep":
                            status_msg = f"Completed: {devices_found} hosts • {ports_found} ports • {elapsed:.0f}s"
                        else:
                            status_msg = f"Found {devices_found} devices • {elapsed:.0f}s"
                        
                        progress.update(task, status=status_msg)
                        self.last_progress_update = current_time
                    
                    # Final summary
                    elif "hosts up" in line:
                        match = re.search(r'(\d+)\s+host[s]?\s+up', line)
                        if match:
                            total_up = match.group(1)
                            progress.update(
                                task,
                                completed=100,
                                status=f"Complete: {total_up} hosts up • {ports_found} open ports"
                            )
                    
                    # Update every 10 lines to show activity
                    elif lines_processed % 10 == 0:
                        progress.update(task, status=f"Processing... ({lines_processed} lines)")

                # Wait for process to complete
                proc.wait()

                if proc.returncode != 0:
                    stderr_output = proc.stderr.read()
                    error_msg = f"Nmap failed with return code {proc.returncode}"
                    if stderr_output:
                        error_msg += f": {stderr_output}"
                    raise Exception(error_msg)

            # Parse XML output
            if os.path.exists(temp_path):
                try:
                    return self._parse_nmap_xml(temp_path)
                except Exception as e:
                    self.console.print(f"[red]Error parsing scan results: {e}[/red]")
                    raise
            else:
                raise Exception("Scan output file not found")
            
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Scan interrupted by user[/yellow]")
            raise
        except Exception as e:
            self.console.print(f"\n[red]Scan error: {e}[/red]")
            raise
        finally:
            # Clean up temp file
            self._cleanup_temp_file(temp_path, needs_sudo=needs_root)

    def _run_masscan(self, target: str) -> List[Dict]:
        """Run masscan for fast host discovery.
        
        Args:
            target: Network target
            
        Returns:
            List of discovered devices
            
        Raises:
            RuntimeError: If masscan is not available or fails
        """
        # Check availability
        if not self._check_scanner_available("masscan"):
            raise RuntimeError(
                "masscan not found. Please install masscan:\n"
                "  Ubuntu/Debian: sudo apt install masscan\n"
                "  macOS: brew install masscan\n"
                "  From source: https://github.com/robertdavidgraham/masscan"
            )
        
        show_details = self.config["scanners"].get("progress_details", False)
        refresh_rate = self.config["scanners"].get("progress_refresh_rate", 4)
        scan_rate = self.config["scanners"].get("masscan_rate", 10000)
        
        # Ensure sudo access for masscan
        if not self._ensure_sudo_access():
            raise RuntimeError("Masscan requires sudo access")
        
        # Generate a unique temp filename
        temp_file = self._create_temp_file("masscan", ".json")

        try:
            cmd = [
                "sudo", "-n",
                "masscan",
                "-p0",  # Ping scan
                f"--rate={scan_rate}",  # Configurable rate
                "-oJ", temp_file,  # JSON output
                "--wait", "3",  # Wait 3 seconds for responses
                target,
            ]

            # Create progress display for masscan
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]Masscan discovery[/bold cyan]"),
                BarColumn(complete_style="cyan", finished_style="cyan"),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                TextColumn("• {task.fields[status]}"),
                console=self.console,
                refresh_per_second=refresh_rate,
                transient=False
            ) as progress:
                
                task = progress.add_task(
                    f"Fast scanning {target}",
                    total=100,
                    status="Initializing masscan..."
                )

                start_time = time.time()
                devices_found = 0
                last_percent = 0
                self.last_progress_update = start_time
                self.hang_detected = False
                
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    bufsize=1
                )

                for line in proc.stdout:
                    line = line.strip()
                    current_time = time.time()
                    
                    if show_details and line:
                        self.console.print(f"[dim]{line}[/dim]")
                    
                    # Parse masscan output
                    if "rate:" in line.lower():
                        # Extract scan rate
                        match = re.search(r'rate:\s*([\d.]+)', line, re.IGNORECASE)
                        if match:
                            rate = match.group(1)
                            progress.update(task, status=f"Scanning at {rate} pkts/s")
                    
                    elif "found=" in line:
                        # Extract progress percentage
                        match = re.search(r'(\d+\.\d+)%', line)
                        if match:
                            percent = float(match.group(1))
                            if percent > last_percent:
                                last_percent = percent
                                self.last_progress_update = current_time
                                self.hang_detected = False
                            progress.update(task, completed=percent)
                        
                        # Extract found count
                        match = re.search(r'found=(\d+)', line)
                        if match:
                            devices_found = int(match.group(1))
                            elapsed = time.time() - start_time
                            progress.update(
                                task,
                                status=f"Found {devices_found} hosts • {elapsed:.0f}s"
                            )
                            if show_details:
                                self.console.print(f"[green]→ Total found: {devices_found}[/green]")
                    
                    elif "waiting" in line.lower() and "seconds" in line.lower():
                        # Waiting phase
                        progress.update(task, status="Waiting for final packets...")
                    
                    # Check for hang
                    self._check_hang(current_time, task, progress)

                proc.wait()
                
                # Set to 100% when done
                progress.update(
                    task,
                    completed=100,
                    status=f"Complete: {devices_found} hosts found"
                )

                if proc.returncode != 0:
                    raise Exception(f"Masscan failed with return code {proc.returncode}")

            # Parse JSON output
            return self._parse_masscan_output(temp_file)
            
        finally:
            # Clean up temp file
            self._cleanup_temp_file(temp_file, needs_sudo=True)

    def _run_arp_scan(self, target: str) -> List[Dict]:
        """Run arp-scan for layer 2 discovery.
        
        Args:
            target: Network target
            
        Returns:
            List of discovered devices
            
        Raises:
            RuntimeError: If arp-scan is not available or fails
        """
        # Check availability
        if not self._check_scanner_available("arp-scan"):
            raise RuntimeError(
                "arp-scan not found. Please install arp-scan:\n"
                "  Ubuntu/Debian: sudo apt install arp-scan\n"
                "  macOS: brew install arp-scan"
            )
        
        show_details = self.config["scanners"].get("progress_details", False)
        refresh_rate = self.config["scanners"].get("progress_refresh_rate", 4)
        
        # Ensure sudo access for arp-scan
        if not self._ensure_sudo_access():
            raise RuntimeError("ARP scan requires sudo access")
        
        try:
            # Build command
            cmd = self._build_arp_scan_command(target)

            # Create progress display
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold green]ARP scan[/bold green]"),
                BarColumn(complete_style="green", finished_style="green", pulse_style="green"),
                TimeElapsedColumn(),
                TextColumn("• {task.fields[status]}"),
                console=self.console,
                refresh_per_second=refresh_rate,
                transient=False
            ) as progress:
                
                task = progress.add_task(
                    f"Layer 2 scanning",
                    total=None,  # Indeterminate
                    status="Sending ARP requests..."
                )

                devices = []
                start_time = time.time()
                
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )

                for line in proc.stdout:
                    line = line.strip()
                    
                    if show_details and line:
                        self.console.print(f"[dim]{line}[/dim]")
                    
                    # Parse arp-scan output format: IP MAC Vendor
                    match = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]+)\s+(.*)$', line)
                    if match:
                        ip, mac, vendor = match.groups()
                        devices.append({
                            "ip": ip,
                            "mac": mac.upper(),
                            "vendor": vendor,
                            "hostname": "",
                            "type": "unknown",
                            "os": "",
                            "services": [],
                            "open_ports": []
                        })
                        
                        elapsed = time.time() - start_time
                        progress.update(
                            task,
                            status=f"Found {len(devices)} devices • {elapsed:.0f}s • Latest: {ip}"
                        )
                        
                        if show_details:
                            self.console.print(f"[green]→ Found: {ip} ({mac}) - {vendor}[/green]")

                proc.wait()
                
                progress.update(
                    task,
                    status=f"Complete: {len(devices)} devices found"
                )

                return devices

        except subprocess.CalledProcessError as e:
            logger.error(f"ARP scan failed: {e}")
            raise RuntimeError(f"ARP scan failed: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error in ARP scan: {e}")
            raise RuntimeError(f"ARP scan error: {e}") from e

    def _check_scanner_available(self, scanner: str) -> bool:
        """Check if a scanner is available on the system.
        
        Args:
            scanner: Scanner name (nmap, masscan, arp-scan)
            
        Returns:
            True if scanner is available
        """
        if scanner in self._scanner_availability:
            return self._scanner_availability[scanner]
            
        try:
            result = subprocess.run(
                ["which", scanner], 
                capture_output=True, 
                timeout=5
            )
            available = result.returncode == 0
            self._scanner_availability[scanner] = available
            return available
        except Exception:
            self._scanner_availability[scanner] = False
            return False
    
    def _show_scan_troubleshooting(self) -> None:
        """Display troubleshooting information for slow scans."""
        self.console.print("\n[yellow]Scan is taking unusually long to start.[/yellow]")
        self.console.print("[yellow]This might be due to:[/yellow]")
        self.console.print("  • Large network range")
        self.console.print("  • Firewall blocking scans")
        self.console.print("  • Slow network response")
        self.console.print("  • DNS resolution delays")
        self.console.print("\n[dim]You can press Ctrl+C to cancel[/dim]\n")

    def _parse_nmap_xml(self, xml_file: str) -> List[Dict]:
        """Parse nmap XML output into standardized format.
        
        Args:
            xml_file: Path to nmap XML output file
            
        Returns:
            List of device dictionaries
            
        Raises:
            ET.ParseError: Invalid XML format
        """
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(f"Failed to parse nmap XML: {e}")
            raise

        devices = []
        for host in root.findall(".//host"):
            # Skip hosts that are down
            if host.find('.//status[@state="up"]') is None:
                continue

            device = self._extract_host_info(host)
            if device.get("ip"):  # Only add if we have an IP
                devices.append(device)
                logger.debug(f"Parsed device: {device['ip']}")

        logger.info(f"Parsed {len(devices)} devices from nmap XML")
        return devices
    
    def _extract_host_info(self, host_elem: ET.Element) -> Dict[str, Any]:
        """Extract device information from nmap host element.
        
        Args:
            host_elem: XML element containing host data
            
        Returns:
            Device information dictionary
        """
        device = {
            "ip": "",
            "mac": "",
            "hostname": "",
            "open_ports": [],
            "services": [],
            "os": "",
            "vendor": "",
            "scan_time": datetime.now().isoformat(),
        }

        # IP address
        ipv4 = host_elem.find('.//address[@addrtype="ipv4"]')
        if ipv4 is not None:
            device["ip"] = ipv4.get("addr", "")

        # MAC address
        mac_elem = host_elem.find('.//address[@addrtype="mac"]')
        if mac_elem is not None:
            device["mac"] = mac_elem.get("addr", "").upper()
            device["vendor"] = mac_elem.get("vendor", "")

        # Hostname
        hostname_elem = host_elem.find(".//hostname")
        if hostname_elem is not None:
            device["hostname"] = hostname_elem.get("name", "")

        # Ports and services
        for port in host_elem.findall(".//port"):
            if port.find('.//state[@state="open"]') is not None:
                port_id = int(port.get("portid", 0))
                if port_id:
                    device["open_ports"].append(port_id)

                    service = port.find(".//service")
                    if service is not None:
                        service_name = service.get("name", "unknown")
                        service_product = service.get("product", "")
                        service_version = service.get("version", "")
                        
                        service_info = f"{service_name}:{port_id}"
                        if service_product:
                            service_info += f" ({service_product}"
                            if service_version:
                                service_info += f" {service_version}"
                            service_info += ")"
                        
                        device["services"].append(service_info)

        # OS detection with confidence
        os_matches = host_elem.findall(".//osmatch")
        if os_matches:
            # Take the highest accuracy match
            best_match = max(os_matches, key=lambda x: int(x.get("accuracy", 0)))
            device["os"] = best_match.get("name", "")
            device["os_accuracy"] = int(best_match.get("accuracy", 0))

        return device
    
    def _create_temp_file(self, prefix: str, suffix: str) -> str:
        """Create a unique temporary file.
        
        Args:
            prefix: File prefix (e.g., 'nmap', 'masscan')
            suffix: File suffix (e.g., '.xml', '.json')
            
        Returns:
            Path to temporary file
        """
        temp_dir = tempfile.gettempdir()
        unique_id = f"{os.getpid()}_{os.urandom(4).hex()}"
        filename = f"{prefix}_{unique_id}{suffix}"
        return os.path.join(temp_dir, filename)
    
    def _cleanup_temp_file(self, filepath: str, needs_sudo: bool = False) -> None:
        """Safely clean up temporary file.
        
        Args:
            filepath: Path to file to remove
            needs_sudo: Whether sudo is needed to remove the file
        """
        if not os.path.exists(filepath):
            return
            
        try:
            if needs_sudo and os.stat(filepath).st_uid == 0:
                subprocess.run(["sudo", "rm", filepath], capture_output=True, timeout=5)
            else:
                os.remove(filepath)
        except Exception as e:
            logger.warning(f"Failed to remove temp file {filepath}: {e}")
    
    def _parse_masscan_output(self, json_file: str) -> List[Dict]:
        """Parse masscan JSON output.
        
        Args:
            json_file: Path to masscan JSON output
            
        Returns:
            List of device dictionaries
        """
        if not os.path.exists(json_file):
            logger.warning(f"Masscan output file not found: {json_file}")
            return []
            
        devices = {}
        try:
            with open(json_file) as f:
                data = f.read()
                if not data.strip():
                    return []
                    
                # Masscan outputs one JSON object per line
                for line in data.strip().split("\n"):
                    line = line.strip()
                    if not line or line in ["{}", "{ }", "[", "]"]:
                        continue
                        
                    try:
                        # Remove trailing comma if present
                        if line.endswith(","):
                            line = line[:-1]
                            
                        entry = json.loads(line)
                        if "ip" in entry:
                            ip = entry["ip"]
                            if ip not in devices:
                                devices[ip] = {
                                    "ip": ip,
                                    "mac": "",
                                    "hostname": "",
                                    "vendor": "",
                                    "type": "unknown",
                                    "os": "",
                                    "services": [],
                                    "open_ports": [],
                                    "scan_time": datetime.now().isoformat(),
                                }
                            
                            # Add port information if available
                            if "ports" in entry:
                                for port_info in entry["ports"]:
                                    port = port_info.get("port", 0)
                                    if port and port not in devices[ip]["open_ports"]:
                                        devices[ip]["open_ports"].append(port)
                                        devices[ip]["services"].append(f"unknown:{port}")
                                        
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse masscan line: {line} - {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"Failed to parse masscan output: {e}")
            
        return list(devices.values())
    
    def _build_arp_scan_command(self, target: str) -> List[str]:
        """Build arp-scan command with appropriate options.
        
        Args:
            target: Network target
            
        Returns:
            Command list for subprocess
        """
        cmd = ["sudo", "-n", "arp-scan"]
        
        # Determine scan scope
        if target == "localnet" or not target:
            cmd.extend(["--localnet"])
        elif "/" in target:
            # CIDR notation
            cmd.append(target)
        else:
            # Single host
            cmd.append(target)
            
        # Add common options
        cmd.extend([
            "--retry=2",  # Retry twice for reliability
            "--timeout=500",  # 500ms timeout
            "--backoff=1.5",  # Backoff multiplier
        ])
        
        return cmd
    
    def _enrich_with_snmp(self, devices: List[Dict], snmp_config: Dict) -> List[Dict]:
        """Enrich devices with SNMP data
        
        Args:
            devices: List of discovered devices
            snmp_config: SNMP configuration dictionary
            
        Returns:
            List of enriched devices
        """
        if not SNMP_AVAILABLE:
            logger.warning("SNMP enrichment requested but pysnmp not available")
            return devices
            
        # Filter devices that might respond to SNMP
        snmp_candidates = [
            device for device in devices 
            if device.get('type') in ['router', 'switch', 'server', 'printer', 'nas', 'firewall']
            or any(port in device.get('open_ports', []) for port in [161, 80, 443, 22])
        ]
        
        if not snmp_candidates:
            logger.info("No SNMP candidates found in scan results")
            return devices
            
        version = snmp_config.get('version', 'v2c')
        self.console.print(f"\n[cyan]Enriching {len(snmp_candidates)} devices with SNMP {version}...[/cyan]")
        
        # Create SNMP manager
        snmp_manager = SNMPManager(config=snmp_config)
        
        # Progress tracking for SNMP enrichment
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]SNMP enrichment[/bold cyan]"),
            BarColumn(complete_style="cyan", finished_style="cyan"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("• {task.fields[status]}"),
            console=self.console,
            transient=False
        ) as progress:
            
            task = progress.add_task(
                "Enriching devices",
                total=len(snmp_candidates),
                status="Starting SNMP queries..."
            )
            
            enriched_count = 0
            failed_count = 0
            
            # Process devices with limited concurrency
            try:
                enriched_devices = snmp_manager.enrich_devices(snmp_candidates, max_workers=5)
                
                # Update progress and count successes
                for i, (original, enriched) in enumerate(zip(snmp_candidates, enriched_devices)):
                    if 'snmp_data' in enriched:
                        enriched_count += 1
                    else:
                        failed_count += 1
                        
                    progress.update(
                        task,
                        completed=i + 1,
                        status=f"Enriched: {enriched_count}, Failed: {failed_count}"
                    )
                
                # Replace original devices with enriched versions
                device_map = {device['ip']: device for device in enriched_devices}
                for i, device in enumerate(devices):
                    if device['ip'] in device_map:
                        devices[i] = device_map[device['ip']]
                        
                progress.update(
                    task,
                    completed=len(snmp_candidates),
                    status=f"Complete: {enriched_count} enriched, {failed_count} failed"
                )
                
            except Exception as e:
                logger.error(f"SNMP enrichment error: {e}")
                progress.update(task, status=f"Error: {e}")
                
        if enriched_count > 0:
            self.console.print(f"[green]✓ Successfully enriched {enriched_count} devices with SNMP data[/green]")
        if failed_count > 0:
            self.console.print(f"[yellow]⚠ Failed to enrich {failed_count} devices (SNMP not responding)[/yellow]")
            
        return devices