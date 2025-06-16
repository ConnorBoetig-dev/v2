import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
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

# Import friendly error handling
try:
    from utils.friendly_errors import FriendlyError, handle_scanner_error, handle_network_error
except ImportError:
    # Fallback if module not available
    FriendlyError = RuntimeError
    handle_scanner_error = lambda name, err: RuntimeError(str(err))
    handle_network_error = lambda err, target="": RuntimeError(str(err))


class NetworkScanner:
    def __init__(self):
        self.scan_profiles = {
            "discovery": {
                "nmap": [
                    "-sn",
                    "-PE",
                    "-PP",
                    "-PM",
                    "-PS80,443,22,445",
                    "-PA80,443,22,445",
                    "-PU53,161,123",
                ],
                "masscan": ["-p80,443,22,445,3389,8080,21,23,25,53,135,139,161"],
                "description": "Multi-technique host discovery",
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
            "fast": {
                # Optimized for large networks - uses masscan for discovery and limited enrichment
                "masscan": ["-p21,22,23,25,53,80,110,111,135,139,143,161,443,445,465,587,631,993,995,1433,1521,1723,3306,3389,5432,5900,8080,8443,9100,27017,U:53,U:67,U:68,U:69,U:123,U:161,U:500,U:514,U:520,U:1900"],
                "nmap": [
                    "-sS",
                    "-sV",
                    "-O",
                    "--osscan-guess",
                    "--version-intensity",
                    "0",
                    "--top-ports",
                    "100",
                    "-T5",
                ],
                "description": "Fast scan for large networks (65k+ hosts)",
            },
            "deeper": {
                # More thorough scan - uses masscan for discovery and comprehensive nmap enrichment
                "masscan": ["-p21-23,25,53,67,69,80-81,88,110-111,123,135,137-139,143,161,389,443,445,465,514,515,548,554,587,593,631,636,873,902,993,995,1025-1029,1080,1194,1337,1433-1434,1521,1604,1645,1701,1723,1755,1812-1813,1883,1900,2049,2082-2083,2086-2087,2095-2096,2121,2181,2222,2375,2376,2404,3000,3128,3260,3268-3269,3283,3306,3333,3389-3390,3478,3689,3690,3784,4000,4040,4045,4443,4444,4567,4662,4848,4899,5000-5010,5060-5061,5093,5351,5353,5355,5432,5500,5555,5632,5800,5900-5910,5984-5986,6000-6009,6379,6514,6660-6669,6881,6969,7000-7002,7070,7077,7100,7144,7145,7262,7272,7474,7777,7778,8000-8014,8016,8018,8020-8022,8025,8028,8030-8032,8036,8038,8040-8082,8084-8100,8180-8181,8192,8222,8243,8280,8281,8333,8337,8388,8400,8443-8445,8500,8530-8531,8765,8766,8787,8800,8808,8843,8880,8883,8888,8899,8983,9000-9003,9009,9043,9050,9080-9081,9090-9091,9100,9110,9200,9290,9300,9418,9443,9500,9502,9503,9535,9800,9981,9998-10001,10022-10025,10050,10080,10082,10180,10215,10243,10443,10616-10626,11110-11111,11211,12345,13579,13720-13722,14000,15000,16080,16992-16993,17988,18080,18264,19226,19350,19780,19999-20000,20031,20222,22222,23023,25565,27015,27017-27019,27374,28017,30000,30718,31337,32768,32769,32771,32815,33899,34571-34573,35500,37777,40000,41080,44818,47808,49152-49156,50000,50050,50070,50100,51106,55020,55055,55555,55600,58080,60008,60020,62078,64738,U:53,U:67-69,U:111,U:123,U:135,U:137-138,U:161,U:177,U:445,U:500,U:514,U:520,U:631,U:1434,U:1604,U:1701,U:1900,U:2049,U:4500,U:5060,U:5353,U:5632,U:9200,U:10000,U:17185,U:31337,U:44818,U:47808,U:49152-49154"],
                "nmap": [
                    "-sS",
                    "-sV",
                    "-O",
                    "--osscan-guess",
                    "--version-intensity",
                    "5",  # Medium intensity (0-9 scale, default is 7)
                    "--top-ports",
                    "500",  # Scan top 500 ports instead of 100
                    "-T3",  # Normal timing (less aggressive than T5)
                    "--script-timeout",
                    "10s",  # Add script timeout for reliability
                ],
                "description": "Deeper scan for more accurate OS/service detection",
            },
            "os_detect": {
                # Dedicated OS detection scan
                "nmap": ["-O", "--osscan-guess", "--osscan-limit", "-T4", "-n"],
                "description": "OS detection only (for enriching existing results)",
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
                "scan": {"timeout": 300},
                "scanners": {
                    "progress_details": False,
                    "hang_threshold": 30,
                    "nmap_stats_interval": "1s",
                    "progress_refresh_rate": 4,
                    "nmap_timing": "-T4",
                },
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
        # Fast scan for large networks
        if scan_type == "fast":
            self.console.print("[cyan]⚡ Fast scan mode for large networks[/cyan]")
            # Always use masscan for discovery in fast mode
            devices = self._run_masscan_fast(target)
            if devices:
                # Light enrichment with nmap on discovered hosts only
                self.console.print(f"[cyan]📊 Enriching {len(devices)} discovered hosts...[/cyan]")
                self.console.print(
                    "[cyan]🔍 This includes: OS detection, hostname resolution, and service detection[/cyan]"
                )
                devices = self._enrich_fast_scan(devices)
            return devices

        # Deeper scan for more accurate results
        if scan_type == "deeper":
            self.console.print("[cyan]🔬 Deeper scan mode for comprehensive analysis[/cyan]")
            # Use masscan for discovery with more ports
            devices = self._run_masscan_deeper(target)
            if devices:
                # Thorough enrichment with nmap on discovered hosts
                self.console.print(f"[cyan]📊 Performing deep enrichment on {len(devices)} discovered hosts...[/cyan]")
                self.console.print(
                    "[cyan]🔍 This includes: Comprehensive OS detection, detailed service versions, and extended port scanning[/cyan]"
                )
                devices = self._enrich_deeper_scan(devices)
            return devices

        # For discovery scans, use hybrid approach for better coverage
        if scan_type == "discovery":
            if use_masscan:
                # Masscan for fast discovery with ICMP + TCP
                devices = self._run_masscan(target)
            else:
                # Check if target is local subnet for ARP scan optimization
                if self._is_local_subnet(target):
                    self.console.print(
                        "[cyan]🔍 Local subnet detected - using ARP + ICMP discovery[/cyan]"
                    )
                    # Run both ARP and regular discovery for maximum coverage
                    arp_devices = []
                    if self._check_scanner_available("arp-scan"):
                        try:
                            arp_devices = self._run_arp_scan(target)
                            self.console.print(
                                f"[green]✓ ARP scan found {len(arp_devices)} devices[/green]"
                            )
                        except Exception as e:
                            self.console.print(f"[yellow]⚠ ARP scan failed: {e}[/yellow]")

                    # Also run nmap for devices that don't respond to ARP
                    nmap_devices = self._run_nmap(target, scan_type, needs_root)

                    # Merge results, avoiding duplicates
                    devices = self._merge_scan_results(arp_devices, nmap_devices)
                else:
                    # Remote subnet - use nmap with multiple discovery techniques
                    devices = self._run_nmap(target, scan_type, needs_root)
        else:
            # Non-discovery scans use nmap
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
                self.console.print(
                    f"[yellow]Warning: No progress for {int(time_since_update)}s - scan may be hung[/yellow]"
                )
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

            # DNS resolution optimization
            if scan_type == "discovery":
                # For discovery, skip DNS to speed up
                cmd.append("-n")
                self.console.print("[dim]Note: DNS resolution disabled for faster discovery[/dim]")
            else:
                # For detailed scans, enable DNS
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
                "deep": "Deep scan (5000 ports + scripts)",
            }.get(scan_type, scan_type.capitalize())

            # Show initial scan information
            if scan_type == "deep":
                self.console.print(f"[yellow]Deep Scan Information:[/yellow]")
                self.console.print(f"  • Target: {target}")
                self.console.print(f"  • Estimated hosts: {self.total_hosts}")
                self.console.print(
                    f"  • Ports to scan: {'All 65535' if '-p-' in cmd else 'Top 5000'}"
                )
                self.console.print(f"  • Scripts enabled: Yes")
                self.console.print(f"  • ARP discovery: Yes")
                self.console.print(f"  • DNS resolution: Yes")
                self.console.print(
                    f"  • This scan will take time, progress will update as hosts complete\n"
                )

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
                transient=False,
            ) as progress:
                task = progress.add_task(
                    f"Scanning {target}", total=100, scan_desc=scan_desc, status="Starting nmap..."
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
                    self.console.print(
                        f"[dim]Starting process at {datetime.now().strftime('%H:%M:%S')}[/dim]"
                    )

                    # Use line buffering for real-time output
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        universal_newlines=True,
                        bufsize=1,  # Line buffered
                        env={**os.environ, "PYTHONUNBUFFERED": "1"},  # Force unbuffered
                    )

                    # Check if process started
                    time.sleep(0.5)
                    if proc.poll() is not None:
                        stderr_output = proc.stderr.read()
                        if "sudo:" in stderr_output:
                            raise Exception(
                                "Sudo authentication failed. Please run the scan again."
                            )
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
                            progress.update(
                                task,
                                status=f"Waiting for nmap output... ({int(time.time() - start_time)}s)",
                            )

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
                        match = re.search(
                            r"(\d+)\s+IP\s+address(?:es)?\s+\((\d+)\s+host(?:s)?\s+up\)", line
                        )
                        if match:
                            total_scanned = int(match.group(1))
                            hosts_discovered = int(match.group(2))
                            if hosts_discovered == 0:
                                progress.update(task, completed=100, status="No hosts found")
                                break
                            else:
                                progress.update(
                                    task,
                                    completed=10,
                                    status=f"Discovery complete: {hosts_discovered} hosts up • Starting detailed scan...",
                                )
                                self.last_progress_update = current_time

                    # Progress stats
                    elif "Stats:" in line and "done" in line:
                        match = re.search(r"(\d+\.\d+)%.*done", line)
                        if match:
                            percent = float(match.group(1))
                            if percent > last_percent:
                                last_percent = percent
                                self.last_progress_update = current_time
                                self.hang_detected = False

                            # Extract timing info
                            time_match = re.search(r"(\d+:\d+:\d+)\s+remaining", line)
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
                                discovery_progress = min(
                                    (hosts_discovered / self.total_hosts) * 10, 10
                                )
                                progress.update(
                                    task,
                                    completed=discovery_progress,
                                    status=f"Discovering hosts: {hosts_discovered} found...",
                                )
                        self.last_progress_update = current_time

                    # Currently scanning host
                    elif "Scanning" in line:
                        match = re.search(r"Scanning\s+([^\s\[]+)", line)
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
                        match = re.search(r"port\s+(\d+)/(\w+)\s+on\s+(.+)", line)
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
                            estimated_progress = min(
                                10 + (devices_found / max(hosts_discovered, 1)) * 80, 90
                            )
                            progress.update(task, completed=estimated_progress)

                        if scan_type == "deep":
                            status_msg = f"Completed: {devices_found} hosts • {ports_found} ports • {elapsed:.0f}s"
                        else:
                            status_msg = f"Found {devices_found} devices • {elapsed:.0f}s"

                        progress.update(task, status=status_msg)
                        self.last_progress_update = current_time

                    # Final summary
                    elif "hosts up" in line:
                        match = re.search(r"(\d+)\s+host[s]?\s+up", line)
                        if match:
                            total_up = match.group(1)
                            progress.update(
                                task,
                                completed=100,
                                status=f"Complete: {total_up} hosts up • {ports_found} open ports",
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

        # Calculate number of hosts in target for optimization
        total_hosts = self._estimate_total_hosts(target)
        large_network_threshold = self.config["scanners"].get("large_network_threshold", 10000)

        # Use appropriate scan rate based on network size
        if total_hosts > 50000:
            # Very large network - use moderate rate to avoid initialization issues
            scan_rate = 30000
            self.console.print(
                f"[cyan]⚡ Very large network detected ({total_hosts:,} hosts)[/cyan]"
            )
            self.console.print(f"[cyan]📊 Using moderate scan rate for stability[/cyan]")
        elif total_hosts > large_network_threshold:
            scan_rate = self.config["scanners"].get("masscan_rate_large", 40000)
            self.console.print(
                f"[cyan]⚡ Large network detected ({total_hosts:,} hosts) - using optimized settings[/cyan]"
            )
        else:
            scan_rate = self.config["scanners"].get("masscan_rate", 25000)

        # Check if we need to ensure sudo access
        # (might already be handled by the interface)
        try:
            # Quick check if sudo is already available
            result = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=1)
            if result.returncode != 0:
                # Only prompt if we don't have sudo access yet
                if not self._ensure_sudo_access():
                    raise RuntimeError("Masscan requires sudo access")
        except subprocess.TimeoutExpired:
            # If timeout, assume we need to authenticate
            if not self._ensure_sudo_access():
                raise RuntimeError("Masscan requires sudo access")

        # Generate a unique temp filename
        temp_file = self._create_temp_file("masscan", ".json")

        try:
            # Build masscan command with optimizations
            # For large networks, use fewer ports to speed up initialization
            if total_hosts > large_network_threshold:
                # Minimal port set for large network discovery
                port_list = "80,443,22,445,3389"
                wait_time = "2"
            else:
                # Standard port list for smaller networks
                port_list = "80,443,22,445,135,139,8080,3389,21,23,25,53,161"
                wait_time = "3"

            cmd = [
                "sudo",
                "-n",
                "masscan",
                f"-p{port_list}",
                f"--rate={scan_rate}",  # Configurable rate
                "-oJ",
                temp_file,  # JSON output
                "--wait",
                wait_time,  # Wait time for responses
                "--open-only",  # Only report open ports
            ]

            # Add interface selection for large networks
            if total_hosts > large_network_threshold:
                # Try to auto-detect the best interface
                interface = self._get_best_interface_for_target(target)
                if interface:
                    cmd.extend(["-e", interface])
                    self.console.print(f"[cyan]📡 Using interface: {interface}[/cyan]")

                # Also try to get source IP for faster initialization
                src_ip = self._get_source_ip_for_interface(interface)
                if src_ip:
                    cmd.extend(["--adapter-ip", src_ip])
                    self.console.print(f"[cyan]📍 Source IP: {src_ip}[/cyan]")

            cmd.append(target)

            # Show command for debugging large scans
            if total_hosts > 50000:
                self.console.print(f"[dim]Ports being scanned: {port_list}[/dim]")
                self.console.print(f"[dim]Scan rate: {scan_rate:,} packets/sec[/dim]")
                self.console.print(f"[dim]This may take a moment to initialize...[/dim]")

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
                transient=False,
            ) as progress:
                task = progress.add_task(
                    f"Fast scanning {target}", total=100, status="Initializing masscan..."
                )

                start_time = time.time()
                devices_found = 0
                last_percent = 0
                self.last_progress_update = start_time
                self.hang_detected = False
                auth_check_done = False

                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    bufsize=1,
                )

                # Check for early errors (including sudo issues)
                time.sleep(0.5)
                if proc.poll() is not None:
                    stderr_output = proc.stderr.read()
                    if "sudo:" in stderr_output and "password" in stderr_output:
                        # Progress bar interfered with password prompt
                        progress.stop()
                        self.console.print("\n[red]❌ Sudo authentication failed.[/red]")
                        self.console.print(
                            "[yellow]💡 Tip: The password prompt was missed. Please run the scan again.[/yellow]"
                        )
                        raise FriendlyError(
                            "Sudo authentication failed - please retry",
                            "Administrator access is required for this scan.",
                            "Run the command again and enter your password when prompted"
                        )
                    elif stderr_output:
                        raise handle_scanner_error("masscan", RuntimeError(stderr_output))

                # Monitor stderr in a separate thread
                stderr_lines = []

                def monitor_stderr():
                    try:
                        for line in proc.stderr:
                            stderr_lines.append(line.strip())
                            if "sudo:" in line:
                                progress.stop()
                                self.console.print(f"\n[red]Error: {line.strip()}[/red]")
                    except:
                        pass

                stderr_thread = threading.Thread(target=monitor_stderr, daemon=True)
                stderr_thread.start()

                # Track initialization
                initialized = False
                init_timeout = 15  # 15 seconds max for initialization
                last_status_update = start_time
                lines_without_progress = 0

                for line in proc.stdout:
                    line = line.strip()
                    current_time = time.time()

                    # Check for initialization timeout
                    if not initialized and (current_time - start_time) > init_timeout:
                        progress.update(
                            task, status="Initialization taking longer than expected..."
                        )
                        if (current_time - start_time) > 30:
                            # Kill the process if it takes too long
                            proc.terminate()
                            raise RuntimeError(
                                "Masscan initialization timeout - try reducing scan rate or target size"
                            )

                    if show_details and line:
                        self.console.print(f"[dim]{line}[/dim]")

                    # Parse masscan output
                    if not initialized and line:
                        initialized = True
                        progress.update(task, status="Scan started...")

                    if "rate:" in line.lower():
                        # Extract scan rate
                        match = re.search(r"rate:\s*([\d.]+)", line, re.IGNORECASE)
                        if match:
                            rate = match.group(1)
                            progress.update(task, status=f"Scanning at {rate} pkts/s")

                    elif "found=" in line or "Discovered" in line:
                        # Extract progress percentage
                        match = re.search(r"(\d+\.\d+)%", line)
                        if match:
                            percent = float(match.group(1))
                            if percent > last_percent:
                                last_percent = percent
                                self.last_progress_update = current_time
                                self.hang_detected = False
                            progress.update(task, completed=percent)
                            lines_without_progress = 0  # Reset counter

                        # Extract found count
                        match = re.search(r"found=(\d+)", line)
                        if match:
                            devices_found = int(match.group(1))
                            elapsed = time.time() - start_time
                            progress.update(
                                task, status=f"Found {devices_found} hosts • {elapsed:.0f}s"
                            )
                            lines_without_progress = 0  # Reset counter
                            if show_details:
                                self.console.print(f"[green]→ Total found: {devices_found}[/green]")

                    elif "waiting" in line.lower() and "seconds" in line.lower():
                        # Waiting phase
                        progress.update(task, status="Waiting for final packets...")

                    # Also check for standard masscan output format
                    elif "Scanning" in line and "/" in line:
                        # Format: "Scanning 4 hosts [1 port/host]"
                        match = re.search(r"Scanning\s+(\d+)\s+hosts", line)
                        if match:
                            hosts_count = match.group(1)
                            progress.update(task, status=f"Scanning {hosts_count} hosts...")

                    # Check for completion
                    elif "scanned" in line.lower() and "seconds" in line.lower():
                        # Format: "scanned 65536 hosts in X seconds"
                        match = re.search(r"scanned\s+(\d+)\s+hosts", line, re.IGNORECASE)
                        if match:
                            total_scanned = match.group(1)
                            progress.update(task, status=f"Scanned {total_scanned} hosts")

                    # Check for hang
                    self._check_hang(current_time, task, progress)
                    
                    # Provide periodic updates if no progress info
                    if current_time - last_status_update > 3:
                        lines_without_progress += 1
                        if lines_without_progress > 5:
                            elapsed = current_time - start_time
                            progress.update(
                                task, 
                                status=f"Scanning in progress... ({devices_found} found, {elapsed:.0f}s)"
                            )
                        last_status_update = current_time

                proc.wait()

                # Check if there were sudo errors
                if proc.returncode != 0:
                    stderr_output = "\n".join(stderr_lines)
                    if "sudo:" in stderr_output:
                        raise RuntimeError("Sudo authentication failed. Please run the scan again.")
                    else:
                        raise RuntimeError(f"Masscan failed with return code {proc.returncode}")

                # Set to 100% when done (temporary status)
                progress.update(task, completed=100, status=f"Scan complete, parsing results...")

            # Parse JSON output
            devices = self._parse_masscan_output(temp_file)

            # Update with actual device count
            self.console.print(f"\n[green]✓ Masscan discovered {len(devices)} devices[/green]")

            # Debug: Check if temp file has content
            if os.path.exists(temp_file):
                file_size = os.path.getsize(temp_file)
                if file_size == 0:
                    self.console.print("[yellow]⚠ Masscan output file is empty[/yellow]")
                else:
                    # Always save a copy for debugging when no devices found
                    if len(devices) == 0 and file_size > 0:
                        debug_dir = Path("output") / "debug"
                        debug_dir.mkdir(parents=True, exist_ok=True)
                        debug_file = (
                            debug_dir
                            / f"masscan_debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                        )

                        try:
                            import shutil

                            shutil.copy2(temp_file, debug_file)
                            self.console.print(
                                f"[yellow]⚠ No devices parsed, debug output saved to: {debug_file}[/yellow]"
                            )

                            # Also show first few lines of the file for immediate debugging
                            with open(temp_file, "r") as f:
                                lines = f.readlines()[:10]
                                if lines:
                                    self.console.print(
                                        "[yellow]First few lines of masscan output:[/yellow]"
                                    )
                                    for i, line in enumerate(lines):
                                        self.console.print(
                                            f"[dim]{i+1}: {line.strip()[:120]}[/dim]"
                                        )
                        except Exception as e:
                            logger.warning(f"Could not save debug file: {e}")

                    if show_details:
                        self.console.print(f"[dim]Output file size: {file_size} bytes[/dim]")

            # If masscan found no hosts, suggest falling back to nmap
            if len(devices) == 0:
                self.console.print("\n[yellow]⚠ Masscan found no hosts on the network[/yellow]")
                self.console.print("[dim]This could mean:[/dim]")
                self.console.print("[dim]  • No hosts have the scanned ports open[/dim]")
                self.console.print("[dim]  • Firewall is blocking the scan[/dim]")
                self.console.print("[dim]  • Network uses non-standard ports[/dim]")
                self.console.print(
                    "\n[cyan]💡 Tip: Try using standard nmap discovery instead (more thorough but slower)[/cyan]"
                )
            else:
                # Log successful parsing
                self.console.print(
                    f"\n[green]✓ Successfully parsed {len(devices)} devices from masscan[/green]"
                )
                if show_details:
                    for i, device in enumerate(devices[:5]):  # Show first 5
                        self.console.print(
                            f"[dim]  {i+1}. {device['ip']} - Ports: {device.get('open_ports', [])}[/dim]"
                        )
                    if len(devices) > 5:
                        self.console.print(f"[dim]  ... and {len(devices) - 5} more[/dim]")

            return devices

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
                transient=False,
            ) as progress:
                task = progress.add_task(
                    f"Layer 2 scanning",
                    total=None,  # Indeterminate
                    status="Sending ARP requests...",
                )

                devices = []
                start_time = time.time()

                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True
                )

                for line in proc.stdout:
                    line = line.strip()

                    if show_details and line:
                        self.console.print(f"[dim]{line}[/dim]")

                    # Parse arp-scan output format: IP MAC Vendor
                    match = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]+)\s+(.*)$", line)
                    if match:
                        ip, mac, vendor = match.groups()
                        devices.append(
                            {
                                "ip": ip,
                                "mac": mac.upper(),
                                "vendor": vendor,
                                "hostname": "",
                                "type": "unknown",
                                "os": "",
                                "services": [],
                                "open_ports": [],
                            }
                        )

                        elapsed = time.time() - start_time
                        progress.update(
                            task,
                            status=f"Found {len(devices)} devices • {elapsed:.0f}s • Latest: {ip}",
                        )

                        if show_details:
                            self.console.print(f"[green]→ Found: {ip} ({mac}) - {vendor}[/green]")

                proc.wait()

                progress.update(task, status=f"Complete: {len(devices)} devices found")

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
            result = subprocess.run(["which", scanner], capture_output=True, timeout=5)
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

                # Debug: Log the first 500 chars of output
                logger.debug(f"Masscan output preview: {data[:500]}")

                # Masscan outputs one JSON object per line, each representing a finding
                for line_num, line in enumerate(data.strip().split("\n"), 1):
                    line = line.strip()

                    # Skip empty lines and array brackets
                    if not line or line in ["{}", "{ }", "[", "]", "[\n", "\n]", ","]:
                        continue

                    try:
                        # Remove trailing comma if present
                        if line.endswith(","):
                            line = line[:-1]

                        # Parse the JSON object
                        entry = json.loads(line)

                        # Ensure entry is a dictionary before accessing keys
                        if not isinstance(entry, dict):
                            logger.debug(
                                f"Line {line_num}: entry is not a dict, skipping: {type(entry)}"
                            )
                            continue

                        # Masscan format: each line has ip, timestamp, and ports array
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
                                    "discovery_method": "masscan",
                                }

                            # Add port information if available
                            if "ports" in entry and isinstance(entry["ports"], list):
                                for port_info in entry["ports"]:
                                    # Ensure port_info is a dict
                                    if not isinstance(port_info, dict):
                                        continue

                                    port = port_info.get("port", 0)
                                    proto = port_info.get("proto", "tcp")
                                    status = port_info.get(
                                        "status", "open"
                                    )  # Default to "open" if not specified

                                    # Accept the port if status is "open" or not specified (masscan default)
                                    if port and (status == "open" or status == ""):
                                        if port not in devices[ip]["open_ports"]:
                                            devices[ip]["open_ports"].append(port)
                                            devices[ip]["services"].append(f"{proto}:{port}")

                        # Also check for the "rec" field (some masscan versions)
                        elif "rec" in entry and isinstance(entry["rec"], dict):
                            rec = entry["rec"]
                            if rec.get("rec_type") == "banner" and "ip" in rec:
                                ip = rec["ip"]
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
                                        "discovery_method": "masscan",
                                    }

                    except json.JSONDecodeError as e:
                        # Only log warnings for non-empty lines that failed to parse
                        if line and not line.isspace():
                            # Check if this might be a masscan comment or header
                            if not line.startswith("#") and not "masscan" in line.lower():
                                logger.debug(f"Line {line_num} not valid JSON: {line[:100]}")
                        continue
                    except (TypeError, AttributeError) as e:
                        logger.debug(f"Line {line_num} type error: {e} - line: {line[:100]}")
                        continue
                    except Exception as e:
                        logger.warning(f"Error processing masscan entry on line {line_num}: {e}")
                        continue

            # Log summary
            logger.info(f"Parsed {len(devices)} devices from masscan output")

            # If we got no devices but had data, try alternate parsing
            if len(devices) == 0 and data.strip():
                logger.warning("No devices parsed with standard format, trying alternate parsing")

                # Try parsing as single JSON array
                try:
                    json_data = json.loads(data)
                    if isinstance(json_data, list):
                        for entry in json_data:
                            if isinstance(entry, dict) and "ip" in entry:
                                ip = entry["ip"]
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
                                    "discovery_method": "masscan",
                                }
                                # Add ports
                                if "ports" in entry and isinstance(entry["ports"], list):
                                    for port_info in entry["ports"]:
                                        if isinstance(port_info, dict):
                                            port = port_info.get("port", 0)
                                            proto = port_info.get("proto", "tcp")
                                            if port:
                                                devices[ip]["open_ports"].append(port)
                                                devices[ip]["services"].append(f"{proto}:{port}")
                        logger.info(f"Alternate parsing found {len(devices)} devices")
                except (json.JSONDecodeError, TypeError) as e:
                    logger.warning(f"Alternate JSON array parsing failed: {e}")
                except Exception as e:
                    logger.warning(f"Unexpected error in alternate parsing: {e}")

        except Exception as e:
            logger.error(f"Failed to parse masscan output: {e}")
            import traceback

            logger.error(f"Traceback: {traceback.format_exc()}")

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
        cmd.extend(
            [
                "--retry=2",  # Retry twice for reliability
                "--timeout=500",  # 500ms timeout
                "--backoff=1.5",  # Backoff multiplier
            ]
        )

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
            device
            for device in devices
            if device.get("type") in ["router", "switch", "server", "printer", "nas", "firewall"]
            or any(port in device.get("open_ports", []) for port in [161, 80, 443, 22])
        ]

        if not snmp_candidates:
            logger.info("No SNMP candidates found in scan results")
            return devices

        version = snmp_config.get("version", "v2c")
        self.console.print(
            f"\n[cyan]Enriching {len(snmp_candidates)} devices with SNMP {version}...[/cyan]"
        )

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
            transient=False,
        ) as progress:
            task = progress.add_task(
                "Enriching devices", total=len(snmp_candidates), status="Starting SNMP queries..."
            )

            enriched_count = 0
            failed_count = 0

            # Process devices with limited concurrency
            try:
                enriched_devices = snmp_manager.enrich_devices(snmp_candidates, max_workers=5)

                # Update progress and count successes
                for i, (original, enriched) in enumerate(zip(snmp_candidates, enriched_devices)):
                    if "snmp_data" in enriched:
                        enriched_count += 1
                    else:
                        failed_count += 1

                    progress.update(
                        task,
                        completed=i + 1,
                        status=f"Enriched: {enriched_count}, Failed: {failed_count}",
                    )

                # Replace original devices with enriched versions
                device_map = {device["ip"]: device for device in enriched_devices}
                for i, device in enumerate(devices):
                    if device["ip"] in device_map:
                        devices[i] = device_map[device["ip"]]

                progress.update(
                    task,
                    completed=len(snmp_candidates),
                    status=f"Complete: {enriched_count} enriched, {failed_count} failed",
                )

            except Exception as e:
                logger.error(f"SNMP enrichment error: {e}")
                progress.update(task, status=f"Error: {e}")

        if enriched_count > 0:
            self.console.print(
                f"[green]✓ Successfully enriched {enriched_count} devices with SNMP data[/green]"
            )
        if failed_count > 0:
            self.console.print(
                f"[yellow]⚠ Failed to enrich {failed_count} devices (SNMP not responding)[/yellow]"
            )

        return devices

    def _is_local_subnet(self, target: str) -> bool:
        """Check if target is a local subnet that can benefit from ARP scanning"""
        import ipaddress
        import socket

        try:
            # Parse the target network
            if "/" in target:
                network = ipaddress.IPv4Network(target, strict=False)
            else:
                # Single IP
                return True

            # Get local interfaces
            hostname = socket.gethostname()
            local_ips = socket.gethostbyname_ex(hostname)[2]

            # Also check common local network ranges
            local_ranges = [
                ipaddress.IPv4Network("10.0.0.0/8"),
                ipaddress.IPv4Network("172.16.0.0/12"),
                ipaddress.IPv4Network("192.168.0.0/16"),
            ]

            # Check if target overlaps with local networks
            for local_range in local_ranges:
                if network.overlaps(local_range):
                    return True

            # Check if any local IP is in the target network
            for ip in local_ips:
                if ipaddress.IPv4Address(ip) in network:
                    return True

        except Exception as e:
            logger.debug(f"Error checking if subnet is local: {e}")

        return False

    def _merge_scan_results(self, arp_devices: List[Dict], nmap_devices: List[Dict]) -> List[Dict]:
        """Merge results from multiple scanners, avoiding duplicates"""
        merged = {}

        # First add all ARP devices (more reliable for local)
        for device in arp_devices:
            ip = device.get("ip")
            if ip:
                merged[ip] = device

        # Then add/update with nmap results
        for device in nmap_devices:
            ip = device.get("ip")
            if ip:
                if ip in merged:
                    # Merge information
                    existing = merged[ip]
                    # Update with nmap data but keep ARP MAC if present
                    if not device.get("mac") and existing.get("mac"):
                        device["mac"] = existing["mac"]
                    if not device.get("vendor") and existing.get("vendor"):
                        device["vendor"] = existing["vendor"]
                    # Merge services and ports
                    existing_services = set(existing.get("services", []))
                    new_services = set(device.get("services", []))
                    device["services"] = list(existing_services | new_services)

                    existing_ports = set(existing.get("open_ports", []))
                    new_ports = set(device.get("open_ports", []))
                    device["open_ports"] = sorted(list(existing_ports | new_ports))

                merged[ip] = device

        return list(merged.values())

    def _get_best_interface_for_target(self, target: str) -> Optional[str]:
        """Determine the best network interface for scanning a target"""
        try:
            import ipaddress
            import subprocess

            # Get routing table to find best interface
            result = subprocess.run(
                ["ip", "route", "get", target.split("/")[0]],
                capture_output=True,
                text=True,
                timeout=2,
            )

            if result.returncode == 0 and result.stdout:
                # Parse output like: "10.0.0.1 via 192.168.1.1 dev eth0 src 192.168.1.100"
                parts = result.stdout.split()
                if "dev" in parts:
                    dev_index = parts.index("dev")
                    if dev_index + 1 < len(parts):
                        return parts[dev_index + 1]

        except Exception as e:
            logger.debug(f"Could not determine best interface: {e}")

        return None

    def _get_source_ip_for_interface(self, interface: str) -> Optional[str]:
        """Get the source IP address for a given interface"""
        if not interface:
            return None

        try:
            import subprocess

            # Use ip addr show to get interface IPs
            result = subprocess.run(
                ["ip", "addr", "show", interface], capture_output=True, text=True, timeout=2
            )

            if result.returncode == 0 and result.stdout:
                # Parse output for IPv4 address
                import re

                match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/\d+", result.stdout)
                if match:
                    return match.group(1)

        except Exception as e:
            logger.debug(f"Could not get source IP for interface {interface}: {e}")

        return None

    def _run_masscan_fast(self, target: str) -> List[Dict]:
        """Run masscan optimized for very large networks

        Args:
            target: Network target (can be multiple /16s)

        Returns:
            List of discovered devices
        """
        # Check availability
        if not self._check_scanner_available("masscan"):
            self.console.print(
                "[yellow]⚠ Masscan not available, falling back to standard discovery[/yellow]"
            )
            return self._run_masscan(target)

        # Calculate total hosts
        total_hosts = self._estimate_total_hosts(target)

        # For very large networks, use aggressive settings
        if total_hosts > 50000:
            scan_rate = 100000  # 100k pps for large networks
            ports = "80,443,22,445,3389,135,139,8080"  # Common ports that are usually open
            wait_time = "2"  # Give more time for responses
        else:
            scan_rate = 50000
            ports = "80,443,22,445,3389,8080,135,139,21,23,25,53,161"
            wait_time = "3"

        self.console.print(f"[cyan]🚀 Fast scanning {total_hosts:,} hosts at {scan_rate:,} packets/sec[/cyan]")
        self.console.print(f"[cyan]📍 Target ports: {ports}[/cyan]")
        self.console.print(f"[dim]Note: Progress updates may be intermittent during masscan phase[/dim]")

        # Ensure sudo
        if not self._ensure_sudo_access():
            raise FriendlyError(
                "Fast scan requires sudo access",
                "Administrator privileges are required for high-speed scanning.",
                "Run with: sudo python3 mapper.py"
            )

        temp_file = self._create_temp_file("masscan_fast", ".json")

        try:
            cmd = [
                "sudo",
                "-n",
                "masscan",
                f"-p{ports}",
                f"--rate={scan_rate}",
                "-oJ",
                temp_file,
                "--wait",
                wait_time,
                "--open-only",
                "--randomize-hosts",  # Better for large ranges
            ]

            # Add interface if detected
            interface = self._get_best_interface_for_target(target)
            if interface:
                cmd.extend(["-e", interface])

            cmd.append(target)

            # Create progress bar
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]Ultra-fast scan[/bold cyan]"),
                BarColumn(complete_style="cyan", finished_style="cyan"),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                TextColumn("• {task.fields[status]}"),
                console=self.console,
                refresh_per_second=2,
                transient=False,
            ) as progress:
                task = progress.add_task(
                    f"Scanning {target}", total=100, status="Initializing masscan..."
                )

                start_time = time.time()
                devices_found = 0
                last_percent = 0

                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    bufsize=1,
                )

                # Quick error check
                time.sleep(0.5)
                if proc.poll() is not None:
                    stderr = proc.stderr.read()
                    if "sudo:" in stderr:
                        raise RuntimeError("Sudo authentication failed")
                    raise RuntimeError(f"Masscan failed: {stderr}")

                # Process output with better progress tracking
                last_update_time = start_time
                no_output_count = 0
                
                while True:
                    # Try to read line with timeout
                    line = proc.stdout.readline()
                    
                    if not line:
                        # Check if process has finished
                        if proc.poll() is not None:
                            break
                        
                        # No output - update status periodically
                        current_time = time.time()
                        if current_time - last_update_time > 2:  # Update every 2 seconds
                            elapsed = current_time - start_time
                            no_output_count += 1
                            
                            if no_output_count < 5:
                                progress.update(
                                    task,
                                    status=f"Scanning in progress... ({elapsed:.0f}s elapsed)"
                                )
                            else:
                                progress.update(
                                    task,
                                    status=f"Scanning (no output from masscan)... ({elapsed:.0f}s)"
                                )
                            last_update_time = current_time
                        
                        time.sleep(0.1)
                        continue
                    
                    line = line.strip()
                    no_output_count = 0  # Reset counter on output
                    
                    # Parse progress
                    if "found=" in line:
                        match = re.search(r"found=(\d+)", line)
                        if match:
                            devices_found = int(match.group(1))

                    percent_match = re.search(r"(\d+\.\d+)%", line)
                    if percent_match:
                        percent = float(percent_match.group(1))
                        if percent > last_percent:
                            last_percent = percent
                            elapsed = time.time() - start_time
                            rate = devices_found / elapsed if elapsed > 0 else 0
                            progress.update(
                                task,
                                completed=percent,
                                status=f"Found {devices_found} hosts ({rate:.0f}/sec)",
                            )
                            last_update_time = time.time()
                    
                    # Also update on any output to show activity
                    elif time.time() - last_update_time > 3:
                        elapsed = time.time() - start_time
                        progress.update(
                            task,
                            status=f"Scanning... ({devices_found} found, {elapsed:.0f}s)"
                        )
                        last_update_time = time.time()

                proc.wait()

                if proc.returncode != 0:
                    stderr = proc.stderr.read()
                    raise RuntimeError(f"Masscan failed: {stderr}")

                progress.update(
                    task, completed=100, status=f"Complete: {devices_found} hosts found"
                )

            # Parse results
            devices = self._parse_masscan_output(temp_file)
            self.console.print(
                f"[green]✓ Fast scan complete: {len(devices)} active hosts found[/green]"
            )

            return devices

        finally:
            self._cleanup_temp_file(temp_file, needs_sudo=True)

    def _enrich_fast_scan(self, devices: List[Dict]) -> List[Dict]:
        """Enrich devices from fast scan with minimal service detection

        Args:
            devices: List of devices from masscan

        Returns:
            Enriched device list
        """
        if not devices:
            return devices

        # Create target list of just discovered IPs
        ip_list = [d["ip"] for d in devices]

        # For large sets, process in chunks
        chunk_size = 25  # Smaller chunks for better timeout handling
        enriched_devices = []

        total_chunks = (len(ip_list) + chunk_size - 1) // chunk_size

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold green]Enrichment[/bold green]"),
            BarColumn(complete_style="green", finished_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("• {task.fields[status]}"),
            console=self.console,
            transient=False,
        ) as progress:
            task = progress.add_task(
                "Enriching devices",
                total=len(devices),
                status="Starting enrichment with DNS resolution...",
            )

            for i in range(0, len(ip_list), chunk_size):
                chunk = ip_list[i : i + chunk_size]
                chunk_num = i // chunk_size + 1
                
                # Show which IPs are being enriched
                ip_range = f"{chunk[0]} - {chunk[-1]}" if len(chunk) > 1 else chunk[0]
                progress.update(
                    task, 
                    completed=i, 
                    status=f"Enriching chunk {chunk_num}/{total_chunks} ({ip_range})"
                )

                # Create target string for this chunk
                target = " ".join(chunk)

                try:
                    # Run light nmap scan on chunk
                    temp_file = self._create_temp_file("nmap_enrich", ".xml")

                    cmd = [
                        "sudo",
                        "-n",
                        "nmap",
                        "-sS",  # SYN scan
                        "-sV",  # Version detection
                        "-O",  # OS detection
                        "--osscan-guess",  # Aggressive OS guessing
                        "--version-intensity",
                        "0",  # Fastest version detection
                        "-T5",  # Aggressive timing
                        # DNS resolution enabled for hostname discovery
                        "--top-ports",
                        "20",  # Only check top 20 ports for speed
                        "-oX",
                        temp_file,
                        "--max-rtt-timeout",
                        "100ms",
                        "--max-retries",
                        "1",
                    ] + chunk

                    # Update status to show nmap is running
                    progress.update(
                        task,
                        status=f"Running nmap on chunk {chunk_num}/{total_chunks} ({len(chunk)} IPs)..."
                    )
                    
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=120,  # 120 second timeout per chunk for OS detection
                    )

                    if result.returncode == 0 and os.path.exists(temp_file):
                        # Parse enrichment data
                        enriched = self._parse_nmap_xml(temp_file)

                        # Merge with original masscan data
                        enriched_map = {e["ip"]: e for e in enriched}

                        for device in devices[i : i + len(chunk)]:
                            if device["ip"] in enriched_map:
                                # Merge data
                                e = enriched_map[device["ip"]]
                                device.update(
                                    {
                                        "hostname": e.get("hostname", ""),
                                        "os": e.get("os", ""),
                                        "os_accuracy": e.get("os_accuracy", 0),
                                        "services": e.get("services", []),
                                        "vendor": e.get("vendor", device.get("vendor", "")),
                                    }
                                )
                                # Debug: Log if OS was found
                                if e.get("os"):
                                    logger.info(f"OS detected for {device['ip']}: {e.get('os')}")
                                    self.console.print(
                                        f"[green]✓ OS detected for {device['ip']}: {e.get('os', 'Unknown')}[/green]"
                                    )
                                # Log if hostname was found
                                if e.get("hostname"):
                                    logger.info(
                                        f"Hostname resolved for {device['ip']}: {e.get('hostname')}"
                                    )
                                    self.console.print(
                                        f"[green]✓ Hostname found for {device['ip']}: {e.get('hostname')}[/green]"
                                    )
                            enriched_devices.append(device)
                            
                        # Update progress after chunk completion
                        progress.update(
                            task,
                            completed=i + len(chunk),
                            status=f"Completed chunk {chunk_num}/{total_chunks}"
                        )
                    else:
                        # If enrichment fails, keep original data
                        enriched_devices.extend(devices[i : i + len(chunk)])
                        progress.update(
                            task,
                            completed=i + len(chunk),
                            status=f"Chunk {chunk_num} enrichment failed, keeping basic data"
                        )

                    self._cleanup_temp_file(temp_file, needs_sudo=True)

                except subprocess.TimeoutExpired:
                    self.console.print(
                        f"[yellow]⚠ Enrichment timeout for chunk {chunk_num} - trying without OS detection[/yellow]"
                    )
                    # Try again without OS detection
                    try:
                        cmd_no_os = [
                            "sudo",
                            "-n",
                            "nmap",
                            "-sS",  # SYN scan
                            "-sV",  # Version detection
                            "--version-intensity",
                            "0",  # Fastest version detection
                            "-T5",  # Aggressive timing
                            # DNS resolution enabled for hostname discovery
                            "--top-ports",
                            "10",  # Only top 10 ports
                            "-oX",
                            temp_file,
                            "--max-rtt-timeout",
                            "50ms",
                            "--max-retries",
                            "0",
                        ] + chunk

                        result = subprocess.run(
                            cmd_no_os,
                            capture_output=True,
                            text=True,
                            timeout=30,  # Much shorter timeout
                        )

                        if result.returncode == 0 and os.path.exists(temp_file):
                            enriched = self._parse_nmap_xml(temp_file)
                            enriched_map = {e["ip"]: e for e in enriched}

                            for device in devices[i : i + len(chunk)]:
                                if device["ip"] in enriched_map:
                                    e = enriched_map[device["ip"]]
                                    device.update(
                                        {
                                            "hostname": e.get("hostname", ""),
                                            "services": e.get("services", []),
                                            "vendor": e.get("vendor", device.get("vendor", "")),
                                        }
                                    )
                                enriched_devices.append(device)
                        else:
                            enriched_devices.extend(devices[i : i + len(chunk)])

                        self._cleanup_temp_file(temp_file, needs_sudo=True)
                    except:
                        enriched_devices.extend(devices[i : i + len(chunk)])
                except Exception as e:
                    logger.warning(f"Enrichment error for chunk {chunk_num}: {e}")
                    enriched_devices.extend(devices[i : i + len(chunk)])

            progress.update(task, completed=len(devices), status="Enrichment complete")

        return enriched_devices

    def _run_masscan_deeper(self, target: str) -> List[Dict]:
        """Run masscan with more ports for deeper scan

        Args:
            target: Network target

        Returns:
            List of discovered devices
        """
        # Use the same masscan logic but with more ports (defined in scan profile)
        return self._run_masscan_fast(target)  # Reuse the same method, it will use the profile ports

    def _enrich_deeper_scan(self, devices: List[Dict]) -> List[Dict]:
        """Enrich devices with comprehensive nmap scanning

        Args:
            devices: List of devices from masscan

        Returns:
            Enriched device list with detailed service and OS info
        """
        if not devices:
            return devices

        # Create target list of just discovered IPs
        ip_list = [d["ip"] for d in devices]

        # For deeper scan, use smaller chunks for better accuracy
        chunk_size = 10  # Smaller chunks for more thorough scanning
        enriched_devices = []

        total_chunks = (len(ip_list) + chunk_size - 1) // chunk_size

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold green]Deep Enrichment[/bold green]"),
            BarColumn(complete_style="green", finished_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("• {task.fields[status]}"),
            console=self.console,
            transient=False,
        ) as progress:
            task = progress.add_task(
                "Enriching devices", total=len(devices), status="Starting deep enrichment..."
            )

            for chunk_idx in range(total_chunks):
                start_idx = chunk_idx * chunk_size
                end_idx = min(start_idx + chunk_size, len(ip_list))
                chunk_ips = ip_list[start_idx:end_idx]

                progress.update(
                    task,
                    completed=start_idx,
                    status=f"Scanning chunk {chunk_idx + 1}/{total_chunks} ({len(chunk_ips)} IPs)"
                )

                # Use the deeper scan profile which has more comprehensive settings
                temp_file = self._create_temp_file("nmap_deeper", ".xml")

                try:
                    # Build nmap command with deeper scan profile
                    profile = self.scan_profiles["deeper"]
                    cmd = ["sudo", "nmap"] + profile["nmap"] + ["-oX", temp_file] + chunk_ips

                    # Run with longer timeout for deeper scanning
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=300  # 5 minute timeout per chunk
                    )

                    if result.returncode == 0:
                        # Parse results
                        chunk_results = self._parse_nmap_xml(temp_file)
                        
                        # Merge with original device data
                        device_map = {d["ip"]: d for d in devices[start_idx:end_idx]}
                        for enriched in chunk_results:
                            if enriched["ip"] in device_map:
                                # Keep original open_ports from masscan
                                original = device_map[enriched["ip"]]
                                enriched["open_ports"] = list(set(original.get("open_ports", []) + enriched.get("open_ports", [])))
                                enriched_devices.append(enriched)
                            else:
                                enriched_devices.append(enriched)
                    else:
                        # If enrichment fails, keep original devices
                        enriched_devices.extend(devices[start_idx:end_idx])
                        logger.warning(f"Deeper enrichment failed for chunk {chunk_idx + 1}: {result.stderr}")

                except subprocess.TimeoutExpired:
                    # On timeout, keep original devices
                    enriched_devices.extend(devices[start_idx:end_idx])
                    logger.warning(f"Deeper enrichment timeout for chunk {chunk_idx + 1}")
                except Exception as e:
                    enriched_devices.extend(devices[start_idx:end_idx])
                    logger.error(f"Deeper enrichment error: {e}")
                finally:
                    self._cleanup_temp_file(temp_file, needs_sudo=True)

            progress.update(task, completed=len(devices), status="Deep enrichment complete")

        # Log enrichment summary
        self.console.print(f"[green]✓ Deep enrichment complete for {len(enriched_devices)} devices[/green]")
        
        # Show sample of enriched data
        if enriched_devices and self.config["scanners"].get("progress_details", False):
            sample = enriched_devices[0]
            if sample.get("os"):
                self.console.print(f"[dim]Sample OS detection: {sample['ip']} -> {sample['os']}[/dim]")
            if sample.get("services"):
                self.console.print(f"[dim]Sample services: {len(sample['services'])} services detected[/dim]")

        return enriched_devices
