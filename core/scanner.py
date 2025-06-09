import json
import os
import re
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import yaml
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table


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
                "nmap": ["-sS", "-sV", "-O", "-p-", "--script", "default"],
                "description": "Full port scan with scripts",
            },
        }
        self.console = Console()
        self.config = self._load_config()
        self.last_progress_update = time.time()
        self.hang_detected = False

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
                    "progress_refresh_rate": 4
                }
            }

    def scan(
        self,
        target: str,
        scan_type: str = "discovery",
        use_masscan: bool = False,
        needs_root: bool = False,
    ) -> List[Dict]:
        """Execute network scan with progress feedback"""
        if use_masscan and scan_type == "discovery":
            return self._run_masscan(target)
        else:
            return self._run_nmap(target, scan_type, needs_root)

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

    def _run_nmap(self, target: str, scan_type: str, needs_root: bool) -> List[Dict]:
        """Run nmap scan with real-time progress"""
        profile = self.scan_profiles[scan_type]
        show_details = self.config["scanners"].get("progress_details", False)
        stats_interval = self.config["scanners"].get("nmap_stats_interval", "1s")
        refresh_rate = self.config["scanners"].get("progress_refresh_rate", 4)

        # Generate a unique temp filename
        temp_dir = tempfile.gettempdir()
        temp_filename = f"nmap_{os.getpid()}_{os.urandom(4).hex()}.xml"
        temp_path = os.path.join(temp_dir, temp_filename)

        try:
            # Build command with stats output
            cmd = ["nmap", "-oX", temp_path, "--stats-every", stats_interval] + profile["nmap"] + [target]

            if needs_root:
                cmd = ["sudo"] + cmd

            # Create progress display without Live wrapper
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Nmap {task.fields[scan_type]} scan[/bold blue]"),
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
                    scan_type=scan_type.capitalize(),
                    status="Initializing..."
                )

                # Progress tracking variables
                start_time = time.time()
                devices_found = 0
                current_host = ""
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
                    
                    # Detailed output if enabled
                    if show_details and line:
                        self.console.print(f"[dim]{line}[/dim]")
                    
                    # Parse nmap progress output
                    if "Stats:" in line:
                        # Extract percentage from stats line
                        match = re.search(r'(\d+\.\d+)%.*done', line)
                        if match:
                            percent = float(match.group(1))
                            if percent > last_percent:
                                last_percent = percent
                                self.last_progress_update = current_time
                                self.hang_detected = False
                            progress.update(task, completed=percent)
                    
                    elif "Scanning" in line and "(" in line:
                        # Extract current host being scanned
                        match = re.search(r'Scanning\s+([^\s]+)\s+\(([^)]+)\)', line)
                        if match:
                            current_host = f"{match.group(1)} ({match.group(2)})"
                            progress.update(task, status=f"Scanning {current_host}")
                            if show_details:
                                self.console.print(f"[green]→ Found host: {current_host}[/green]")
                    
                    elif "Discovered open port" in line:
                        # Found an open port
                        match = re.search(r'port\s+(\d+)/(\w+)\s+on\s+(.+)', line)
                        if match:
                            port_info = f"{match.group(1)}/{match.group(2)} on {match.group(3)}"
                            progress.update(task, status=f"Found: {port_info}")
                            if show_details:
                                self.console.print(f"[cyan]  ↳ Open port: {port_info}[/cyan]")
                    
                    elif "Nmap scan report for" in line:
                        # Found a live host
                        devices_found += 1
                        elapsed = time.time() - start_time
                        progress.update(
                            task, 
                            status=f"Found {devices_found} devices • {elapsed:.0f}s"
                        )
                    
                    elif "hosts up" in line:
                        # Final summary
                        match = re.search(r'(\d+)\s+host[s]?\s+up', line)
                        if match:
                            total_up = match.group(1)
                            progress.update(
                                task,
                                completed=100,
                                status=f"Complete: {total_up} hosts up"
                            )
                    
                    # Check for hang
                    self._check_hang(current_time, task, progress)

                proc.wait()

                if proc.returncode != 0:
                    raise Exception(f"Nmap failed with return code {proc.returncode}")

            # Parse XML output
            return self._parse_nmap_xml(temp_path)
            
        finally:
            # Clean up temp file
            try:
                if os.path.exists(temp_path):
                    if needs_root and os.stat(temp_path).st_uid == 0:
                        subprocess.run(["sudo", "rm", temp_path], capture_output=True)
                    else:
                        os.remove(temp_path)
            except:
                pass

    def _run_masscan(self, target: str) -> List[Dict]:
        """Run masscan for fast discovery with progress"""
        show_details = self.config["scanners"].get("progress_details", False)
        refresh_rate = self.config["scanners"].get("progress_refresh_rate", 4)
        
        # Generate a unique temp filename
        temp_dir = tempfile.gettempdir()
        temp_filename = f"masscan_{os.getpid()}_{os.urandom(4).hex()}.json"
        temp_file = os.path.join(temp_dir, temp_filename)

        try:
            cmd = [
                "sudo",
                "masscan",
                "-p0",  # Ping scan
                "--rate=10000",  # 10k packets/sec
                "-oJ",
                temp_file,  # JSON output
                target,
            ]

            # Create progress display for masscan without Live wrapper
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
            if os.path.exists(temp_file):
                with open(temp_file) as f:
                    data = f.read()
                    if data.strip():
                        results = []
                        for line in data.strip().split("\n"):
                            if line.strip() and line != "{" and line != "}":
                                try:
                                    entry = json.loads(line.rstrip(","))
                                    results.append(entry)
                                except json.JSONDecodeError:
                                    continue
                        return results
            return []
            
        finally:
            # Clean up temp file
            if os.path.exists(temp_file):
                try:
                    subprocess.run(["sudo", "rm", temp_file], capture_output=True)
                except:
                    pass

    def _run_arp_scan(self, target: str) -> List[Dict]:
        """Run arp-scan for layer 2 discovery with progress"""
        show_details = self.config["scanners"].get("progress_details", False)
        refresh_rate = self.config["scanners"].get("progress_refresh_rate", 4)
        
        try:
            cmd = ["sudo", "arp-scan", "--localnet", "--retry=2"]
            
            # Add target if specified
            if "/" in target:
                cmd = ["sudo", "arp-scan", target, "--retry=2"]

            # Create progress display without Live wrapper
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
            raise Exception(f"ARP scan failed: {e}")
        except FileNotFoundError:
            raise Exception("arp-scan not found. Install with: sudo apt install arp-scan")

    def _parse_nmap_xml(self, xml_file: str) -> List[Dict]:
        """Parse nmap XML output"""
        tree = ET.parse(xml_file)
        root = tree.getroot()

        devices = []
        for host in root.findall(".//host"):
            if host.find('.//status[@state="up"]') is None:
                continue

            device = {
                "ip": "",
                "mac": "",
                "hostname": "",
                "open_ports": [],
                "services": [],
                "os": "",
                "vendor": "",
            }

            # IP address
            ipv4 = host.find('.//address[@addrtype="ipv4"]')
            if ipv4 is not None:
                device["ip"] = ipv4.get("addr")

            # MAC address
            mac_elem = host.find('.//address[@addrtype="mac"]')
            if mac_elem is not None:
                device["mac"] = mac_elem.get("addr", "")
                device["vendor"] = mac_elem.get("vendor", "")

            # Hostname
            hostname_elem = host.find(".//hostname")
            if hostname_elem is not None:
                device["hostname"] = hostname_elem.get("name", "")

            # Ports and services
            for port in host.findall(".//port"):
                if port.find('.//state[@state="open"]') is not None:
                    port_id = int(port.get("portid"))
                    device["open_ports"].append(port_id)

                    service = port.find(".//service")
                    if service is not None:
                        service_name = service.get("name", "unknown")
                        device["services"].append(f"{service_name}:{port_id}")

            # OS detection
            osmatch = host.find(".//osmatch")
            if osmatch is not None:
                device["os"] = osmatch.get("name", "")

            if device["ip"]:  # Only add if we have an IP
                devices.append(device)

        return devices