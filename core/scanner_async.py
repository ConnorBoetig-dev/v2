import asyncio
import concurrent.futures
import ipaddress
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
from typing import Any, Dict, List, Optional, Tuple, Union
from functools import partial

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


class AsyncNetworkScanner:
    """Asynchronous network scanner with parallel execution capabilities"""
    
    def __init__(self):
        # Preserve all existing initialization
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
                "nmap": ["-PR", "-sS", "-sV", "-O", "--top-ports", "5000", "--script", "default"],
                "description": "Deep scan with top 5000 ports + ARP discovery",
            },
            "fast": {
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
                "masscan": ["-p21-23,25,53,67,69,80-81,88,110-111,123,135,137-139,143,161,389,443,445,465,514,515,548,554,587,593,631,636,873,902,993,995,1025-1029,1080,1194,1337,1433-1434,1521,1604,1645,1701,1723,1755,1812-1813,1883,1900,2049,2082-2083,2086-2087,2095-2096,2121,2181,2222,2375,2376,2404,3000,3128,3260,3268-3269,3283,3306,3333,3389-3390,3478,3689,3690,3784,4000,4040,4045,4443,4444,4567,4662,4848,4899,5000-5010,5060-5061,5093,5351,5353,5355,5432,5500,5555,5632,5800,5900-5910,5984-5986,6000-6009,6379,6514,6660-6669,6881,6969,7000-7002,7070,7077,7100,7144,7145,7262,7272,7474,7777,7778,8000-8014,8016,8018,8020-8022,8025,8028,8030-8032,8036,8038,8040-8082,8084-8100,8180-8181,8192,8222,8243,8280,8281,8333,8337,8388,8400,8443-8445,8500,8530-8531,8765,8766,8787,8800,8808,8843,8880,8883,8888,8899,8983,9000-9003,9009,9043,9050,9080-9081,9090-9091,9100,9110,9200,9290,9300,9418,9443,9500,9502,9503,9535,9800,9981,9998-10001,10022-10025,10050,10080,10082,10180,10215,10243,10443,10616-10626,11110-11111,11211,12345,13579,13720-13722,14000,15000,16080,16992-16993,17988,18080,18264,19226,19350,19780,19999-20000,20031,20222,22222,23023,25565,27015,27017-27019,27374,28017,30000,30718,31337,32768,32769,32771,32815,33899,34571-34573,35500,37777,40000,41080,44818,47808,49152-49156,50000,50050,50070,50100,51106,55020,55055,55555,55600,58080,60008,60020,62078,64738,U:53,U:67-69,U:111,U:123,U:135,U:137-138,U:161,U:177,U:445,U:500,U:514,U:520,U:631,U:1434,U:1604,U:1701,U:1900,U:2049,U:4500,U:5060,U:5353,U:5632,U:9200,U:10000,U:17185,U:31337,U:44818,U:47808,U:49152-49154"],
                "nmap": [
                    "-sS",
                    "-sV",
                    "-O",
                    "--osscan-guess",
                    "--version-intensity",
                    "5",
                    "--top-ports",
                    "500",
                    "-T3",
                    "--script-timeout",
                    "10s",
                ],
                "description": "Deeper scan for more accurate OS/service detection",
            },
            "os_detect": {
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
        self._scanner_availability = {}
        
        # New async-specific attributes
        self._scan_semaphore = asyncio.Semaphore(32)  # Limit concurrent subnet scans
        self._enrich_semaphore = asyncio.Semaphore(16)  # Limit concurrent enrichment
        self._snmp_semaphore = asyncio.Semaphore(8)  # Limit concurrent SNMP queries
        self._progress_lock = asyncio.Lock()  # Thread-safe progress updates
        self._results_lock = asyncio.Lock()  # Thread-safe results merging
        self._temp_files_lock = threading.Lock()  # Thread-safe temp file tracking
        self._temp_files = []  # Track temp files for cleanup
        
    def _load_config(self):
        """Load configuration from config.yaml"""
        config_path = Path(__file__).parent.parent / "config.yaml"
        if config_path.exists():
            with open(config_path) as f:
                return yaml.safe_load(f)
        else:
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
    
    async def scan(
        self,
        target: str,
        scan_type: str = "discovery",
        use_masscan: bool = False,
        needs_root: bool = False,
        snmp_config: Dict = None,
    ) -> List[Dict]:
        """Execute network scan with parallel execution"""
        
        # Fast and deeper scan modes use masscan + enrichment approach
        if scan_type == "fast":
            return await self._run_fast_scan_async(target)
        
        if scan_type == "deeper":
            return await self._run_deeper_scan_async(target)
        
        # For large networks, split into subnets for parallel scanning
        subnets = self._split_target_into_subnets(target)
        
        if len(subnets) > 1:
            self.console.print(f"[cyan]🔀 Splitting scan into {len(subnets)} parallel subnet scans[/cyan]")
        
        # Run subnet scans in parallel
        scan_tasks = []
        for subnet in subnets:
            if scan_type == "discovery":
                task = self._scan_subnet_discovery(subnet, use_masscan, needs_root)
            else:
                task = self._scan_subnet_detailed(subnet, scan_type, needs_root)
            scan_tasks.append(task)
        
        # Execute all subnet scans concurrently
        subnet_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
        
        # Merge results from all subnets
        devices = []
        for result in subnet_results:
            if isinstance(result, Exception):
                logger.error(f"Subnet scan failed: {result}")
            elif result:
                devices.extend(result)
        
        # Deduplicate devices
        devices = self._deduplicate_devices(devices)
        
        # Enrich with SNMP if requested
        if snmp_config and SNMP_AVAILABLE and devices:
            devices = await self._enrich_with_snmp_async(devices, snmp_config)
        
        return devices
    
    def _split_target_into_subnets(self, target: str) -> List[str]:
        """Split a large network into smaller subnets for parallel scanning"""
        try:
            network = ipaddress.ip_network(target, strict=False)
            
            # For single hosts or small networks, don't split
            if network.num_addresses <= 256:
                return [target]
            
            # Calculate optimal subnet size based on network size
            if network.num_addresses <= 1024:  # /22 or smaller
                # Split into /24s
                prefix_len = 24
            elif network.num_addresses <= 4096:  # /20 or smaller
                # Split into /24s
                prefix_len = 24
            elif network.num_addresses <= 16384:  # /18 or smaller
                # Split into /22s
                prefix_len = 22
            else:
                # Split into /20s for very large networks
                prefix_len = 20
            
            # Don't create subnets smaller than the original
            if prefix_len <= network.prefixlen:
                return [target]
            
            # Generate subnets
            subnets = []
            for subnet in network.subnets(new_prefix=prefix_len):
                subnets.append(str(subnet))
            
            # Limit to reasonable number of parallel scans
            if len(subnets) > 64:
                # Group smaller subnets together
                grouped = []
                group_size = len(subnets) // 32
                for i in range(0, len(subnets), group_size):
                    # Join multiple subnets into a single target
                    group = subnets[i:i+group_size]
                    grouped.append(" ".join(group))
                return grouped
            
            return subnets
            
        except ValueError:
            # Not a valid network, return as-is
            return [target]
    
    async def _scan_subnet_discovery(self, subnet: str, use_masscan: bool, needs_root: bool) -> List[Dict]:
        """Scan a subnet for discovery with semaphore limiting"""
        async with self._scan_semaphore:
            if use_masscan:
                return await self._run_masscan_async(subnet)
            else:
                # Check if local subnet
                if self._is_local_subnet(subnet):
                    # Run ARP and nmap in parallel
                    arp_task = None
                    if self._check_scanner_available("arp-scan"):
                        arp_task = self._run_arp_scan_async(subnet)
                    
                    nmap_task = self._run_nmap_async(subnet, "discovery", needs_root)
                    
                    if arp_task:
                        results = await asyncio.gather(arp_task, nmap_task, return_exceptions=True)
                        arp_devices = results[0] if not isinstance(results[0], Exception) else []
                        nmap_devices = results[1] if not isinstance(results[1], Exception) else []
                        return self._merge_scan_results(arp_devices, nmap_devices)
                    else:
                        return await nmap_task
                else:
                    return await self._run_nmap_async(subnet, "discovery", needs_root)
    
    async def _scan_subnet_detailed(self, subnet: str, scan_type: str, needs_root: bool) -> List[Dict]:
        """Scan a subnet with detailed scanning"""
        async with self._scan_semaphore:
            return await self._run_nmap_async(subnet, scan_type, needs_root)
    
    async def _run_nmap_async(self, target: str, scan_type: str, needs_root: bool) -> List[Dict]:
        """Run nmap scan asynchronously with real-time progress"""
        profile = self.scan_profiles[scan_type]
        show_details = self.config["scanners"].get("progress_details", False)
        stats_interval = self.config["scanners"].get("nmap_stats_interval", "1s")
        
        # Check nmap availability
        if not self._check_scanner_available("nmap"):
            raise Exception("nmap not found. Please install nmap: sudo apt install nmap")
        
        # Ensure sudo access if needed
        if needs_root:
            if not await self._ensure_sudo_access_async():
                raise Exception("Failed to obtain sudo access")
        
        # Create temp file
        temp_path = self._create_temp_file("nmap", ".xml")
        
        try:
            # Build command
            cmd = ["nmap", "-oX", temp_path, "--stats-every", stats_interval]
            cmd.append(self.config["scanners"].get("nmap_timing", "-T4"))
            
            if scan_type == "discovery":
                cmd.append("-n")  # Skip DNS for speed
            
            cmd.extend(profile["nmap"])
            cmd.append(target)
            
            if needs_root:
                cmd = ["sudo", "-n"] + cmd
            
            # Create subprocess
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Parse output in real-time
            devices_found = 0
            async for line in process.stdout:
                line = line.decode().strip()
                
                if show_details and line:
                    self.console.print(f"[dim]{line}[/dim]")
                
                # Update progress based on output
                if "Nmap scan report for" in line:
                    devices_found += 1
                    async with self._progress_lock:
                        self.hosts_completed += 1
                        self.console.print(f"[green]Found device: {line}[/green]")
            
            # Wait for completion
            await process.wait()
            
            if process.returncode != 0:
                stderr = await process.stderr.read()
                raise Exception(f"Nmap failed: {stderr.decode()}")
            
            # Parse XML results
            return self._parse_nmap_xml(temp_path)
            
        finally:
            self._cleanup_temp_file(temp_path, needs_sudo=needs_root)
    
    async def _run_masscan_async(self, target: str) -> List[Dict]:
        """Run masscan asynchronously"""
        if not self._check_scanner_available("masscan"):
            raise RuntimeError("masscan not found")
        
        # Ensure sudo
        if not await self._ensure_sudo_access_async():
            raise RuntimeError("Masscan requires sudo access")
        
        temp_file = self._create_temp_file("masscan", ".json")
        
        try:
            # Calculate scan rate based on network size
            total_hosts = self._estimate_total_hosts(target)
            scan_rate = 50000 if total_hosts > 10000 else 25000
            
            cmd = [
                "sudo", "-n", "masscan",
                f"-p80,443,22,445,3389,8080,21,23,25,53,135,139,161",
                f"--rate={scan_rate}",
                "-oJ", temp_file,
                "--wait", "3",
                "--open-only",
                target
            ]
            
            # Add interface if available
            interface = self._get_best_interface_for_target(target)
            if interface:
                cmd.extend(["-e", interface])
            
            # Run masscan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Monitor output
            devices_found = 0
            async for line in process.stdout:
                line = line.decode().strip()
                if "found=" in line:
                    match = re.search(r"found=(\d+)", line)
                    if match:
                        devices_found = int(match.group(1))
                        self.console.print(f"[cyan]Masscan: {devices_found} hosts found[/cyan]")
            
            await process.wait()
            
            if process.returncode != 0:
                stderr = await process.stderr.read()
                raise RuntimeError(f"Masscan failed: {stderr.decode()}")
            
            # Parse results
            return self._parse_masscan_output(temp_file)
            
        finally:
            self._cleanup_temp_file(temp_file, needs_sudo=True)
    
    async def _run_arp_scan_async(self, target: str) -> List[Dict]:
        """Run arp-scan asynchronously"""
        if not self._check_scanner_available("arp-scan"):
            raise RuntimeError("arp-scan not found")
        
        if not await self._ensure_sudo_access_async():
            raise RuntimeError("ARP scan requires sudo access")
        
        cmd = self._build_arp_scan_command(target)
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            devices = []
            async for line in process.stdout:
                line = line.decode().strip()
                
                # Parse arp-scan output
                match = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]+)\s+(.*)$", line)
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
                        "open_ports": [],
                    })
            
            await process.wait()
            return devices
            
        except Exception as e:
            logger.error(f"ARP scan error: {e}")
            raise RuntimeError(f"ARP scan failed: {e}")
    
    async def _run_fast_scan_async(self, target: str) -> List[Dict]:
        """Run fast scan mode for large networks"""
        self.console.print("[cyan]⚡ Fast scan mode for large networks[/cyan]")
        
        # Use masscan for discovery
        devices = await self._run_masscan_fast_async(target)
        
        if devices:
            # Parallel enrichment
            self.console.print(f"[cyan]📊 Enriching {len(devices)} discovered hosts...[/cyan]")
            devices = await self._enrich_fast_scan_async(devices)
        
        return devices
    
    async def _run_masscan_fast_async(self, target: str) -> List[Dict]:
        """Run masscan optimized for very large networks"""
        if not self._check_scanner_available("masscan"):
            return await self._run_masscan_async(target)
        
        total_hosts = self._estimate_total_hosts(target)
        
        # Configure for large networks
        if total_hosts > 50000:
            scan_rate = 100000
            ports = "80,443,22,445,3389,135,139,8080"
        else:
            scan_rate = 50000
            ports = "80,443,22,445,3389,8080,135,139,21,23,25,53,161"
        
        self.console.print(f"[cyan]🚀 Fast scanning {total_hosts:,} hosts at {scan_rate:,} packets/sec[/cyan]")
        self.console.print(f"[cyan]📍 Target ports: {ports}[/cyan]")
        self.console.print(f"[dim]Note: Progress updates may be intermittent during masscan phase[/dim]")
        
        if not await self._ensure_sudo_access_async():
            raise RuntimeError("Fast scan requires sudo access")
        
        temp_file = self._create_temp_file("masscan_fast", ".json")
        
        try:
            cmd = [
                "sudo", "-n", "masscan",
                f"-p{ports}",
                f"--rate={scan_rate}",
                "-oJ", temp_file,
                "--wait", "2",
                "--open-only",
                "--randomize-hosts",
                target
            ]
            
            # Create progress display
            from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]Masscan discovery[/bold cyan]"),
                BarColumn(complete_style="cyan", finished_style="cyan"),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                TextColumn("• {task.fields[status]}"),
                console=self.console,
                refresh_per_second=2,
                transient=False,
            ) as progress:
                task = progress.add_task(
                    f"Fast scanning {target}", total=100, status="Initializing masscan..."
                )
                
                start_time = time.time()
                devices_found = 0
                last_percent = 0
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                # Quick error check
                await asyncio.sleep(0.5)
                if process.returncode is not None:
                    stderr = await process.stderr.read()
                    if "sudo:" in stderr.decode():
                        raise RuntimeError("Sudo authentication failed")
                    raise RuntimeError(f"Masscan failed: {stderr.decode()}")
                
                # Process output with progress
                last_update_time = start_time
                no_output_count = 0
                
                while True:
                    try:
                        # Try to read line with timeout
                        line = await asyncio.wait_for(process.stdout.readline(), timeout=0.1)
                        
                        if not line:
                            if process.returncode is not None:
                                break
                            continue
                            
                        line = line.decode().strip()
                        
                        # Parse progress
                        if "found=" in line:
                            match = re.search(r"found=(\d+)", line)
                            if match:
                                devices_found = int(match.group(1))
                                no_output_count = 0  # Reset counter
                        
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
                                    status=f"Found {devices_found} hosts ({rate:.0f}/sec)"
                                )
                                last_update_time = time.time()
                                
                    except asyncio.TimeoutError:
                        # No output - update status periodically
                        current_time = time.time()
                        if current_time - last_update_time > 2:  # Update every 2 seconds
                            elapsed = int(current_time - start_time)
                            no_output_count += 1
                            
                            if no_output_count > 5:  # After 10 seconds
                                status = f"Scanning in progress... ({elapsed}s elapsed, no output from masscan)"
                            else:
                                status = f"Scanning in progress... ({elapsed}s elapsed)"
                            
                            progress.update(task, status=status)
                            last_update_time = current_time
                    
                    # Check if process finished
                    if process.returncode is not None:
                        break
                
                await process.wait()
                
                if process.returncode != 0:
                    stderr = await process.stderr.read()
                    raise RuntimeError(f"Masscan failed: {stderr.decode()}")
                
                progress.update(
                    task, completed=100, status=f"Complete: {devices_found} hosts found"
                )
            
            devices = self._parse_masscan_output(temp_file)
            self.console.print(f"[green]✓ Fast scan complete: {len(devices)} active hosts[/green]")
            
            return devices
            
        finally:
            self._cleanup_temp_file(temp_file, needs_sudo=True)
    
    async def _enrich_fast_scan_async(self, devices: List[Dict]) -> List[Dict]:
        """Enrich devices in parallel"""
        if not devices:
            return devices
        
        # Process in chunks for parallel enrichment
        chunk_size = 25
        total_chunks = (len(devices) + chunk_size - 1) // chunk_size
        
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold green]Enrichment[/bold green]"),
            BarColumn(complete_style="green", finished_style="green"),
            TaskProgressColumn(),
            TextColumn("• {task.fields[status]}"),
            console=self.console,
            transient=False
        ) as progress:
            task = progress.add_task(
                "Enriching devices",
                total=len(devices),
                status="Starting enrichment with DNS resolution..."
            )
            
            enriched_devices = []
            
            for i in range(0, len(devices), chunk_size):
                chunk = devices[i:i + chunk_size]
                chunk_num = i // chunk_size + 1
                
                progress.update(
                    task, 
                    completed=i, 
                    status=f"Processing chunk {chunk_num}/{total_chunks} ({chunk[0]['ip']} - {chunk[-1]['ip']})"
                )
                
                try:
                    enriched_chunk = await self._enrich_chunk_async(chunk)
                    enriched_devices.extend(enriched_chunk)
                    
                    # Update progress after chunk completion
                    progress.update(
                        task,
                        completed=min(i + len(chunk), len(devices)),
                        status=f"Completed chunk {chunk_num}/{total_chunks}"
                    )
                except Exception as e:
                    logger.error(f"Enrichment failed for chunk {chunk_num}: {e}")
                    enriched_devices.extend(chunk)  # Keep original data if enrichment fails
                    progress.update(
                        task,
                        status=f"Chunk {chunk_num} failed - continuing..."
                    )
            
            progress.update(task, completed=len(devices), status="Enrichment complete")
        
        return enriched_devices
    
    async def _run_deeper_scan_async(self, target: str) -> List[Dict]:
        """Run deeper scan mode for more accurate results"""
        self.console.print("[cyan]🔬 Deeper scan mode for comprehensive analysis[/cyan]")
        
        # Use masscan for discovery with more ports
        devices = await self._run_masscan_deeper_async(target)
        
        if devices:
            # Thorough enrichment
            self.console.print(f"[cyan]📊 Performing deep enrichment on {len(devices)} discovered hosts...[/cyan]")
            self.console.print("[cyan]🔍 This includes: Comprehensive OS detection, detailed service versions, and extended port scanning[/cyan]")
            devices = await self._enrich_deeper_scan_async(devices)
        
        return devices
    
    async def _run_masscan_deeper_async(self, target: str) -> List[Dict]:
        """Run masscan with extended port list for deeper scan"""
        # Just use the fast scan method - it will pick up the ports from the scan profile
        return await self._run_masscan_fast_async(target)
    
    async def _enrich_deeper_scan_async(self, devices: List[Dict]) -> List[Dict]:
        """Enrich devices with comprehensive nmap scanning"""
        if not devices:
            return devices
        
        # Use smaller chunks for more thorough scanning
        chunk_size = 10
        enriched_devices = []
        
        total_chunks = (len(devices) + chunk_size - 1) // chunk_size
        
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
            
            # Process chunks in parallel
            tasks = []
            for i in range(0, len(devices), chunk_size):
                chunk = devices[i:i+chunk_size]
                chunk_task = self._enrich_deeper_chunk_async(chunk, i//chunk_size, total_chunks)
                tasks.append(chunk_task)
            
            # Run all enrichment tasks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Collect results
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Deeper enrichment chunk {i} failed: {result}")
                    # Add original devices if enrichment failed
                    start_idx = i * chunk_size
                    end_idx = min(start_idx + chunk_size, len(devices))
                    enriched_devices.extend(devices[start_idx:end_idx])
                else:
                    enriched_devices.extend(result or [])
                
                progress.update(task, completed=min((i+1)*chunk_size, len(devices)))
            
            progress.update(task, completed=len(devices), status="Deep enrichment complete")
        
        self.console.print(f"[green]✓ Deep enrichment complete for {len(enriched_devices)} devices[/green]")
        
        return enriched_devices
    
    async def _enrich_deeper_chunk_async(self, chunk: List[Dict], chunk_idx: int, total_chunks: int) -> List[Dict]:
        """Enrich a chunk with deeper scanning"""
        async with self._enrich_semaphore:
            ips = [d["ip"] for d in chunk]
            
            self.console.print(f"[dim]Deep scanning chunk {chunk_idx + 1}/{total_chunks} ({len(ips)} IPs)[/dim]")
            
            temp_file = self._create_temp_file("nmap_deeper", ".xml")
            
            try:
                # Use deeper scan profile
                profile = self.scan_profiles["deeper"]
                cmd = ["sudo", "-n", "nmap"] + profile["nmap"] + ["-oX", temp_file] + ips
                
                # Run with longer timeout
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                # Wait with timeout
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
                except asyncio.TimeoutError:
                    proc.kill()
                    logger.warning(f"Deeper enrichment timeout for chunk {chunk_idx + 1}")
                    return chunk
                
                if proc.returncode == 0:
                    # Parse results
                    enriched = await asyncio.to_thread(self._parse_nmap_xml, temp_file)
                    
                    # Merge with original data
                    device_map = {d["ip"]: d for d in chunk}
                    merged = []
                    for e in enriched:
                        if e["ip"] in device_map:
                            original = device_map[e["ip"]]
                            e["open_ports"] = list(set(original.get("open_ports", []) + e.get("open_ports", [])))
                            merged.append(e)
                        else:
                            merged.append(e)
                    
                    # Add any devices that weren't in enrichment results
                    enriched_ips = {e["ip"] for e in enriched}
                    for d in chunk:
                        if d["ip"] not in enriched_ips:
                            merged.append(d)
                    
                    return merged
                else:
                    logger.warning(f"Deeper enrichment failed for chunk {chunk_idx + 1}: {stderr.decode()}")
                    return chunk
                    
            except Exception as e:
                logger.error(f"Deeper enrichment error: {e}")
                return chunk
            finally:
                self._cleanup_temp_file(temp_file, needs_sudo=True)
    
    async def _enrich_chunk_async(self, chunk: List[Dict]) -> List[Dict]:
        """Enrich a chunk of devices"""
        async with self._enrich_semaphore:
            # Extract IPs
            ips = [d["ip"] for d in chunk]
            target = " ".join(ips)
            
            temp_file = self._create_temp_file("nmap_enrich", ".xml")
            
            try:
                cmd = [
                    "sudo", "-n", "nmap",
                    "-sS", "-sV", "-O",
                    "--osscan-guess",
                    "--version-intensity", "0",
                    "-T5",
                    "--top-ports", "20",
                    "-oX", temp_file,
                    "--max-rtt-timeout", "100ms",
                    "--max-retries", "1",
                ] + ips
                
                # Show what we're doing
                self.console.print(f"[dim]Running nmap enrichment on {len(ips)} hosts...[/dim]")
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                # Set timeout for enrichment
                try:
                    await asyncio.wait_for(process.wait(), timeout=120)
                except asyncio.TimeoutError:
                    process.terminate()
                    await process.wait()
                    logger.warning(f"Enrichment timeout for chunk")
                    self.console.print(f"[yellow]⚠ Enrichment timeout for chunk - trying without OS detection[/yellow]")
                    
                    # Try again without OS detection for speed
                    cmd_no_os = [
                        "sudo", "-n", "nmap",
                        "-sS", "-sV",
                        "--version-intensity", "0",
                        "-T5",
                        "--top-ports", "10",
                        "-oX", temp_file,
                        "--max-rtt-timeout", "50ms",
                        "--max-retries", "0",
                    ] + ips
                    
                    process = await asyncio.create_subprocess_exec(
                        *cmd_no_os,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    
                    try:
                        await asyncio.wait_for(process.wait(), timeout=30)
                    except asyncio.TimeoutError:
                        process.terminate()
                        await process.wait()
                        return chunk
                
                if process.returncode == 0 and os.path.exists(temp_file):
                    enriched = self._parse_nmap_xml(temp_file)
                    enriched_map = {e["ip"]: e for e in enriched}
                    
                    # Merge enrichment data
                    for device in chunk:
                        if device["ip"] in enriched_map:
                            e = enriched_map[device["ip"]]
                            device.update({
                                "hostname": e.get("hostname", ""),
                                "os": e.get("os", ""),
                                "os_accuracy": e.get("os_accuracy", 0),
                                "services": e.get("services", []),
                                "vendor": e.get("vendor", device.get("vendor", "")),
                            })
                
                return chunk
                
            finally:
                self._cleanup_temp_file(temp_file, needs_sudo=True)
    
    async def _enrich_with_snmp_async(self, devices: List[Dict], snmp_config: Dict) -> List[Dict]:
        """Enrich devices with SNMP data asynchronously"""
        # Filter SNMP candidates
        snmp_candidates = [
            device for device in devices
            if device.get("type") in ["router", "switch", "server", "printer", "nas", "firewall"]
            or any(port in device.get("open_ports", []) for port in [161, 80, 443, 22])
        ]
        
        if not snmp_candidates:
            return devices
        
        self.console.print(f"\n[cyan]Enriching {len(snmp_candidates)} devices with SNMP...[/cyan]")
        
        # Create SNMP manager
        snmp_manager = SNMPManager(config=snmp_config)
        
        # Run SNMP queries in parallel with semaphore
        snmp_tasks = []
        for device in snmp_candidates:
            task = self._query_snmp_device_async(device, snmp_manager)
            snmp_tasks.append(task)
        
        enriched_results = await asyncio.gather(*snmp_tasks, return_exceptions=True)
        
        # Update devices with SNMP data
        enriched_map = {}
        for result in enriched_results:
            if isinstance(result, dict) and "ip" in result:
                enriched_map[result["ip"]] = result
        
        # Update original devices list
        for i, device in enumerate(devices):
            if device["ip"] in enriched_map:
                devices[i] = enriched_map[device["ip"]]
        
        return devices
    
    async def _query_snmp_device_async(self, device: Dict, snmp_manager: Any) -> Dict:
        """Query a single device for SNMP data"""
        async with self._snmp_semaphore:
            try:
                # Run SNMP query in thread pool to avoid blocking
                loop = asyncio.get_event_loop()
                enriched = await loop.run_in_executor(
                    None,
                    snmp_manager.enrich_device,
                    device
                )
                return enriched
            except Exception as e:
                logger.error(f"SNMP error for {device['ip']}: {e}")
                return device
    
    async def _ensure_sudo_access_async(self) -> bool:
        """Ensure sudo access asynchronously"""
        try:
            # Check if already have sudo
            process = await asyncio.create_subprocess_exec(
                "sudo", "-n", "true",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.wait()
            
            if process.returncode == 0:
                return True
            
            # Need to authenticate - this is tricky in async
            # For now, fall back to sync method
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._ensure_sudo_access)
            
        except Exception as e:
            logger.error(f"Sudo access error: {e}")
            return False
    
    def _deduplicate_devices(self, devices: List[Dict]) -> List[Dict]:
        """Remove duplicate devices from merged results"""
        seen = {}
        for device in devices:
            ip = device.get("ip")
            if ip:
                if ip not in seen:
                    seen[ip] = device
                else:
                    # Merge information from duplicate
                    existing = seen[ip]
                    # Merge services and ports
                    existing_services = set(existing.get("services", []))
                    new_services = set(device.get("services", []))
                    existing["services"] = list(existing_services | new_services)
                    
                    existing_ports = set(existing.get("open_ports", []))
                    new_ports = set(device.get("open_ports", []))
                    existing["open_ports"] = sorted(list(existing_ports | new_ports))
                    
                    # Use better OS detection if available
                    if device.get("os") and not existing.get("os"):
                        existing["os"] = device["os"]
                        existing["os_accuracy"] = device.get("os_accuracy", 0)
        
        return list(seen.values())
    
    # Reuse all existing helper methods from original scanner.py
    def _create_temp_file(self, prefix: str, suffix: str) -> str:
        """Create a unique temporary file (thread-safe)"""
        temp_dir = tempfile.gettempdir()
        unique_id = f"{os.getpid()}_{os.urandom(4).hex()}"
        filename = f"{prefix}_{unique_id}{suffix}"
        filepath = os.path.join(temp_dir, filename)
        
        # Track for cleanup
        with self._temp_files_lock:
            self._temp_files.append(filepath)
        
        return filepath
    
    def _cleanup_temp_file(self, filepath: str, needs_sudo: bool = False) -> None:
        """Safely clean up temporary file"""
        if not os.path.exists(filepath):
            return
        
        try:
            if needs_sudo and os.stat(filepath).st_uid == 0:
                subprocess.run(["sudo", "rm", filepath], capture_output=True, timeout=5)
            else:
                os.remove(filepath)
            
            # Remove from tracking
            with self._temp_files_lock:
                if filepath in self._temp_files:
                    self._temp_files.remove(filepath)
                    
        except Exception as e:
            logger.warning(f"Failed to remove temp file {filepath}: {e}")
    
    def cleanup_all_temp_files(self):
        """Clean up all tracked temp files"""
        with self._temp_files_lock:
            for filepath in self._temp_files[:]:
                self._cleanup_temp_file(filepath, needs_sudo=True)
            self._temp_files.clear()
    
    # Include all other helper methods from original scanner.py
    def _check_scanner_available(self, scanner: str) -> bool:
        """Check if a scanner is available on the system"""
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
    
    def _estimate_total_hosts(self, target: str) -> int:
        """Estimate number of hosts in target range"""
        if "/" in target:
            try:
                prefix = int(target.split("/")[1])
                if prefix == 32:
                    return 1
                elif prefix == 31:
                    return 2
                else:
                    return 2 ** (32 - prefix) - 2
            except:
                return 256
        else:
            return 1
    
    def _is_local_subnet(self, target: str) -> bool:
        """Check if target is a local subnet"""
        import ipaddress
        import socket
        
        try:
            if "/" in target:
                network = ipaddress.IPv4Network(target, strict=False)
            else:
                return True
            
            # Check common local ranges
            local_ranges = [
                ipaddress.IPv4Network("10.0.0.0/8"),
                ipaddress.IPv4Network("172.16.0.0/12"),
                ipaddress.IPv4Network("192.168.0.0/16"),
            ]
            
            for local_range in local_ranges:
                if network.overlaps(local_range):
                    return True
                    
        except Exception as e:
            logger.debug(f"Error checking if subnet is local: {e}")
        
        return False
    
    def _merge_scan_results(self, arp_devices: List[Dict], nmap_devices: List[Dict]) -> List[Dict]:
        """Merge results from multiple scanners"""
        merged = {}
        
        # Add ARP devices first
        for device in arp_devices:
            ip = device.get("ip")
            if ip:
                merged[ip] = device
        
        # Merge with nmap results
        for device in nmap_devices:
            ip = device.get("ip")
            if ip:
                if ip in merged:
                    existing = merged[ip]
                    # Keep ARP MAC if present
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
        """Determine the best network interface"""
        try:
            import subprocess
            
            result = subprocess.run(
                ["ip", "route", "get", target.split("/")[0]],
                capture_output=True,
                text=True,
                timeout=2,
            )
            
            if result.returncode == 0 and result.stdout:
                parts = result.stdout.split()
                if "dev" in parts:
                    dev_index = parts.index("dev")
                    if dev_index + 1 < len(parts):
                        return parts[dev_index + 1]
                        
        except Exception as e:
            logger.debug(f"Could not determine best interface: {e}")
        
        return None
    
    def _build_arp_scan_command(self, target: str) -> List[str]:
        """Build arp-scan command"""
        cmd = ["sudo", "-n", "arp-scan"]
        
        if target == "localnet" or not target:
            cmd.extend(["--localnet"])
        elif "/" in target:
            cmd.append(target)
        else:
            cmd.append(target)
        
        cmd.extend([
            "--retry=2",
            "--timeout=500",
            "--backoff=1.5",
        ])
        
        return cmd
    
    def _ensure_sudo_access(self):
        """Ensure we have sudo access before starting scan"""
        try:
            result = subprocess.run(["sudo", "-n", "true"], capture_output=True)
            if result.returncode == 0:
                return True
            
            self.console.print("\n[yellow]This scan requires administrator privileges.[/yellow]")
            self.console.print("[dim]You may be prompted for your password.[/dim]\n")
            
            result = subprocess.run(["sudo", "-v"])
            
            if result.returncode != 0:
                return False
            
            result = subprocess.run(["sudo", "-n", "true"], capture_output=True)
            return result.returncode == 0
            
        except Exception as e:
            self.console.print(f"[red]Error checking sudo access: {e}[/red]")
            return False
    
    def _parse_nmap_xml(self, xml_file: str) -> List[Dict]:
        """Parse nmap XML output"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(f"Failed to parse nmap XML: {e}")
            raise
        
        devices = []
        for host in root.findall(".//host"):
            if host.find('.//status[@state="up"]') is None:
                continue
            
            device = self._extract_host_info(host)
            if device.get("ip"):
                devices.append(device)
                logger.debug(f"Parsed device: {device['ip']}")
        
        logger.info(f"Parsed {len(devices)} devices from nmap XML")
        return devices
    
    def _extract_host_info(self, host_elem: ET.Element) -> Dict[str, Any]:
        """Extract device information from nmap host element"""
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
        
        # OS detection
        os_matches = host_elem.findall(".//osmatch")
        if os_matches:
            best_match = max(os_matches, key=lambda x: int(x.get("accuracy", 0)))
            device["os"] = best_match.get("name", "")
            device["os_accuracy"] = int(best_match.get("accuracy", 0))
        
        return device
    
    def _parse_masscan_output(self, json_file: str) -> List[Dict]:
        """Parse masscan JSON output"""
        if not os.path.exists(json_file):
            logger.warning(f"Masscan output file not found: {json_file}")
            return []
        
        devices = {}
        try:
            with open(json_file) as f:
                data = f.read()
                if not data.strip():
                    return []
                
                # Process line by line
                for line_num, line in enumerate(data.strip().split("\n"), 1):
                    line = line.strip()
                    
                    if not line or line in ["{}", "{ }", "[", "]", "[\n", "\n]", ","]:
                        continue
                    
                    try:
                        if line.endswith(","):
                            line = line[:-1]
                        
                        entry = json.loads(line)
                        
                        if not isinstance(entry, dict):
                            continue
                        
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
                            
                            if "ports" in entry and isinstance(entry["ports"], list):
                                for port_info in entry["ports"]:
                                    if isinstance(port_info, dict):
                                        port = port_info.get("port", 0)
                                        proto = port_info.get("proto", "tcp")
                                        status = port_info.get("status", "open")
                                        
                                        if port and (status == "open" or status == ""):
                                            if port not in devices[ip]["open_ports"]:
                                                devices[ip]["open_ports"].append(port)
                                                devices[ip]["services"].append(f"{proto}:{port}")
                    
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        logger.warning(f"Error processing masscan entry on line {line_num}: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Failed to parse masscan output: {e}")
        
        return list(devices.values())


# Backward compatibility wrapper
class NetworkScanner(AsyncNetworkScanner):
    """Synchronous wrapper for backward compatibility"""
    
    def scan(
        self,
        target: str,
        scan_type: str = "discovery", 
        use_masscan: bool = False,
        needs_root: bool = False,
        snmp_config: Dict = None,
    ) -> List[Dict]:
        """Synchronous scan method that runs async implementation"""
        # Create new event loop for sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Run async scan
            result = loop.run_until_complete(
                super().scan(target, scan_type, use_masscan, needs_root, snmp_config)
            )
            return result
        finally:
            # Clean up
            self.cleanup_all_temp_files()
            loop.close()