"""
Nmap scanner implementation following the scanner interface.

This module provides a clean implementation of the nmap scanner with proper
separation of concerns and modular design.
"""
import subprocess
import logging
import time
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any
from pathlib import Path

from ..interfaces.scanner import Scanner, ScanOptions, ScanProgress, ScanType
from ...utils.exceptions import ScannerError, PermissionError
from ...infrastructure.config.scan_profiles import ScanProfile, get_scan_profile


logger = logging.getLogger(__name__)


class NmapScanner(Scanner):
    """
    Nmap scanner implementation.
    
    This scanner uses nmap for comprehensive network scanning with support
    for various scan types and progress tracking.
    """
    
    def __init__(self, progress_callback=None):
        """Initialize nmap scanner."""
        super().__init__(progress_callback)
        self._process: Optional[subprocess.Popen] = None
        self._start_time: Optional[float] = None
    
    def scan(self, options: ScanOptions) -> Dict[str, Any]:
        """
        Execute nmap scan with given options.
        
        Args:
            options: Scan configuration
            
        Returns:
            Parsed scan results
            
        Raises:
            ScannerError: If scan fails
            PermissionError: If insufficient permissions
        """
        self.validate_options(options)
        
        # Get scan profile
        profile = get_scan_profile(options.scan_type)
        
        # Build command
        cmd = self._build_command(options, profile)
        
        # Execute scan
        self._start_time = time.time()
        
        try:
            # Check permissions
            if self._requires_sudo(options) and not self._check_sudo():
                raise PermissionError("This scan type requires sudo privileges")
            
            # Run scan with progress tracking
            results = self._execute_scan(cmd, options)
            
            # Parse results
            return self._parse_results(results)
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Nmap scan failed: {e}")
            raise ScannerError(f"Nmap scan failed: {e.stderr.decode()}") from e
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
            raise ScannerError(f"Scan failed: {str(e)}") from e
        finally:
            self._process = None
    
    def validate_options(self, options: ScanOptions) -> None:
        """Validate scan options."""
        if not options.targets:
            raise ValueError("No targets specified for scan")
        
        # Validate targets
        for target in options.targets:
            if not self._is_valid_target(target):
                raise ValueError(f"Invalid target: {target}")
        
        # Validate scan type
        if options.scan_type not in ScanType:
            raise ValueError(f"Invalid scan type: {options.scan_type}")
    
    def is_available(self) -> bool:
        """Check if nmap is installed."""
        try:
            result = subprocess.run(
                ['nmap', '--version'],
                capture_output=True,
                text=True,
                check=True
            )
            return 'Nmap' in result.stdout
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def get_required_permissions(self, options: ScanOptions) -> List[str]:
        """Get required permissions for scan type."""
        permissions = []
        
        if options.scan_type in [ScanType.INVENTORY, ScanType.DEEP, ScanType.ARP]:
            permissions.append('sudo')
        
        if options.scan_type == ScanType.ARP:
            permissions.append('cap_net_raw')
        
        return permissions
    
    def get_version(self) -> str:
        """Get nmap version."""
        try:
            result = subprocess.run(
                ['nmap', '--version'],
                capture_output=True,
                text=True,
                check=True
            )
            # Extract version from output
            match = re.search(r'Nmap version (\d+\.\d+)', result.stdout)
            return match.group(1) if match else "Unknown"
        except:
            return "Unknown"
    
    def cancel(self) -> None:
        """Cancel ongoing scan."""
        super().cancel()
        if self._process:
            self._process.terminate()
            time.sleep(1)
            if self._process.poll() is None:
                self._process.kill()
    
    def _build_command(self, options: ScanOptions, profile: ScanProfile) -> List[str]:
        """Build nmap command from options and profile."""
        cmd = []
        
        # Add sudo if required
        if self._requires_sudo(options):
            cmd.append('sudo')
        
        cmd.append('nmap')
        
        # Add profile arguments
        cmd.extend(profile.nmap_args)
        
        # Add interface if specified
        if options.interface:
            cmd.extend(['-e', options.interface])
        
        # Add custom ports if specified
        if options.ports:
            cmd.extend(['-p', options.ports])
        
        # Add timing/rate options
        if options.max_rate:
            cmd.extend(['--max-rate', str(options.max_rate)])
        
        # Output format
        cmd.extend(['-oX', '-'])  # XML to stdout
        
        # Add extra arguments
        if options.extra_args:
            cmd.extend(options.extra_args)
        
        # Add targets
        cmd.extend(options.targets)
        
        # Add exclusions
        if options.exclude_targets:
            cmd.extend(['--exclude', ','.join(options.exclude_targets)])
        
        return cmd
    
    def _execute_scan(self, cmd: List[str], options: ScanOptions) -> str:
        """Execute scan command with progress tracking."""
        logger.info(f"Executing: {' '.join(cmd)}")
        
        # Start process
        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        output_lines = []
        discovered_hosts = 0
        current_host = None
        
        # Process output line by line
        for line in self._process.stdout:
            output_lines.append(line)
            
            if self._is_cancelled:
                self._process.terminate()
                raise ScannerError("Scan cancelled by user")
            
            # Parse progress from output
            progress = self._parse_progress(line, discovered_hosts, current_host)
            if progress:
                self.update_progress(progress)
                
                # Update tracking variables
                if 'Discovered' in line:
                    discovered_hosts += 1
                if 'Scanning' in line:
                    match = re.search(r'Scanning ([^\s]+)', line)
                    if match:
                        current_host = match.group(1)
        
        # Wait for completion
        self._process.wait()
        
        if self._process.returncode != 0:
            stderr = self._process.stderr.read()
            raise subprocess.CalledProcessError(
                self._process.returncode,
                cmd,
                stderr=stderr.encode()
            )
        
        return ''.join(output_lines)
    
    def _parse_progress(
        self, 
        line: str, 
        discovered_hosts: int,
        current_host: Optional[str]
    ) -> Optional[ScanProgress]:
        """Parse progress information from nmap output."""
        elapsed = time.time() - self._start_time
        
        # Host discovery phase
        if "Starting Nmap" in line:
            return ScanProgress(
                current=0,
                total=100,
                percentage=0,
                phase="initialization",
                message="Starting scan...",
                elapsed_time=elapsed
            )
        
        # Scanning phase
        if "Scanning" in line and current_host:
            # Estimate progress based on discovered hosts
            estimated_total = max(discovered_hosts * 1.2, 10)
            percentage = min(95, (discovered_hosts / estimated_total) * 100)
            
            return ScanProgress(
                current=discovered_hosts,
                total=int(estimated_total),
                percentage=percentage,
                phase="scanning",
                message=f"Scanning {current_host}",
                elapsed_time=elapsed
            )
        
        # Completion
        if "Nmap done" in line:
            match = re.search(r'(\d+) IP address.*scanned in ([0-9.]+) seconds', line)
            if match:
                total_hosts = int(match.group(1))
                return ScanProgress(
                    current=total_hosts,
                    total=total_hosts,
                    percentage=100,
                    phase="complete",
                    message=f"Scan complete: {total_hosts} hosts",
                    elapsed_time=elapsed
                )
        
        return None
    
    def _parse_results(self, xml_output: str) -> Dict[str, Any]:
        """Parse nmap XML output into structured results."""
        try:
            root = ET.fromstring(xml_output)
            
            hosts = []
            for host_elem in root.findall('.//host'):
                host_data = self._parse_host(host_elem)
                if host_data:
                    hosts.append(host_data)
            
            # Extract scan metadata
            scan_info = root.find('scaninfo')
            run_stats = root.find('runstats')
            
            return {
                'hosts': hosts,
                'scan_info': {
                    'type': scan_info.get('type') if scan_info is not None else None,
                    'protocol': scan_info.get('protocol') if scan_info is not None else None,
                    'services': scan_info.get('services') if scan_info is not None else None
                },
                'stats': {
                    'hosts_up': run_stats.find('.//hosts').get('up') if run_stats else 0,
                    'hosts_down': run_stats.find('.//hosts').get('down') if run_stats else 0,
                    'elapsed': run_stats.find('.//elapsed').get('elapsed') if run_stats else 0
                }
            }
        except ET.ParseError as e:
            logger.error(f"Failed to parse nmap XML: {e}")
            raise ScannerError(f"Invalid scan output: {e}") from e
    
    def _parse_host(self, host_elem: ET.Element) -> Optional[Dict[str, Any]]:
        """Parse individual host from XML."""
        # Get IP address
        addr_elem = host_elem.find('.//address[@addrtype="ipv4"]')
        if addr_elem is None:
            return None
        
        host_data = {
            'ip': addr_elem.get('addr'),
            'status': host_elem.find('status').get('state'),
            'ports': []
        }
        
        # Get MAC address
        mac_elem = host_elem.find('.//address[@addrtype="mac"]')
        if mac_elem is not None:
            host_data['mac'] = mac_elem.get('addr')
            host_data['vendor'] = mac_elem.get('vendor', '')
        
        # Get hostname
        hostname_elem = host_elem.find('.//hostname')
        if hostname_elem is not None:
            host_data['hostname'] = hostname_elem.get('name')
        
        # Get OS information
        os_match = host_elem.find('.//osmatch')
        if os_match is not None:
            host_data['os'] = os_match.get('name')
            host_data['os_accuracy'] = int(os_match.get('accuracy', 0))
        
        # Get ports
        for port_elem in host_elem.findall('.//port'):
            port_data = self._parse_port(port_elem)
            if port_data:
                host_data['ports'].append(port_data)
        
        return host_data
    
    def _parse_port(self, port_elem: ET.Element) -> Optional[Dict[str, Any]]:
        """Parse port information from XML."""
        state_elem = port_elem.find('state')
        if state_elem is None or state_elem.get('state') != 'open':
            return None
        
        port_data = {
            'port': int(port_elem.get('portid')),
            'protocol': port_elem.get('protocol'),
            'state': state_elem.get('state')
        }
        
        # Get service information
        service_elem = port_elem.find('service')
        if service_elem is not None:
            port_data['service'] = service_elem.get('name')
            port_data['product'] = service_elem.get('product')
            port_data['version'] = service_elem.get('version')
            port_data['extra_info'] = service_elem.get('extrainfo')
        
        return port_data
    
    def _requires_sudo(self, options: ScanOptions) -> bool:
        """Check if scan requires sudo privileges."""
        return options.scan_type in [
            ScanType.INVENTORY, 
            ScanType.DEEP, 
            ScanType.ARP
        ]
    
    def _check_sudo(self) -> bool:
        """Check if we have sudo privileges."""
        try:
            result = subprocess.run(
                ['sudo', '-n', 'true'],
                capture_output=True,
                check=False
            )
            return result.returncode == 0
        except:
            return False
    
    def _is_valid_target(self, target: str) -> bool:
        """Validate target format."""
        # Simple validation - could be enhanced
        import ipaddress
        
        try:
            # Try as IP address or network
            ipaddress.ip_network(target, strict=False)
            return True
        except:
            # Could be hostname - basic check
            return bool(re.match(r'^[a-zA-Z0-9.-]+$', target))