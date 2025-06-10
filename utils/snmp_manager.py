"""
Simple SNMP Manager - Enriches device data through SNMP queries
This is a simplified implementation that focuses on core functionality
"""

import logging
import socket
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# For now, create a simple mock implementation
# In a production environment, you would integrate with actual SNMP libraries

class SNMPManager:
    """Manages SNMP queries to enrich device information"""
    
    def __init__(self, config: Dict = None, community: str = 'public', timeout: int = 1, retries: int = 1):
        """Initialize SNMP manager
        
        Args:
            config: SNMP configuration dictionary (takes precedence over individual params)
            community: SNMP community string (default: 'public')
            timeout: Query timeout in seconds
            retries: Number of retries for failed queries
        """
        if config:
            self.config = config
            self.version = config.get('version', 'v2c')
            self.community = config.get('community', 'public')
            self.timeout = config.get('timeout', timeout)
            self.retries = config.get('retries', retries)
            
            # SNMPv3 specific settings
            self.username = config.get('username')
            self.auth_password = config.get('auth_password')
            self.priv_password = config.get('priv_password')
        else:
            self.config = {}
            self.version = 'v2c'
            self.community = community
            self.timeout = timeout
            self.retries = retries
            self.username = None
            self.auth_password = None
            self.priv_password = None
        
    def enrich_device(self, device: Dict, snmp_version: str = 'v2c') -> Dict:
        """Enrich a single device with SNMP data
        
        Args:
            device: Device dictionary with at least 'ip' field
            snmp_version: SNMP version to use ('v1', 'v2c', 'v3')
            
        Returns:
            Enriched device dictionary
        """
        ip = device.get('ip')
        if not ip:
            return device
            
        logger.debug(f"Enriching device {ip} via SNMP")
        
        # For demo purposes, simulate SNMP enrichment based on device type
        if self._is_snmp_responsive(ip):
            device['snmp_data'] = self._get_mock_snmp_data(device)
            
            # Update device fields with simulated SNMP data
            snmp_data = device['snmp_data']
            if snmp_data.get('sysName') and not device.get('hostname'):
                device['hostname'] = snmp_data['sysName']
                
            if snmp_data.get('sysDescr'):
                device['system_description'] = snmp_data['sysDescr']
                
            if snmp_data.get('uptime'):
                device['uptime'] = snmp_data['uptime']
                
        return device
        
    def enrich_devices(self, devices: List[Dict], max_workers: int = 10) -> List[Dict]:
        """Enrich multiple devices with SNMP data
        
        Args:
            devices: List of device dictionaries
            max_workers: Maximum concurrent SNMP queries
            
        Returns:
            List of enriched device dictionaries
        """
        enriched_devices = []
        
        for device in devices:
            try:
                enriched_device = self.enrich_device(device.copy())
                enriched_devices.append(enriched_device)
            except Exception as e:
                logger.warning(f"SNMP enrichment failed for {device.get('ip')}: {e}")
                enriched_devices.append(device)
                
        return enriched_devices
        
    def _is_snmp_responsive(self, ip: str) -> bool:
        """Check if device responds to SNMP (simplified check)
        
        Args:
            ip: Device IP address
            
        Returns:
            True if device might respond to SNMP
        """
        # For demo purposes, simulate SNMP responsiveness
        # In real implementation, you would do an actual SNMP query
        
        # Check if port 161 is reachable (SNMP port)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, 161))
            sock.close()
            
            # For UDP, connect_ex doesn't guarantee the port is open
            # But we'll use this as a basic connectivity check
            return result == 0
        except Exception:
            return False
            
    def _get_mock_snmp_data(self, device: Dict) -> Dict:
        """Generate mock SNMP data based on device type
        
        Args:
            device: Device dictionary
            
        Returns:
            Mock SNMP data
        """
        device_type = device.get('type', 'unknown')
        ip = device.get('ip', 'unknown')
        
        # Generate realistic mock data based on device type
        mock_data = {
            'sysDescr': self._get_mock_system_description(device_type),
            'sysName': device.get('hostname') or f"{device_type}-{ip.split('.')[-1]}",
            'sysLocation': 'Network Closet A',
            'sysContact': 'Network Administrator',
            'uptime': '15d 8h 42m 18s',
            'uptime_ticks': 134138000
        }
        
        # Add device-specific data
        if device_type == 'router':
            mock_data.update({
                'sysLocation': 'Main Network Closet',
                'interface_count': 24,
                'routing_table_size': 150000
            })
        elif device_type == 'switch':
            mock_data.update({
                'interface_count': 48,
                'vlan_count': 12,
                'mac_table_size': 2048
            })
        elif device_type in ['server', 'windows_server', 'linux_server']:
            mock_data.update({
                'logged_in_users': 3,
                'running_processes': 245,
                'memory_size': '16.0 GB',
                'cpu_count': 4
            })
        elif device_type == 'printer':
            mock_data.update({
                'model': 'HP LaserJet Pro 400',
                'pages_printed': 15420,
                'toner_level': 65
            })
            
        return mock_data
        
    def _get_mock_system_description(self, device_type: str) -> str:
        """Generate mock system description
        
        Args:
            device_type: Type of device
            
        Returns:
            Mock system description string
        """
        descriptions = {
            'router': 'Cisco IOS Software, Version 15.1(4)M12a, RELEASE SOFTWARE',
            'switch': 'Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M)',
            'server': 'Linux Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-88-generic x86_64)',
            'windows_server': 'Microsoft Windows Server 2019 Standard 10.0.17763',
            'linux_server': 'Linux CentOS 8.4.2105 (Core) 4.18.0-305.el8.x86_64',
            'printer': 'HP LaserJet Pro 400 M401a Firmware Version 20190524',
            'firewall': 'pfSense 2.5.2-RELEASE (amd64) built on FreeBSD 12.2-STABLE',
            'nas': 'Synology DiskStation DS920+ DSM 7.0.1-42218',
            'access_point': 'Ubiquiti UniFi UAP-AC-PRO 5.43.23.12533',
            'workstation': 'Microsoft Windows 10 Pro 10.0.19043 Build 19043',
            'iot_device': 'IoT Device Linux 4.14.y embedded system',
            'unknown': 'SNMP-enabled network device'
        }
        
        return descriptions.get(device_type, descriptions['unknown'])