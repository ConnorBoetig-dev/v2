"""
SNMP Manager - Enriches device data through SNMP queries
"""

import logging
import socket
from typing import Dict, List, Optional, Tuple

from pysnmp.hlapi.v3arch.asyncio import (
    getCmd, nextCmd, 
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity
)
import asyncio

logger = logging.getLogger(__name__)


class SNMPManager:
    """Manages SNMP queries to enrich device information"""
    
    # Common OIDs
    OIDS = {
        # System information
        'sysDescr': '1.3.6.1.2.1.1.1.0',
        'sysObjectID': '1.3.6.1.2.1.1.2.0',
        'sysUpTime': '1.3.6.1.2.1.1.3.0',
        'sysContact': '1.3.6.1.2.1.1.4.0',
        'sysName': '1.3.6.1.2.1.1.5.0',
        'sysLocation': '1.3.6.1.2.1.1.6.0',
        'sysServices': '1.3.6.1.2.1.1.7.0',
        
        # Interface information
        'ifNumber': '1.3.6.1.2.1.2.1.0',
        'ifTable': '1.3.6.1.2.1.2.2.1',
        'ifDescr': '1.3.6.1.2.1.2.2.1.2',
        'ifType': '1.3.6.1.2.1.2.2.1.3',
        'ifSpeed': '1.3.6.1.2.1.2.2.1.5',
        'ifPhysAddress': '1.3.6.1.2.1.2.2.1.6',
        'ifAdminStatus': '1.3.6.1.2.1.2.2.1.7',
        'ifOperStatus': '1.3.6.1.2.1.2.2.1.8',
        
        # IP information
        'ipAddrTable': '1.3.6.1.2.1.4.20.1',
        'ipNetToMediaTable': '1.3.6.1.2.1.4.22.1',
        
        # Host resources (if available)
        'hrSystemUptime': '1.3.6.1.2.1.25.1.1.0',
        'hrSystemNumUsers': '1.3.6.1.2.1.25.1.5.0',
        'hrSystemProcesses': '1.3.6.1.2.1.25.1.6.0',
        'hrMemorySize': '1.3.6.1.2.1.25.2.2.0',
        'hrProcessorTable': '1.3.6.1.2.1.25.3.3.1',
        'hrStorageTable': '1.3.6.1.2.1.25.2.3.1',
        
        # Enterprise specific
        'enterprises': '1.3.6.1.4.1',
    }
    
    # Interface type mappings
    INTERFACE_TYPES = {
        1: 'other',
        6: 'ethernetCsmacd',
        9: 'iso88025TokenRing',
        15: 'fddi',
        23: 'ppp',
        24: 'softwareLoopback',
        32: 'frameRelay',
        37: 'atm',
        49: 'aal5',
        53: 'propVirtual',
        63: 'isdn',
        75: 'ethernetCsmacd100BaseTX',
        77: 'tdlc',
        81: 'ds0',
        82: 'ds1',
        83: 'e1',
        117: 'gigabitEthernet',
        127: 'docsCableMaclayer',
        131: 'tunnel',
        135: 'l2vlan',
        136: 'l3ipvlan',
        137: 'l3ipxvlan',
        141: 'mplsTunnel',
        142: 'mplsTransport',
        161: 'ieee8023adLag',
    }
    
    def __init__(self, community: str = 'public', timeout: int = 1, retries: int = 1):
        """Initialize SNMP manager
        
        Args:
            community: SNMP community string (default: 'public')
            timeout: Query timeout in seconds
            retries: Number of retries for failed queries
        """
        self.community = community
        self.timeout = timeout
        self.retries = retries
        
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
        
        # Get system information
        sys_info = self.get_system_info(ip, snmp_version)
        if sys_info:
            device['snmp_data'] = sys_info
            
            # Update device fields with SNMP data
            if sys_info.get('sysName') and not device.get('hostname'):
                device['hostname'] = sys_info['sysName']
                
            if sys_info.get('sysDescr'):
                device['system_description'] = sys_info['sysDescr']
                
            if sys_info.get('sysLocation'):
                device['location'] = sys_info['sysLocation']
                
            if sys_info.get('sysContact'):
                device['contact'] = sys_info['sysContact']
                
            if sys_info.get('uptime'):
                device['uptime'] = sys_info['uptime']
                
        # Get interface information
        interfaces = self.get_interfaces(ip, snmp_version)
        if interfaces:
            device['interfaces'] = interfaces
            device['interface_count'] = len(interfaces)
            
        # Get host resources (for servers/workstations)
        if device.get('type') in ['server', 'workstation', 'windows_server', 'linux_server']:
            host_info = self.get_host_resources(ip, snmp_version)
            if host_info:
                device['host_resources'] = host_info
                
        return device
        
    def enrich_devices(self, devices: List[Dict], max_workers: int = 10) -> List[Dict]:
        """Enrich multiple devices with SNMP data
        
        Args:
            devices: List of device dictionaries
            max_workers: Maximum concurrent SNMP queries
            
        Returns:
            List of enriched device dictionaries
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        enriched_devices = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit enrichment tasks
            future_to_device = {
                executor.submit(self.enrich_device, device.copy()): device 
                for device in devices
            }
            
            # Collect results
            for future in as_completed(future_to_device):
                try:
                    enriched_device = future.result()
                    enriched_devices.append(enriched_device)
                except Exception as e:
                    # If enrichment fails, return original device
                    original_device = future_to_device[future]
                    logger.warning(f"SNMP enrichment failed for {original_device.get('ip')}: {e}")
                    enriched_devices.append(original_device)
                    
        return enriched_devices
        
    def get_system_info(self, ip: str, version: str = 'v2c') -> Optional[Dict]:
        """Get basic system information via SNMP
        
        Args:
            ip: Device IP address
            version: SNMP version
            
        Returns:
            Dictionary with system information or None if failed
        """
        try:
            # Query system OIDs
            oids = [
                self.OIDS['sysDescr'],
                self.OIDS['sysObjectID'],
                self.OIDS['sysUpTime'],
                self.OIDS['sysContact'],
                self.OIDS['sysName'],
                self.OIDS['sysLocation'],
            ]
            
            results = self._snmp_get(ip, oids, version)
            if not results:
                return None
                
            sys_info = {}
            
            # Parse results
            if results.get(self.OIDS['sysDescr']):
                sys_info['sysDescr'] = str(results[self.OIDS['sysDescr']])
                
            if results.get(self.OIDS['sysObjectID']):
                sys_info['sysObjectID'] = str(results[self.OIDS['sysObjectID']])
                
            if results.get(self.OIDS['sysUpTime']):
                # Convert timeticks to human-readable format
                timeticks = int(results[self.OIDS['sysUpTime']])
                sys_info['uptime'] = self._format_uptime(timeticks)
                sys_info['uptime_ticks'] = timeticks
                
            if results.get(self.OIDS['sysContact']):
                sys_info['sysContact'] = str(results[self.OIDS['sysContact']])
                
            if results.get(self.OIDS['sysName']):
                sys_info['sysName'] = str(results[self.OIDS['sysName']])
                
            if results.get(self.OIDS['sysLocation']):
                sys_info['sysLocation'] = str(results[self.OIDS['sysLocation']])
                
            return sys_info
            
        except Exception as e:
            logger.error(f"Failed to get system info for {ip}: {e}")
            return None
            
    def get_interfaces(self, ip: str, version: str = 'v2c') -> Optional[List[Dict]]:
        """Get network interface information via SNMP
        
        Args:
            ip: Device IP address
            version: SNMP version
            
        Returns:
            List of interface dictionaries or None if failed
        """
        try:
            interfaces = []
            
            # Get interface count
            if_count_result = self._snmp_get(ip, [self.OIDS['ifNumber']], version)
            if not if_count_result:
                return None
                
            if_count = int(if_count_result.get(self.OIDS['ifNumber'], 0))
            if if_count == 0:
                return []
                
            # Walk interface table
            if_table = self._snmp_walk(ip, self.OIDS['ifTable'], version)
            if not if_table:
                return None
                
            # Parse interface data
            interface_data = {}
            for oid, value in if_table.items():
                # Extract interface index and property
                parts = oid.split('.')
                if len(parts) >= 2:
                    if_property = '.'.join(parts[:-1])
                    if_index = parts[-1]
                    
                    if if_index not in interface_data:
                        interface_data[if_index] = {}
                        
                    # Map OID to property name
                    if if_property.endswith('.2.2.1.2'):  # ifDescr
                        interface_data[if_index]['description'] = str(value)
                    elif if_property.endswith('.2.2.1.3'):  # ifType
                        if_type = int(value) if value else 0
                        interface_data[if_index]['type'] = self.INTERFACE_TYPES.get(if_type, f'unknown({if_type})')
                    elif if_property.endswith('.2.2.1.5'):  # ifSpeed
                        speed = int(value) if value else 0
                        interface_data[if_index]['speed'] = self._format_speed(speed)
                        interface_data[if_index]['speed_bps'] = speed
                    elif if_property.endswith('.2.2.1.6'):  # ifPhysAddress
                        mac = self._format_mac(value)
                        if mac:
                            interface_data[if_index]['mac_address'] = mac
                    elif if_property.endswith('.2.2.1.7'):  # ifAdminStatus
                        interface_data[if_index]['admin_status'] = 'up' if int(value) == 1 else 'down'
                    elif if_property.endswith('.2.2.1.8'):  # ifOperStatus
                        interface_data[if_index]['oper_status'] = 'up' if int(value) == 1 else 'down'
                        
            # Convert to list
            for if_index, if_data in interface_data.items():
                if_data['index'] = int(if_index)
                interfaces.append(if_data)
                
            return sorted(interfaces, key=lambda x: x['index'])
            
        except Exception as e:
            logger.error(f"Failed to get interfaces for {ip}: {e}")
            return None
            
    def get_host_resources(self, ip: str, version: str = 'v2c') -> Optional[Dict]:
        """Get host resource information (CPU, memory, etc.)
        
        Args:
            ip: Device IP address
            version: SNMP version
            
        Returns:
            Dictionary with host resources or None if failed
        """
        try:
            resources = {}
            
            # Get basic host resources
            oids = [
                self.OIDS['hrSystemUptime'],
                self.OIDS['hrSystemNumUsers'],
                self.OIDS['hrSystemProcesses'],
                self.OIDS['hrMemorySize'],
            ]
            
            results = self._snmp_get(ip, oids, version)
            if results:
                if results.get(self.OIDS['hrSystemUptime']):
                    timeticks = int(results[self.OIDS['hrSystemUptime']])
                    resources['system_uptime'] = self._format_uptime(timeticks)
                    
                if results.get(self.OIDS['hrSystemNumUsers']):
                    resources['logged_in_users'] = int(results[self.OIDS['hrSystemNumUsers']])
                    
                if results.get(self.OIDS['hrSystemProcesses']):
                    resources['running_processes'] = int(results[self.OIDS['hrSystemProcesses']])
                    
                if results.get(self.OIDS['hrMemorySize']):
                    # Memory size is in KBytes
                    mem_kb = int(results[self.OIDS['hrMemorySize']])
                    resources['memory_size'] = self._format_bytes(mem_kb * 1024)
                    resources['memory_size_bytes'] = mem_kb * 1024
                    
            # Get storage information
            storage_table = self._snmp_walk(ip, self.OIDS['hrStorageTable'], version)
            if storage_table:
                resources['storage'] = self._parse_storage_table(storage_table)
                
            # Get processor information
            processor_table = self._snmp_walk(ip, self.OIDS['hrProcessorTable'], version)
            if processor_table:
                resources['processors'] = self._parse_processor_table(processor_table)
                
            return resources if resources else None
            
        except Exception as e:
            logger.error(f"Failed to get host resources for {ip}: {e}")
            return None
            
    def _snmp_get(self, ip: str, oids: List[str], version: str = 'v2c') -> Optional[Dict]:
        """Perform SNMP GET operation
        
        Args:
            ip: Target IP address
            oids: List of OIDs to query
            version: SNMP version
            
        Returns:
            Dictionary mapping OIDs to values
        """
        async def _async_get():
            try:
                # Convert OID strings to ObjectIdentity objects
                oid_objects = [ObjectType(ObjectIdentity(oid)) for oid in oids]
                
                # Perform GET
                error_indication, error_status, error_index, var_binds = await getCmd(
                    SnmpEngine(),
                    CommunityData(self.community),
                    await UdpTransportTarget.create((ip, 161), timeout=self.timeout, retries=self.retries),
                    ContextData(),
                    *oid_objects
                )
                
                if error_indication:
                    logger.warning(f"SNMP GET error for {ip}: {error_indication}")
                    return None
                    
                if error_status:
                    logger.warning(f"SNMP GET status error for {ip}: {error_status}")
                    return None
                    
                # Parse results
                results = {}
                for var_bind in var_binds:
                    oid, value = var_bind
                    results[str(oid)] = value
                    
                return results
                
            except Exception as e:
                logger.error(f"SNMP GET exception for {ip}: {e}")
                return None
        
        try:
            return asyncio.get_event_loop().run_until_complete(_async_get())
        except RuntimeError:
            # Create new event loop if none exists
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(_async_get())
            finally:
                loop.close()
            
    def _snmp_walk(self, ip: str, oid: str, version: str = 'v2c') -> Optional[Dict]:
        """Perform SNMP WALK operation
        
        Args:
            ip: Target IP address
            oid: Base OID to walk
            version: SNMP version
            
        Returns:
            Dictionary mapping OIDs to values
        """
        try:
            # Perform WALK
            results = {}
            
            for (error_indication, error_status, error_index, var_binds) in nextCmd(
                SnmpEngine(),
                CommunityData(self.community),
                UdpTransportTarget((ip, 161), timeout=self.timeout, retries=self.retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
                ignoreNonIncreasingOid=False
            ):
                if error_indication:
                    logger.warning(f"SNMP WALK error for {ip}: {error_indication}")
                    break
                    
                if error_status:
                    logger.warning(f"SNMP WALK status error for {ip}: {error_status}")
                    break
                    
                for var_bind in var_binds:
                    oid_obj, value = var_bind
                    results[str(oid_obj)] = value
                    
            return results if results else None
            
        except Exception as e:
            logger.error(f"SNMP WALK exception for {ip}: {e}")
            return None
            
    def _format_uptime(self, timeticks: int) -> str:
        """Format SNMP timeticks to human-readable uptime
        
        Args:
            timeticks: SNMP timeticks (1/100th of a second)
            
        Returns:
            Formatted uptime string
        """
        total_seconds = timeticks // 100
        
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        if seconds > 0 or not parts:
            parts.append(f"{seconds}s")
            
        return " ".join(parts)
        
    def _format_speed(self, bps: int) -> str:
        """Format network speed from bits per second
        
        Args:
            bps: Speed in bits per second
            
        Returns:
            Formatted speed string
        """
        if bps >= 1000000000:
            return f"{bps / 1000000000:.1f} Gbps"
        elif bps >= 1000000:
            return f"{bps / 1000000:.1f} Mbps"
        elif bps >= 1000:
            return f"{bps / 1000:.1f} Kbps"
        else:
            return f"{bps} bps"
            
    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes to human-readable size
        
        Args:
            bytes_val: Size in bytes
            
        Returns:
            Formatted size string
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f} PB"
        
    def _format_mac(self, mac_bytes) -> Optional[str]:
        """Format MAC address from SNMP bytes
        
        Args:
            mac_bytes: MAC address as SNMP octet string
            
        Returns:
            Formatted MAC address or None
        """
        try:
            if hasattr(mac_bytes, '__iter__') and not isinstance(mac_bytes, str):
                hex_values = [f"{b:02X}" for b in mac_bytes]
                if len(hex_values) == 6:
                    return ":".join(hex_values)
            elif isinstance(mac_bytes, str) and len(mac_bytes) == 6:
                hex_values = [f"{ord(b):02X}" for b in mac_bytes]
                return ":".join(hex_values)
            return None
        except:
            return None
            
    def _parse_storage_table(self, storage_table: Dict) -> List[Dict]:
        """Parse hrStorageTable results
        
        Args:
            storage_table: Raw SNMP walk results
            
        Returns:
            List of storage dictionaries
        """
        storage_data = {}
        
        for oid, value in storage_table.items():
            parts = oid.split('.')
            if len(parts) >= 2:
                storage_index = parts[-1]
                property_oid = '.'.join(parts[:-1])
                
                if storage_index not in storage_data:
                    storage_data[storage_index] = {}
                    
                # Map OIDs to properties
                if property_oid.endswith('.2.3.1.3'):  # hrStorageDescr
                    storage_data[storage_index]['description'] = str(value)
                elif property_oid.endswith('.2.3.1.4'):  # hrStorageAllocationUnits
                    storage_data[storage_index]['allocation_units'] = int(value) if value else 0
                elif property_oid.endswith('.2.3.1.5'):  # hrStorageSize
                    storage_data[storage_index]['size_units'] = int(value) if value else 0
                elif property_oid.endswith('.2.3.1.6'):  # hrStorageUsed
                    storage_data[storage_index]['used_units'] = int(value) if value else 0
                    
        # Calculate sizes and usage
        storage_list = []
        for idx, data in storage_data.items():
            if 'description' in data and 'allocation_units' in data:
                allocation_units = data['allocation_units']
                size_units = data.get('size_units', 0)
                used_units = data.get('used_units', 0)
                
                if allocation_units > 0:
                    total_bytes = size_units * allocation_units
                    used_bytes = used_units * allocation_units
                    
                    storage_info = {
                        'description': data['description'],
                        'total': self._format_bytes(total_bytes),
                        'used': self._format_bytes(used_bytes),
                        'free': self._format_bytes(total_bytes - used_bytes),
                        'percent_used': round((used_bytes / total_bytes * 100) if total_bytes > 0 else 0, 1)
                    }
                    storage_list.append(storage_info)
                    
        return storage_list
        
    def _parse_processor_table(self, processor_table: Dict) -> List[Dict]:
        """Parse hrProcessorTable results
        
        Args:
            processor_table: Raw SNMP walk results
            
        Returns:
            List of processor dictionaries
        """
        processors = []
        
        for oid, value in processor_table.items():
            if oid.endswith('.3.3.1.2'):  # hrProcessorLoad
                parts = oid.split('.')
                if len(parts) > 0:
                    cpu_index = parts[-1]
                    load = int(value) if value else 0
                    processors.append({
                        'index': int(cpu_index),
                        'load_percent': load
                    })
                    
        return sorted(processors, key=lambda x: x['index'])