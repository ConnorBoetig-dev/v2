import platform
import re
import subprocess
from typing import Dict, List, Optional


class MACLookup:
    def __init__(self):
        # Common MAC vendor prefixes (OUI)
        # In production, this would load from IEEE OUI database
        self.vendor_db = {
            '00:00:0c': 'Cisco Systems',
            '00:01:42': 'Cisco Systems',
            '00:1b:54': 'Cisco Systems',
            '00:23:ea': 'Cisco Systems',
            '00:50:56': 'VMware',
            '00:0c:29': 'VMware',
            '00:05:69': 'VMware',
            '00:15:5d': 'Microsoft Corp',
            '00:03:ff': 'Microsoft Corp',
            '00:50:f2': 'Microsoft Corp',
            '00:17:42': 'Dell Inc.',
            '00:1c:23': 'Dell Inc.',
            '00:24:e8': 'Dell Inc.',
            '3c:d9:2b': 'HP Inc.',
            '00:1e:0b': 'Hewlett Packard',
            '00:25:b3': 'Hewlett Packard',
            '00:50:ba': 'D-Link',
            '00:05:5d': 'D-Link',
            '00:0f:3d': 'D-Link',
            '00:1f:1f': 'Edimax',
            '00:0e:2e': 'Edimax',
            '74:da:88': 'Edimax',
            'b8:27:eb': 'Raspberry Pi Foundation',
            'dc:a6:32': 'Raspberry Pi Foundation',
            'e4:5f:01': 'Raspberry Pi Foundation',
            '00:11:32': 'Synology',
            '00:50:43': 'Marvell',
            '00:1b:21': 'Intel Corporate',
            '00:1f:29': 'Intel Corporate',
            '00:21:6a': 'Intel Corporate',
            'a4:c3:f0': 'Intel Corporate',
            '00:26:b9': 'Dell Inc.',
            'f0:4d:a2': 'Dell Inc.',
            '18:db:f2': 'Dell Inc.',
            '00:14:22': 'Dell Inc.',
            '00:21:70': 'Dell Inc.',
            '00:22:19': 'Dell Inc.',
            '00:a0:c9': '3Com',
            '00:04:75': '3Com',
            '00:06:5b': '3Com',
            '00:1e:c9': 'Apple',
            '00:23:12': 'Apple',
            '00:25:4b': 'Apple',
            '00:26:bb': 'Apple',
            '10:dd:b1': 'Apple',
            '00:16:cb': 'Apple',
            '00:17:f2': 'Apple',
            '00:19:e3': 'Apple',
            '00:1b:63': 'Apple',
            '00:1c:b3': 'Apple',
            '00:1d:4f': 'Apple',
            '00:1e:52': 'Apple',
            '00:1f:5b': 'Apple',
            '00:21:e9': 'Apple',
            '00:22:41': 'Apple',
            '00:23:32': 'Apple',
            '00:23:6c': 'Apple',
            '00:23:df': 'Apple',
            '00:24:36': 'Apple',
            '00:25:00': 'Apple',
            '00:25:bc': 'Apple',
            '00:26:08': 'Apple',
            '00:26:4a': 'Apple',
            '00:26:b0': 'Apple',
        }
        self.system = platform.system()
    
    def get_arp_cache(self) -> Dict[str, str]:
        """Get MAC addresses from system ARP cache (cross-platform)"""
        if self.system == 'Darwin':
            return self._get_macos_arp_cache()
        elif self.system == 'Linux':
            return self._get_linux_arp_cache()
        elif self.system == 'Windows':
            return self._get_windows_arp_cache()
        else:
            return {}
    
    def _get_macos_arp_cache(self) -> Dict[str, str]:
        """Get MAC addresses from macOS ARP cache"""
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            if result.returncode != 0:
                return {}
            
            arp_cache = {}
            for line in result.stdout.split('\n'):
                # Parse lines like: hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
                match = re.search(r'\(([0-9.]+)\) at ([0-9a-fA-F:]+)', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2)
                    arp_cache[ip] = mac.upper()
            
            return arp_cache
        except Exception:
            return {}
    
    def _get_linux_arp_cache(self) -> Dict[str, str]:
        """Get MAC addresses from Linux ARP cache"""
        try:
            # First try ip neigh command (modern Linux)
            result = subprocess.run(['ip', 'neigh'], capture_output=True, text=True)
            if result.returncode == 0:
                arp_cache = {}
                for line in result.stdout.split('\n'):
                    # Parse lines like: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+).*lladdr\s+([0-9a-fA-F:]+)', line)
                    if match:
                        ip = match.group(1)
                        mac = match.group(2)
                        arp_cache[ip] = mac.upper()
                return arp_cache
        except:
            pass
        
        # Fallback to arp -n command
        try:
            result = subprocess.run(['arp', '-n'], capture_output=True, text=True)
            if result.returncode == 0:
                arp_cache = {}
                for line in result.stdout.split('\n'):
                    # Parse lines like: 192.168.1.1  ether  aa:bb:cc:dd:ee:ff  C  eth0
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+ether\s+([0-9a-fA-F:]+)', line)
                    if match:
                        ip = match.group(1)
                        mac = match.group(2)
                        arp_cache[ip] = mac.upper()
                return arp_cache
        except:
            pass
        
        return {}
    
    def _get_windows_arp_cache(self) -> Dict[str, str]:
        """Get MAC addresses from Windows ARP cache"""
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, shell=True)
            if result.returncode != 0:
                return {}
            
            arp_cache = {}
            for line in result.stdout.split('\n'):
                # Parse lines like: 192.168.1.1  aa-bb-cc-dd-ee-ff  dynamic
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+dynamic', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace('-', ':')
                    arp_cache[ip] = mac.upper()
            
            return arp_cache
        except Exception:
            return {}
    
    def lookup_vendor_online(self, mac: str) -> Optional[str]:
        """Lookup vendor using online API (requires internet)"""
        # Note: In production, consider caching results to avoid rate limits
        try:
            import requests

            # Clean MAC for API
            clean_mac = mac.replace(':', '').replace('-', '').upper()
            
            # Try macvendors.co API (free, no key required)
            try:
                response = requests.get(
                    f'https://api.macvendors.com/{clean_mac[:6]}',
                    timeout=3,
                    headers={'User-Agent': 'NetworkMapper/2.0'}
                )
                if response.status_code == 200:
                    vendor = response.text.strip()
                    if vendor and 'Not Found' not in vendor:
                        return vendor
            except:
                pass
            
            # Alternative: maclookup.app (also free)
            try:
                response = requests.get(
                    f'https://api.maclookup.app/v2/macs/{clean_mac[:6]}',
                    timeout=3
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('company'):
                        return data['company']
            except:
                pass
            
        except ImportError:
            # requests not available
            pass
        except Exception:
            pass
        
        return None
    
    def lookup(self, mac: str) -> Optional[str]:
        """Lookup vendor by MAC address"""
        if not mac:
            return None
        
        # Normalize MAC format
        mac = self._normalize_mac(mac)
        if not mac:
            return None
        
        # Check OUI (first 3 octets)
        oui = mac[:8].lower()
        
        # Direct lookup in local database
        if oui in self.vendor_db:
            return self.vendor_db[oui]print(f"{ip} -> {mac_addr}")
        
        # Check for VMware variants
        if mac.upper().startswith(('00:50:56', '00:0C:29', '00:05:69')):
            return 'VMware'
        
        # Check for virtual machine patterns
        if self._is_virtual_mac(mac):
            return 'Virtual Machine'
        
        # Try online lookup as fallback (if enabled)
        vendor = self.lookup_vendor_online(mac)
        if vendor:
            # Cache the result for future use
            self.vendor_db[oui] = vendor
            return vendor
        
        return None
    
    def _normalize_mac(self, mac: str) -> Optional[str]:
        """Normalize MAC address format"""
        if not mac:
            return None
            
        # Remove common separators
        mac = mac.replace(':', '').replace('-', '').replace('.', '').upper()
        
        # Validate length
        if len(mac) != 12:
            return None
        
        # Validate hex
        if not re.match(r'^[0-9A-F]{12}$', mac):
            return None
        
        # Format as XX:XX:XX:XX:XX:XX
        return ':'.join(mac[i:i+2] for i in range(0, 12, 2))
    
    def _is_virtual_mac(self, mac: str) -> bool:
        """Check if MAC indicates virtual machine"""
        virtual_patterns = [
            '00:50:56',  # VMware
            '00:0C:29',  # VMware
            '00:05:69',  # VMware
            '00:15:5D',  # Hyper-V
            '00:03:FF',  # Microsoft Virtual PC
            '08:00:27',  # VirtualBox
            '52:54:00',  # QEMU/KVM
            '00:16:3E',  # Xen
            '02:42:',    # Docker
        ]
        
        mac_start = mac[:8].upper()
        return any(mac_start.startswith(pattern.upper()) for pattern in virtual_patterns)
    
    def enrich_with_arp_cache(self, devices: List[Dict]) -> List[Dict]:
        """Enrich devices with MAC addresses from ARP cache"""
        arp_cache = self.get_arp_cache()
        
        if not arp_cache:
            return devices
        
        for device in devices:
            # If device has no MAC but we have it in ARP cache
            if not device.get('mac') and device.get('ip') in arp_cache:
                device['mac'] = arp_cache[device['ip']]
                # Try to get vendor for this MAC
                vendor = self.lookup(device['mac'])
                if vendor:
                    device['vendor'] = vendor
            # If device has MAC but no vendor, try to get vendor
            elif device.get('mac') and not device.get('vendor'):
                vendor = self.lookup(device['mac'])
                if vendor:
                    device['vendor'] = vendor
        
        return devices
    
    def enrich_device(self, device: Dict) -> Dict:
        """Enrich device data with vendor information"""
        if 'mac' in device and device['mac']:
            vendor = self.lookup(device['mac'])
            if vendor:
                device['vendor'] = vendor
                
                # Add virtual flag if applicable
                if 'Virtual' in vendor or self._is_virtual_mac(device['mac']):
                    device['is_virtual'] = True
        
        return device