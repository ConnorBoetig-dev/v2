import re
from typing import Optional, Dict

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
        
        # Direct lookup
        if oui in self.vendor_db:
            return self.vendor_db[oui]
        
        # Check for VMware variants
        if mac.startswith(('00:50:56', '00:0c:29', '00:05:69')):
            return 'VMware'
        
        # Check for virtual machine patterns
        if self._is_virtual_mac(mac):
            return 'Virtual Machine'
        
        return None
    
    def _normalize_mac(self, mac: str) -> Optional[str]:
        """Normalize MAC address format"""
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
        ]
        
        mac_start = mac[:8].upper()
        return any(mac_start.startswith(pattern.upper()) for pattern in virtual_patterns)
    
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