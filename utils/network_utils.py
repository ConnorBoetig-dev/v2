import ipaddress
import socket
from typing import List, Tuple, Optional

class NetworkUtils:
    @staticmethod
    def validate_target(target: str) -> Tuple[bool, Optional[str]]:
        """Validate network target (IP or CIDR)"""
        try:
            # Try as single IP
            ipaddress.ip_address(target)
            return True, None
        except ValueError:
            pass
        
        try:
            # Try as network
            ipaddress.ip_network(target, strict=False)
            return True, None
        except ValueError:
            pass
        
        # Try as hostname
        try:
            socket.gethostbyname(target)
            return True, None
        except socket.error:
            pass
        
        return False, f"Invalid target: {target}"
    
    @staticmethod
    def expand_network(target: str) -> List[str]:
        """Expand CIDR notation to list of IPs"""
        try:
            network = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            # Single IP or hostname
            return [target]
    
    @staticmethod
    def get_subnet(ip: str) -> str:
        """Get /24 subnet for an IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Create /24 network
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(network)
        except ValueError:
            return "unknown"
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP is private"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
    
    @staticmethod
    def get_ip_info(ip: str) -> dict:
        """Get detailed IP information"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return {
                'ip': str(ip_obj),
                'version': ip_obj.version,
                'is_private': ip_obj.is_private,
                'is_global': ip_obj.is_global,
                'is_multicast': ip_obj.is_multicast,
                'is_loopback': ip_obj.is_loopback,
                'reverse_dns': NetworkUtils.reverse_dns_lookup(ip)
            }
        except ValueError:
            return {'ip': ip, 'error': 'Invalid IP address'}
    
    @staticmethod
    def reverse_dns_lookup(ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return None
    
    @staticmethod
    def sort_ips(ip_list: List[str]) -> List[str]:
        """Sort IP addresses properly"""
        try:
            return sorted(ip_list, key=lambda ip: ipaddress.ip_address(ip))
        except ValueError:
            # Fallback to string sort if some IPs are invalid
            return sorted(ip_list)
    
    @staticmethod
    def calculate_network_summary(devices: List[dict]) -> dict:
        """Calculate network statistics"""
        summary = {
            'total_devices': len(devices),
            'subnets': {},
            'private_ips': 0,
            'public_ips': 0,
            'ip_ranges': []
        }
        
        ips = []
        for device in devices:
            ip = device.get('ip')
            if not ip:
                continue
                
            try:
                ip_obj = ipaddress.ip_address(ip)
                ips.append(ip_obj)
                
                # Count private/public
                if ip_obj.is_private:
                    summary['private_ips'] += 1
                else:
                    summary['public_ips'] += 1
                
                # Group by subnet
                subnet = NetworkUtils.get_subnet(ip)
                if subnet not in summary['subnets']:
                    summary['subnets'][subnet] = 0
                summary['subnets'][subnet] += 1
                
            except ValueError:
                continue
        
        # Calculate IP range
        if ips:
            sorted_ips = sorted(ips)
            summary['ip_ranges'] = [
                f"{sorted_ips[0]} - {sorted_ips[-1]}"
            ]
        
        return summary