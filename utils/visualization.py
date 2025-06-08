import json
from typing import Dict, List
import random

class MapGenerator:
    def generate_d3_data(self, devices: List[Dict]) -> Dict:
        """Generate D3.js compatible network data"""
        # Group devices by subnet
        subnets = {}
        for device in devices:
            ip_parts = device['ip'].split('.')
            subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            if subnet not in subnets:
                subnets[subnet] = []
            subnets[subnet].append(device)
        
        # Build nodes and links
        nodes = []
        links = []
        node_map = {}
        
        # Create subnet nodes
        for subnet_id, subnet in enumerate(subnets):
            subnet_node = {
                'id': f"subnet_{subnet_id}",
                'name': subnet,
                'type': 'subnet',
                'group': subnet_id
            }
            nodes.append(subnet_node)
            
            # Create device nodes
            for device in subnets[subnet]:
                device_node = {
                    'id': device['ip'],
                    'name': device.get('hostname', device['ip']),
                    'type': device.get('type', 'unknown'),
                    'group': subnet_id,
                    'critical': device.get('critical', False),
                    'services': device.get('services', []),
                    'vendor': device.get('vendor', '')
                }
                nodes.append(device_node)
                node_map[device['ip']] = device_node
                
                # Link to subnet
                links.append({
                    'source': f"subnet_{subnet_id}",
                    'target': device['ip'],
                    'value': 1
                })
        
        # Infer connections between devices
        # (Example: servers connect to routers, workstations to switches)
        routers = [d for d in devices if d.get('type') == 'router']
        switches = [d for d in devices if d.get('type') == 'switch']
        servers = [d for d in devices if d.get('type') in ['windows_server', 'linux_server']]
        
        # Connect servers to routers
        for server in servers:
            if routers:
                router = min(routers, key=lambda r: self._ip_distance(server['ip'], r['ip']))
                links.append({
                    'source': server['ip'],
                    'target': router['ip'],
                    'value': 2,
                    'type': 'uplink'
                })
        
        return {
            'nodes': nodes,
            'links': links,
            'metadata': {
                'total_devices': len(devices),
                'subnets': len(subnets),
                'device_types': self._count_types(devices)
            }
        }
    
    def generate_threejs_data(self, devices: List[Dict]) -> Dict:
        """Generate Three.js 3D visualization data"""
        # Organize devices in 3D space
        layers = {
            'router': {'y': 3, 'color': '#ff6b6b'},
            'switch': {'y': 2, 'color': '#4ecdc4'},
            'server': {'y': 1, 'color': '#45b7d1'},
            'workstation': {'y': 0, 'color': '#96ceb4'},
            'iot': {'y': 0, 'color': '#daa520'},
            'unknown': {'y': 0, 'color': '#95a5a6'}
        }
        
        positions = []
        colors = []
        labels = []
        connections = []
        
        # Position devices
        device_positions = {}
        for i, device in enumerate(devices):
            device_type = device.get('type', 'unknown')
            if device_type not in layers:
                device_type = 'unknown'
            
            # Spread devices in a circle at each layer
            angle = (i * 2 * 3.14159) / len(devices)
            radius = 5
            
            x = radius * random.uniform(0.8, 1.2) * json.cos(angle)
            z = radius * random.uniform(0.8, 1.2) * json.sin(angle)
            y = layers[device_type]['y'] + random.uniform(-0.2, 0.2)
            
            position = {'x': x, 'y': y, 'z': z}
            device_positions[device['ip']] = position
            
            positions.append(position)
            colors.append(layers[device_type]['color'])
            labels.append({
                'text': device.get('hostname', device['ip']),
                'position': position
            })
        
        # Create connections (simplified)
        routers = [d for d in devices if d.get('type') == 'router']
        for device in devices:
            if device.get('type') != 'router' and routers:
                # Connect to nearest router
                router = routers[0]  # Simplified
                if device['ip'] in device_positions and router['ip'] in device_positions:
                    connections.append({
                        'start': device_positions[device['ip']],
                        'end': device_positions[router['ip']],
                        'color': '#34495e',
                        'opacity': 0.3
                    })
        
        return {
            'positions': positions,
            'colors': colors,
            'labels': labels,
            'connections': connections,
            'camera': {'x': 10, 'y': 5, 'z': 10}
        }
    
    def _ip_distance(self, ip1: str, ip2: str) -> int:
        """Calculate distance between IPs (simple)"""
        parts1 = [int(p) for p in ip1.split('.')]
        parts2 = [int(p) for p in ip2.split('.')]
        return sum(abs(p1 - p2) for p1, p2 in zip(parts1, parts2))
    
    def _count_types(self, devices: List[Dict]) -> Dict[str, int]:
        """Count devices by type"""
        counts = {}
        for device in devices:
            dtype = device.get('type', 'unknown')
            counts[dtype] = counts.get(dtype, 0) + 1
        return counts
