import math
import random
from typing import Dict, List


class MapGenerator:
    def generate_d3_data(self, devices: List[Dict]) -> Dict:
        """Generate D3.js compatible network data with enhanced topology"""
        # Group devices by subnet
        subnets = {}
        for device in devices:
            ip_parts = device["ip"].split(".")
            subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

            if subnet not in subnets:
                subnets[subnet] = []
            subnets[subnet].append(device)

        # Build nodes and links
        nodes = []
        links = []
        node_map = {}

        # Create device nodes (no subnet nodes for cleaner topology)
        for device in devices:
            device_node = {
                "id": device["ip"],
                "name": device.get("hostname", device["ip"]),
                "type": device.get("type", "unknown"),
                "critical": device.get("critical", False),
                "services": device.get("services", []),
                "vendor": device.get("vendor", ""),
                "group": self._get_device_group(device)
            }
            nodes.append(device_node)
            node_map[device["ip"]] = device_node

        # Create intelligent connections based on network topology
        self._create_network_links(devices, links, node_map)

        return {
            "nodes": nodes,
            "links": links,
            "metadata": {
                "total_devices": len(devices),
                "subnets": len(subnets),
                "device_types": self._count_types(devices),
            },
        }

    def _get_device_group(self, device: Dict) -> int:
        """Assign group based on device characteristics"""
        device_type = device.get("type", "unknown")

        # Group hierarchy: infrastructure > servers > clients
        if device_type in ["router"]:
            return 1
        elif device_type in ["switch"]:
            return 2
        elif "server" in device_type or device_type in ["web_server", "database"]:
            return 3
        elif device_type in ["workstation", "printer", "iot"]:
            return 4
        else:
            return 5

    def _create_network_links(self, devices: List[Dict], links: List[Dict], node_map: Dict):
        """Create realistic network topology links"""
        # Categorize devices
        routers = [d for d in devices if d.get("type") == "router"]
        switches = [d for d in devices if d.get("type") == "switch"]
        servers = [d for d in devices if "server" in d.get("type", "") or d.get("type") in ["web_server", "database"]]
        workstations = [d for d in devices if d.get("type") == "workstation"]
        others = [d for d in devices if d.get("type") in ["printer", "iot", "unknown"]]

        # Strategy 1: Connect all infrastructure devices
        if len(routers) > 1:
            # Connect routers in a ring for redundancy
            for i in range(len(routers)):
                next_router = routers[(i + 1) % len(routers)]
                links.append({
                    "source": routers[i]["ip"],
                    "target": next_router["ip"],
                    "value": 4,
                    "type": "backbone"
                })

        # Strategy 2: Connect switches to routers
        for switch in switches:
            if routers:
                # Connect to nearest router (by IP proximity)
                nearest_router = min(routers, key=lambda r: self._ip_distance(switch["ip"], r["ip"]))
                links.append({
                    "source": switch["ip"],
                    "target": nearest_router["ip"],
                    "value": 3,
                    "type": "uplink"
                })

        # Strategy 3: Connect servers intelligently
        for server in servers:
            # Critical servers connect directly to routers
            if server.get("critical", False) and routers:
                router = min(routers, key=lambda r: self._ip_distance(server["ip"], r["ip"]))
                links.append({
                    "source": server["ip"],
                    "target": router["ip"],
                    "value": 3,
                    "type": "critical"
                })
            # Other servers connect to switches or routers
            else:
                infrastructure = switches + routers
                if infrastructure:
                    target = min(infrastructure, key=lambda i: self._ip_distance(server["ip"], i["ip"]))
                    links.append({
                        "source": server["ip"],
                        "target": target["ip"],
                        "value": 2,
                        "type": "server_link"
                    })

        # Strategy 4: Connect workstations to switches (or routers if no switches)
        for workstation in workstations:
            infrastructure = switches if switches else routers
            if infrastructure:
                # Distribute workstations among switches
                target = infrastructure[hash(workstation["ip"]) % len(infrastructure)]
                links.append({
                    "source": workstation["ip"],
                    "target": target["ip"],
                    "value": 1,
                    "type": "access"
                })

        # Strategy 5: Connect other devices (printers, IoT) to local infrastructure
        for device in others:
            infrastructure = switches + routers
            if infrastructure:
                target = min(infrastructure, key=lambda i: self._ip_distance(device["ip"], i["ip"]))
                links.append({
                    "source": device["ip"],
                    "target": target["ip"],
                    "value": 1,
                    "type": "peripheral"
                })

        # Strategy 6: Add some cross-connections for realism
        if len(servers) > 1:
            # Connect database servers to web servers
            db_servers = [s for s in servers if s.get("type") == "database"]
            web_servers = [s for s in servers if s.get("type") == "web_server"]

            for web_server in web_servers:
                if db_servers:
                    db_server = min(db_servers, key=lambda d: self._ip_distance(web_server["ip"], d["ip"]))
                    links.append({
                        "source": web_server["ip"],
                        "target": db_server["ip"],
                        "value": 2,
                        "type": "application"
                    })

    def generate_threejs_data(self, devices: List[Dict]) -> Dict:
        """Generate Three.js 3D visualization data with improved positioning"""
        if not devices:
            return {
                "positions": [],
                "colors": [],
                "labels": [],
                "connections": [],
                "camera": {"x": 15, "y": 10, "z": 15},
            }

        # Enhanced color scheme for dark theme
        colors = {
            "router": 0xf48771,      # Coral red
            "switch": 0x7ca9dd,      # Light blue
            "windows_server": 0x6fc28b,  # Green
            "linux_server": 0x4ec9b0,    # Teal
            "web_server": 0x569cd6,      # Blue
            "database": 0xb99bd8,        # Purple
            "workstation": 0x9cdcfe,     # Light cyan
            "printer": 0xdaa674,         # Orange
            "iot": 0xd4c896,            # Yellow
            "unknown": 0x858585         # Gray
        }

        # Organize devices by type with improved layering
        layer_config = {
            "router": {"y": 8, "radius": 3, "spread": 1.0},
            "switch": {"y": 5, "radius": 5, "spread": 1.2},
            "windows_server": {"y": 2, "radius": 7, "spread": 1.0},
            "linux_server": {"y": 2, "radius": 7, "spread": 1.0},
            "web_server": {"y": 2, "radius": 8, "spread": 1.1},
            "database": {"y": 1, "radius": 6, "spread": 0.9},
            "workstation": {"y": -2, "radius": 10, "spread": 1.5},
            "printer": {"y": -1, "radius": 9, "spread": 1.0},
            "iot": {"y": -3, "radius": 12, "spread": 1.8},
            "unknown": {"y": -4, "radius": 8, "spread": 1.0}
        }

        positions = []
        device_colors = []
        labels = []
        device_positions = {}

        # Group devices by type
        devices_by_type = {}
        for device in devices:
            device_type = device.get("type", "unknown")
            if device_type not in devices_by_type:
                devices_by_type[device_type] = []
            devices_by_type[device_type].append(device)

        # Position devices with improved spacing
        for device_type, type_devices in devices_by_type.items():
            config = layer_config.get(device_type, layer_config["unknown"])

            if len(type_devices) == 1:
                # Single device - place at center of layer
                device = type_devices[0]
                position = {
                    "x": 0 + random.uniform(-0.5, 0.5),
                    "y": config["y"] + random.uniform(-0.3, 0.3),
                    "z": 0 + random.uniform(-0.5, 0.5)
                }
                # Store position and create visual elements
                positions.append(position)
                device_positions[device["ip"]] = position
                device_colors.append(colors.get(device_type, colors["unknown"]))

                labels.append({
                    "text": device.get("hostname") or device["ip"],
                    "position": position,
                    "type": device_type,
                    "critical": device.get("critical", False)
                })
            else:
                # Multiple devices - arrange in expanding patterns
                for i, device in enumerate(type_devices):
                    if len(type_devices) <= 6:
                        # Small groups: simple circle
                        angle = (i * 2 * math.pi) / len(type_devices)
                        radius = config["radius"] * config["spread"]
                    else:
                        # Larger groups: spiral pattern
                        spiral_turns = math.ceil(len(type_devices) / 8)
                        angle = (i * 2 * math.pi * spiral_turns) / len(type_devices)
                        radius = config["radius"] * (1 + (i / len(type_devices)) * config["spread"])

                    # Add height variation for visual interest
                    height_variation = math.sin(angle * 3) * 0.5

                    position = {
                        "x": radius * math.cos(angle) + random.uniform(-0.3, 0.3),
                        "y": config["y"] + height_variation + random.uniform(-0.2, 0.2),
                        "z": radius * math.sin(angle) + random.uniform(-0.3, 0.3)
                    }

                    # Store position and create visual elements
                    positions.append(position)
                    device_positions[device["ip"]] = position
                    device_colors.append(colors.get(device_type, colors["unknown"]))

                    labels.append({
                        "text": device.get("hostname") or device["ip"],
                        "position": position,
                        "type": device_type,
                        "critical": device.get("critical", False)
                    })

        # Create enhanced connections
        connections = []
        self._create_3d_connections(devices, device_positions, connections)

        return {
            "positions": positions,
            "colors": [f"#{color:06x}" for color in device_colors],
            "labels": labels,
            "connections": connections,
            "camera": {"x": 20, "y": 15, "z": 20},
            "metadata": {
                "total_nodes": len(positions),
                "device_types": list(devices_by_type.keys()),
                "connections": len(connections)
            }
        }

    def _create_3d_connections(self, devices: List[Dict], positions: Dict, connections: List[Dict]):
        """Create 3D connections with visual variety"""
        # Categorize devices
        routers = [d for d in devices if d.get("type") == "router"]
        switches = [d for d in devices if d.get("type") == "switch"]
        servers = [d for d in devices if "server" in d.get("type", "") or d.get("type") in ["web_server", "database"]]
        clients = [d for d in devices if d.get("type") in ["workstation", "printer", "iot"]]

        # Connection types with different visual properties
        connection_styles = {
            "backbone": {"color": "#ff6b6b", "opacity": 0.8, "thickness": 3},
            "uplink": {"color": "#4ecdc4", "opacity": 0.7, "thickness": 2.5},
            "server": {"color": "#45b7d1", "opacity": 0.6, "thickness": 2},
            "access": {"color": "#96ceb4", "opacity": 0.4, "thickness": 1.5},
            "peripheral": {"color": "#feca57", "opacity": 0.3, "thickness": 1}
        }

        def add_connection(dev1, dev2, style_name):
            if dev1["ip"] in positions and dev2["ip"] in positions:
                style = connection_styles[style_name]
                connections.append({
                    "start": positions[dev1["ip"]],
                    "end": positions[dev2["ip"]],
                    "color": style["color"],
                    "opacity": style["opacity"],
                    "thickness": style["thickness"],
                    "type": style_name
                })

        # 1. Connect infrastructure backbone
        for i in range(len(routers)):
            for j in range(i + 1, len(routers)):
                add_connection(routers[i], routers[j], "backbone")

        # 2. Connect switches to routers
        for switch in switches:
            if routers:
                nearest_router = min(routers, key=lambda r: self._ip_distance(switch["ip"], r["ip"]))
                add_connection(switch, nearest_router, "uplink")

        # 3. Connect servers strategically
        for server in servers:
            # Critical servers to routers, others to nearest infrastructure
            if server.get("critical", False) and routers:
                router = min(routers, key=lambda r: self._ip_distance(server["ip"], r["ip"]))
                add_connection(server, router, "server")
            else:
                infrastructure = switches + routers
                if infrastructure:
                    target = min(infrastructure, key=lambda i: self._ip_distance(server["ip"], i["ip"]))
                    add_connection(server, target, "server")

        # 4. Connect clients to local infrastructure
        for client in clients:
            # Prefer switches for workstations, any infrastructure for others
            infrastructure = switches if switches and client.get("type") == "workstation" else switches + routers
            if infrastructure:
                target = min(infrastructure, key=lambda i: self._ip_distance(client["ip"], i["ip"]))
                connection_type = "access" if client.get("type") == "workstation" else "peripheral"
                add_connection(client, target, connection_type)

        # 5. Add some server-to-server connections for realism
        if len(servers) > 1:
            web_servers = [s for s in servers if s.get("type") == "web_server"]
            db_servers = [s for s in servers if s.get("type") == "database"]

            # Connect web servers to database servers
            for web_server in web_servers:
                if db_servers:
                    db_server = min(db_servers, key=lambda d: self._ip_distance(web_server["ip"], d["ip"]))
                    add_connection(web_server, db_server, "server")

    def _ip_distance(self, ip1: str, ip2: str) -> int:
        """Calculate Manhattan distance between IPs for logical proximity"""
        try:
            parts1 = [int(p) for p in ip1.split(".")]
            parts2 = [int(p) for p in ip2.split(".")]

            # Weight the octets differently - subnet proximity is most important
            weights = [1, 1, 10, 100]  # Last octet matters most for local proximity
            distance = sum(w * abs(p1 - p2) for w, p1, p2 in zip(weights, parts1, parts2))
            return distance
        except (ValueError, AttributeError):
            return 999999  # Large distance for invalid IPs

    def _count_types(self, devices: List[Dict]) -> Dict[str, int]:
        """Count devices by type"""
        counts = {}
        for device in devices:
            dtype = device.get("type", "unknown")
            counts[dtype] = counts.get(dtype, 0) + 1
        return counts

    def generate_subnet_topology(self, devices: List[Dict]) -> Dict:
        """Generate subnet-level topology view"""
        subnets = {}

        for device in devices:
            ip_parts = device["ip"].split(".")
            subnet_key = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

            if subnet_key not in subnets:
                subnets[subnet_key] = {
                    "network": subnet_key,
                    "devices": [],
                    "device_count": 0,
                    "types": {},
                    "critical_count": 0
                }

            subnets[subnet_key]["devices"].append(device)
            subnets[subnet_key]["device_count"] += 1

            device_type = device.get("type", "unknown")
            subnets[subnet_key]["types"][device_type] = subnets[subnet_key]["types"].get(device_type, 0) + 1

            if device.get("critical", False):
                subnets[subnet_key]["critical_count"] += 1

        return {
            "subnets": list(subnets.values()),
            "total_subnets": len(subnets),
            "total_devices": len(devices)
        }
