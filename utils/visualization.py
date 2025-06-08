import math
import random
from typing import Dict, List


class MapGenerator:
    def generate_d3_data(self, devices: List[Dict]) -> Dict:
        """Generate D3.js compatible network data"""
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

        # Create subnet nodes
        for subnet_id, subnet in enumerate(subnets):
            subnet_node = {
                "id": f"subnet_{subnet_id}",
                "name": subnet,
                "type": "subnet",
                "group": subnet_id,
            }
            nodes.append(subnet_node)

            # Create device nodes
            for device in subnets[subnet]:
                device_node = {
                    "id": device["ip"],
                    "name": device.get("hostname", device["ip"]),
                    "type": device.get("type", "unknown"),
                    "group": subnet_id,
                    "critical": device.get("critical", False),
                    "services": device.get("services", []),
                    "vendor": device.get("vendor", ""),
                }
                nodes.append(device_node)
                node_map[device["ip"]] = device_node

                # Link to subnet
                links.append({"source": f"subnet_{subnet_id}", "target": device["ip"], "value": 1})

        # Infer connections between devices
        # (Example: servers connect to routers, workstations to switches)
        routers = [d for d in devices if d.get("type") == "router"]
        switches = [d for d in devices if d.get("type") == "switch"]
        servers = [
            d for d in devices if d.get("type") in ["windows_server", "linux_server", "web_server"]
        ]
        workstations = [d for d in devices if d.get("type") == "workstation"]

        # Connect servers to routers
        for server in servers:
            if routers:
                router = min(routers, key=lambda r: self._ip_distance(server["ip"], r["ip"]))
                links.append(
                    {"source": server["ip"], "target": router["ip"], "value": 2, "type": "uplink"}
                )

        # Connect workstations to switches
        for workstation in workstations:
            if switches:
                switch = min(switches, key=lambda s: self._ip_distance(workstation["ip"], s["ip"]))
                links.append(
                    {
                        "source": workstation["ip"],
                        "target": switch["ip"],
                        "value": 1,
                        "type": "access",
                    }
                )

        # Connect switches to routers
        for switch in switches:
            if routers:
                router = min(routers, key=lambda r: self._ip_distance(switch["ip"], r["ip"]))
                links.append(
                    {"source": switch["ip"], "target": router["ip"], "value": 3, "type": "trunk"}
                )

        return {
            "nodes": nodes,
            "links": links,
            "metadata": {
                "total_devices": len(devices),
                "subnets": len(subnets),
                "device_types": self._count_types(devices),
            },
        }

    def generate_threejs_data(self, devices: List[Dict]) -> Dict:
        """Generate Three.js 3D visualization data"""
        # Organize devices in 3D space by type - Updated colors for dark theme
        layers = {
            "router": {"y": 3, "color": "#f48771"},
            "switch": {"y": 2, "color": "#7ca9dd"},
            "windows_server": {"y": 1, "color": "#6fc28b"},
            "linux_server": {"y": 1, "color": "#4ec9b0"},
            "web_server": {"y": 1, "color": "#569cd6"},
            "database": {"y": 1, "color": "#b99bd8"},
            "workstation": {"y": 0, "color": "#9cdcfe"},
            "printer": {"y": 0, "color": "#daa674"},
            "iot": {"y": 0, "color": "#d4c896"},
            "unknown": {"y": 0, "color": "#858585"},
        }

        positions = []
        colors = []
        labels = []
        connections = []

        # Position devices
        device_positions = {}
        device_count_by_type = {}

        # Count devices by type for positioning
        for device in devices:
            device_type = device.get("type", "unknown")
            if device_type not in device_count_by_type:
                device_count_by_type[device_type] = 0
            device_count_by_type[device_type] += 1

        # Position devices in circles at each layer
        type_indices = {}
        for device in devices:
            device_type = device.get("type", "unknown")
            if device_type not in layers:
                device_type = "unknown"

            # Get index for this type
            if device_type not in type_indices:
                type_indices[device_type] = 0
            type_index = type_indices[device_type]
            type_indices[device_type] += 1

            # Calculate position in circle
            total_of_type = device_count_by_type.get(device_type, 1)
            angle = (type_index * 2 * math.pi) / total_of_type

            # Vary radius based on device type
            radius_multiplier = {
                "router": 2.0,
                "switch": 3.0,
                "server": 4.0,
                "workstation": 5.0,
            }.get(device_type, 4.0)

            radius = radius_multiplier

            x = radius * math.cos(angle)
            z = radius * math.sin(angle)
            y = layers[device_type]["y"] + random.uniform(-0.2, 0.2)

            position = {"x": x, "y": y, "z": z}
            device_positions[device["ip"]] = position

            positions.append(position)
            colors.append(layers[device_type]["color"])
            labels.append(
                {
                    "text": device.get("hostname", device["ip"]),
                    "position": position,
                    "type": device_type,
                }
            )

        # Create connections based on logical topology
        routers = [d for d in devices if d.get("type") == "router"]
        switches = [d for d in devices if d.get("type") == "switch"]

        # Connect all non-infrastructure devices to nearest switch or router
        for device in devices:
            if device.get("type") in ["router", "switch", "subnet"]:
                continue

            # Find nearest infrastructure device
            infrastructure = routers + switches
            if infrastructure:
                nearest = min(
                    infrastructure, key=lambda i: self._ip_distance(device["ip"], i["ip"])
                )

                if device["ip"] in device_positions and nearest["ip"] in device_positions:
                    connections.append(
                        {
                            "start": device_positions[device["ip"]],
                            "end": device_positions[nearest["ip"]],
                            "color": "#666666",
                            "opacity": 0.3,
                        }
                    )

        # Connect switches to routers
        for switch in switches:
            if routers and switch["ip"] in device_positions:
                router = routers[0]  # Simplified - connect to first router
                if router["ip"] in device_positions:
                    connections.append(
                        {
                            "start": device_positions[switch["ip"]],
                            "end": device_positions[router["ip"]],
                            "color": "#888888",
                            "opacity": 0.5,
                        }
                    )

        return {
            "positions": positions,
            "colors": colors,
            "labels": labels,
            "connections": connections,
            "camera": {"x": 10, "y": 5, "z": 10},
        }

    def _ip_distance(self, ip1: str, ip2: str) -> int:
        """Calculate distance between IPs (simple Manhattan distance)"""
        try:
            parts1 = [int(p) for p in ip1.split(".")]
            parts2 = [int(p) for p in ip2.split(".")]
            return sum(abs(p1 - p2) for p1, p2 in zip(parts1, parts2))
        except (ValueError, AttributeError):
            return 999  # Large distance for invalid IPs

    def _count_types(self, devices: List[Dict]) -> Dict[str, int]:
        """Count devices by type"""
        counts = {}
        for device in devices:
            dtype = device.get("type", "unknown")
            counts[dtype] = counts.get(dtype, 0) + 1
        return counts
