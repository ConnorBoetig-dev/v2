"""
Visualization Module - Network topology and traffic flow visualization data generation

This module generates structured data for D3.js and Three.js network visualizations.
It creates intelligent network topologies based on device types, relationships, and
observed traffic patterns. The generated data supports both static topology views
and dynamic traffic flow visualizations.

Key Features:
- Hierarchical network layout generation
- Intelligent link creation based on device types
- Traffic flow visualization support
- Change tracking visualization
- 3D coordinate generation for Three.js

Design Philosophy:
- Generate realistic network topologies
- Minimize link overlap for clarity
- Support both 2D and 3D visualizations
- Enable interactive exploration
"""

import math
import random
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


class MapGenerator:
    """
    Generates visualization data for network topology displays.

    This class creates structured data suitable for rendering with D3.js
    (2D visualization) and Three.js (3D visualization). It analyzes device
    relationships and creates logical network topologies that reflect
    real-world network architectures.
    """

    def generate_d3_data(self, devices: List[Dict]) -> Dict:
        """
        Generate D3.js compatible network data with enhanced topology.

        Creates a force-directed graph structure with:
        - Nodes representing devices with rich metadata
        - Links representing logical network connections
        - Hierarchical layout hints for better visualization
        - Device grouping by type and criticality

        The topology generation follows networking best practices:
        - Routers form the network backbone
        - Switches connect to routers
        - End devices connect to switches
        - Application-layer connections for servers

        Args:
            devices: List of device dictionaries from scanner

        Returns:
            Dictionary with nodes, links, and metadata for D3.js
        """
        # Group devices by subnet for topology generation
        # Subnet grouping helps create realistic network segments
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

        # Create device nodes with rich metadata for visualization
        # Each node contains all necessary data for interactive displays
        for device in devices:
            device_node = {
                "id": device["ip"],  # Unique identifier
                "name": device.get("hostname", device["ip"]),  # Display name
                "type": device.get("type", "unknown"),  # Device classification
                "subtype": device.get("subtype", ""),  # Additional categorization
                "critical": device.get("critical", False),  # Critical infrastructure flag
                "services": device.get("services", []),  # Running services
                "vendor": device.get("vendor", ""),  # Manufacturer
                "group": self._get_device_group(device),  # Visual grouping
                "tags": device.get("tags", []),  # User-defined tags
                "dependent_count": device.get("dependent_count", 0),  # Dependency metric
                "uptime_days": device.get("uptime_days", 0),  # Availability metric
                "always_on": device.get("always_on", False),  # 24/7 requirement flag
            }
            nodes.append(device_node)
            node_map[device["ip"]] = device_node

        # Create intelligent connections based on network topology
        # Links represent logical network relationships, not just physical connections
        self._create_network_links(devices, links, node_map)

        # Calculate critical asset statistics for dashboard display
        critical_stats = self._calculate_critical_stats(devices)

        return {
            "nodes": nodes,
            "links": links,
            "metadata": {
                "total_devices": len(devices),
                "subnets": len(subnets),
                "device_types": self._count_types(devices),
                "critical_assets": critical_stats,
            },
        }

    def generate_traffic_flow_data(
        self, devices: List[Dict], flow_matrix: Optional[Dict] = None
    ) -> Dict:
        """
        Generate D3.js data with traffic flow information.

        Creates visualization data that shows actual network traffic patterns
        discovered through passive analysis. This differs from the topology
        view by showing real communication paths rather than logical structure.

        Flow visualization helps identify:
        - Active communication patterns
        - Service dependencies
        - Unusual traffic flows
        - Network bottlenecks

        Args:
            devices: List of devices including passive discoveries
            flow_matrix: Optional traffic flow matrix from passive analysis
                        Format: {source_ip: {dest_ip: flow_count}}

        Returns:
            Enhanced D3.js data with traffic flow links and metrics
        """
        # For traffic flow visualization, we show only observed connections
        # This provides a true picture of network communication patterns
        nodes = []
        node_map = {}

        # Create nodes with traffic-specific metadata
        for device in devices:
            device_node = {
                "id": device["ip"],
                "name": device.get("hostname", device["ip"]),
                "type": device.get("type", "unknown"),
                "subtype": device.get("subtype", ""),
                "critical": device.get("critical", False),
                "services": device.get("services", []),
                "vendor": device.get("vendor", ""),
                "group": self._get_device_group(device),
                "tags": device.get("tags", []),
                "dependent_count": device.get("dependent_count", 0),
                "uptime_days": device.get("uptime_days", 0),
                "always_on": device.get("always_on", False),
            }
            nodes.append(device_node)
            node_map[device["ip"]] = device_node

        # Create node index for quick lookup
        node_index = {node["id"]: i for i, node in enumerate(nodes)}

        # Add traffic flow information to nodes
        if flow_matrix:
            for node in nodes:
                ip = node["id"]

                # Calculate traffic volume
                outbound = sum(flow_matrix.get(ip, {}).values())
                inbound = sum(flow_matrix.get(src, {}).get(ip, 0) for src in flow_matrix)

                node["traffic"] = {
                    "inbound": inbound,
                    "outbound": outbound,
                    "total": inbound + outbound,
                }

                # Mark stealth devices and add enhanced metadata
                device = next((d for d in devices if d["ip"] == ip), None)
                if device and device.get("stealth_device", False):
                    node["stealth"] = True
                    node["discovery_method"] = "passive"

        # Create links ONLY from actual traffic flows
        links = []
        if flow_matrix:
            # Debug: Track skipped connections
            skipped_sources = 0
            skipped_targets = 0

            for src_ip, destinations in flow_matrix.items():
                if src_ip not in node_index:
                    skipped_sources += 1
                    continue

                for dst_ip, packet_count in destinations.items():
                    if dst_ip not in node_index:
                        skipped_targets += 1
                        continue

                    if packet_count == 0:
                        continue

                    # Scale link width based on traffic (logarithmic scale)
                    link_width = min(10, 1 + math.log10(packet_count))

                    links.append(
                        {
                            "source": src_ip,  # Use IP addresses, not indices
                            "target": dst_ip,  # Use IP addresses, not indices
                            "value": link_width,
                            "packets": packet_count,
                            "type": "traffic_flow",
                        }
                    )

            # Add debug info to metadata if connections were skipped
            if skipped_sources > 0 or skipped_targets > 0:
                print(
                    f"[DEBUG] Skipped {skipped_sources} source IPs and {skipped_targets} target IPs not in device list"
                )

        return {
            "nodes": nodes,
            "links": links,  # Only real traffic flows, no inferred connections
            "metadata": {
                "total_devices": len(devices),
                "traffic_flows": len(links),
                "stealth_devices": len([n for n in nodes if n.get("stealth", False)]),
                "data_source": "traffic_analysis",
            },
        }

    def _merge_links(self, traffic_links: List[Dict], topology_links: List[Dict]) -> List[Dict]:
        """
        Merge traffic flow links with topology links.

        Combines actual observed traffic flows with inferred topology connections,
        preferring real traffic data when both exist between the same nodes.
        This creates a comprehensive view showing both actual usage and logical
        network structure.

        Args:
            traffic_links: Links from passive traffic analysis
            topology_links: Links from topology inference

        Returns:
            Merged list with duplicates removed, traffic flows prioritized
        """
        # Create a set of node pairs that have traffic flows
        traffic_pairs = set()
        for link in traffic_links:
            pair = (link["source"], link["target"])
            traffic_pairs.add(pair)
            traffic_pairs.add((link["target"], link["source"]))  # Bidirectional

        # Add topology links that don't have traffic flows
        merged = traffic_links.copy()
        for link in topology_links:
            pair = (link["source"], link["target"])
            if pair not in traffic_pairs:
                merged.append(link)

        return merged

    def _get_device_group(self, device: Dict) -> int:
        """
        Assign visual group based on device characteristics and criticality.

        Groups are used for:
        - Visual clustering in force-directed layouts
        - Color coding in visualizations
        - Determining node importance/size
        - Layout positioning hints

        Group hierarchy:
        1. Critical infrastructure (routers, firewalls)
        2. Core services (switches, domain controllers)
        3. Critical services with dependencies
        4. Server infrastructure
        5. Industrial/OT systems
        6. End user devices
        7. IoT devices
        8. Unknown/other

        Args:
            device: Device dictionary with type and metadata

        Returns:
            Group number (1-8) for visualization grouping
        """
        device_type = device.get("type", "unknown")
        subtype = device.get("subtype", "")
        is_critical = device.get("critical", False)
        dependent_count = device.get("dependent_count", 0)

        # Critical infrastructure (group 1)
        if device_type in ["router", "firewall"] or subtype == "gateway":
            return 1
        # Core infrastructure (group 2)
        elif device_type in ["switch", "domain_controller", "dns_server", "ntp_server"]:
            return 2
        # Critical services with many dependents (group 3)
        elif is_critical and dependent_count > 3:
            return 3
        # Server infrastructure (group 4)
        elif "server" in device_type or device_type in [
            "web_server",
            "database",
            "backup_server",
            "monitoring_server",
        ]:
            return 4
        # Industrial/OT systems (group 5)
        elif device_type in ["plc", "scada", "ups"] or subtype in ["plc", "scada", "ups"]:
            return 5
        # End user devices (group 6)
        elif device_type in ["workstation", "printer", "voip"]:
            return 6
        # IoT and other devices (group 7)
        elif device_type == "iot":
            return 7
        else:
            return 8

    def _create_network_links(self, devices: List[Dict], links: List[Dict], node_map: Dict):
        """Create network topology links based on device types and relationships

        This method attempts to infer logical network connections based on:
        1. Device types (routers, switches, servers, workstations)
        2. Network hierarchy (routers -> switches -> end devices)
        3. Service relationships (web servers -> databases)

        For small networks without infrastructure devices, no connections are created
        unless there's actual traffic flow data available.
        """
        # Categorize devices by type for topology generation
        # This classification drives the connection logic
        routers = [d for d in devices if d.get("type") == "router"]
        switches = [d for d in devices if d.get("type") == "switch"]
        servers = [
            d
            for d in devices
            if "server" in d.get("type", "") or d.get("type") in ["web_server", "database"]
        ]
        workstations = [d for d in devices if d.get("type") == "workstation"]
        others = [d for d in devices if d.get("type") in ["printer", "iot", "unknown"]]

        # If no infrastructure devices exist, don't create artificial connections
        # The traffic flow data will show the real connections
        if not routers and not switches:
            # Only create connections if we have clear evidence of infrastructure
            # For example, if there's a device that looks like it's acting as a gateway
            gateway_candidates = []
            for device in devices:
                # Check if device has router/firewall-like characteristics
                services = device.get("services", [])
                if any(svc in services for svc in ["ssh", "telnet", "https", "snmp"]):
                    if len(device.get("open_ports", [])) > 5:  # Multiple services
                        gateway_candidates.append(device)

            # If we found a likely gateway, connect other devices to it
            if gateway_candidates:
                gateway = gateway_candidates[0]  # Pick the most likely gateway
                for device in devices:
                    if device["ip"] != gateway["ip"]:
                        # Only connect if it makes sense (not between two workstations)
                        if (
                            device.get("type") != "workstation"
                            or gateway.get("type") != "workstation"
                        ):
                            links.append(
                                {
                                    "source": gateway["ip"],
                                    "target": device["ip"],
                                    "value": 1,
                                    "type": "inferred",
                                }
                            )

            return  # Exit early - let traffic flow data show real connections

        # Strategy 1: Connect all infrastructure devices
        if len(routers) > 1:
            # Connect routers in a ring for redundancy
            for i in range(len(routers)):
                next_router = routers[(i + 1) % len(routers)]
                links.append(
                    {
                        "source": routers[i]["ip"],
                        "target": next_router["ip"],
                        "value": 4,
                        "type": "backbone",
                    }
                )

        # Strategy 2: Connect switches to routers
        for switch in switches:
            if routers:
                # Connect to nearest router (by IP proximity)
                nearest_router = min(
                    routers, key=lambda r: self._ip_distance(switch["ip"], r["ip"])
                )
                links.append(
                    {
                        "source": switch["ip"],
                        "target": nearest_router["ip"],
                        "value": 3,
                        "type": "uplink",
                    }
                )

        # Strategy 3: Connect servers intelligently
        for server in servers:
            # Critical servers connect directly to routers
            if server.get("critical", False) and routers:
                router = min(routers, key=lambda r: self._ip_distance(server["ip"], r["ip"]))
                links.append(
                    {"source": server["ip"], "target": router["ip"], "value": 3, "type": "critical"}
                )
            # Other servers connect to switches or routers
            else:
                infrastructure = switches + routers
                if infrastructure:
                    target = min(
                        infrastructure, key=lambda i: self._ip_distance(server["ip"], i["ip"])
                    )
                    links.append(
                        {
                            "source": server["ip"],
                            "target": target["ip"],
                            "value": 2,
                            "type": "server_link",
                        }
                    )

        # Strategy 4: Connect workstations to switches (or routers if no switches)
        for workstation in workstations:
            infrastructure = switches if switches else routers
            if infrastructure:
                # Distribute workstations among switches
                target = infrastructure[hash(workstation["ip"]) % len(infrastructure)]
                links.append(
                    {
                        "source": workstation["ip"],
                        "target": target["ip"],
                        "value": 1,
                        "type": "access",
                    }
                )

        # Strategy 5: Connect other devices (printers, IoT) to local infrastructure
        for device in others:
            infrastructure = switches + routers
            if infrastructure:
                target = min(infrastructure, key=lambda i: self._ip_distance(device["ip"], i["ip"]))
                links.append(
                    {
                        "source": device["ip"],
                        "target": target["ip"],
                        "value": 1,
                        "type": "peripheral",
                    }
                )

        # Strategy 6: Add some cross-connections for realism
        if len(servers) > 1:
            # Connect database servers to web servers
            db_servers = [s for s in servers if s.get("type") == "database"]
            web_servers = [s for s in servers if s.get("type") == "web_server"]

            for web_server in web_servers:
                if db_servers:
                    db_server = min(
                        db_servers, key=lambda d: self._ip_distance(web_server["ip"], d["ip"])
                    )
                    links.append(
                        {
                            "source": web_server["ip"],
                            "target": db_server["ip"],
                            "value": 2,
                            "type": "application",
                        }
                    )

    def generate_threejs_data(self, devices: List[Dict]) -> Dict:
        """
        Generate Three.js 3D visualization data with layered positioning.

        Creates a 3D network topology with:
        - Vertical layers by device type (routers at top, workstations at bottom)
        - Circular arrangement within each layer
        - Color coding by device type
        - Curved connections between layers

        The 3D view provides better separation of device types and reduces
        visual clutter compared to 2D layouts.

        Args:
            devices: List of device dictionaries

        Returns:
            Dictionary with positions, colors, labels, and connections for Three.js
        """
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
            "router": 0xF48771,  # Coral red
            "switch": 0x7CA9DD,  # Light blue
            "windows_server": 0x6FC28B,  # Green
            "linux_server": 0x4EC9B0,  # Teal
            "web_server": 0x569CD6,  # Blue
            "database": 0xB99BD8,  # Purple
            "workstation": 0x9CDCFE,  # Light cyan
            "printer": 0xDAA674,  # Orange
            "iot": 0xD4C896,  # Yellow
            "unknown": 0x858585,  # Gray
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
            "unknown": {"y": -4, "radius": 8, "spread": 1.0},
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
                    "z": 0 + random.uniform(-0.5, 0.5),
                }
                # Store position and create visual elements
                positions.append(position)
                device_positions[device["ip"]] = position
                device_colors.append(colors.get(device_type, colors["unknown"]))

                labels.append(
                    {
                        "text": device.get("hostname") or device["ip"],
                        "position": position,
                        "type": device_type,
                        "critical": device.get("critical", False),
                    }
                )
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
                        "z": radius * math.sin(angle) + random.uniform(-0.3, 0.3),
                    }

                    # Store position and create visual elements
                    positions.append(position)
                    device_positions[device["ip"]] = position
                    device_colors.append(colors.get(device_type, colors["unknown"]))

                    labels.append(
                        {
                            "text": device.get("hostname") or device["ip"],
                            "position": position,
                            "type": device_type,
                            "critical": device.get("critical", False),
                        }
                    )

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
                "connections": len(connections),
            },
        }

    def _create_3d_connections(self, devices: List[Dict], positions: Dict, connections: List[Dict]):
        """
        Create 3D connections with visual variety and network hierarchy.

        Generates curved connections between devices with different styles:
        - Backbone: Thick red lines between routers
        - Uplinks: Medium cyan lines from switches to routers
        - Server: Blue lines for server connections
        - Access: Green lines for workstation connections
        - Peripheral: Yellow lines for IoT/printer connections

        Connection thickness and opacity indicate importance and traffic volume.

        Args:
            devices: List of all devices
            positions: Dictionary mapping IPs to 3D positions
            connections: List to append connection data to
        """
        # Categorize devices
        routers = [d for d in devices if d.get("type") == "router"]
        switches = [d for d in devices if d.get("type") == "switch"]
        servers = [
            d
            for d in devices
            if "server" in d.get("type", "") or d.get("type") in ["web_server", "database"]
        ]
        clients = [d for d in devices if d.get("type") in ["workstation", "printer", "iot"]]

        # Connection types with different visual properties
        connection_styles = {
            "backbone": {"color": "#ff6b6b", "opacity": 0.8, "thickness": 3},
            "uplink": {"color": "#4ecdc4", "opacity": 0.7, "thickness": 2.5},
            "server": {"color": "#45b7d1", "opacity": 0.6, "thickness": 2},
            "access": {"color": "#96ceb4", "opacity": 0.4, "thickness": 1.5},
            "peripheral": {"color": "#feca57", "opacity": 0.3, "thickness": 1},
        }

        def add_connection(dev1, dev2, style_name):
            if dev1["ip"] in positions and dev2["ip"] in positions:
                style = connection_styles[style_name]
                connections.append(
                    {
                        "start": positions[dev1["ip"]],
                        "end": positions[dev2["ip"]],
                        "color": style["color"],
                        "opacity": style["opacity"],
                        "thickness": style["thickness"],
                        "type": style_name,
                    }
                )

        # 1. Connect infrastructure backbone
        for i in range(len(routers)):
            for j in range(i + 1, len(routers)):
                add_connection(routers[i], routers[j], "backbone")

        # 2. Connect switches to routers
        for switch in switches:
            if routers:
                nearest_router = min(
                    routers, key=lambda r: self._ip_distance(switch["ip"], r["ip"])
                )
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
                    target = min(
                        infrastructure, key=lambda i: self._ip_distance(server["ip"], i["ip"])
                    )
                    add_connection(server, target, "server")

        # 4. Connect clients to local infrastructure
        for client in clients:
            # Prefer switches for workstations, any infrastructure for others
            infrastructure = (
                switches if switches and client.get("type") == "workstation" else switches + routers
            )
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
                    db_server = min(
                        db_servers, key=lambda d: self._ip_distance(web_server["ip"], d["ip"])
                    )
                    add_connection(web_server, db_server, "server")

    def _ip_distance(self, ip1: str, ip2: str) -> int:
        """
        Calculate weighted Manhattan distance between IPs for logical proximity.

        Uses weighted octets to prioritize subnet locality:
        - Same subnet (first 3 octets) = very close
        - Different subnets = progressively farther

        This helps create realistic topologies where devices in the same
        subnet tend to connect to the same infrastructure.

        Args:
            ip1: First IP address
            ip2: Second IP address

        Returns:
            Integer distance value (lower = closer)
        """
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
        """
        Count devices by type for summary statistics.

        Simple aggregation used in metadata generation to show
        network composition at a glance.

        Args:
            devices: List of device dictionaries

        Returns:
            Dictionary mapping device types to counts
        """
        counts = {}
        for device in devices:
            dtype = device.get("type", "unknown")
            counts[dtype] = counts.get(dtype, 0) + 1
        return counts

    def _calculate_critical_stats(self, devices: List[Dict]) -> Dict:
        """
        Calculate comprehensive statistics about critical assets.

        Analyzes critical infrastructure to provide insights on:
        - Total critical device count
        - High-dependency devices (many dependents)
        - Always-on requirements
        - Long uptime devices (stability indicators)
        - Distribution by device type

        These metrics help prioritize security efforts and maintenance windows.

        Args:
            devices: List of device dictionaries

        Returns:
            Dictionary with critical asset statistics
        """
        stats = {
            "total_critical": 0,
            "high_dependency": 0,  # >20 dependents
            "always_on": 0,
            "long_uptime": 0,  # >180 days
            "critical_by_type": {},
            "critical_tags": {},
        }

        for device in devices:
            if device.get("critical", False):
                stats["total_critical"] += 1

                # Count by type
                dtype = device.get("type", "unknown")
                stats["critical_by_type"][dtype] = stats["critical_by_type"].get(dtype, 0) + 1

            # High dependency devices
            if device.get("dependent_count", 0) > 20:
                stats["high_dependency"] += 1

            # Always-on devices
            if device.get("always_on", False):
                stats["always_on"] += 1

            # Long uptime devices
            if device.get("uptime_days", 0) > 180:
                stats["long_uptime"] += 1

            # Count tags
            for tag in device.get("tags", []):
                if tag in ["critical", "high_dependency", "always_on", "long_uptime"]:
                    stats["critical_tags"][tag] = stats["critical_tags"].get(tag, 0) + 1

        return stats

    def generate_subnet_topology(self, devices: List[Dict]) -> Dict:
        """
        Generate subnet-level topology view for network segmentation analysis.

        Aggregates devices by /24 subnets to show:
        - Device distribution across subnets
        - Device type composition per subnet
        - Critical asset distribution
        - Subnet utilization

        This high-level view helps identify:
        - Network segmentation effectiveness
        - Subnet purposes (server farm, user segment, etc.)
        - Critical asset concentration risks

        Args:
            devices: List of device dictionaries

        Returns:
            Dictionary with subnet analysis data
        """
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
                    "critical_count": 0,
                }

            subnets[subnet_key]["devices"].append(device)
            subnets[subnet_key]["device_count"] += 1

            device_type = device.get("type", "unknown")
            subnets[subnet_key]["types"][device_type] = (
                subnets[subnet_key]["types"].get(device_type, 0) + 1
            )

            if device.get("critical", False):
                subnets[subnet_key]["critical_count"] += 1

        return {
            "subnets": list(subnets.values()),
            "total_subnets": len(subnets),
            "total_devices": len(devices),
        }
