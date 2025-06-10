"""
Traffic Flow Visualization Module

Generates visualization data for traffic flows discovered through passive analysis
"""

import json
import logging
import math
from collections import defaultdict
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)


class TrafficVisualizer:
    """Generate visualization data for traffic flows"""

    def __init__(self):
        """Initialize traffic visualizer"""
        self.color_palette = {
            "http": "#4CAF50",  # Green
            "https": "#2196F3",  # Blue
            "ssh": "#FF9800",  # Orange
            "dns": "#9C27B0",  # Purple
            "smtp": "#F44336",  # Red
            "database": "#795548",  # Brown
            "unknown": "#9E9E9E",  # Grey
        }

    def generate_flow_visualization(
        self, devices: List[Dict], flow_matrix: Dict[str, Dict[str, int]]
    ) -> Dict:
        """Generate D3.js compatible flow visualization data

        Args:
            devices: List of all devices (active + passive)
            flow_matrix: Communication matrix from passive analysis

        Returns:
            D3.js force graph data with traffic flows
        """
        # Create device lookup
        device_map = {d["ip"]: d for d in devices}

        # Build nodes
        nodes = []
        node_index = {}

        for i, device in enumerate(devices):
            # Determine node size based on traffic
            ip = device["ip"]
            total_traffic = sum(flow_matrix.get(ip, {}).values())

            # Add incoming traffic
            for src in flow_matrix:
                total_traffic += flow_matrix[src].get(ip, 0)

            # Scale node size
            size = 10 + min(40, total_traffic / 1000)

            # Determine if stealth device
            is_stealth = device.get("stealth_device", False)

            node = {
                "id": ip,
                "label": device.get("hostname", ip),
                "type": device.get("type", "unknown"),
                "size": size,
                "stealth": is_stealth,
                "color": self._get_device_color(device),
                "passive_analysis": device.get("passive_analysis", {}),
                "traffic_volume": total_traffic,
            }

            nodes.append(node)
            node_index[ip] = i

        # Build links from flow matrix
        links = []
        for src_ip, destinations in flow_matrix.items():
            if src_ip not in node_index:
                continue

            for dst_ip, packet_count in destinations.items():
                if dst_ip not in node_index or packet_count == 0:
                    continue

                # Determine link properties
                link_strength = min(5, packet_count / 100)

                # Guess service type from devices
                src_device = device_map.get(src_ip, {})
                dst_device = device_map.get(dst_ip, {})
                service_type = self._guess_service_type(src_device, dst_device)

                link = {
                    "source": node_index[src_ip],
                    "target": node_index[dst_ip],
                    "value": link_strength,
                    "packets": packet_count,
                    "service": service_type,
                    "color": self.color_palette.get(service_type, self.color_palette["unknown"]),
                }

                links.append(link)

        # Generate summary statistics
        stats = {
            "total_devices": len(devices),
            "stealth_devices": len([d for d in devices if d.get("stealth_device", False)]),
            "total_flows": len(links),
            "top_talkers": self._get_top_talkers(flow_matrix, device_map, 5),
        }

        return {"nodes": nodes, "links": links, "stats": stats}

    def generate_sankey_diagram(
        self, service_usage: Dict[str, List[str]], devices: List[Dict]
    ) -> Dict:
        """Generate Sankey diagram data for service flows

        Args:
            service_usage: Service to device IP mapping
            devices: List of all devices

        Returns:
            Sankey diagram data
        """
        # Create device lookup
        device_map = {d["ip"]: d for d in devices}

        # Build nodes for Sankey
        nodes = []
        node_map = {}

        # Add service nodes
        for service in service_usage:
            node_id = f"service_{service}"
            nodes.append({"id": node_id, "name": service.upper(), "type": "service"})
            node_map[node_id] = len(nodes) - 1

        # Add device type nodes
        device_types = defaultdict(list)
        for service, ips in service_usage.items():
            for ip in ips:
                device = device_map.get(ip, {})
                device_type = device.get("type", "unknown")
                device_types[device_type].append((service, ip))

        for device_type in device_types:
            node_id = f"type_{device_type}"
            if node_id not in node_map:
                nodes.append(
                    {
                        "id": node_id,
                        "name": device_type.replace("_", " ").title(),
                        "type": "device_type",
                    }
                )
                node_map[node_id] = len(nodes) - 1

        # Build links
        links = []
        for device_type, connections in device_types.items():
            # Count connections per service
            service_counts = defaultdict(int)
            for service, ip in connections:
                service_counts[service] += 1

            # Create links
            for service, count in service_counts.items():
                links.append(
                    {
                        "source": node_map[f"service_{service}"],
                        "target": node_map[f"type_{device_type}"],
                        "value": count,
                    }
                )

        return {"nodes": nodes, "links": links}

    def generate_traffic_heatmap(
        self, flow_matrix: Dict[str, Dict[str, int]], top_n: int = 20
    ) -> Dict:
        """Generate heatmap data for traffic patterns

        Args:
            flow_matrix: Communication matrix
            top_n: Number of top devices to include

        Returns:
            Heatmap visualization data
        """
        # Find top talkers
        traffic_totals = defaultdict(int)
        for src, destinations in flow_matrix.items():
            for dst, packets in destinations.items():
                traffic_totals[src] += packets
                traffic_totals[dst] += packets

        # Get top N devices
        top_devices = sorted(traffic_totals.items(), key=lambda x: x[1], reverse=True)[:top_n]
        top_ips = [ip for ip, _ in top_devices]

        # Build heatmap data
        data = []
        for i, src_ip in enumerate(top_ips):
            for j, dst_ip in enumerate(top_ips):
                if src_ip in flow_matrix and dst_ip in flow_matrix[src_ip]:
                    value = flow_matrix[src_ip][dst_ip]
                    if value > 0:
                        data.append(
                            {
                                "source": i,
                                "target": j,
                                "value": value,
                                "source_ip": src_ip,
                                "target_ip": dst_ip,
                            }
                        )

        return {
            "ips": top_ips,
            "data": data,
            "max_value": max([d["value"] for d in data]) if data else 0,
        }

    def generate_timeline_data(self, flows: List[Dict]) -> Dict:
        """Generate timeline visualization of traffic flows

        Args:
            flows: List of traffic flows with timestamps

        Returns:
            Timeline visualization data
        """
        # Group flows by time buckets (e.g., per minute)
        time_buckets = defaultdict(
            lambda: {"total_flows": 0, "total_bytes": 0, "services": defaultdict(int)}
        )

        for flow in flows:
            # Parse timestamp and bucket to minute
            start_time = flow.get("start_time", "")
            if start_time:
                # Simple bucketing - would need proper datetime parsing
                bucket = start_time[:16]  # YYYY-MM-DD HH:MM

                time_buckets[bucket]["total_flows"] += 1
                time_buckets[bucket]["total_bytes"] += flow.get("bytes", 0)

                service = flow.get("service", "unknown")
                time_buckets[bucket]["services"][service] += 1

        # Convert to list format
        timeline = []
        for timestamp, data in sorted(time_buckets.items()):
            timeline.append(
                {
                    "time": timestamp,
                    "flows": data["total_flows"],
                    "bytes": data["total_bytes"],
                    "top_service": max(data["services"].items(), key=lambda x: x[1])[0]
                    if data["services"]
                    else "unknown",
                }
            )

        return {
            "timeline": timeline,
            "total_duration": len(timeline),
            "peak_time": max(timeline, key=lambda x: x["flows"])["time"] if timeline else None,
        }

    def _get_device_color(self, device: Dict) -> str:
        """Get color for device based on type"""
        type_colors = {
            "router": "#F44336",
            "switch": "#E91E63",
            "firewall": "#FF5722",
            "server": "#2196F3",
            "workstation": "#4CAF50",
            "printer": "#FF9800",
            "iot": "#9C27B0",
            "unknown": "#9E9E9E",
        }

        device_type = device.get("type", "unknown")

        # Stealth devices get darker shade
        if device.get("stealth_device", False):
            base_color = type_colors.get(device_type, type_colors["unknown"])
            # Simple darkening - in real implementation would use proper color manipulation
            return base_color.replace("#", "#7F")

        return type_colors.get(device_type, type_colors["unknown"])

    def _guess_service_type(self, src_device: Dict, dst_device: Dict) -> str:
        """Guess service type based on device types"""
        # Check passive analysis data
        src_services = src_device.get("passive_analysis", {}).get("services_observed", [])
        dst_services = dst_device.get("passive_analysis", {}).get("services_observed", [])

        # Common services
        for service in ["https", "http", "ssh", "dns", "smtp"]:
            if service in src_services or service in dst_services:
                return service

        # Guess from device types
        if dst_device.get("type") == "web_server":
            return "http"
        elif dst_device.get("type") == "database":
            return "database"
        elif dst_device.get("type") == "dns_server":
            return "dns"

        return "unknown"

    def _get_top_talkers(self, flow_matrix: Dict, device_map: Dict, limit: int) -> List[Dict]:
        """Get top talking devices from flow matrix"""
        traffic_totals = defaultdict(int)

        for src, destinations in flow_matrix.items():
            for dst, packets in destinations.items():
                traffic_totals[src] += packets
                traffic_totals[dst] += packets

        top_talkers = []
        for ip, total in sorted(traffic_totals.items(), key=lambda x: x[1], reverse=True)[:limit]:
            device = device_map.get(ip, {})
            top_talkers.append(
                {
                    "ip": ip,
                    "hostname": device.get("hostname", ip),
                    "type": device.get("type", "unknown"),
                    "traffic_volume": total,
                    "stealth": device.get("stealth_device", False),
                }
            )

        return top_talkers
