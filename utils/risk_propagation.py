"""Risk Propagation Modeling for Network Failure Analysis

This module provides functionality to simulate device failures and analyze
their cascading impact on the network based on dependencies and traffic flows.
"""

import json
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ImpactAnalysis:
    """Results of a failure simulation"""

    failed_device: str
    directly_impacted: List[str] = field(default_factory=list)
    indirectly_impacted: List[str] = field(default_factory=list)
    total_impacted: int = 0
    critical_services_lost: List[str] = field(default_factory=list)
    impact_severity: str = "Low"  # Low, Medium, High, Critical
    affected_subnets: List[str] = field(default_factory=list)
    redundancy_available: bool = False
    mitigation_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "failed_device": self.failed_device,
            "directly_impacted": self.directly_impacted,
            "indirectly_impacted": self.indirectly_impacted,
            "total_impacted": self.total_impacted,
            "critical_services_lost": self.critical_services_lost,
            "impact_severity": self.impact_severity,
            "affected_subnets": self.affected_subnets,
            "redundancy_available": self.redundancy_available,
            "mitigation_suggestions": self.mitigation_suggestions,
            "timestamp": datetime.now().isoformat(),
        }


class RiskPropagationAnalyzer:
    """Analyzes cascading failures in network topology"""

    def __init__(self):
        self.dependency_graph = {}
        self.device_map = {}
        self.flow_matrix = {}
        self.critical_services = {
            "dns": ["dns", "domain"],
            "authentication": ["ldap", "kerberos", "radius"],
            "database": ["mysql", "postgresql", "oracle", "mssql"],
            "web": ["http", "https"],
            "ntp": ["ntp"],
            "dhcp": ["dhcp"],
            "gateway": ["router", "firewall"],
        }

    def load_network_data(self, devices: List[Dict], flow_matrix: Optional[Dict] = None):
        """Load network topology and traffic flow data"""
        # Build device map
        self.device_map = {device["ip"]: device for device in devices}

        # Load traffic flow matrix if available
        if flow_matrix:
            self.flow_matrix = flow_matrix

        # Build dependency graph from device data and flows
        self._build_dependency_graph(devices)

    def _build_dependency_graph(self, devices: List[Dict]):
        """Build network dependency graph from device relationships and traffic flows"""
        self.dependency_graph = defaultdict(lambda: {"depends_on": set(), "dependents": set()})

        # Extract dependencies from device data
        for device in devices:
            device_ip = device["ip"]

            # Check for explicit dependencies
            if "dependencies" in device:
                for dep_hostname in device["dependencies"]:
                    # Find IP for hostname
                    dep_device = next(
                        (d for d in devices if d.get("hostname") == dep_hostname), None
                    )
                    if dep_device:
                        dep_ip = dep_device["ip"]
                        self.dependency_graph[device_ip]["depends_on"].add(dep_ip)
                        self.dependency_graph[dep_ip]["dependents"].add(device_ip)

            # Infer dependencies based on device type and services
            self._infer_dependencies(device, devices)

        # Add dependencies from traffic flows
        if self.flow_matrix:
            self._add_flow_dependencies()

    def _infer_dependencies(self, device: Dict, all_devices: List[Dict]):
        """Infer dependencies based on device type and network role"""
        device_ip = device["ip"]
        device_type = device.get("type", "unknown")

        # All devices depend on gateways/routers
        if device_type not in ["router", "firewall"]:
            gateways = [
                d
                for d in all_devices
                if d.get("type") in ["router", "firewall"] or d.get("is_gateway", False)
            ]
            for gateway in gateways:
                self.dependency_graph[device_ip]["depends_on"].add(gateway["ip"])
                self.dependency_graph[gateway["ip"]]["dependents"].add(device_ip)

        # All devices depend on DNS servers
        if device_type != "dns_server":
            dns_servers = [
                d
                for d in all_devices
                if d.get("type") == "dns_server"
                or any("dns" in str(s).lower() for s in d.get("services", []))
            ]
            for dns in dns_servers:
                self.dependency_graph[device_ip]["depends_on"].add(dns["ip"])
                self.dependency_graph[dns["ip"]]["dependents"].add(device_ip)

        # Domain-joined devices depend on domain controllers
        if (
            device.get("os", "").lower().startswith("windows")
            and device_type != "domain_controller"
        ):
            dcs = [
                d
                for d in all_devices
                if d.get("type") == "domain_controller"
                or any("ldap" in str(s).lower() for s in d.get("services", []))
            ]
            for dc in dcs:
                self.dependency_graph[device_ip]["depends_on"].add(dc["ip"])
                self.dependency_graph[dc["ip"]]["dependents"].add(device_ip)

    def _add_flow_dependencies(self):
        """Add dependencies based on traffic flow patterns"""
        # Analyze flow matrix to identify service dependencies
        for src_ip, destinations in self.flow_matrix.items():
            for dst_ip, packet_count in destinations.items():
                if packet_count > 100:  # Significant traffic indicates dependency
                    src_device = self.device_map.get(src_ip, {})
                    dst_device = self.device_map.get(dst_ip, {})

                    # Check if destination provides critical services
                    dst_services = dst_device.get("services", [])
                    for service_type, service_names in self.critical_services.items():
                        if any(sn in str(s).lower() for s in dst_services for sn in service_names):
                            # Source depends on destination for this service
                            self.dependency_graph[src_ip]["depends_on"].add(dst_ip)
                            self.dependency_graph[dst_ip]["dependents"].add(src_ip)
                            break

    def simulate_device_failure(self, failed_device_ip: str) -> ImpactAnalysis:
        """Simulate a device failure and analyze cascading impact"""
        if failed_device_ip not in self.device_map:
            logger.warning(f"Device {failed_device_ip} not found in network")
            return ImpactAnalysis(failed_device=failed_device_ip)

        analysis = ImpactAnalysis(failed_device=failed_device_ip)
        failed_device = self.device_map[failed_device_ip]

        # Get directly impacted devices (those that depend on failed device)
        direct_deps = self.dependency_graph[failed_device_ip]["dependents"]
        analysis.directly_impacted = list(direct_deps)

        # Perform breadth-first search to find all impacted devices
        visited = set()
        queue = deque([(failed_device_ip, 0)])  # (device_ip, depth)
        impact_by_depth = defaultdict(set)

        while queue:
            current_ip, depth = queue.popleft()

            if current_ip in visited:
                continue

            visited.add(current_ip)
            impact_by_depth[depth].add(current_ip)

            # Add dependents to queue
            for dependent_ip in self.dependency_graph[current_ip]["dependents"]:
                if dependent_ip not in visited:
                    queue.append((dependent_ip, depth + 1))

        # Calculate indirect impact (depth > 1)
        for depth, devices in impact_by_depth.items():
            if depth > 1:
                analysis.indirectly_impacted.extend(list(devices))

        # Remove the failed device itself from counts
        visited.discard(failed_device_ip)
        analysis.total_impacted = len(visited)

        # Analyze critical services lost
        failed_services = failed_device.get("services", [])
        for service_type, service_names in self.critical_services.items():
            if any(sn in str(s).lower() for s in failed_services for sn in service_names):
                analysis.critical_services_lost.append(service_type)

        # Determine impact severity
        analysis.impact_severity = self._calculate_severity(
            failed_device, analysis.total_impacted, analysis.critical_services_lost
        )

        # Find affected subnets
        affected_ips = visited
        subnets = set()
        for ip in affected_ips:
            parts = ip.split(".")
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            subnets.add(subnet)
        analysis.affected_subnets = list(subnets)

        # Check for redundancy
        analysis.redundancy_available = self._check_redundancy(failed_device, failed_services)

        # Generate mitigation suggestions
        analysis.mitigation_suggestions = self._generate_mitigations(
            failed_device, analysis.critical_services_lost, analysis.redundancy_available
        )

        return analysis

    def _calculate_severity(
        self, failed_device: Dict, impact_count: int, services_lost: List[str]
    ) -> str:
        """Calculate the severity of the failure impact"""
        severity_score = 0

        # Device criticality
        if failed_device.get("critical", False):
            severity_score += 3

        # Number of impacted devices
        if impact_count > 50:
            severity_score += 3
        elif impact_count > 20:
            severity_score += 2
        elif impact_count > 5:
            severity_score += 1

        # Critical services lost
        critical_service_weights = {
            "gateway": 3,
            "dns": 3,
            "authentication": 3,
            "database": 2,
            "dhcp": 2,
            "ntp": 1,
            "web": 1,
        }

        for service in services_lost:
            severity_score += critical_service_weights.get(service, 1)

        # Determine severity level
        if severity_score >= 8:
            return "Critical"
        elif severity_score >= 5:
            return "High"
        elif severity_score >= 2:
            return "Medium"
        else:
            return "Low"

    def _check_redundancy(self, failed_device: Dict, failed_services: List[str]) -> bool:
        """Check if redundant services are available"""
        device_type = failed_device.get("type", "unknown")

        # Find other devices of same type
        similar_devices = [
            d
            for d in self.device_map.values()
            if d["ip"] != failed_device["ip"] and d.get("type") == device_type
        ]

        if not similar_devices:
            return False

        # Check if similar devices provide same services
        for device in similar_devices:
            device_services = device.get("services", [])
            if any(s in device_services for s in failed_services):
                return True

        return False

    def _generate_mitigations(
        self, failed_device: Dict, services_lost: List[str], has_redundancy: bool
    ) -> List[str]:
        """Generate mitigation suggestions based on failure analysis"""
        suggestions = []
        device_type = failed_device.get("type", "unknown")

        if not has_redundancy:
            suggestions.append(f"Deploy redundant {device_type} for high availability")

        if "gateway" in services_lost:
            suggestions.append("Configure backup gateway/route for network redundancy")

        if "dns" in services_lost:
            suggestions.append("Configure secondary DNS servers on all devices")
            suggestions.append("Consider implementing local DNS caching")

        if "authentication" in services_lost:
            suggestions.append("Deploy secondary domain controller/LDAP server")
            suggestions.append("Enable cached credentials on workstations")

        if failed_device.get("critical", False):
            suggestions.append("Implement real-time monitoring for this critical device")
            suggestions.append("Create automated failover procedures")

        if len(self.dependency_graph[failed_device["ip"]]["dependents"]) > 3:
            suggestions.append("Consider distributing load across multiple devices")
            suggestions.append("Implement network segmentation to limit failure impact")

        return suggestions

    def find_single_points_of_failure(self) -> List[Tuple[str, int]]:
        """Identify devices that would cause significant impact if they fail"""
        spof_candidates = []

        for device_ip, device in self.device_map.items():
            # Simulate failure
            impact = self.simulate_device_failure(device_ip)

            # Check if it's a single point of failure
            if (
                impact.total_impacted > 10
                or impact.impact_severity in ["High", "Critical"]
                or len(impact.critical_services_lost) > 0
            ):
                spof_candidates.append((device_ip, impact.total_impacted))

        # Sort by impact count
        spof_candidates.sort(key=lambda x: x[1], reverse=True)

        return spof_candidates

    def generate_redundancy_report(self) -> Dict:
        """Generate a report on network redundancy and resilience"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "single_points_of_failure": [],
            "redundancy_gaps": [],
            "critical_dependencies": [],
            "recommendations": [],
        }

        # Find SPOFs
        spofs = self.find_single_points_of_failure()
        for device_ip, impact_count in spofs[:10]:  # Top 10
            device = self.device_map[device_ip]
            report["single_points_of_failure"].append(
                {
                    "ip": device_ip,
                    "hostname": device.get("hostname", "N/A"),
                    "type": device.get("type", "unknown"),
                    "impact_count": impact_count,
                    "critical": device.get("critical", False),
                }
            )

        # Check redundancy for critical services
        for service_type, service_names in self.critical_services.items():
            providers = []
            for device in self.device_map.values():
                device_services = device.get("services", [])
                if any(sn in str(s).lower() for s in device_services for sn in service_names):
                    providers.append(device)

            if len(providers) < 2:
                report["redundancy_gaps"].append(
                    {
                        "service": service_type,
                        "provider_count": len(providers),
                        "providers": [
                            {"ip": p["ip"], "hostname": p.get("hostname", "N/A")} for p in providers
                        ],
                    }
                )

        # Find critical dependency chains
        for device_ip, deps in self.dependency_graph.items():
            if len(deps["dependents"]) > 3:
                device = self.device_map[device_ip]
                report["critical_dependencies"].append(
                    {
                        "ip": device_ip,
                        "hostname": device.get("hostname", "N/A"),
                        "type": device.get("type", "unknown"),
                        "dependent_count": len(deps["dependents"]),
                    }
                )

        # Generate recommendations
        if report["single_points_of_failure"]:
            report["recommendations"].append(
                "Deploy redundant systems for identified single points of failure"
            )

        if report["redundancy_gaps"]:
            report["recommendations"].append(
                "Implement service redundancy for critical services with single providers"
            )

        if any(d["dependent_count"] > 50 for d in report["critical_dependencies"]):
            report["recommendations"].append(
                "Consider load distribution for devices with excessive dependencies"
            )

        return report
