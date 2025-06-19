"""
Network Utilities Module - IP address manipulation and network calculations

This module provides essential network-related utilities for NetworkMapper,
handling IP address validation, network expansion, subnet calculations,
and DNS operations. It serves as the foundation for all network-based
operations throughout the application.

Key capabilities:
- Target validation (IPs, CIDRs, hostnames)
- Network expansion and IP sorting
- Subnet detection and grouping
- Private/public IP classification
- Reverse DNS lookups
- Network statistics generation

Design Philosophy:
- Use Python's ipaddress module for robust IP handling
- Graceful fallbacks for invalid inputs
- Support both IPv4 and IPv6 (where applicable)
- Efficient operations for large IP lists
"""

import ipaddress
import socket
from typing import List, Optional, Tuple


class NetworkUtils:
    """
    Collection of static methods for network-related operations.

    All methods are static since they perform stateless operations
    on network data. This design allows easy usage throughout the
    application without instantiation.
    """

    @staticmethod
    def validate_target(target: str) -> Tuple[bool, Optional[str]]:
        """
        Validate network target (IP, CIDR, or hostname).

        Performs comprehensive validation to ensure the target is scannable.
        Accepts multiple formats to provide flexibility:
        - Single IP: "192.168.1.1"
        - CIDR notation: "192.168.1.0/24"
        - Hostname: "router.local"
        - IP range: "192.168.1.1-50" (validated elsewhere)

        The validation cascade tries each format in order, ensuring
        maximum compatibility with user input.

        Args:
            target: String representation of target to validate

        Returns:
            Tuple of (is_valid, error_message)
            - is_valid: True if target is valid
            - error_message: None if valid, error string if invalid
        """
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
        """
        Expand CIDR notation to list of individual IP addresses.

        Handles network expansion for scanning operations:
        - CIDR networks: Expands to all usable host IPs
        - Single IPs: Returns as single-item list
        - Hostnames: Returns as-is for resolver handling

        Note: This excludes network and broadcast addresses for
        CIDR notations to focus on scannable hosts.

        Args:
            target: Network target (CIDR, IP, or hostname)

        Returns:
            List of IP addresses to scan
        """
        try:
            network = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            # Single IP or hostname
            return [target]

    @staticmethod
    def get_subnet(ip: str) -> str:
        """
        Get /24 subnet for an IP address.

        Standardizes IPs into /24 subnets for network grouping.
        This is useful for:
        - Organizing scan results by subnet
        - Detecting network boundaries
        - Visualizing network topology

        Always returns /24 (255.255.255.0) regardless of actual
        subnet mask, providing consistent grouping.

        Args:
            ip: IP address string

        Returns:
            Subnet string in CIDR notation (e.g., "192.168.1.0/24")
            or "unknown" if IP is invalid
        """
        try:
            # Create /24 network
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(network)
        except ValueError:
            return "unknown"

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """
        Check if IP address is in private/RFC1918 range.

        Identifies private IPs as defined by:
        - 10.0.0.0/8 (Class A)
        - 172.16.0.0/12 (Class B)
        - 192.168.0.0/16 (Class C)
        - IPv6 private ranges (fc00::/7)

        This classification helps with:
        - Security assessments (internal vs external)
        - Network topology understanding
        - Scan strategy decisions

        Args:
            ip: IP address to check

        Returns:
            True if IP is private, False otherwise
        """
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    @staticmethod
    def get_ip_info(ip: str) -> dict:
        """
        Get comprehensive information about an IP address.

        Provides detailed IP metadata for analysis and reporting:
        - Version (4 or 6)
        - Address type classifications
        - Reverse DNS information

        This rich data helps with:
        - Device identification (via reverse DNS)
        - Network segmentation analysis
        - Security policy decisions

        Args:
            ip: IP address to analyze

        Returns:
            Dictionary containing:
            - ip: Normalized IP string
            - version: IP version (4 or 6)
            - is_private: RFC1918 private address
            - is_global: Globally routable
            - is_multicast: Multicast address
            - is_loopback: Loopback address
            - reverse_dns: Hostname if resolvable
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return {
                "ip": str(ip_obj),
                "version": ip_obj.version,
                "is_private": ip_obj.is_private,
                "is_global": ip_obj.is_global,
                "is_multicast": ip_obj.is_multicast,
                "is_loopback": ip_obj.is_loopback,
                "reverse_dns": NetworkUtils.reverse_dns_lookup(ip),
            }
        except ValueError:
            return {"ip": ip, "error": "Invalid IP address"}

    @staticmethod
    def reverse_dns_lookup(ip: str) -> Optional[str]:
        """
        Perform reverse DNS lookup to find hostname.

        Attempts to resolve IP to hostname using PTR records.
        This is valuable for:
        - Device identification (often reveals device purpose)
        - Network documentation
        - Validation of DNS configuration

        Failures are common and expected (many IPs lack PTR records),
        so this gracefully returns None rather than raising exceptions.

        Args:
            ip: IP address to resolve

        Returns:
            Hostname if found, None if not resolvable
        """
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return None

    @staticmethod
    def sort_ips(ip_list: List[str]) -> List[str]:
        """
        Sort IP addresses in proper numerical order.

        Standard string sorting fails for IPs (e.g., "10.0.0.2" comes
        after "10.0.0.100"). This method ensures correct numerical
        sorting for better readability in reports and tables.

        Handles mixed valid/invalid IPs by falling back to string
        sort for unparseable addresses.

        Args:
            ip_list: List of IP address strings

        Returns:
            Properly sorted list of IP addresses
        """
        try:
            return sorted(ip_list, key=lambda ip: ipaddress.ip_address(ip))
        except ValueError:
            # Fallback to string sort if some IPs are invalid
            return sorted(ip_list)

    @staticmethod
    def calculate_network_summary(devices: List[dict]) -> dict:
        """
        Calculate comprehensive network statistics from device list.

        Aggregates network-wide metrics for reporting and analysis:
        - Device counts and distributions
        - Subnet utilization
        - Private vs public IP breakdown
        - IP range detection

        This summary provides a quick network overview, useful for:
        - Executive reports
        - Network planning
        - Anomaly detection (unexpected subnets)
        - Capacity analysis

        Args:
            devices: List of device dictionaries with 'ip' field

        Returns:
            Dictionary containing:
            - total_devices: Total device count
            - subnets: Dict of subnet -> device count
            - private_ips: Count of RFC1918 addresses
            - public_ips: Count of public addresses
            - ip_ranges: List of IP range strings
        """
        summary = {
            "total_devices": len(devices),
            "subnets": {},
            "private_ips": 0,
            "public_ips": 0,
            "ip_ranges": [],
        }

        ips = []
        for device in devices:
            ip = device.get("ip")
            if not ip:
                continue

            try:
                ip_obj = ipaddress.ip_address(ip)
                ips.append(ip_obj)

                # Count private/public
                if ip_obj.is_private:
                    summary["private_ips"] += 1
                else:
                    summary["public_ips"] += 1

                # Group by subnet
                subnet = NetworkUtils.get_subnet(ip)
                if subnet not in summary["subnets"]:
                    summary["subnets"][subnet] = 0
                summary["subnets"][subnet] += 1

            except ValueError:
                continue

        # Calculate IP range
        if ips:
            sorted_ips = sorted(ips)
            summary["ip_ranges"] = [f"{sorted_ips[0]} - {sorted_ips[-1]}"]

        return summary
