"""
Scan profile configuration management.

This module centralizes all scan configurations, making them easily
maintainable and testable.
"""
from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum

from ...core.interfaces.scanner import ScanType


@dataclass
class ScanProfile:
    """Configuration profile for a scan type."""

    name: str
    description: str
    nmap_args: List[str]
    masscan_args: List[str]
    default_ports: Optional[str] = None
    timeout: int = 300
    requires_sudo: bool = False
    max_rate: Optional[int] = None


# Centralized scan profiles
SCAN_PROFILES: Dict[ScanType, ScanProfile] = {
    ScanType.DISCOVERY: ScanProfile(
        name="Discovery Scan",
        description="Quick host discovery to find active devices",
        nmap_args=[
            "-sn",  # Ping scan
            "-PE",  # ICMP echo
            "-PP",  # ICMP timestamp
            "-PM",  # ICMP netmask
            "-PS21,22,23,25,80,443,445,3389",  # TCP SYN to common ports
            "-PA80,443",  # TCP ACK
            "-PU161,162",  # UDP to SNMP ports
            "--max-retries",
            "2",
            "--host-timeout",
            "30s",
        ],
        masscan_args=["-p80,443,22,445,3389", "--rate=10000", "--ping"],
        timeout=60,
        requires_sudo=False,
    ),
    ScanType.INVENTORY: ScanProfile(
        name="Inventory Scan",
        description="Service detection and OS fingerprinting",
        nmap_args=[
            "-sS",  # TCP SYN scan
            "-sU",  # UDP scan for top ports
            "-sV",  # Version detection
            "-O",  # OS detection
            "--osscan-guess",  # Aggressive OS guessing
            "--max-os-tries",
            "2",  # More OS detection attempts
            "--version-intensity",
            "7",
            "--top-ports",
            "1000",
            "--max-retries",
            "2",
            "--host-timeout",
            "300s",
            "-T4",  # Consistent timing
            "--script",
            "discovery,safe",
        ],
        masscan_args=[],  # Not suitable for masscan
        default_ports="1-1000",
        timeout=300,
        requires_sudo=True,
    ),
    ScanType.DEEP: ScanProfile(
        name="Deep Scan",
        description="Comprehensive analysis with NSE scripts",
        nmap_args=[
            "-sS",  # TCP SYN scan
            "-sU",  # UDP scan
            "-sV",  # Version detection
            "-O",  # OS detection
            "--osscan-guess",  # Aggressive OS guessing
            "--max-os-tries",
            "3",  # More OS detection attempts
            "-A",  # Aggressive scan
            "--version-all",
            "--top-ports",
            "5000",
            "-T4",  # Consistent timing
            "--script",
            "default,discovery,vuln,safe",
            "--max-retries",
            "3",
            "--host-timeout",
            "900s",
            "--script-timeout",
            "60s",
        ],
        masscan_args=[],  # Not suitable for masscan
        default_ports="1-5000",
        timeout=900,
        requires_sudo=True,
    ),
    ScanType.ARP: ScanProfile(
        name="ARP Scan",
        description="Layer 2 discovery for local networks",
        nmap_args=[
            "-sn",  # No port scan
            "-PR",  # ARP ping
            "--send-eth",
            "--max-retries",
            "3",
            "--host-timeout",
            "10s",
        ],
        masscan_args=[],  # Not suitable for masscan
        timeout=30,
        requires_sudo=True,
    ),
    ScanType.FAST: ScanProfile(
        name="Fast Scan",
        description="Ultra-fast scanning for large networks",
        nmap_args=[
            "-sS",  # TCP SYN scan
            "-Pn",  # Skip host discovery
            "--top-ports",
            "100",
            "--max-retries",
            "1",
            "--host-timeout",
            "15s",
            "-T4",  # Aggressive timing
            "--osscan-limit",  # Skip OS detection on hosts without ports
        ],
        masscan_args=["-p80,443,22,445,3389,8080", "--rate=100000", "--wait=0", "--open-only"],
        default_ports="80,443,22,445,3389,8080",
        timeout=120,
        requires_sudo=True,
        max_rate=100000,
    ),
}


def get_scan_profile(scan_type: ScanType) -> ScanProfile:
    """
    Get scan profile for the specified type.

    Args:
        scan_type: Type of scan

    Returns:
        Scan profile configuration

    Raises:
        ValueError: If scan type not found
    """
    if scan_type not in SCAN_PROFILES:
        raise ValueError(f"Unknown scan type: {scan_type}")

    return SCAN_PROFILES[scan_type]


def list_scan_profiles() -> List[Dict[str, str]]:
    """
    List all available scan profiles.

    Returns:
        List of profile summaries
    """
    return [
        {
            "type": scan_type.value,
            "name": profile.name,
            "description": profile.description,
            "requires_sudo": profile.requires_sudo,
        }
        for scan_type, profile in SCAN_PROFILES.items()
    ]


def validate_scan_arguments(scan_type: ScanType, custom_args: List[str]) -> List[str]:
    """
    Validate custom scan arguments.

    Args:
        scan_type: Type of scan
        custom_args: Custom arguments to validate

    Returns:
        Validated arguments

    Raises:
        ValueError: If arguments are invalid
    """
    # Define forbidden arguments that could break functionality
    forbidden_args = [
        "-oA",
        "-oN",
        "-oG",
        "-oS",  # Output format conflicts
        "-iL",
        "-iR",  # Input conflicts
        "--resume",  # State conflicts
    ]

    for arg in custom_args:
        if any(arg.startswith(forbidden) for forbidden in forbidden_args):
            raise ValueError(f"Forbidden argument: {arg}")

    return custom_args


def merge_scan_options(
    profile: ScanProfile,
    custom_ports: Optional[str] = None,
    custom_args: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Merge profile with custom options.

    Args:
        profile: Base scan profile
        custom_ports: Custom port specification
        custom_args: Additional arguments

    Returns:
        Merged configuration
    """
    config = {
        "args": profile.nmap_args.copy(),
        "timeout": profile.timeout,
        "requires_sudo": profile.requires_sudo,
    }

    # Override ports if specified
    if custom_ports:
        # Remove existing port specifications
        config["args"] = [
            arg for arg in config["args"] if not (arg == "-p" or arg.startswith("--top-ports"))
        ]
        config["args"].extend(["-p", custom_ports])

    # Add custom arguments
    if custom_args:
        validated_args = validate_scan_arguments(ScanType(profile.name.lower()), custom_args)
        config["args"].extend(validated_args)

    return config
