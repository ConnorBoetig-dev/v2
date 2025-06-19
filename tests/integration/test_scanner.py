#!/usr/bin/env python3
"""
Test suite for core/scanner.py
"""

import pytest
import json
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
import subprocess

from core.scanner import NetworkScanner


class TestNetworkScanner:
    """Test NetworkScanner class"""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance for testing"""
        return NetworkScanner()

    def test_init(self, scanner):
        """Test scanner initialization"""
        assert scanner.sudo_available is not None
        assert scanner.scanners == {"nmap": None, "masscan": None, "arp-scan": None}
        assert len(scanner.scan_profiles) > 0
        assert scanner.current_process is None

    def test_check_scanner(self, scanner):
        """Test scanner availability checking"""
        with patch("subprocess.run") as mock_run:
            # Test successful scanner check
            mock_run.return_value = Mock(returncode=0, stdout="Nmap version 7.92")
            result = scanner._check_scanner("nmap")
            assert result is True

            # Test failed scanner check
            mock_run.return_value = Mock(returncode=1)
            result = scanner._check_scanner("invalid-scanner")
            assert result is False

    def test_estimate_hosts(self, scanner):
        """Test host count estimation"""
        # Test /24 network
        count = scanner._estimate_hosts("10.0.1.0/24")
        assert count == 254

        # Test /16 network
        count = scanner._estimate_hosts("192.168.0.0/16")
        assert count == 65534

        # Test single host
        count = scanner._estimate_hosts("10.0.1.1")
        assert count == 1

        # Test invalid target
        count = scanner._estimate_hosts("invalid")
        assert count == 1

    def test_parse_progress_line(self, scanner):
        """Test progress line parsing"""
        scanner.discovered_hosts = 5
        scanner.estimated_hosts = 100

        # Test nmap progress
        progress = scanner._parse_progress_line(
            "Completed SYN Stealth Scan at 15:30, 10.00s elapsed (256 total ports)", "nmap"
        )
        assert progress > 0

        # Test masscan progress
        progress = scanner._parse_progress_line("rate:  0.00-kpps,  50.00% done", "masscan")
        assert progress == 50

        # Test arp-scan progress
        scanner.discovered_hosts = 10
        progress = scanner._parse_progress_line("10.0.1.50\t00:11:22:33:44:55\tVendor", "arp-scan")
        assert scanner.discovered_hosts == 10

    @patch("subprocess.Popen")
    def test_scan_discovery(self, mock_popen, scanner):
        """Test discovery scan"""
        # Mock the scanner check
        scanner.scanners["nmap"] = True

        # Mock subprocess
        mock_process = Mock()
        mock_process.poll.return_value = 0
        mock_process.stdout = iter(
            [
                b"Starting Nmap scan...\n",
                b"Nmap scan report for 10.0.1.1\n",
                b"Host is up (0.001s latency).\n",
                b"Nmap done: 1 IP address (1 host up) scanned\n",
            ]
        )
        mock_process.stderr = iter([])
        mock_popen.return_value = mock_process

        result = scanner.scan_network("10.0.1.0/24", profile="discovery", progress_callback=None)
        assert result is not None
        assert len(result) > 0

    def test_parse_nmap_output(self, scanner):
        """Test nmap output parsing"""
        nmap_output = """
Starting Nmap 7.92
Nmap scan report for 10.0.1.1
Host is up (0.001s latency).
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
MAC Address: 00:11:22:33:44:55 (Vendor Name)
Service Info: OS: Linux

Nmap scan report for 10.0.1.2
Host is up (0.002s latency).
PORT     STATE SERVICE
443/tcp  open  https
"""

        results = scanner._parse_nmap_output(nmap_output)
        assert len(results) == 2
        assert results[0]["ip"] == "10.0.1.1"
        assert results[0]["mac"] == "00:11:22:33:44:55"
        assert results[0]["vendor"] == "Vendor Name"
        assert 22 in results[0]["open_ports"]
        assert 80 in results[0]["open_ports"]

    def test_parse_masscan_output(self, scanner):
        """Test masscan output parsing"""
        masscan_output = """
Discovered open port 22/tcp on 10.0.1.1
Discovered open port 80/tcp on 10.0.1.1
Discovered open port 443/tcp on 10.0.1.2
"""

        results = scanner._parse_masscan_output(masscan_output)
        assert len(results) == 2
        assert results["10.0.1.1"]["open_ports"] == [22, 80]
        assert results["10.0.1.2"]["open_ports"] == [443]

    def test_parse_arp_output(self, scanner):
        """Test arp-scan output parsing"""
        arp_output = """
Interface: eth0, type: EN10MB, MAC: 00:11:22:33:44:55, IPv4: 10.0.1.100
Starting arp-scan
10.0.1.1\t00:11:22:33:44:55\tCisco Systems
10.0.1.2\t00:11:22:33:44:56\tDell Inc.
10.0.1.3\t00:11:22:33:44:57\tUnknown
3 packets received
"""

        results = scanner._parse_arp_output(arp_output)
        assert len(results) == 3
        assert results[0]["ip"] == "10.0.1.1"
        assert results[0]["mac"] == "00:11:22:33:44:55"
        assert results[0]["vendor"] == "Cisco Systems"

    def test_scan_profiles(self, scanner):
        """Test scan profiles"""
        assert "discovery" in scanner.scan_profiles
        assert "inventory" in scanner.scan_profiles
        assert "deep" in scanner.scan_profiles

        # Test profile contents
        discovery = scanner.scan_profiles["discovery"]
        assert "nmap" in discovery
        assert "-sn" in discovery["nmap"] or "-sS" in discovery["nmap"]
