#!/usr/bin/env python3
"""
Enhanced Scanner Tests - Comprehensive testing for scan profiles and edge cases
"""

import pytest
import json
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call
import subprocess
import asyncio
from datetime import datetime

from core.scanner import NetworkScanner
from core.scanner_async import AsyncNetworkScanner


class TestEnhancedScanner:
    """Enhanced tests for scanner functionality"""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance for testing"""
        return NetworkScanner()
    
    @pytest.fixture
    def async_scanner(self):
        """Create async scanner instance for testing"""
        return AsyncNetworkScanner()
    
    @pytest.fixture
    def mock_nmap_xml(self):
        """Mock nmap XML output for testing"""
        return '''<?xml version="1.0" encoding="UTF-8"?>
        <nmaprun>
            <host>
                <address addr="192.168.1.1" addrtype="ipv4"/>
                <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Cisco"/>
                <hostnames>
                    <hostname name="router.local" type="PTR"/>
                </hostnames>
                <status state="up"/>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="open"/>
                        <service name="ssh" version="OpenSSH 8.0"/>
                    </port>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http" version="nginx 1.18"/>
                    </port>
                </ports>
                <os>
                    <osmatch name="Cisco IOS" accuracy="95"/>
                </os>
            </host>
        </nmaprun>'''
    
    @pytest.fixture
    def mock_masscan_output(self):
        """Mock masscan JSON output for testing"""
        return '''[
            {"ip": "192.168.1.1", "port": 22, "status": "open", "protocol": "tcp", "timestamp": "1234567890"},
            {"ip": "192.168.1.1", "port": 80, "status": "open", "protocol": "tcp", "timestamp": "1234567890"},
            {"ip": "192.168.1.2", "port": 443, "status": "open", "protocol": "tcp", "timestamp": "1234567890"}
        ]'''

    def test_scan_profiles_exist(self, scanner):
        """Test that scan profiles are properly defined"""
        profiles = scanner.scan_profiles
        
        # Should only have fast and deeper profiles after cleanup
        assert "fast" in profiles
        assert "deeper" in profiles
        assert len(profiles) == 2
        
        # Verify profile structure
        for profile_name, profile in profiles.items():
            if "masscan" in profile:
                assert isinstance(profile["masscan"], list)
            if "nmap" in profile:
                assert isinstance(profile["nmap"], list)
            assert "description" in profile
            assert isinstance(profile["description"], str)

    def test_fast_scan_profile(self, scanner):
        """Test fast scan profile configuration"""
        fast_profile = scanner.scan_profiles["fast"]
        
        # Should have both masscan and nmap configs
        assert "masscan" in fast_profile
        assert "nmap" in fast_profile
        
        # Check nmap args for fast scan
        nmap_args = fast_profile["nmap"]
        assert "--version-intensity" in nmap_args
        intensity_index = nmap_args.index("--version-intensity")
        assert nmap_args[intensity_index + 1] == "0"  # Fast = low intensity
        
        assert "--top-ports" in nmap_args
        ports_index = nmap_args.index("--top-ports")
        assert nmap_args[ports_index + 1] == "100"  # Fast = fewer ports
        
        assert "-T5" in nmap_args  # Fast timing

    def test_deeper_scan_profile(self, scanner):
        """Test deeper scan profile configuration"""
        deeper_profile = scanner.scan_profiles["deeper"]
        
        # Should have both masscan and nmap configs
        assert "masscan" in deeper_profile
        assert "nmap" in deeper_profile
        
        # Check nmap args for deeper scan
        nmap_args = deeper_profile["nmap"]
        assert "--version-intensity" in nmap_args
        intensity_index = nmap_args.index("--version-intensity")
        assert nmap_args[intensity_index + 1] == "5"  # Deeper = higher intensity
        
        assert "--top-ports" in nmap_args
        ports_index = nmap_args.index("--top-ports")
        assert nmap_args[ports_index + 1] == "500"  # Deeper = more ports
        
        assert "-T3" in nmap_args  # Normal timing

    @patch('subprocess.run')
    def test_scanner_availability_check(self, mock_run, scanner):
        """Test scanner availability checking"""
        # Test nmap available
        mock_run.return_value = Mock(returncode=0, stdout="Nmap version 7.97")
        assert scanner._check_scanner_available("nmap") is True
        
        # Test scanner not available
        mock_run.return_value = Mock(returncode=1)
        assert scanner._check_scanner_available("nonexistent") is False
        
        # Test with exception
        mock_run.side_effect = FileNotFoundError()
        assert scanner._check_scanner_available("nmap") is False

    @patch('tempfile.NamedTemporaryFile')
    @patch('subprocess.run')
    def test_nmap_command_building(self, mock_run, mock_temp, scanner):
        """Test nmap command construction"""
        mock_temp.return_value.__enter__.return_value.name = "/tmp/test.xml"
        mock_run.return_value = Mock(returncode=0)
        
        with patch.object(scanner, '_parse_nmap_xml', return_value=[]):
            with patch.object(scanner, '_check_scanner_available', return_value=True):
                # Test fast scan command
                scanner._run_nmap("192.168.1.0/24", "fast", False)
                
                # Verify command structure
                call_args = mock_run.call_args[0][0]
                assert "nmap" in call_args
                assert "-oX" in call_args
                assert "--version-intensity" in call_args
                assert "0" in call_args  # Fast intensity
                assert "192.168.1.0/24" in call_args

    @patch('tempfile.NamedTemporaryFile')
    def test_nmap_xml_parsing(self, mock_temp, scanner, mock_nmap_xml):
        """Test nmap XML parsing"""
        # Create temporary file with mock XML
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(mock_nmap_xml)
            temp_path = f.name
        
        try:
            devices = scanner._parse_nmap_xml(temp_path)
            
            assert len(devices) == 1
            device = devices[0]
            
            assert device["ip"] == "192.168.1.1"
            assert device["mac"] == "00:11:22:33:44:55"
            assert device["hostname"] == "router.local"
            assert device["vendor"] == "Cisco"
            assert 22 in device["open_ports"]
            assert 80 in device["open_ports"]
            assert "ssh" in device["services"]
            assert "http" in device["services"]
            
        finally:
            Path(temp_path).unlink()

    @patch('tempfile.NamedTemporaryFile')
    def test_masscan_json_parsing(self, mock_temp, scanner, mock_masscan_output):
        """Test masscan JSON parsing"""
        # Create temporary file with mock JSON
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(mock_masscan_output)
            temp_path = f.name
        
        try:
            devices = scanner._parse_masscan_json(temp_path)
            
            assert len(devices) == 2  # Two unique IPs
            
            # Check first device
            device1 = next(d for d in devices if d["ip"] == "192.168.1.1")
            assert 22 in device1["open_ports"]
            assert 80 in device1["open_ports"]
            
            # Check second device
            device2 = next(d for d in devices if d["ip"] == "192.168.1.2")
            assert 443 in device2["open_ports"]
            
        finally:
            Path(temp_path).unlink()

    @patch('subprocess.Popen')
    def test_scan_progress_tracking(self, mock_popen, scanner):
        """Test scan progress tracking and parsing"""
        # Mock process with stdout
        mock_process = Mock()
        mock_process.poll.return_value = None
        mock_process.returncode = 0
        mock_process.stdout = iter([
            b"Starting Nmap 7.97\\n",
            b"Nmap scan report for 192.168.1.1\\n",
            b"Host is up (0.001s latency)\\n",
            b"PORT     STATE SERVICE\\n",
            b"22/tcp   open  ssh\\n",
            b"Nmap done: 256 IP addresses (1 host up) scanned\\n"
        ])
        mock_popen.return_value = mock_process
        
        with patch.object(scanner, '_check_scanner_available', return_value=True):
            with patch.object(scanner, '_parse_nmap_xml', return_value=[]):
                scanner._run_nmap("192.168.1.0/24", "fast", False)
                
                # Verify process was created
                mock_popen.assert_called_once()

    def test_sudo_access_detection(self, scanner):
        """Test sudo access detection"""
        with patch('subprocess.run') as mock_run:
            # Test sudo available
            mock_run.return_value = Mock(returncode=0)
            assert scanner._check_sudo() is True
            
            # Test sudo not available
            mock_run.return_value = Mock(returncode=1)
            assert scanner._check_sudo() is False

    @patch('subprocess.run')
    def test_interface_detection(self, mock_run, scanner):
        """Test network interface detection"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="192.168.1.1 via 192.168.1.1 dev eth0 src 192.168.1.100",
            text=True
        )
        
        interface = scanner._get_best_interface_for_target("192.168.1.0/24")
        assert interface == "eth0"

    def test_network_size_estimation(self, scanner):
        """Test network size estimation for different CIDR ranges"""
        # Test /24 network
        assert scanner._estimate_total_hosts("192.168.1.0/24") == 254
        
        # Test /16 network
        assert scanner._estimate_total_hosts("10.0.0.0/16") == 65534
        
        # Test single IP
        assert scanner._estimate_total_hosts("192.168.1.1") == 1
        
        # Test hostname
        assert scanner._estimate_total_hosts("example.com") == 1

    @patch('subprocess.run')
    def test_error_handling_scanner_not_found(self, mock_run, scanner):
        """Test error handling when scanner not found"""
        mock_run.side_effect = FileNotFoundError("Scanner not found")
        
        with pytest.raises(Exception) as exc_info:
            scanner._check_scanner_available("nonexistent")
        
        assert scanner._check_scanner_available("nonexistent") is False

    @pytest.mark.asyncio
    async def test_async_scanner_basic_functionality(self, async_scanner):
        """Test basic async scanner functionality"""
        # Test initialization
        assert hasattr(async_scanner, 'scan_profiles')
        assert "fast" in async_scanner.scan_profiles
        assert "deeper" in async_scanner.scan_profiles

    def test_temp_file_cleanup(self, scanner):
        """Test temporary file cleanup"""
        # Create a temp file
        temp_path = scanner._create_temp_file("test", ".xml")
        assert Path(temp_path).exists()
        
        # Clean it up
        scanner._cleanup_temp_file(temp_path, needs_sudo=False)
        assert not Path(temp_path).exists()

    @patch('subprocess.run')
    def test_arp_scan_command_building(self, mock_run, scanner):
        """Test ARP scan command construction"""
        mock_run.return_value = Mock(returncode=0, stdout="")
        
        cmd = scanner._build_arp_scan_command("192.168.1.0/24")
        
        assert "arp-scan" in cmd
        assert "192.168.1.0/24" in cmd
        assert "sudo" in cmd  # ARP scan requires sudo

    def test_result_merging(self, scanner):
        """Test merging results from different scanners"""
        arp_devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "vendor": "Cisco"}
        ]
        
        nmap_devices = [
            {"ip": "192.168.1.1", "open_ports": [22, 80], "services": ["ssh", "http"]}
        ]
        
        merged = scanner._merge_scan_results(arp_devices, nmap_devices)
        
        assert len(merged) == 1
        device = merged[0]
        assert device["ip"] == "192.168.1.1"
        assert device["mac"] == "00:11:22:33:44:55"
        assert device["vendor"] == "Cisco"
        assert 22 in device["open_ports"]
        assert "ssh" in device["services"]

    def test_hang_detection(self, scanner):
        """Test scan hang detection"""
        # Set a very short hang threshold for testing
        scanner.hang_threshold = 1  # 1 second
        
        # Simulate no progress updates
        scanner.last_progress_update = datetime.now().timestamp() - 2
        
        assert scanner._is_scan_hanging() is True

    @patch('subprocess.run')
    def test_masscan_rate_calculation(self, mock_run, scanner):
        """Test masscan rate calculation based on network size"""
        mock_run.return_value = Mock(returncode=0)
        
        with patch.object(scanner, '_estimate_total_hosts') as mock_estimate:
            # Large network should use higher rate
            mock_estimate.return_value = 50000
            cmd = scanner._build_masscan_command("10.0.0.0/16")
            rate_arg = next(arg for arg in cmd if arg.startswith("--rate="))
            rate = int(rate_arg.split("=")[1])
            assert rate >= 50000
            
            # Small network should use lower rate
            mock_estimate.return_value = 254
            cmd = scanner._build_masscan_command("192.168.1.0/24")
            rate_arg = next(arg for arg in cmd if arg.startswith("--rate="))
            rate = int(rate_arg.split("=")[1])
            assert rate <= 25000


class TestScanWorkflows:
    """Test complete scan workflows"""
    
    @pytest.fixture
    def scanner(self):
        return NetworkScanner()
    
    @patch('subprocess.run')
    @patch('subprocess.Popen')
    def test_fast_scan_workflow(self, mock_popen, mock_run, scanner):
        """Test complete fast scan workflow"""
        # Mock scanner availability
        mock_run.return_value = Mock(returncode=0)
        
        # Mock scan process
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.stdout = iter([b"Nmap done: 1 host up\\n"])
        mock_popen.return_value = mock_process
        
        with patch.object(scanner, '_parse_nmap_xml', return_value=[]):
            with patch.object(scanner, '_parse_masscan_json', return_value=[]):
                with patch.object(scanner, '_check_scanner_available', return_value=True):
                    results = scanner.scan(
                        target="192.168.1.0/24",
                        scan_type="fast",
                        use_masscan=True,
                        needs_root=False
                    )
                    
                    assert isinstance(results, list)

    @patch('subprocess.run')
    @patch('subprocess.Popen')
    def test_deeper_scan_workflow(self, mock_popen, mock_run, scanner):
        """Test complete deeper scan workflow"""
        # Mock scanner availability
        mock_run.return_value = Mock(returncode=0)
        
        # Mock scan process
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.stdout = iter([b"Nmap done: 1 host up\\n"])
        mock_popen.return_value = mock_process
        
        with patch.object(scanner, '_parse_nmap_xml', return_value=[]):
            with patch.object(scanner, '_parse_masscan_json', return_value=[]):
                with patch.object(scanner, '_check_scanner_available', return_value=True):
                    results = scanner.scan(
                        target="192.168.1.0/24",
                        scan_type="deeper",
                        use_masscan=True,
                        needs_root=False
                    )
                    
                    assert isinstance(results, list)

    def test_invalid_scan_type(self, scanner):
        """Test handling of invalid scan type"""
        with pytest.raises(KeyError):
            scanner.scan(
                target="192.168.1.0/24",
                scan_type="invalid_type",
                use_masscan=False,
                needs_root=False
            )


if __name__ == "__main__":
    pytest.main([__file__])