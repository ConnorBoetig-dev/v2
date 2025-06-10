"""Comprehensive unit tests for the ScanParser module."""

import json
import logging
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch, mock_open

from core.parser import Device, ScanParser


class TestDevice(unittest.TestCase):
    """Test cases for Device dataclass."""
    
    def test_device_creation(self):
        """Test Device creation with all fields."""
        device = Device(
            ip="192.168.1.1",
            mac="00:11:22:33:44:55",
            vendor="Test Vendor",
            hostname="test-host",
            type="router",
            os="Linux",
            services=["ssh:22", "http:80"],
            open_ports=[22, 80],
            scan_time="2023-01-01T12:00:00"
        )
        
        self.assertEqual(device.ip, "192.168.1.1")
        self.assertEqual(device.mac, "00:11:22:33:44:55")
        self.assertEqual(device.vendor, "Test Vendor")
        self.assertEqual(device.hostname, "test-host")
        self.assertEqual(device.type, "router")
        self.assertEqual(device.os, "Linux")
        self.assertEqual(device.services, ["ssh:22", "http:80"])
        self.assertEqual(device.open_ports, [22, 80])
        self.assertEqual(device.scan_time, "2023-01-01T12:00:00")
    
    def test_device_defaults(self):
        """Test Device creation with default values."""
        device = Device(ip="10.0.0.1")
        
        self.assertEqual(device.ip, "10.0.0.1")
        self.assertEqual(device.mac, "")
        self.assertEqual(device.vendor, "")
        self.assertEqual(device.hostname, "")
        self.assertEqual(device.type, "unknown")
        self.assertEqual(device.os, "")
        self.assertEqual(device.services, [])
        self.assertEqual(device.open_ports, [])
        self.assertIsNotNone(device.scan_time)
    
    def test_device_to_dict(self):
        """Test converting Device to dictionary."""
        device = Device(
            ip="192.168.1.1",
            mac="AA:BB:CC:DD:EE:FF",
            open_ports=[22, 443]
        )
        
        device_dict = device.to_dict()
        self.assertIsInstance(device_dict, dict)
        self.assertEqual(device_dict['ip'], "192.168.1.1")
        self.assertEqual(device_dict['mac'], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(device_dict['open_ports'], [22, 443])
        self.assertIn('scan_time', device_dict)
    
    def test_device_from_dict(self):
        """Test creating Device from dictionary."""
        data = {
            "ip": "192.168.1.1",
            "mac": "00:11:22:33:44:55",
            "hostname": "test-host",
            "type": "router",
            "extra_field": "ignored"  # Should be filtered out
        }
        
        device = Device.from_dict(data)
        self.assertEqual(device.ip, "192.168.1.1")
        self.assertEqual(device.mac, "00:11:22:33:44:55")
        self.assertEqual(device.hostname, "test-host")
        self.assertEqual(device.type, "router")


class TestScanParser(unittest.TestCase):
    """Test cases for ScanParser class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.parser = ScanParser()
        # Configure logging
        logging.basicConfig(level=logging.DEBUG)
    
    def test_init(self):
        """Test parser initialization."""
        parser = ScanParser()
        self.assertIsNotNone(parser.mac_lookup)
        self.assertIsInstance(parser.parsers, dict)
        self.assertIn("nmap", parser.parsers)
        self.assertIn("masscan", parser.parsers)
        self.assertIn("arp-scan", parser.parsers)
    
    def test_parse_results_nmap(self):
        """Test parsing nmap results."""
        nmap_data = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "hostname": "router.local",
                "open_ports": [22, 80, 443],
                "services": ["ssh:22", "http:80", "https:443"],
                "os": "RouterOS",
                "vendor": "MikroTik"
            }
        ]
        
        devices = self.parser.parse_results(nmap_data, scanner_type="nmap")
        
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["ip"], "192.168.1.1")
        self.assertEqual(devices[0]["mac"], "00:11:22:33:44:55")
        self.assertEqual(devices[0]["hostname"], "router.local")
    
    def test_parse_results_masscan(self):
        """Test parsing masscan results."""
        masscan_data = [
            {
                "ip": "10.0.0.1",
                "ports": [
                    {"port": 22, "proto": "tcp", "state": "open"},
                    {"port": 443, "proto": "tcp", "state": "open"}
                ]
            }
        ]
        
        devices = self.parser.parse_results(masscan_data, scanner_type="masscan")
        
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["ip"], "10.0.0.1")
        self.assertIn(22, devices[0]["open_ports"])
        self.assertIn(443, devices[0]["open_ports"])
    
    def test_parse_results_arp_scan(self):
        """Test parsing arp-scan results."""
        arp_data = [
            {
                "ip": "192.168.1.1",
                "mac": "AA:BB:CC:DD:EE:FF",
                "vendor": "Cisco Systems, Inc."
            }
        ]
        
        devices = self.parser.parse_results(arp_data, scanner_type="arp-scan")
        
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["ip"], "192.168.1.1")
        self.assertEqual(devices[0]["mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(devices[0]["vendor"], "Cisco Systems, Inc.")
    
    def test_parse_results_empty(self):
        """Test parsing empty results."""
        devices = self.parser.parse_results([])
        self.assertEqual(len(devices), 0)
        
        devices = self.parser.parse_results(None)
        self.assertEqual(len(devices), 0)
    
    def test_parse_results_auto_detect(self):
        """Test auto-detection of scanner format."""
        # Nmap-like format
        data = [{"ip": "192.168.1.1", "services": ["ssh:22"]}]
        devices = self.parser.parse_results(data)
        self.assertEqual(len(devices), 1)
        
        # Masscan-like format
        data = [{"ip": "192.168.1.1", "ports": [{"port": 22}]}]
        devices = self.parser.parse_results(data)
        self.assertEqual(len(devices), 1)
    
    def test_standardize_devices(self):
        """Test device standardization."""
        raw_devices = [
            {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff"},  # Lowercase MAC
            Device(ip="192.168.1.2", mac="11:22:33:44:55:66"),  # Device object
            {"invalid": "data"},  # Missing IP
        ]
        
        standardized = self.parser._standardize_devices(raw_devices)
        
        self.assertEqual(len(standardized), 2)  # Invalid device filtered out
        self.assertEqual(standardized[0]["mac"], "AA:BB:CC:DD:EE:FF")  # MAC normalized
        self.assertEqual(standardized[1]["ip"], "192.168.1.2")
    
    @patch('utils.mac_lookup.MACLookup.lookup')
    def test_vendor_enrichment(self, mock_lookup):
        """Test vendor enrichment from MAC address."""
        mock_lookup.return_value = "Test Vendor"
        
        devices = [{"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"}]
        standardized = self.parser._standardize_devices(devices)
        
        self.assertEqual(standardized[0]["vendor"], "Test Vendor")
        mock_lookup.assert_called_with("00:11:22:33:44:55")
    
    def test_service_normalization(self):
        """Test service string normalization."""
        devices = [
            {
                "ip": "192.168.1.1",
                "services": [22, "http", "https:443", "ssh:22"]
            }
        ]
        
        standardized = self.parser._standardize_devices(devices)
        
        services = standardized[0]["services"]
        self.assertIn("unknown:22", services)  # Port number converted
        self.assertIn("http:unknown", services)  # Missing port added
        self.assertIn("https:443", services)  # Already correct
        self.assertIn("ssh:22", services)  # Already correct
    
    def test_error_handling(self):
        """Test error handling in parsing."""
        # Invalid data type
        with self.assertLogs(level='WARNING'):
            devices = self.parser.parse_results("invalid_string")
            self.assertEqual(len(devices), 0)
        
        # Exception in parser - parser may log at WARNING instead of ERROR
        devices = self.parser.parse_results([{"ip": None}])
        # Should handle gracefully and return empty list
        self.assertEqual(len(devices), 0)
    
    def test_parse_results_with_enrichment(self):
        """Test full parsing pipeline with enrichment."""
        data = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "services": ["ssh", 22, "http:80"],
                "open_ports": [22, 80]
            }
        ]
        
        with patch('utils.mac_lookup.MACLookup.lookup', return_value="Cisco"):
            devices = self.parser.parse_results(data)
            
            self.assertEqual(len(devices), 1)
            device = devices[0]
            self.assertEqual(device["vendor"], "Cisco")
            self.assertEqual(device["mac"], "00:11:22:33:44:55")
            # Services should be normalized
            self.assertIn("ssh:unknown", device["services"])
            self.assertIn("unknown:22", device["services"])
            self.assertIn("http:80", device["services"])


class TestParserIntegration(unittest.TestCase):
    """Integration tests for parser with realistic data."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.parser = ScanParser()
    
    def test_mixed_scanner_data(self):
        """Test parsing data from multiple scanners."""
        # Nmap data
        nmap_data = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "hostname": "gateway.local",
                "open_ports": [22, 80, 443],
                "services": ["ssh:22 (OpenSSH 8.0)", "http:80", "https:443"],
                "os": "pfSense",
                "vendor": "Netgate"
            }
        ]
        
        # Parse nmap data
        nmap_devices = self.parser.parse_results(nmap_data, scanner_type="nmap")
        self.assertEqual(len(nmap_devices), 1)
        self.assertEqual(nmap_devices[0]["hostname"], "gateway.local")
        
        # Masscan data
        masscan_data = [
            {"ip": "192.168.1.10", "ports": [{"port": 22}, {"port": 3306}]}
        ]
        
        masscan_devices = self.parser.parse_results(masscan_data, scanner_type="masscan")
        self.assertEqual(len(masscan_devices), 1)
        self.assertIn(3306, masscan_devices[0]["open_ports"])
        
        # ARP data
        arp_data = [
            {"ip": "192.168.1.20", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Dell Inc."}
        ]
        
        arp_devices = self.parser.parse_results(arp_data, scanner_type="arp-scan")
        self.assertEqual(len(arp_devices), 1)
        self.assertEqual(arp_devices[0]["vendor"], "Dell Inc.")
    
    def test_large_scan_performance(self):
        """Test performance with large scan results."""
        import time
        
        # Generate 1000 devices
        large_scan = []
        for i in range(1000):
            large_scan.append({
                "ip": f"10.0.{i // 256}.{i % 256}",
                "mac": f"00:11:22:33:{i // 256:02x}:{i % 256:02x}",
                "services": ["ssh:22", "http:80"] if i % 2 else ["rdp:3389"],
                "open_ports": [22, 80] if i % 2 else [3389]
            })
        
        start_time = time.time()
        devices = self.parser.parse_results(large_scan)
        parse_time = time.time() - start_time
        
        self.assertEqual(len(devices), 1000)
        self.assertLess(parse_time, 2.0)  # Should parse in under 2 seconds
    
    def test_real_world_data_formats(self):
        """Test with real-world data format variations."""
        # Mixed format data
        mixed_data = [
            # Complete device info
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "hostname": "router",
                "vendor": "Cisco",
                "open_ports": [22, 80, 443],
                "services": ["ssh:22", "http:80", "https:443"],
                "os": "IOS 15.1"
            },
            # Minimal info
            {"ip": "192.168.1.2"},
            # Device with non-standard service format
            {
                "ip": "192.168.1.3",
                "services": ["SSH (22)", "HTTP - Port 80", "443/tcp https"]
            },
            # Device with mixed case MAC
            {"ip": "192.168.1.4", "mac": "aA:bB:Cc:Dd:Ee:Ff"}
        ]
        
        devices = self.parser.parse_results(mixed_data)
        
        self.assertEqual(len(devices), 4)
        
        # Check first device
        self.assertEqual(devices[0]["hostname"], "router")
        self.assertEqual(devices[0]["vendor"], "Cisco")
        
        # Check minimal device
        self.assertEqual(devices[1]["ip"], "192.168.1.2")
        self.assertEqual(devices[1]["mac"], "")
        
        # Check MAC normalization
        self.assertEqual(devices[3]["mac"], "AA:BB:CC:DD:EE:FF")


if __name__ == '__main__':
    unittest.main()