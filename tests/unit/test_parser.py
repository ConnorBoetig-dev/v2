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
    
    def test_device_asdict(self):
        """Test converting Device to dictionary."""
        device = Device(
            ip="192.168.1.1",
            mac="AA:BB:CC:DD:EE:FF",
            open_ports=[22, 443]
        )
        
        device_dict = device.asdict()
        self.assertIsInstance(device_dict, dict)
        self.assertEqual(device_dict['ip'], "192.168.1.1")
        self.assertEqual(device_dict['mac'], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(device_dict['open_ports'], [22, 443])
        self.assertIn('scan_time', device_dict)


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
        self.assertIsInstance(parser._device_cache, dict)
    
    def test_normalize_scan_results_dict(self):
        """Test normalizing scan results from dictionary format."""
        scan_data = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "hostname": "router.local",
                "open_ports": [22, 80, 443],
                "services": ["ssh:22", "http:80", "https:443"],
                "os": "RouterOS",
                "vendor": "MikroTik"
            },
            {
                "ip": "192.168.1.100",
                "mac": "",
                "hostname": "",
                "open_ports": [3389],
                "services": ["rdp:3389"],
                "os": "Windows 10",
                "vendor": ""
            }
        ]
        
        devices = self.parser.normalize_scan_results(scan_data)
        
        self.assertEqual(len(devices), 2)
        # Check first device
        self.assertEqual(devices[0].ip, "192.168.1.1")
        self.assertEqual(devices[0].mac, "00:11:22:33:44:55")
        self.assertEqual(devices[0].hostname, "router.local")
        self.assertEqual(devices[0].open_ports, [22, 80, 443])
        # Check second device
        self.assertEqual(devices[1].ip, "192.168.1.100")
        self.assertEqual(devices[1].os, "Windows 10")
    
    def test_normalize_scan_results_device_objects(self):
        """Test normalizing when already Device objects."""
        devices_in = [
            Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF"),
            Device(ip="10.0.0.2", hostname="server.local")
        ]
        
        devices_out = self.parser.normalize_scan_results(devices_in)
        
        self.assertEqual(len(devices_out), 2)
        self.assertEqual(devices_out[0].ip, "10.0.0.1")
        self.assertEqual(devices_out[1].hostname, "server.local")
    
    def test_normalize_scan_results_empty(self):
        """Test normalizing empty results."""
        devices = self.parser.normalize_scan_results([])
        self.assertEqual(len(devices), 0)
        
        devices = self.parser.normalize_scan_results(None)
        self.assertEqual(len(devices), 0)
    
    def test_enhance_device_info(self):
        """Test device information enhancement."""
        device = Device(
            ip="192.168.1.1",
            mac="00:11:22:33:44:55",
            open_ports=[22, 80, 443, 8080]
        )
        
        with patch.object(self.parser.mac_lookup, 'lookup', return_value="Cisco Systems"):
            enhanced = self.parser.enhance_device_info(device)
            
            self.assertEqual(enhanced.vendor, "Cisco Systems")
            # Services should be generated from ports
            self.assertIn("ssh:22", enhanced.services)
            self.assertIn("http:80", enhanced.services)
            self.assertIn("https:443", enhanced.services)
            self.assertIn("http-proxy:8080", enhanced.services)
    
    def test_enhance_device_info_no_mac(self):
        """Test enhancement without MAC address."""
        device = Device(ip="10.0.0.1", open_ports=[22])
        
        enhanced = self.parser.enhance_device_info(device)
        self.assertEqual(enhanced.vendor, "")
        self.assertIn("ssh:22", enhanced.services)
    
    def test_enhance_device_info_with_existing_vendor(self):
        """Test enhancement when vendor already set."""
        device = Device(
            ip="192.168.1.1",
            mac="00:11:22:33:44:55",
            vendor="Existing Vendor"
        )
        
        with patch.object(self.parser.mac_lookup, 'lookup', return_value="New Vendor"):
            enhanced = self.parser.enhance_device_info(device)
            # Should keep existing vendor
            self.assertEqual(enhanced.vendor, "Existing Vendor")
    
    def test_port_to_service_mapping(self):
        """Test port to service name mapping."""
        test_cases = [
            (21, "ftp:21"),
            (22, "ssh:22"),
            (23, "telnet:23"),
            (25, "smtp:25"),
            (53, "dns:53"),
            (80, "http:80"),
            (110, "pop3:110"),
            (143, "imap:143"),
            (443, "https:443"),
            (445, "smb:445"),
            (3306, "mysql:3306"),
            (3389, "rdp:3389"),
            (5432, "postgresql:5432"),
            (8080, "http-proxy:8080"),
            (9999, "unknown:9999"),  # Unknown port
        ]
        
        device = Device(ip="test")
        for port, expected_service in test_cases:
            device.open_ports = [port]
            device.services = []
            enhanced = self.parser.enhance_device_info(device)
            self.assertIn(expected_service, enhanced.services)
    
    def test_parse_nmap_format(self):
        """Test parsing nmap-specific format."""
        nmap_data = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "hostname": "gateway",
                "open_ports": [22, 80],
                "services": [
                    "ssh:22 (OpenSSH 8.0)",
                    "http:80 (nginx 1.18.0)"
                ],
                "os": "Linux 5.4",
                "os_accuracy": 95
            }
        ]
        
        devices = self.parser.parse_nmap_format(nmap_data)
        
        self.assertEqual(len(devices), 1)
        device = devices[0]
        self.assertEqual(device.ip, "192.168.1.1")
        self.assertEqual(device.os, "Linux 5.4")
        self.assertIn("ssh:22 (OpenSSH 8.0)", device.services)
    
    def test_parse_masscan_format(self):
        """Test parsing masscan-specific format."""
        masscan_data = [
            {
                "ip": "10.0.0.1",
                "ports": [
                    {"port": 22, "proto": "tcp", "status": "open"},
                    {"port": 443, "proto": "tcp", "status": "open"}
                ]
            },
            {
                "ip": "10.0.0.2",
                "ports": [
                    {"port": 80, "proto": "tcp", "status": "open"}
                ]
            }
        ]
        
        devices = self.parser.parse_masscan_format(masscan_data)
        
        self.assertEqual(len(devices), 2)
        # First device
        self.assertEqual(devices[0].ip, "10.0.0.1")
        self.assertIn(22, devices[0].open_ports)
        self.assertIn(443, devices[0].open_ports)
        # Second device
        self.assertEqual(devices[1].ip, "10.0.0.2")
        self.assertIn(80, devices[1].open_ports)
    
    def test_parse_arp_scan_format(self):
        """Test parsing arp-scan format."""
        arp_data = [
            {
                "ip": "192.168.1.1",
                "mac": "AA:BB:CC:DD:EE:FF",
                "vendor": "Cisco Systems, Inc."
            },
            {
                "ip": "192.168.1.10",
                "mac": "11:22:33:44:55:66",
                "vendor": "Apple, Inc."
            }
        ]
        
        devices = self.parser.parse_arp_scan_format(arp_data)
        
        self.assertEqual(len(devices), 2)
        self.assertEqual(devices[0].ip, "192.168.1.1")
        self.assertEqual(devices[0].mac, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(devices[0].vendor, "Cisco Systems, Inc.")
        self.assertEqual(devices[1].vendor, "Apple, Inc.")
    
    def test_merge_scan_results(self):
        """Test merging results from multiple scanners."""
        # Results from different scanners
        nmap_results = [
            Device(
                ip="192.168.1.1",
                hostname="router.local",
                open_ports=[22, 80],
                os="RouterOS"
            )
        ]
        
        arp_results = [
            Device(
                ip="192.168.1.1",
                mac="00:11:22:33:44:55",
                vendor="MikroTik"
            ),
            Device(
                ip="192.168.1.2",
                mac="AA:BB:CC:DD:EE:FF",
                vendor="Apple"
            )
        ]
        
        merged = self.parser.merge_scan_results([nmap_results, arp_results])
        
        self.assertEqual(len(merged), 2)
        
        # Check merged device
        router = next(d for d in merged if d.ip == "192.168.1.1")
        self.assertEqual(router.hostname, "router.local")
        self.assertEqual(router.mac, "00:11:22:33:44:55")
        self.assertEqual(router.vendor, "MikroTik")
        self.assertEqual(router.os, "RouterOS")
        self.assertIn(22, router.open_ports)
        
        # Check device only from ARP scan
        apple = next(d for d in merged if d.ip == "192.168.1.2")
        self.assertEqual(apple.mac, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(apple.vendor, "Apple")
    
    def test_merge_scan_results_prefer_detailed(self):
        """Test that merge prefers more detailed information."""
        scan1 = [
            Device(
                ip="10.0.0.1",
                mac="11:11:11:11:11:11",
                hostname="",
                open_ports=[22]
            )
        ]
        
        scan2 = [
            Device(
                ip="10.0.0.1",
                mac="11:11:11:11:11:11",
                hostname="server.example.com",
                open_ports=[22, 80, 443],
                os="Ubuntu 20.04"
            )
        ]
        
        merged = self.parser.merge_scan_results([scan1, scan2])
        
        self.assertEqual(len(merged), 1)
        device = merged[0]
        # Should prefer the more detailed scan2 result
        self.assertEqual(device.hostname, "server.example.com")
        self.assertEqual(device.os, "Ubuntu 20.04")
        self.assertEqual(len(device.open_ports), 3)
    
    def test_save_and_load_results(self):
        """Test saving and loading scan results."""
        devices = [
            Device(
                ip="192.168.1.1",
                mac="00:11:22:33:44:55",
                hostname="router",
                open_ports=[22, 80]
            ),
            Device(
                ip="192.168.1.10",
                hostname="server",
                services=["ssh:22", "http:80"]
            )
        ]
        
        # Test saving
        json_output = self.parser.save_results(devices, format="json")
        self.assertIsInstance(json_output, str)
        
        # Verify JSON structure
        data = json.loads(json_output)
        self.assertIn("scan_time", data)
        self.assertIn("total_devices", data)
        self.assertEqual(data["total_devices"], 2)
        self.assertIn("devices", data)
        self.assertEqual(len(data["devices"]), 2)
        
        # Test loading
        loaded_devices = self.parser.load_results(json_output)
        self.assertEqual(len(loaded_devices), 2)
        self.assertEqual(loaded_devices[0].ip, "192.168.1.1")
        self.assertEqual(loaded_devices[1].hostname, "server")
    
    def test_save_results_csv(self):
        """Test saving results in CSV format."""
        devices = [
            Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF", hostname="host1"),
            Device(ip="10.0.0.2", mac="11:22:33:44:55:66", hostname="host2")
        ]
        
        csv_output = self.parser.save_results(devices, format="csv")
        self.assertIn("ip,mac,hostname", csv_output)
        self.assertIn("10.0.0.1,AA:BB:CC:DD:EE:FF,host1", csv_output)
        self.assertIn("10.0.0.2,11:22:33:44:55:66,host2", csv_output)
    
    def test_filter_devices(self):
        """Test device filtering functionality."""
        devices = [
            Device(ip="192.168.1.1", type="router", open_ports=[22, 80]),
            Device(ip="192.168.1.10", type="server", open_ports=[22, 3306]),
            Device(ip="192.168.1.20", type="workstation", open_ports=[]),
            Device(ip="192.168.1.30", type="printer", open_ports=[9100])
        ]
        
        # Filter by type
        routers = self.parser.filter_devices(devices, device_type="router")
        self.assertEqual(len(routers), 1)
        self.assertEqual(routers[0].ip, "192.168.1.1")
        
        # Filter by open ports
        with_ports = self.parser.filter_devices(devices, has_ports=True)
        self.assertEqual(len(with_ports), 3)  # All except workstation
        
        # Filter by specific port
        ssh_devices = self.parser.filter_devices(devices, port=22)
        self.assertEqual(len(ssh_devices), 2)  # Router and server
        
        # Multiple filters
        ssh_servers = self.parser.filter_devices(
            devices,
            device_type="server",
            port=22
        )
        self.assertEqual(len(ssh_servers), 1)
        self.assertEqual(ssh_servers[0].ip, "192.168.1.10")
    
    def test_get_statistics(self):
        """Test scan statistics generation."""
        devices = [
            Device(ip="192.168.1.1", type="router", os="RouterOS", open_ports=[22, 80]),
            Device(ip="192.168.1.10", type="server", os="Linux", open_ports=[22, 80, 443]),
            Device(ip="192.168.1.11", type="server", os="Windows", open_ports=[3389, 445]),
            Device(ip="192.168.1.20", type="workstation", os="Windows", open_ports=[]),
            Device(ip="192.168.1.30", type="printer", open_ports=[9100])
        ]
        
        stats = self.parser.get_statistics(devices)
        
        self.assertEqual(stats['total_devices'], 5)
        self.assertEqual(stats['device_types']['router'], 1)
        self.assertEqual(stats['device_types']['server'], 2)
        self.assertEqual(stats['device_types']['workstation'], 1)
        self.assertEqual(stats['device_types']['printer'], 1)
        
        self.assertEqual(stats['os_distribution']['RouterOS'], 1)
        self.assertEqual(stats['os_distribution']['Linux'], 1)
        self.assertEqual(stats['os_distribution']['Windows'], 2)
        self.assertEqual(stats['os_distribution']['Unknown'], 1)
        
        self.assertEqual(stats['devices_with_open_ports'], 4)
        self.assertEqual(stats['common_ports'][22], 2)
        self.assertEqual(stats['common_ports'][80], 2)
        self.assertEqual(stats['common_ports'][443], 1)
        self.assertEqual(stats['common_ports'][3389], 1)
    
    def test_error_handling(self):
        """Test error handling in various methods."""
        # Invalid data format
        with self.assertLogs(level='WARNING'):
            devices = self.parser.normalize_scan_results("invalid_data")
            self.assertEqual(len(devices), 0)
        
        # Invalid device data
        invalid_device_data = [
            {"no_ip_field": "test"},
            {"ip": None},
            "not_a_dict"
        ]
        
        devices = self.parser.normalize_scan_results(invalid_device_data)
        # Should handle gracefully and skip invalid entries
        self.assertEqual(len(devices), 0)
    
    def test_device_cache(self):
        """Test device caching functionality."""
        device1 = Device(ip="192.168.1.1", mac="00:11:22:33:44:55")
        device2 = Device(ip="192.168.1.1", mac="00:11:22:33:44:55", hostname="updated")
        
        # First enhancement should cache
        self.parser.enhance_device_info(device1)
        self.assertIn("192.168.1.1", self.parser._device_cache)
        
        # Second enhancement should use cache
        with patch.object(self.parser.mac_lookup, 'lookup') as mock_lookup:
            self.parser.enhance_device_info(device2)
            # MAC lookup should not be called due to caching
            mock_lookup.assert_not_called()


class TestParserIntegration(unittest.TestCase):
    """Integration tests for parser with realistic data."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.parser = ScanParser()
    
    def test_full_parsing_workflow(self):
        """Test complete parsing workflow with mixed scanner data."""
        # Simulate data from different scanners
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
        
        masscan_data = [
            {"ip": "192.168.1.10", "ports": [{"port": 22}, {"port": 3306}]},
            {"ip": "192.168.1.11", "ports": [{"port": 80}]}
        ]
        
        arp_data = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "vendor": "Netgate"},
            {"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Dell Inc."},
            {"ip": "192.168.1.11", "mac": "11:22:33:44:55:66", "vendor": "HP"}
        ]
        
        # Parse each format
        nmap_devices = self.parser.parse_nmap_format(nmap_data)
        masscan_devices = self.parser.parse_masscan_format(masscan_data)
        arp_devices = self.parser.parse_arp_scan_format(arp_data)
        
        # Merge results
        all_devices = self.parser.merge_scan_results([
            nmap_devices,
            masscan_devices,
            arp_devices
        ])
        
        # Verify results
        self.assertEqual(len(all_devices), 3)
        
        # Check gateway (has data from nmap and arp)
        gateway = next(d for d in all_devices if d.ip == "192.168.1.1")
        self.assertEqual(gateway.hostname, "gateway.local")
        self.assertEqual(gateway.os, "pfSense")
        self.assertEqual(len(gateway.open_ports), 3)
        
        # Check server (has data from masscan and arp)
        server = next(d for d in all_devices if d.ip == "192.168.1.10")
        self.assertEqual(server.mac, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(server.vendor, "Dell Inc.")
        self.assertIn(22, server.open_ports)
        self.assertIn(3306, server.open_ports)
        
        # Generate statistics
        stats = self.parser.get_statistics(all_devices)
        self.assertEqual(stats['total_devices'], 3)
        self.assertEqual(stats['devices_with_open_ports'], 3)
        
        # Save and reload
        json_data = self.parser.save_results(all_devices)
        reloaded = self.parser.load_results(json_data)
        self.assertEqual(len(reloaded), 3)


if __name__ == '__main__':
    unittest.main()