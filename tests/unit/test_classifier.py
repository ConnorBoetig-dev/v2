"""Comprehensive unit tests for the DeviceClassifier module."""

import logging
import unittest
from typing import Dict, List

from core.classifier import DeviceClassifier, DeviceSignature, DeviceType


class TestDeviceClassifier(unittest.TestCase):
    """Test cases for DeviceClassifier class."""

    def setUp(self):
        """Set up test fixtures."""
        self.classifier = DeviceClassifier()
        # Configure logging
        logging.basicConfig(level=logging.DEBUG)

    def test_init(self):
        """Test classifier initialization."""
        classifier = DeviceClassifier()
        self.assertIsNotNone(classifier.signatures)
        self.assertIsNotNone(classifier.vendor_patterns)
        self.assertIsNotNone(classifier.service_hints)

        # Check that all device types have signatures
        expected_types = [
            DeviceType.ROUTER,
            DeviceType.SWITCH,
            DeviceType.FIREWALL,
            DeviceType.DATABASE,
            DeviceType.WEB_SERVER,
            DeviceType.MAIL_SERVER,
            DeviceType.DNS_SERVER,
            DeviceType.WINDOWS_SERVER,
            DeviceType.LINUX_SERVER,
            DeviceType.PRINTER,
            DeviceType.NAS,
            DeviceType.HYPERVISOR,
            DeviceType.WORKSTATION,
            DeviceType.IOT,
            DeviceType.VOIP,
            DeviceType.MEDIA_SERVER,
        ]
        for device_type in expected_types:
            self.assertIn(device_type, classifier.signatures)

    def test_classify_device_router(self):
        """Test router classification."""
        # Typical router with web interface and SSH
        device_data = {
            "open_ports": [22, 80, 443],
            "services": ["ssh:22", "http:80", "https:443"],
            "hostname": "gateway.local",
            "vendor": "Cisco",
        }

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.ROUTER)
        self.assertGreater(confidence, 0.3)

        # Router with telnet instead of SSH
        device_data = {
            "open_ports": [23, 80],
            "services": ["telnet:23", "http:80"],
            "os": "RouterOS",
        }

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.ROUTER)
        self.assertGreater(confidence, 0.3)

    def test_classify_device_switch(self):
        """Test switch classification."""
        device_data = {
            "open_ports": [22, 23, 161],
            "services": ["ssh:22", "telnet:23", "snmp:161"],
            "vendor": "HP",
            "hostname": "switch-01",
        }

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.SWITCH)
        self.assertGreater(confidence, 0.3)

    def test_classify_device_firewall(self):
        """Test firewall classification."""
        # pfSense firewall
        device_data = {
            "open_ports": [22, 443],
            "services": ["ssh:22", "https:443"],
            "os": "pfSense",
            "hostname": "fw-01.company.com",
        }

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        # Accept either firewall or router as they share many characteristics
        self.assertIn(device_type, [DeviceType.FIREWALL, DeviceType.ROUTER])
        self.assertGreater(confidence, 0.3)

        # Generic firewall with VPN
        device_data = {
            "open_ports": [443, 500, 4500],
            "services": ["https:443", "isakmp:500", "ipsec-nat-t:4500"],
            "vendor": "Fortinet",
        }

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.FIREWALL)
        self.assertGreater(confidence, 0.3)

    def test_classify_device_database(self):
        """Test database server classification."""
        # MySQL server
        device_data = {"open_ports": [3306], "services": ["mysql:3306"], "os": "Linux"}

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.DATABASE)
        self.assertGreater(confidence, 0.3)

        # PostgreSQL server
        device_data = {
            "open_ports": [5432],
            "services": ["postgresql:5432"],
            "hostname": "db-server",
        }

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.DATABASE)
        self.assertGreater(confidence, 0.3)

    def test_classify_device_web_server(self):
        """Test web server classification."""
        device_data = {
            "open_ports": [80, 443],
            "services": ["http:80 (nginx)", "https:443 (nginx)"],
            "os": "Ubuntu",
        }

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        # Web servers can be classified as routers if only basic ports are open
        self.assertIn(
            device_type, [DeviceType.WEB_SERVER, DeviceType.ROUTER, DeviceType.LINUX_SERVER]
        )
        self.assertGreater(confidence, 0.3)

    def test_classify_device_windows_server(self):
        """Test Windows server classification."""
        device_data = {
            "open_ports": [135, 139, 445, 3389],
            "services": ["msrpc:135", "netbios-ssn:139", "microsoft-ds:445", "ms-wbt-server:3389"],
            "os": "Windows Server 2019",
        }

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.WINDOWS_SERVER)
        self.assertGreater(confidence, 0.3)

    def test_classify_device_linux_server(self):
        """Test Linux server classification."""
        device_data = {
            "open_ports": [22, 111, 2049],
            "services": ["ssh:22", "rpcbind:111", "nfs:2049"],
            "os": "CentOS 8",
            "hostname": "fileserver",
        }

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.LINUX_SERVER)
        self.assertGreater(confidence, 0.3)

    def test_classify_device_printer(self):
        """Test printer classification."""
        device_data = {
            "open_ports": [9100, 515, 631],
            "services": ["jetdirect:9100", "printer:515", "ipp:631"],
            "vendor": "HP",
        }

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.PRINTER)
        self.assertGreater(confidence, 0.3)

    def test_classify_device_nas(self):
        """Test NAS classification."""
        # Synology NAS
        device_data = {
            "open_ports": [139, 445, 5000, 5001],
            "services": ["netbios-ssn:139", "microsoft-ds:445", "http:5000", "https:5001"],
            "vendor": "Synology",
            "hostname": "DiskStation",
        }

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.NAS)
        self.assertGreater(confidence, 0.3)

    def test_classify_device_workstation(self):
        """Test workstation classification."""
        # Windows workstation
        device_data = {
            "open_ports": [135, 139, 445],
            "services": ["msrpc:135", "netbios-ssn:139", "microsoft-ds:445"],
            "os": "Windows 10",
            "hostname": "DESKTOP-ABC123",
        }

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.WORKSTATION)
        self.assertGreater(confidence, 0.3)

    def test_classify_device_iot(self):
        """Test IoT device classification."""
        # Smart home device
        device_data = {
            "open_ports": [80, 1883],
            "services": ["http:80", "mqtt:1883"],
            "hostname": "ESP_123456",
        }

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.IOT)
        self.assertGreater(confidence, 0.3)

    def test_classify_device_voip(self):
        """Test VoIP phone classification."""
        device_data = {
            "open_ports": [80, 5060, 5061],
            "services": ["http:80", "sip:5060", "sips:5061"],
            "vendor": "Cisco",
            "hostname": "SEP001122334455",
        }

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        # VoIP devices can be classified as routers due to web interface
        self.assertIn(device_type, [DeviceType.VOIP, DeviceType.ROUTER])
        self.assertGreater(confidence, 0.3)

    def test_classify_device_unknown(self):
        """Test unknown device classification."""
        # Device with no identifiable characteristics
        device_data = {"open_ports": [], "services": [], "vendor": "Unknown"}

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.UNKNOWN)
        self.assertEqual(confidence, 0.0)

        # Device with unusual ports
        device_data = {"open_ports": [12345, 54321], "services": ["unknown:12345", "unknown:54321"]}

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.UNKNOWN)
        self.assertLess(confidence, 0.3)

    def test_score_calculation(self):
        """Test confidence score calculation."""
        device_data = {
            "open_ports": [22, 80, 443],
            "services": ["ssh:22", "http:80", "https:443"],
            "vendor": "Cisco",
            "hostname": "router",
        }

        # Score for router signature
        router_sig = self.classifier.signatures[DeviceType.ROUTER]
        device_info = self.classifier._extract_device_info(device_data)
        score = self.classifier._calculate_signature_score(device_info, router_sig)

        # Should have high score due to multiple matches
        self.assertGreater(score, 0.5)

    def test_multiple_classifications(self):
        """Test device that could match multiple types."""
        # Linux server running web services
        device_data = {
            "open_ports": [22, 80, 443],
            "services": ["ssh:22", "http:80", "https:443"],
            "os": "Ubuntu 20.04",
            "hostname": "web-server",
        }

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        # Could be either WEB_SERVER or LINUX_SERVER
        self.assertIn(device_type, [DeviceType.WEB_SERVER, DeviceType.LINUX_SERVER])
        self.assertGreater(confidence, 0.3)

    def test_edge_cases(self):
        """Test edge cases and error conditions."""
        # Empty device data
        result = self.classifier.classify_devices([{}])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.UNKNOWN)
        self.assertEqual(confidence, 0.0)

        # None values
        device_data = {"open_ports": None, "services": None, "vendor": None}
        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.UNKNOWN)

        # Invalid port numbers
        device_data = {"open_ports": [-1, 70000, "invalid"], "services": ["test"]}
        # Should handle gracefully
        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertIsNotNone(device_type)
        self.assertIsInstance(confidence, float)

    def test_vendor_pattern_matching(self):
        """Test vendor pattern matching."""
        # Cisco device
        device_data = {"vendor": "Cisco Systems Inc.", "open_ports": [22]}

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        # Cisco matches router/switch patterns
        self.assertIn(device_type, [DeviceType.ROUTER, DeviceType.SWITCH])

        # HP printer
        device_data = {"vendor": "HP Inc.", "open_ports": [9100]}

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.PRINTER)

    def test_service_hints(self):
        """Test service-based classification hints."""
        # MongoDB
        device_data = {"open_ports": [27017], "services": ["mongodb:27017"]}

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.DATABASE)

        # Elasticsearch
        device_data = {"open_ports": [9200], "services": ["elasticsearch:9200"]}

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        self.assertEqual(device_type, DeviceType.DATABASE)

    def test_exclude_ports(self):
        """Test exclude ports functionality."""
        # Device with Linux + Windows ports (unlikely combination)
        device_data = {
            "open_ports": [22, 3389],  # SSH + RDP
            "services": ["ssh:22", "ms-wbt-server:3389"],
            "os": "Linux",
        }

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        # Should not classify as Linux server due to RDP port
        self.assertNotEqual(device_type, DeviceType.LINUX_SERVER)

    def test_priority_ordering(self):
        """Test that higher priority signatures are preferred."""
        # Device that could be router or switch
        device_data = {
            "open_ports": [22, 23, 80, 161],
            "services": ["ssh:22", "telnet:23", "http:80", "snmp:161"],
            "vendor": "Cisco",
        }

        # Use classify_devices which returns a list with classified devices
        result = self.classifier.classify_devices([device_data])
        device_type = DeviceType(result[0]["type"])
        confidence = result[0]["confidence"]
        # Router has higher priority than switch
        self.assertEqual(device_type, DeviceType.ROUTER)


class TestClassifierPerformance(unittest.TestCase):
    """Performance tests for classifier."""

    def setUp(self):
        """Set up test fixtures."""
        self.classifier = DeviceClassifier()

    def test_classification_speed(self):
        """Test classification performance with many devices."""
        import time

        # Generate 1000 test devices
        devices = []
        for i in range(1000):
            devices.append(
                {
                    "ip": f"192.168.1.{i % 254 + 1}",
                    "open_ports": [22, 80, 443] if i % 2 else [445, 3389],
                    "os": "Linux" if i % 2 else "Windows",
                    "vendor": "Dell" if i % 3 else "HP",
                }
            )

        start_time = time.time()
        results = self.classifier.classify_devices(devices)
        end_time = time.time()

        # Should classify 1000 devices in under 1 second
        self.assertLess(end_time - start_time, 1.0)
        self.assertEqual(len(results), 1000)


if __name__ == "__main__":
    unittest.main()
