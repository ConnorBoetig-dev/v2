"""Comprehensive unit tests for the DeviceClassifier module."""

import logging
import unittest
from typing import Dict, List

from core.classifier import DeviceClassifier


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
        self.assertIsNotNone(classifier.port_signatures)
        self.assertIsNotNone(classifier.service_keywords)
        self.assertIsNotNone(classifier.os_keywords)
        self.assertIsNotNone(classifier.vendor_keywords)
        
        # Check that all device types are defined
        expected_types = [
            'router', 'switch', 'firewall', 'access_point',
            'server', 'workstation', 'printer', 'camera',
            'iot_device', 'nas', 'voip_phone', 'media_device',
            'mobile_device', 'virtual_machine', 'container',
            'industrial_device'
        ]
        for device_type in expected_types:
            self.assertIn(device_type, classifier.port_signatures)
    
    def test_classify_device_router(self):
        """Test router classification."""
        # Typical router with web interface and SSH
        device_data = {
            'open_ports': [22, 80, 443],
            'services': ['ssh:22', 'http:80', 'https:443'],
            'hostname': 'gateway.local',
            'vendor': 'Cisco'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'router')
        self.assertGreater(confidence, 0.7)
        
        # Router with telnet instead of SSH
        device_data = {
            'open_ports': [23, 80],
            'services': ['telnet:23', 'http:80'],
            'os': 'RouterOS'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'router')
        self.assertGreater(confidence, 0.7)
    
    def test_classify_device_switch(self):
        """Test switch classification."""
        device_data = {
            'open_ports': [22, 23, 161],
            'services': ['ssh:22', 'telnet:23', 'snmp:161'],
            'vendor': 'HP',
            'hostname': 'switch-01'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'switch')
        self.assertGreater(confidence, 0.6)
    
    def test_classify_device_firewall(self):
        """Test firewall classification."""
        # pfSense firewall
        device_data = {
            'open_ports': [22, 443],
            'services': ['ssh:22', 'https:443'],
            'os': 'pfSense',
            'hostname': 'fw-01.company.com'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'firewall')
        self.assertGreater(confidence, 0.8)
        
        # Generic firewall with VPN
        device_data = {
            'open_ports': [443, 500, 4500],
            'services': ['https:443', 'isakmp:500', 'ipsec-nat-t:4500'],
            'vendor': 'Fortinet'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'firewall')
        self.assertGreater(confidence, 0.7)
    
    def test_classify_device_access_point(self):
        """Test access point classification."""
        device_data = {
            'open_ports': [80, 443],
            'services': ['http:80', 'https:443'],
            'vendor': 'Ubiquiti',
            'hostname': 'UAP-AC-PRO'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'access_point')
        self.assertGreater(confidence, 0.6)
    
    def test_classify_device_server(self):
        """Test server classification."""
        # Web server
        device_data = {
            'open_ports': [22, 80, 443, 3306],
            'services': ['ssh:22', 'http:80', 'https:443', 'mysql:3306'],
            'os': 'Ubuntu 20.04'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'server')
        self.assertGreater(confidence, 0.7)
        
        # Windows server
        device_data = {
            'open_ports': [135, 139, 445, 3389],
            'services': ['msrpc:135', 'netbios-ssn:139', 'microsoft-ds:445', 'ms-wbt-server:3389'],
            'os': 'Windows Server 2019'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'server')
        self.assertGreater(confidence, 0.8)
    
    def test_classify_device_workstation(self):
        """Test workstation classification."""
        # Windows workstation
        device_data = {
            'open_ports': [135, 139, 445],
            'services': ['msrpc:135', 'netbios-ssn:139', 'microsoft-ds:445'],
            'os': 'Windows 10',
            'hostname': 'DESKTOP-ABC123'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'workstation')
        self.assertGreater(confidence, 0.7)
        
        # Mac workstation
        device_data = {
            'open_ports': [548, 5900],
            'services': ['afp:548', 'vnc:5900'],
            'vendor': 'Apple',
            'os': 'Mac OS X'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'workstation')
        self.assertGreater(confidence, 0.6)
    
    def test_classify_device_printer(self):
        """Test printer classification."""
        device_data = {
            'open_ports': [9100, 515, 631],
            'services': ['jetdirect:9100', 'printer:515', 'ipp:631'],
            'vendor': 'HP'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'printer')
        self.assertGreater(confidence, 0.8)
        
        # Network scanner/printer combo
        device_data = {
            'open_ports': [80, 443, 9100],
            'hostname': 'HP-LaserJet-MFP',
            'services': ['http:80', 'https:443', 'jetdirect:9100']
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'printer')
        self.assertGreater(confidence, 0.7)
    
    def test_classify_device_camera(self):
        """Test camera classification."""
        # IP camera with RTSP
        device_data = {
            'open_ports': [80, 554, 8000],
            'services': ['http:80', 'rtsp:554', 'http-alt:8000'],
            'vendor': 'Hikvision'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'camera')
        self.assertGreater(confidence, 0.7)
        
        # Camera with ONVIF
        device_data = {
            'open_ports': [80, 554],
            'hostname': 'DCS-2330L',
            'services': ['http:80', 'rtsp:554']
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'camera')
        self.assertGreater(confidence, 0.6)
    
    def test_classify_device_iot(self):
        """Test IoT device classification."""
        # Smart home device
        device_data = {
            'open_ports': [80, 1883],
            'services': ['http:80', 'mqtt:1883'],
            'hostname': 'ESP_123456'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'iot_device')
        self.assertGreater(confidence, 0.6)
        
        # Smart TV
        device_data = {
            'open_ports': [8080, 9080],
            'vendor': 'Samsung',
            'hostname': 'Samsung-TV'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertIn(device_type, ['iot_device', 'media_device'])
        self.assertGreater(confidence, 0.5)
    
    def test_classify_device_nas(self):
        """Test NAS classification."""
        # Synology NAS
        device_data = {
            'open_ports': [80, 443, 139, 445, 5000, 5001],
            'services': ['http:80', 'https:443', 'netbios-ssn:139', 'microsoft-ds:445'],
            'vendor': 'Synology',
            'hostname': 'DiskStation'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'nas')
        self.assertGreater(confidence, 0.8)
        
        # QNAP NAS
        device_data = {
            'open_ports': [22, 80, 443, 445, 8080],
            'hostname': 'QNAP-NAS',
            'os': 'QTS'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'nas')
        self.assertGreater(confidence, 0.7)
    
    def test_classify_device_voip_phone(self):
        """Test VoIP phone classification."""
        device_data = {
            'open_ports': [80, 5060, 5061],
            'services': ['http:80', 'sip:5060', 'sips:5061'],
            'vendor': 'Cisco',
            'hostname': 'SEP001122334455'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'voip_phone')
        self.assertGreater(confidence, 0.7)
    
    def test_classify_device_media(self):
        """Test media device classification."""
        # Roku
        device_data = {
            'open_ports': [8060],
            'vendor': 'Roku',
            'hostname': 'Roku-123'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'media_device')
        self.assertGreater(confidence, 0.7)
        
        # Chromecast
        device_data = {
            'open_ports': [8008, 8009],
            'vendor': 'Google',
            'hostname': 'Chromecast'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'media_device')
        self.assertGreater(confidence, 0.6)
    
    def test_classify_device_mobile(self):
        """Test mobile device classification."""
        # iPhone
        device_data = {
            'open_ports': [62078],
            'vendor': 'Apple',
            'hostname': 'iPhone'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'mobile_device')
        self.assertGreater(confidence, 0.6)
        
        # Android
        device_data = {
            'open_ports': [5555],
            'services': ['adb:5555'],
            'hostname': 'android-1234567890'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'mobile_device')
        self.assertGreater(confidence, 0.6)
    
    def test_classify_device_virtual_machine(self):
        """Test virtual machine classification."""
        # VMware VM
        device_data = {
            'open_ports': [22, 80, 443],
            'vendor': 'VMware',
            'mac': '00:0C:29:11:22:33'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'virtual_machine')
        self.assertGreater(confidence, 0.7)
        
        # VirtualBox VM
        device_data = {
            'mac': '08:00:27:AA:BB:CC',
            'os': 'Ubuntu 20.04'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'virtual_machine')
        self.assertGreater(confidence, 0.6)
    
    def test_classify_device_container(self):
        """Test container classification."""
        # Docker container
        device_data = {
            'open_ports': [80, 443],
            'hostname': 'webapp-container-1',
            'os': 'Alpine Linux'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        # Could be classified as container or server
        self.assertIn(device_type, ['container', 'server'])
    
    def test_classify_device_industrial(self):
        """Test industrial device classification."""
        # PLC with Modbus
        device_data = {
            'open_ports': [502],
            'services': ['modbus:502'],
            'vendor': 'Siemens'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'industrial_device')
        self.assertGreater(confidence, 0.7)
        
        # SCADA system
        device_data = {
            'open_ports': [102, 502],
            'services': ['iso-tsap:102', 'modbus:502'],
            'hostname': 'SCADA-01'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'industrial_device')
        self.assertGreater(confidence, 0.7)
    
    def test_classify_device_unknown(self):
        """Test unknown device classification."""
        # Device with no identifiable characteristics
        device_data = {
            'open_ports': [],
            'services': [],
            'vendor': 'Unknown'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'unknown')
        self.assertEqual(confidence, 0.0)
        
        # Device with unusual ports
        device_data = {
            'open_ports': [12345, 54321],
            'services': ['unknown:12345', 'unknown:54321']
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'unknown')
        self.assertLess(confidence, 0.3)
    
    def test_calculate_confidence(self):
        """Test confidence calculation logic."""
        # High confidence - multiple matching indicators
        matches = {
            'router': {
                'ports': 3,
                'services': 2,
                'os': 1,
                'vendor': 1,
                'hostname': 1
            }
        }
        
        device_type, confidence = self.classifier._calculate_confidence(matches)
        self.assertEqual(device_type, 'router')
        self.assertGreater(confidence, 0.8)
        
        # Medium confidence - some matches
        matches = {
            'server': {
                'ports': 2,
                'services': 1,
                'os': 0,
                'vendor': 0,
                'hostname': 0
            }
        }
        
        device_type, confidence = self.classifier._calculate_confidence(matches)
        self.assertEqual(device_type, 'server')
        self.assertGreater(confidence, 0.5)
        self.assertLess(confidence, 0.7)
        
        # Low confidence - minimal matches
        matches = {
            'workstation': {
                'ports': 1,
                'services': 0,
                'os': 0,
                'vendor': 0,
                'hostname': 0
            }
        }
        
        device_type, confidence = self.classifier._calculate_confidence(matches)
        self.assertEqual(device_type, 'workstation')
        self.assertLess(confidence, 0.5)
    
    def test_multiple_type_matches(self):
        """Test handling of devices that match multiple types."""
        # Device that could be router or firewall
        device_data = {
            'open_ports': [22, 443, 500, 4500],
            'services': ['ssh:22', 'https:443', 'isakmp:500', 'ipsec-nat-t:4500'],
            'hostname': 'edge-device'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertIn(device_type, ['router', 'firewall'])
        self.assertGreater(confidence, 0.5)
    
    def test_get_device_info(self):
        """Test getting device information."""
        info = self.classifier.get_device_info('router')
        self.assertIn('description', info)
        self.assertIn('common_ports', info)
        self.assertIn('typical_services', info)
        
        # Unknown device type
        info = self.classifier.get_device_info('nonexistent')
        self.assertIn('description', info)
        self.assertIn('Unknown', info['description'])
    
    def test_classify_batch(self):
        """Test batch classification of devices."""
        devices = [
            {
                'ip': '192.168.1.1',
                'open_ports': [22, 80, 443],
                'vendor': 'Cisco'
            },
            {
                'ip': '192.168.1.10',
                'open_ports': [22, 3306, 80],
                'os': 'Ubuntu'
            },
            {
                'ip': '192.168.1.20',
                'open_ports': [445, 3389],
                'os': 'Windows 10'
            }
        ]
        
        results = self.classifier.classify_batch(devices)
        
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]['type'], 'router')
        self.assertEqual(results[1]['type'], 'server')
        self.assertEqual(results[2]['type'], 'workstation')
        
        # All should have confidence scores
        for result in results:
            self.assertIn('confidence', result)
            self.assertGreater(result['confidence'], 0)
    
    def test_edge_cases(self):
        """Test edge cases and error conditions."""
        # Empty device data
        device_type, confidence = self.classifier.classify_device({})
        self.assertEqual(device_type, 'unknown')
        self.assertEqual(confidence, 0.0)
        
        # None values
        device_data = {
            'open_ports': None,
            'services': None,
            'vendor': None
        }
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'unknown')
        
        # Invalid port numbers
        device_data = {
            'open_ports': [-1, 70000, 'invalid'],
            'services': ['test']
        }
        device_type, confidence = self.classifier.classify_device(device_data)
        # Should handle gracefully
        self.assertIsNotNone(device_type)
        self.assertIsInstance(confidence, float)
    
    def test_custom_classification_rules(self):
        """Test adding custom classification rules."""
        # Add custom rule
        self.classifier.add_custom_rule(
            'custom_device',
            ports=[12345],
            services=['custom'],
            keywords=['CustomOS']
        )
        
        # Test classification with custom rule
        device_data = {
            'open_ports': [12345],
            'services': ['custom:12345'],
            'os': 'CustomOS'
        }
        
        device_type, confidence = self.classifier.classify_device(device_data)
        self.assertEqual(device_type, 'custom_device')
        self.assertGreater(confidence, 0.5)


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
            devices.append({
                'ip': f'192.168.1.{i % 254 + 1}',
                'open_ports': [22, 80, 443] if i % 2 else [445, 3389],
                'os': 'Linux' if i % 2 else 'Windows',
                'vendor': 'Dell' if i % 3 else 'HP'
            })
        
        start_time = time.time()
        results = self.classifier.classify_batch(devices)
        end_time = time.time()
        
        # Should classify 1000 devices in under 1 second
        self.assertLess(end_time - start_time, 1.0)
        self.assertEqual(len(results), 1000)


if __name__ == '__main__':
    unittest.main()