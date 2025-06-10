"""Integration tests for the complete NetworkMapper workflow."""

import json
import logging
import os
import tempfile
import time
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

# Import all core modules
from core.scanner import NetworkScanner
from core.parser import ScanParser, Device
from core.classifier import DeviceClassifier
from core.tracker import ChangeTracker
from core.annotator import DeviceAnnotator, DeviceAnnotation


class TestFullScanWorkflow(unittest.TestCase):
    """Test the complete scan workflow from scanning to annotation."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.scanner = NetworkScanner()
        self.parser = ScanParser()
        self.classifier = DeviceClassifier()
        self.tracker = ChangeTracker(output_path=Path(self.temp_dir))
        self.annotator = DeviceAnnotator(output_path=Path(self.temp_dir))
        
        # Configure logging
        logging.basicConfig(level=logging.DEBUG)
    
    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    @patch('subprocess.Popen')
    @patch('subprocess.run')
    def test_discovery_scan_workflow(self, mock_run, mock_popen):
        """Test complete discovery scan workflow."""
        # Mock nmap availability check
        mock_run.return_value.returncode = 0
        
        # Mock nmap process output - use generator to avoid StopIteration
        def readline_generator():
            outputs = [
                "Starting Nmap",
                "Nmap scan report for gateway.local (192.168.1.1)",
                "Host is up",
                "MAC Address: 00:11:22:33:44:55 (Cisco Systems)",
                "Nmap scan report for server.local (192.168.1.10)",
                "Host is up",
                "MAC Address: AA:BB:CC:DD:EE:FF (Dell Inc.)",
                "Nmap scan report for 192.168.1.20",
                "Host is up",
                "Nmap done: 256 IP addresses (3 hosts up) scanned"
            ]
            for output in outputs:
                yield output
            while True:
                yield ""  # Keep returning empty strings
        
        mock_proc = MagicMock()
        mock_proc.poll.side_effect = [None] * 10 + [0]
        mock_proc.returncode = 0
        mock_proc.stdout.readline.side_effect = readline_generator()
        mock_proc.stderr.read.return_value = ""
        mock_popen.return_value = mock_proc
        
        # Mock XML output
        xml_content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Cisco Systems"/>
    <hostnames><hostname name="gateway.local"/></hostnames>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Dell Inc."/>
    <hostnames><hostname name="server.local"/></hostnames>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.20" addrtype="ipv4"/>
  </host>
</nmaprun>"""
        
        with patch('builtins.open', mock_open(read_data=xml_content)):
            with patch('os.path.exists', return_value=True):
                with patch.object(self.scanner, '_cleanup_temp_file'):
                    # Step 1: Scan
                    scan_results = self.scanner.scan("192.168.1.0/24", "discovery")
                    
                    self.assertEqual(len(scan_results), 3)
                    
                    # Step 2: Parse results
                    devices = self.parser.parse_results(scan_results, scanner_type="nmap")
                    self.assertEqual(len(devices), 3)
                    
                    # Step 3: Classify devices
                    classified_devices = self.classifier.classify_devices(devices)
                    self.assertEqual(len(classified_devices), 3)
                    
                    # Verify basic device info
                    device_ips = [d['ip'] for d in classified_devices]
                    self.assertIn('192.168.1.1', device_ips)
                    self.assertIn('192.168.1.10', device_ips)
                    self.assertIn('192.168.1.20', device_ips)
    
    def test_inventory_scan_with_classification(self):
        """Test inventory scan with device classification."""
        # Create mock scan data with service information
        mock_scan_data = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "hostname": "gateway.local",
                "open_ports": [22, 80, 443],
                "services": ["ssh:22", "http:80", "https:443"],
                "os": "RouterOS",
                "vendor": "Cisco"
            },
            {
                "ip": "192.168.1.10",
                "mac": "AA:BB:CC:DD:EE:FF",
                "hostname": "db-server.local",
                "open_ports": [22, 3306],
                "services": ["ssh:22", "mysql:3306"],
                "os": "Ubuntu 20.04",
                "vendor": "Dell"
            },
            {
                "ip": "192.168.1.20",
                "mac": "11:22:33:44:55:66",
                "hostname": "printer.local",
                "open_ports": [80, 443, 9100],
                "services": ["http:80", "https:443", "jetdirect:9100"],
                "vendor": "HP"
            }
        ]
        
        # Classify devices
        classified_devices = self.classifier.classify_devices(mock_scan_data)
        
        # Verify classifications
        router = next(d for d in classified_devices if d['ip'] == '192.168.1.1')
        self.assertEqual(router['type'], 'router')
        self.assertGreater(router['confidence'], 0.3)
        
        server = next(d for d in classified_devices if d['ip'] == '192.168.1.10')
        self.assertIn(server['type'], ['database', 'linux_server'])
        self.assertGreater(server['confidence'], 0.3)
        
        printer = next(d for d in classified_devices if d['ip'] == '192.168.1.20')
        self.assertEqual(printer['type'], 'printer')
        self.assertGreater(printer['confidence'], 0.3)
    
    def test_change_tracking_workflow(self):
        """Test change tracking across multiple scans."""
        # First scan
        initial_devices = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "open_ports": [22, 80],
                "type": "router"
            },
            {
                "ip": "192.168.1.10",
                "mac": "AA:BB:CC:DD:EE:FF",
                "open_ports": [22, 3306],
                "type": "server"
            }
        ]
        
        # First scan establishes baseline - no changes
        changes1 = self.tracker.detect_changes(initial_devices)
        self.assertEqual(changes1, {})  # No previous scan to compare
        
        # Save initial scan data
        self.tracker.scans_path.mkdir(parents=True, exist_ok=True)
        scan_file = self.tracker.scans_path / "scan_20230101_120000.json"
        with open(scan_file, 'w') as f:
            json.dump(initial_devices, f)
        
        # Second scan - modifications and new device
        changed_devices = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "open_ports": [22, 80, 443],  # Added HTTPS
                "type": "router"
            },
            {
                "ip": "192.168.1.10",
                "mac": "AA:BB:CC:DD:EE:FF",
                "open_ports": [22, 3306],
                "type": "server"
            },
            {
                "ip": "192.168.1.20",
                "mac": "11:22:33:44:55:66",
                "open_ports": [445],
                "type": "workstation"
            }
        ]
        
        # Mock previous scan
        with patch.object(self.tracker, '_get_previous_scan') as mock_prev:
            mock_prev.return_value = (initial_devices, "2023-01-01T12:00:00")
            
            # Track changes
            changes2 = self.tracker.detect_changes(changed_devices)
            
            # Verify changes
            self.assertEqual(len(changes2['new_devices']), 1)
            self.assertEqual(changes2['new_devices'][0]['ip'], "192.168.1.20")
            
            self.assertEqual(len(changes2['changed_devices']), 1)
            self.assertEqual(changes2['changed_devices'][0]['ip'], "192.168.1.1")
            
            # Check specific changes
            port_changes = [c for c in changes2['changed_devices'][0]['changes'] 
                           if c['field'] == 'ports']
            self.assertGreater(len(port_changes), 0)
    
    def test_annotation_integration(self):
        """Test device annotation workflow."""
        # Create test devices
        devices = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "type": "router",
                "hostname": "gateway"
            },
            {
                "ip": "192.168.1.10",
                "mac": "AA:BB:CC:DD:EE:FF",
                "type": "server",
                "hostname": "db-server"
            }
        ]
        
        # Add annotation manually
        annotation = DeviceAnnotation(
            ip="192.168.1.1",
            critical=True,
            notes="Main router - do not remove",
            tags=["critical", "infrastructure"]
        )
        self.annotator.annotations["192.168.1.1"] = annotation
        self.annotator.save_annotations()
        
        # Apply annotations to devices
        annotated_devices = self.annotator.apply_annotations(devices)
        
        # Verify annotations were applied
        router = next(d for d in annotated_devices if d['ip'] == '192.168.1.1')
        self.assertTrue(router['critical'])
        self.assertEqual(router['notes'], "Main router - do not remove")
        self.assertEqual(router['tags'], ["critical", "infrastructure"])
        
        # Verify unannotated device
        server = next(d for d in annotated_devices if d['ip'] == '192.168.1.10')
        self.assertFalse(server.get('critical', False))
        self.assertEqual(server.get('notes', ''), '')
    
    def test_report_generation_workflow(self):
        """Test report generation with all components."""
        # Create comprehensive test data
        devices = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "type": "router",
                "hostname": "gateway",
                "open_ports": [22, 80, 443],
                "services": ["ssh:22", "http:80", "https:443"],
                "vendor": "Cisco",
                "critical": False
            },
            {
                "ip": "192.168.1.10",
                "mac": "AA:BB:CC:DD:EE:FF",
                "type": "database",
                "hostname": "db-server",
                "open_ports": [22, 3306],
                "services": ["ssh:22", "mysql:3306"],
                "vendor": "Dell",
                "critical": False
            }
        ]
        
        # Add annotation
        annotation = DeviceAnnotation(
            ip="192.168.1.10",
            critical=True,
            notes="Production database server",
            location="Server Room A"
        )
        self.annotator.annotations["192.168.1.10"] = annotation
        
        # Apply annotations
        annotated_devices = self.annotator.apply_annotations(devices)
        
        # Verify report data structure
        self.assertEqual(len(annotated_devices), 2)
        
        # Check critical device
        db_server = next(d for d in annotated_devices if d['ip'] == '192.168.1.10')
        self.assertTrue(db_server['critical'])
        self.assertEqual(db_server['notes'], "Production database server")
        self.assertEqual(db_server['location'], "Server Room A")
        
        # Verify stats
        stats = self.annotator.get_annotation_stats()
        self.assertEqual(stats['total'], 1)
        self.assertEqual(stats['critical'], 1)
        self.assertEqual(stats['with_notes'], 1)
        self.assertEqual(stats['with_location'], 1)
    
    def test_error_handling_integration(self):
        """Test error handling across components."""
        # Test with invalid data
        invalid_data = [
            {"invalid": "data"},  # Missing IP
            {"ip": "not.an.ip"},  # Invalid IP
            {"ip": "192.168.1.1", "open_ports": "not_a_list"}  # Invalid port format
        ]
        
        # Parser should handle gracefully
        devices = self.parser.parse_results(invalid_data, scanner_type="unknown")
        # Should return empty or handle errors
        
        # Classifier should handle gracefully
        try:
            classified = self.classifier.classify_devices([{}])
            # Should not crash
            self.assertIsNotNone(classified)
        except Exception as e:
            self.fail(f"Classifier failed with: {e}")
        
        # Tracker should handle gracefully
        try:
            changes = self.tracker.detect_changes([])
            self.assertIsNotNone(changes)
        except Exception as e:
            self.fail(f"Tracker failed with: {e}")
    
    def test_performance_integration(self):
        """Test performance with large datasets."""
        # Generate large network
        large_network = []
        for i in range(100):
            large_network.append({
                "ip": f"192.168.1.{i+1}",
                "mac": f"00:11:22:33:44:{i:02x}",
                "open_ports": [22, 80] if i % 2 else [445, 3389],
                "type": "server" if i % 3 else "workstation",
                "hostname": f"host-{i+1}"
            })
        
        # Time classification
        start_time = time.time()
        classified = self.classifier.classify_devices(large_network)
        classification_time = time.time() - start_time
        
        # Should complete in reasonable time
        self.assertLess(classification_time, 1.0)
        self.assertEqual(len(classified), 100)
        
        # Time change detection
        start_time = time.time()
        changes = self.tracker.detect_changes(large_network)
        tracking_time = time.time() - start_time
        
        # Should complete quickly
        self.assertLess(tracking_time, 0.5)


class TestVisualizationIntegration(unittest.TestCase):
    """Test integration with visualization components."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        from utils.visualization import MapGenerator
        self.visualizer = MapGenerator()
    
    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_visualization_data_generation(self):
        """Test generating visualization data from scan results."""
        # Create sample network
        devices = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "type": "router",
                "hostname": "gateway"
            },
            {
                "ip": "192.168.1.10",
                "mac": "AA:BB:CC:DD:EE:FF",
                "type": "switch",
                "hostname": "switch01"
            },
            {
                "ip": "192.168.1.20",
                "type": "server",
                "hostname": "webserver"
            },
            {
                "ip": "192.168.1.30",
                "type": "workstation",
                "hostname": "ws01"
            }
        ]
        
        # Generate visualization data
        viz_data = self.visualizer.generate_d3_data(devices)
        
        # Verify structure
        self.assertIn("nodes", viz_data)
        self.assertIn("links", viz_data)
        self.assertEqual(len(viz_data["nodes"]), 4)
        
        # Verify node properties
        for node in viz_data["nodes"]:
            self.assertIn("id", node)
            self.assertIn("name", node)
            self.assertIn("type", node)
            self.assertIn("group", node)
        
        # Verify links exist (router should connect to switch, etc)
        self.assertGreater(len(viz_data["links"]), 0)
        
        # Verify link properties  
        for link in viz_data["links"]:
            self.assertIn("source", link)
            self.assertIn("target", link)


class TestEndToEndScenarios(unittest.TestCase):
    """Test realistic end-to-end scenarios."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.scanner = NetworkScanner()
        self.parser = ScanParser()
        self.classifier = DeviceClassifier()
        self.tracker = ChangeTracker(output_path=Path(self.temp_dir))
        self.annotator = DeviceAnnotator(output_path=Path(self.temp_dir))
    
    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_new_device_detection_scenario(self):
        """Test scenario: New device appears on network."""
        # Initial network state
        initial_network = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "type": "router",
                "hostname": "gateway"
            },
            {
                "ip": "192.168.1.10",
                "mac": "AA:BB:CC:DD:EE:FF",
                "type": "server",
                "hostname": "server01"
            }
        ]
        
        # Save initial scan
        self.tracker.scans_path.mkdir(parents=True, exist_ok=True)
        scan_file = self.tracker.scans_path / "scan_20230101_120000.json"
        with open(scan_file, 'w') as f:
            json.dump(initial_network, f)
        
        # New device appears
        updated_network = initial_network + [
            {
                "ip": "192.168.1.50",
                "mac": "11:22:33:44:55:66",
                "type": "unknown",
                "hostname": ""
            }
        ]
        
        # Detect changes
        with patch.object(self.tracker, '_get_previous_scan') as mock_prev:
            mock_prev.return_value = (initial_network, "2023-01-01T12:00:00")
            changes = self.tracker.detect_changes(updated_network)
        
        # Verify new device detected
        self.assertEqual(len(changes['new_devices']), 1)
        self.assertEqual(changes['new_devices'][0]['ip'], "192.168.1.50")
        
        # Classify new device
        classified = self.classifier.classify_devices([changes['new_devices'][0]])
        # Even unknown devices should be classified
        self.assertEqual(len(classified), 1)
    
    def test_service_change_scenario(self):
        """Test scenario: Critical service change detection."""
        # Server with database
        server = {
            "ip": "192.168.1.100",
            "mac": "AA:BB:CC:DD:EE:FF",
            "type": "database",
            "hostname": "db-prod",
            "open_ports": [22, 3306],
            "services": ["ssh:22", "mysql:3306"]
        }
        
        # Mark as critical
        annotation = DeviceAnnotation(
            ip="192.168.1.100",
            critical=True,
            notes="Production database - monitor closely"
        )
        self.annotator.annotations["192.168.1.100"] = annotation
        
        # Save initial state
        self.tracker.scans_path.mkdir(parents=True, exist_ok=True)
        scan_file = self.tracker.scans_path / "scan_20230101_120000.json"
        with open(scan_file, 'w') as f:
            json.dump([server], f)
        
        # Database port closes
        server_modified = server.copy()
        server_modified['open_ports'] = [22]
        server_modified['services'] = ["ssh:22"]
        
        # Detect changes
        with patch.object(self.tracker, '_get_previous_scan') as mock_prev:
            mock_prev.return_value = ([server], "2023-01-01T12:00:00")
            changes = self.tracker.detect_changes([server_modified])
        
        # Verify critical change detected
        self.assertEqual(len(changes['changed_devices']), 1)
        changed_device = changes['changed_devices'][0]
        self.assertEqual(changed_device['ip'], "192.168.1.100")
        
        # Check for port change
        port_changes = [c for c in changed_device['changes'] if c['field'] == 'ports']
        self.assertGreater(len(port_changes), 0)
        
        # Apply annotation to verify criticality
        annotated = self.annotator.apply_annotations([server_modified])
        self.assertTrue(annotated[0]['critical'])
    
    def test_network_growth_scenario(self):
        """Test scenario: Network growth over time."""
        # Week 1: Small network
        week1_network = [
            {"ip": f"192.168.1.{i}", "type": "workstation"} 
            for i in range(1, 11)
        ]
        
        # Save scan
        self.tracker.scans_path.mkdir(parents=True, exist_ok=True)
        scan_file = self.tracker.scans_path / "scan_week1.json"
        with open(scan_file, 'w') as f:
            json.dump(week1_network, f)
        
        # Week 2: Network grows
        week2_network = [
            {"ip": f"192.168.1.{i}", "type": "workstation"} 
            for i in range(1, 21)
        ]
        
        # Detect growth
        with patch.object(self.tracker, '_get_previous_scan') as mock_prev:
            mock_prev.return_value = (week1_network, "2023-01-01T12:00:00")
            changes = self.tracker.detect_changes(week2_network)
        
        # Verify growth detected
        self.assertEqual(len(changes['new_devices']), 10)
        
        # Get stats
        growth_rate = len(changes['new_devices']) / len(week1_network) * 100
        self.assertEqual(growth_rate, 100.0)  # 100% growth


if __name__ == '__main__':
    unittest.main()