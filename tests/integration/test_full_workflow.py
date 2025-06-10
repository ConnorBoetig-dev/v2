"""Integration tests for the complete NetworkMapper workflow."""

import json
import logging
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

# Import all core modules
from core.scanner import NetworkScanner
from core.parser import ScanParser, Device
from core.classifier import DeviceClassifier
from core.tracker import ChangeTracker
from core.annotator import DeviceAnnotator


class TestFullScanWorkflow(unittest.TestCase):
    """Test the complete scan workflow from scanning to annotation."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.scanner = NetworkScanner()
        self.parser = ScanParser()
        self.classifier = DeviceClassifier()
        self.tracker = ChangeTracker(base_dir=self.temp_dir)
        self.annotator = DeviceAnnotator(base_dir=self.temp_dir)
        
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
        
        # Mock nmap process output
        nmap_output = [
            "Starting Nmap",
            "Nmap scan report for gateway.local (192.168.1.1)",
            "Host is up",
            "MAC Address: 00:11:22:33:44:55 (Cisco Systems)",
            "Nmap scan report for server.local (192.168.1.10)",
            "Host is up",
            "MAC Address: AA:BB:CC:DD:EE:FF (Dell Inc.)",
            "Nmap scan report for 192.168.1.20",
            "Host is up",
            "Nmap done: 256 IP addresses (3 hosts up) scanned",
            ""
        ]
        
        mock_proc = MagicMock()
        mock_proc.poll.side_effect = [None] * (len(nmap_output) - 1) + [0]
        mock_proc.returncode = 0
        mock_proc.stdout.readline.side_effect = nmap_output
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
                    
                    # Step 2: Parse and normalize
                    devices = self.parser.normalize_scan_results(scan_results)
                    self.assertEqual(len(devices), 3)
                    
                    # Step 3: Classify devices
                    for device in devices:
                        device_dict = device.asdict() if hasattr(device, 'asdict') else device
                        device_type, confidence = self.classifier.classify_device(device_dict)
                        device_dict['type'] = device_type
                        device_dict['classification_confidence'] = confidence
                    
                    # Step 4: Track changes (first scan, all should be new)
                    changes = self.tracker.track_changes(
                        [d.asdict() if hasattr(d, 'asdict') else d for d in devices]
                    )
                    
                    new_devices = [c for c in changes if c.type == "new"]
                    self.assertEqual(len(new_devices), 3)
                    
                    # Step 5: Add annotations
                    gateway = next(d for d in devices if "192.168.1.1" in str(d))
                    success = self.annotator.add_annotation(
                        gateway.asdict() if hasattr(gateway, 'asdict') else gateway,
                        name="Main Gateway",
                        criticality="high",
                        location="Server Room"
                    )
                    self.assertTrue(success)
    
    def test_inventory_scan_with_classification(self):
        """Test inventory scan with full device classification."""
        # Mock scan data with service information
        mock_scan_data = [
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
                "ip": "192.168.1.10",
                "mac": "AA:BB:CC:DD:EE:FF",
                "hostname": "webserver.local",
                "open_ports": [22, 80, 443, 3306],
                "services": ["ssh:22", "http:80", "https:443", "mysql:3306"],
                "os": "Ubuntu 20.04",
                "vendor": "Dell Inc."
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
        
        # Parse and classify
        devices = self.parser.normalize_scan_results(mock_scan_data)
        classified_devices = []
        
        for device in devices:
            device_dict = device.asdict() if hasattr(device, 'asdict') else device
            device_type, confidence = self.classifier.classify_device(device_dict)
            device_dict['type'] = device_type
            device_dict['classification_confidence'] = confidence
            classified_devices.append(device_dict)
        
        # Verify classifications
        router = next(d for d in classified_devices if d['ip'] == '192.168.1.1')
        self.assertEqual(router['type'], 'router')
        self.assertGreater(router['classification_confidence'], 0.7)
        
        server = next(d for d in classified_devices if d['ip'] == '192.168.1.10')
        self.assertEqual(server['type'], 'server')
        self.assertGreater(server['classification_confidence'], 0.7)
        
        printer = next(d for d in classified_devices if d['ip'] == '192.168.1.20')
        self.assertEqual(printer['type'], 'printer')
        self.assertGreater(printer['classification_confidence'], 0.7)
    
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
        
        # Track initial state
        changes1 = self.tracker.track_changes(initial_devices)
        self.assertEqual(len(changes1), 2)
        self.assertTrue(all(c.type == "new" for c in changes1))
        
        # Second scan - modifications and new device
        second_devices = [
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
        
        # Track changes
        changes2 = self.tracker.track_changes(second_devices)
        
        # Verify changes
        new_changes = [c for c in changes2 if c.type == "new"]
        modified_changes = [c for c in changes2 if c.type == "modified"]
        
        self.assertEqual(len(new_changes), 1)
        self.assertEqual(new_changes[0].device_ip, "192.168.1.20")
        
        self.assertEqual(len(modified_changes), 1)
        self.assertEqual(modified_changes[0].device_ip, "192.168.1.1")
        self.assertIn("ports_added", modified_changes[0].details)
        self.assertEqual(modified_changes[0].details["ports_added"], [443])
        
        # Third scan - device offline
        third_devices = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "open_ports": [22, 80, 443],
                "type": "router"
            },
            {
                "ip": "192.168.1.20",
                "mac": "11:22:33:44:55:66",
                "open_ports": [445],
                "type": "workstation"
            }
        ]
        
        changes3 = self.tracker.track_changes(third_devices)
        
        missing_changes = [c for c in changes3 if c.type == "missing"]
        self.assertEqual(len(missing_changes), 1)
        self.assertEqual(missing_changes[0].device_ip, "192.168.1.10")
    
    def test_annotation_integration(self):
        """Test annotation integration with device data."""
        # Create devices
        devices = [
            Device(
                ip="192.168.1.1",
                mac="00:11:22:33:44:55",
                hostname="gateway",
                type="router",
                vendor="Cisco"
            ),
            Device(
                ip="192.168.1.10",
                mac="AA:BB:CC:DD:EE:FF",
                hostname="webserver",
                type="server",
                os="Ubuntu 20.04"
            ),
            Device(
                ip="192.168.1.20",
                hostname="workstation01",
                type="workstation",
                os="Windows 10"
            )
        ]
        
        # Add annotations
        self.annotator.add_annotation(
            devices[0].asdict(),
            name="Main Gateway Router",
            criticality="critical",
            location="Server Room A",
            owner="Network Team",
            tags=["production", "critical-infrastructure"]
        )
        
        self.annotator.add_annotation(
            devices[1].asdict(),
            name="Production Web Server",
            criticality="high",
            location="Server Room B",
            owner="Web Team",
            tags=["production", "web-tier"],
            custom_fields={"backup_schedule": "daily", "sla": "99.9%"}
        )
        
        self.annotator.add_annotation(
            devices[2].asdict(),
            name="Developer Workstation",
            criticality="low",
            owner="John Doe",
            tags=["development"]
        )
        
        # Merge annotations with devices
        device_dicts = [d.asdict() for d in devices]
        annotated_devices = self.annotator.merge_with_devices(device_dicts)
        
        # Verify merged data
        self.assertEqual(len(annotated_devices), 3)
        
        gateway = next(d for d in annotated_devices if d["ip"] == "192.168.1.1")
        self.assertIn("annotation", gateway)
        self.assertEqual(gateway["annotation"]["criticality"], "critical")
        self.assertIn("critical-infrastructure", gateway["annotation"]["tags"])
        
        server = next(d for d in annotated_devices if d["ip"] == "192.168.1.10")
        self.assertEqual(server["annotation"]["custom_fields"]["sla"], "99.9%")
    
    def test_report_generation_workflow(self):
        """Test complete report generation workflow."""
        # Simulate complete scan data
        scan_timestamp = datetime.now()
        devices = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "hostname": "gateway",
                "type": "router",
                "open_ports": [22, 80, 443],
                "services": ["ssh:22", "http:80", "https:443"],
                "os": "RouterOS",
                "classification_confidence": 0.95
            },
            {
                "ip": "192.168.1.10",
                "mac": "AA:BB:CC:DD:EE:FF",
                "hostname": "server01",
                "type": "server",
                "open_ports": [22, 80, 443, 3306],
                "services": ["ssh:22", "http:80", "https:443", "mysql:3306"],
                "os": "Ubuntu 20.04",
                "classification_confidence": 0.88
            },
            {
                "ip": "192.168.1.20",
                "hostname": "ws01",
                "type": "workstation",
                "open_ports": [3389],
                "services": ["ms-wbt-server:3389"],
                "os": "Windows 10",
                "classification_confidence": 0.92
            }
        ]
        
        # Add annotations
        self.annotator.add_annotation(
            devices[0],
            name="Main Gateway",
            criticality="critical",
            location="Server Room"
        )
        
        # Track changes
        self.tracker.track_changes(devices, scan_type="inventory")
        
        # Generate statistics
        stats = self.parser.get_statistics(
            [Device(**d) if not isinstance(d, Device) else d for d in devices]
        )
        
        # Generate change report
        change_report = self.tracker.generate_change_report(hours=24)
        
        # Create complete report structure
        complete_report = {
            "scan_info": {
                "timestamp": scan_timestamp.isoformat(),
                "type": "inventory",
                "target": "192.168.1.0/24",
                "total_devices": len(devices)
            },
            "devices": devices,
            "statistics": stats,
            "changes": change_report,
            "annotations_summary": self.annotator.get_statistics()
        }
        
        # Verify report structure
        self.assertIn("scan_info", complete_report)
        self.assertIn("devices", complete_report)
        self.assertIn("statistics", complete_report)
        self.assertIn("changes", complete_report)
        self.assertIn("annotations_summary", complete_report)
        
        # Verify statistics
        self.assertEqual(complete_report["statistics"]["total_devices"], 3)
        self.assertEqual(complete_report["statistics"]["device_types"]["router"], 1)
        self.assertEqual(complete_report["statistics"]["device_types"]["server"], 1)
        self.assertEqual(complete_report["statistics"]["device_types"]["workstation"], 1)
    
    def test_error_handling_integration(self):
        """Test error handling across the workflow."""
        # Test with invalid scan data
        invalid_data = [
            {"no_ip": "invalid"},
            {"ip": None},
            {"ip": "192.168.1.1", "open_ports": "not_a_list"}
        ]
        
        # Parser should handle gracefully
        devices = self.parser.normalize_scan_results(invalid_data)
        self.assertEqual(len(devices), 0)
        
        # Classifier should handle empty data
        device_type, confidence = self.classifier.classify_device({})
        self.assertEqual(device_type, "unknown")
        self.assertEqual(confidence, 0.0)
        
        # Tracker should handle invalid devices
        changes = self.tracker.track_changes(invalid_data)
        self.assertEqual(len(changes), 0)
        
        # Annotator should reject invalid devices
        success = self.annotator.add_annotation(
            {"no_ip": "invalid"},
            name="Test"
        )
        self.assertFalse(success)
    
    def test_performance_integration(self):
        """Test performance with realistic network sizes."""
        import time
        
        # Generate 500 devices
        large_network = []
        for i in range(500):
            device = {
                "ip": f"10.{i // 256}.{i % 256}.1",
                "mac": f"00:11:22:{i // 256:02x}:{i % 256:02x}:01",
                "hostname": f"host-{i:03d}",
                "open_ports": [22, 80] if i % 2 else [3389],
                "services": ["ssh:22", "http:80"] if i % 2 else ["rdp:3389"],
                "os": "Linux" if i % 2 else "Windows",
                "vendor": ["Dell", "HP", "Cisco", "Apple"][i % 4]
            }
            large_network.append(device)
        
        # Time the complete workflow
        start_time = time.time()
        
        # Parse
        devices = self.parser.normalize_scan_results(large_network)
        
        # Classify
        for device in devices:
            device_dict = device.asdict() if hasattr(device, 'asdict') else device
            device_type, confidence = self.classifier.classify_device(device_dict)
            device_dict['type'] = device_type
        
        # Track changes
        device_dicts = [d.asdict() if hasattr(d, 'asdict') else d for d in devices]
        changes = self.tracker.track_changes(device_dicts)
        
        # Add some annotations
        for i in range(50):  # Annotate 10% of devices
            self.annotator.add_annotation(
                device_dicts[i],
                name=f"Annotated Device {i}",
                criticality="high" if i < 25 else "medium"
            )
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Should complete in reasonable time
        self.assertLess(total_time, 10.0)  # 10 seconds for 500 devices
        
        # Verify results
        self.assertEqual(len(devices), 500)
        self.assertEqual(len(changes), 500)  # All new on first scan
        self.assertEqual(len(self.annotator.get_all_annotations()), 50)


class TestVisualizationIntegration(unittest.TestCase):
    """Test integration with visualization components."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        from utils.visualization import NetworkVisualizer
        self.visualizer = NetworkVisualizer()
    
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
        viz_data = self.visualizer.generate_network_topology(devices)
        
        # Verify structure
        self.assertIn("nodes", viz_data)
        self.assertIn("links", viz_data)
        self.assertEqual(len(viz_data["nodes"]), 4)
        
        # Verify node properties
        for node in viz_data["nodes"]:
            self.assertIn("id", node)
            self.assertIn("label", node)
            self.assertIn("type", node)
            self.assertIn("group", node)
        
        # Verify links exist (router should connect to switch, etc)
        self.assertGreater(len(viz_data["links"]), 0)
        
        # Verify link properties
        for link in viz_data["links"]:
            self.assertIn("source", link)
            self.assertIn("target", link)
            self.assertIn("type", link)


class TestEndToEndScenarios(unittest.TestCase):
    """Test realistic end-to-end scenarios."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.scanner = NetworkScanner()
        self.parser = ScanParser()
        self.classifier = DeviceClassifier()
        self.tracker = ChangeTracker(base_dir=self.temp_dir)
        self.annotator = DeviceAnnotator(base_dir=self.temp_dir)
    
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
        
        # Track initial state
        self.tracker.track_changes(initial_network)
        
        # New device appears
        updated_network = initial_network + [
            {
                "ip": "192.168.1.100",
                "mac": "11:22:33:44:55:66",
                "type": "unknown",
                "hostname": ""
            }
        ]
        
        # Track changes
        changes = self.tracker.track_changes(updated_network)
        
        # Should detect new device
        new_device_changes = [c for c in changes if c.type == "new"]
        self.assertEqual(len(new_device_changes), 1)
        self.assertEqual(new_device_changes[0].device_ip, "192.168.1.100")
        
        # Classify the new device
        new_device = updated_network[-1]
        new_device["open_ports"] = [22, 80]  # Simulate discovered ports
        device_type, confidence = self.classifier.classify_device(new_device)
        
        # Auto-annotate suspicious device
        if device_type == "unknown" or confidence < 0.5:
            self.annotator.add_annotation(
                new_device,
                name="Unidentified Device",
                criticality="high",
                tags=["suspicious", "requires-investigation"],
                description="New device detected with unknown type"
            )
        
        # Verify annotation
        annotation = self.annotator.get_annotation(new_device)
        self.assertIsNotNone(annotation)
        self.assertIn("suspicious", annotation.tags)
    
    def test_service_change_scenario(self):
        """Test scenario: Critical service goes offline."""
        # Web server with services
        web_server = {
            "ip": "192.168.1.10",
            "mac": "AA:BB:CC:DD:EE:FF",
            "type": "server",
            "hostname": "webserver",
            "open_ports": [22, 80, 443, 3306],
            "services": ["ssh:22", "http:80", "https:443", "mysql:3306"]
        }
        
        # Annotate as critical
        self.annotator.add_annotation(
            web_server,
            name="Production Web Server",
            criticality="critical",
            tags=["production", "web-tier"],
            owner="Web Team"
        )
        
        # Initial scan
        self.tracker.track_changes([web_server])
        
        # Service goes down (port 80 closes)
        updated_server = web_server.copy()
        updated_server["open_ports"] = [22, 443, 3306]  # No port 80
        updated_server["services"] = ["ssh:22", "https:443", "mysql:3306"]
        
        # Track changes
        changes = self.tracker.track_changes([updated_server])
        
        # Should detect port removal
        modified_changes = [c for c in changes if c.type == "modified"]
        self.assertEqual(len(modified_changes), 1)
        self.assertIn("ports_removed", modified_changes[0].details)
        self.assertIn(80, modified_changes[0].details["ports_removed"])
        
        # Check if critical service affected
        annotation = self.annotator.get_annotation(updated_server)
        if annotation and annotation.criticality in ["high", "critical"]:
            # This would trigger an alert in real system
            alert = {
                "severity": "critical",
                "device": annotation.name,
                "message": f"Critical service down: HTTP (port 80) on {annotation.name}",
                "timestamp": datetime.now().isoformat()
            }
            self.assertIn("HTTP", alert["message"])
    
    def test_network_growth_scenario(self):
        """Test scenario: Network grows over time."""
        # Initial small network
        week1_network = [
            {"ip": f"192.168.1.{i}", "type": "workstation"}
            for i in range(1, 11)
        ]
        
        # Week 1
        self.tracker.track_changes(week1_network)
        stats1 = self.parser.get_statistics(
            [Device(**d) for d in week1_network]
        )
        
        # Week 2 - Network grows
        week2_network = week1_network + [
            {"ip": f"192.168.1.{i}", "type": "workstation"}
            for i in range(11, 21)
        ]
        
        changes2 = self.tracker.track_changes(week2_network)
        new_devices_week2 = [c for c in changes2 if c.type == "new"]
        self.assertEqual(len(new_devices_week2), 10)
        
        # Week 3 - Add servers
        week3_network = week2_network + [
            {"ip": f"192.168.1.{i}", "type": "server", "open_ports": [22, 80]}
            for i in range(100, 103)
        ]
        
        changes3 = self.tracker.track_changes(week3_network)
        new_devices_week3 = [c for c in changes3 if c.type == "new"]
        self.assertEqual(len(new_devices_week3), 3)
        
        # Generate growth report
        all_changes = self.tracker.get_recent_changes(hours=24*21)  # 3 weeks
        growth_report = {
            "total_devices": len(week3_network),
            "growth_rate": (len(week3_network) - len(week1_network)) / len(week1_network) * 100,
            "device_types": self.parser.get_statistics([Device(**d) for d in week3_network])["device_types"]
        }
        
        self.assertEqual(growth_report["total_devices"], 23)
        self.assertEqual(growth_report["growth_rate"], 130.0)  # 130% growth
        self.assertEqual(growth_report["device_types"]["workstation"], 20)
        self.assertEqual(growth_report["device_types"]["server"], 3)


if __name__ == '__main__':
    unittest.main()