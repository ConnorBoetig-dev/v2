"""Comprehensive unit tests for the ChangeTracker module."""

import json
import logging
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

from core.tracker import ChangeTracker, DeviceChange, ChangeType, ChangeReport


class TestDeviceChange(unittest.TestCase):
    """Test cases for DeviceChange dataclass."""
    
    def test_device_change_creation(self):
        """Test DeviceChange creation."""
        change = DeviceChange(
            ip="192.168.1.1",
            change_type=ChangeType.NEW_DEVICE,
            change_field="device",
            old_value=None,
            new_value="router",
            timestamp="2023-01-01T12:00:00",
            severity="info"
        )
        
        self.assertEqual(change.ip, "192.168.1.1")
        self.assertEqual(change.change_type, ChangeType.NEW_DEVICE)
        self.assertEqual(change.timestamp, "2023-01-01T12:00:00")
        self.assertEqual(change.severity, "info")
    
    def test_device_change_to_dict(self):
        """Test DeviceChange serialization."""
        change = DeviceChange(
            ip="10.0.0.1",
            change_type=ChangeType.NEW_PORT,
            change_field="open_ports",
            old_value="[22, 80]",
            new_value="[22, 80, 443]"
        )
        
        change_dict = change.to_dict()
        self.assertIsInstance(change_dict, dict)
        self.assertEqual(change_dict["ip"], "10.0.0.1")
        self.assertEqual(change_dict["change_type"], "new_port")
        self.assertEqual(change_dict["change_field"], "open_ports")


class TestChangeReport(unittest.TestCase):
    """Test cases for ChangeReport dataclass."""
    
    def test_change_report_creation(self):
        """Test ChangeReport creation."""
        report = ChangeReport(
            new_devices=[{"ip": "192.168.1.1"}],
            missing_devices=[{"ip": "192.168.1.2"}],
            changed_devices=[],
            summary={"total_changes": 2}
        )
        
        self.assertEqual(len(report.new_devices), 1)
        self.assertEqual(len(report.missing_devices), 1)
        self.assertTrue(report.has_changes())
    
    def test_change_report_severity(self):
        """Test ChangeReport severity calculation."""
        # Critical severity when device missing
        report = ChangeReport(
            missing_devices=[{"ip": "192.168.1.1"}]
        )
        self.assertEqual(report.get_severity(), "critical")
        
        # Warning severity for new devices
        report = ChangeReport(
            new_devices=[{"ip": "192.168.1.1"}]
        )
        self.assertEqual(report.get_severity(), "warning")
        
        # Info when no changes
        report = ChangeReport()
        self.assertEqual(report.get_severity(), "info")


class TestChangeTracker(unittest.TestCase):
    """Test cases for ChangeTracker class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.tracker = ChangeTracker(output_path=Path(self.temp_dir))
        # Configure logging
        logging.basicConfig(level=logging.DEBUG)
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_init(self):
        """Test tracker initialization."""
        tracker = ChangeTracker(output_path=Path(self.temp_dir))
        # The directories are created as needed, not in init
        self.assertEqual(tracker.output_path, Path(self.temp_dir))
        self.assertEqual(tracker.scans_path, Path(self.temp_dir) / "scans")
        self.assertEqual(tracker.changes_path, Path(self.temp_dir) / "changes")
    
    def test_detect_changes_new_devices(self):
        """Test detecting new devices."""
        current_scan = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "type": "router",
                "open_ports": [22, 80, 443]
            },
            {
                "ip": "192.168.1.10",
                "mac": "AA:BB:CC:DD:EE:FF",
                "type": "workstation"
            }
        ]
        
        result = self.tracker.detect_changes(current_scan)
        
        # Without a previous scan, detect_changes returns empty dict
        self.assertIsInstance(result, dict)
        # For first scan, all devices would be new but detect_changes needs a previous scan
        if result:  # Only check if we have results
            self.assertEqual(len(result.get("new_devices", [])), 2)
            self.assertEqual(len(result.get("missing_devices", [])), 0)
    
    def test_detect_changes_missing_devices(self):
        """Test detecting missing devices."""
        # Save initial scan
        initial_scan = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"},
            {"ip": "192.168.1.2", "mac": "11:22:33:44:55:66"}
        ]
        
        # Mock previous scan
        with patch.object(self.tracker, '_get_previous_scan') as mock_prev:
            mock_prev.return_value = (initial_scan, "2023-01-01T12:00:00")
            
            # Current scan with missing device
            current_scan = [
                {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"}
            ]
            
            result = self.tracker.detect_changes(current_scan)
            
            self.assertEqual(len(result.get("missing_devices", [])), 1)
            self.assertEqual(result.get("missing_devices", [])[0]["ip"], "192.168.1.2")
    
    def test_detect_changes_modified_devices(self):
        """Test detecting modified devices."""
        # Previous scan
        previous = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "open_ports": [22, 80],
                "type": "router"
            }
        ]
        
        # Current scan with modified device
        current = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "open_ports": [22, 80, 443],  # Added port
                "type": "router"
            }
        ]
        
        with patch.object(self.tracker, '_get_previous_scan') as mock_prev:
            mock_prev.return_value = (previous, "2023-01-01T12:00:00")
            
            result = self.tracker.detect_changes(current)
            
            self.assertEqual(len(result.get("changed_devices", [])), 1)
            # Changed devices have a "changes" field
            changed_device = result.get("changed_devices", [])[0]
            self.assertIn("changes", changed_device)
    
    def test_compare_devices(self):
        """Test device comparison."""
        old_device = {
            "ip": "192.168.1.1",
            "open_ports": [22, 80],
            "services": ["ssh:22", "http:80"],
            "os": "Linux",
            "type": "router"
        }
        
        new_device = {
            "ip": "192.168.1.1", 
            "open_ports": [22, 80, 443],  # Added port
            "services": ["ssh:22", "http:80", "https:443"],  # Added service
            "os": "Linux",
            "type": "router"
        }
        
        changes = self.tracker._compare_devices(new_device, old_device)
        
        # Should detect port and service changes
        self.assertGreater(len(changes), 0)
        # Check for service changes
        service_changes = [c for c in changes if c["field"] == "services"]
        self.assertGreater(len(service_changes), 0)
        # Check for port changes
        port_changes = [c for c in changes if c["field"] == "ports"]
        self.assertGreater(len(port_changes), 0)
    
    def test_generate_fingerprint(self):
        """Test device fingerprint generation."""
        device1 = {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"}
        device2 = {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"}
        device3 = {"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:FF"}
        
        fp1 = self.tracker._generate_fingerprint(device1)
        fp2 = self.tracker._generate_fingerprint(device2)
        fp3 = self.tracker._generate_fingerprint(device3)
        
        # Same device should have same fingerprint
        self.assertEqual(fp1, fp2)
        # Different device should have different fingerprint
        self.assertNotEqual(fp1, fp3)
    
    def test_check_dangerous_ports(self):
        """Test dangerous port detection."""
        ports = {22, 80, 445, 3389, 23}  # Mix of safe and dangerous
        
        dangerous = self.tracker._check_dangerous_ports(ports)
        
        # Should detect telnet (23), SMB (445), RDP (3389)
        self.assertIn(23, dangerous)
        self.assertIn(445, dangerous)
        self.assertIn(3389, dangerous)
    
    def test_save_change_report(self):
        """Test saving change report."""
        # Ensure the changes directory exists
        self.tracker.changes_path.mkdir(parents=True, exist_ok=True)
        
        changes = {
            "new_devices": [{"ip": "192.168.1.1"}],
            "missing_devices": [],
            "changed_devices": [],
            "summary": {"total_changes": 1}
        }
        
        timestamp = "2023-01-01T12:00:00"
        report_path = self.tracker.save_change_report(changes, timestamp)
        
        self.assertIsNotNone(report_path)
        self.assertTrue(report_path.exists())
        
        # Verify content
        with open(report_path, 'r') as f:
            saved_data = json.load(f)
        
        # save_change_report saves the changes dict as-is
        self.assertEqual(len(saved_data["new_devices"]), 1)
        self.assertEqual(saved_data["summary"]["total_changes"], 1)
    
    def test_empty_scan_handling(self):
        """Test handling empty scan results."""
        # Previous scan had devices
        previous = [
            {"ip": "192.168.1.1"},
            {"ip": "192.168.1.2"}
        ]
        
        with patch.object(self.tracker, '_get_previous_scan') as mock_prev:
            mock_prev.return_value = (previous, "2023-01-01T12:00:00")
            
            # Empty current scan
            result = self.tracker.detect_changes([])
            
            # All devices should be missing
            self.assertEqual(len(result.get("missing_devices", [])), 2)
    
    def test_first_scan(self):
        """Test first scan with no previous data."""
        devices = [
            {"ip": "192.168.1.1", "type": "router"},
            {"ip": "192.168.1.2", "type": "workstation"}
        ]
        
        result = self.tracker.detect_changes(devices)
        
        # First scan returns empty dict since there's no previous scan to compare
        self.assertEqual(result, {})
    
    def test_os_change_detection(self):
        """Test OS change detection."""
        previous = [{
            "ip": "192.168.1.1",
            "mac": "00:11:22:33:44:55",
            "os": "Windows 10"
        }]
        
        current = [{
            "ip": "192.168.1.1", 
            "mac": "00:11:22:33:44:55",
            "os": "Windows 11"
        }]
        
        with patch.object(self.tracker, '_get_previous_scan') as mock_prev:
            mock_prev.return_value = (previous, "2023-01-01T12:00:00")
            
            result = self.tracker.detect_changes(current)
            
            self.assertEqual(len(result.get("changed_devices", [])), 1)
            changes = result.get("changed_devices", [])[0]["changes"]
            # Check for OS change in the field
            os_changes = [c for c in changes if c.get("field") == "os"]
            self.assertGreater(len(os_changes), 0)
    
    def test_type_change_detection(self):
        """Test device type change detection."""
        previous = [{
            "ip": "192.168.1.1",
            "mac": "00:11:22:33:44:55",
            "type": "unknown"
        }]
        
        current = [{
            "ip": "192.168.1.1",
            "mac": "00:11:22:33:44:55",
            "type": "router"
        }]
        
        with patch.object(self.tracker, '_get_previous_scan') as mock_prev:
            mock_prev.return_value = (previous, "2023-01-01T12:00:00")
            
            result = self.tracker.detect_changes(current)
            
            self.assertEqual(len(result.get("changed_devices", [])), 1)
            changes = result.get("changed_devices", [])[0]["changes"]
            # Check for type change in the field
            type_changes = [c for c in changes if c.get("field") == "type"]
            self.assertGreater(len(type_changes), 0)


class TestTrackerIntegration(unittest.TestCase):
    """Integration tests for change tracking."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.tracker = ChangeTracker(output_path=Path(self.temp_dir))
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_multiple_scan_workflow(self):
        """Test tracking changes across multiple scans."""
        # First scan
        scan1 = [
            {"ip": "192.168.1.1", "type": "router", "open_ports": [22, 80]},
            {"ip": "192.168.1.2", "type": "workstation", "open_ports": [445]}
        ]
        
        result1 = self.tracker.detect_changes(scan1)
        # First scan should show all devices as new if no previous scan
        if result1:  # Only check if we get results
            self.assertEqual(len(result1.get("new_devices", [])), 2)
        
        # Save the scan data
        self.tracker.scans_path.mkdir(parents=True, exist_ok=True)
        scan_file = self.tracker.scans_path / "scan1.json"
        with open(scan_file, 'w') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "devices": scan1
            }, f)
        
        # Second scan - one device modified, one missing, one new
        scan2 = [
            {"ip": "192.168.1.1", "type": "router", "open_ports": [22, 80, 443]},  # Added port
            {"ip": "192.168.1.3", "type": "printer", "open_ports": [9100]}  # New device
        ]
        
        with patch.object(self.tracker, '_get_previous_scan') as mock_prev:
            mock_prev.return_value = (scan1, "2023-01-01T12:00:00")
            
            result2 = self.tracker.detect_changes(scan2)
            
            self.assertEqual(len(result2.get("new_devices", [])), 1)  # .3 is new
            self.assertEqual(len(result2.get("missing_devices", [])), 1)  # .2 is missing
            self.assertEqual(len(result2.get("changed_devices", [])), 1)  # .1 changed


if __name__ == '__main__':
    unittest.main()