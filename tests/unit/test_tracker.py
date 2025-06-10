"""Comprehensive unit tests for the ChangeTracker module."""

import json
import logging
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

from core.tracker import ChangeTracker, DeviceChange, NetworkSnapshot


class TestDeviceChange(unittest.TestCase):
    """Test cases for DeviceChange dataclass."""
    
    def test_device_change_creation(self):
        """Test DeviceChange creation."""
        change = DeviceChange(
            type="new",
            device_ip="192.168.1.1",
            timestamp="2023-01-01T12:00:00",
            details={"mac": "00:11:22:33:44:55"}
        )
        
        self.assertEqual(change.type, "new")
        self.assertEqual(change.device_ip, "192.168.1.1")
        self.assertEqual(change.timestamp, "2023-01-01T12:00:00")
        self.assertEqual(change.details["mac"], "00:11:22:33:44:55")
    
    def test_device_change_to_dict(self):
        """Test DeviceChange serialization."""
        change = DeviceChange(
            type="modified",
            device_ip="10.0.0.1",
            timestamp="2023-01-01T12:00:00",
            details={"ports_added": [80, 443]}
        )
        
        change_dict = change.to_dict()
        self.assertIsInstance(change_dict, dict)
        self.assertEqual(change_dict["type"], "modified")
        self.assertEqual(change_dict["device_ip"], "10.0.0.1")
        self.assertIn("ports_added", change_dict["details"])


class TestNetworkSnapshot(unittest.TestCase):
    """Test cases for NetworkSnapshot dataclass."""
    
    def test_network_snapshot_creation(self):
        """Test NetworkSnapshot creation."""
        devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"},
            {"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"}
        ]
        
        snapshot = NetworkSnapshot(
            timestamp="2023-01-01T12:00:00",
            devices=devices,
            total_devices=2,
            scan_type="inventory"
        )
        
        self.assertEqual(snapshot.total_devices, 2)
        self.assertEqual(len(snapshot.devices), 2)
        self.assertEqual(snapshot.scan_type, "inventory")
    
    def test_network_snapshot_to_dict(self):
        """Test NetworkSnapshot serialization."""
        snapshot = NetworkSnapshot(
            timestamp="2023-01-01T12:00:00",
            devices=[{"ip": "10.0.0.1"}],
            total_devices=1,
            scan_type="discovery"
        )
        
        snapshot_dict = snapshot.to_dict()
        self.assertIsInstance(snapshot_dict, dict)
        self.assertEqual(snapshot_dict["total_devices"], 1)
        self.assertEqual(snapshot_dict["scan_type"], "discovery")


class TestChangeTracker(unittest.TestCase):
    """Test cases for ChangeTracker class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.tracker = ChangeTracker(base_dir=self.temp_dir)
        # Configure logging
        logging.basicConfig(level=logging.DEBUG)
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_init(self):
        """Test tracker initialization."""
        tracker = ChangeTracker()
        self.assertIsNotNone(tracker.output_dir)
        self.assertTrue(os.path.exists(tracker.output_dir))
        
        # Test with custom directory
        custom_dir = os.path.join(self.temp_dir, "custom")
        tracker = ChangeTracker(base_dir=custom_dir)
        self.assertTrue(os.path.exists(custom_dir))
    
    def test_track_changes_new_devices(self):
        """Test tracking new devices."""
        # First scan - all devices are new
        current_devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "type": "router"},
            {"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF", "type": "server"}
        ]
        
        changes = self.tracker.track_changes(current_devices, scan_type="discovery")
        
        self.assertEqual(len(changes), 2)
        self.assertTrue(all(c.type == "new" for c in changes))
        self.assertEqual(changes[0].device_ip, "192.168.1.1")
        self.assertEqual(changes[1].device_ip, "192.168.1.10")
    
    def test_track_changes_missing_devices(self):
        """Test tracking missing devices."""
        # First scan
        initial_devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"},
            {"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"}
        ]
        
        self.tracker.track_changes(initial_devices, scan_type="discovery")
        
        # Second scan - one device missing
        current_devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"}
        ]
        
        changes = self.tracker.track_changes(current_devices, scan_type="discovery")
        
        missing_changes = [c for c in changes if c.type == "missing"]
        self.assertEqual(len(missing_changes), 1)
        self.assertEqual(missing_changes[0].device_ip, "192.168.1.10")
    
    def test_track_changes_modified_devices(self):
        """Test tracking modified devices."""
        # First scan
        initial_devices = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "open_ports": [22, 80],
                "services": ["ssh:22", "http:80"],
                "hostname": "router"
            }
        ]
        
        self.tracker.track_changes(initial_devices, scan_type="inventory")
        
        # Second scan - ports changed
        current_devices = [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "open_ports": [22, 80, 443],
                "services": ["ssh:22", "http:80", "https:443"],
                "hostname": "router.local"  # Hostname changed too
            }
        ]
        
        changes = self.tracker.track_changes(current_devices, scan_type="inventory")
        
        modified_changes = [c for c in changes if c.type == "modified"]
        self.assertEqual(len(modified_changes), 1)
        
        details = modified_changes[0].details
        self.assertIn("ports_added", details)
        self.assertEqual(details["ports_added"], [443])
        self.assertIn("services_added", details)
        self.assertIn("hostname_changed", details)
        self.assertEqual(details["hostname_changed"]["old"], "router")
        self.assertEqual(details["hostname_changed"]["new"], "router.local")
    
    def test_track_changes_ports_removed(self):
        """Test tracking removed ports."""
        # First scan
        initial_devices = [
            {
                "ip": "192.168.1.1",
                "open_ports": [22, 80, 443],
                "services": ["ssh:22", "http:80", "https:443"]
            }
        ]
        
        self.tracker.track_changes(initial_devices)
        
        # Second scan - port 80 removed
        current_devices = [
            {
                "ip": "192.168.1.1",
                "open_ports": [22, 443],
                "services": ["ssh:22", "https:443"]
            }
        ]
        
        changes = self.tracker.track_changes(current_devices)
        
        modified_changes = [c for c in changes if c.type == "modified"]
        self.assertEqual(len(modified_changes), 1)
        self.assertIn("ports_removed", modified_changes[0].details)
        self.assertEqual(modified_changes[0].details["ports_removed"], [80])
    
    def test_detect_changes_complex(self):
        """Test complex change detection scenarios."""
        old_device = {
            "ip": "192.168.1.1",
            "mac": "00:11:22:33:44:55",
            "hostname": "server",
            "os": "Ubuntu 18.04",
            "open_ports": [22, 80, 3306],
            "services": ["ssh:22", "http:80", "mysql:3306"],
            "vendor": "Dell"
        }
        
        new_device = {
            "ip": "192.168.1.1",
            "mac": "00:11:22:33:44:55",
            "hostname": "server.example.com",  # Changed
            "os": "Ubuntu 20.04",  # Changed
            "open_ports": [22, 443, 3306, 5432],  # 80 removed, 443 and 5432 added
            "services": ["ssh:22", "https:443", "mysql:3306", "postgresql:5432"],
            "vendor": "Dell"
        }
        
        changes = self.tracker._detect_changes(old_device, new_device)
        
        self.assertIn("hostname_changed", changes)
        self.assertIn("os_changed", changes)
        self.assertIn("ports_added", changes)
        self.assertIn("ports_removed", changes)
        self.assertEqual(set(changes["ports_added"]), {443, 5432})
        self.assertEqual(changes["ports_removed"], [80])
    
    def test_get_device_history(self):
        """Test retrieving device history."""
        # Multiple scans of the same device
        device_scans = [
            {"ip": "192.168.1.1", "open_ports": [22]},
            {"ip": "192.168.1.1", "open_ports": [22, 80]},
            {"ip": "192.168.1.1", "open_ports": [22, 80, 443]}
        ]
        
        for device in device_scans:
            self.tracker.track_changes([device])
        
        history = self.tracker.get_device_history("192.168.1.1")
        
        self.assertGreater(len(history), 0)
        # Should show progression of ports being added
        port_counts = [len(h.get("open_ports", [])) for h in history]
        self.assertEqual(port_counts, [1, 2, 3])
    
    def test_get_recent_changes(self):
        """Test retrieving recent changes."""
        # Track some changes
        devices1 = [{"ip": "192.168.1.1"}]
        devices2 = [{"ip": "192.168.1.1"}, {"ip": "192.168.1.2"}]
        
        self.tracker.track_changes(devices1)
        changes = self.tracker.track_changes(devices2)
        
        # Get recent changes
        recent = self.tracker.get_recent_changes(hours=1)
        self.assertGreater(len(recent), 0)
        
        # Should include the new device
        new_device_changes = [c for c in recent if c["type"] == "new" and c["device_ip"] == "192.168.1.2"]
        self.assertEqual(len(new_device_changes), 1)
    
    def test_get_recent_changes_time_filter(self):
        """Test time filtering for recent changes."""
        # Create old change file
        old_timestamp = (datetime.now() - timedelta(days=2)).strftime("%Y%m%d_%H%M%S")
        old_file = os.path.join(self.tracker.output_dir, f"changes_{old_timestamp}.json")
        
        old_changes = {
            "timestamp": (datetime.now() - timedelta(days=2)).isoformat(),
            "changes": [
                {
                    "type": "new",
                    "device_ip": "192.168.1.100",
                    "timestamp": (datetime.now() - timedelta(days=2)).isoformat(),
                    "details": {}
                }
            ]
        }
        
        with open(old_file, 'w') as f:
            json.dump(old_changes, f)
        
        # Track recent change
        self.tracker.track_changes([{"ip": "192.168.1.1"}])
        
        # Get changes from last 24 hours only
        recent = self.tracker.get_recent_changes(hours=24)
        
        # Should not include the old change
        old_device_changes = [c for c in recent if c["device_ip"] == "192.168.1.100"]
        self.assertEqual(len(old_device_changes), 0)
    
    def test_generate_change_report(self):
        """Test change report generation."""
        # Create some changes
        initial_devices = [
            {"ip": "192.168.1.1", "type": "router"},
            {"ip": "192.168.1.10", "type": "server"}
        ]
        
        self.tracker.track_changes(initial_devices)
        
        # Second scan with changes
        current_devices = [
            {"ip": "192.168.1.1", "type": "router", "open_ports": [22, 80]},
            {"ip": "192.168.1.20", "type": "workstation"}  # 1.10 missing, 1.20 new
        ]
        
        self.tracker.track_changes(current_devices)
        
        # Generate report
        report = self.tracker.generate_change_report(hours=24)
        
        self.assertIn("summary", report)
        self.assertIn("new_devices", report["summary"])
        self.assertIn("missing_devices", report["summary"])
        self.assertIn("modified_devices", report["summary"])
        self.assertIn("timeline", report)
        
        # Verify counts
        self.assertGreater(report["summary"]["new_devices"], 0)
        self.assertGreater(report["summary"]["missing_devices"], 0)
    
    def test_save_and_load_snapshot(self):
        """Test saving and loading snapshots."""
        devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"},
            {"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"}
        ]
        
        # Save snapshot
        timestamp = self.tracker._save_snapshot(devices, "test_scan")
        
        # Verify file exists
        snapshot_file = os.path.join(
            self.tracker.output_dir,
            f"snapshot_{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
        )
        self.assertTrue(os.path.exists(snapshot_file))
        
        # Load and verify
        with open(snapshot_file) as f:
            data = json.load(f)
        
        self.assertEqual(data["total_devices"], 2)
        self.assertEqual(data["scan_type"], "test_scan")
        self.assertEqual(len(data["devices"]), 2)
    
    def test_get_last_snapshot(self):
        """Test retrieving the last snapshot."""
        # No snapshots initially
        self.assertIsNone(self.tracker._get_last_snapshot())
        
        # Create snapshot
        devices = [{"ip": "192.168.1.1"}]
        self.tracker._save_snapshot(devices, "discovery")
        
        # Should now return the snapshot
        snapshot = self.tracker._get_last_snapshot()
        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot["total_devices"], 1)
    
    def test_track_changes_no_changes(self):
        """Test tracking when no changes occurred."""
        devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "open_ports": [22, 80]}
        ]
        
        # First scan
        self.tracker.track_changes(devices)
        
        # Second scan - identical
        changes = self.tracker.track_changes(devices)
        
        # Should have no changes
        self.assertEqual(len(changes), 0)
    
    def test_concurrent_tracking(self):
        """Test concurrent change tracking."""
        import threading
        
        results = []
        
        def track_devices(device_set):
            changes = self.tracker.track_changes(device_set)
            results.append(len(changes))
        
        # Create threads
        thread1 = threading.Thread(
            target=track_devices,
            args=([{"ip": "192.168.1.1"}],)
        )
        thread2 = threading.Thread(
            target=track_devices,
            args=([{"ip": "192.168.1.2"}],)
        )
        
        # Run concurrently
        thread1.start()
        thread2.start()
        thread1.join()
        thread2.join()
        
        # Both should complete successfully
        self.assertEqual(len(results), 2)
    
    def test_change_persistence(self):
        """Test that changes are persisted correctly."""
        # Track changes
        devices = [{"ip": "192.168.1.1", "type": "router"}]
        self.tracker.track_changes(devices)
        
        # Create new tracker instance with same directory
        new_tracker = ChangeTracker(base_dir=self.temp_dir)
        
        # Should be able to see previous snapshot
        snapshot = new_tracker._get_last_snapshot()
        self.assertIsNotNone(snapshot)
        self.assertEqual(len(snapshot["devices"]), 1)
    
    def test_ip_only_comparison(self):
        """Test device comparison by IP only when MAC not available."""
        # First scan - device without MAC
        initial_devices = [
            {"ip": "192.168.1.1", "open_ports": [22]}
        ]
        
        self.tracker.track_changes(initial_devices)
        
        # Second scan - same IP, different ports
        current_devices = [
            {"ip": "192.168.1.1", "open_ports": [22, 80]}
        ]
        
        changes = self.tracker.track_changes(current_devices)
        
        # Should detect modification
        modified = [c for c in changes if c.type == "modified"]
        self.assertEqual(len(modified), 1)
        self.assertIn("ports_added", modified[0].details)
    
    def test_mac_change_detection(self):
        """Test detection of MAC address changes."""
        # First scan
        initial_devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"}
        ]
        
        self.tracker.track_changes(initial_devices)
        
        # Second scan - same IP, different MAC
        current_devices = [
            {"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:FF"}
        ]
        
        changes = self.tracker.track_changes(current_devices)
        
        # Should detect MAC change
        modified = [c for c in changes if c.type == "modified"]
        self.assertEqual(len(modified), 1)
        self.assertIn("mac_changed", modified[0].details)
        self.assertEqual(modified[0].details["mac_changed"]["old"], "00:11:22:33:44:55")
        self.assertEqual(modified[0].details["mac_changed"]["new"], "AA:BB:CC:DD:EE:FF")
    
    def test_error_handling(self):
        """Test error handling in various scenarios."""
        # Invalid device data
        with self.assertLogs(level='ERROR'):
            changes = self.tracker.track_changes([{"no_ip": "invalid"}])
            self.assertEqual(len(changes), 0)
        
        # Corrupted snapshot file
        bad_snapshot = os.path.join(self.tracker.output_dir, "snapshot_20230101_120000.json")
        with open(bad_snapshot, 'w') as f:
            f.write("invalid json {")
        
        # Should handle gracefully
        snapshot = self.tracker._get_last_snapshot()
        # May return None or skip the corrupted file
        
        # Corrupted change file
        bad_change = os.path.join(self.tracker.output_dir, "changes_20230101_120000.json")
        with open(bad_change, 'w') as f:
            f.write("invalid json {")
        
        # Should handle gracefully
        recent = self.tracker.get_recent_changes(hours=24)
        self.assertIsInstance(recent, list)
    
    def test_large_network_tracking(self):
        """Test tracking changes in large networks."""
        # Create 1000 devices
        large_network = []
        for i in range(1000):
            large_network.append({
                "ip": f"10.0.{i // 256}.{i % 256}",
                "mac": f"00:11:22:33:{i // 256:02x}:{i % 256:02x}",
                "type": "workstation" if i % 2 else "server"
            })
        
        # Track initial state
        import time
        start_time = time.time()
        self.tracker.track_changes(large_network)
        first_scan_time = time.time() - start_time
        
        # Should complete in reasonable time
        self.assertLess(first_scan_time, 5.0)
        
        # Make changes to 10% of devices
        for i in range(0, 1000, 10):
            large_network[i]["open_ports"] = [22, 80]
        
        # Track changes
        start_time = time.time()
        changes = self.tracker.track_changes(large_network)
        change_scan_time = time.time() - start_time
        
        # Should detect 100 modifications
        modified = [c for c in changes if c.type == "modified"]
        self.assertEqual(len(modified), 100)
        
        # Should complete quickly
        self.assertLess(change_scan_time, 5.0)


class TestChangeTrackerReporting(unittest.TestCase):
    """Test cases for change tracking reports."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.tracker = ChangeTracker(base_dir=self.temp_dir)
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_timeline_generation(self):
        """Test timeline generation in reports."""
        # Create changes over time
        base_time = datetime.now()
        
        # First scan
        self.tracker.track_changes([{"ip": "192.168.1.1"}])
        
        # Second scan after 1 hour
        with patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = base_time + timedelta(hours=1)
            mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)
            self.tracker.track_changes([
                {"ip": "192.168.1.1"},
                {"ip": "192.168.1.2"}  # New device
            ])
        
        report = self.tracker.generate_change_report(hours=24)
        
        self.assertIn("timeline", report)
        self.assertGreater(len(report["timeline"]), 0)
        
        # Check timeline entries
        timeline_types = [entry["type"] for entry in report["timeline"]]
        self.assertIn("new", timeline_types)
    
    def test_change_categorization(self):
        """Test proper categorization of changes in reports."""
        # Various types of changes
        initial = [
            {"ip": "192.168.1.1", "open_ports": [22]},
            {"ip": "192.168.1.2", "open_ports": [80]},
            {"ip": "192.168.1.3", "open_ports": [443]}
        ]
        
        self.tracker.track_changes(initial)
        
        current = [
            {"ip": "192.168.1.1", "open_ports": [22, 80]},  # Modified
            {"ip": "192.168.1.2", "open_ports": [80]},      # No change
            # 192.168.1.3 missing
            {"ip": "192.168.1.4", "open_ports": [3389]}     # New
        ]
        
        self.tracker.track_changes(current)
        
        report = self.tracker.generate_change_report()
        
        self.assertEqual(report["summary"]["new_devices"], 1)
        self.assertEqual(report["summary"]["missing_devices"], 1)
        self.assertEqual(report["summary"]["modified_devices"], 1)
        
        # Check categorized changes
        self.assertIn("changes_by_type", report)
        self.assertIn("new", report["changes_by_type"])
        self.assertIn("missing", report["changes_by_type"])
        self.assertIn("modified", report["changes_by_type"])


if __name__ == '__main__':
    unittest.main()