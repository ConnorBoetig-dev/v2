"""Comprehensive unit tests for the DeviceAnnotator module."""

import json
import logging
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

from core.annotator import DeviceAnnotator, DeviceAnnotation


class TestDeviceAnnotation(unittest.TestCase):
    """Test cases for DeviceAnnotation dataclass."""
    
    def test_device_annotation_creation(self):
        """Test DeviceAnnotation creation with all fields."""
        annotation = DeviceAnnotation(
            device_id="192.168.1.1_00:11:22:33:44:55",
            name="Main Router",
            description="Primary network gateway",
            location="Server Room A",
            owner="Network Team",
            criticality="high",
            tags=["production", "critical"],
            custom_fields={"asset_id": "RT-001", "warranty": "2025-12-31"},
            last_updated="2023-01-01T12:00:00"
        )
        
        self.assertEqual(annotation.device_id, "192.168.1.1_00:11:22:33:44:55")
        self.assertEqual(annotation.name, "Main Router")
        self.assertEqual(annotation.description, "Primary network gateway")
        self.assertEqual(annotation.location, "Server Room A")
        self.assertEqual(annotation.owner, "Network Team")
        self.assertEqual(annotation.criticality, "high")
        self.assertIn("production", annotation.tags)
        self.assertEqual(annotation.custom_fields["asset_id"], "RT-001")
    
    def test_device_annotation_defaults(self):
        """Test DeviceAnnotation with default values."""
        annotation = DeviceAnnotation(device_id="192.168.1.1")
        
        self.assertEqual(annotation.device_id, "192.168.1.1")
        self.assertEqual(annotation.name, "")
        self.assertEqual(annotation.description, "")
        self.assertEqual(annotation.location, "")
        self.assertEqual(annotation.owner, "")
        self.assertEqual(annotation.criticality, "medium")
        self.assertEqual(annotation.tags, [])
        self.assertEqual(annotation.custom_fields, {})
        self.assertIsNotNone(annotation.last_updated)
    
    def test_device_annotation_to_dict(self):
        """Test converting annotation to dictionary."""
        annotation = DeviceAnnotation(
            device_id="10.0.0.1",
            name="Test Device",
            tags=["test", "development"]
        )
        
        annotation_dict = annotation.to_dict()
        self.assertIsInstance(annotation_dict, dict)
        self.assertEqual(annotation_dict["device_id"], "10.0.0.1")
        self.assertEqual(annotation_dict["name"], "Test Device")
        self.assertEqual(annotation_dict["tags"], ["test", "development"])
        self.assertIn("last_updated", annotation_dict)
    
    def test_device_annotation_from_dict(self):
        """Test creating annotation from dictionary."""
        data = {
            "device_id": "192.168.1.1",
            "name": "Router",
            "criticality": "high",
            "tags": ["network", "core"],
            "last_updated": "2023-01-01T12:00:00"
        }
        
        annotation = DeviceAnnotation.from_dict(data)
        self.assertEqual(annotation.device_id, "192.168.1.1")
        self.assertEqual(annotation.name, "Router")
        self.assertEqual(annotation.criticality, "high")
        self.assertEqual(annotation.tags, ["network", "core"])


class TestDeviceAnnotator(unittest.TestCase):
    """Test cases for DeviceAnnotator class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.annotator = DeviceAnnotator(base_dir=self.temp_dir)
        # Configure logging
        logging.basicConfig(level=logging.DEBUG)
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_init(self):
        """Test annotator initialization."""
        annotator = DeviceAnnotator()
        self.assertIsNotNone(annotator.annotations_dir)
        self.assertTrue(os.path.exists(annotator.annotations_dir))
        self.assertIsInstance(annotator._annotations_cache, dict)
        
        # Test with custom directory
        custom_dir = os.path.join(self.temp_dir, "custom")
        annotator = DeviceAnnotator(base_dir=custom_dir)
        self.assertTrue(os.path.exists(os.path.join(custom_dir, "annotations")))
    
    def test_generate_device_id(self):
        """Test device ID generation."""
        # With MAC address
        device_id = self.annotator._generate_device_id("192.168.1.1", "00:11:22:33:44:55")
        self.assertEqual(device_id, "192.168.1.1_00:11:22:33:44:55")
        
        # Without MAC address
        device_id = self.annotator._generate_device_id("10.0.0.1", "")
        self.assertEqual(device_id, "10.0.0.1")
        
        # With None MAC
        device_id = self.annotator._generate_device_id("172.16.0.1", None)
        self.assertEqual(device_id, "172.16.0.1")
    
    def test_add_annotation(self):
        """Test adding device annotation."""
        device = {
            "ip": "192.168.1.1",
            "mac": "00:11:22:33:44:55"
        }
        
        success = self.annotator.add_annotation(
            device,
            name="Main Router",
            description="Primary gateway device",
            location="Rack A1",
            owner="IT Team",
            criticality="high",
            tags=["production", "critical"]
        )
        
        self.assertTrue(success)
        
        # Verify annotation was saved
        annotation_file = os.path.join(
            self.annotator.annotations_dir,
            "192.168.1.1_00:11:22:33:44:55.json"
        )
        self.assertTrue(os.path.exists(annotation_file))
        
        # Verify content
        with open(annotation_file) as f:
            data = json.load(f)
        
        self.assertEqual(data["name"], "Main Router")
        self.assertEqual(data["criticality"], "high")
        self.assertIn("production", data["tags"])
    
    def test_update_annotation(self):
        """Test updating existing annotation."""
        device = {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"}
        
        # Add initial annotation
        self.annotator.add_annotation(
            device,
            name="Router",
            criticality="medium"
        )
        
        # Update annotation
        success = self.annotator.update_annotation(
            device,
            name="Main Router",
            criticality="high",
            tags=["updated"]
        )
        
        self.assertTrue(success)
        
        # Verify updates
        annotation = self.annotator.get_annotation(device)
        self.assertEqual(annotation.name, "Main Router")
        self.assertEqual(annotation.criticality, "high")
        self.assertIn("updated", annotation.tags)
    
    def test_update_annotation_preserve_fields(self):
        """Test that update preserves non-updated fields."""
        device = {"ip": "192.168.1.1"}
        
        # Add initial annotation
        self.annotator.add_annotation(
            device,
            name="Device",
            description="Original description",
            location="Room A",
            tags=["original"]
        )
        
        # Update only name
        self.annotator.update_annotation(device, name="Updated Device")
        
        # Other fields should be preserved
        annotation = self.annotator.get_annotation(device)
        self.assertEqual(annotation.name, "Updated Device")
        self.assertEqual(annotation.description, "Original description")
        self.assertEqual(annotation.location, "Room A")
        self.assertIn("original", annotation.tags)
    
    def test_get_annotation(self):
        """Test retrieving annotation."""
        device = {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"}
        
        # No annotation initially
        annotation = self.annotator.get_annotation(device)
        self.assertIsNone(annotation)
        
        # Add annotation
        self.annotator.add_annotation(device, name="Test Device")
        
        # Should now retrieve it
        annotation = self.annotator.get_annotation(device)
        self.assertIsNotNone(annotation)
        self.assertEqual(annotation.name, "Test Device")
        
        # Test cache hit
        annotation2 = self.annotator.get_annotation(device)
        self.assertEqual(annotation.device_id, annotation2.device_id)
    
    def test_delete_annotation(self):
        """Test deleting annotation."""
        device = {"ip": "192.168.1.1"}
        
        # Add annotation
        self.annotator.add_annotation(device, name="To Delete")
        
        # Verify it exists
        self.assertIsNotNone(self.annotator.get_annotation(device))
        
        # Delete it
        success = self.annotator.delete_annotation(device)
        self.assertTrue(success)
        
        # Should be gone
        self.assertIsNone(self.annotator.get_annotation(device))
        
        # File should be deleted
        annotation_file = os.path.join(self.annotator.annotations_dir, "192.168.1.1.json")
        self.assertFalse(os.path.exists(annotation_file))
    
    def test_get_all_annotations(self):
        """Test retrieving all annotations."""
        # Add multiple annotations
        devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"},
            {"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:FF"},
            {"ip": "192.168.1.3"}
        ]
        
        for i, device in enumerate(devices):
            self.annotator.add_annotation(device, name=f"Device {i+1}")
        
        # Get all annotations
        all_annotations = self.annotator.get_all_annotations()
        
        self.assertEqual(len(all_annotations), 3)
        names = [a.name for a in all_annotations]
        self.assertIn("Device 1", names)
        self.assertIn("Device 2", names)
        self.assertIn("Device 3", names)
    
    def test_search_annotations(self):
        """Test searching annotations."""
        # Add annotations with different attributes
        devices = [
            {"ip": "192.168.1.1"},
            {"ip": "192.168.1.2"},
            {"ip": "192.168.1.3"},
            {"ip": "192.168.1.4"}
        ]
        
        self.annotator.add_annotation(
            devices[0],
            name="Production Server",
            criticality="high",
            tags=["production", "web"]
        )
        self.annotator.add_annotation(
            devices[1],
            name="Test Server",
            criticality="low",
            tags=["test", "web"]
        )
        self.annotator.add_annotation(
            devices[2],
            name="Database Server",
            criticality="high",
            tags=["production", "database"]
        )
        self.annotator.add_annotation(
            devices[3],
            name="Development Workstation",
            criticality="low",
            tags=["development"]
        )
        
        # Search by name
        results = self.annotator.search_annotations(name="Server")
        self.assertEqual(len(results), 3)
        
        # Search by criticality
        results = self.annotator.search_annotations(criticality="high")
        self.assertEqual(len(results), 2)
        
        # Search by tag
        results = self.annotator.search_annotations(tag="production")
        self.assertEqual(len(results), 2)
        
        # Search by multiple criteria
        results = self.annotator.search_annotations(
            criticality="high",
            tag="production"
        )
        self.assertEqual(len(results), 2)
        
        # Search with no matches
        results = self.annotator.search_annotations(name="NonExistent")
        self.assertEqual(len(results), 0)
    
    def test_bulk_operations(self):
        """Test bulk annotation operations."""
        # Prepare devices
        devices = [
            {"ip": f"192.168.1.{i}", "type": "server"}
            for i in range(1, 11)
        ]
        
        # Bulk add annotations
        annotations_data = []
        for i, device in enumerate(devices):
            annotations_data.append({
                "device": device,
                "name": f"Server {i+1}",
                "criticality": "high" if i < 5 else "medium",
                "tags": ["bulk", "server"]
            })
        
        # Add all annotations
        success_count = 0
        for data in annotations_data:
            if self.annotator.add_annotation(**data):
                success_count += 1
        
        self.assertEqual(success_count, 10)
        
        # Verify all were added
        all_annotations = self.annotator.get_all_annotations()
        self.assertEqual(len(all_annotations), 10)
    
    def test_annotation_tags(self):
        """Test tag management functionality."""
        device = {"ip": "192.168.1.1"}
        
        # Add annotation with tags
        self.annotator.add_annotation(
            device,
            name="Tagged Device",
            tags=["tag1", "tag2", "tag3"]
        )
        
        # Add more tags
        self.annotator.add_tags(device, ["tag4", "tag5"])
        
        annotation = self.annotator.get_annotation(device)
        self.assertEqual(len(annotation.tags), 5)
        self.assertIn("tag4", annotation.tags)
        self.assertIn("tag5", annotation.tags)
        
        # Remove tags
        self.annotator.remove_tags(device, ["tag2", "tag4"])
        
        annotation = self.annotator.get_annotation(device)
        self.assertEqual(len(annotation.tags), 3)
        self.assertNotIn("tag2", annotation.tags)
        self.assertNotIn("tag4", annotation.tags)
        
        # Try to remove non-existent tag
        self.annotator.remove_tags(device, ["nonexistent"])
        annotation = self.annotator.get_annotation(device)
        self.assertEqual(len(annotation.tags), 3)
    
    def test_custom_fields(self):
        """Test custom fields functionality."""
        device = {"ip": "192.168.1.1"}
        
        # Add annotation with custom fields
        custom_fields = {
            "asset_id": "AST-001",
            "purchase_date": "2023-01-01",
            "warranty_expires": "2026-01-01",
            "department": "IT"
        }
        
        self.annotator.add_annotation(
            device,
            name="Asset",
            custom_fields=custom_fields
        )
        
        # Verify custom fields
        annotation = self.annotator.get_annotation(device)
        self.assertEqual(annotation.custom_fields["asset_id"], "AST-001")
        self.assertEqual(annotation.custom_fields["department"], "IT")
        
        # Update custom fields
        new_fields = {
            "department": "Engineering",  # Update existing
            "cost_center": "CC-123"      # Add new
        }
        
        self.annotator.update_custom_fields(device, new_fields)
        
        annotation = self.annotator.get_annotation(device)
        self.assertEqual(annotation.custom_fields["department"], "Engineering")
        self.assertEqual(annotation.custom_fields["cost_center"], "CC-123")
        # Original fields should still exist
        self.assertEqual(annotation.custom_fields["asset_id"], "AST-001")
    
    def test_criticality_levels(self):
        """Test criticality level validation."""
        device = {"ip": "192.168.1.1"}
        
        # Valid criticality levels
        for level in ["low", "medium", "high", "critical"]:
            success = self.annotator.add_annotation(
                device,
                name=f"Device {level}",
                criticality=level
            )
            self.assertTrue(success)
            
            annotation = self.annotator.get_annotation(device)
            self.assertEqual(annotation.criticality, level)
            
            # Clean up for next iteration
            self.annotator.delete_annotation(device)
        
        # Invalid criticality should default to medium
        self.annotator.add_annotation(
            device,
            name="Invalid criticality",
            criticality="invalid"
        )
        
        annotation = self.annotator.get_annotation(device)
        self.assertEqual(annotation.criticality, "medium")
    
    def test_export_annotations(self):
        """Test exporting annotations."""
        # Add some annotations
        devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"},
            {"ip": "192.168.1.2"},
            {"ip": "192.168.1.3", "mac": "AA:BB:CC:DD:EE:FF"}
        ]
        
        for i, device in enumerate(devices):
            self.annotator.add_annotation(
                device,
                name=f"Device {i+1}",
                criticality="high" if i == 0 else "medium",
                tags=[f"tag{i}"]
            )
        
        # Export all annotations
        export_data = self.annotator.export_annotations()
        
        self.assertIn("annotations", export_data)
        self.assertIn("export_time", export_data)
        self.assertIn("total_annotations", export_data)
        self.assertEqual(export_data["total_annotations"], 3)
        self.assertEqual(len(export_data["annotations"]), 3)
        
        # Export filtered annotations
        export_data = self.annotator.export_annotations(criticality="high")
        self.assertEqual(export_data["total_annotations"], 1)
    
    def test_import_annotations(self):
        """Test importing annotations."""
        # Prepare import data
        import_data = {
            "annotations": [
                {
                    "device_id": "192.168.1.1",
                    "name": "Imported Device 1",
                    "criticality": "high",
                    "tags": ["imported"]
                },
                {
                    "device_id": "192.168.1.2_00:11:22:33:44:55",
                    "name": "Imported Device 2",
                    "location": "Import Location"
                }
            ]
        }
        
        # Import annotations
        success_count = self.annotator.import_annotations(import_data)
        self.assertEqual(success_count, 2)
        
        # Verify imported annotations
        device1 = {"ip": "192.168.1.1"}
        annotation1 = self.annotator.get_annotation(device1)
        self.assertIsNotNone(annotation1)
        self.assertEqual(annotation1.name, "Imported Device 1")
        self.assertEqual(annotation1.criticality, "high")
        
        device2 = {"ip": "192.168.1.2", "mac": "00:11:22:33:44:55"}
        annotation2 = self.annotator.get_annotation(device2)
        self.assertIsNotNone(annotation2)
        self.assertEqual(annotation2.location, "Import Location")
    
    def test_merge_annotations(self):
        """Test merging device annotations with scan data."""
        # Add annotations
        devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "type": "router"},
            {"ip": "192.168.1.2", "type": "server"},
            {"ip": "192.168.1.3", "type": "workstation"}
        ]
        
        self.annotator.add_annotation(
            devices[0],
            name="Main Router",
            criticality="high",
            location="Server Room"
        )
        self.annotator.add_annotation(
            devices[1],
            name="Web Server",
            owner="Web Team"
        )
        
        # Merge annotations with device data
        merged_devices = self.annotator.merge_with_devices(devices)
        
        self.assertEqual(len(merged_devices), 3)
        
        # Check merged data
        router = next(d for d in merged_devices if d["ip"] == "192.168.1.1")
        self.assertIn("annotation", router)
        self.assertEqual(router["annotation"]["name"], "Main Router")
        self.assertEqual(router["annotation"]["criticality"], "high")
        
        server = next(d for d in merged_devices if d["ip"] == "192.168.1.2")
        self.assertIn("annotation", server)
        self.assertEqual(server["annotation"]["owner"], "Web Team")
        
        workstation = next(d for d in merged_devices if d["ip"] == "192.168.1.3")
        self.assertNotIn("annotation", workstation)
    
    def test_annotation_persistence(self):
        """Test annotation persistence across instances."""
        device = {"ip": "192.168.1.1"}
        
        # Add annotation
        self.annotator.add_annotation(
            device,
            name="Persistent Device",
            tags=["test", "persistence"]
        )
        
        # Create new annotator instance
        new_annotator = DeviceAnnotator(base_dir=self.temp_dir)
        
        # Should load existing annotations
        annotation = new_annotator.get_annotation(device)
        self.assertIsNotNone(annotation)
        self.assertEqual(annotation.name, "Persistent Device")
        self.assertIn("persistence", annotation.tags)
    
    def test_concurrent_access(self):
        """Test concurrent annotation access."""
        import threading
        
        results = []
        device = {"ip": "192.168.1.1"}
        
        def add_annotation(name):
            success = self.annotator.add_annotation(
                device,
                name=name,
                description=f"Added by {name}"
            )
            results.append((name, success))
        
        # Create threads
        threads = []
        for i in range(5):
            thread = threading.Thread(
                target=add_annotation,
                args=(f"Thread-{i}",)
            )
            threads.append(thread)
        
        # Run concurrently
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        
        # One should succeed, others should update
        self.assertEqual(len(results), 5)
        
        # Final annotation should exist
        annotation = self.annotator.get_annotation(device)
        self.assertIsNotNone(annotation)
    
    def test_error_handling(self):
        """Test error handling in various scenarios."""
        # Invalid device data
        with self.assertLogs(level='ERROR'):
            success = self.annotator.add_annotation(
                {"no_ip": "invalid"},
                name="Test"
            )
            self.assertFalse(success)
        
        # Corrupted annotation file
        device = {"ip": "192.168.1.1"}
        annotation_file = os.path.join(self.annotator.annotations_dir, "192.168.1.1.json")
        
        # Create corrupted file
        with open(annotation_file, 'w') as f:
            f.write("invalid json {")
        
        # Should handle gracefully
        annotation = self.annotator.get_annotation(device)
        self.assertIsNone(annotation)
        
        # Should be able to overwrite with valid annotation
        success = self.annotator.add_annotation(device, name="Valid")
        self.assertTrue(success)
    
    def test_annotation_statistics(self):
        """Test annotation statistics generation."""
        # Add various annotations
        devices = []
        for i in range(20):
            devices.append({"ip": f"192.168.1.{i+1}"})
        
        # Add annotations with different attributes
        for i, device in enumerate(devices):
            criticality = ["low", "medium", "high", "critical"][i % 4]
            tags = []
            if i % 2 == 0:
                tags.append("production")
            if i % 3 == 0:
                tags.append("monitored")
            
            self.annotator.add_annotation(
                device,
                name=f"Device {i+1}",
                criticality=criticality,
                tags=tags,
                owner="IT Team" if i < 10 else "Dev Team"
            )
        
        # Get statistics
        stats = self.annotator.get_statistics()
        
        self.assertEqual(stats["total_annotations"], 20)
        self.assertEqual(stats["criticality_distribution"]["low"], 5)
        self.assertEqual(stats["criticality_distribution"]["medium"], 5)
        self.assertEqual(stats["criticality_distribution"]["high"], 5)
        self.assertEqual(stats["criticality_distribution"]["critical"], 5)
        
        self.assertIn("production", stats["top_tags"])
        self.assertIn("monitored", stats["top_tags"])
        
        self.assertEqual(stats["owners"]["IT Team"], 10)
        self.assertEqual(stats["owners"]["Dev Team"], 10)


if __name__ == '__main__':
    unittest.main()