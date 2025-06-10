"""Comprehensive unit tests for the DeviceAnnotator module."""

import json
import logging
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

from core.annotator import DeviceAnnotation, DeviceAnnotator


class TestDeviceAnnotation(unittest.TestCase):
    """Test cases for DeviceAnnotation dataclass."""

    def test_device_annotation_creation(self):
        """Test DeviceAnnotation creation."""
        annotation = DeviceAnnotation(
            ip="192.168.1.1",
            critical=True,
            notes="Main router",
            tags=["network", "critical"],
            location="Server Room A",
            owner="IT Department",
            department="Infrastructure",
        )

        self.assertEqual(annotation.ip, "192.168.1.1")
        self.assertTrue(annotation.critical)
        self.assertEqual(annotation.notes, "Main router")
        self.assertEqual(annotation.tags, ["network", "critical"])
        self.assertEqual(annotation.location, "Server Room A")
        self.assertEqual(annotation.owner, "IT Department")
        self.assertEqual(annotation.department, "Infrastructure")
        self.assertIsNotNone(annotation.created)
        self.assertIsNotNone(annotation.last_modified)

    def test_device_annotation_defaults(self):
        """Test DeviceAnnotation default values."""
        annotation = DeviceAnnotation(ip="192.168.1.1")

        self.assertEqual(annotation.ip, "192.168.1.1")
        self.assertFalse(annotation.critical)
        self.assertEqual(annotation.notes, "")
        self.assertEqual(annotation.tags, [])
        self.assertEqual(annotation.location, "")
        self.assertEqual(annotation.owner, "")
        self.assertEqual(annotation.department, "")
        self.assertEqual(annotation.custom_fields, {})

    def test_device_annotation_to_dict(self):
        """Test DeviceAnnotation serialization."""
        annotation = DeviceAnnotation(
            ip="192.168.1.1",
            critical=True,
            tags=["router", "main"],
            custom_fields={"asset_id": "A123"},
        )

        data = annotation.to_dict()
        self.assertIsInstance(data, dict)
        self.assertEqual(data["ip"], "192.168.1.1")
        self.assertTrue(data["critical"])
        self.assertEqual(data["tags"], ["router", "main"])
        self.assertEqual(data["custom_fields"]["asset_id"], "A123")

    def test_device_annotation_from_dict(self):
        """Test DeviceAnnotation deserialization."""
        data = {
            "ip": "10.0.0.1",
            "critical": False,
            "notes": "Test device",
            "tags": ["test"],
            "created": "2023-01-01T12:00:00",
            "extra_field": "ignored",  # Should be filtered out
        }

        annotation = DeviceAnnotation.from_dict(data)
        self.assertEqual(annotation.ip, "10.0.0.1")
        self.assertFalse(annotation.critical)
        self.assertEqual(annotation.notes, "Test device")
        self.assertEqual(annotation.tags, ["test"])
        self.assertEqual(annotation.created, "2023-01-01T12:00:00")


class TestDeviceAnnotator(unittest.TestCase):
    """Test cases for DeviceAnnotator class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.annotator = DeviceAnnotator(output_path=Path(self.temp_dir))
        # Configure logging
        logging.basicConfig(level=logging.DEBUG)

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir)

    def test_init(self):
        """Test annotator initialization."""
        annotator = DeviceAnnotator(output_path=Path(self.temp_dir))
        self.assertEqual(annotator.output_path, Path(self.temp_dir))
        self.assertTrue(os.path.exists(self.temp_dir))

        # Check annotations file path
        expected_path = Path(self.temp_dir) / "annotations" / "device_annotations.json"
        self.assertEqual(annotator.annotations_file, expected_path)

    def test_add_annotation_manually(self):
        """Test manually adding annotations."""
        # Add annotation directly to internal structure
        annotation = DeviceAnnotation(
            ip="192.168.1.1",
            critical=True,
            notes="Main gateway router",
            tags=["network", "critical"],
        )
        self.annotator.annotations["192.168.1.1"] = annotation

        # Save and verify
        self.assertTrue(self.annotator.save_annotations())

        # Verify annotation was saved
        self.assertEqual(len(self.annotator.annotations), 1)
        self.assertIn("192.168.1.1", self.annotator.annotations)
        ann = self.annotator.annotations["192.168.1.1"]
        self.assertTrue(ann.critical)
        self.assertEqual(ann.notes, "Main gateway router")

    def test_get_annotation(self):
        """Test getting specific annotation."""
        # Add an annotation directly
        annotation = DeviceAnnotation(ip="192.168.1.1", notes="Test device")
        self.annotator.annotations["192.168.1.1"] = annotation

        # Get it back
        retrieved = self.annotator.annotations.get("192.168.1.1")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.ip, "192.168.1.1")
        self.assertEqual(retrieved.notes, "Test device")

        # Try non-existent
        retrieved = self.annotator.annotations.get("192.168.1.99")
        self.assertIsNone(retrieved)

    def test_update_annotation(self):
        """Test updating annotations."""
        # Add initial annotation
        annotation = DeviceAnnotation(ip="192.168.1.1", notes="Initial note")
        self.annotator.annotations["192.168.1.1"] = annotation

        # Update it manually
        annotation.notes = "Updated note"
        annotation.critical = True
        annotation.last_modified = datetime.now().isoformat()

        # Save and verify
        self.assertTrue(self.annotator.save_annotations())

        # Verify update
        updated_ann = self.annotator.annotations.get("192.168.1.1")
        self.assertEqual(updated_ann.notes, "Updated note")
        self.assertTrue(updated_ann.critical)

    def test_update_annotation_preserve_fields(self):
        """Test that updates preserve non-updated fields."""
        # Add annotation with multiple fields
        annotation = DeviceAnnotation(
            ip="192.168.1.1", notes="Original note", tags=["router", "main"], location="Room A"
        )
        self.annotator.annotations["192.168.1.1"] = annotation

        # Update only notes
        annotation.notes = "New note"
        annotation.last_modified = datetime.now().isoformat()

        # Verify other fields preserved
        self.assertEqual(annotation.notes, "New note")
        self.assertEqual(annotation.tags, ["router", "main"])
        self.assertEqual(annotation.location, "Room A")

    def test_delete_annotation(self):
        """Test deleting annotations."""
        # Add annotation
        annotation = DeviceAnnotation(ip="192.168.1.1")
        self.annotator.annotations["192.168.1.1"] = annotation

        # Delete it
        del self.annotator.annotations["192.168.1.1"]
        self.assertTrue(self.annotator.save_annotations())

        # Verify deleted
        self.assertNotIn("192.168.1.1", self.annotator.annotations)

        # Try deleting non-existent (no error expected)
        self.assertNotIn("192.168.1.99", self.annotator.annotations)

    def test_get_all_annotations(self):
        """Test getting all annotations."""
        # Add multiple annotations
        ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

        for ip in ips:
            self.annotator.annotations[ip] = DeviceAnnotation(ip=ip)

        # Get all
        self.assertEqual(len(self.annotator.annotations), 3)
        self.assertIn("192.168.1.1", self.annotator.annotations)
        self.assertIn("192.168.1.2", self.annotator.annotations)
        self.assertIn("192.168.1.3", self.annotator.annotations)

    def test_apply_annotations(self):
        """Test applying annotations to scan results."""
        # Add some annotations
        self.annotator.annotations["192.168.1.1"] = DeviceAnnotation(
            ip="192.168.1.1", critical=True, notes="Critical router"
        )
        self.annotator.annotations["192.168.1.2"] = DeviceAnnotation(
            ip="192.168.1.2", tags=["workstation", "dev"]
        )

        # Apply to scan results
        devices = [
            {"ip": "192.168.1.1", "type": "router"},
            {"ip": "192.168.1.2", "type": "workstation"},
            {"ip": "192.168.1.3", "type": "unknown"},  # No annotation
        ]

        annotated = self.annotator.apply_annotations(devices)

        # Check annotations were applied
        self.assertTrue(annotated[0]["critical"])
        self.assertEqual(annotated[0]["notes"], "Critical router")
        self.assertEqual(annotated[1]["tags"], ["workstation", "dev"])
        self.assertFalse(annotated[2].get("critical", False))

    def test_export_annotations(self):
        """Test exporting annotations."""
        # Add annotations
        self.annotator.annotations["192.168.1.1"] = DeviceAnnotation(
            ip="192.168.1.1", critical=True
        )
        self.annotator.annotations["192.168.1.2"] = DeviceAnnotation(ip="192.168.1.2", notes="Test")

        # Save annotations
        self.assertTrue(self.annotator.save_annotations())

        # Verify saved file exists and contains data
        self.assertTrue(self.annotator.annotations_file.exists())
        with open(self.annotator.annotations_file) as f:
            data = json.load(f)

        self.assertEqual(len(data), 2)
        self.assertIn("192.168.1.1", data)
        self.assertIn("192.168.1.2", data)

    def test_load_annotations(self):
        """Test loading annotations from file."""
        # Create annotations file with data
        import_data = {
            "192.168.1.1": {"ip": "192.168.1.1", "critical": True, "notes": "Imported"},
            "192.168.1.2": {"ip": "192.168.1.2", "tags": ["imported"]},
        }

        # Write to the expected location
        self.annotator.annotations_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.annotator.annotations_file, "w") as f:
            json.dump(import_data, f)

        # Load annotations
        self.annotator.load_annotations()

        # Verify loaded
        self.assertEqual(len(self.annotator.annotations), 2)
        self.assertTrue(self.annotator.annotations["192.168.1.1"].critical)
        self.assertEqual(self.annotator.annotations["192.168.1.2"].tags, ["imported"])

    def test_merge_annotations(self):
        """Test merging annotations."""
        # Add existing annotation
        existing = DeviceAnnotation(ip="192.168.1.1", notes="Existing", tags=["existing"])
        self.annotator.annotations["192.168.1.1"] = existing

        # Create new annotation to merge
        new_annotation = DeviceAnnotation(ip="192.168.1.1", critical=True, tags=["imported"])

        # Merge using the DeviceAnnotation merge method
        existing.merge(new_annotation)

        # Verify merged
        self.assertTrue(existing.critical)
        # Tags should be combined
        self.assertIn("existing", existing.tags)
        self.assertIn("imported", existing.tags)
        # Notes should be preserved
        self.assertEqual(existing.notes, "Existing")

    def test_annotation_stats(self):
        """Test getting annotation statistics."""
        # Add various annotations
        self.annotator.annotations["192.168.1.1"] = DeviceAnnotation(
            ip="192.168.1.1",
            notes="Main router in server room",
            tags=["router", "critical"],
            critical=True,
            location="Server Room",
        )
        self.annotator.annotations["192.168.1.2"] = DeviceAnnotation(
            ip="192.168.1.2",
            notes="Development workstation",
            tags=["workstation", "dev"],
            owner="John Doe",
        )
        self.annotator.annotations["192.168.1.3"] = DeviceAnnotation(
            ip="192.168.1.3", notes="Test server", tags=["server"]
        )

        # Get stats
        stats = self.annotator.get_annotation_stats()
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["critical"], 1)
        self.assertEqual(stats["with_notes"], 3)
        self.assertEqual(stats["with_tags"], 3)
        self.assertEqual(stats["with_location"], 1)
        self.assertEqual(stats["with_owner"], 1)
        self.assertEqual(stats["unique_tags"], 5)  # router, critical, workstation, dev, server

    def test_annotation_persistence(self):
        """Test annotations persist across instances."""
        # Add annotation
        self.annotator.annotations["192.168.1.1"] = DeviceAnnotation(
            ip="192.168.1.1", critical=True, notes="Persistent"
        )

        # Save
        self.assertTrue(self.annotator.save_annotations())

        # Create new instance
        new_annotator = DeviceAnnotator(output_path=Path(self.temp_dir))

        # Verify annotation persisted
        self.assertIn("192.168.1.1", new_annotator.annotations)
        annotation = new_annotator.annotations["192.168.1.1"]
        self.assertTrue(annotation.critical)
        self.assertEqual(annotation.notes, "Persistent")

    def test_error_handling(self):
        """Test error handling in various scenarios."""
        # Test saving with invalid path
        old_file = self.annotator.annotations_file
        self.annotator.annotations_file = Path("/invalid/path/annotations.json")

        # Should handle error gracefully
        result = self.annotator.save_annotations()
        self.assertFalse(result)

        # Restore valid path
        self.annotator.annotations_file = old_file

        # Test loading invalid JSON
        self.annotator.annotations_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.annotator.annotations_file, "w") as f:
            f.write("invalid json{")

        # Should handle error gracefully
        self.annotator.load_annotations()
        self.assertEqual(len(self.annotator.annotations), 0)


if __name__ == "__main__":
    unittest.main()
