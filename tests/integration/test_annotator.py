#!/usr/bin/env python3
"""
Test suite for core/annotator.py
"""

import pytest
import json
import tempfile
from pathlib import Path
from core.annotator import DeviceAnnotator


class TestDeviceAnnotator:
    """Test DeviceAnnotator class"""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def annotator(self, temp_dir):
        """Create annotator instance with temp directory"""
        return DeviceAnnotator(base_dir=temp_dir)

    @pytest.fixture
    def sample_devices(self):
        """Sample device list for testing"""
        return [
            {
                "ip": "10.0.1.1",
                "mac": "00:11:22:33:44:55",
                "hostname": "router01",
                "type": "router",
                "vendor": "Cisco",
            },
            {
                "ip": "10.0.1.2",
                "mac": "00:11:22:33:44:56",
                "hostname": "server01",
                "type": "server",
                "vendor": "Dell",
            },
        ]

    def test_init(self, annotator, temp_dir):
        """Test annotator initialization"""
        assert annotator.annotations_dir == temp_dir / "annotations"
        assert annotator.annotations_dir.exists()
        assert annotator.annotations_file.exists()

        # Check empty annotations file
        with open(annotator.annotations_file) as f:
            data = json.load(f)
            assert data == {"devices": {}}

    def test_annotate_device(self, annotator):
        """Test device annotation"""
        result = annotator.annotate_device(
            "10.0.1.1",
            critical=True,
            notes="Core router - do not modify",
            tags=["production", "critical-infra"],
            custom_fields={"location": "Data Center A"},
        )

        assert result is True
        annotations = annotator.get_annotations()
        assert "10.0.1.1" in annotations
        assert annotations["10.0.1.1"]["critical"] is True
        assert annotations["10.0.1.1"]["notes"] == "Core router - do not modify"
        assert annotations["10.0.1.1"]["tags"] == ["production", "critical-infra"]
        assert annotations["10.0.1.1"]["custom_fields"]["location"] == "Data Center A"
        assert "last_updated" in annotations["10.0.1.1"]

    def test_update_annotation(self, annotator):
        """Test updating existing annotation"""
        # Initial annotation
        annotator.annotate_device("10.0.1.1", critical=True, notes="Initial note")

        # Update annotation
        annotator.annotate_device("10.0.1.1", notes="Updated note", tags=["updated"])

        annotations = annotator.get_annotations()
        assert annotations["10.0.1.1"]["critical"] is True  # Preserved
        assert annotations["10.0.1.1"]["notes"] == "Updated note"  # Updated
        assert annotations["10.0.1.1"]["tags"] == ["updated"]  # Updated

    def test_get_device_annotation(self, annotator):
        """Test getting single device annotation"""
        annotator.annotate_device("10.0.1.1", critical=True, notes="Test")

        annotation = annotator.get_device_annotation("10.0.1.1")
        assert annotation["critical"] is True
        assert annotation["notes"] == "Test"

        # Non-existent device
        assert annotator.get_device_annotation("10.0.1.99") == {}

    def test_remove_annotation(self, annotator):
        """Test removing annotation"""
        annotator.annotate_device("10.0.1.1", critical=True)
        assert "10.0.1.1" in annotator.get_annotations()

        result = annotator.remove_annotation("10.0.1.1")
        assert result is True
        assert "10.0.1.1" not in annotator.get_annotations()

        # Remove non-existent
        assert annotator.remove_annotation("10.0.1.99") is False

    def test_apply_annotations(self, annotator, sample_devices):
        """Test applying annotations to device list"""
        # Add annotations
        annotator.annotate_device("10.0.1.1", critical=True, notes="Critical router")
        annotator.annotate_device("10.0.1.2", tags=["database", "production"])

        # Apply to devices
        annotated = annotator.apply_annotations(sample_devices)

        # Check annotations were applied
        router = next(d for d in annotated if d["ip"] == "10.0.1.1")
        assert router["critical"] is True
        assert router["notes"] == "Critical router"

        server = next(d for d in annotated if d["ip"] == "10.0.1.2")
        assert server["tags"] == ["database", "production"]

    def test_search_annotations(self, annotator):
        """Test searching annotations"""
        # Add various annotations
        annotator.annotate_device("10.0.1.1", critical=True, tags=["router", "core"])
        annotator.annotate_device("10.0.1.2", critical=True, tags=["server", "database"])
        annotator.annotate_device("10.0.1.3", critical=False, tags=["workstation"])

        # Search by critical
        critical = annotator.search_annotations(critical=True)
        assert len(critical) == 2
        assert "10.0.1.1" in critical
        assert "10.0.1.2" in critical

        # Search by tag
        routers = annotator.search_annotations(tag="router")
        assert len(routers) == 1
        assert "10.0.1.1" in routers

    def test_export_import_annotations(self, annotator, temp_dir):
        """Test export and import functionality"""
        # Add annotations
        annotator.annotate_device("10.0.1.1", critical=True, notes="Test")
        annotator.annotate_device("10.0.1.2", tags=["production"])

        # Export
        export_file = temp_dir / "export.json"
        result = annotator.export_annotations(export_file)
        assert result is True
        assert export_file.exists()

        # Create new annotator and import
        new_annotator = DeviceAnnotator(base_dir=temp_dir / "new")
        result = new_annotator.import_annotations(export_file)
        assert result is True

        # Verify imported data
        annotations = new_annotator.get_annotations()
        assert len(annotations) == 2
        assert annotations["10.0.1.1"]["critical"] is True
        assert annotations["10.0.1.2"]["tags"] == ["production"]

    def test_persistence(self, temp_dir):
        """Test annotation persistence across instances"""
        # First instance
        annotator1 = DeviceAnnotator(base_dir=temp_dir)
        annotator1.annotate_device("10.0.1.1", critical=True)

        # Second instance
        annotator2 = DeviceAnnotator(base_dir=temp_dir)
        annotations = annotator2.get_annotations()
        assert "10.0.1.1" in annotations
        assert annotations["10.0.1.1"]["critical"] is True

    def test_bulk_operations(self, annotator):
        """Test bulk annotation operations"""
        devices = ["10.0.1.1", "10.0.1.2", "10.0.1.3"]

        # Bulk annotate
        for ip in devices:
            annotator.annotate_device(ip, tags=["bulk-tagged"])

        # Verify
        annotations = annotator.get_annotations()
        assert len(annotations) == 3
        for ip in devices:
            assert annotations[ip]["tags"] == ["bulk-tagged"]
