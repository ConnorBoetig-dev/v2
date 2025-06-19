#!/usr/bin/env python3
"""
Integration tests for NetworkMapper v2
"""

import pytest
import json
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch

from mapper import NetworkMapper
from core.scanner import NetworkScanner
from core.classifier import DeviceClassifier
from core.parser import ScanParser
from core.tracker import ChangeTracker
from core.annotator import DeviceAnnotator
from utils.visualization import MapGenerator


class TestIntegration:
    """Integration tests combining multiple components"""

    @pytest.fixture
    def temp_output_dir(self):
        """Create temporary output directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def mock_scan_data(self):
        """Mock scan data for testing"""
        return [
            {
                "ip": "10.0.1.1",
                "mac": "00:11:22:33:44:55",
                "hostname": "router01",
                "open_ports": [22, 80, 443, 161],
                "services": ["ssh", "http", "https", "snmp"],
                "os": "Cisco IOS",
                "vendor": "Cisco",
            },
            {
                "ip": "10.0.1.2",
                "mac": "00:11:22:33:44:56",
                "hostname": "web01",
                "open_ports": [22, 80, 443],
                "services": ["ssh", "http", "https"],
                "os": "Ubuntu 20.04",
                "vendor": "Dell",
            },
            {
                "ip": "10.0.1.3",
                "mac": "00:11:22:33:44:57",
                "hostname": "db01",
                "open_ports": [22, 3306],
                "services": ["ssh", "mysql"],
                "os": "CentOS 8",
                "vendor": "HP",
            },
        ]

    def test_full_scan_pipeline(self, temp_output_dir):
        """Test complete scan pipeline"""
        scanner = NetworkScanner()
        classifier = DeviceClassifier()
        parser = ScanParser()

        # Mock scan execution
        raw_output = """
        Nmap scan report for 10.0.1.1
        Host is up (0.001s latency).
        PORT     STATE SERVICE
        22/tcp   open  ssh
        80/tcp   open  http
        MAC Address: 00:11:22:33:44:55 (Cisco Systems)
        """

        with patch.object(scanner, "scan_network") as mock_scan:
            mock_scan.return_value = parser.parse_nmap_text(raw_output)

            # Run scan
            devices = scanner.scan_network("10.0.1.0/24", profile="discovery")

            # Classify devices
            for device in devices:
                device["type"], device["confidence"] = classifier.classify_device(device)

            assert len(devices) == 1
            assert devices[0]["type"] == "router"
            assert devices[0]["confidence"] > 0.5

    def test_change_tracking_workflow(self, mock_scan_data):
        """Test change tracking between scans"""
        tracker = ChangeTracker()

        # Initial scan
        old_devices = mock_scan_data[:2]  # First two devices

        # New scan with changes
        new_devices = [
            mock_scan_data[0],  # Router unchanged
            {
                **mock_scan_data[1],
                "open_ports": [22, 80, 443, 8080],  # Added port 8080
                "services": ["ssh", "http", "https", "http-proxy"],
            },
            mock_scan_data[2],  # Database server (new)
        ]

        # Track changes
        changes = tracker.track_changes(old_devices, new_devices)

        assert len(changes["new_devices"]) == 1
        assert changes["new_devices"][0]["hostname"] == "db01"

        assert len(changes["modified_devices"]) == 1
        assert changes["modified_devices"][0]["hostname"] == "web01"
        assert 8080 in changes["modified_devices"][0]["changes"]["open_ports"]["added"]

        assert len(changes["missing_devices"]) == 0

    def test_annotation_workflow(self, mock_scan_data, temp_output_dir):
        """Test device annotation workflow"""
        annotator = DeviceAnnotator(base_dir=temp_output_dir)

        # Annotate devices
        annotator.annotate_device("10.0.1.1", critical=True, notes="Core router")
        annotator.annotate_device("10.0.1.3", tags=["database", "production"])

        # Apply annotations
        annotated_devices = annotator.apply_annotations(mock_scan_data)

        # Verify annotations
        router = next(d for d in annotated_devices if d["ip"] == "10.0.1.1")
        assert router["critical"] is True
        assert router["notes"] == "Core router"

        db = next(d for d in annotated_devices if d["ip"] == "10.0.1.3")
        assert db["tags"] == ["database", "production"]

    def test_visualization_workflow(self, mock_scan_data):
        """Test visualization data generation"""
        visualizer = MapGenerator()
        classifier = DeviceClassifier()

        # Classify devices
        for device in mock_scan_data:
            device["type"], _ = classifier.classify_device(device)

        # Generate topology
        topology = visualizer.generate_topology_data(mock_scan_data)

        assert len(topology["nodes"]) == 3
        assert len(topology["links"]) > 0

        # Verify node properties
        router_node = next(n for n in topology["nodes"] if n["id"] == "10.0.1.1")
        assert router_node["type"] == "router"
        assert router_node["group"] == "infrastructure"

    @patch("mapper.NetworkScanner")
    @patch("mapper.DeviceClassifier")
    def test_mapper_integration(self, mock_classifier_class, mock_scanner_class, temp_output_dir):
        """Test NetworkMapper integration"""
        # Setup mocks
        mock_scanner = Mock()
        mock_classifier = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_classifier_class.return_value = mock_classifier

        # Create mapper with temp directory
        with patch("mapper.OUTPUT_DIR", temp_output_dir):
            mapper = NetworkMapper()

            # Mock scan results
            scan_results = [
                {
                    "ip": "10.0.1.1",
                    "hostname": "test-device",
                    "open_ports": [22, 80],
                    "type": "router",
                }
            ]

            mock_scanner.scan_network.return_value = scan_results
            mock_classifier.classify_device.return_value = ("router", 0.9)

            # Test scan
            with patch("mapper.NetworkMapper._save_scan_results") as mock_save:
                devices = mapper.scan_network("10.0.1.0/24")
                assert len(devices) == 1
                assert devices[0]["type"] == "router"
                mock_save.assert_called_once()

    def test_report_generation(self, mock_scan_data, temp_output_dir):
        """Test report generation"""
        with patch("mapper.OUTPUT_DIR", temp_output_dir):
            mapper = NetworkMapper()

            # Generate reports
            with patch("mapper.NetworkMapper.generate_html_report") as mock_report:
                mock_report.return_value = ["report1.html", "report2.html"]

                reports = mapper.generate_html_report(mock_scan_data)
                assert len(reports) == 2
                mock_report.assert_called_once()

    def test_passive_analysis_integration(self, mock_scan_data):
        """Test passive traffic analysis integration"""
        flow_matrix = {
            "10.0.1.2": {"10.0.1.3": 100},  # Web to DB traffic
            "10.0.1.3": {"10.0.1.2": 50},  # DB to Web traffic
        }

        visualizer = MapGenerator()
        traffic_data = visualizer.generate_traffic_flow_data(mock_scan_data, flow_matrix)

        assert len(traffic_data["nodes"]) == 3
        assert len(traffic_data["links"]) > 0

        # Verify traffic links
        traffic_links = [l for l in traffic_data["links"] if l.get("traffic", 0) > 0]
        assert len(traffic_links) == 2

    def test_error_handling(self):
        """Test error handling across components"""
        scanner = NetworkScanner()
        classifier = DeviceClassifier()
        parser = ScanParser()

        # Test with invalid input
        assert parser.parse_nmap_text("invalid data") == []

        # Test with empty device
        device_type, confidence = classifier.classify_device({})
        assert device_type == "unknown"
        assert confidence == 0.0

        # Test with invalid target
        with patch.object(scanner, "_check_scanner", return_value=False):
            result = scanner.scan_network("invalid-target")
            assert result == []
