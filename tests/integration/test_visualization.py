#!/usr/bin/env python3
"""
Test suite for utils/visualization.py
"""

import pytest
import json
from utils.visualization import MapGenerator


class TestMapGenerator:
    """Test MapGenerator class"""

    @pytest.fixture
    def visualizer(self):
        """Create visualizer instance for testing"""
        return MapGenerator()

    @pytest.fixture
    def sample_devices(self):
        """Sample device list for visualization"""
        return [
            {
                "ip": "10.0.1.1",
                "hostname": "router01",
                "type": "router",
                "mac": "00:11:22:33:44:55",
                "critical": True,
            },
            {
                "ip": "10.0.1.2",
                "hostname": "switch01",
                "type": "switch",
                "mac": "00:11:22:33:44:56",
            },
            {
                "ip": "10.0.1.3",
                "hostname": "switch02",
                "type": "switch",
                "mac": "00:11:22:33:44:57",
            },
            {
                "ip": "10.0.2.1",
                "hostname": "web01",
                "type": "web_server",
                "mac": "00:11:22:33:44:58",
            },
            {
                "ip": "10.0.2.2",
                "hostname": "db01",
                "type": "database",
                "mac": "00:11:22:33:44:59",
                "critical": True,
            },
            {
                "ip": "10.0.3.1",
                "hostname": "ws01",
                "type": "workstation",
                "mac": "00:11:22:33:44:60",
            },
            {
                "ip": "10.0.3.2",
                "hostname": "ws02",
                "type": "workstation",
                "mac": "00:11:22:33:44:61",
            },
        ]

    @pytest.fixture
    def sample_flow_matrix(self):
        """Sample traffic flow matrix"""
        return {
            "10.0.3.1": {"10.0.2.1": 100, "10.0.2.2": 50},
            "10.0.3.2": {"10.0.2.1": 200},
            "10.0.2.1": {"10.0.2.2": 500},
        }

    def test_generate_topology_data(self, visualizer, sample_devices):
        """Test topology data generation"""
        data = visualizer.generate_topology_data(sample_devices)

        assert "nodes" in data
        assert "links" in data
        assert len(data["nodes"]) == len(sample_devices)

        # Check node properties
        router = next(n for n in data["nodes"] if n["id"] == "10.0.1.1")
        assert router["label"] == "router01"
        assert router["type"] == "router"
        assert router["group"] == "infrastructure"
        assert router["critical"] is True

        # Check links exist
        assert len(data["links"]) > 0

        # Verify link structure
        for link in data["links"]:
            assert "source" in link
            assert "target" in link
            assert "type" in link

    def test_node_grouping(self, visualizer, sample_devices):
        """Test device grouping logic"""
        data = visualizer.generate_topology_data(sample_devices)

        # Count groups
        groups = {}
        for node in data["nodes"]:
            group = node["group"]
            groups[group] = groups.get(group, 0) + 1

        assert groups["infrastructure"] == 3  # router + 2 switches
        assert groups["servers"] == 2  # web + database
        assert groups["endpoints"] == 2  # 2 workstations

    def test_link_generation(self, visualizer, sample_devices):
        """Test network link generation"""
        data = visualizer.generate_topology_data(sample_devices)
        links = data["links"]

        # Find infrastructure links
        infra_links = [l for l in links if l["type"] == "infrastructure"]
        assert len(infra_links) > 0

        # Verify switches connect to router
        switch_ips = ["10.0.1.2", "10.0.1.3"]
        for switch_ip in switch_ips:
            link_exists = any(
                (l["source"] == "10.0.1.1" and l["target"] == switch_ip)
                or (l["source"] == switch_ip and l["target"] == "10.0.1.1")
                for l in infra_links
            )
            assert link_exists

    def test_generate_traffic_flow_data(self, visualizer, sample_devices, sample_flow_matrix):
        """Test traffic flow data generation"""
        data = visualizer.generate_traffic_flow_data(sample_devices, sample_flow_matrix)

        assert "nodes" in data
        assert "links" in data

        # Check traffic links
        traffic_links = [l for l in data["links"] if l.get("traffic", 0) > 0]
        assert len(traffic_links) == 3  # Based on flow matrix

        # Verify traffic values
        ws1_to_web = next(
            l for l in traffic_links if l["source"] == "10.0.3.1" and l["target"] == "10.0.2.1"
        )
        assert ws1_to_web["traffic"] == 100
        assert ws1_to_web["type"] == "traffic"

    def test_calculate_node_importance(self, visualizer, sample_devices, sample_flow_matrix):
        """Test node importance calculation"""
        data = visualizer.generate_traffic_flow_data(sample_devices, sample_flow_matrix)

        # Web server should have high importance (receives most traffic)
        web_node = next(n for n in data["nodes"] if n["id"] == "10.0.2.1")
        db_node = next(n for n in data["nodes"] if n["id"] == "10.0.2.2")
        ws_node = next(n for n in data["nodes"] if n["id"] == "10.0.3.1")

        assert web_node["size"] > ws_node["size"]  # More traffic
        assert db_node["critical"] is True  # Critical flag preserved

    def test_generate_3d_topology(self, visualizer, sample_devices):
        """Test 3D topology generation"""
        data = visualizer.generate_3d_topology(sample_devices)

        assert "nodes" in data
        assert "links" in data

        # Check 3D coordinates
        for node in data["nodes"]:
            assert "x" in node
            assert "y" in node
            assert "z" in node
            assert isinstance(node["x"], (int, float))
            assert isinstance(node["y"], (int, float))
            assert isinstance(node["z"], (int, float))

        # Check layer assignment
        router = next(n for n in data["nodes"] if n["type"] == "router")
        workstation = next(n for n in data["nodes"] if n["type"] == "workstation")

        # Different device types should be on different layers (z-axis)
        assert router["z"] != workstation["z"]

    def test_empty_device_list(self, visualizer):
        """Test handling of empty device list"""
        data = visualizer.generate_topology_data([])
        assert data["nodes"] == []
        assert data["links"] == []

    def test_single_device(self, visualizer):
        """Test handling of single device"""
        devices = [{"ip": "10.0.1.1", "hostname": "lonely", "type": "router"}]
        data = visualizer.generate_topology_data(devices)

        assert len(data["nodes"]) == 1
        assert len(data["links"]) == 0  # No links for single device

    def test_unknown_device_types(self, visualizer):
        """Test handling of unknown device types"""
        devices = [
            {"ip": "10.0.1.1", "hostname": "unknown1", "type": "unknown"},
            {"ip": "10.0.1.2", "hostname": "unknown2", "type": "mysterious"},
            {"ip": "10.0.1.3", "hostname": "router", "type": "router"},
        ]

        data = visualizer.generate_topology_data(devices)

        # Should still generate valid topology
        assert len(data["nodes"]) == 3

        # Unknown devices should be in 'other' group
        unknown = next(n for n in data["nodes"] if n["id"] == "10.0.1.1")
        assert unknown["group"] == "other"

    def test_subnet_detection(self, visualizer, sample_devices):
        """Test subnet-based grouping"""
        data = visualizer.generate_topology_data(sample_devices)

        # Devices in same subnet should have connections
        ws1 = "10.0.3.1"
        ws2 = "10.0.3.2"

        # Both workstations should connect to same switch
        ws1_links = [l for l in data["links"] if ws1 in [l["source"], l["target"]]]
        ws2_links = [l for l in data["links"] if ws2 in [l["source"], l["target"]]]

        assert len(ws1_links) > 0
        assert len(ws2_links) > 0
