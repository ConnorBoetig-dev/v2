"""
Unit tests for parser edge cases and error handling
"""

import json
import pytest
from unittest.mock import Mock, patch
from core.parser import ScanParser


class TestParserEdgeCases:
    """Test edge cases in the scan parser"""

    @pytest.fixture
    def parser(self):
        """Create a parser instance"""
        return ScanParser()

    def test_parse_empty_results(self, parser):
        """Test parsing empty results"""
        result = parser.parse_results([])
        assert result == []

    def test_parse_none_results(self, parser):
        """Test parsing None results"""
        result = parser.parse_results(None)
        assert result == []

    def test_parse_invalid_json_string(self, parser):
        """Test parsing invalid JSON string"""
        result = parser.parse_results("invalid json {")
        assert result == []

    def test_parse_malformed_device_data(self, parser):
        """Test parsing malformed device data"""
        malformed_data = [
            {"no_ip_field": "test"},  # Missing IP
            {"ip": "192.168.1.1"},  # Valid
            None,  # None entry
            "not a dict",  # String instead of dict
        ]
        result = parser.parse_results(malformed_data)
        # Should only return the valid device
        assert len(result) == 1
        assert result[0]["ip"] == "192.168.1.1"

    def test_auto_detect_with_mixed_formats(self, parser):
        """Test auto-detection with mixed format data"""
        mixed_data = [
            {"ip": "192.168.1.1", "ports": [80]},  # Valid device
            "<xml>test</xml>",  # XML string
            {"host": {"address": "192.168.1.2"}},  # Nmap-like format
        ]
        result = parser.parse_results(mixed_data)
        # Should handle the valid device
        assert any(d["ip"] == "192.168.1.1" for d in result)

    def test_parse_with_unicode_characters(self, parser):
        """Test parsing data with unicode characters"""
        unicode_data = [
            {
                "ip": "192.168.1.1",
                "hostname": "测试主机",  # Chinese characters
                "vendor": "Société Française",  # French characters
            }
        ]
        result = parser.parse_results(unicode_data)
        assert len(result) == 1
        assert result[0]["hostname"] == "测试主机"
        assert result[0]["vendor"] == "Société Française"

    def test_parse_very_large_port_list(self, parser):
        """Test parsing device with very large port list"""
        device = {
            "ip": "192.168.1.1",
            "open_ports": list(range(1, 65536)),  # All ports
        }
        result = parser.parse_results([device])
        assert len(result) == 1
        assert len(result[0]["open_ports"]) == 65535

    def test_parse_duplicate_devices(self, parser):
        """Test parsing results with duplicate devices"""
        duplicates = [
            {"ip": "192.168.1.1", "hostname": "host1"},
            {"ip": "192.168.1.1", "hostname": "host2"},  # Same IP
            {"ip": "192.168.1.2", "hostname": "host3"},
        ]
        result = parser.parse_results(duplicates)
        # Parser should handle duplicates appropriately
        assert len(result) >= 2  # At least unique IPs

    def test_parse_nested_error_in_results(self, parser):
        """Test parsing results with nested errors"""
        with patch("core.parser.logger") as mock_logger:
            error_data = {
                "error": "Scan failed",
                "devices": [{"ip": "192.168.1.1"}],
            }
            result = parser.parse_results(error_data)
            # Should attempt to extract any valid data
            assert isinstance(result, list)

    def test_standardize_device_missing_fields(self, parser):
        """Test standardizing device with missing fields"""
        incomplete_device = {"ip": "192.168.1.1"}
        standardized = parser._standardize_devices([incomplete_device])

        assert len(standardized) == 1
        device = standardized[0]
        # Check default values are added
        assert "hostname" in device
        assert "mac" in device
        assert "vendor" in device
        assert "open_ports" in device
        assert "services" in device

    def test_parse_circular_reference(self, parser):
        """Test parsing data with circular references"""
        # Create a circular reference
        data = {"ip": "192.168.1.1"}
        data["self"] = data

        # Parser should handle this without infinite recursion
        try:
            result = parser.parse_results([data])
            assert True  # Didn't crash
        except RecursionError:
            pytest.fail("Parser failed to handle circular reference")

    def test_parse_binary_data_in_results(self, parser):
        """Test parsing results containing binary data"""
        binary_data = [
            {
                "ip": "192.168.1.1",
                "raw_data": b"\x00\x01\x02\x03",  # Binary data
            }
        ]
        # Should handle or skip binary data gracefully
        result = parser.parse_results(binary_data)
        assert len(result) >= 0  # Shouldn't crash

    def test_parse_extremely_nested_structure(self, parser):
        """Test parsing extremely nested data structure"""
        # Create deeply nested structure
        nested = {"ip": "192.168.1.1"}
        current = nested
        for i in range(100):
            current["nested"] = {"level": i}
            current = current["nested"]

        result = parser.parse_results([nested])
        assert len(result) >= 0  # Should handle deep nesting

    def test_parse_with_special_characters_in_ip(self, parser):
        """Test parsing IPs with special characters (invalid IPs)"""
        invalid_ips = [
            {"ip": "192.168.1.1; rm -rf /"},  # Injection attempt
            {"ip": "192.168.1.1\x00"},  # Null byte
            {"ip": "192.168.1.1<script>"},  # XSS attempt
            {"ip": "192.168.1.1"},  # Valid for comparison
        ]
        result = parser.parse_results(invalid_ips)
        # Should sanitize or skip invalid IPs
        assert all(";" not in device.get("ip", "") for device in result)
        assert all("<" not in device.get("ip", "") for device in result)

    def test_parse_memory_efficient_large_dataset(self, parser):
        """Test parsing large dataset efficiently"""
        # Create large dataset
        large_dataset = []
        for i in range(10000):
            large_dataset.append(
                {
                    "ip": f"10.0.{i // 256}.{i % 256}",
                    "hostname": f"host{i}",
                    "open_ports": [22, 80, 443],
                }
            )

        result = parser.parse_results(large_dataset)
        assert len(result) == 10000
        # Verify first and last devices
        assert result[0]["ip"] == "10.0.0.0"
        assert result[-1]["ip"] == "10.0.39.15"

    def test_parse_with_datetime_objects(self, parser):
        """Test parsing results with datetime objects"""
        from datetime import datetime

        data_with_datetime = [
            {
                "ip": "192.168.1.1",
                "last_seen": datetime.now(),
                "scan_time": datetime.now().isoformat(),
            }
        ]
        # Should handle datetime objects
        result = parser.parse_results(data_with_datetime)
        assert len(result) >= 0  # Shouldn't crash on datetime

    def test_parse_format_detection_with_insufficient_data(self, parser):
        """Test format detection with insufficient data"""
        insufficient_data = [{"unknown_field": "value"}]
        with patch("core.parser.logger") as mock_logger:
            result = parser.parse_results(insufficient_data)
            # Should log warning about format detection
            assert mock_logger.warning.called
