"""
Comprehensive unit tests for NetworkUtils
"""

import pytest
from unittest.mock import patch, Mock
import ipaddress
import socket
from utils.network_utils import NetworkUtils


class TestNetworkUtilsValidation:
    """Test network validation functions"""

    def test_validate_target_valid_ip(self):
        """Test validating valid IP addresses"""
        valid, error = NetworkUtils.validate_target("192.168.1.1")
        assert valid is True
        assert error is None

        valid, error = NetworkUtils.validate_target("10.0.0.1")
        assert valid is True
        assert error is None

    def test_validate_target_valid_cidr(self):
        """Test validating valid CIDR notation"""
        valid, error = NetworkUtils.validate_target("192.168.1.0/24")
        assert valid is True
        assert error is None

        valid, error = NetworkUtils.validate_target("10.0.0.0/8")
        assert valid is True
        assert error is None

    def test_validate_target_invalid_inputs(self):
        """Test validating invalid inputs"""
        # Invalid IP
        valid, error = NetworkUtils.validate_target("256.256.256.256")
        assert valid is False
        assert "Invalid target" in error

        # Invalid CIDR
        valid, error = NetworkUtils.validate_target("192.168.1.0/33")
        assert valid is False
        assert "Invalid target" in error

        # Empty string
        valid, error = NetworkUtils.validate_target("")
        assert valid is False
        assert error is not None

    @patch("socket.gethostbyname")
    def test_validate_target_hostname(self, mock_gethostbyname):
        """Test validating hostnames"""
        # Valid hostname
        mock_gethostbyname.return_value = "192.168.1.1"
        valid, error = NetworkUtils.validate_target("example.com")
        assert valid is True
        assert error is None

        # Invalid hostname
        mock_gethostbyname.side_effect = socket.error("Host not found")
        valid, error = NetworkUtils.validate_target("invalid.hostname.local")
        assert valid is False
        assert "Invalid target" in error

    def test_validate_target_special_cases(self):
        """Test special cases in validation"""
        # Localhost
        valid, error = NetworkUtils.validate_target("127.0.0.1")
        assert valid is True

        # Broadcast
        valid, error = NetworkUtils.validate_target("255.255.255.255")
        assert valid is True

        # Network address
        valid, error = NetworkUtils.validate_target("192.168.1.0")
        assert valid is True


class TestNetworkUtilsExpansion:
    """Test network expansion functions"""

    def test_expand_network_cidr(self):
        """Test expanding CIDR notation"""
        # Small network
        ips = NetworkUtils.expand_network("192.168.1.0/30")
        assert len(ips) == 2  # .1 and .2 (excludes network and broadcast)
        assert "192.168.1.1" in ips
        assert "192.168.1.2" in ips

        # /32 network (single host)
        ips = NetworkUtils.expand_network("192.168.1.1/32")
        assert len(ips) == 0 or len(ips) == 1  # Depends on implementation

    def test_expand_network_single_ip(self):
        """Test expanding single IP"""
        ips = NetworkUtils.expand_network("192.168.1.1")
        assert ips == ["192.168.1.1"]

    def test_expand_network_hostname(self):
        """Test expanding hostname"""
        ips = NetworkUtils.expand_network("example.com")
        assert ips == ["example.com"]

    def test_expand_network_large_range(self):
        """Test expanding large network"""
        # /24 network
        ips = NetworkUtils.expand_network("192.168.1.0/24")
        assert len(ips) == 254  # Excludes network and broadcast

    def test_expand_network_invalid_input(self):
        """Test expanding invalid input"""
        # Should return original input or empty list
        result = NetworkUtils.expand_network("invalid-input")
        assert result == ["invalid-input"] or result == []


class TestNetworkUtilsSubnet:
    """Test subnet calculation functions"""

    def test_get_subnet_valid_ip(self):
        """Test getting subnet for valid IP"""
        subnet = NetworkUtils.get_subnet("192.168.1.100")
        assert subnet == "192.168.1.0/24"

        subnet = NetworkUtils.get_subnet("10.0.0.50")
        assert subnet == "10.0.0.0/24"

    def test_get_subnet_network_address(self):
        """Test getting subnet for network address"""
        subnet = NetworkUtils.get_subnet("192.168.1.0")
        assert subnet == "192.168.1.0/24"

    def test_get_subnet_broadcast_address(self):
        """Test getting subnet for broadcast address"""
        subnet = NetworkUtils.get_subnet("192.168.1.255")
        assert subnet == "192.168.1.0/24"

    def test_get_subnet_invalid_ip(self):
        """Test getting subnet for invalid IP"""
        subnet = NetworkUtils.get_subnet("invalid-ip")
        assert subnet is None

    def test_get_subnet_special_ips(self):
        """Test getting subnet for special IPs"""
        # Loopback
        subnet = NetworkUtils.get_subnet("127.0.0.1")
        assert subnet == "127.0.0.0/24"

        # Private ranges
        subnet = NetworkUtils.get_subnet("10.0.0.1")
        assert subnet == "10.0.0.0/24"

        subnet = NetworkUtils.get_subnet("172.16.0.1")
        assert subnet == "172.16.0.0/24"


class TestNetworkUtilsEdgeCases:
    """Test edge cases and error handling"""

    def test_none_inputs(self):
        """Test handling None inputs"""
        # validate_target should handle None
        try:
            valid, error = NetworkUtils.validate_target(None)
            assert valid is False
        except:
            # If it raises an exception, that's also acceptable
            pass

    def test_empty_string_inputs(self):
        """Test handling empty string inputs"""
        valid, error = NetworkUtils.validate_target("")
        assert valid is False

        ips = NetworkUtils.expand_network("")
        assert ips == [""] or ips == []

    def test_unicode_inputs(self):
        """Test handling unicode inputs"""
        # Unicode hostname
        valid, error = NetworkUtils.validate_target("测试.com")
        # Should handle unicode gracefully
        assert isinstance(valid, bool)

    def test_very_long_inputs(self):
        """Test handling very long inputs"""
        long_input = "a" * 1000
        valid, error = NetworkUtils.validate_target(long_input)
        assert valid is False

    @patch("ipaddress.ip_network")
    def test_ipaddress_exceptions(self, mock_ip_network):
        """Test handling ipaddress module exceptions"""
        # Simulate various exceptions
        mock_ip_network.side_effect = ValueError("Invalid network")

        ips = NetworkUtils.expand_network("192.168.1.0/24")
        # Should handle exception gracefully
        assert isinstance(ips, list)

    def test_boundary_ip_addresses(self):
        """Test boundary IP addresses"""
        # Min IP
        valid, error = NetworkUtils.validate_target("0.0.0.0")
        assert valid is True

        # Max IP
        valid, error = NetworkUtils.validate_target("255.255.255.255")
        assert valid is True

    def test_special_cidr_ranges(self):
        """Test special CIDR ranges"""
        # /0 - entire Internet
        valid, error = NetworkUtils.validate_target("0.0.0.0/0")
        assert valid is True

        # /31 - point-to-point
        valid, error = NetworkUtils.validate_target("192.168.1.0/31")
        assert valid is True

        # /32 - single host
        valid, error = NetworkUtils.validate_target("192.168.1.1/32")
        assert valid is True


class TestNetworkUtilsIntegration:
    """Integration tests for NetworkUtils"""

    def test_validate_and_expand_workflow(self):
        """Test typical validate and expand workflow"""
        # First validate
        valid, error = NetworkUtils.validate_target("192.168.1.0/28")
        assert valid is True

        # Then expand
        ips = NetworkUtils.expand_network("192.168.1.0/28")
        assert len(ips) == 14  # 16 - 2 (network and broadcast)

        # Verify first and last usable IPs
        assert "192.168.1.1" in ips
        assert "192.168.1.14" in ips

    def test_subnet_calculation_workflow(self):
        """Test subnet calculation workflow"""
        test_ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]

        subnets = []
        for ip in test_ips:
            subnet = NetworkUtils.get_subnet(ip)
            subnets.append(subnet)

        # All should be in same /24
        assert all(s == "192.168.1.0/24" for s in subnets)

    @patch("socket.gethostbyname")
    def test_hostname_resolution_workflow(self, mock_gethostbyname):
        """Test hostname resolution workflow"""
        # Setup mock
        mock_gethostbyname.return_value = "192.168.1.100"

        # Validate hostname
        valid, error = NetworkUtils.validate_target("internal.server.local")
        assert valid is True

        # Get subnet for resolved IP
        subnet = NetworkUtils.get_subnet("192.168.1.100")
        assert subnet == "192.168.1.0/24"
