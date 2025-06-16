"""
Unit tests for friendly error messages
"""

import pytest
from utils.friendly_errors import (
    FriendlyError,
    get_friendly_error,
    handle_scanner_error,
    handle_network_error,
    format_error_for_user,
)


class TestFriendlyError:
    """Test the FriendlyError class"""

    def test_friendly_error_creation(self):
        """Test creating a FriendlyError"""
        error = FriendlyError(
            technical_msg="Technical error details",
            user_msg="User-friendly message",
            suggestion="Try this solution",
        )
        assert error.technical_msg == "Technical error details"
        assert error.user_msg == "User-friendly message"
        assert error.suggestion == "Try this solution"

    def test_friendly_error_str_with_suggestion(self):
        """Test string representation with suggestion"""
        error = FriendlyError(
            technical_msg="Tech error",
            user_msg="User message",
            suggestion="Do this",
        )
        assert str(error) == "User message\n💡 Suggestion: Do this"

    def test_friendly_error_str_without_suggestion(self):
        """Test string representation without suggestion"""
        error = FriendlyError(
            technical_msg="Tech error",
            user_msg="User message",
        )
        assert str(error) == "User message"


class TestErrorMessageLookup:
    """Test error message lookup functions"""

    def test_get_friendly_error_known_key(self):
        """Test getting a known error message"""
        result = get_friendly_error("nmap_not_found")
        assert "Nmap is not installed" in result["user_message"]
        assert "sudo apt install nmap" in result["suggestion"]

    def test_get_friendly_error_unknown_key(self):
        """Test getting error message for unknown key"""
        result = get_friendly_error("unknown_error_key")
        assert "unexpected error occurred" in result["user_message"]

    def test_get_friendly_error_with_formatting(self):
        """Test error message with format parameters"""
        result = get_friendly_error("scanner_not_found", scanner="custom-scanner")
        assert "custom-scanner" in result["suggestion"]


class TestScannerErrorHandling:
    """Test scanner-specific error handling"""

    def test_handle_scanner_not_found_error(self):
        """Test handling scanner not found error"""
        original_error = Exception("nmap: command not found")
        friendly_error = handle_scanner_error("nmap", original_error)
        
        assert isinstance(friendly_error, FriendlyError)
        assert "Nmap is not installed" in str(friendly_error)
        assert "sudo apt install nmap" in str(friendly_error)

    def test_handle_masscan_not_found(self):
        """Test handling masscan not found"""
        original_error = Exception("masscan: not found")
        friendly_error = handle_scanner_error("masscan", original_error)
        
        assert "Masscan is not installed" in str(friendly_error)

    def test_handle_permission_error(self):
        """Test handling permission denied error"""
        original_error = Exception("Operation not permitted")
        friendly_error = handle_scanner_error("nmap", original_error)
        
        # Check that it returns appropriate permission error
        assert isinstance(friendly_error, FriendlyError)
        error_str = str(friendly_error)
        assert "privileges" in error_str.lower() or "permission" in error_str.lower()
        assert "sudo" in error_str

    def test_handle_network_unreachable(self):
        """Test handling network unreachable error"""
        original_error = Exception("Network is unreachable")
        friendly_error = handle_scanner_error("nmap", original_error)
        
        assert "Cannot reach the specified network" in str(friendly_error)

    def test_handle_generic_scan_error(self):
        """Test handling generic scan error"""
        original_error = Exception("Some other error")
        friendly_error = handle_scanner_error("nmap", original_error)
        
        assert "scan encountered an error" in str(friendly_error)


class TestNetworkErrorHandling:
    """Test network-specific error handling"""

    def test_handle_invalid_target_error(self):
        """Test handling invalid target error"""
        original_error = Exception("Could not parse target")
        friendly_error = handle_network_error(original_error, "bad-target")
        
        assert isinstance(friendly_error, FriendlyError)
        assert "network target format is invalid" in str(friendly_error)

    def test_handle_unreachable_network(self):
        """Test handling unreachable network"""
        original_error = Exception("Network unreachable")
        friendly_error = handle_network_error(original_error)
        
        assert "Cannot reach the specified network" in str(friendly_error)

    def test_handle_no_hosts_found(self):
        """Test handling no hosts found"""
        original_error = Exception("No hosts found")
        friendly_error = handle_network_error(original_error)
        
        assert "No devices were found" in str(friendly_error)


class TestErrorFormatting:
    """Test general error formatting"""

    def test_format_friendly_error(self):
        """Test formatting a FriendlyError"""
        error = FriendlyError(
            technical_msg="Tech",
            user_msg="User friendly",
            suggestion="Try this",
        )
        result = format_error_for_user(error)
        assert result == "User friendly\n💡 Suggestion: Try this"

    def test_format_permission_error(self):
        """Test formatting permission error"""
        error = Exception("Permission denied")
        result = format_error_for_user(error)
        assert "Permission denied" in result
        assert "Try running with sudo" in result

    def test_format_not_found_error(self):
        """Test formatting not found error"""
        error = Exception("Command not found")
        result = format_error_for_user(error)
        assert "Required tool not found" in result

    def test_format_timeout_error(self):
        """Test formatting timeout error"""
        error = Exception("Operation timeout")
        result = format_error_for_user(error)
        assert "Operation timed out" in result

    def test_format_connection_error(self):
        """Test formatting connection error"""
        error = Exception("Connection refused")
        result = format_error_for_user(error)
        assert "Connection error" in result

    def test_format_generic_error(self):
        """Test formatting generic error"""
        error = Exception("Something went wrong")
        result = format_error_for_user(error)
        assert "Error: Something went wrong" in result


class TestErrorMessageContent:
    """Test the content of error messages"""

    def test_all_error_messages_have_user_message(self):
        """Test that all error messages have user messages"""
        from utils.friendly_errors import ERROR_MESSAGES
        
        for key, value in ERROR_MESSAGES.items():
            assert "user" in value
            assert len(value["user"]) > 0

    def test_suggestions_are_helpful(self):
        """Test that suggestions are actionable"""
        from utils.friendly_errors import ERROR_MESSAGES
        
        # Check some key suggestions
        assert "sudo apt install" in ERROR_MESSAGES["nmap_not_found"]["suggestion"]
        assert "sudo python3" in ERROR_MESSAGES["sudo_required"]["suggestion"]
        assert "Check" in ERROR_MESSAGES["network_unreachable"]["suggestion"]