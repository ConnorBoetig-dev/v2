"""
User-friendly error messages for NetworkMapper v2
"""

from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)


class FriendlyError(Exception):
    """Base class for user-friendly errors"""

    def __init__(self, technical_msg: str, user_msg: str, suggestion: Optional[str] = None):
        self.technical_msg = technical_msg
        self.user_msg = user_msg
        self.suggestion = suggestion
        super().__init__(user_msg)

    def __str__(self):
        msg = self.user_msg
        if self.suggestion:
            msg += f"\n💡 Suggestion: {self.suggestion}"
        return msg


# Error message mappings for common errors
ERROR_MESSAGES: Dict[str, Dict[str, str]] = {
    # Scanner errors
    "scanner_not_found": {
        "user": "The required network scanner is not installed on your system.",
        "suggestion": "Install the scanner with: sudo apt install {scanner}",
    },
    "nmap_not_found": {
        "user": "Nmap is not installed. This is required for network scanning.",
        "suggestion": "Install with: sudo apt install nmap",
    },
    "masscan_not_found": {
        "user": "Masscan is not installed. This tool speeds up large network scans.",
        "suggestion": "Install with: sudo apt install masscan (or build from source)",
    },
    "arp_scan_not_found": {
        "user": "ARP-scan is not installed. This is needed for local network discovery.",
        "suggestion": "Install with: sudo apt install arp-scan",
    },
    # Permission errors
    "sudo_required": {
        "user": "This scan requires administrator privileges to access network interfaces.",
        "suggestion": "Run with: sudo python3 mapper.py",
    },
    "permission_denied": {
        "user": "Permission denied. You need elevated privileges for this operation.",
        "suggestion": "Try running with sudo or check file permissions",
    },
    # Network errors
    "network_unreachable": {
        "user": "Cannot reach the specified network. The network may be down or blocked.",
        "suggestion": "Check your network connection and firewall settings",
    },
    "invalid_target": {
        "user": "The network target format is invalid.",
        "suggestion": "Use formats like: 192.168.1.0/24, 10.0.0.1-100, or hostname.com",
    },
    "no_hosts_found": {
        "user": "No devices were found on the network.",
        "suggestion": "Verify the network range is correct and devices are powered on",
    },
    # File errors
    "file_not_found": {
        "user": "The requested file could not be found.",
        "suggestion": "Check the file path and ensure it exists",
    },
    "output_dir_error": {
        "user": "Cannot create or access the output directory.",
        "suggestion": "Check write permissions for the output folder",
    },
    # SNMP errors
    "snmp_timeout": {
        "user": "SNMP device did not respond in time.",
        "suggestion": "Check SNMP is enabled on the device and credentials are correct",
    },
    "snmp_auth_failed": {
        "user": "SNMP authentication failed.",
        "suggestion": "Verify SNMP community string or credentials",
    },
    # API errors
    "api_timeout": {
        "user": "External API request timed out.",
        "suggestion": "Check your internet connection or try again later",
    },
    "api_rate_limit": {
        "user": "API rate limit exceeded.",
        "suggestion": "Wait a few minutes before trying again",
    },
    # Scan errors
    "scan_timeout": {
        "user": "The scan is taking longer than expected.",
        "suggestion": "Try scanning a smaller network range or use the Deep Scan option",
    },
    "scan_failed": {
        "user": "The scan encountered an error and could not complete.",
        "suggestion": "Check the logs for details or try a different scan type",
    },
    # General errors
    "unexpected_error": {
        "user": "An unexpected error occurred.",
        "suggestion": "Check the logs for more details or report this issue",
    },
}


def get_friendly_error(error_key: str, **kwargs) -> Dict[str, str]:
    """Get user-friendly error message by key"""
    error_info = ERROR_MESSAGES.get(error_key, ERROR_MESSAGES["unexpected_error"])
    
    # Format the messages with any provided kwargs
    user_msg = error_info["user"].format(**kwargs)
    suggestion = error_info.get("suggestion", "").format(**kwargs)
    
    return {
        "user_message": user_msg,
        "suggestion": suggestion,
    }


def handle_scanner_error(scanner_name: str, error: Exception) -> FriendlyError:
    """Handle scanner-specific errors"""
    error_str = str(error).lower()
    
    if "not found" in error_str or "command not found" in error_str:
        if scanner_name == "nmap":
            err_info = get_friendly_error("nmap_not_found")
        elif scanner_name == "masscan":
            err_info = get_friendly_error("masscan_not_found")
        elif scanner_name == "arp-scan":
            err_info = get_friendly_error("arp_scan_not_found")
        else:
            err_info = get_friendly_error("scanner_not_found", scanner=scanner_name)
    elif "permission" in error_str or "operation not permitted" in error_str:
        err_info = get_friendly_error("sudo_required")
    elif "network is unreachable" in error_str:
        err_info = get_friendly_error("network_unreachable")
    else:
        err_info = get_friendly_error("scan_failed")
    
    return FriendlyError(
        technical_msg=str(error),
        user_msg=err_info["user_message"],
        suggestion=err_info["suggestion"],
    )


def handle_network_error(error: Exception, target: str = "") -> FriendlyError:
    """Handle network-related errors"""
    error_str = str(error).lower()
    
    if "invalid" in error_str or "could not parse" in error_str:
        err_info = get_friendly_error("invalid_target")
    elif "unreachable" in error_str:
        err_info = get_friendly_error("network_unreachable")
    elif "no hosts found" in error_str:
        err_info = get_friendly_error("no_hosts_found")
    else:
        err_info = get_friendly_error("unexpected_error")
    
    return FriendlyError(
        technical_msg=str(error),
        user_msg=err_info["user_message"],
        suggestion=err_info["suggestion"],
    )


def format_error_for_user(error: Exception) -> str:
    """Format any error for user display"""
    if isinstance(error, FriendlyError):
        return str(error)
    
    # Try to make common errors more friendly
    error_str = str(error).lower()
    
    if "permission" in error_str:
        return "❌ Permission denied. Try running with sudo."
    elif "not found" in error_str:
        return "❌ Required tool not found. Check installation instructions."
    elif "timeout" in error_str:
        return "❌ Operation timed out. Try again or use a smaller network range."
    elif "connection" in error_str:
        return "❌ Connection error. Check network connectivity."
    else:
        # Return original error but formatted nicely
        return f"❌ Error: {str(error)}"