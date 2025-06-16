"""
Abstract scanner interface defining the contract for all scanner implementations.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from enum import Enum


class ScanType(Enum):
    """Enumeration of available scan types."""
    DISCOVERY = "discovery"
    INVENTORY = "inventory"
    DEEP = "deep"
    ARP = "arp"
    FAST = "fast"


@dataclass
class ScanOptions:
    """Configuration options for a scan."""
    scan_type: ScanType
    targets: List[str]
    interface: Optional[str] = None
    timeout: int = 300
    max_rate: Optional[int] = None
    ports: Optional[str] = None
    exclude_targets: Optional[List[str]] = None
    sudo_password: Optional[str] = None
    extra_args: Optional[List[str]] = None


@dataclass
class ScanProgress:
    """Progress information for ongoing scans."""
    current: int
    total: int
    percentage: float
    phase: str
    message: str
    elapsed_time: float
    estimated_remaining: Optional[float] = None


class Scanner(ABC):
    """
    Abstract base class for network scanners.
    
    This interface ensures all scanner implementations provide consistent
    behavior while allowing for tool-specific optimizations.
    """
    
    def __init__(self, progress_callback: Optional[Callable[[ScanProgress], None]] = None):
        """
        Initialize scanner with optional progress callback.
        
        Args:
            progress_callback: Function to call with progress updates
        """
        self.progress_callback = progress_callback
        self._is_cancelled = False
    
    @abstractmethod
    def scan(self, options: ScanOptions) -> Dict[str, Any]:
        """
        Execute a network scan with the given options.
        
        Args:
            options: Scan configuration options
            
        Returns:
            Dictionary containing scan results
            
        Raises:
            ScannerError: If scan fails
            PermissionError: If insufficient permissions
        """
        pass
    
    @abstractmethod
    def validate_options(self, options: ScanOptions) -> None:
        """
        Validate scan options before execution.
        
        Args:
            options: Scan configuration to validate
            
        Raises:
            ValueError: If options are invalid
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the scanner tool is available on the system.
        
        Returns:
            True if scanner can be used, False otherwise
        """
        pass
    
    @abstractmethod
    def get_required_permissions(self, options: ScanOptions) -> List[str]:
        """
        Get list of required permissions for the scan type.
        
        Args:
            options: Scan configuration
            
        Returns:
            List of required permissions (e.g., ['sudo', 'cap_net_raw'])
        """
        pass
    
    def cancel(self) -> None:
        """Cancel the ongoing scan."""
        self._is_cancelled = True
    
    def update_progress(self, progress: ScanProgress) -> None:
        """
        Update scan progress if callback is registered.
        
        Args:
            progress: Current progress information
        """
        if self.progress_callback and not self._is_cancelled:
            self.progress_callback(progress)
    
    @abstractmethod
    def get_version(self) -> str:
        """
        Get the version of the scanner tool.
        
        Returns:
            Version string
        """
        pass