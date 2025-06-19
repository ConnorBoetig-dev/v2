"""
Base exporter interface and abstract implementation.

This module defines the contract that all exporters must follow,
ensuring consistent behavior across different export formats.
"""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Optional

from ...core.models.scan_result import ScanResult


class ExportError(Exception):
    """Raised when export operation fails."""

    pass


class Exporter(ABC):
    """
    Abstract base class for all exporters.

    This interface ensures that all export implementations provide
    consistent functionality while allowing format-specific optimizations.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize exporter with optional configuration.

        Args:
            config: Format-specific configuration options
        """
        self.config = config or {}

    @abstractmethod
    def export(self, scan_result: ScanResult, output_path: Path) -> None:
        """
        Export scan results to the specified file.

        Args:
            scan_result: Scan results to export
            output_path: Path where to save the export

        Raises:
            ExportError: If export fails
        """
        pass

    @abstractmethod
    def get_file_extension(self) -> str:
        """
        Get the default file extension for this format.

        Returns:
            File extension including the dot (e.g., '.json')
        """
        pass

    @abstractmethod
    def supports_streaming(self) -> bool:
        """
        Check if this exporter supports streaming large datasets.

        Returns:
            True if streaming is supported, False otherwise
        """
        pass

    def validate_output_path(self, output_path: Path) -> None:
        """
        Validate the output path before export.

        Args:
            output_path: Path to validate

        Raises:
            ExportError: If path is invalid
        """
        # Ensure parent directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Check if we can write to the location
        if output_path.exists() and not output_path.is_file():
            raise ExportError(f"Output path is not a file: {output_path}")

        # Validate extension if strict mode
        if self.config.get("strict_extension", True):
            expected_ext = self.get_file_extension()
            if output_path.suffix != expected_ext:
                raise ExportError(
                    f"Invalid file extension. Expected {expected_ext}, " f"got {output_path.suffix}"
                )

    def prepare_export_data(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Prepare scan data for export with common transformations.

        Args:
            scan_result: Raw scan results

        Returns:
            Prepared data dictionary
        """
        return {
            "metadata": {
                "scan_id": scan_result.metadata.scan_id,
                "scan_type": scan_result.metadata.scan_type.value,
                "start_time": scan_result.metadata.start_time.isoformat(),
                "end_time": scan_result.metadata.end_time.isoformat(),
                "duration": (
                    scan_result.metadata.end_time - scan_result.metadata.start_time
                ).total_seconds(),
                "targets": scan_result.metadata.targets,
                "total_devices": scan_result.metadata.total_devices,
                "scanner_used": scan_result.metadata.scanner_used,
            },
            "devices": [device.to_dict() for device in scan_result.devices],
            "summary": self._generate_summary(scan_result),
            "changes": scan_result.changes,
        }

    def _generate_summary(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Generate summary statistics for the scan."""
        devices = scan_result.devices

        # Device type distribution
        type_distribution = {}
        for device in devices:
            device_type = device.device_type.value
            type_distribution[device_type] = type_distribution.get(device_type, 0) + 1

        # Vulnerability summary
        vuln_summary = {
            "total": sum(len(d.vulnerabilities) for d in devices),
            "critical": sum(
                1 for d in devices for v in d.vulnerabilities if v.severity.lower() == "critical"
            ),
            "high": sum(
                1 for d in devices for v in d.vulnerabilities if v.severity.lower() == "high"
            ),
            "devices_with_vulns": sum(1 for d in devices if d.vulnerabilities),
        }

        # Service summary
        all_services = {}
        for device in devices:
            for service in device.get_service_names():
                all_services[service] = all_services.get(service, 0) + 1

        return {
            "device_types": type_distribution,
            "vulnerabilities": vuln_summary,
            "top_services": dict(
                sorted(all_services.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "critical_devices": sum(1 for d in devices if d.is_critical),
            "total_open_ports": sum(len(d.open_ports) for d in devices),
        }
