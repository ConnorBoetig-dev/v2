"""
Scan orchestration service that coordinates the scanning workflow.

This service acts as the main coordinator for network scans, managing the
interaction between scanners, enrichers, analyzers, and persistence layers.
"""
import logging
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
import asyncio
from concurrent.futures import ThreadPoolExecutor

from ..interfaces.scanner import Scanner, ScanOptions, ScanProgress
from ..interfaces.enricher import Enricher
from ..models.device import Device
from ..models.scan_result import ScanResult, ScanMetadata
from .device_classifier import DeviceClassifier
from .change_tracker import ChangeTracker
from ...infrastructure.persistence.repository import DeviceRepository
from ...utils.exceptions import ScanError, EnrichmentError


logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """
    Orchestrates the complete scanning workflow.

    This service coordinates:
    - Scanner selection and execution
    - Device enrichment (SNMP, DNS, etc.)
    - Device classification
    - Vulnerability analysis
    - Change tracking
    - Data persistence
    """

    def __init__(
        self,
        scanner_factory: "ScannerFactory",
        enrichers: List[Enricher],
        classifier: DeviceClassifier,
        change_tracker: ChangeTracker,
        repository: DeviceRepository,
        vulnerability_analyzer: Optional["VulnerabilityAnalyzer"] = None,
        max_workers: int = 10,
    ):
        """
        Initialize the scan orchestrator.

        Args:
            scanner_factory: Factory for creating scanner instances
            enrichers: List of enricher services
            classifier: Device classification service
            change_tracker: Change tracking service
            repository: Data persistence repository
            vulnerability_analyzer: Optional vulnerability analysis service
            max_workers: Maximum concurrent workers for enrichment
        """
        self.scanner_factory = scanner_factory
        self.enrichers = enrichers
        self.classifier = classifier
        self.change_tracker = change_tracker
        self.repository = repository
        self.vulnerability_analyzer = vulnerability_analyzer
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self._current_scan: Optional[Scanner] = None
        self._is_cancelled = False

    async def execute_scan(
        self,
        options: ScanOptions,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> ScanResult:
        """
        Execute a complete scan workflow.

        Args:
            options: Scan configuration options
            progress_callback: Optional callback for progress updates

        Returns:
            Complete scan result with all devices and metadata

        Raises:
            ScanError: If scan fails
        """
        self._is_cancelled = False
        start_time = datetime.now()

        try:
            # Phase 1: Network Discovery
            await self._update_progress(
                progress_callback, phase="discovery", message="Starting network scan..."
            )

            scanner = self._select_scanner(options)
            self._current_scan = scanner

            # Execute the scan
            raw_results = await self._execute_scanner(scanner, options, progress_callback)

            # Phase 2: Parse and classify devices
            await self._update_progress(
                progress_callback, phase="parsing", message="Processing scan results..."
            )

            devices = await self._parse_results(raw_results, options)

            # Phase 3: Enrich devices
            if self.enrichers and not self._is_cancelled:
                await self._update_progress(
                    progress_callback, phase="enrichment", message="Enriching device information..."
                )
                devices = await self._enrich_devices(devices, progress_callback)

            # Phase 4: Vulnerability analysis
            if self.vulnerability_analyzer and not self._is_cancelled:
                await self._update_progress(
                    progress_callback, phase="vulnerability", message="Analyzing vulnerabilities..."
                )
                devices = await self._analyze_vulnerabilities(devices, progress_callback)

            # Phase 5: Track changes
            if not self._is_cancelled:
                await self._update_progress(
                    progress_callback, phase="tracking", message="Tracking network changes..."
                )
                changes = await self._track_changes(devices, options)
            else:
                changes = None

            # Phase 6: Persist results
            await self._update_progress(
                progress_callback, phase="saving", message="Saving scan results..."
            )

            scan_result = ScanResult(
                devices=devices,
                metadata=ScanMetadata(
                    scan_id=self._generate_scan_id(),
                    scan_type=options.scan_type,
                    start_time=start_time,
                    end_time=datetime.now(),
                    targets=options.targets,
                    total_devices=len(devices),
                    scanner_used=scanner.__class__.__name__,
                ),
                changes=changes,
            )

            await self._persist_results(scan_result)

            await self._update_progress(
                progress_callback, phase="complete", message="Scan completed successfully!"
            )

            return scan_result

        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            raise ScanError(f"Scan execution failed: {str(e)}") from e
        finally:
            self._current_scan = None

    def cancel_scan(self) -> None:
        """Cancel the current scan operation."""
        self._is_cancelled = True
        if self._current_scan:
            self._current_scan.cancel()

    def _select_scanner(self, options: ScanOptions) -> Scanner:
        """Select appropriate scanner based on options."""
        return self.scanner_factory.create_scanner(options)

    async def _execute_scanner(
        self, scanner: Scanner, options: ScanOptions, progress_callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """Execute scanner with progress tracking."""

        def scanner_progress(progress: ScanProgress):
            if progress_callback and not self._is_cancelled:
                asyncio.create_task(
                    self._update_progress(
                        progress_callback,
                        phase="discovery",
                        message=progress.message,
                        current=progress.current,
                        total=progress.total,
                        percentage=progress.percentage,
                    )
                )

        scanner.progress_callback = scanner_progress

        # Run scanner in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, scanner.scan, options)

    async def _parse_results(
        self, raw_results: Dict[str, Any], options: ScanOptions
    ) -> List[Device]:
        """Parse raw scan results into device models."""
        devices = []

        for host_data in raw_results.get("hosts", []):
            device = Device(
                ip_address=host_data["ip"],
                hostname=host_data.get("hostname"),
                mac_address=host_data.get("mac"),
                vendor=host_data.get("vendor"),
                status=DeviceStatus(host_data.get("status", "unknown")),
            )

            # Add ports
            for port_data in host_data.get("ports", []):
                device.open_ports.append(
                    Port(
                        number=port_data["port"],
                        protocol=port_data.get("protocol", "tcp"),
                        service=port_data.get("service"),
                        version=port_data.get("version"),
                        product=port_data.get("product"),
                    )
                )

            # Classify device type
            device.device_type = self.classifier.classify(device)

            devices.append(device)

        return devices

    async def _enrich_devices(
        self, devices: List[Device], progress_callback: Optional[Callable] = None
    ) -> List[Device]:
        """Enrich devices using configured enrichers."""
        total = len(devices)

        async def enrich_device(device: Device, index: int) -> Device:
            for enricher in self.enrichers:
                if self._is_cancelled:
                    break

                try:
                    device = await enricher.enrich(device)
                except Exception as e:
                    logger.warning(f"Enrichment failed for {device.ip_address}: {e}")

            if progress_callback:
                await self._update_progress(
                    progress_callback,
                    phase="enrichment",
                    message=f"Enriched {device.ip_address}",
                    current=index + 1,
                    total=total,
                    percentage=((index + 1) / total) * 100,
                )

            return device

        # Process devices concurrently
        tasks = [enrich_device(device, i) for i, device in enumerate(devices)]

        return await asyncio.gather(*tasks)

    async def _analyze_vulnerabilities(
        self, devices: List[Device], progress_callback: Optional[Callable] = None
    ) -> List[Device]:
        """Analyze devices for vulnerabilities."""
        if not self.vulnerability_analyzer:
            return devices

        total = len(devices)

        for i, device in enumerate(devices):
            if self._is_cancelled:
                break

            try:
                vulnerabilities = await self.vulnerability_analyzer.analyze(device)
                device.vulnerabilities.extend(vulnerabilities)
                device.risk_score = self._calculate_risk_score(device)
            except Exception as e:
                logger.warning(f"Vulnerability analysis failed for {device.ip_address}: {e}")

            if progress_callback:
                await self._update_progress(
                    progress_callback,
                    phase="vulnerability",
                    message=f"Analyzed {device.ip_address}",
                    current=i + 1,
                    total=total,
                    percentage=((i + 1) / total) * 100,
                )

        return devices

    async def _track_changes(
        self, devices: List[Device], options: ScanOptions
    ) -> Optional[Dict[str, Any]]:
        """Track changes from previous scans."""
        try:
            # Get previous scan for comparison
            previous_scan = await self.repository.get_latest_scan(targets=options.targets)

            if previous_scan:
                return self.change_tracker.compare_scans(previous_scan.devices, devices)
        except Exception as e:
            logger.warning(f"Change tracking failed: {e}")

        return None

    async def _persist_results(self, scan_result: ScanResult) -> None:
        """Persist scan results to storage."""
        await self.repository.save_scan(scan_result)

    async def _update_progress(
        self,
        callback: Optional[Callable],
        phase: str,
        message: str,
        current: Optional[int] = None,
        total: Optional[int] = None,
        percentage: Optional[float] = None,
    ) -> None:
        """Update progress through callback."""
        if callback and not self._is_cancelled:
            progress_data = {"phase": phase, "message": message}

            if current is not None:
                progress_data["current"] = current
            if total is not None:
                progress_data["total"] = total
            if percentage is not None:
                progress_data["percentage"] = percentage

            await callback(progress_data)

    def _generate_scan_id(self) -> str:
        """Generate unique scan ID."""
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def _calculate_risk_score(self, device: Device) -> float:
        """Calculate risk score based on vulnerabilities."""
        if not device.vulnerabilities:
            return 0.0

        severity_weights = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.0}

        total_score = sum(
            severity_weights.get(v.severity.lower(), 0) for v in device.vulnerabilities
        )

        # Normalize to 0-10 scale
        return min(10.0, total_score / len(device.vulnerabilities) * 2)
