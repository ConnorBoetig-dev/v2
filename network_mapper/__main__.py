"""
Main entry point for NetworkMapper v2.

This module bootstraps the application with proper dependency injection
and configuration loading.
"""
import sys
import logging
from pathlib import Path

from .cli.commands import app, initialize_cli, CLIContext
from .core.services.scan_orchestrator import ScanOrchestrator
from .core.services.device_classifier import DeviceClassifier
from .core.services.change_tracker import ChangeTracker
from .core.services.annotation_service import AnnotationService
from .core.scanners.scanner_factory import ScannerFactory
from .infrastructure.persistence.repository import DeviceRepository
from .infrastructure.exporters.exporter_factory import ExporterFactory
from .infrastructure.config.settings import load_config
from .infrastructure.external.snmp_client import SNMPClient
from .infrastructure.external.dns_client import DNSClient
from .core.analyzers.vulnerability_analyzer import VulnerabilityAnalyzer
from .utils.logger import setup_logging


def create_application() -> CLIContext:
    """
    Create and configure the application with all dependencies.
    
    This function sets up the entire dependency injection container,
    ensuring proper initialization order and configuration.
    """
    # Load configuration
    config = load_config()
    
    # Setup logging
    setup_logging(config.get('logging', {}))
    
    # Create persistence layer
    data_dir = Path(config.get('data_dir', './output'))
    repository = DeviceRepository(data_dir)
    
    # Create external clients
    snmp_client = SNMPClient(config.get('snmp', {}))
    dns_client = DNSClient(config.get('dns', {}))
    
    # Create enrichers
    enrichers = []
    if config.get('enrichment', {}).get('snmp_enabled', True):
        from .core.services.enrichment_service import SNMPEnricher
        enrichers.append(SNMPEnricher(snmp_client))
    
    if config.get('enrichment', {}).get('dns_enabled', True):
        from .core.services.enrichment_service import DNSEnricher
        enrichers.append(DNSEnricher(dns_client))
    
    # Create core services
    scanner_factory = ScannerFactory()
    classifier = DeviceClassifier()
    change_tracker = ChangeTracker()
    annotation_service = AnnotationService(repository)
    
    # Create vulnerability analyzer if enabled
    vuln_analyzer = None
    if config.get('vulnerability', {}).get('enabled', True):
        from .infrastructure.external.osv_client import OSVClient
        from .infrastructure.external.circl_client import CIRCLClient
        
        osv_client = OSVClient()
        circl_client = CIRCLClient()
        vuln_analyzer = VulnerabilityAnalyzer([osv_client, circl_client])
    
    # Create scan orchestrator
    orchestrator = ScanOrchestrator(
        scanner_factory=scanner_factory,
        enrichers=enrichers,
        classifier=classifier,
        change_tracker=change_tracker,
        repository=repository,
        vulnerability_analyzer=vuln_analyzer,
        max_workers=config.get('performance', {}).get('max_workers', 10)
    )
    
    # Create exporter factory
    exporter_factory = ExporterFactory(config.get('export', {}))
    
    # Create CLI context
    context = CLIContext(
        scan_orchestrator=orchestrator,
        annotation_service=annotation_service,
        exporter_factory=exporter_factory,
        config=config
    )
    
    return context


def main():
    """Main application entry point."""
    try:
        # Create application
        context = create_application()
        
        # Initialize CLI with dependencies
        initialize_cli(context)
        
        # Run CLI
        app()
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Application error: {e}")
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()