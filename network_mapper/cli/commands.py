"""
CLI command handlers with clean separation from business logic.

This module contains all CLI command implementations using dependency injection
to interact with core services.
"""
import asyncio
from typing import Optional, List, Dict, Any
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ..core.interfaces.scanner import ScanOptions, ScanType
from ..core.services.scan_orchestrator import ScanOrchestrator
from ..core.services.annotation_service import AnnotationService
from ..core.models.device import Device
from ..infrastructure.exporters.exporter_factory import ExporterFactory
from .formatters import DeviceTableFormatter, ScanResultFormatter, ChangeFormatter
from .prompts import ScanWizard, AnnotationPrompt


app = typer.Typer(help="NetworkMapper v2 - Network Discovery and Asset Management")
console = Console()


class CLIContext:
    """Dependency injection container for CLI commands."""

    def __init__(
        self,
        scan_orchestrator: ScanOrchestrator,
        annotation_service: AnnotationService,
        exporter_factory: ExporterFactory,
        config: Dict[str, Any],
    ):
        self.scan_orchestrator = scan_orchestrator
        self.annotation_service = annotation_service
        self.exporter_factory = exporter_factory
        self.config = config


# Global context (initialized at startup)
_context: Optional[CLIContext] = None


def initialize_cli(context: CLIContext):
    """Initialize CLI with dependencies."""
    global _context
    _context = context


@app.command()
def scan(
    targets: Optional[List[str]] = typer.Argument(None, help="Target networks or hosts to scan"),
    scan_type: Optional[str] = typer.Option(
        None, "--type", "-t", help="Scan type: discovery, inventory, deep, arp, fast"
    ),
    interface: Optional[str] = typer.Option(
        None, "--interface", "-i", help="Network interface to use"
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: str = typer.Option(
        "json", "--format", "-f", help="Output format: json, csv, html, pdf, excel"
    ),
    no_enrich: bool = typer.Option(False, "--no-enrich", help="Skip enrichment phase (SNMP, DNS)"),
    no_vulns: bool = typer.Option(False, "--no-vulns", help="Skip vulnerability scanning"),
):
    """Execute a network scan."""
    if not _context:
        console.print("[red]Error: CLI not initialized[/red]")
        raise typer.Exit(1)

    # Use wizard if no targets provided
    if not targets:
        wizard = ScanWizard(console)
        scan_config = wizard.run()
        if not scan_config:
            raise typer.Exit(0)

        targets = scan_config["targets"]
        scan_type = scan_config["scan_type"]

    # Convert string scan type to enum
    try:
        scan_type_enum = ScanType(scan_type or "discovery")
    except ValueError:
        console.print(f"[red]Invalid scan type: {scan_type}[/red]")
        raise typer.Exit(1)

    # Create scan options
    options = ScanOptions(scan_type=scan_type_enum, targets=targets, interface=interface)

    # Configure orchestrator based on flags
    if no_enrich:
        _context.scan_orchestrator.enrichers = []
    if no_vulns:
        _context.scan_orchestrator.vulnerability_analyzer = None

    # Execute scan with progress tracking
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        scan_task = progress.add_task("Scanning network...", total=100)

        def progress_callback(update: Dict[str, Any]):
            progress.update(
                scan_task,
                description=update.get("message", "Scanning..."),
                completed=update.get("percentage", 0),
            )

        # Run scan
        try:
            result = asyncio.run(
                _context.scan_orchestrator.execute_scan(options, progress_callback)
            )
        except Exception as e:
            console.print(f"[red]Scan failed: {e}[/red]")
            raise typer.Exit(1)

    # Display results
    formatter = ScanResultFormatter(console)
    formatter.display(result)

    # Export if requested
    if output:
        exporter = _context.exporter_factory.create_exporter(format)
        exporter.export(result, output)
        console.print(f"[green]Results exported to {output}[/green]")


@app.command()
def list_devices(
    search: Optional[str] = typer.Option(
        None, "--search", "-s", help="Search devices by IP, hostname, or type"
    ),
    device_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by device type"),
    critical_only: bool = typer.Option(False, "--critical", help="Show only critical devices"),
):
    """List all discovered devices."""
    if not _context:
        console.print("[red]Error: CLI not initialized[/red]")
        raise typer.Exit(1)

    # Get devices from repository
    devices = asyncio.run(_context.scan_orchestrator.repository.get_all_devices())

    # Apply filters
    if search:
        devices = [
            d
            for d in devices
            if search.lower() in d.ip_address.lower()
            or (d.hostname and search.lower() in d.hostname.lower())
            or search.lower() in d.device_type.value.lower()
        ]

    if device_type:
        devices = [d for d in devices if d.device_type.value == device_type.lower()]

    if critical_only:
        devices = [d for d in devices if d.is_critical]

    # Display results
    formatter = DeviceTableFormatter(console)
    formatter.display_devices(devices)


@app.command()
def annotate(
    ip_address: str = typer.Argument(..., help="Device IP address"),
    notes: Optional[str] = typer.Option(None, "--notes", "-n", help="Add notes to device"),
    tags: Optional[List[str]] = typer.Option(None, "--tag", "-t", help="Add tags to device"),
    critical: Optional[bool] = typer.Option(None, "--critical", help="Mark device as critical"),
    interactive: bool = typer.Option(
        False, "--interactive", "-i", help="Interactive annotation mode"
    ),
):
    """Annotate a device with additional information."""
    if not _context:
        console.print("[red]Error: CLI not initialized[/red]")
        raise typer.Exit(1)

    # Get device
    device = asyncio.run(_context.scan_orchestrator.repository.get_device_by_ip(ip_address))

    if not device:
        console.print(f"[red]Device {ip_address} not found[/red]")
        raise typer.Exit(1)

    # Interactive mode
    if interactive:
        prompt = AnnotationPrompt(console)
        annotations = prompt.get_annotations(device)
        if not annotations:
            raise typer.Exit(0)

        notes = annotations.get("notes")
        tags = annotations.get("tags")
        critical = annotations.get("critical")

    # Apply annotations
    if notes is not None:
        device.notes = notes
    if tags is not None:
        device.tags.update(tags)
    if critical is not None:
        device.is_critical = critical

    # Save
    asyncio.run(_context.annotation_service.update_annotations(device))

    console.print(f"[green]Device {ip_address} annotated successfully[/green]")


@app.command()
def compare(
    scan1: Path = typer.Argument(..., help="First scan file"),
    scan2: Path = typer.Argument(..., help="Second scan file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Export comparison results"),
):
    """Compare two scan results."""
    if not _context:
        console.print("[red]Error: CLI not initialized[/red]")
        raise typer.Exit(1)

    # Load scans
    try:
        result1 = asyncio.run(_context.scan_orchestrator.repository.load_scan_file(scan1))
        result2 = asyncio.run(_context.scan_orchestrator.repository.load_scan_file(scan2))
    except Exception as e:
        console.print(f"[red]Error loading scans: {e}[/red]")
        raise typer.Exit(1)

    # Compare
    changes = _context.scan_orchestrator.change_tracker.compare_scans(
        result1.devices, result2.devices
    )

    # Display results
    formatter = ChangeFormatter(console)
    formatter.display_changes(changes)

    # Export if requested
    if output:
        with open(output, "w") as f:
            import json

            json.dump(changes, f, indent=2)
        console.print(f"[green]Comparison exported to {output}[/green]")


@app.command()
def export(
    scan_file: Path = typer.Argument(..., help="Scan result file"),
    output: Path = typer.Argument(..., help="Output file path"),
    format: str = typer.Option(
        "json", "--format", "-f", help="Export format: json, csv, html, pdf, excel"
    ),
):
    """Export scan results to different formats."""
    if not _context:
        console.print("[red]Error: CLI not initialized[/red]")
        raise typer.Exit(1)

    # Load scan
    try:
        result = asyncio.run(_context.scan_orchestrator.repository.load_scan_file(scan_file))
    except Exception as e:
        console.print(f"[red]Error loading scan: {e}[/red]")
        raise typer.Exit(1)

    # Export
    try:
        exporter = _context.exporter_factory.create_exporter(format)
        exporter.export(result, output)
        console.print(f"[green]Exported to {output}[/green]")
    except Exception as e:
        console.print(f"[red]Export failed: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def serve(
    port: int = typer.Option(5000, "--port", "-p", help="Port to serve on"),
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host to bind to"),
):
    """Start web interface for viewing reports."""
    if not _context:
        console.print("[red]Error: CLI not initialized[/red]")
        raise typer.Exit(1)

    console.print(f"[green]Starting web interface on http://{host}:{port}[/green]")

    # Import web app (lazy load)
    from ..web.app import create_app

    app = create_app(_context)
    app.run(host=host, port=port)


@app.command()
def config(
    show: bool = typer.Option(False, "--show", help="Show current configuration"),
    edit: bool = typer.Option(False, "--edit", help="Edit configuration interactively"),
):
    """Manage application configuration."""
    if not _context:
        console.print("[red]Error: CLI not initialized[/red]")
        raise typer.Exit(1)

    if show:
        console.print("[bold]Current Configuration:[/bold]")
        for key, value in _context.config.items():
            console.print(f"  {key}: {value}")

    elif edit:
        console.print("[yellow]Configuration editing not yet implemented[/yellow]")

    else:
        console.print("Use --show to view or --edit to modify configuration")


if __name__ == "__main__":
    app()
