"""Fast parallel DNS resolver for discovered hosts"""

import concurrent.futures
import logging
import socket
from typing import Dict, List
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

logger = logging.getLogger(__name__)


class DNSResolver:
    """Resolve hostnames for IP addresses in parallel"""

    def __init__(self, max_workers: int = 50, timeout: float = 2.0):
        """
        Initialize DNS resolver

        Args:
            max_workers: Maximum parallel DNS queries
            timeout: DNS query timeout in seconds
        """
        self.max_workers = max_workers
        self.timeout = timeout
        socket.setdefaulttimeout(timeout)

    def resolve_devices(self, devices: List[Dict], console=None) -> List[Dict]:
        """
        Resolve hostnames for all devices in parallel

        Args:
            devices: List of device dictionaries with 'ip' field
            console: Rich console for progress display

        Returns:
            Updated device list with resolved hostnames
        """
        if not devices:
            return devices

        # Only resolve for devices without hostnames
        to_resolve = [d for d in devices if d.get("ip") and not d.get("hostname")]

        if not to_resolve:
            return devices

        if console:
            console.print(f"\n[cyan]🔍 Resolving hostnames for {len(to_resolve)} devices...[/cyan]")

        resolved_count = 0

        # Create progress bar if console provided
        if console:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]DNS resolution[/bold cyan]"),
                BarColumn(complete_style="cyan", finished_style="cyan"),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("• {task.fields[status]}"),
                console=console,
                transient=False,
            ) as progress:
                task = progress.add_task(
                    "Resolving hostnames", total=len(to_resolve), status="Starting DNS queries..."
                )

                # Resolve in parallel
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=self.max_workers
                ) as executor:
                    # Submit all resolution tasks
                    future_to_device = {
                        executor.submit(self._resolve_hostname, device["ip"]): device
                        for device in to_resolve
                    }

                    # Process completed resolutions
                    for i, future in enumerate(concurrent.futures.as_completed(future_to_device)):
                        device = future_to_device[future]
                        try:
                            hostname = future.result()
                            if hostname and hostname != device["ip"]:
                                device["hostname"] = hostname
                                resolved_count += 1
                        except Exception as e:
                            logger.debug(f"Failed to resolve {device['ip']}: {e}")

                        progress.update(
                            task,
                            completed=i + 1,
                            status=f"Resolved: {resolved_count}, Failed: {i + 1 - resolved_count}",
                        )

                progress.update(
                    task,
                    completed=len(to_resolve),
                    status=f"Complete: {resolved_count} hostnames resolved",
                )
        else:
            # No console - just resolve quietly
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_device = {
                    executor.submit(self._resolve_hostname, device["ip"]): device
                    for device in to_resolve
                }

                for future in concurrent.futures.as_completed(future_to_device):
                    device = future_to_device[future]
                    try:
                        hostname = future.result()
                        if hostname and hostname != device["ip"]:
                            device["hostname"] = hostname
                            resolved_count += 1
                    except Exception:
                        pass

        if console and resolved_count > 0:
            console.print(f"[green]✓ Successfully resolved {resolved_count} hostnames[/green]")

        return devices

    def _resolve_hostname(self, ip: str) -> str:
        """
        Resolve single IP to hostname

        Args:
            ip: IP address to resolve

        Returns:
            Hostname or original IP if resolution fails
        """
        try:
            # Try reverse DNS lookup
            hostname, _, _ = socket.gethostbyaddr(ip)
            # Clean up hostname (remove domain in some cases)
            if hostname and hostname != ip:
                return hostname.split(".")[0]  # Return short hostname
            return ip
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            return ip
