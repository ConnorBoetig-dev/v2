"""
Scan Progress Indicator Module

Provides a simple, clean progress indication for network scans
that works alongside existing progress tracking.
"""

import asyncio
import threading
import time
from typing import Optional, Callable
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.layout import Layout
from rich.align import Align


class ScanProgressIndicator:
    """Simple scan progress indicator that shows actual progress"""
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.is_active = False
        self._start_time = None
        self._scanner = None
        self._update_thread = None
        self._stop_event = threading.Event()
        self._last_update = None
        self._status_line = None
        
    def start(self, scanner, target: str, scan_type: str):
        """Start showing scan progress"""
        self.is_active = True
        self._scanner = scanner
        self._start_time = time.time()
        self._stop_event.clear()
        
        # Create progress display
        self._progress = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold cyan]Network Scan in Progress[/bold cyan]"),
            BarColumn(bar_width=40, complete_style="green", finished_style="green"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TextColumn("• {task.fields[status]}"),
            console=self.console,
            transient=False
        )
        
        # Create a nice panel for the progress
        panel = Panel(
            self._progress,
            title=f"[bold]Scanning {target}[/bold]",
            subtitle=f"[dim]{scan_type.title()} scan[/dim]",
            border_style="cyan",
            padding=(1, 2)
        )
        
        # Start live display
        self._live = Live(panel, console=self.console, refresh_per_second=4)
        self._live.start()
        
        # Add progress task
        self._task_id = self._progress.add_task(
            "Scanning...",
            total=100,
            status="Initializing scan..."
        )
        
        # Start background thread to update progress
        self._update_thread = threading.Thread(target=self._update_progress_loop, daemon=True)
        self._update_thread.start()
    
    def _update_progress_loop(self):
        """Background thread to update progress from scanner state"""
        last_status = ""
        last_completed = 0
        
        while not self._stop_event.is_set():
            try:
                if self._scanner and hasattr(self._scanner, 'hosts_completed') and hasattr(self._scanner, 'total_hosts'):
                    # Calculate real progress
                    total = self._scanner.total_hosts
                    completed = self._scanner.hosts_completed
                    
                    if total > 0:
                        percentage = (completed / total) * 100
                    else:
                        # Use time-based progress for unknown totals
                        elapsed = time.time() - self._start_time
                        # Estimate based on typical scan times
                        if elapsed < 10:
                            percentage = elapsed * 3  # Quick start
                        elif elapsed < 60:
                            percentage = 30 + (elapsed - 10) * 1.0  # Slower middle
                        else:
                            percentage = min(80 + (elapsed - 60) * 0.3, 95)  # Slow end
                    
                    # Determine status from scanner state
                    status = "Scanning network..."
                    
                    # Check for specific scanner states
                    if hasattr(self._scanner, 'hang_detected') and self._scanner.hang_detected:
                        status = "Scan may be hung - waiting for response..."
                    elif completed > last_completed:
                        status = f"Found {completed} hosts"
                        last_completed = completed
                    elif percentage < 10:
                        status = "Discovering hosts..."
                    elif percentage < 50:
                        status = "Scanning ports and services..."
                    elif percentage < 80:
                        status = "Detecting OS and services..."
                    else:
                        status = "Finalizing results..."
                    
                    # Update progress
                    self._progress.update(
                        self._task_id,
                        completed=min(percentage, 100),
                        status=status
                    )
                
            except Exception:
                # Silently ignore errors in background thread
                pass
            
            time.sleep(0.25)  # Update 4 times per second
    
    def stop(self):
        """Stop showing progress"""
        self.is_active = False
        self._stop_event.set()
        
        if self._update_thread:
            self._update_thread.join(timeout=1.0)
        
        if self._progress and self._task_id is not None:
            # Show completion
            self._progress.update(
                self._task_id,
                completed=100,
                status="[bold green]Scan complete![/bold green]"
            )
            
            # Give a moment to show completion
            time.sleep(0.5)
        
        if self._live:
            self._live.stop()
        
        self._progress = None
        self._live = None
        self._task_id = None
        self._scanner = None
    
    def __enter__(self):
        """Context manager support"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Ensure progress is stopped"""
        self.stop()


class MinimalScanIndicator:
    """Even simpler scan indicator - just a status message"""
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self._status = None
        
    def start(self, target: str, scan_type: str):
        """Show scan started message"""
        self._status = self.console.status(
            f"[bold cyan]Scanning {target}[/bold cyan] ({scan_type} scan)...",
            spinner="dots"
        )
        self._status.start()
    
    def stop(self):
        """Stop the indicator"""
        if self._status:
            self._status.stop()
            self._status = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()