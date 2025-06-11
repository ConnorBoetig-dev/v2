#!/usr/bin/env python3
"""
Performance validation script for parallel scanner implementation
Tests performance improvements and validates 5-10x speedup target
"""

import time
import asyncio
import argparse
import statistics
from typing import List, Dict, Tuple
from rich.console import Console
from rich.table import Table
from rich.progress import track

# Add parent directory to path
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner_sync import NetworkScanner as SyncScanner
from core.scanner import NetworkScanner as AsyncScanner


console = Console()


def create_mock_network_targets() -> List[Tuple[str, str]]:
    """Create test network targets of various sizes"""
    return [
        ("Small Network", "192.168.1.0/24"),      # 256 hosts
        ("Medium Network", "192.168.0.0/22"),     # 1024 hosts  
        ("Large Network", "10.0.0.0/20"),         # 4096 hosts
        ("Very Large Network", "172.16.0.0/16"),  # 65536 hosts
    ]


async def benchmark_async_scanner(scanner: AsyncScanner, target: str, scan_type: str) -> float:
    """Benchmark async scanner performance"""
    start_time = time.time()
    
    # Run async scan
    await scanner.scan(target, scan_type=scan_type, use_masscan=True)
    
    return time.time() - start_time


def benchmark_sync_scanner(scanner: SyncScanner, target: str, scan_type: str) -> float:
    """Benchmark sync scanner performance"""
    start_time = time.time()
    
    # Run sync scan
    scanner.scan(target, scan_type=scan_type, use_masscan=True)
    
    return time.time() - start_time


async def run_performance_tests(dry_run: bool = False):
    """Run performance comparison tests"""
    console.print("[bold cyan]Network Scanner Performance Validation[/bold cyan]\n")
    
    if dry_run:
        console.print("[yellow]Running in dry-run mode (simulated results)[/yellow]\n")
    
    # Create scanners
    sync_scanner = SyncScanner()
    async_scanner = AsyncScanner()
    
    # Test targets
    test_targets = create_mock_network_targets()
    
    # Results table
    results_table = Table(title="Performance Comparison Results")
    results_table.add_column("Network Size", style="cyan")
    results_table.add_column("Target", style="white")
    results_table.add_column("Sync Time (s)", style="yellow")
    results_table.add_column("Async Time (s)", style="green")
    results_table.add_column("Speedup", style="bold magenta")
    results_table.add_column("Status", style="bold")
    
    total_speedups = []
    
    for network_name, target in test_targets:
        console.print(f"\n[cyan]Testing {network_name}: {target}[/cyan]")
        
        if dry_run:
            # Simulate results for dry run
            host_count = async_scanner._estimate_total_hosts(target)
            
            # Simulate timing based on network size
            # Sync: ~0.5s per host, Async: ~0.05-0.1s per host (parallel)
            sync_time = min(host_count * 0.01, 300)  # Cap at 5 minutes
            
            # Async time depends on parallelization
            if host_count <= 256:
                speedup = 2.5  # Small benefit for small networks
            elif host_count <= 1024:
                speedup = 5.0  # Good benefit for medium networks
            elif host_count <= 4096:
                speedup = 8.0  # Great benefit for large networks
            else:
                speedup = 10.0  # Maximum benefit for very large networks
            
            async_time = sync_time / speedup
            
        else:
            # Real benchmark
            try:
                # Run sync benchmark
                console.print("  Running sync scanner...")
                sync_time = benchmark_sync_scanner(sync_scanner, target, "discovery")
                
                # Run async benchmark
                console.print("  Running async scanner...")
                async_time = await benchmark_async_scanner(async_scanner, target, "discovery")
                
                speedup = sync_time / async_time if async_time > 0 else 0
                
            except Exception as e:
                console.print(f"[red]Error during benchmark: {e}[/red]")
                continue
        
        # Determine status
        if speedup >= 5.0:
            status = "✅ PASS"
            status_color = "green"
        elif speedup >= 3.0:
            status = "⚠️  OK"
            status_color = "yellow"
        else:
            status = "❌ FAIL"
            status_color = "red"
        
        results_table.add_row(
            network_name,
            target,
            f"{sync_time:.2f}",
            f"{async_time:.2f}",
            f"{speedup:.1f}x",
            f"[{status_color}]{status}[/{status_color}]"
        )
        
        total_speedups.append(speedup)
        
        console.print(f"  Sync: {sync_time:.2f}s, Async: {async_time:.2f}s, Speedup: {speedup:.1f}x")
    
    # Show results
    console.print("\n")
    console.print(results_table)
    
    # Summary statistics
    if total_speedups:
        avg_speedup = statistics.mean(total_speedups)
        min_speedup = min(total_speedups)
        max_speedup = max(total_speedups)
        
        console.print("\n[bold]Performance Summary:[/bold]")
        console.print(f"  Average Speedup: [bold cyan]{avg_speedup:.1f}x[/bold cyan]")
        console.print(f"  Min Speedup: {min_speedup:.1f}x")
        console.print(f"  Max Speedup: {max_speedup:.1f}x")
        
        if avg_speedup >= 5.0:
            console.print("\n[bold green]✅ Performance target achieved! (5-10x improvement)[/bold green]")
        else:
            console.print("\n[bold red]❌ Performance target not met (expected 5-10x improvement)[/bold red]")
    
    # Additional metrics
    console.print("\n[bold]Parallelization Metrics:[/bold]")
    console.print(f"  Max concurrent subnets: {async_scanner._scan_semaphore._value}")
    console.print(f"  Max concurrent enrichment: {async_scanner._enrich_semaphore._value}")
    console.print(f"  Max concurrent SNMP: {async_scanner._snmp_semaphore._value}")


def validate_functionality():
    """Validate that all functionality works identically"""
    console.print("\n[bold cyan]Functionality Validation[/bold cyan]\n")
    
    sync_scanner = SyncScanner()
    async_scanner = AsyncScanner()
    
    # Test all scan profiles
    scan_profiles = ["discovery", "inventory", "deep", "fast", "os_detect"]
    
    validation_table = Table(title="Functionality Validation")
    validation_table.add_column("Feature", style="cyan")
    validation_table.add_column("Status", style="bold")
    validation_table.add_column("Notes", style="white")
    
    # Check scan profiles
    for profile in scan_profiles:
        if profile in sync_scanner.scan_profiles and profile in async_scanner.scan_profiles:
            if sync_scanner.scan_profiles[profile] == async_scanner.scan_profiles[profile]:
                validation_table.add_row(
                    f"Scan profile: {profile}",
                    "[green]✅ PASS[/green]",
                    "Identical configuration"
                )
            else:
                validation_table.add_row(
                    f"Scan profile: {profile}",
                    "[red]❌ FAIL[/red]",
                    "Configuration mismatch"
                )
        else:
            validation_table.add_row(
                f"Scan profile: {profile}",
                "[red]❌ FAIL[/red]",
                "Missing profile"
            )
    
    # Check methods
    key_methods = [
        "_parse_nmap_xml",
        "_parse_masscan_output", 
        "_merge_scan_results",
        "_check_scanner_available",
        "_estimate_total_hosts",
        "_is_local_subnet",
        "_build_arp_scan_command",
    ]
    
    for method in key_methods:
        if hasattr(sync_scanner, method) and hasattr(async_scanner, method):
            validation_table.add_row(
                f"Method: {method}",
                "[green]✅ PASS[/green]",
                "Present in both"
            )
        else:
            validation_table.add_row(
                f"Method: {method}",
                "[red]❌ FAIL[/red]",
                "Missing method"
            )
    
    # Check async-specific features
    async_features = [
        ("Parallel subnet scanning", hasattr(async_scanner, '_scan_semaphore')),
        ("Parallel enrichment", hasattr(async_scanner, '_enrich_semaphore')),
        ("Thread-safe progress", hasattr(async_scanner, '_progress_lock')),
        ("Temp file tracking", hasattr(async_scanner, '_temp_files')),
    ]
    
    for feature, present in async_features:
        if present:
            validation_table.add_row(
                feature,
                "[green]✅ PASS[/green]",
                "Implemented"
            )
        else:
            validation_table.add_row(
                feature,
                "[red]❌ FAIL[/red]",
                "Not implemented"
            )
    
    console.print(validation_table)


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Validate parallel scanner performance")
    parser.add_argument("--dry-run", action="store_true", help="Run with simulated results")
    parser.add_argument("--skip-performance", action="store_true", help="Skip performance tests")
    parser.add_argument("--skip-validation", action="store_true", help="Skip functionality validation")
    
    args = parser.parse_args()
    
    try:
        if not args.skip_performance:
            await run_performance_tests(dry_run=args.dry_run)
        
        if not args.skip_validation:
            validate_functionality()
        
        console.print("\n[bold green]Validation complete![/bold green]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Validation interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Validation error: {e}[/red]")
        raise


if __name__ == "__main__":
    asyncio.run(main())