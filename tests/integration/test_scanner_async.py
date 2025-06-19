"""
Test suite for async/parallel scanner implementation
"""

import asyncio
import pytest
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import xml.etree.ElementTree as ET

from core.scanner import NetworkScanner
from core.scanner_async import AsyncNetworkScanner


class TestAsyncNetworkScanner:
    """Test cases for async network scanner"""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance"""
        return NetworkScanner()

    @pytest.fixture
    def async_scanner(self):
        """Create async scanner instance"""
        return AsyncNetworkScanner()

    def test_scanner_initialization(self, scanner):
        """Test scanner initializes with correct attributes"""
        assert scanner.scan_profiles is not None
        assert "discovery" in scanner.scan_profiles
        assert "inventory" in scanner.scan_profiles
        assert "deep" in scanner.scan_profiles
        assert "fast" in scanner.scan_profiles

        # Check async-specific attributes
        assert hasattr(scanner, "_scan_semaphore")
        assert hasattr(scanner, "_enrich_semaphore")
        assert hasattr(scanner, "_snmp_semaphore")
        assert hasattr(scanner, "_progress_lock")
        assert hasattr(scanner, "_results_lock")

    def test_subnet_splitting(self, scanner):
        """Test network splitting for parallel scanning"""
        # Test single host
        subnets = scanner._split_target_into_subnets("192.168.1.1")
        assert len(subnets) == 1
        assert subnets[0] == "192.168.1.1"

        # Test /24 network (shouldn't split)
        subnets = scanner._split_target_into_subnets("192.168.1.0/24")
        assert len(subnets) == 1

        # Test /16 network (should split)
        subnets = scanner._split_target_into_subnets("10.0.0.0/16")
        assert len(subnets) > 1
        assert len(subnets) <= 64  # Should limit parallel scans

        # Test large /8 network
        subnets = scanner._split_target_into_subnets("10.0.0.0/8")
        assert len(subnets) > 1
        assert len(subnets) <= 64

    def test_temp_file_management(self, scanner):
        """Test thread-safe temp file creation and cleanup"""
        # Create multiple temp files
        temp_files = []
        for i in range(5):
            temp_file = scanner._create_temp_file(f"test_{i}", ".xml")
            temp_files.append(temp_file)
            # Create actual file
            with open(temp_file, "w") as f:
                f.write("test")

        # Verify all files tracked
        assert len(scanner._temp_files) == 5

        # Cleanup all files
        scanner.cleanup_all_temp_files()

        # Verify cleanup
        assert len(scanner._temp_files) == 0
        for temp_file in temp_files:
            assert not os.path.exists(temp_file)

    def test_device_deduplication(self, scanner):
        """Test device deduplication after parallel scans"""
        devices = [
            {"ip": "192.168.1.1", "open_ports": [22, 80], "services": ["ssh:22", "http:80"]},
            {"ip": "192.168.1.1", "open_ports": [443], "services": ["https:443"]},
            {"ip": "192.168.1.2", "open_ports": [22], "services": ["ssh:22"]},
        ]

        deduplicated = scanner._deduplicate_devices(devices)

        assert len(deduplicated) == 2

        # Check merged device
        device1 = next(d for d in deduplicated if d["ip"] == "192.168.1.1")
        assert sorted(device1["open_ports"]) == [22, 80, 443]
        assert len(device1["services"]) == 3

    @pytest.mark.asyncio
    async def test_async_scan_subnet_discovery(self, async_scanner):
        """Test async subnet discovery scanning"""
        with patch.object(async_scanner, "_run_nmap_async") as mock_nmap:
            mock_nmap.return_value = [
                {"ip": "192.168.1.1", "hostname": "router"},
                {"ip": "192.168.1.100", "hostname": "workstation"},
            ]

            with patch.object(async_scanner, "_check_scanner_available", return_value=True):
                with patch.object(async_scanner, "_is_local_subnet", return_value=False):
                    result = await async_scanner._scan_subnet_discovery(
                        "192.168.1.0/24", use_masscan=False, needs_root=False
                    )

            assert len(result) == 2
            mock_nmap.assert_called_once()

    @pytest.mark.asyncio
    async def test_parallel_enrichment(self, async_scanner):
        """Test parallel device enrichment"""
        devices = [{"ip": f"192.168.1.{i}"} for i in range(1, 51)]  # 50 devices

        with patch.object(async_scanner, "_enrich_chunk_async") as mock_enrich:

            async def mock_enrich_impl(chunk):
                # Simulate enrichment
                for device in chunk:
                    device["hostname"] = f"host-{device['ip'].split('.')[-1]}"
                    device["os"] = "Linux"
                return chunk

            mock_enrich.side_effect = mock_enrich_impl

            result = await async_scanner._enrich_fast_scan_async(devices)

            # Should have called enrich for multiple chunks
            assert mock_enrich.call_count == 2  # 50 devices / 25 chunk size

            # All devices should be enriched
            assert len(result) == 50
            assert all(d.get("hostname") for d in result)
            assert all(d.get("os") == "Linux" for d in result)

    @pytest.mark.asyncio
    async def test_concurrent_scan_execution(self, async_scanner):
        """Test concurrent execution of multiple subnet scans"""
        with patch.object(async_scanner, "_split_target_into_subnets") as mock_split:
            mock_split.return_value = ["192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24"]

            scan_results = [
                [{"ip": "192.168.1.1"}],
                [{"ip": "192.168.2.1"}],
                [{"ip": "192.168.3.1"}],
            ]

            with patch.object(async_scanner, "_scan_subnet_discovery") as mock_scan:
                mock_scan.side_effect = scan_results

                result = await async_scanner.scan("192.168.0.0/16", scan_type="discovery")

            assert len(result) == 3
            assert mock_scan.call_count == 3

    def test_sync_wrapper_compatibility(self, scanner):
        """Test synchronous wrapper maintains compatibility"""
        with patch.object(AsyncNetworkScanner, "scan") as mock_async_scan:
            # Mock the async scan to return a coroutine
            async def mock_scan(*args, **kwargs):
                return [{"ip": "192.168.1.1"}]

            mock_async_scan.return_value = mock_scan()

            # Call sync method
            result = scanner.scan("192.168.1.0/24")

            assert len(result) == 1
            assert result[0]["ip"] == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_semaphore_limiting(self, async_scanner):
        """Test semaphore limits concurrent operations"""
        # Track concurrent executions
        concurrent_count = 0
        max_concurrent = 0

        async def mock_scan_subnet(subnet):
            nonlocal concurrent_count, max_concurrent
            concurrent_count += 1
            max_concurrent = max(max_concurrent, concurrent_count)
            await asyncio.sleep(0.1)  # Simulate scan time
            concurrent_count -= 1
            return [{"ip": f"{subnet.split('/')[0]}"}]

        # Create many subnets
        subnets = [f"192.168.{i}.0/24" for i in range(100)]

        with patch.object(async_scanner, "_split_target_into_subnets", return_value=subnets):
            with patch.object(
                async_scanner, "_scan_subnet_discovery", side_effect=mock_scan_subnet
            ):
                await async_scanner.scan("192.168.0.0/16")

        # Should respect semaphore limit
        assert max_concurrent <= 32  # Default semaphore limit

    @pytest.mark.asyncio
    async def test_error_handling_in_parallel_scans(self, async_scanner):
        """Test error handling when some subnet scans fail"""

        def make_scan_result(subnet):
            if "2" in subnet:
                raise Exception("Scan failed")
            return [{"ip": subnet.split("/")[0]}]

        with patch.object(async_scanner, "_split_target_into_subnets") as mock_split:
            mock_split.return_value = ["192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24"]

            with patch.object(async_scanner, "_scan_subnet_discovery") as mock_scan:
                mock_scan.side_effect = make_scan_result

                result = await async_scanner.scan("192.168.0.0/16")

        # Should still get results from successful scans
        assert len(result) == 2
        assert not any("192.168.2" in d["ip"] for d in result)

    def test_parse_nmap_xml_performance(self, scanner):
        """Test XML parsing doesn't become bottleneck"""
        # Create sample XML with many hosts
        xml_content = """<?xml version="1.0"?>
        <nmaprun>
        """
        for i in range(1, 101):
            xml_content += f"""
            <host>
                <status state="up"/>
                <address addr="192.168.1.{i}" addrtype="ipv4"/>
                <ports>
                    <port portid="22"><state state="open"/></port>
                </ports>
            </host>
            """
        xml_content += "</nmaprun>"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(xml_content)
            temp_file = f.name

        try:
            import time

            start = time.time()
            devices = scanner._parse_nmap_xml(temp_file)
            duration = time.time() - start

            assert len(devices) == 100
            assert duration < 1.0  # Should parse 100 hosts in under 1 second
        finally:
            os.unlink(temp_file)

    @pytest.mark.asyncio
    async def test_snmp_parallel_enrichment(self, async_scanner):
        """Test parallel SNMP enrichment"""
        devices = [{"ip": f"192.168.1.{i}", "type": "router"} for i in range(1, 21)]

        with patch("core.scanner_async.SNMP_AVAILABLE", True):
            with patch("core.scanner_async.SNMPManager") as mock_snmp_class:
                mock_manager = Mock()
                mock_manager.enrich_device.side_effect = lambda d: {
                    **d,
                    "snmp_data": {"sysName": f"device-{d['ip']}"},
                }
                mock_snmp_class.return_value = mock_manager

                result = await async_scanner._enrich_with_snmp_async(
                    devices, {"version": "v2c", "community": "public"}
                )

        # All devices should have SNMP data
        assert all("snmp_data" in d or d["ip"] in result for d in devices)

    def test_progress_tracking_thread_safety(self, scanner):
        """Test progress tracking is thread-safe"""
        import threading

        def update_progress():
            for _ in range(100):
                scanner.hosts_completed += 1

        scanner.total_hosts = 1000
        scanner.hosts_completed = 0

        # Create multiple threads updating progress
        threads = []
        for _ in range(10):
            t = threading.Thread(target=update_progress)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Should have accurate count despite concurrent updates
        assert scanner.hosts_completed == 1000


@pytest.mark.integration
class TestAsyncScannerIntegration:
    """Integration tests for async scanner"""

    @pytest.mark.asyncio
    async def test_full_scan_workflow(self):
        """Test complete scan workflow with mocked tools"""
        scanner = AsyncNetworkScanner()

        with patch("subprocess.run") as mock_run:
            # Mock which commands
            mock_run.return_value = Mock(returncode=0)

            with patch("asyncio.create_subprocess_exec") as mock_exec:
                # Mock nmap process
                mock_process = AsyncMock()
                mock_process.stdout = AsyncMock()
                mock_process.stderr = AsyncMock()
                mock_process.returncode = 0

                # Simulate nmap output
                mock_process.stdout.__aiter__.return_value = [
                    b"Starting Nmap scan...\n",
                    b"Nmap scan report for 192.168.1.1\n",
                    b"Host is up\n",
                ]

                mock_exec.return_value = mock_process

                with patch.object(scanner, "_parse_nmap_xml") as mock_parse:
                    mock_parse.return_value = [
                        {"ip": "192.168.1.1", "hostname": "router", "open_ports": [80, 443]}
                    ]

                    result = await scanner.scan("192.168.1.0/24", scan_type="discovery")

        assert len(result) == 1
        assert result[0]["ip"] == "192.168.1.1"
