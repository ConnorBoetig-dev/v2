"""
Unit tests for scanner error handling paths
"""

import pytest
import subprocess
from unittest.mock import Mock, patch, MagicMock
from core.scanner_sync import NetworkScanner
from utils.friendly_errors import FriendlyError


class TestScannerErrorHandling:
    """Test error handling in the scanner"""

    @pytest.fixture
    def scanner(self):
        """Create a scanner instance"""
        return NetworkScanner()

    def test_scanner_not_available_error(self, scanner):
        """Test handling when scanner is not available"""
        with patch.object(scanner, "_check_scanner_available", return_value=False):
            with patch.object(scanner, "_run_nmap") as mock_nmap:
                mock_nmap.side_effect = Exception("nmap not found")
                
                # Should fall back or raise appropriate error
                with pytest.raises(Exception):
                    scanner.scan("192.168.1.0/24", scan_type="discovery")

    def test_sudo_authentication_failure(self, scanner):
        """Test handling sudo authentication failure"""
        with patch.object(scanner, "_ensure_sudo_access", return_value=False):
            # Should raise FriendlyError for scans requiring sudo
            with pytest.raises(FriendlyError) as exc_info:
                scanner._run_masscan_fast("10.0.0.0/16")
            
            assert "Administrator privileges" in str(exc_info.value)

    def test_network_unreachable_error(self, scanner):
        """Test handling network unreachable error"""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                1, "nmap", stderr="Network is unreachable"
            )
            
            # Should handle network errors gracefully
            result = scanner._run_nmap(["192.168.1.0/24"], scan_type="discovery")
            assert result == []  # Empty result on network error

    def test_scan_timeout_handling(self, scanner):
        """Test handling scan timeout"""
        with patch("subprocess.Popen") as mock_popen:
            # Mock a process that times out
            mock_proc = Mock()
            mock_proc.poll.return_value = None  # Still running
            mock_proc.stdout = iter([])  # No output
            mock_proc.stderr = Mock()
            mock_proc.stderr.read.return_value = ""
            mock_proc.terminate = Mock()
            mock_proc.wait = Mock()
            mock_popen.return_value = mock_proc
            
            with patch("time.time") as mock_time:
                # Simulate timeout by advancing time
                mock_time.side_effect = [0, 10, 20, 30, 400]  # Past timeout
                
                # Should handle timeout gracefully
                result = scanner._run_nmap_with_progress(
                    ["nmap", "-sn", "192.168.1.0/24"],
                    estimated_hosts=256,
                    timeout=300
                )
                
                # Process should be terminated
                mock_proc.terminate.assert_called()

    def test_invalid_scan_type_error(self, scanner):
        """Test handling invalid scan type"""
        with pytest.raises(KeyError):
            scanner.scan("192.168.1.0/24", scan_type="invalid_type")

    def test_malformed_scanner_output(self, scanner):
        """Test handling malformed scanner output"""
        with patch("subprocess.run") as mock_run:
            # Return success but with malformed output
            mock_run.return_value = Mock(
                returncode=0,
                stdout="malformed output that's not valid"
            )
            
            with patch.object(scanner, "_parse_nmap_xml") as mock_parse:
                mock_parse.side_effect = Exception("Parse error")
                
                # Should handle parse errors gracefully
                result = scanner._run_nmap(["192.168.1.0/24"], scan_type="discovery")
                assert result == []  # Empty result on parse error

    def test_permission_denied_on_output_file(self, scanner):
        """Test handling permission denied on output file"""
        with patch.object(scanner, "_create_temp_file") as mock_create:
            mock_create.side_effect = PermissionError("Permission denied")
            
            # Should handle file permission errors
            with pytest.raises(PermissionError):
                scanner._run_nmap(["192.168.1.0/24"], scan_type="discovery")

    def test_interrupted_scan_cleanup(self, scanner):
        """Test cleanup when scan is interrupted"""
        with patch("subprocess.Popen") as mock_popen:
            mock_proc = Mock()
            mock_proc.poll.return_value = None
            mock_proc.stdout = iter([])
            mock_proc.terminate = Mock()
            mock_popen.return_value = mock_proc
            
            with patch.object(scanner, "_cleanup_temp_file") as mock_cleanup:
                try:
                    # Simulate KeyboardInterrupt during scan
                    with patch("builtins.iter", side_effect=KeyboardInterrupt):
                        scanner._run_nmap_with_progress(
                            ["nmap", "-sn", "192.168.1.0/24"],
                            estimated_hosts=256
                        )
                except KeyboardInterrupt:
                    pass
                
                # Cleanup should still be called
                assert mock_cleanup.called

    def test_masscan_rate_limit_handling(self, scanner):
        """Test handling masscan rate limit issues"""
        with patch("subprocess.Popen") as mock_popen:
            mock_proc = Mock()
            mock_proc.poll.return_value = 1  # Failed
            mock_proc.stdout = iter([])
            mock_proc.stderr = Mock()
            mock_proc.stderr.read.return_value = "Rate too high"
            mock_proc.wait.return_value = None
            mock_proc.returncode = 1
            mock_popen.return_value = mock_proc
            
            # Should handle rate limit errors
            with pytest.raises(Exception) as exc_info:
                scanner._run_masscan("192.168.1.0/24")
            
            assert "rate" in str(exc_info.value).lower()

    def test_empty_network_range_error(self, scanner):
        """Test handling empty network range"""
        # Should handle empty or invalid targets
        result = scanner.scan("", scan_type="discovery")
        assert result == []

    def test_snmp_timeout_handling(self, scanner):
        """Test handling SNMP timeouts"""
        devices = [{"ip": "192.168.1.1"}]
        snmp_config = {"version": "v2c", "community": "public"}
        
        with patch("utils.snmp_manager.SNMPManager") as mock_snmp_class:
            mock_snmp = Mock()
            mock_snmp.get_device_info.side_effect = TimeoutError("SNMP timeout")
            mock_snmp_class.return_value = mock_snmp
            
            # Should handle SNMP timeouts gracefully
            result = scanner._enrich_with_snmp(devices, snmp_config)
            # Device should still be in results even if SNMP failed
            assert len(result) == 1

    def test_concurrent_scan_resource_exhaustion(self, scanner):
        """Test handling resource exhaustion in concurrent scans"""
        # Large number of targets
        targets = [f"192.168.{i}.0/24" for i in range(256)]
        
        with patch("concurrent.futures.ProcessPoolExecutor") as mock_executor:
            mock_executor.side_effect = OSError("Resource temporarily unavailable")
            
            # Should handle resource exhaustion
            with pytest.raises(OSError):
                scanner.scan(",".join(targets), scan_type="discovery")

    def test_xml_parse_error_recovery(self, scanner):
        """Test recovery from XML parse errors"""
        with patch.object(scanner, "_parse_nmap_xml") as mock_parse:
            # First call fails, second succeeds
            mock_parse.side_effect = [
                Exception("XML parse error"),
                [{"ip": "192.168.1.1"}]
            ]
            
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0)
                
                # Try with retries
                with patch.object(scanner, "_create_temp_file", return_value="/tmp/test.xml"):
                    with patch.object(scanner, "_cleanup_temp_file"):
                        # First attempt
                        result1 = scanner._run_nmap(["192.168.1.0/24"], scan_type="discovery")
                        assert result1 == []
                        
                        # Second attempt should work
                        result2 = scanner._run_nmap(["192.168.1.0/24"], scan_type="discovery")
                        assert len(result2) == 1

    def test_memory_error_during_large_scan(self, scanner):
        """Test handling memory errors during large scans"""
        with patch.object(scanner, "_parse_masscan_output") as mock_parse:
            mock_parse.side_effect = MemoryError("Out of memory")
            
            # Should handle memory errors
            with pytest.raises(MemoryError):
                scanner._run_masscan("10.0.0.0/8")  # Very large network

    def test_invalid_ip_in_enrichment(self, scanner):
        """Test handling invalid IPs during enrichment"""
        devices = [
            {"ip": "192.168.1.1"},
            {"ip": "invalid.ip.address"},
            {"ip": "256.256.256.256"},
        ]
        
        # Should skip invalid IPs during enrichment
        result = scanner._enrich_fast_scan(devices)
        # Should process valid IPs and skip invalid ones
        assert len(result) >= 1