"""
Unit tests for the Fast Scan feature
"""
import json
import os
import tempfile
from unittest.mock import MagicMock, Mock, patch

import pytest

from core.scanner import NetworkScanner


class TestFastScan:
    """Test the fast scan functionality"""

    @pytest.fixture
    def scanner(self):
        """Create a scanner instance"""
        return NetworkScanner()

    def test_fast_scan_profile_exists(self, scanner):
        """Test that fast scan profile is defined"""
        assert "fast" in scanner.scan_profiles
        profile = scanner.scan_profiles["fast"]
        assert "masscan" in profile
        assert "nmap" in profile
        assert "description" in profile

    def test_fast_scan_uses_masscan(self, scanner):
        """Test that fast scan always uses masscan"""
        with patch.object(scanner, "_run_masscan_fast") as mock_masscan:
            with patch.object(scanner, "_enrich_fast_scan") as mock_enrich:
                mock_masscan.return_value = [{"ip": "192.168.1.1"}]
                mock_enrich.return_value = [{"ip": "192.168.1.1", "enriched": True}]
                
                results = scanner.scan(
                    target="10.0.0.0/16",
                    scan_type="fast",
                    use_masscan=True  # Should be ignored for fast scan
                )
                
                mock_masscan.assert_called_once_with("10.0.0.0/16")
                mock_enrich.assert_called_once()
                assert results[0]["enriched"] is True

    def test_run_masscan_fast_large_network(self, scanner):
        """Test masscan settings for very large networks"""
        with patch("subprocess.Popen") as mock_popen:
            with patch.object(scanner, "_parse_masscan_output") as mock_parse:
                with patch.object(scanner, "_check_scanner_available", return_value=True):
                    # Mock the process
                    mock_proc = Mock()
                    mock_proc.poll.side_effect = [None, None, 0]  # Not done, not done, done
                    mock_proc.stdout = iter(["found=100", "50.0% done"])
                    mock_proc.stderr = Mock()
                    mock_proc.stderr.read.return_value = ""
                    mock_proc.wait.return_value = None
                    mock_proc.returncode = 0
                    mock_popen.return_value = mock_proc
                    
                    mock_parse.return_value = [{"ip": f"10.0.0.{i}"} for i in range(1, 101)]
                    
                    # Test with large network
                    with patch.object(scanner, "_estimate_total_hosts", return_value=65534):
                        with patch.object(scanner, "_ensure_sudo_access", return_value=True):
                            with patch.object(scanner, "_create_temp_file", return_value="/tmp/test.json"):
                                with patch.object(scanner, "_cleanup_temp_file"):
                                    results = scanner._run_masscan_fast("10.0.0.0/16")
                
                # Check that appropriate settings were used
                call_args = mock_popen.call_args[0][0]
                assert "--rate=100000" in call_args  # 100k pps for large networks
                assert "-p80,443,22,445,3389,135,139,8080" in call_args
                assert len(results) == 100

    def test_run_masscan_fast_medium_network(self, scanner):
        """Test masscan settings for medium networks"""
        with patch("subprocess.Popen") as mock_popen:
            with patch.object(scanner, "_parse_masscan_output") as mock_parse:
                with patch.object(scanner, "_check_scanner_available", return_value=True):
                    # Mock the process
                    mock_proc = Mock()
                    mock_proc.poll.side_effect = [None, 0]
                    mock_proc.stdout = iter(["found=50"])
                    mock_proc.stderr = Mock()
                    mock_proc.stderr.read.return_value = ""
                    mock_proc.wait.return_value = None
                    mock_proc.returncode = 0
                    mock_popen.return_value = mock_proc
                    
                    mock_parse.return_value = [{"ip": f"192.168.1.{i}"} for i in range(1, 51)]
                    
                    # Test with medium network
                    with patch.object(scanner, "_estimate_total_hosts", return_value=10000):
                        with patch.object(scanner, "_ensure_sudo_access", return_value=True):
                            with patch.object(scanner, "_create_temp_file", return_value="/tmp/test.json"):
                                with patch.object(scanner, "_cleanup_temp_file"):
                                    results = scanner._run_masscan_fast("192.168.0.0/16")
                
                # Check that appropriate settings were used
                call_args = mock_popen.call_args[0][0]
                assert "--rate=50000" in call_args  # 50k pps for medium networks
                assert "-p80,443,22,445,3389,8080,135,139,21,23,25,53,161" in call_args

    def test_enrich_fast_scan_chunking(self, scanner):
        """Test that enrichment processes devices in chunks"""
        # Create 150 devices to test chunking
        devices = [{"ip": f"192.168.1.{i}", "open_ports": [80]} for i in range(1, 151)]
        
        with patch("subprocess.run") as mock_run:
            with patch.object(scanner, "_parse_nmap_xml") as mock_parse:
                with patch.object(scanner, "_create_temp_file", return_value="/tmp/test.xml"):
                    with patch.object(scanner, "_cleanup_temp_file"):
                        # Mock successful nmap runs
                        mock_run.return_value = Mock(returncode=0)
                        mock_parse.return_value = []
                        
                        enriched = scanner._enrich_fast_scan(devices)
                        
                        # Should be called 3 times (150 devices / 50 per chunk)
                        assert mock_run.call_count == 3
                        assert len(enriched) == 150

    def test_enrich_fast_scan_with_os_detection(self, scanner):
        """Test that enrichment includes OS detection"""
        devices = [{"ip": "192.168.1.1", "open_ports": [80, 443]}]
        
        with patch("subprocess.run") as mock_run:
            with patch.object(scanner, "_parse_nmap_xml") as mock_parse:
                with patch.object(scanner, "_create_temp_file", return_value="/tmp/test.xml"):
                    with patch.object(scanner, "_cleanup_temp_file"):
                        mock_run.return_value = Mock(returncode=0)
                        mock_parse.return_value = [{
                            "ip": "192.168.1.1",
                            "hostname": "test-host",
                            "os": "Linux 4.x",
                            "services": ["http:80", "https:443"],
                            "vendor": "Dell"
                        }]
                        
                        enriched = scanner._enrich_fast_scan(devices)
                        
                        # Check nmap command includes OS detection
                        call_args = mock_run.call_args[0][0]
                        assert "-O" in call_args
                        assert "--osscan-guess" in call_args
                        
                        # Check enriched data (the enrichment merges data)
                        assert len(enriched) == 1
                        # The original device data should be preserved if enrichment data was merged
                        assert enriched[0]["ip"] == "192.168.1.1"
                        assert enriched[0]["open_ports"] == [80, 443]

    def test_fast_scan_fallback_on_masscan_unavailable(self, scanner):
        """Test fallback when masscan is not available"""
        with patch.object(scanner, "_check_scanner_available", return_value=False):
            with patch.object(scanner, "_run_masscan") as mock_regular_masscan:
                mock_regular_masscan.return_value = []
                
                results = scanner._run_masscan_fast("192.168.1.0/24")
                
                mock_regular_masscan.assert_called_once_with("192.168.1.0/24")

    def test_fast_scan_sudo_handling(self, scanner):
        """Test sudo authentication handling"""
        with patch.object(scanner, "_check_scanner_available", return_value=True):
            with patch.object(scanner, "_ensure_sudo_access", return_value=False):
                with pytest.raises(RuntimeError, match="Fast scan requires sudo access"):
                    scanner._run_masscan_fast("192.168.1.0/24")

    def test_fast_scan_interface_detection(self, scanner):
        """Test automatic interface detection for large networks"""
        with patch("subprocess.Popen") as mock_popen:
            with patch.object(scanner, "_parse_masscan_output", return_value=[]):
                with patch.object(scanner, "_check_scanner_available", return_value=True):
                    with patch.object(scanner, "_get_best_interface_for_target", return_value="eth0"):
                        with patch.object(scanner, "_get_source_ip_for_interface", return_value="192.168.1.100"):
                            mock_proc = Mock()
                            mock_proc.poll.side_effect = [None, 0]
                            mock_proc.stdout = iter([])
                            mock_proc.stderr = Mock()
                            mock_proc.stderr.read.return_value = ""
                            mock_proc.wait.return_value = None
                            mock_proc.returncode = 0
                            mock_popen.return_value = mock_proc
                            
                            with patch.object(scanner, "_estimate_total_hosts", return_value=65534):
                                with patch.object(scanner, "_ensure_sudo_access", return_value=True):
                                    with patch.object(scanner, "_create_temp_file", return_value="/tmp/test.json"):
                                        with patch.object(scanner, "_cleanup_temp_file"):
                                            scanner._run_masscan_fast("10.0.0.0/16")
                        
                        # Check interface was added to command
                        call_args = mock_popen.call_args[0][0]
                        assert "-e" in call_args
                        assert "eth0" in call_args
                        # Check that if source IP was found, it's added
                        if "--adapter-ip" in call_args:
                            assert "192.168.1.100" in call_args