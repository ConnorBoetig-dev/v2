"""
Unit tests for improved traffic analyzer with sudo support
"""
import json
import os
import tempfile
from unittest.mock import MagicMock, Mock, patch

import pytest

from utils.traffic_analyzer import PassiveTrafficAnalyzer


class TestTrafficAnalyzerSudo:
    """Test the improved traffic analyzer with sudo wrapper"""

    @pytest.fixture
    def analyzer(self):
        """Create traffic analyzer instance"""
        return PassiveTrafficAnalyzer(interface="eth0")

    def test_sudo_wrapper_script_exists(self):
        """Test that sudo wrapper script exists"""
        from pathlib import Path
        script_path = Path(__file__).parent.parent.parent / "utils" / "traffic_capture_sudo.py"
        assert script_path.exists()
        assert os.access(str(script_path), os.X_OK)  # Check it's executable

    def test_capture_uses_sudo_wrapper(self, analyzer):
        """Test that capture uses the sudo wrapper instead of direct scapy"""
        with patch("subprocess.run") as mock_run:
            with patch("os.path.exists", return_value=True):
                with patch("builtins.open", create=True) as mock_open:
                    # Mock successful capture
                    mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                    mock_open.return_value.__enter__.return_value.read.return_value = json.dumps({
                        "packets": [
                            {
                                "src_ip": "192.168.1.1",
                                "dst_ip": "192.168.1.2",
                                "src_port": 12345,
                                "dst_port": 80,
                                "proto_name": "TCP",
                                "size": 100
                            }
                        ],
                        "stats": {"total_packets": 1}
                    })
                    
                    # Start capture in a thread
                    analyzer.start_capture(duration=5)
                    
                    # Wait a bit for thread to start
                    import time
                    time.sleep(0.1)
                    
                    # Check sudo command was used
                    call_args = mock_run.call_args[0][0]
                    assert call_args[0] == "sudo"
                    assert call_args[1] == "-n"
                    assert "traffic_capture_sudo.py" in call_args[3]

    def test_process_packet_data(self, analyzer):
        """Test processing of packet data from sudo wrapper"""
        packet_data = {
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.1",
            "src_port": 54321,
            "dst_port": 443,
            "proto_name": "TCP",
            "size": 1500
        }
        
        analyzer._process_packet_data(packet_data)
        
        # Check flow was created
        flow_key = ("192.168.1.100", "192.168.1.1", 54321, 443, "TCP")
        assert flow_key in analyzer.flows
        flow = analyzer.flows[flow_key]
        assert flow.packets == 1
        assert flow.bytes == 1500
        assert flow.service == "https"  # Port 443
        
        # Check devices were tracked
        assert "192.168.1.100" in analyzer.discovered_devices
        assert "192.168.1.1" in analyzer.discovered_devices
        
        # Check stats
        assert analyzer.stats["packets_processed"] == 1
        assert analyzer.stats["flows_tracked"] == 1
        assert analyzer.stats["devices_discovered"] == 2

    def test_arp_packet_processing(self, analyzer):
        """Test ARP packet processing"""
        arp_packet = {
            "arp_src_ip": "192.168.1.50",
            "arp_src_mac": "AA:BB:CC:DD:EE:FF",
            "proto_name": "ARP"
        }
        
        analyzer._process_packet_data(arp_packet)
        
        # Check ARP cache was updated
        assert analyzer.arp_cache["192.168.1.50"] == "AA:BB:CC:DD:EE:FF"
        assert "192.168.1.50" in analyzer.discovered_devices

    def test_sudo_authentication_error_handling(self, analyzer):
        """Test handling of sudo authentication errors"""
        with patch("subprocess.run") as mock_run:
            # Mock sudo password required
            mock_run.return_value = Mock(
                returncode=1, 
                stdout="", 
                stderr="sudo: a password is required"
            )
            
            analyzer.start_capture(duration=5)
            
            # Should log error about sudo authentication
            assert analyzer.stats["packets_captured"] == 0

    def test_capture_error_handling(self, analyzer):
        """Test handling of capture errors"""
        with patch("subprocess.run") as mock_run:
            # Mock capture failure
            mock_run.return_value = Mock(
                returncode=1,
                stdout='{"error": "Interface not found"}',
                stderr=""
            )
            
            analyzer.start_capture(duration=5)
            
            # Should handle error gracefully
            assert analyzer.stats["packets_captured"] == 0

    def test_temp_file_cleanup(self, analyzer):
        """Test that temporary files are cleaned up"""
        with patch("subprocess.run") as mock_run:
            with patch("os.unlink") as mock_unlink:
                mock_run.return_value = Mock(returncode=0)
                
                # Create a real temp file for testing
                with tempfile.NamedTemporaryFile(delete=False) as tf:
                    temp_path = tf.name
                    tf.write(json.dumps({"packets": [], "stats": {}}).encode())
                
                with patch("tempfile.mkstemp", return_value=(0, temp_path)):
                    analyzer.start_capture(duration=1)
                    
                    # Wait for capture to complete
                    import time
                    time.sleep(1.5)
                    
                    # Check cleanup was attempted
                    mock_unlink.assert_called()

    def test_flow_aggregation(self, analyzer):
        """Test that multiple packets for same flow are aggregated"""
        # First packet
        analyzer._process_packet_data({
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 8080,
            "dst_port": 80,
            "proto_name": "TCP",
            "size": 100
        })
        
        # Second packet in same flow
        analyzer._process_packet_data({
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2", 
            "src_port": 8080,
            "dst_port": 80,
            "proto_name": "TCP",
            "size": 200
        })
        
        # Check flow was updated
        flow_key = ("10.0.0.1", "10.0.0.2", 8080, 80, "TCP")
        flow = analyzer.flows[flow_key]
        assert flow.packets == 2
        assert flow.bytes == 300
        
        # Still only one flow
        assert analyzer.stats["flows_tracked"] == 1

    def test_service_detection(self, analyzer):
        """Test service detection based on ports"""
        test_cases = [
            (22, "ssh"),
            (80, "http"),
            (443, "https"),
            (3306, "mysql"),
            (5432, "postgresql"),
            (27017, "mongodb")
        ]
        
        for port, expected_service in test_cases:
            analyzer.flows.clear()  # Reset flows
            
            analyzer._process_packet_data({
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 12345,
                "dst_port": port,
                "proto_name": "TCP",
                "size": 100
            })
            
            # Get the created flow
            flow = list(analyzer.flows.values())[0]
            assert flow.service == expected_service