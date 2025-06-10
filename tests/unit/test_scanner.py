"""Comprehensive unit tests for the NetworkScanner module."""

import json
import logging
import os
import subprocess
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch, call, mock_open

from core.scanner import NetworkScanner


class TestNetworkScanner(unittest.TestCase):
    """Test cases for NetworkScanner class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.scanner = NetworkScanner()
        # Configure logging to capture log messages
        logging.basicConfig(level=logging.DEBUG)
        
    def tearDown(self):
        """Clean up after tests."""
        # Clean up any temp files that might be left
        temp_dir = tempfile.gettempdir()
        for file in os.listdir(temp_dir):
            if file.startswith(('nmap_', 'masscan_')):
                try:
                    os.remove(os.path.join(temp_dir, file))
                except:
                    pass
    
    def test_init(self):
        """Test scanner initialization."""
        scanner = NetworkScanner()
        self.assertIsNotNone(scanner.scan_profiles)
        self.assertIn('discovery', scanner.scan_profiles)
        self.assertIn('inventory', scanner.scan_profiles)
        self.assertIn('deep', scanner.scan_profiles)
        self.assertIsNotNone(scanner.console)
        self.assertIsNotNone(scanner.config)
        self.assertEqual(scanner.total_hosts, 0)
        self.assertEqual(scanner.hosts_completed, 0)
        self.assertIsInstance(scanner._scanner_availability, dict)
    
    def test_load_config_with_file(self):
        """Test config loading when config.yaml exists."""
        config_content = """
scan:
  timeout: 600
scanners:
  progress_details: true
  hang_threshold: 60
  nmap_stats_interval: "2s"
  progress_refresh_rate: 8
  nmap_timing: "-T5"
"""
        with patch('builtins.open', mock_open(read_data=config_content)):
            with patch('pathlib.Path.exists', return_value=True):
                scanner = NetworkScanner()
                self.assertEqual(scanner.config['scan']['timeout'], 600)
                self.assertTrue(scanner.config['scanners']['progress_details'])
                self.assertEqual(scanner.config['scanners']['hang_threshold'], 60)
    
    def test_load_config_without_file(self):
        """Test config loading when config.yaml doesn't exist."""
        with patch('pathlib.Path.exists', return_value=False):
            scanner = NetworkScanner()
            # Should use default config
            self.assertEqual(scanner.config['scan']['timeout'], 300)
            self.assertFalse(scanner.config['scanners']['progress_details'])
            self.assertEqual(scanner.config['scanners']['hang_threshold'], 30)
    
    def test_estimate_total_hosts_cidr(self):
        """Test host estimation for CIDR notation."""
        # /24 network
        self.assertEqual(self.scanner._estimate_total_hosts("192.168.1.0/24"), 254)
        # /16 network
        self.assertEqual(self.scanner._estimate_total_hosts("10.0.0.0/16"), 65534)
        # /32 single host
        self.assertEqual(self.scanner._estimate_total_hosts("192.168.1.1/32"), 1)
        # Invalid CIDR
        self.assertEqual(self.scanner._estimate_total_hosts("192.168.1.0/invalid"), 256)
    
    def test_estimate_total_hosts_single(self):
        """Test host estimation for single IP."""
        self.assertEqual(self.scanner._estimate_total_hosts("192.168.1.1"), 1)
        self.assertEqual(self.scanner._estimate_total_hosts("10.0.0.1"), 1)
    
    def test_check_hang(self):
        """Test hang detection logic."""
        # Set up progress mock
        progress = MagicMock()
        task = "test_task"
        
        # No hang initially
        current_time = time.time()
        self.scanner.last_progress_update = current_time - 10  # 10 seconds ago
        self.assertFalse(self.scanner._check_hang(current_time, task, progress))
        
        # Hang detected after threshold
        self.scanner.last_progress_update = current_time - 40  # 40 seconds ago
        self.scanner.hang_detected = False
        self.assertTrue(self.scanner._check_hang(current_time, task, progress))
        self.assertTrue(self.scanner.hang_detected)
        progress.update.assert_called_with(task, description="[yellow]⚠ Scan may be hung[/yellow]")
    
    @patch('subprocess.run')
    def test_ensure_sudo_access_cached(self, mock_run):
        """Test sudo access when already cached."""
        # Already have sudo cached
        mock_run.return_value.returncode = 0
        self.assertTrue(self.scanner._ensure_sudo_access())
        mock_run.assert_called_with(["sudo", "-n", "true"], capture_output=True)
    
    @patch('subprocess.run')
    def test_ensure_sudo_access_not_cached(self, mock_run):
        """Test sudo access when not cached."""
        # First call fails (not cached), second succeeds (after auth), third verifies
        mock_run.side_effect = [
            Mock(returncode=1),  # Not cached
            Mock(returncode=0),  # Auth succeeds
            Mock(returncode=0),  # Verification succeeds
        ]
        self.assertTrue(self.scanner._ensure_sudo_access())
        self.assertEqual(mock_run.call_count, 3)
    
    @patch('subprocess.run')
    def test_ensure_sudo_access_failed(self, mock_run):
        """Test sudo access failure."""
        mock_run.side_effect = [
            Mock(returncode=1),  # Not cached
            Mock(returncode=1),  # Auth fails
        ]
        self.assertFalse(self.scanner._ensure_sudo_access())
    
    def test_create_temp_file(self):
        """Test temporary file creation."""
        # Test nmap XML file
        temp_file = self.scanner._create_temp_file("nmap", ".xml")
        self.assertTrue(temp_file.startswith(tempfile.gettempdir()))
        self.assertIn("nmap_", temp_file)
        self.assertTrue(temp_file.endswith(".xml"))
        
        # Test masscan JSON file
        temp_file = self.scanner._create_temp_file("masscan", ".json")
        self.assertIn("masscan_", temp_file)
        self.assertTrue(temp_file.endswith(".json"))
    
    def test_cleanup_temp_file(self):
        """Test temporary file cleanup."""
        # Create a temp file
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            temp_file = tf.name
        
        # File exists
        self.assertTrue(os.path.exists(temp_file))
        
        # Clean it up
        self.scanner._cleanup_temp_file(temp_file)
        self.assertFalse(os.path.exists(temp_file))
        
        # Cleanup non-existent file should not raise
        self.scanner._cleanup_temp_file("/tmp/nonexistent_file_12345")
    
    @patch('subprocess.run')
    def test_cleanup_temp_file_with_sudo(self, mock_run):
        """Test cleanup of root-owned temp file."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            temp_file = tf.name
        
        # Mock file as root-owned
        with patch('os.stat') as mock_stat:
            mock_stat.return_value.st_uid = 0
            self.scanner._cleanup_temp_file(temp_file, needs_sudo=True)
            mock_run.assert_called_with(["sudo", "rm", temp_file], capture_output=True, timeout=5)
    
    @patch('subprocess.run')
    def test_check_scanner_available(self, mock_run):
        """Test scanner availability check."""
        # Scanner available
        mock_run.return_value.returncode = 0
        self.assertTrue(self.scanner._check_scanner_available("nmap"))
        
        # Check caching
        self.assertTrue(self.scanner._check_scanner_available("nmap"))
        # Should only be called once due to caching
        mock_run.assert_called_once()
        
        # Scanner not available
        mock_run.reset_mock()
        mock_run.return_value.returncode = 1
        self.assertFalse(self.scanner._check_scanner_available("masscan"))
    
    def test_parse_nmap_xml_valid(self):
        """Test parsing valid nmap XML output."""
        xml_content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Test Vendor"/>
    <hostnames>
      <hostname name="test-host.local"/>
    </hostnames>
    <ports>
      <port portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.0"/>
      </port>
      <port portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.4" accuracy="95"/>
      <osmatch name="Linux 5.0" accuracy="85"/>
    </os>
  </host>
</nmaprun>"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as tf:
            tf.write(xml_content)
            tf.flush()
            
            devices = self.scanner._parse_nmap_xml(tf.name)
            
            self.assertEqual(len(devices), 1)
            device = devices[0]
            self.assertEqual(device['ip'], '192.168.1.1')
            self.assertEqual(device['mac'], '00:11:22:33:44:55')
            self.assertEqual(device['vendor'], 'Test Vendor')
            self.assertEqual(device['hostname'], 'test-host.local')
            self.assertIn(22, device['open_ports'])
            self.assertIn(80, device['open_ports'])
            self.assertEqual(device['os'], 'Linux 5.4')
            self.assertEqual(device['os_accuracy'], 95)
            
            os.unlink(tf.name)
    
    def test_parse_nmap_xml_no_hosts(self):
        """Test parsing nmap XML with no hosts up."""
        xml_content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="down"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
  </host>
</nmaprun>"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as tf:
            tf.write(xml_content)
            tf.flush()
            
            devices = self.scanner._parse_nmap_xml(tf.name)
            self.assertEqual(len(devices), 0)
            
            os.unlink(tf.name)
    
    def test_parse_masscan_output_valid(self):
        """Test parsing valid masscan JSON output."""
        json_content = """{   "ip": "192.168.1.1",   "ports": [{"port": 80}]   }
{   "ip": "192.168.1.2",   "ports": [{"port": 22}, {"port": 443}]   }
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tf:
            tf.write(json_content)
            tf.flush()
            
            devices = self.scanner._parse_masscan_output(tf.name)
            
            self.assertEqual(len(devices), 2)
            # Check first device
            self.assertEqual(devices[0]['ip'], '192.168.1.1')
            self.assertIn(80, devices[0]['open_ports'])
            # Check second device
            self.assertEqual(devices[1]['ip'], '192.168.1.2')
            self.assertIn(22, devices[1]['open_ports'])
            self.assertIn(443, devices[1]['open_ports'])
            
            os.unlink(tf.name)
    
    def test_parse_masscan_output_empty(self):
        """Test parsing empty masscan output."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tf:
            tf.write("")
            tf.flush()
            
            devices = self.scanner._parse_masscan_output(tf.name)
            self.assertEqual(len(devices), 0)
            
            os.unlink(tf.name)
    
    def test_parse_masscan_output_invalid_json(self):
        """Test parsing invalid masscan JSON."""
        json_content = """{ invalid json content
{ "ip": "192.168.1.1" }"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tf:
            tf.write(json_content)
            tf.flush()
            
            devices = self.scanner._parse_masscan_output(tf.name)
            # Should handle the error gracefully and parse valid lines
            self.assertEqual(len(devices), 1)
            
            os.unlink(tf.name)
    
    def test_build_arp_scan_command(self):
        """Test building arp-scan command."""
        # Local network scan
        cmd = self.scanner._build_arp_scan_command("localnet")
        self.assertEqual(cmd[0:3], ["sudo", "-n", "arp-scan"])
        self.assertIn("--localnet", cmd)
        
        # CIDR scan
        cmd = self.scanner._build_arp_scan_command("192.168.1.0/24")
        self.assertIn("192.168.1.0/24", cmd)
        
        # Single host
        cmd = self.scanner._build_arp_scan_command("192.168.1.1")
        self.assertIn("192.168.1.1", cmd)
        
        # Check common options
        self.assertIn("--retry=2", cmd)
        self.assertIn("--timeout=500", cmd)
        self.assertIn("--backoff=1.5", cmd)
    
    @patch('subprocess.run')
    @patch('subprocess.Popen')
    def test_scan_nmap_discovery(self, mock_popen, mock_run):
        """Test nmap discovery scan."""
        # Mock which nmap check
        mock_run.return_value.returncode = 0
        
        # Mock nmap process
        mock_proc = MagicMock()
        mock_proc.poll.side_effect = [None, None, None, None, 0]  # Process running then done
        mock_proc.returncode = 0
        # Use a generator that returns empty strings after the real output
        def readline_generator():
            outputs = [
                "Starting Nmap",
                "Nmap scan report for 192.168.1.1",
                "Host is up",
                "Nmap done: 256 IP addresses (1 host up) scanned",
            ]
            for output in outputs:
                yield output
            while True:
                yield ""  # Keep returning empty strings
        
        mock_proc.stdout.readline.side_effect = readline_generator()
        mock_proc.stderr = MagicMock()
        mock_proc.stderr.__iter__ = Mock(return_value=iter([]))
        mock_proc.wait.return_value = None
        mock_popen.return_value = mock_proc
        
        # Create mock XML file
        xml_content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
  </host>
</nmaprun>"""
        
        with patch('builtins.open', mock_open(read_data=xml_content)):
            with patch('os.path.exists', return_value=True):
                with patch.object(self.scanner, '_cleanup_temp_file'):
                    devices = self.scanner.scan("192.168.1.0/24", "discovery")
                    
                    self.assertEqual(len(devices), 1)
                    self.assertEqual(devices[0]['ip'], '192.168.1.1')
    
    @patch('subprocess.run')
    def test_scan_masscan_not_available(self, mock_run):
        """Test masscan scan when masscan is not available."""
        mock_run.return_value.returncode = 1  # masscan not found
        
        with self.assertRaises(RuntimeError) as context:
            self.scanner.scan("192.168.1.0/24", "discovery", use_masscan=True)
        
        self.assertIn("masscan not found", str(context.exception))
    
    @patch('subprocess.Popen')
    def test_run_arp_scan(self, mock_popen):
        """Test ARP scan execution."""
        # Mock arp-scan process
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.returncode = 0
        mock_proc.stdout = [
            "192.168.1.1\t00:11:22:33:44:55\tTest Vendor",
            "192.168.1.2\taa:bb:cc:dd:ee:ff\tAnother Vendor",
        ]
        mock_proc.stderr = []
        mock_popen.return_value = mock_proc
        
        with patch.object(self.scanner, '_check_scanner_available', return_value=True):
            with patch.object(self.scanner, '_ensure_sudo_access', return_value=True):
                devices = self.scanner._run_arp_scan("192.168.1.0/24")
                
                self.assertEqual(len(devices), 2)
                self.assertEqual(devices[0]['ip'], '192.168.1.1')
                self.assertEqual(devices[0]['mac'], '00:11:22:33:44:55')
                self.assertEqual(devices[0]['vendor'], 'Test Vendor')
    
    def test_scan_type_selection(self):
        """Test correct scanner selection based on parameters."""
        with patch.object(self.scanner, '_run_masscan') as mock_masscan:
            with patch.object(self.scanner, '_run_nmap') as mock_nmap:
                # Masscan for discovery
                self.scanner.scan("192.168.1.0/24", "discovery", use_masscan=True)
                mock_masscan.assert_called_once()
                mock_nmap.assert_not_called()
                
                # Reset mocks
                mock_masscan.reset_mock()
                mock_nmap.reset_mock()
                
                # Nmap for inventory
                self.scanner.scan("192.168.1.0/24", "inventory")
                mock_nmap.assert_called_once()
                mock_masscan.assert_not_called()
    
    def test_extract_host_info_minimal(self):
        """Test extracting host info with minimal data."""
        host_xml = ET.fromstring("""
        <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
        </host>
        """)
        
        device = self.scanner._extract_host_info(host_xml)
        self.assertEqual(device['ip'], '10.0.0.1')
        self.assertEqual(device['mac'], '')
        self.assertEqual(device['hostname'], '')
        self.assertEqual(len(device['open_ports']), 0)
        self.assertEqual(len(device['services']), 0)
    
    def test_extract_host_info_complete(self):
        """Test extracting complete host information."""
        host_xml = ET.fromstring("""
        <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <address addr="DE:AD:BE:EF:00:01" addrtype="mac" vendor="Test Corp"/>
            <hostnames>
                <hostname name="server.example.com"/>
            </hostnames>
            <ports>
                <port portid="22">
                    <state state="open"/>
                    <service name="ssh" product="OpenSSH" version="8.2p1"/>
                </port>
                <port portid="443">
                    <state state="closed"/>
                </port>
            </ports>
            <os>
                <osmatch name="Ubuntu Linux 20.04" accuracy="98"/>
            </os>
        </host>
        """)
        
        device = self.scanner._extract_host_info(host_xml)
        self.assertEqual(device['ip'], '10.0.0.1')
        self.assertEqual(device['mac'], 'DE:AD:BE:EF:00:01')
        self.assertEqual(device['vendor'], 'Test Corp')
        self.assertEqual(device['hostname'], 'server.example.com')
        self.assertIn(22, device['open_ports'])
        self.assertNotIn(443, device['open_ports'])  # Closed port
        self.assertEqual(device['os'], 'Ubuntu Linux 20.04')
        self.assertEqual(device['os_accuracy'], 98)
    
    @patch('subprocess.Popen')
    def test_scan_error_handling(self, mock_popen):
        """Test error handling during scan."""
        # Mock process that fails
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1  # Non-zero return code
        mock_proc.returncode = 1
        mock_proc.stdout.readline.return_value = ""
        mock_proc.stderr.read.return_value = "Permission denied"
        mock_popen.return_value = mock_proc
        
        with patch('subprocess.run', return_value=Mock(returncode=0)):  # which nmap succeeds
            with self.assertRaises(Exception) as context:
                self.scanner.scan("192.168.1.0/24", "discovery")
            
            self.assertIn("failed", str(context.exception).lower())
    
    def test_show_scan_troubleshooting(self):
        """Test troubleshooting message display."""
        # Just verify the method exists and runs without error
        self.scanner._show_scan_troubleshooting()
        # Method only prints to console, no return value to test


class TestScannerIntegration(unittest.TestCase):
    """Integration tests for scanner with real command simulation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.scanner = NetworkScanner()
    
    @patch('subprocess.Popen')
    @patch('subprocess.run')
    def test_full_scan_workflow(self, mock_run, mock_popen):
        """Test complete scan workflow from start to finish."""
        # Mock which nmap
        mock_run.return_value.returncode = 0
        
        # Create a more realistic nmap output simulation
        nmap_output = [
            "Starting Nmap 7.91 ( https://nmap.org )",
            "Initiating Ping Scan at 12:00",
            "Scanning 192.168.1.0/24 [2 ports]",
            "Stats: 0:00:01 elapsed; 0 hosts completed (0 up), 256 undergoing Ping Scan",
            "Ping Scan Timing: About 25.00% done; ETC: 12:00 (0:00:03 remaining)",
            "Stats: 0:00:02 elapsed; 0 hosts completed (0 up), 256 undergoing Ping Scan",
            "Ping Scan Timing: About 50.00% done; ETC: 12:00 (0:00:02 remaining)",
            "Discovered open port 22/tcp on 192.168.1.10",
            "Discovered open port 80/tcp on 192.168.1.10",
            "Nmap scan report for router.local (192.168.1.1)",
            "Host is up (0.0010s latency).",
            "Nmap scan report for server.local (192.168.1.10)",
            "Host is up (0.0020s latency).",
            "Stats: 0:00:05 elapsed; 2 hosts completed (2 up), 0 undergoing",
            "Nmap done: 256 IP addresses (2 hosts up) scanned in 5.12 seconds",
            ""
        ]
        
        # Mock process
        mock_proc = MagicMock()
        mock_proc.poll.side_effect = [None] * (len(nmap_output) - 1) + [0]
        mock_proc.returncode = 0
        # Use a generator that returns empty strings after the real output
        def readline_generator():
            for output in nmap_output:
                yield output
            while True:
                yield ""  # Keep returning empty strings
        
        mock_proc.stdout.readline.side_effect = readline_generator()
        mock_proc.stderr = MagicMock()
        mock_proc.stderr.__iter__ = Mock(return_value=iter([]))
        mock_proc.wait.return_value = None
        mock_popen.return_value = mock_proc
        
        # Mock XML output
        xml_content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="router.local"/></hostnames>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames><hostname name="server.local"/></hostnames>
    <ports>
      <port portid="22"><state state="open"/></port>
      <port portid="80"><state state="open"/></port>
    </ports>
  </host>
</nmaprun>"""
        
        with patch('builtins.open', mock_open(read_data=xml_content)):
            with patch('os.path.exists', return_value=True):
                with patch.object(self.scanner, '_cleanup_temp_file'):
                    devices = self.scanner.scan("192.168.1.0/24", "inventory")
                    
                    self.assertEqual(len(devices), 2)
                    # Verify router
                    router = next(d for d in devices if d['ip'] == '192.168.1.1')
                    self.assertEqual(router['hostname'], 'router.local')
                    # Verify server
                    server = next(d for d in devices if d['ip'] == '192.168.1.10')
                    self.assertEqual(server['hostname'], 'server.local')
                    self.assertIn(22, server['open_ports'])
                    self.assertIn(80, server['open_ports'])


if __name__ == '__main__':
    unittest.main()