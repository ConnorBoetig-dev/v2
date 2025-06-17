#!/usr/bin/env python3
"""
CLI Workflow Tests - Test interactive menu navigation and scan wizard
"""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call
from io import StringIO
import sys

from mapper import NetworkMapper
from core.scanner import NetworkScanner


class TestCLIWorkflows:
    """Test CLI workflows and interactive features"""
    
    @pytest.fixture
    def temp_output_dir(self):
        """Create temporary output directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    @pytest.fixture
    def mapper(self, temp_output_dir):
        """Create NetworkMapper instance with temporary output"""
        mapper = NetworkMapper()
        mapper.output_path = temp_output_dir
        mapper.ensure_directories()
        return mapper
    
    @pytest.fixture
    def mock_scanner_success(self):
        """Mock successful scanner operations"""
        with patch('core.scanner.NetworkScanner') as mock_scanner_class:
            mock_scanner = Mock()
            mock_scanner.scan.return_value = [
                {
                    'ip': '192.168.1.1',
                    'mac': '00:11:22:33:44:55',
                    'hostname': 'router01',
                    'type': 'router',
                    'vendor': 'Cisco',
                    'open_ports': [22, 80, 443],
                    'services': ['ssh', 'http', 'https'],
                    'os': 'Cisco IOS'
                },
                {
                    'ip': '192.168.1.2',
                    'mac': '00:11:22:33:44:56',
                    'hostname': 'switch01',
                    'type': 'switch',
                    'vendor': 'Cisco',
                    'open_ports': [22, 23],
                    'services': ['ssh', 'telnet']
                }
            ]
            mock_scanner_class.return_value = mock_scanner
            yield mock_scanner

    def test_scan_wizard_target_validation(self, mapper):
        """Test scan wizard target validation"""
        # Test valid CIDR
        with patch('rich.prompt.Prompt.ask', return_value='192.168.1.0/24'):
            target = mapper._get_scan_target()
            assert target == '192.168.1.0/24'
        
        # Test valid IP
        with patch('rich.prompt.Prompt.ask', return_value='192.168.1.1'):
            target = mapper._get_scan_target()
            assert target == '192.168.1.1'
        
        # Test valid hostname
        with patch('rich.prompt.Prompt.ask', return_value='example.com'):
            target = mapper._get_scan_target()
            assert target == 'example.com'

    def test_scan_type_selection(self, mapper):
        """Test scan type selection in wizard"""
        # Test Deep Scan selection (choice 1)
        with patch('rich.prompt.Prompt.ask', return_value='1'):
            scan_type, scan_name, needs_root, use_masscan = mapper._select_scan_type()
            assert scan_type == 'fast'
            assert scan_name == 'Deep Scan'
            assert needs_root is True
            assert use_masscan is True
        
        # Test Deeper Scan selection (choice 2)
        with patch('rich.prompt.Prompt.ask', return_value='2'):
            scan_type, scan_name, needs_root, use_masscan = mapper._select_scan_type()
            assert scan_type == 'deeper'
            assert scan_name == 'Deeper Scan'
            assert needs_root is True
            assert use_masscan is True

    def test_snmp_setup_enabled(self, mapper):
        """Test SNMP configuration setup - enabled"""
        with patch('rich.prompt.Confirm.ask', return_value=True):
            with patch.object(mapper.snmp_config, 'interactive_setup') as mock_setup:
                mock_setup.return_value = {
                    'enabled': True,
                    'community': 'public',
                    'version': 'v2c'
                }
                
                enabled, config = mapper._handle_snmp_setup()
                assert enabled is True
                assert config is not None
                mock_setup.assert_called_once()

    def test_snmp_setup_disabled(self, mapper):
        """Test SNMP configuration setup - disabled"""
        with patch('rich.prompt.Confirm.ask', return_value=False):
            enabled, config = mapper._handle_snmp_setup()
            assert enabled is False
            assert config is None

    def test_vulnerability_setup_enabled(self, mapper):
        """Test vulnerability scanning setup - enabled"""
        with patch('rich.prompt.Confirm.ask', return_value=True):
            enabled = mapper._handle_vulnerability_setup()
            assert enabled is True

    def test_vulnerability_setup_disabled(self, mapper):
        """Test vulnerability scanning setup - disabled"""
        with patch('rich.prompt.Confirm.ask', return_value=False):
            enabled = mapper._handle_vulnerability_setup()
            assert enabled is False

    def test_passive_analysis_setup_enabled(self, mapper):
        """Test passive traffic analysis setup - enabled"""
        with patch('rich.prompt.Confirm.ask', return_value=True):
            with patch('rich.prompt.Prompt.ask', return_value='2'):  # Standard duration
                enabled, duration = mapper._handle_passive_analysis_setup()
                assert enabled is True
                assert duration == 60

    def test_passive_analysis_setup_disabled(self, mapper):
        """Test passive traffic analysis setup - disabled"""
        with patch('rich.prompt.Confirm.ask', return_value=False):
            enabled, duration = mapper._handle_passive_analysis_setup()
            assert enabled is False
            assert duration == 30  # Default

    def test_passive_analysis_custom_duration(self, mapper):
        """Test passive traffic analysis with custom duration"""
        with patch('rich.prompt.Confirm.ask', return_value=True):
            with patch('rich.prompt.Prompt.ask', side_effect=['4', '180']):  # Custom, then 180 seconds
                enabled, duration = mapper._handle_passive_analysis_setup()
                assert enabled is True
                assert duration == 180

    @patch('rich.prompt.Prompt.ask')
    @patch('rich.prompt.Confirm.ask')
    def test_complete_scan_wizard_flow(self, mock_confirm, mock_prompt, mapper, mock_scanner_success):
        """Test complete scan wizard workflow"""
        # Mock user inputs
        mock_prompt.side_effect = [
            '192.168.1.0/24',  # Target
            '1',  # Scan type (Deep Scan)
            '2',  # Passive analysis duration (Standard)
        ]
        mock_confirm.side_effect = [
            False,  # SNMP disabled
            True,   # Vulnerability enabled
            False,  # Passive analysis disabled
        ]
        
        with patch.object(mapper, 'generate_html_report') as mock_report:
            mock_report.return_value = (Path('/tmp/report.html'), None)
            
            with patch('builtins.input'):  # Mock the "Press Enter" prompt
                mapper.run_scan_wizard()
        
        # Verify scanner was called
        mock_scanner_success.scan.assert_called_once()
        call_args = mock_scanner_success.scan.call_args
        assert call_args[1]['target'] == '192.168.1.0/24'
        assert call_args[1]['scan_type'] == 'fast'

    def test_recent_scans_view_empty(self, mapper):
        """Test viewing recent scans when none exist"""
        with patch('builtins.input'):  # Mock the "Press Enter" prompt
            # Should not raise exception
            mapper.view_recent_scans()

    def test_recent_scans_view_with_data(self, mapper, temp_output_dir):
        """Test viewing recent scans with existing data"""
        # Create mock scan file
        scan_file = temp_output_dir / "scans" / "scan_20231201_120000.json"
        scan_data = {
            "metadata": {
                "timestamp": "2023-12-01 12:00:00",
                "target": "192.168.1.0/24",
                "scan_type": "fast",
                "duration": 120
            },
            "devices": [
                {"ip": "192.168.1.1", "hostname": "router01", "type": "router"}
            ]
        }
        scan_file.write_text(json.dumps(scan_data, indent=2))
        
        with patch('builtins.input'):  # Mock the "Press Enter" prompt
            mapper.view_recent_scans()

    def test_device_annotation_workflow(self, mapper, temp_output_dir):
        """Test device annotation workflow"""
        # Create mock scan data
        devices = [
            {"ip": "192.168.1.1", "hostname": "router01", "type": "router"},
            {"ip": "192.168.1.2", "hostname": "switch01", "type": "switch"}
        ]
        
        with patch.object(mapper, '_load_latest_scan') as mock_load:
            mock_load.return_value = devices
            
            with patch('rich.prompt.Prompt.ask', side_effect=['192.168.1.1', 'Critical infrastructure router', 'y']):
                with patch('rich.prompt.Confirm.ask', side_effect=[True, False]):  # Mark critical, don't continue
                    with patch('builtins.input'):  # Mock the "Press Enter" prompt
                        mapper.annotate_devices()

    def test_export_data_csv(self, mapper, temp_output_dir):
        """Test data export to CSV"""
        # Create mock devices
        devices = [
            {
                "ip": "192.168.1.1",
                "hostname": "router01",
                "mac": "00:11:22:33:44:55",
                "vendor": "Cisco",
                "type": "router",
                "os": "Cisco IOS",
                "services": ["ssh", "http"],
                "open_ports": [22, 80],
                "vulnerability_count": 0,
                "critical_vulns": 0,
                "high_vulns": 0,
                "critical": True,
                "notes": "Main router"
            }
        ]
        
        with patch.object(mapper, '_load_latest_scan') as mock_load:
            mock_load.return_value = devices
            
            with patch('rich.prompt.Prompt.ask', return_value='1'):  # CSV export
                with patch('builtins.input'):  # Mock the "Press Enter" prompt
                    mapper.export_data()
        
        # Verify CSV file was created
        csv_files = list((temp_output_dir / "exports").glob("*.csv"))
        assert len(csv_files) > 0

    def test_generate_reports_workflow(self, mapper, temp_output_dir):
        """Test report generation workflow"""
        # Create mock devices
        devices = [
            {"ip": "192.168.1.1", "hostname": "router01", "type": "router"}
        ]
        
        with patch.object(mapper, '_load_latest_scan') as mock_load:
            mock_load.return_value = devices
            
            with patch.object(mapper, 'generate_html_report') as mock_report:
                mock_report.return_value = (Path('/tmp/report.html'), None)
                
                with patch('builtins.input'):  # Mock the "Press Enter" prompt
                    mapper.generate_reports()
                
                mock_report.assert_called_once()

    @patch('webbrowser.open')
    def test_view_network_map_workflow(self, mock_browser, mapper, temp_output_dir):
        """Test network map viewing workflow"""
        # Create mock report file
        report_file = temp_output_dir / "reports" / "network_map_20231201_120000.html"
        report_file.write_text("<html><body>Mock Network Map</body></html>")
        
        with patch('builtins.input'):  # Mock the "Press Enter" prompt
            mapper.view_network_map()

    def test_change_tracking_workflow(self, mapper, temp_output_dir):
        """Test change tracking workflow"""
        # Create mock scan files
        scan1_file = temp_output_dir / "scans" / "scan_20231201_120000.json"
        scan2_file = temp_output_dir / "scans" / "scan_20231201_130000.json"
        
        scan1_data = {
            "devices": [
                {"ip": "192.168.1.1", "hostname": "router01", "type": "router"}
            ]
        }
        scan2_data = {
            "devices": [
                {"ip": "192.168.1.1", "hostname": "router01", "type": "router"},
                {"ip": "192.168.1.2", "hostname": "switch01", "type": "switch"}
            ]
        }
        
        scan1_file.write_text(json.dumps(scan1_data, indent=2))
        scan2_file.write_text(json.dumps(scan2_data, indent=2))
        
        with patch.object(mapper, 'generate_html_report') as mock_report:
            mock_report.return_value = (Path('/tmp/report.html'), Path('/tmp/comparison.html'))
            
            with patch('builtins.input'):  # Mock the "Press Enter" prompt
                mapper.check_changes()

    def test_interactive_menu_navigation(self, mapper):
        """Test interactive menu navigation"""
        with patch('rich.prompt.Prompt.ask', side_effect=['9']):  # Exit
            with patch('rich.prompt.Confirm.ask', return_value=True):  # Confirm exit
                with patch('rich.console.Console.clear'):
                    mapper.interactive_menu()

    def test_menu_choice_scan(self, mapper, mock_scanner_success):
        """Test menu choice 1 - Run Network Scan"""
        with patch('rich.prompt.Prompt.ask', side_effect=['1', '9']):  # Scan, then exit
            with patch('rich.prompt.Confirm.ask', return_value=True):  # Confirm exit
                with patch.object(mapper, 'run_scan_wizard') as mock_wizard:
                    with patch('rich.console.Console.clear'):
                        mapper.interactive_menu()
                    mock_wizard.assert_called_once()

    def test_menu_choice_recent_scans(self, mapper):
        """Test menu choice 2 - View Recent Scans"""
        with patch('rich.prompt.Prompt.ask', side_effect=['2', '9']):  # Recent scans, then exit
            with patch('rich.prompt.Confirm.ask', return_value=True):  # Confirm exit
                with patch.object(mapper, 'view_recent_scans') as mock_view:
                    with patch('rich.console.Console.clear'):
                        mapper.interactive_menu()
                    mock_view.assert_called_once()

    def test_menu_choice_compare_scans(self, mapper):
        """Test menu choice 3 - Compare to Last Scan"""
        with patch('rich.prompt.Prompt.ask', side_effect=['3', '9']):  # Compare, then exit
            with patch('rich.prompt.Confirm.ask', return_value=True):  # Confirm exit
                with patch.object(mapper, 'check_changes') as mock_compare:
                    with patch('rich.console.Console.clear'):
                        mapper.interactive_menu()
                    mock_compare.assert_called_once()

    def test_menu_choice_annotate(self, mapper):
        """Test menu choice 5 - Annotate Devices"""
        with patch('rich.prompt.Prompt.ask', side_effect=['5', '9']):  # Annotate, then exit
            with patch('rich.prompt.Confirm.ask', return_value=True):  # Confirm exit
                with patch.object(mapper, 'annotate_devices') as mock_annotate:
                    with patch('rich.console.Console.clear'):
                        mapper.interactive_menu()
                    mock_annotate.assert_called_once()

    def test_error_handling_in_wizard(self, mapper):
        """Test error handling in scan wizard"""
        with patch('rich.prompt.Prompt.ask', return_value='192.168.1.0/24'):
            with patch('rich.prompt.Confirm.ask', return_value=False):  # Disable everything
                with patch.object(mapper.scanner, 'scan', side_effect=Exception("Scanner error")):
                    with pytest.raises(Exception):
                        mapper.run_scan_wizard()

    def test_scan_status_indicator(self, mapper):
        """Test scan status indicator functionality"""
        from utils.scan_status import ScanStatusIndicator
        
        indicator = ScanStatusIndicator(mapper.console)
        
        # Test showing scan start
        indicator.show_scan_starting("192.168.1.0/24", "fast")
        
        # Test showing scan complete
        indicator.show_scan_complete(5)

    def test_large_network_handling(self, mapper, mock_scanner_success):
        """Test handling of large network scans"""
        # Mock a large network target
        with patch('rich.prompt.Prompt.ask', side_effect=['10.0.0.0/16', '1']):  # Large network, fast scan
            with patch('rich.prompt.Confirm.ask', return_value=False):  # Disable extras
                with patch.object(mapper, 'generate_html_report') as mock_report:
                    mock_report.return_value = (Path('/tmp/report.html'), None)
                    
                    with patch('builtins.input'):  # Mock the "Press Enter" prompt
                        mapper.run_scan_wizard()
        
        # Verify scanner was called with large network
        mock_scanner_success.scan.assert_called_once()
        call_args = mock_scanner_success.scan.call_args
        assert call_args[1]['target'] == '10.0.0.0/16'

    def test_invalid_target_handling(self, mapper):
        """Test handling of invalid scan targets"""
        # This would need to be implemented in the actual _get_scan_target method
        # For now, we test that the method exists and can be called
        with patch('rich.prompt.Prompt.ask', return_value='invalid-target-format'):
            # The actual validation would happen in the real implementation
            target = mapper._get_scan_target()
            # In real implementation, this might re-prompt or validate


class TestCLIArgumentHandling:
    """Test CLI argument handling and overrides"""
    
    def test_cli_override_snmp_disabled(self):
        """Test CLI override for SNMP disabled"""
        mapper = NetworkMapper()
        mapper.cli_overrides = {'disable_snmp': True}
        
        # When SNMP is disabled via CLI, setup should return disabled
        enabled, config = mapper._handle_snmp_setup()
        assert enabled is False
        assert config is None

    def test_cli_override_snmp_community(self):
        """Test CLI override for SNMP community"""
        mapper = NetworkMapper()
        mapper.cli_overrides = {
            'snmp_community': 'private',
            'snmp_version': 'v2c'
        }
        
        with patch.object(mapper.snmp_config, 'get_config') as mock_config:
            mock_config.return_value = {
                'enabled': True,
                'community': 'private',
                'version': 'v2c'
            }
            
            enabled, config = mapper._handle_snmp_setup()
            assert enabled is True
            assert config['community'] == 'private'


if __name__ == "__main__":
    pytest.main([__file__])