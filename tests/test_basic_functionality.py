#!/usr/bin/env python3
"""
Basic Functionality Tests - Verify core features work correctly
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch
import tempfile

from core.scanner import NetworkScanner
from core.classifier import DeviceClassifier
from core.parser import ScanParser
from core.tracker import ChangeTracker


class TestBasicFunctionality:
    """Test basic functionality of core components"""

    def test_scanner_initialization(self):
        """Test scanner initializes correctly"""
        scanner = NetworkScanner()
        
        # Should have scan profiles
        assert hasattr(scanner, 'scan_profiles')
        assert len(scanner.scan_profiles) > 0
        
        # Should have both scan types after cleanup
        assert 'fast' in scanner.scan_profiles
        assert 'deeper' in scanner.scan_profiles
        assert len(scanner.scan_profiles) == 2

    def test_classifier_initialization(self):
        """Test classifier initializes correctly"""
        classifier = DeviceClassifier()
        
        # Should have signatures
        assert hasattr(classifier, 'signatures')
        assert len(classifier.signatures) > 0

    def test_parser_initialization(self):
        """Test parser initializes correctly"""
        parser = ScanParser()
        
        # Should have parsing methods
        assert hasattr(parser, 'parse_results')

    def test_basic_device_classification(self):
        """Test basic device classification works"""
        classifier = DeviceClassifier()
        
        # Test obvious router
        router_device = {
            'ip': '192.168.1.1',
            'hostname': 'gateway',
            'open_ports': [22, 80, 443],
            'services': ['ssh', 'http', 'https'],
            'vendor': 'Cisco'
        }
        
        classified = classifier.classify_devices([router_device])
        assert len(classified) == 1
        assert 'type' in classified[0]
        # Router should be classified as network equipment
        assert classified[0]['type'] in ['router', 'switch', 'firewall']

    def test_basic_change_detection(self):
        """Test basic change detection initialization"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = ChangeTracker(output_path=Path(tmpdir))
            
            # Test devices
            test_devices = [
                {'ip': '192.168.1.1', 'hostname': 'router', 'type': 'router'},
                {'ip': '192.168.1.2', 'hostname': 'pc1', 'type': 'workstation'}
            ]
            
            # When no previous scan exists, should return empty dict
            changes = tracker.detect_changes(test_devices)
            
            # Should return changes object (empty since no previous scan)
            assert isinstance(changes, dict)

    def test_scan_profiles_configuration(self):
        """Test scan profiles are properly configured"""
        scanner = NetworkScanner()
        
        # Fast scan should be configured for speed
        fast_profile = scanner.scan_profiles['fast']
        assert 'nmap' in fast_profile
        nmap_args = fast_profile['nmap']
        
        # Should have version intensity 0 for speed
        assert '--version-intensity' in nmap_args
        intensity_idx = nmap_args.index('--version-intensity')
        assert nmap_args[intensity_idx + 1] == '0'
        
        # Deeper scan should be configured for accuracy
        deeper_profile = scanner.scan_profiles['deeper']
        assert 'nmap' in deeper_profile
        nmap_args = deeper_profile['nmap']
        
        # Should have higher version intensity for accuracy
        assert '--version-intensity' in nmap_args
        intensity_idx = nmap_args.index('--version-intensity')
        assert nmap_args[intensity_idx + 1] == '5'

    def test_device_types_comprehensive(self):
        """Test comprehensive device type classification"""
        classifier = DeviceClassifier()
        
        test_devices = [
            # Web server
            {
                'ip': '10.0.1.10',
                'hostname': 'web01',
                'open_ports': [22, 80, 443],
                'services': ['ssh', 'http', 'https'],
                'os': 'Ubuntu'
            },
            # Database server
            {
                'ip': '10.0.1.11',
                'hostname': 'db01',
                'open_ports': [22, 3306],
                'services': ['ssh', 'mysql'],
                'os': 'Ubuntu'
            },
            # Windows workstation
            {
                'ip': '10.0.1.100',
                'hostname': 'pc01',
                'open_ports': [135, 139, 445],
                'services': ['msrpc', 'netbios-ssn', 'microsoft-ds'],
                'os': 'Windows 10'
            },
            # Printer
            {
                'ip': '10.0.1.200',
                'hostname': 'printer01',
                'open_ports': [80, 631, 9100],
                'services': ['http', 'ipp', 'jetdirect'],
                'vendor': 'HP'
            }
        ]
        
        classified = classifier.classify_devices(test_devices)
        
        # All devices should be classified
        assert len(classified) == 4
        
        # Check specific classifications
        web_server = next(d for d in classified if d['hostname'] == 'web01')
        assert web_server['type'] in ['web_server', 'linux_server']
        
        db_server = next(d for d in classified if d['hostname'] == 'db01')
        assert db_server['type'] in ['database', 'linux_server']
        
        workstation = next(d for d in classified if d['hostname'] == 'pc01')
        assert workstation['type'] in ['workstation', 'windows_server']
        
        printer = next(d for d in classified if d['hostname'] == 'printer01')
        assert printer['type'] == 'printer'

    def test_parser_basic_functionality(self):
        """Test parser can handle basic scan results"""
        parser = ScanParser()
        
        # Mock scan results
        mock_results = [
            {
                'ip': '192.168.1.1',
                'mac': '00:11:22:33:44:55',
                'hostname': 'router',
                'open_ports': [22, 80],
                'services': ['ssh', 'http']
            }
        ]
        
        parsed = parser.parse_results(mock_results)
        
        # Should return valid parsed results
        assert isinstance(parsed, list)
        assert len(parsed) == 1
        assert parsed[0]['ip'] == '192.168.1.1'

    @patch('subprocess.run')
    def test_scanner_availability_check(self, mock_run):
        """Test scanner availability checking"""
        scanner = NetworkScanner()
        
        # Mock successful scanner check
        mock_run.return_value = Mock(returncode=0, stdout='nmap version 7.97')
        
        # This should not raise an exception
        available = scanner._check_scanner_available('nmap')
        assert isinstance(available, bool)

    def test_error_handling_graceful(self):
        """Test that components handle errors gracefully"""
        classifier = DeviceClassifier()
        
        # Test with malformed device data
        malformed_devices = [
            {},  # Empty device
            {'ip': 'invalid'},  # Missing required fields
            {'ip': '192.168.1.1', 'invalid_field': 'test'}  # Unknown fields
        ]
        
        # Should not crash, should handle gracefully
        try:
            classified = classifier.classify_devices(malformed_devices)
            # Should return something, even if classification is 'unknown'
            assert isinstance(classified, list)
        except Exception as e:
            pytest.fail(f"Classifier should handle malformed data gracefully, but raised: {e}")

    def test_performance_baseline(self):
        """Test basic performance expectations"""
        import time
        
        classifier = DeviceClassifier()
        
        # Generate moderate dataset
        devices = []
        for i in range(50):
            device = {
                'ip': f'192.168.1.{i}',
                'hostname': f'device-{i}',
                'open_ports': [22, 80],
                'services': ['ssh', 'http'],
                'vendor': 'Generic'
            }
            devices.append(device)
        
        # Measure classification time
        start_time = time.time()
        classified = classifier.classify_devices(devices)
        end_time = time.time()
        
        classification_time = end_time - start_time
        
        # Should complete in reasonable time (under 5 seconds for 50 devices)
        assert classification_time < 5.0
        assert len(classified) == 50


if __name__ == "__main__":
    pytest.main([__file__])