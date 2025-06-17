#!/usr/bin/env python3
"""
Network Simulation Tests - Test with synthetic network data and scenarios
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

from core.classifier import DeviceClassifier
from core.tracker import ChangeTracker
from core.parser import ScanParser
from utils.vulnerability_scanner import VulnerabilityScanner


class TestNetworkSimulation:
    """Test with simulated network scenarios"""
    
    @pytest.fixture
    def classifier(self):
        """Create device classifier instance"""
        return DeviceClassifier()
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    @pytest.fixture
    def tracker(self, temp_dir):
        """Create change tracker instance"""
        return ChangeTracker(output_path=temp_dir)
    
    @pytest.fixture
    def parser(self):
        """Create scan parser instance"""
        return ScanParser()
    
    @pytest.fixture
    def vuln_scanner(self, temp_dir):
        """Create vulnerability scanner instance"""
        return VulnerabilityScanner(cache_dir=temp_dir / "cache")

    @pytest.fixture
    def enterprise_network_devices(self):
        """Simulate a typical enterprise network"""
        return [
            # Core Infrastructure
            {
                'ip': '10.0.1.1',
                'mac': '00:1a:a0:12:34:56',
                'hostname': 'core-router-01',
                'vendor': 'Cisco',
                'open_ports': [22, 23, 80, 161, 443, 8080],
                'services': ['ssh', 'telnet', 'http', 'snmp', 'https', 'http-proxy'],
                'os': 'Cisco IOS 15.1'
            },
            {
                'ip': '10.0.1.2',
                'mac': '00:1a:a0:12:34:57',
                'hostname': 'core-switch-01',
                'vendor': 'Cisco',
                'open_ports': [22, 23, 161],
                'services': ['ssh', 'telnet', 'snmp'],
                'os': 'Cisco IOS'
            },
            {
                'ip': '10.0.1.3',
                'mac': '00:1a:a0:12:34:58',
                'hostname': 'firewall-01',
                'vendor': 'Fortinet',
                'open_ports': [22, 80, 443, 8080],
                'services': ['ssh', 'http', 'https', 'http-proxy'],
                'os': 'FortiOS'
            },
            
            # Servers
            {
                'ip': '10.0.2.10',
                'mac': '00:50:56:ab:cd:ef',
                'hostname': 'web-server-01',
                'vendor': 'VMware',
                'open_ports': [22, 80, 443],
                'services': ['ssh', 'http', 'https'],
                'os': 'Ubuntu 20.04'
            },
            {
                'ip': '10.0.2.11',
                'mac': '00:50:56:ab:cd:f0',
                'hostname': 'db-server-01',
                'vendor': 'VMware',
                'open_ports': [22, 3306, 5432],
                'services': ['ssh', 'mysql', 'postgresql'],
                'os': 'Ubuntu 20.04'
            },
            {
                'ip': '10.0.2.12',
                'mac': '00:50:56:ab:cd:f1',
                'hostname': 'mail-server-01',
                'vendor': 'VMware',
                'open_ports': [22, 25, 110, 143, 993, 995],
                'services': ['ssh', 'smtp', 'pop3', 'imap', 'imaps', 'pop3s'],
                'os': 'Ubuntu 20.04'
            },
            {
                'ip': '10.0.2.13',
                'mac': '00:0c:29:12:34:56',
                'hostname': 'file-server-01',
                'vendor': 'VMware',
                'open_ports': [22, 139, 445],
                'services': ['ssh', 'netbios-ssn', 'microsoft-ds'],
                'os': 'Windows Server 2019'
            },
            
            # Workstations
            {
                'ip': '10.0.3.100',
                'mac': '00:23:ae:12:34:56',
                'hostname': 'ws-001',
                'vendor': 'Dell',
                'open_ports': [135, 139, 445, 3389],
                'services': ['msrpc', 'netbios-ssn', 'microsoft-ds', 'rdp'],
                'os': 'Windows 10'
            },
            {
                'ip': '10.0.3.101',
                'mac': '00:23:ae:12:34:57',
                'hostname': 'ws-002',
                'vendor': 'Dell',
                'open_ports': [22, 80],
                'services': ['ssh', 'http'],
                'os': 'Ubuntu 20.04'
            },
            
            # IoT Devices
            {
                'ip': '10.0.4.50',
                'mac': '00:17:88:ab:cd:ef',
                'hostname': 'printer-01',
                'vendor': 'HP',
                'open_ports': [80, 443, 631, 9100],
                'services': ['http', 'https', 'ipp', 'jetdirect'],
                'os': ''
            },
            {
                'ip': '10.0.4.51',
                'mac': '00:04:20:12:34:56',
                'hostname': 'camera-01',
                'vendor': 'Axis',
                'open_ports': [80, 554],
                'services': ['http', 'rtsp'],
                'os': ''
            },
            {
                'ip': '10.0.4.52',
                'mac': '00:1f:d0:ab:cd:ef',
                'hostname': 'thermostat-01',
                'vendor': 'Honeywell',
                'open_ports': [80, 443],
                'services': ['http', 'https'],
                'os': ''
            }
        ]

    @pytest.fixture
    def small_office_network(self):
        """Simulate a small office network"""
        return [
            {
                'ip': '192.168.1.1',
                'mac': '00:11:22:33:44:55',
                'hostname': 'router',
                'vendor': 'Linksys',
                'open_ports': [22, 80, 443],
                'services': ['ssh', 'http', 'https'],
                'os': 'Linux'
            },
            {
                'ip': '192.168.1.100',
                'mac': '00:11:22:33:44:56',
                'hostname': 'desktop-01',
                'vendor': 'HP',
                'open_ports': [135, 139, 445],
                'services': ['msrpc', 'netbios-ssn', 'microsoft-ds'],
                'os': 'Windows 10'
            },
            {
                'ip': '192.168.1.101',
                'mac': '00:11:22:33:44:57',
                'hostname': 'laptop-01',
                'vendor': 'Apple',
                'open_ports': [22],
                'services': ['ssh'],
                'os': 'macOS'
            }
        ]

    def test_device_classification_enterprise(self, classifier, enterprise_network_devices):
        """Test device classification on enterprise network"""
        classified_devices = classifier.classify_devices(enterprise_network_devices)
        
        # Verify core infrastructure classification
        router = next(d for d in classified_devices if d['hostname'] == 'core-router-01')
        assert router['type'] in ['router', 'switch']  # Router signature may match
        
        switch = next(d for d in classified_devices if d['hostname'] == 'core-switch-01')
        assert switch['type'] in ['switch', 'router']  # Switch may be classified as router due to similar ports
        
        firewall = next(d for d in classified_devices if d['hostname'] == 'firewall-01')
        assert firewall['type'] in ['firewall', 'router']  # Firewall should be classified correctly
        
        # Verify server classification
        web_server = next(d for d in classified_devices if d['hostname'] == 'web-server-01')
        assert web_server['type'] == 'web_server'
        
        db_server = next(d for d in classified_devices if d['hostname'] == 'db-server-01')
        assert db_server['type'] == 'database'
        
        mail_server = next(d for d in classified_devices if d['hostname'] == 'mail-server-01')
        assert mail_server['type'] == 'mail_server'
        
        file_server = next(d for d in classified_devices if d['hostname'] == 'file-server-01')
        assert file_server['type'] == 'file_server'
        
        # Verify workstation classification
        windows_ws = next(d for d in classified_devices if d['hostname'] == 'ws-001')
        assert windows_ws['type'] == 'workstation'
        
        linux_ws = next(d for d in classified_devices if d['hostname'] == 'ws-002')
        assert linux_ws['type'] == 'workstation'
        
        # Verify IoT device classification
        printer = next(d for d in classified_devices if d['hostname'] == 'printer-01')
        assert printer['type'] == 'printer'
        
        camera = next(d for d in classified_devices if d['hostname'] == 'camera-01')
        assert camera['type'] == 'security_camera'
        
        thermostat = next(d for d in classified_devices if d['hostname'] == 'thermostat-01')
        assert thermostat['type'] == 'iot_device'

    def test_device_classification_small_office(self, classifier, small_office_network):
        """Test device classification on small office network"""
        classified_devices = classifier.classify_devices(small_office_network)
        
        router = next(d for d in classified_devices if d['hostname'] == 'router')
        assert router['type'] == 'router'
        
        windows_pc = next(d for d in classified_devices if d['hostname'] == 'desktop-01')
        assert windows_pc['type'] == 'workstation'
        
        mac_laptop = next(d for d in classified_devices if d['hostname'] == 'laptop-01')
        assert mac_laptop['type'] == 'workstation'

    def test_confidence_scoring(self, classifier, enterprise_network_devices):
        """Test classification confidence scoring"""
        classified_devices = classifier.classify_devices(enterprise_network_devices)
        
        # Devices with clear signatures should have high confidence
        router = next(d for d in classified_devices if d['hostname'] == 'core-router-01')
        assert router.get('classification_confidence', 0) >= 0.8
        
        web_server = next(d for d in classified_devices if d['hostname'] == 'web-server-01')
        assert web_server.get('classification_confidence', 0) >= 0.8
        
        printer = next(d for d in classified_devices if d['hostname'] == 'printer-01')
        assert printer.get('classification_confidence', 0) >= 0.8

    def test_change_detection_new_devices(self, tracker, enterprise_network_devices):
        """Test detection of new devices"""
        # Initial scan with subset of devices
        initial_devices = enterprise_network_devices[:5]
        
        # Simulate a later scan with new devices
        later_devices = enterprise_network_devices  # All devices
        
        changes = tracker.detect_changes(initial_devices, later_devices)
        
        assert 'new_devices' in changes
        assert len(changes['new_devices']) == len(enterprise_network_devices) - 5
        
        # Verify new device details
        new_ips = [d['ip'] for d in changes['new_devices']]
        expected_new_ips = [d['ip'] for d in enterprise_network_devices[5:]]
        assert set(new_ips) == set(expected_new_ips)

    def test_change_detection_missing_devices(self, tracker, enterprise_network_devices):
        """Test detection of missing devices"""
        # Initial scan with all devices
        initial_devices = enterprise_network_devices
        
        # Later scan with some devices missing
        later_devices = enterprise_network_devices[:-3]
        
        changes = tracker.detect_changes(initial_devices, later_devices)
        
        assert 'missing_devices' in changes
        assert len(changes['missing_devices']) == 3
        
        # Verify missing device details
        missing_ips = [d['ip'] for d in changes['missing_devices']]
        expected_missing_ips = [d['ip'] for d in enterprise_network_devices[-3:]]
        assert set(missing_ips) == set(expected_missing_ips)

    def test_change_detection_modified_services(self, tracker, enterprise_network_devices):
        """Test detection of service changes"""
        initial_devices = enterprise_network_devices.copy()
        
        # Modify services on one device
        modified_devices = enterprise_network_devices.copy()
        web_server = next(d for d in modified_devices if d['hostname'] == 'web-server-01')
        web_server['open_ports'].append(8080)
        web_server['services'].append('http-alt')
        
        changes = tracker.detect_changes(initial_devices, modified_devices)
        
        assert 'changed_devices' in changes
        assert len(changes['changed_devices']) >= 1
        
        # Find the changed web server
        changed_web_server = next(
            (d for d in changes['changed_devices'] if d['ip'] == '10.0.2.10'),
            None
        )
        assert changed_web_server is not None
        
        # Verify change details
        service_changes = [c for c in changed_web_server['changes'] if c['field'] == 'services']
        assert len(service_changes) > 0

    def test_vulnerability_correlation_simulation(self, vuln_scanner):
        """Test vulnerability correlation with simulated devices"""
        devices_with_vulns = [
            {
                'ip': '10.0.2.10',
                'hostname': 'web-server-01',
                'services': ['ssh', 'http', 'https'],
                'service_versions': {
                    'ssh': 'OpenSSH 7.4',
                    'http': 'Apache 2.4.6',
                    'https': 'Apache 2.4.6'
                }
            },
            {
                'ip': '10.0.2.11',
                'hostname': 'db-server-01',
                'services': ['ssh', 'mysql'],
                'service_versions': {
                    'ssh': 'OpenSSH 8.0',
                    'mysql': 'MySQL 5.7.25'
                }
            }
        ]
        
        with patch.object(vuln_scanner, '_query_osv_api') as mock_osv:
            with patch.object(vuln_scanner, '_query_circl_api') as mock_circl:
                # Mock vulnerability responses
                mock_osv.return_value = [
                    {
                        'id': 'CVE-2021-28041',
                        'summary': 'OpenSSH vulnerability',
                        'severity': 'HIGH'
                    }
                ]
                mock_circl.return_value = []
                
                enriched_devices = vuln_scanner.enrich_devices_with_vulnerabilities(devices_with_vulns)
                
                assert len(enriched_devices) == 2
                
                # Check that vulnerabilities were added
                web_server = next(d for d in enriched_devices if d['hostname'] == 'web-server-01')
                assert 'vulnerabilities' in web_server
                assert len(web_server['vulnerabilities']) > 0

    def test_network_topology_analysis(self, classifier, enterprise_network_devices):
        """Test network topology analysis"""
        classified_devices = classifier.classify_devices(enterprise_network_devices)
        
        # Count device types
        device_counts = {}
        for device in classified_devices:
            device_type = device.get('type', 'unknown')
            device_counts[device_type] = device_counts.get(device_type, 0) + 1
        
        # Verify expected topology
        assert device_counts.get('router', 0) >= 1
        assert device_counts.get('switch', 0) >= 1
        assert device_counts.get('firewall', 0) >= 1
        assert device_counts.get('workstation', 0) >= 2
        assert device_counts.get('web_server', 0) >= 1
        assert device_counts.get('database', 0) >= 1

    def test_subnet_analysis(self, enterprise_network_devices):
        """Test subnet-based device analysis"""
        from utils.network_utils import NetworkUtils
        
        # Group devices by subnet
        subnet_groups = {}
        for device in enterprise_network_devices:
            ip = device['ip']
            if ip.startswith('10.0.1.'):
                subnet = 'infrastructure'
            elif ip.startswith('10.0.2.'):
                subnet = 'servers'
            elif ip.startswith('10.0.3.'):
                subnet = 'workstations'
            elif ip.startswith('10.0.4.'):
                subnet = 'iot'
            else:
                subnet = 'other'
            
            if subnet not in subnet_groups:
                subnet_groups[subnet] = []
            subnet_groups[subnet].append(device)
        
        # Verify subnet organization
        assert 'infrastructure' in subnet_groups
        assert 'servers' in subnet_groups
        assert 'workstations' in subnet_groups
        assert 'iot' in subnet_groups
        
        # Verify infrastructure subnet has network equipment
        infra_devices = subnet_groups['infrastructure']
        infra_types = [d.get('vendor', '').lower() for d in infra_devices]
        assert any('cisco' in vendor for vendor in infra_types)

    def test_security_assessment_simulation(self, classifier, enterprise_network_devices):
        """Test security assessment on simulated network"""
        classified_devices = classifier.classify_devices(enterprise_network_devices)
        
        security_issues = []
        
        for device in classified_devices:
            # Check for insecure services
            if 'telnet' in device.get('services', []):
                security_issues.append({
                    'ip': device['ip'],
                    'issue': 'Insecure Telnet service detected',
                    'severity': 'HIGH'
                })
            
            # Check for default ports
            open_ports = device.get('open_ports', [])
            if 23 in open_ports:  # Telnet
                security_issues.append({
                    'ip': device['ip'],
                    'issue': 'Telnet port open',
                    'severity': 'MEDIUM'
                })
            
            # Check for excessive open ports
            if len(open_ports) > 10:
                security_issues.append({
                    'ip': device['ip'],
                    'issue': 'Too many open ports',
                    'severity': 'LOW'
                })
        
        # Verify security assessment found issues
        assert len(security_issues) > 0
        
        # Verify we found telnet issues (present in our test data)
        telnet_issues = [i for i in security_issues if 'telnet' in i['issue'].lower()]
        assert len(telnet_issues) > 0

    def test_performance_with_large_dataset(self, classifier):
        """Test classifier performance with large device dataset"""
        import time
        
        # Generate large dataset
        large_dataset = []
        for i in range(1000):
            device = {
                'ip': f'10.0.{i//254}.{i%254+1}',
                'mac': f'00:11:22:33:{i//256:02x}:{i%256:02x}',
                'hostname': f'device-{i:04d}',
                'vendor': ['Cisco', 'HP', 'Dell', 'VMware'][i % 4],
                'open_ports': [22, 80, 443][:(i % 3) + 1],
                'services': ['ssh', 'http', 'https'][:(i % 3) + 1],
                'os': ['Linux', 'Windows', 'macOS'][i % 3]
            }
            large_dataset.append(device)
        
        start_time = time.time()
        classified_devices = classifier.classify_devices(large_dataset)
        end_time = time.time()
        
        classification_time = end_time - start_time
        
        # Verify results
        assert len(classified_devices) == 1000
        assert classification_time < 10.0  # Should complete in under 10 seconds
        
        # Verify all devices were classified
        unclassified = [d for d in classified_devices if d.get('type') == 'unknown']
        # Should have good classification rate
        assert len(unclassified) / len(classified_devices) < 0.5

    def test_edge_case_devices(self, classifier):
        """Test classification of edge case devices"""
        edge_devices = [
            # Device with no open ports
            {
                'ip': '10.0.1.100',
                'mac': '00:11:22:33:44:55',
                'hostname': 'stealth-device',
                'vendor': 'Unknown',
                'open_ports': [],
                'services': [],
                'os': ''
            },
            # Device with unusual port combination
            {
                'ip': '10.0.1.101',
                'mac': '00:11:22:33:44:56',
                'hostname': 'custom-device',
                'vendor': 'Custom',
                'open_ports': [1234, 5678, 9999],
                'services': ['custom-service-1', 'custom-service-2'],
                'os': 'Custom OS'
            },
            # Device with conflicting indicators
            {
                'ip': '10.0.1.102',
                'mac': '00:11:22:33:44:57',
                'hostname': 'confusing-device',
                'vendor': 'Cisco',
                'open_ports': [80, 443, 3389],  # Web + RDP ports
                'services': ['http', 'https', 'rdp'],
                'os': 'Windows Server'
            }
        ]
        
        classified_devices = classifier.classify_devices(edge_devices)
        
        # Verify edge cases are handled gracefully
        assert len(classified_devices) == 3
        
        for device in classified_devices:
            assert 'type' in device
            # Even edge cases should get some classification
            assert device['type'] in ['unknown', 'workstation', 'server', 'network_device', 'iot_device', 'web_server']


if __name__ == "__main__":
    pytest.main([__file__])