#!/usr/bin/env python3
"""
Test suite for core/tracker.py
"""

import pytest
from datetime import datetime, timedelta
from core.tracker import ChangeTracker


class TestChangeTracker:
    """Test ChangeTracker class"""
    
    @pytest.fixture
    def tracker(self):
        """Create tracker instance for testing"""
        return ChangeTracker()
    
    @pytest.fixture
    def old_devices(self):
        """Sample old device list"""
        return [
            {
                'ip': '10.0.1.1',
                'mac': '00:11:22:33:44:55',
                'hostname': 'router01',
                'open_ports': [22, 80, 443],
                'services': ['ssh', 'http', 'https'],
                'os': 'Cisco IOS',
                'vendor': 'Cisco'
            },
            {
                'ip': '10.0.1.2',
                'mac': '00:11:22:33:44:56',
                'hostname': 'server01',
                'open_ports': [22, 80],
                'services': ['ssh', 'http'],
                'os': 'Ubuntu',
                'vendor': 'Dell'
            },
            {
                'ip': '10.0.1.3',
                'mac': '00:11:22:33:44:57',
                'hostname': 'workstation01',
                'open_ports': [3389],
                'services': ['rdp'],
                'os': 'Windows 10',
                'vendor': 'HP'
            }
        ]
    
    @pytest.fixture
    def new_devices(self):
        """Sample new device list with changes"""
        return [
            {
                'ip': '10.0.1.1',
                'mac': '00:11:22:33:44:55',
                'hostname': 'router01',
                'open_ports': [22, 80, 443, 161],  # Added SNMP
                'services': ['ssh', 'http', 'https', 'snmp'],
                'os': 'Cisco IOS',
                'vendor': 'Cisco'
            },
            {
                'ip': '10.0.1.2',
                'mac': '00:11:22:33:44:56',
                'hostname': 'server01',
                'open_ports': [22],  # Removed HTTP
                'services': ['ssh'],
                'os': 'Ubuntu',
                'vendor': 'Dell'
            },
            {
                'ip': '10.0.1.4',  # New device
                'mac': '00:11:22:33:44:58',
                'hostname': 'server02',
                'open_ports': [22, 3306],
                'services': ['ssh', 'mysql'],
                'os': 'CentOS',
                'vendor': 'Dell'
            }
        ]
    
    def test_track_changes_new_devices(self, tracker, old_devices, new_devices):
        """Test detection of new devices"""
        changes = tracker.track_changes(old_devices, new_devices)
        
        assert len(changes['new_devices']) == 1
        assert changes['new_devices'][0]['ip'] == '10.0.1.4'
        assert changes['new_devices'][0]['hostname'] == 'server02'
    
    def test_track_changes_missing_devices(self, tracker, old_devices, new_devices):
        """Test detection of missing devices"""
        changes = tracker.track_changes(old_devices, new_devices)
        
        assert len(changes['missing_devices']) == 1
        assert changes['missing_devices'][0]['ip'] == '10.0.1.3'
        assert changes['missing_devices'][0]['hostname'] == 'workstation01'
    
    def test_track_changes_modified_devices(self, tracker, old_devices, new_devices):
        """Test detection of modified devices"""
        changes = tracker.track_changes(old_devices, new_devices)
        
        assert len(changes['modified_devices']) == 2
        
        # Check router modifications (added port)
        router_change = next(d for d in changes['modified_devices'] if d['ip'] == '10.0.1.1')
        assert 'services' in router_change['changes']
        assert 161 in router_change['changes']['open_ports']['added']
        
        # Check server modifications (removed port)
        server_change = next(d for d in changes['modified_devices'] if d['ip'] == '10.0.1.2')
        assert 80 in server_change['changes']['open_ports']['removed']
    
    def test_track_changes_no_changes(self, tracker, old_devices):
        """Test when there are no changes"""
        changes = tracker.track_changes(old_devices, old_devices)
        
        assert len(changes['new_devices']) == 0
        assert len(changes['missing_devices']) == 0
        assert len(changes['modified_devices']) == 0
    
    def test_compare_devices_ports(self, tracker):
        """Test device comparison for port changes"""
        old = {
            'ip': '10.0.1.1',
            'open_ports': [22, 80, 443]
        }
        new = {
            'ip': '10.0.1.1',
            'open_ports': [22, 443, 8080]
        }
        
        changes = tracker._compare_devices(old, new)
        assert 'open_ports' in changes
        assert 80 in changes['open_ports']['removed']
        assert 8080 in changes['open_ports']['added']
    
    def test_compare_devices_services(self, tracker):
        """Test device comparison for service changes"""
        old = {
            'ip': '10.0.1.1',
            'services': ['ssh', 'http', 'https']
        }
        new = {
            'ip': '10.0.1.1',
            'services': ['ssh', 'https', 'snmp']
        }
        
        changes = tracker._compare_devices(old, new)
        assert 'services' in changes
        assert 'http' in changes['services']['removed']
        assert 'snmp' in changes['services']['added']
    
    def test_compare_devices_attributes(self, tracker):
        """Test device comparison for attribute changes"""
        old = {
            'ip': '10.0.1.1',
            'hostname': 'oldname',
            'os': 'Ubuntu 18.04',
            'vendor': 'Dell'
        }
        new = {
            'ip': '10.0.1.1',
            'hostname': 'newname',
            'os': 'Ubuntu 20.04',
            'vendor': 'Dell'
        }
        
        changes = tracker._compare_devices(old, new)
        assert changes['hostname'] == {'old': 'oldname', 'new': 'newname'}
        assert changes['os'] == {'old': 'Ubuntu 18.04', 'new': 'Ubuntu 20.04'}
        assert 'vendor' not in changes  # No change
    
    def test_format_change_summary(self, tracker, old_devices, new_devices):
        """Test change summary formatting"""
        changes = tracker.track_changes(old_devices, new_devices)
        summary = tracker.format_change_summary(changes)
        
        assert 'New Devices: 1' in summary
        assert 'Missing Devices: 1' in summary
        assert 'Modified Devices: 2' in summary
        assert '10.0.1.4' in summary
        assert 'server02' in summary
    
    def test_empty_lists(self, tracker):
        """Test handling of empty device lists"""
        # All devices are new
        changes = tracker.track_changes([], [{'ip': '10.0.1.1'}])
        assert len(changes['new_devices']) == 1
        assert len(changes['missing_devices']) == 0
        
        # All devices are missing
        changes = tracker.track_changes([{'ip': '10.0.1.1'}], [])
        assert len(changes['new_devices']) == 0
        assert len(changes['missing_devices']) == 1
    
    def test_ip_change_detection(self, tracker):
        """Test detection of IP address changes for same MAC"""
        old = [{
            'ip': '10.0.1.1',
            'mac': '00:11:22:33:44:55',
            'hostname': 'device01'
        }]
        new = [{
            'ip': '10.0.1.100',  # Different IP
            'mac': '00:11:22:33:44:55',  # Same MAC
            'hostname': 'device01'
        }]
        
        changes = tracker.track_changes(old, new)
        # Should detect as modified device (IP changed)
        assert len(changes['modified_devices']) == 1
        assert changes['modified_devices'][0]['mac'] == '00:11:22:33:44:55'