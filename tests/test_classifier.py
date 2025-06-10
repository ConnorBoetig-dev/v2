#!/usr/bin/env python3
"""
Test suite for core/classifier.py
"""

import pytest
from core.classifier import DeviceClassifier


class TestDeviceClassifier:
    """Test DeviceClassifier class"""
    
    @pytest.fixture
    def classifier(self):
        """Create classifier instance for testing"""
        return DeviceClassifier()
    
    def test_init(self, classifier):
        """Test classifier initialization"""
        assert len(classifier.port_signatures) > 0
        assert 'router' in classifier.port_signatures
        assert 'web_server' in classifier.port_signatures
        assert 'database' in classifier.port_signatures
    
    def test_classify_router(self, classifier):
        """Test router classification"""
        device = {
            'ip': '10.0.1.1',
            'open_ports': [22, 23, 80, 443, 161],
            'services': ['ssh', 'telnet', 'http', 'https', 'snmp'],
            'os': 'Cisco IOS',
            'vendor': 'Cisco'
        }
        
        device_type, confidence = classifier._classify_single_device(device)
        assert device_type.value == 'router'
        assert confidence >= 0.8
    
    def test_classify_switch(self, classifier):
        """Test switch classification"""
        device = {
            'ip': '10.0.1.2',
            'open_ports': [22, 23, 80, 161],
            'services': ['ssh', 'telnet', 'http', 'snmp'],
            'vendor': 'Cisco'
        }
        
        device_type, confidence = classifier._classify_single_device(device)
        assert device_type.value == 'switch'
        assert confidence >= 0.7
    
    def test_classify_web_server(self, classifier):
        """Test web server classification"""
        device = {
            'ip': '10.0.2.10',
            'open_ports': [22, 80, 443],
            'services': ['ssh', 'http', 'https'],
            'os': 'Linux'
        }
        
        device_type, confidence = classifier._classify_single_device(device)
        assert device_type.value == 'web_server'
        assert confidence >= 0.7
    
    def test_classify_database(self, classifier):
        """Test database classification"""
        # Test MySQL
        device = {
            'ip': '10.0.3.10',
            'open_ports': [3306, 22],
            'services': ['mysql', 'ssh']
        }
        device_type, confidence = classifier._classify_single_device(device)
        assert device_type.value == 'database'
        assert confidence >= 0.8
        
        # Test PostgreSQL
        device = {
            'ip': '10.0.3.11',
            'open_ports': [5432, 22],
            'services': ['postgresql', 'ssh']
        }
        device_type, confidence = classifier._classify_single_device(device)
        assert device_type.value == 'database'
        assert confidence >= 0.8
    
    def test_classify_workstation(self, classifier):
        """Test workstation classification"""
        device = {
            'ip': '10.0.4.50',
            'open_ports': [445, 3389],
            'services': ['smb', 'rdp'],
            'os': 'Windows 10'
        }
        
        device_type, confidence = classifier._classify_single_device(device)
        assert device_type.value == 'workstation'
        assert confidence >= 0.7
    
    def test_classify_printer(self, classifier):
        """Test printer classification"""
        device = {
            'ip': '10.0.5.100',
            'open_ports': [80, 631, 9100],
            'services': ['http', 'ipp', 'jetdirect'],
            'vendor': 'HP'
        }
        
        device_type, confidence = classifier._classify_single_device(device)
        assert device_type.value == 'printer'
        assert confidence >= 0.8
    
    def test_classify_firewall(self, classifier):
        """Test firewall classification"""
        device = {
            'ip': '10.0.1.254',
            'open_ports': [22, 443],
            'services': ['ssh', 'https'],
            'os': 'pfSense',
            'vendor': 'Netgate'
        }
        
        device_type, confidence = classifier._classify_single_device(device)
        assert device_type.value == 'firewall'
        assert confidence >= 0.8
    
    def test_classify_unknown(self, classifier):
        """Test unknown device classification"""
        device = {
            'ip': '10.0.6.200',
            'open_ports': [12345],
            'services': ['unknown']
        }
        
        device_type, confidence = classifier._classify_single_device(device)
        assert device_type.value == 'unknown'
        assert confidence < 0.5
    
    def test_confidence_calculation(self, classifier):
        """Test confidence score calculation"""
        # High confidence - many matching indicators
        device = {
            'ip': '10.0.1.1',
            'open_ports': [22, 23, 80, 443, 161, 179],
            'services': ['ssh', 'telnet', 'http', 'https', 'snmp', 'bgp'],
            'os': 'Cisco IOS',
            'vendor': 'Cisco',
            'hostname': 'core-router'
        }
        _, confidence = classifier._classify_single_device(device)
        assert confidence >= 0.9
        
        # Low confidence - few matching indicators
        device = {
            'ip': '10.0.1.2',
            'open_ports': [80],
            'services': ['http']
        }
        _, confidence = classifier._classify_single_device(device)
        assert confidence < 0.7
    
    def test_service_matching(self, classifier):
        """Test service-based classification"""
        device = {
            'ip': '10.0.7.10',
            'open_ports': [554, 80],
            'services': ['rtsp', 'http'],
            'vendor': 'Hikvision'
        }
        
        device_type, confidence = classifier._classify_single_device(device)
        assert device_type.value == 'iot'
        assert confidence >= 0.7