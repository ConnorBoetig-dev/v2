#!/usr/bin/env python3
"""
Test suite for utility modules
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
import json

from utils.mac_lookup import MACLookup
from utils.network_utils import NetworkUtils


class TestMACLookup:
    """Test MacLookup class"""
    
    @pytest.fixture
    def mac_lookup(self):
        """Create MACLookup instance for testing"""
        with patch('utils.mac_lookup.MACLookup._load_oui_database'):
            return MACLookup()
    
    def test_lookup_known_vendor(self, mac_lookup):
        """Test looking up known MAC vendor"""
        # Add test data
        mac_lookup.oui_db = {
            '00:11:22': 'Cisco Systems',
            'AA:BB:CC': 'Test Vendor'
        }
        
        assert mac_lookup.lookup('00:11:22:33:44:55') == 'Cisco Systems'
        assert mac_lookup.lookup('aa:bb:cc:dd:ee:ff') == 'Test Vendor'  # Case insensitive
    
    def test_lookup_unknown_vendor(self, mac_lookup):
        """Test looking up unknown MAC vendor"""
        mac_lookup.oui_db = {}
        assert mac_lookup.lookup('00:11:22:33:44:55') == 'Unknown'
    
    def test_lookup_invalid_mac(self, mac_lookup):
        """Test looking up invalid MAC address"""
        assert mac_lookup.lookup('invalid') == 'Unknown'
        assert mac_lookup.lookup('') == 'Unknown'
        assert mac_lookup.lookup(None) == 'Unknown'
    
    def test_is_virtual_machine(self, mac_lookup):
        """Test virtual machine MAC detection"""
        # VMware MACs
        assert mac_lookup.is_virtual_machine('00:50:56:12:34:56') is True
        assert mac_lookup.is_virtual_machine('00:0C:29:12:34:56') is True
        assert mac_lookup.is_virtual_machine('00:05:69:12:34:56') is True
        
        # VirtualBox MACs
        assert mac_lookup.is_virtual_machine('08:00:27:12:34:56') is True
        
        # Physical MAC
        assert mac_lookup.is_virtual_machine('00:11:22:33:44:55') is False
    
    @patch('urllib.request.urlopen')
    def test_update_database(self, mock_urlopen, mac_lookup):
        """Test OUI database update"""
        # Mock response
        mock_response = Mock()
        mock_response.read.return_value = b"""
        00-11-22   (hex)		Cisco Systems
        001122     (base 16)		Cisco Systems
        				123 Main St
        
        AA-BB-CC   (hex)		Test Vendor
        AABBCC     (base 16)		Test Vendor
        				456 Test Ave
        """
        mock_urlopen.return_value = mock_response
        
        with patch('builtins.open', mock_open()):
            result = mac_lookup.update_database()
            assert result is True
        
        # Verify parsed data
        assert mac_lookup.oui_db['00:11:22'] == 'Cisco Systems'
        assert mac_lookup.oui_db['AA:BB:CC'] == 'Test Vendor'
    
    def test_load_cache(self, mac_lookup):
        """Test loading OUI cache"""
        cache_data = {
            '00:11:22': 'Cached Vendor',
            'AA:BB:CC': 'Another Vendor'
        }
        
        with patch('builtins.open', mock_open(read_data=json.dumps(cache_data))):
            with patch('pathlib.Path.exists', return_value=True):
                mac_lookup._load_oui_database()
                
        assert mac_lookup.oui_db == cache_data


class TestNetworkUtils:
    """Test NetworkUtils class"""
    
    def test_validate_target(self):
        """Test target validation"""
        # Valid targets
        assert NetworkUtils.validate_target('10.0.1.1')[0] is True
        assert NetworkUtils.validate_target('192.168.1.0/24')[0] is True
        assert NetworkUtils.validate_target('172.16.0.0/16')[0] is True
        
        # Invalid targets
        assert NetworkUtils.validate_target('256.1.1.1')[0] is False
        # Note: 'invalid' and '' may timeout on hostname resolution
    
    def test_expand_network(self):
        """Test network expansion"""
        # Single IP
        result = NetworkUtils.expand_network('10.0.1.1')
        assert result == ['10.0.1.1']
        
        # Small network
        result = NetworkUtils.expand_network('10.0.1.0/30')
        assert len(result) == 2
        assert '10.0.1.1' in result
        assert '10.0.1.2' in result
    
    def test_get_subnet(self):
        """Test subnet calculation"""
        # Test getting /24 subnet
        result = NetworkUtils.get_subnet('10.0.1.100')
        assert result == '10.0.1.0/24'
        
        result = NetworkUtils.get_subnet('192.168.50.200')
        assert result == '192.168.50.0/24'