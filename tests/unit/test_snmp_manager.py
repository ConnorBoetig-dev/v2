"""Unit tests for SNMP manager module"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import subprocess

from utils.snmp_manager import SNMPManager


class TestSNMPManager:
    """Test SNMP manager functionality"""
    
    @pytest.fixture
    def snmp_manager(self):
        """Create SNMP manager instance"""
        return SNMPManager()
    
    @pytest.fixture
    def snmp_v2_config(self):
        """Sample SNMPv2c configuration"""
        return {
            'version': 'v2c',
            'community': 'public',
            'timeout': 2,
            'retries': 1
        }
    
    @pytest.fixture
    def snmp_v3_config(self):
        """Sample SNMPv3 configuration"""
        return {
            'version': 'v3',
            'username': 'admin',
            'auth_protocol': 'SHA',
            'auth_password': 'authpass123',
            'priv_protocol': 'AES',
            'priv_password': 'privpass123',
            'timeout': 2,
            'retries': 1
        }
    
    def test_init(self, snmp_manager):
        """Test SNMP manager initialization"""
        assert snmp_manager.oids is not None
        assert 'sysDescr' in snmp_manager.oids
        assert 'sysName' in snmp_manager.oids
        assert 'sysUpTime' in snmp_manager.oids
    
    def test_filter_snmp_candidates(self, snmp_manager):
        """Test filtering devices for SNMP enrichment"""
        devices = [
            {'ip': '192.168.1.1', 'type': 'router'},
            {'ip': '192.168.1.2', 'type': 'switch'},
            {'ip': '192.168.1.3', 'type': 'printer'},
            {'ip': '192.168.1.4', 'type': 'server'},
            {'ip': '192.168.1.5', 'type': 'workstation'},
            {'ip': '192.168.1.6', 'type': 'network_device'}
        ]
        
        candidates = snmp_manager.filter_snmp_candidates(devices)
        
        # Should include router, switch, printer, server, network_device
        assert len(candidates) == 5
        ips = [d['ip'] for d in candidates]
        assert '192.168.1.5' not in ips  # Workstation should be excluded
    
    @patch('subprocess.run')
    def test_enrich_devices_v2c(self, mock_run, snmp_manager, snmp_v2_config):
        """Test device enrichment with SNMPv2c"""
        devices = [{'ip': '192.168.1.1', 'type': 'router'}]
        
        # Mock successful SNMP response
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='SNMPv2-MIB::sysDescr.0 = STRING: Test Router\n'
        )
        
        enriched = snmp_manager.enrich_devices(devices, snmp_v2_config)
        
        assert len(enriched) == 1
        assert 'snmp_data' in enriched[0]
        assert enriched[0]['snmp_data']['sysDescr'] == 'Test Router'
        
        # Verify snmpget was called with correct arguments
        mock_run.assert_called()
        call_args = mock_run.call_args[0][0]
        assert 'snmpget' in call_args
        assert '-v2c' in call_args
        assert '-c' in call_args
        assert 'public' in call_args
    
    @patch('subprocess.run')
    def test_enrich_devices_v3(self, mock_run, snmp_manager, snmp_v3_config):
        """Test device enrichment with SNMPv3"""
        devices = [{'ip': '192.168.1.1', 'type': 'switch'}]
        
        # Mock successful SNMP response
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='SNMPv2-MIB::sysName.0 = STRING: core-switch\n'
        )
        
        enriched = snmp_manager.enrich_devices(devices, snmp_v3_config)
        
        assert len(enriched) == 1
        assert 'snmp_data' in enriched[0]
        
        # Verify SNMPv3 specific arguments
        call_args = mock_run.call_args[0][0]
        assert '-v3' in call_args
        assert '-u' in call_args
        assert 'admin' in call_args
        assert '-a' in call_args
        assert 'SHA' in call_args
        assert '-x' in call_args
        assert 'AES' in call_args
    
    @patch('subprocess.run')
    def test_query_device_no_snmp(self, mock_run, snmp_manager, snmp_v2_config):
        """Test querying device with no SNMP response"""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout='',
            stderr='Timeout: No Response from 192.168.1.1'
        )
        
        device = {'ip': '192.168.1.1', 'type': 'router'}
        snmp_manager._query_device(device, snmp_v2_config)
        
        assert 'snmp_data' not in device  # Should not add empty data
    
    @patch('subprocess.run')
    def test_query_device_exception(self, mock_run, snmp_manager, snmp_v2_config):
        """Test handling exceptions during SNMP query"""
        mock_run.side_effect = Exception("Command failed")
        
        device = {'ip': '192.168.1.1', 'type': 'router'}
        snmp_manager._query_device(device, snmp_v2_config)
        
        assert 'snmp_data' not in device  # Should handle exception gracefully
    
    def test_parse_snmp_output(self, snmp_manager):
        """Test parsing SNMP command output"""
        output = """SNMPv2-MIB::sysDescr.0 = STRING: Cisco IOS Software
SNMPv2-MIB::sysName.0 = STRING: router.local
SNMPv2-MIB::sysUpTime.0 = Timeticks: (1234567) 0:20:34.56
IF-MIB::ifNumber.0 = INTEGER: 4
"""
        
        data = snmp_manager._parse_snmp_output(output)
        
        assert data['sysDescr'] == 'Cisco IOS Software'
        assert data['sysName'] == 'router.local'
        assert data['sysUpTime'] == '0:20:34.56'
        assert data['ifNumber'] == '4'
    
    def test_parse_snmp_output_malformed(self, snmp_manager):
        """Test parsing malformed SNMP output"""
        output = """Invalid line without equals
SNMPv2-MIB::sysDescr.0 = STRING: Valid line
Another invalid line
= No OID line
"""
        
        data = snmp_manager._parse_snmp_output(output)
        
        # Should only parse valid lines
        assert len(data) == 1
        assert data['sysDescr'] == 'Valid line'
    
    def test_build_snmp_command_v1(self, snmp_manager):
        """Test building SNMP command for v1"""
        config = {
            'version': 'v1',
            'community': 'private',
            'timeout': 3,
            'retries': 2
        }
        
        cmd = snmp_manager._build_snmp_command('192.168.1.1', config, ['sysDescr'])
        
        assert cmd[0] == 'snmpget'
        assert '-v1' in cmd
        assert '-c' in cmd
        assert 'private' in cmd
        assert '-t' in cmd
        assert '3' in cmd
        assert '-r' in cmd
        assert '2' in cmd
        assert '192.168.1.1' in cmd
        assert 'SNMPv2-MIB::sysDescr.0' in cmd
    
    def test_empty_device_list(self, snmp_manager, snmp_v2_config):
        """Test enriching empty device list"""
        enriched = snmp_manager.enrich_devices([], snmp_v2_config)
        assert enriched == []
    
    def test_no_config_provided(self, snmp_manager):
        """Test enrichment with no config"""
        devices = [{'ip': '192.168.1.1', 'type': 'router'}]
        enriched = snmp_manager.enrich_devices(devices, None)
        assert enriched == devices  # Should return unchanged
    
    @patch('subprocess.run')
    def test_multiple_devices(self, mock_run, snmp_manager, snmp_v2_config):
        """Test enriching multiple devices"""
        devices = [
            {'ip': '192.168.1.1', 'type': 'router'},
            {'ip': '192.168.1.2', 'type': 'switch'},
            {'ip': '192.168.1.3', 'type': 'workstation'}  # Should be skipped
        ]
        
        # Mock different responses
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout='SNMPv2-MIB::sysDescr.0 = STRING: Router\n'),
            MagicMock(returncode=0, stdout='SNMPv2-MIB::sysDescr.0 = STRING: Switch\n')
        ]
        
        enriched = snmp_manager.enrich_devices(devices, snmp_v2_config)
        
        assert len(enriched) == 3
        assert 'snmp_data' in enriched[0]
        assert 'snmp_data' in enriched[1]
        assert 'snmp_data' not in enriched[2]  # Workstation should not be queried
        
        # Verify only 2 SNMP queries were made (router and switch)
        assert mock_run.call_count == 2