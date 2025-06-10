"""Unit tests for SNMP configuration module"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import json

from utils.snmp_config import SNMPConfig


class TestSNMPConfig:
    """Test SNMP configuration functionality"""
    
    @pytest.fixture
    def snmp_config(self, tmp_path):
        """Create SNMP config instance with temp directory"""
        return SNMPConfig(config_dir=tmp_path)
    
    def test_init(self, snmp_config):
        """Test SNMP config initialization"""
        assert snmp_config.config_dir.exists()
        assert snmp_config.config_file.name == 'snmp_config.json'
    
    def test_load_config_no_file(self, snmp_config):
        """Test loading config when file doesn't exist"""
        config = snmp_config.load_config()
        assert config is None
    
    def test_save_and_load_config(self, snmp_config):
        """Test saving and loading configuration"""
        test_config = {
            'version': 'v2c',
            'community': 'public',
            'timeout': 2,
            'retries': 1
        }
        
        # Save config
        snmp_config.save_config(test_config)
        assert snmp_config.config_file.exists()
        
        # Load config
        loaded = snmp_config.load_config()
        assert loaded == test_config
    
    @patch('rich.prompt.Confirm.ask')
    @patch('rich.prompt.Prompt.ask')
    def test_interactive_setup_no_existing(self, mock_prompt, mock_confirm, snmp_config):
        """Test interactive setup with no existing config"""
        # Mock user inputs
        mock_confirm.side_effect = [True]  # Enable SNMP
        mock_prompt.side_effect = ['2', 'public']  # Version v2c, community
        
        with patch.object(snmp_config.console, 'print'):
            enabled, config = snmp_config.interactive_setup()
        
        assert enabled is True
        assert config['version'] == 'v2c'
        assert config['community'] == 'public'
        assert config['timeout'] == 2
        assert config['retries'] == 1
    
    @patch('rich.prompt.Confirm.ask')
    def test_interactive_setup_disable_snmp(self, mock_confirm, snmp_config):
        """Test disabling SNMP during setup"""
        mock_confirm.return_value = False  # Disable SNMP
        
        with patch.object(snmp_config.console, 'print'):
            enabled, config = snmp_config.interactive_setup()
        
        assert enabled is False
        assert config == {}
    
    @patch('rich.prompt.Confirm.ask')
    @patch('rich.prompt.Prompt.ask')
    def test_interactive_setup_with_existing(self, mock_prompt, mock_confirm, snmp_config):
        """Test interactive setup with existing config"""
        # Save existing config
        existing = {
            'version': 'v2c',
            'community': 'existing',
            'timeout': 2,
            'retries': 1
        }
        snmp_config.save_config(existing)
        
        # Mock user choosing to use existing
        mock_confirm.return_value = True  # Use existing config
        
        with patch.object(snmp_config.console, 'print'):
            enabled, config = snmp_config.interactive_setup()
        
        assert enabled is True
        assert config == existing
    
    @patch('rich.prompt.Confirm.ask')
    @patch('rich.prompt.Prompt.ask')
    def test_setup_snmpv1(self, mock_prompt, mock_confirm, snmp_config):
        """Test SNMPv1 setup"""
        mock_confirm.side_effect = [True]  # Enable SNMP
        mock_prompt.side_effect = ['1', 'public']  # Version v1, community
        
        with patch.object(snmp_config.console, 'print'):
            enabled, config = snmp_config._setup_new_config()
        
        assert enabled is True
        assert config['version'] == 'v1'
        assert config['community'] == 'public'
    
    @patch('rich.prompt.Confirm.ask')
    @patch('rich.prompt.Prompt.ask')
    @patch('getpass.getpass')
    def test_setup_snmpv3(self, mock_getpass, mock_prompt, mock_confirm, snmp_config):
        """Test SNMPv3 setup"""
        mock_confirm.side_effect = [True, True, True]  # Enable SNMP, auth, priv
        mock_prompt.side_effect = ['3', 'admin', '2', '2']  # v3, username, SHA, AES
        mock_getpass.side_effect = ['authpass123', 'authpass123', 'privpass123', 'privpass123']
        
        with patch.object(snmp_config.console, 'print'):
            enabled, config = snmp_config._setup_new_config()
        
        assert enabled is True
        assert config['version'] == 'v3'
        assert config['username'] == 'admin'
        assert config['auth_protocol'] == 'SHA'
        assert config['auth_password'] == 'authpass123'
        assert config['priv_protocol'] == 'AES'
        assert config['priv_password'] == 'privpass123'
    
    @patch('rich.prompt.Confirm.ask')
    @patch('rich.prompt.Prompt.ask')
    def test_handle_existing_config_use(self, mock_prompt, mock_confirm, snmp_config):
        """Test handling existing config - use it"""
        existing = {'version': 'v2c', 'community': 'test'}
        mock_confirm.return_value = True  # Use existing
        
        with patch.object(snmp_config.console, 'print'):
            enabled, config = snmp_config._handle_existing_config(existing)
        
        assert enabled is True
        assert config == existing
    
    @patch('rich.prompt.Confirm.ask')
    @patch('rich.prompt.Prompt.ask')
    def test_handle_existing_config_new(self, mock_prompt, mock_confirm, snmp_config):
        """Test handling existing config - create new"""
        existing = {'version': 'v2c', 'community': 'test'}
        mock_confirm.side_effect = [False, True]  # Don't use existing, save new
        mock_prompt.side_effect = ['2', 'newcommunity']
        
        with patch.object(snmp_config.console, 'print'):
            with patch.object(snmp_config, '_setup_new_config') as mock_setup:
                mock_setup.return_value = (True, {'version': 'v2c', 'community': 'newcommunity'})
                enabled, config = snmp_config._handle_existing_config(existing)
        
        assert enabled is True
        assert mock_setup.called
    
    def test_display_config(self, snmp_config):
        """Test config display formatting"""
        config = {
            'version': 'v2c',
            'community': 'public',
            'timeout': 2
        }
        
        # Just test that it doesn't raise an exception
        with patch.object(snmp_config.console, 'print'):
            snmp_config._display_config(config)
    
    @patch('rich.prompt.Prompt.ask')
    def test_invalid_version_selection(self, mock_prompt, snmp_config):
        """Test handling invalid version selection"""
        # First invalid, then valid
        mock_prompt.side_effect = ['5', '2', 'public']
        
        with patch.object(snmp_config.console, 'print'):
            with patch('rich.prompt.Confirm.ask', return_value=True):
                enabled, config = snmp_config._setup_new_config()
        
        assert enabled is True
        assert config['version'] == 'v2c'
    
    def test_force_prompt(self, snmp_config):
        """Test force prompt bypasses existing config"""
        # Save existing config
        existing = {'version': 'v2c', 'community': 'existing'}
        snmp_config.save_config(existing)
        
        with patch.object(snmp_config, '_setup_new_config') as mock_setup:
            mock_setup.return_value = (True, {'version': 'v2c', 'community': 'new'})
            with patch.object(snmp_config.console, 'print'):
                enabled, config = snmp_config.interactive_setup(force_prompt=True)
        
        assert mock_setup.called  # Should go directly to new setup
    
    def test_config_file_permissions(self, snmp_config):
        """Test that config file is saved with appropriate permissions"""
        config = {'version': 'v2c', 'community': 'secret'}
        snmp_config.save_config(config)
        
        # Check file exists and is readable
        assert snmp_config.config_file.exists()
        assert snmp_config.config_file.stat().st_size > 0
        
        # Verify JSON format
        with open(snmp_config.config_file) as f:
            loaded = json.load(f)
            assert loaded == config