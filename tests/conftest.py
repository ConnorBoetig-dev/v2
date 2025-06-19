"""
Pytest configuration and shared fixtures for NetworkMapper tests
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_subprocess():
    """Mock subprocess calls for scanner tests"""
    with patch("subprocess.Popen") as mock_popen:
        mock_process = Mock()
        mock_process.poll.return_value = 0
        mock_process.returncode = 0
        mock_process.stdout = iter([])
        mock_process.stderr = iter([])
        mock_popen.return_value = mock_process
        yield mock_popen


@pytest.fixture
def sample_devices():
    """Common device list for testing"""
    return [
        {
            "ip": "10.0.1.1",
            "mac": "00:11:22:33:44:55",
            "hostname": "router01",
            "type": "router",
            "vendor": "Cisco",
            "open_ports": [22, 80, 443, 161],
            "services": ["ssh", "http", "https", "snmp"],
            "os": "Cisco IOS",
        },
        {
            "ip": "10.0.1.2",
            "mac": "00:11:22:33:44:56",
            "hostname": "switch01",
            "type": "switch",
            "vendor": "Cisco",
            "open_ports": [22, 23, 161],
            "services": ["ssh", "telnet", "snmp"],
        },
        {
            "ip": "10.0.2.1",
            "mac": "00:11:22:33:44:57",
            "hostname": "web01",
            "type": "web_server",
            "vendor": "Dell",
            "open_ports": [22, 80, 443],
            "services": ["ssh", "http", "https"],
            "os": "Ubuntu 20.04",
        },
    ]


@pytest.fixture
def sample_flow_matrix():
    """Common traffic flow matrix for testing"""
    return {
        "10.0.2.1": {"10.0.3.1": 1000, "10.0.3.2": 500},
        "10.0.3.1": {"10.0.2.1": 200, "10.0.1.1": 50},
        "10.0.3.2": {"10.0.2.1": 300, "10.0.1.1": 50},
    }
