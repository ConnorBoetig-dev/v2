#!/usr/bin/env python3
"""
Test suite for core/parser.py
"""

import pytest
from core.parser import ScanParser


class TestScanParser:
    """Test ScanParser class"""
    
    @pytest.fixture
    def parser(self):
        """Create parser instance for testing"""
        return ScanParser()
    
    def test_parse_nmap_xml(self, parser):
        """Test parsing of nmap XML output"""
        nmap_xml = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <status state="up"/>
                <address addr="10.0.1.1" addrtype="ipv4"/>
                <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Cisco"/>
                <hostnames>
                    <hostname name="router01.local" type="PTR"/>
                </hostnames>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="open"/>
                        <service name="ssh" product="OpenSSH" version="7.9"/>
                    </port>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http" product="nginx" version="1.14.0"/>
                    </port>
                </ports>
                <os>
                    <osmatch name="Cisco IOS 15.X" accuracy="95"/>
                </os>
            </host>
        </nmaprun>"""
        
        devices = parser.parse_nmap_xml(nmap_xml)
        assert len(devices) == 1
        assert devices[0]['ip'] == '10.0.1.1'
        assert devices[0]['mac'] == '00:11:22:33:44:55'
        assert devices[0]['vendor'] == 'Cisco'
        assert devices[0]['hostname'] == 'router01.local'
        assert 22 in devices[0]['open_ports']
        assert 80 in devices[0]['open_ports']
        assert 'ssh' in devices[0]['services']
        assert 'http' in devices[0]['services']
        assert devices[0]['os'] == 'Cisco IOS 15.X'
    
    def test_parse_nmap_text(self, parser):
        """Test parsing of nmap text output"""
        nmap_text = """
Starting Nmap 7.92
Nmap scan report for router01.local (10.0.1.1)
Host is up (0.001s latency).
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.9
80/tcp   open  http       nginx 1.14.0
443/tcp  open  ssl/https  nginx 1.14.0
MAC Address: 00:11:22:33:44:55 (Cisco Systems)
Device type: router
Running: Cisco IOS 15.X
OS details: Cisco IOS 15.X

Nmap scan report for 10.0.1.2
Host is up (0.002s latency).
PORT     STATE SERVICE
3306/tcp open  mysql
"""
        
        devices = parser.parse_nmap_text(nmap_text)
        assert len(devices) == 2
        
        # Check first device
        assert devices[0]['ip'] == '10.0.1.1'
        assert devices[0]['hostname'] == 'router01.local'
        assert devices[0]['mac'] == '00:11:22:33:44:55'
        assert devices[0]['vendor'] == 'Cisco Systems'
        assert devices[0]['open_ports'] == [22, 80, 443]
        assert set(devices[0]['services']) == {'ssh', 'http', 'ssl/https'}
        assert devices[0]['os'] == 'Cisco IOS 15.X'
        
        # Check second device
        assert devices[1]['ip'] == '10.0.1.2'
        assert devices[1]['open_ports'] == [3306]
        assert devices[1]['services'] == ['mysql']
    
    def test_parse_masscan_json(self, parser):
        """Test parsing of masscan JSON output"""
        masscan_json = """[
        {   "ip": "10.0.1.1",
            "timestamp": "1640000000", 
            "ports": [
                {"port": 22, "proto": "tcp", "status": "open", "ttl": 64},
                {"port": 80, "proto": "tcp", "status": "open", "ttl": 64}
            ]
        },
        {   "ip": "10.0.1.2",
            "timestamp": "1640000001",
            "ports": [
                {"port": 443, "proto": "tcp", "status": "open", "ttl": 64}
            ]
        }
        ]"""
        
        devices = parser.parse_masscan_json(masscan_json)
        assert len(devices) == 2
        assert devices[0]['ip'] == '10.0.1.1'
        assert devices[0]['open_ports'] == [22, 80]
        assert devices[1]['ip'] == '10.0.1.2'
        assert devices[1]['open_ports'] == [443]
    
    def test_parse_arp_scan(self, parser):
        """Test parsing of arp-scan output"""
        arp_output = """
Interface: eth0, type: EN10MB, MAC: 00:11:22:33:44:99, IPv4: 10.0.1.254
Starting arp-scan 1.9.7
10.0.1.1\t00:11:22:33:44:55\tCisco Systems, Inc
10.0.1.2\t00:11:22:33:44:56\tDell Inc.
10.0.1.3\t00:11:22:33:44:57\tHewlett Packard Enterprise
10.0.1.4\t00:11:22:33:44:58\t(Unknown)

4 packets received by filter, 0 packets dropped by kernel
"""
        
        devices = parser.parse_arp_scan(arp_output)
        assert len(devices) == 4
        assert devices[0]['ip'] == '10.0.1.1'
        assert devices[0]['mac'] == '00:11:22:33:44:55'
        assert devices[0]['vendor'] == 'Cisco Systems, Inc'
        assert devices[3]['vendor'] == 'Unknown'
    
    def test_normalize_device(self, parser):
        """Test device normalization"""
        raw_device = {
            'ip': '10.0.1.1',
            'mac': '00:11:22:33:44:55',
            'hostname': 'router01',
            'ports': [22, 80, 443],
            'service_list': ['ssh', 'http', 'https'],
            'operating_system': 'Cisco IOS',
            'manufacturer': 'Cisco'
        }
        
        normalized = parser.normalize_device(raw_device)
        assert normalized['ip'] == '10.0.1.1'
        assert normalized['mac'] == '00:11:22:33:44:55'
        assert normalized['hostname'] == 'router01'
        assert normalized['open_ports'] == [22, 80, 443]
        assert normalized['services'] == ['ssh', 'http', 'https']
        assert normalized['os'] == 'Cisco IOS'
        assert normalized['vendor'] == 'Cisco'
        assert 'last_seen' in normalized
    
    def test_merge_scan_results(self, parser):
        """Test merging of multiple scan results"""
        nmap_results = [
            {
                'ip': '10.0.1.1',
                'hostname': 'router01',
                'open_ports': [22, 80],
                'services': ['ssh', 'http'],
                'os': 'Cisco IOS'
            }
        ]
        
        arp_results = [
            {
                'ip': '10.0.1.1',
                'mac': '00:11:22:33:44:55',
                'vendor': 'Cisco'
            },
            {
                'ip': '10.0.1.2',
                'mac': '00:11:22:33:44:56',
                'vendor': 'Dell'
            }
        ]
        
        merged = parser.merge_scan_results([nmap_results, arp_results])
        assert len(merged) == 2
        
        # Check merged device
        router = next(d for d in merged if d['ip'] == '10.0.1.1')
        assert router['hostname'] == 'router01'
        assert router['mac'] == '00:11:22:33:44:55'
        assert router['vendor'] == 'Cisco'
        assert router['open_ports'] == [22, 80]
        assert router['os'] == 'Cisco IOS'
        
        # Check ARP-only device
        dell = next(d for d in merged if d['ip'] == '10.0.1.2')
        assert dell['mac'] == '00:11:22:33:44:56'
        assert dell['vendor'] == 'Dell'
    
    def test_invalid_input_handling(self, parser):
        """Test handling of invalid input"""
        # Empty input
        assert parser.parse_nmap_text("") == []
        assert parser.parse_masscan_json("") == []
        assert parser.parse_arp_scan("") == []
        
        # Invalid format
        assert parser.parse_masscan_json("not json") == []
        assert parser.parse_nmap_xml("not xml") == []