import json
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path


class NetworkScanner:
    def __init__(self):
        self.scan_profiles = {
            "discovery": {
                "nmap": ["-sn"],
                "masscan": ["-p0", "--rate=10000"],
                "description": "Host discovery only",
            },
            "inventory": {
                "nmap": ["-sS", "-sV", "-O", "--top-ports", "1000"],
                "description": "Service and OS detection",
            },
            "deep": {
                "nmap": ["-sS", "-sV", "-O", "-p-", "--script", "default"],
                "description": "Full port scan with scripts",
            },
        }

    def scan(self, target, scan_type="discovery", use_masscan=False, needs_root=False):
        """Execute network scan"""
        if use_masscan and scan_type == "discovery":
            return self._run_masscan(target)
        else:
            return self._run_nmap(target, scan_type, needs_root)

    def _run_nmap(self, target, scan_type, needs_root):
        """Run nmap scan"""
        profile = self.scan_profiles[scan_type]

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            cmd = ["nmap", "-oX", tmp.name] + profile["nmap"] + [target]

            if needs_root:
                cmd = ["sudo"] + cmd

            # Execute scan
            proc = subprocess.run(cmd, capture_output=True, text=True)

            if proc.returncode != 0:
                raise Exception(f"Nmap failed: {proc.stderr}")

            # Parse XML output
            return self._parse_nmap_xml(tmp.name)

    def _run_masscan(self, target):
        """Run masscan for fast discovery"""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            cmd = [
                "sudo",
                "masscan",
                "-p0",  # Ping scan
                "--rate=10000",  # 10k packets/sec
                "-oJ",
                tmp.name,  # JSON output
                target,
            ]

            proc = subprocess.run(cmd, capture_output=True, text=True)

            if proc.returncode != 0:
                raise Exception(f"Masscan failed: {proc.stderr}")

            # Parse JSON output
            with open(tmp.name) as f:
                data = f.read()
                if data.strip():
                    return json.loads(data)
                return []

    def _parse_nmap_xml(self, xml_file):
        """Parse nmap XML output"""
        tree = ET.parse(xml_file)
        root = tree.getroot()

        devices = []
        for host in root.findall(".//host"):
            if host.find('.//status[@state="up"]') is None:
                continue

            device = {
                "ip": host.find('.//address[@addrtype="ipv4"]').get("addr"),
                "mac": "",
                "hostname": "",
                "open_ports": [],
                "services": [],
                "os": "",
            }

            # MAC address
            mac_elem = host.find('.//address[@addrtype="mac"]')
            if mac_elem is not None:
                device["mac"] = mac_elem.get("addr")
                device["vendor"] = mac_elem.get("vendor", "")

            # Hostname
            hostname_elem = host.find(".//hostname")
            if hostname_elem is not None:
                device["hostname"] = hostname_elem.get("name")

            # Ports and services
            for port in host.findall(".//port"):
                if port.find('.//state[@state="open"]') is not None:
                    port_id = int(port.get("portid"))
                    device["open_ports"].append(port_id)

                    service = port.find(".//service")
                    if service is not None:
                        service_name = service.get("name", "unknown")
                        device["services"].append(f"{service_name}:{port_id}")

            # OS detection
            osmatch = host.find(".//osmatch")
            if osmatch is not None:
                device["os"] = osmatch.get("name", "")

            devices.append(device)

        return devices
