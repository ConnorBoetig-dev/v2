import json
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Dict, List


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

    def scan(
        self,
        target: str,
        scan_type: str = "discovery",
        use_masscan: bool = False,
        needs_root: bool = False,
    ) -> List[Dict]:
        """Execute network scan"""
        if use_masscan and scan_type == "discovery":
            return self._run_masscan(target)
        else:
            return self._run_nmap(target, scan_type, needs_root)

    def _run_nmap(self, target: str, scan_type: str, needs_root: bool) -> List[Dict]:
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

    def _run_masscan(self, target: str) -> List[Dict]:
        """Run masscan for fast discovery"""
        # Create temp file in a writable location
        temp_dir = tempfile.gettempdir()
        temp_file = os.path.join(temp_dir, f"masscan_{os.getpid()}.json")

        try:
            cmd = [
                "sudo",
                "masscan",
                "-p0",  # Ping scan
                "--rate=10000",  # 10k packets/sec
                "-oJ",
                temp_file,  # JSON output
                target,
            ]

            proc = subprocess.run(cmd, capture_output=True, text=True)

            if proc.returncode != 0:
                raise Exception(f"Masscan failed: {proc.stderr}")

            # Parse JSON output
            if os.path.exists(temp_file):
                with open(temp_file) as f:
                    data = f.read()
                    if data.strip():
                        results = []
                        # Masscan JSON is line-delimited
                        for line in data.strip().split("\n"):
                            if line.strip() and line != "{" and line != "}":
                                try:
                                    entry = json.loads(line.rstrip(","))
                                    results.append(entry)
                                except json.JSONDecodeError:
                                    continue
                        return results
            return []
        finally:
            # Clean up temp file
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except:
                    pass

    def _parse_nmap_xml(self, xml_file: str) -> List[Dict]:
        """Parse nmap XML output"""
        tree = ET.parse(xml_file)
        root = tree.getroot()

        devices = []
        for host in root.findall(".//host"):
            if host.find('.//status[@state="up"]') is None:
                continue

            device = {
                "ip": "",
                "mac": "",
                "hostname": "",
                "open_ports": [],
                "services": [],
                "os": "",
                "vendor": "",
            }

            # IP address
            ipv4 = host.find('.//address[@addrtype="ipv4"]')
            if ipv4 is not None:
                device["ip"] = ipv4.get("addr")

            # MAC address
            mac_elem = host.find('.//address[@addrtype="mac"]')
            if mac_elem is not None:
                device["mac"] = mac_elem.get("addr", "")
                device["vendor"] = mac_elem.get("vendor", "")

            # Hostname
            hostname_elem = host.find(".//hostname")
            if hostname_elem is not None:
                device["hostname"] = hostname_elem.get("name", "")

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

            if device["ip"]:  # Only add if we have an IP
                devices.append(device)

        return devices
