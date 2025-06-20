import os
import platform
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class MACLookup:
    def __init__(self, cache_dir: Path = None):
        self.system = platform.system()

        # Setup cache directory
        if cache_dir is None:
            cache_dir = Path(__file__).parent.parent / "cache"
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(exist_ok=True)

        self.oui_file = self.cache_dir / "oui.txt"
        self.vendor_cache = {}

        # Load OUI database from local file only
        self._load_oui_database()

        # Virtual machine patterns
        self.virtual_patterns = [
            "00:50:56",  # VMware
            "00:0C:29",  # VMware
            "00:05:69",  # VMware
            "00:15:5D",  # Hyper-V
            "00:03:FF",  # Microsoft Virtual PC
            "08:00:27",  # VirtualBox
            "52:54:00",  # QEMU/KVM
            "00:16:3E",  # Xen
            "02:42:",  # Docker
        ]

    def _load_oui_database(self):
        """Load IEEE OUI database from local cache file"""
        # Parse the OUI file
        if self.oui_file.exists():
            self._parse_oui_file()
        else:
            print(
                "[WARNING] OUI database not found at cache/oui.txt. MAC vendor lookups will be limited."
            )
            # Fallback to minimal hardcoded database for critical vendors
            self.vendor_cache = {
                "00:00:0c": "Cisco Systems, Inc",
                "00:50:56": "VMware, Inc.",
                "00:0c:29": "VMware, Inc.",
                "00:15:5d": "Microsoft Corporation",
                "00:1c:23": "Dell Inc.",
                "b8:27:eb": "Raspberry Pi Foundation",
                "00:1b:21": "Intel Corporate",
            }

    def _parse_oui_file(self):
        """Parse the OUI database file"""
        self.vendor_cache = {}

        try:
            with open(self.oui_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()

                    # IEEE format: XX-XX-XX   (hex)    Organization Name
                    if re.match(r"^[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}", line):
                        # Split by multiple spaces to handle format
                        parts = re.split(r"\s{2,}|\t", line)
                        if len(parts) >= 2:
                            # Extract just the MAC part (XX-XX-XX)
                            oui = parts[0].strip().replace("-", ":").lower()
                            # Extract vendor name, skipping (hex)
                            vendor = None
                            for part in parts[1:]:
                                part = part.strip()
                                if part and part != "(hex)":
                                    vendor = part
                                    break

                            if vendor:
                                self.vendor_cache[oui] = vendor

                    # Alternative format (XX:XX:XX or XXXXXX)
                    elif re.match(r"^[0-9A-F]{6}", line):
                        # Format: XXXXXX     (base 16)     Organization
                        parts = re.split(r"\s{2,}|\t", line)
                        if len(parts) >= 2:
                            mac_hex = parts[0].strip()
                            if len(mac_hex) == 6:
                                # Convert XXXXXX to XX:XX:XX
                                oui = ":".join(mac_hex[i : i + 2] for i in range(0, 6, 2)).lower()
                                # Find vendor, skipping (base 16)
                                vendor = None
                                for part in parts[1:]:
                                    part = part.strip()
                                    if part and "base 16" not in part:
                                        vendor = part
                                        break
                                if vendor:
                                    self.vendor_cache[oui] = vendor

            print(f"[INFO] Loaded {len(self.vendor_cache)} OUI entries")

        except Exception as e:
            print(f"[ERROR] Failed to parse OUI file: {e}")

    def get_arp_cache(self) -> Dict[str, str]:
        """Get MAC addresses from system ARP cache (cross-platform)"""
        if self.system == "Darwin":
            return self._get_macos_arp_cache()
        elif self.system == "Linux":
            return self._get_linux_arp_cache()
        elif self.system == "Windows":
            return self._get_windows_arp_cache()
        else:
            return {}

    def _get_macos_arp_cache(self) -> Dict[str, str]:
        """Get MAC addresses from macOS ARP cache"""
        try:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
            if result.returncode != 0:
                return {}

            arp_cache = {}
            for line in result.stdout.split("\n"):
                # Parse ARP output format:
                # hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0
                match = re.search(r"\(([0-9.]+)\) at ([0-9a-fA-F:]+)", line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2)
                    arp_cache[ip] = mac.upper()

            return arp_cache
        except Exception:
            return {}

    def _get_linux_arp_cache(self) -> Dict[str, str]:
        """Get MAC addresses from Linux ARP cache"""
        try:
            # First try ip neigh command (modern Linux)
            result = subprocess.run(["ip", "neigh"], capture_output=True, text=True)
            if result.returncode == 0:
                arp_cache = {}
                for line in result.stdout.split("\n"):
                    # Parse lines like: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
                    match = re.search(r"(\d+\.\d+\.\d+\.\d+).*lladdr\s+([0-9a-fA-F:]+)", line)
                    if match:
                        ip = match.group(1)
                        mac = match.group(2)
                        arp_cache[ip] = mac.upper()
                return arp_cache
        except Exception:
            pass

        # Fallback to arp -n command
        try:
            result = subprocess.run(["arp", "-n"], capture_output=True, text=True)
            if result.returncode == 0:
                arp_cache = {}
                for line in result.stdout.split("\n"):
                    # Parse lines like: 192.168.1.1  ether  aa:bb:cc:dd:ee:ff  C  eth0
                    match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+ether\s+([0-9a-fA-F:]+)", line)
                    if match:
                        ip = match.group(1)
                        mac = match.group(2)
                        arp_cache[ip] = mac.upper()
                return arp_cache
        except Exception:
            pass

        return {}

    def _get_windows_arp_cache(self) -> Dict[str, str]:
        """Get MAC addresses from Windows ARP cache"""
        try:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, shell=True)
            if result.returncode != 0:
                return {}

            arp_cache = {}
            for line in result.stdout.split("\n"):
                # Parse lines like: 192.168.1.1  aa-bb-cc-dd-ee-ff  dynamic
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+dynamic", line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace("-", ":")
                    arp_cache[ip] = mac.upper()

            return arp_cache
        except Exception:
            return {}

    def lookup(self, mac: str) -> Optional[str]:
        """Lookup vendor by MAC address using local database only"""
        if not mac:
            return None

        # Normalize MAC format
        mac = self._normalize_mac(mac)
        if not mac:
            return None

        # Check OUI (first 3 octets)
        oui = mac[:8].lower()

        # Direct lookup in cache
        if oui in self.vendor_cache:
            return self.vendor_cache[oui]

        # Check for virtual machine patterns
        if self._is_virtual_mac(mac):
            return "Virtual Machine"

        return None

    def _normalize_mac(self, mac: str) -> Optional[str]:
        """Normalize MAC address format"""
        if not mac:
            return None

        # Remove common separators
        mac = mac.replace(":", "").replace("-", "").replace(".", "").upper()

        # Validate length
        if len(mac) != 12:
            return None

        # Validate hex
        if not re.match(r"^[0-9A-F]{12}$", mac):
            return None

        # Format as XX:XX:XX:XX:XX:XX
        return ":".join(mac[i : i + 2] for i in range(0, 12, 2))

    def _is_virtual_mac(self, mac: str) -> bool:
        """Check if MAC indicates virtual machine"""
        mac_start = mac[:8].upper()
        return any(mac_start.startswith(pattern.upper()) for pattern in self.virtual_patterns)

    def enrich_with_arp_cache(self, devices: List[Dict]) -> List[Dict]:
        """Enrich devices with MAC addresses from ARP cache"""
        arp_cache = self.get_arp_cache()

        if not arp_cache:
            return devices

        for device in devices:
            # If device has no MAC but we have it in ARP cache
            if not device.get("mac") and device.get("ip") in arp_cache:
                device["mac"] = arp_cache[device["ip"]]
                # Try to get vendor for this MAC
                vendor = self.lookup(device["mac"])
                if vendor:
                    device["vendor"] = vendor
            # If device has MAC but no vendor, try to get vendor
            elif device.get("mac") and not device.get("vendor"):
                vendor = self.lookup(device["mac"])
                if vendor:
                    device["vendor"] = vendor

        return devices

    def enrich_device(self, device: Dict) -> Dict:
        """Enrich device data with vendor information"""
        if "mac" in device and device["mac"]:
            vendor = self.lookup(device["mac"])
            if vendor:
                device["vendor"] = vendor

                # Add virtual flag if applicable
                if "Virtual" in vendor or self._is_virtual_mac(device["mac"]):
                    device["is_virtual"] = True

        return device

    def _download_oui_database(self):
        """Download the IEEE OUI database (manual update only)"""
        try:
            import requests

            # IEEE OUI database URL
            url = "http://standards-oui.ieee.org/oui/oui.txt"

            print("[INFO] Downloading IEEE OUI database from standards-oui.ieee.org...")

            # Download with timeout
            response = requests.get(url, timeout=30, stream=True)
            response.raise_for_status()

            # Write to temporary file first
            temp_file = self.oui_file.with_suffix(".tmp")
            with open(temp_file, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

            # Move to final location
            temp_file.replace(self.oui_file)
            print(
                f"[INFO] OUI database updated successfully ({self.oui_file.stat().st_size // 1024} KB)"
            )

        except Exception as e:
            print(f"[WARNING] Failed to download OUI database: {e}")
            # Try alternative source
            self._download_oui_alternative()

    def _download_oui_alternative(self):
        """Try alternative OUI database source"""
        try:
            import requests

            # Alternative: Wireshark's manuf database from automated build server
            url = "https://www.wireshark.org/download/automated/data/manuf"

            print("[INFO] Trying alternative source (Wireshark manuf database)...")

            response = requests.get(url, timeout=30)
            response.raise_for_status()

            # Convert to OUI format and save
            temp_file = self.oui_file.with_suffix(".tmp")
            with open(temp_file, "w") as f:
                for line in response.text.split("\n"):
                    if line and not line.startswith("#"):
                        parts = line.split("\t")
                        if len(parts) >= 2:
                            mac = parts[0].replace(":", "-").upper()
                            vendor = parts[1]
                            f.write(f"{mac}\t{vendor}\n")

            temp_file.replace(self.oui_file)
            print("[INFO] Alternative OUI database downloaded successfully")

        except Exception as e:
            print(f"[WARNING] Failed to download alternative OUI database: {e}")

    def update_database(self):
        """Manually trigger OUI database update"""
        print("[INFO] Manually updating OUI database...")
        self._download_oui_database()
        self._parse_oui_file()
        print(f"[INFO] Database now contains {len(self.vendor_cache)} vendor entries")

    def get_stats(self) -> Dict:
        """Get statistics about the MAC lookup database"""
        return {
            "vendor_count": len(self.vendor_cache),
            "database_file": str(self.oui_file),
            "database_exists": self.oui_file.exists(),
            "database_size": self.oui_file.stat().st_size if self.oui_file.exists() else 0,
            "database_modified": (
                datetime.fromtimestamp(self.oui_file.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            )
            if self.oui_file.exists()
            else "N/A",
        }
