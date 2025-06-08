import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class ChangeTracker:
    def __init__(self, output_path: Path = Path("output")):
        self.output_path = output_path
        self.scans_path = output_path / "scans"

    def detect_changes(self, current_devices: List[Dict]) -> Dict:
        """Compare current scan with previous scan"""
        # Get most recent previous scan
        previous_devices = self._get_previous_scan()
        if not previous_devices:
            return {}

        # Create lookup maps
        current_map = {d["ip"]: d for d in current_devices}
        previous_map = {d["ip"]: d for d in previous_devices}

        changes = {
            "new_devices": [],
            "missing_devices": [],
            "changed_devices": [],
            "summary": {
                "total_current": len(current_devices),
                "total_previous": len(previous_devices),
                "timestamp": datetime.now().isoformat(),
            },
        }

        # Find new devices
        for ip in current_map:
            if ip not in previous_map:
                device = current_map[ip].copy()
                device["change_type"] = "new"
                changes["new_devices"].append(device)

        # Find missing devices
        for ip in previous_map:
            if ip not in current_map:
                device = previous_map[ip].copy()
                device["change_type"] = "missing"
                changes["missing_devices"].append(device)

        # Find changed devices
        for ip in current_map:
            if ip in previous_map:
                current = current_map[ip]
                previous = previous_map[ip]

                diff = self._compare_devices(current, previous)
                if diff:
                    change_record = {
                        "ip": ip,
                        "hostname": current.get("hostname", ""),
                        "type": current.get("type", "unknown"),
                        "changes": diff,
                        "change_type": "modified",
                    }
                    changes["changed_devices"].append(change_record)

        return changes

    def _get_previous_scan(self) -> Optional[List[Dict]]:
        """Get the most recent previous scan"""
        scan_files = sorted(self.scans_path.glob("scan_*.json"))
        if len(scan_files) < 2:
            return None

        # Get second most recent (most recent is current)
        with open(scan_files[-2]) as f:
            return json.load(f)

    def _compare_devices(self, current: Dict, previous: Dict) -> List[Dict]:
        """Compare two device records"""
        changes = []

        # Check services
        curr_services = set(current.get("services", []))
        prev_services = set(previous.get("services", []))

        new_services = curr_services - prev_services
        if new_services:
            changes.append({"field": "services", "action": "added", "values": list(new_services)})

        removed_services = prev_services - curr_services
        if removed_services:
            changes.append(
                {"field": "services", "action": "removed", "values": list(removed_services)}
            )

        # Check ports
        curr_ports = set(current.get("open_ports", []))
        prev_ports = set(previous.get("open_ports", []))

        new_ports = curr_ports - prev_ports
        if new_ports:
            changes.append({"field": "ports", "action": "opened", "values": list(new_ports)})

        closed_ports = prev_ports - curr_ports
        if closed_ports:
            changes.append({"field": "ports", "action": "closed", "values": list(closed_ports)})

        # Check other fields
        for field in ["hostname", "os", "type", "vendor"]:
            if current.get(field) != previous.get(field):
                changes.append(
                    {
                        "field": field,
                        "action": "changed",
                        "old_value": previous.get(field, ""),
                        "new_value": current.get(field, ""),
                    }
                )

        return changes

    def _generate_fingerprint(self, device: Dict) -> str:
        """Generate unique fingerprint for device state"""
        # Create stable string representation
        data = {
            "mac": device.get("mac", ""),
            "ports": sorted(device.get("open_ports", [])),
            "services": sorted(device.get("services", [])),
            "os": device.get("os", ""),
        }

        json_str = json.dumps(data, sort_keys=True)
        return hashlib.md5(json_str.encode()).hexdigest()
