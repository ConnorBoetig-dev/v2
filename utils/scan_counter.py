#!/usr/bin/env python3
"""
Scan counter management for simple file naming
"""

import json
from pathlib import Path
from typing import Optional, Dict
import logging

logger = logging.getLogger(__name__)


class ScanCounter:
    """Manages scan counters for simple incremental file naming"""
    
    def __init__(self, output_path: Path):
        """
        Initialize scan counter.
        
        Args:
            output_path: Base output directory path
        """
        self.output_path = Path(output_path)
        self.counter_file = self.output_path / ".scan_counter.json"
        self._ensure_counter_file()
    
    def _ensure_counter_file(self):
        """Ensure counter file exists with initial state"""
        if not self.counter_file.exists():
            self._reset_counters()
    
    def _reset_counters(self):
        """Reset all counters to initial state"""
        initial_state = {
            "next_scan_number": 1,
            "scan_history": {}
        }
        with open(self.counter_file, 'w') as f:
            json.dump(initial_state, f, indent=2)
    
    def get_next_scan_number(self) -> int:
        """
        Get the next available scan number and increment counter.
        
        Returns:
            int: Next scan number to use
        """
        try:
            with open(self.counter_file, 'r') as f:
                data = json.load(f)
            
            scan_number = data.get("next_scan_number", 1)
            
            # Update counter for next time
            data["next_scan_number"] = scan_number + 1
            
            with open(self.counter_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            return scan_number
        
        except Exception as e:
            logger.error(f"Error reading counter file: {e}")
            # Fallback: return 1 if there's an error
            return 1
    
    def record_scan(self, scan_number: int, scan_type: str, target: str, timestamp: str):
        """
        Record scan metadata for future reference.
        
        Args:
            scan_number: The scan number used
            scan_type: Type of scan (deep, deeper, etc.)
            target: Scan target
            timestamp: Original timestamp for reference
        """
        try:
            with open(self.counter_file, 'r') as f:
                data = json.load(f)
            
            # Store scan metadata
            data["scan_history"][str(scan_number)] = {
                "scan_type": scan_type,
                "target": target,
                "timestamp": timestamp,
                "readable_time": self._format_readable_time(timestamp)
            }
            
            with open(self.counter_file, 'w') as f:
                json.dump(data, f, indent=2)
        
        except Exception as e:
            logger.error(f"Error recording scan: {e}")
    
    def get_scan_info(self, scan_number: int) -> Optional[Dict]:
        """
        Get metadata for a specific scan number.
        
        Args:
            scan_number: Scan number to look up
            
        Returns:
            Dict with scan metadata or None if not found
        """
        try:
            with open(self.counter_file, 'r') as f:
                data = json.load(f)
            
            return data.get("scan_history", {}).get(str(scan_number))
        
        except Exception as e:
            logger.error(f"Error reading scan info: {e}")
            return None
    
    def reset(self):
        """Reset scan counter (used when clearing scan history)"""
        self._reset_counters()
        logger.info("Scan counter reset")
    
    @staticmethod
    def _format_readable_time(timestamp: str) -> str:
        """
        Convert timestamp to readable format.
        
        Args:
            timestamp: Timestamp in format YYYYMMDD_HHMMSS
            
        Returns:
            Readable time string
        """
        from datetime import datetime
        
        try:
            dt = datetime.strptime(timestamp, "%Y%m%d_%H%M%S")
            # Format as "Dec 18, 2024 at 2:34 PM"
            return dt.strftime("%b %d, %Y at %-I:%M %p")
        except:
            return timestamp


class SimpleFileNamer:
    """Generate simple, consistent filenames for all output files"""
    
    @staticmethod
    def scan_file(scan_number: int, scan_type: str) -> str:
        """Generate scan JSON filename"""
        return f"scan_{scan_number}_{scan_type}.json"
    
    @staticmethod
    def summary_file(scan_number: int, scan_type: str) -> str:
        """Generate summary JSON filename"""
        return f"summary_{scan_number}_{scan_type}.json"
    
    @staticmethod
    def csv_file(scan_number: int, scan_type: str) -> str:
        """Generate CSV filename"""
        return f"scan_{scan_number}_{scan_type}.csv"
    
    @staticmethod
    def report_file(scan_number: int, scan_type: str) -> str:
        """Generate HTML report filename"""
        return f"report_{scan_number}_{scan_type}.html"
    
    @staticmethod
    def network_map_file(scan_number: int, scan_type: str) -> str:
        """Generate network map filename"""
        return f"network_map_{scan_number}_{scan_type}.html"
    
    @staticmethod
    def traffic_flow_file(scan_number: int) -> str:
        """Generate traffic flow report filename"""
        return f"traffic_flow_{scan_number}.html"
    
    @staticmethod
    def changes_json_file(scan_number: int) -> str:
        """Generate changes JSON filename"""
        return f"changes_{scan_number}.json"
    
    @staticmethod
    def changes_txt_file(scan_number: int) -> str:
        """Generate changes text filename"""
        return f"changes_{scan_number}.txt"
    
    @staticmethod
    def comparison_file(scan_number: int, previous_number: int) -> str:
        """Generate comparison report filename"""
        return f"comparison_{scan_number}_vs_{previous_number}.html"
    
    @staticmethod
    def sanitize_scan_type(scan_type: str) -> str:
        """
        Sanitize scan type for use in filenames.
        
        Args:
            scan_type: Raw scan type
            
        Returns:
            Sanitized scan type
        """
        # Map scan types to simple names
        type_map = {
            "fast": "deep",
            "deeper": "deeper",
            "discovery": "discovery",
            "arp": "arp"
        }
        
        return type_map.get(scan_type.lower(), "scan")