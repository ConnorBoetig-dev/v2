"""Device annotation module for managing persistent device metadata.

This module handles user-defined annotations for devices including:
- Critical infrastructure flags
- Notes and tags
- Physical location
- Owner/department information
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field, asdict

from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class DeviceAnnotation:
    """Annotation data for a device."""
    ip: str
    critical: bool = False
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    location: str = ""
    owner: str = ""
    department: str = ""
    last_modified: str = field(default_factory=lambda: datetime.now().isoformat())
    created: str = field(default_factory=lambda: datetime.now().isoformat())
    custom_fields: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'DeviceAnnotation':
        """Create from dictionary."""
        # Filter valid fields
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)
    
    def merge(self, other: 'DeviceAnnotation') -> None:
        """Merge another annotation into this one."""
        if other.critical:
            self.critical = True
        if other.notes and other.notes != self.notes:
            self.notes = other.notes
        if other.tags:
            self.tags = list(set(self.tags + other.tags))
        if other.location:
            self.location = other.location
        if other.owner:
            self.owner = other.owner
        if other.department:
            self.department = other.department
        self.custom_fields.update(other.custom_fields)
        self.last_modified = datetime.now().isoformat()


class DeviceAnnotator:
    """Manages device annotations and metadata."""
    
    def __init__(self, output_path: Path = Path("output")):
        """Initialize annotator.
        
        Args:
            output_path: Base output directory
        """
        self.output_path = output_path
        self.output_path.mkdir(exist_ok=True)
        
        self.annotations_file = output_path / "annotations" / "device_annotations.json"
        self.annotations_file.parent.mkdir(exist_ok=True)
        
        self.console = Console()
        self.annotations: Dict[str, DeviceAnnotation] = {}
        self.load_annotations()
        
        # Track changes for undo functionality
        self._history: List[Dict[str, DeviceAnnotation]] = []

    def load_annotations(self) -> None:
        """Load existing annotations from file."""
        if self.annotations_file.exists():
            try:
                with open(self.annotations_file) as f:
                    data = json.load(f)
                    
                # Convert to DeviceAnnotation objects
                self.annotations = {}
                for ip, annotation_data in data.items():
                    try:
                        # Handle both old and new formats
                        if isinstance(annotation_data, dict):
                            if "ip" not in annotation_data:
                                annotation_data["ip"] = ip
                            self.annotations[ip] = DeviceAnnotation.from_dict(annotation_data)
                        else:
                            logger.warning(f"Invalid annotation format for {ip}")
                    except Exception as e:
                        logger.error(f"Failed to load annotation for {ip}: {e}")
                        
                logger.info(f"Loaded {len(self.annotations)} device annotations")
            except Exception as e:
                logger.error(f"Failed to load annotations file: {e}")
                self.annotations = {}
        else:
            logger.info("No existing annotations found")
            self.annotations = {}

    def save_annotations(self) -> bool:
        """Save annotations to file.
        
        Returns:
            True if successful
        """
        try:
            # Save current state to history
            self._save_to_history()
            
            # Convert to serializable format
            data = {ip: ann.to_dict() for ip, ann in self.annotations.items()}
            
            # Write to temporary file first
            temp_file = self.annotations_file.with_suffix('.tmp')
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2)
                
            # Move to final location
            temp_file.replace(self.annotations_file)
            
            logger.info(f"Saved {len(self.annotations)} annotations")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save annotations: {e}")
            return False

    def annotate_device(self, device: Dict) -> None:
        """Interactive device annotation.
        
        Args:
            device: Device dictionary to annotate
        """
        ip = device.get("ip")
        if not ip:
            self.console.print("[red]Device missing IP address[/red]")
            return
            
        # Display device info
        self._display_device_info(device)
        
        # Get or create annotation
        if ip in self.annotations:
            annotation = self.annotations[ip]
            self.console.print("\n[yellow]Existing annotation found[/yellow]")
            self._display_annotation(annotation)
        else:
            annotation = DeviceAnnotation(ip=ip)
            
        # Interactive annotation
        updated = False
        
        # Critical flag
        critical = Confirm.ask(
            "Mark as critical infrastructure?",
            default=annotation.critical
        )
        if critical != annotation.critical:
            annotation.critical = critical
            updated = True
            
        # Notes
        if annotation.notes:
            self.console.print(f"\nCurrent notes: {annotation.notes}")
            if Confirm.ask("Update notes?"):
                notes = Prompt.ask("Enter notes")
                if notes != annotation.notes:
                    annotation.notes = notes
                    updated = True
        else:
            notes = Prompt.ask("Enter notes (optional)", default="")
            if notes:
                annotation.notes = notes
                updated = True
                
        # Tags
        if annotation.tags:
            self.console.print(f"\nCurrent tags: {', '.join(annotation.tags)}")
            
        new_tags = Prompt.ask("Enter tags (comma-separated, optional)", default="")
        if new_tags:
            tags = [t.strip() for t in new_tags.split(",") if t.strip()]
            if set(tags) != set(annotation.tags):
                annotation.tags = tags
                updated = True
                
        # Location
        location = Prompt.ask(
            "Physical location",
            default=annotation.location
        )
        if location != annotation.location:
            annotation.location = location
            updated = True
            
        # Owner/Department
        owner = Prompt.ask(
            "Owner",
            default=annotation.owner
        )
        if owner != annotation.owner:
            annotation.owner = owner
            updated = True
            
        department = Prompt.ask(
            "Department",
            default=annotation.department
        )
        if department != annotation.department:
            annotation.department = department
            updated = True
            
        # Save if updated
        if updated:
            annotation.last_modified = datetime.now().isoformat()
            self.annotations[ip] = annotation
            
            if self.save_annotations():
                self.console.print("\n[green]✓ Annotation saved![/green]")
            else:
                self.console.print("\n[red]✗ Failed to save annotation[/red]")
        else:
            self.console.print("\n[yellow]No changes made[/yellow]")

    def bulk_annotate(self, devices: List[Dict]) -> None:
        """Annotate multiple devices.
        
        Args:
            devices: List of device dictionaries
        """
        if not devices:
            self.console.print("[yellow]No devices to annotate[/yellow]")
            return
            
        # Display device table
        table = Table(title="Select Devices to Annotate")
        table.add_column("#", style="cyan", width=4)
        table.add_column("IP", style="yellow", width=15)
        table.add_column("Hostname", width=20)
        table.add_column("Type", width=12)
        table.add_column("Vendor", width=15)
        table.add_column("Critical", style="red", width=8)
        table.add_column("Tags", width=20)
        
        for i, device in enumerate(devices):
            ip = device.get("ip", "")
            annotation = self.annotations.get(ip)
            
            critical = "✓" if annotation and annotation.critical else ""
            tags = ", ".join(annotation.tags) if annotation and annotation.tags else ""
            
            table.add_row(
                str(i + 1),
                ip,
                device.get("hostname", "")[:20],
                device.get("type", "unknown"),
                device.get("vendor", "")[:15],
                critical,
                tags[:20]
            )
            
        self.console.print(table)
        
        # Get selections
        self.console.print("\n[bold]Select devices to annotate[/bold]")
        self.console.print("Enter numbers separated by commas (e.g., 1,3,5)")
        self.console.print("Or use ranges (e.g., 1-5)")
        self.console.print("Enter 'all' to annotate all devices")
        
        selection = Prompt.ask("Selection")
        
        # Parse selection
        indices = self._parse_selection(selection, len(devices))
        
        if not indices:
            self.console.print("[yellow]No valid selections[/yellow]")
            return
            
        # Annotate selected devices
        self.console.print(f"\n[bold]Annotating {len(indices)} devices[/bold]")
        
        for idx in indices:
            if 0 <= idx < len(devices):
                self.console.print(f"\n[cyan]Device {idx + 1} of {len(indices)}[/cyan]")
                self.annotate_device(devices[idx])
                
        self.console.print("\n[green]Bulk annotation complete![/green]")

    def apply_annotations(self, devices: List[Dict]) -> List[Dict]:
        """Apply saved annotations to device list.
        
        Args:
            devices: List of device dictionaries
            
        Returns:
            Updated device list with annotations applied
        """
        annotated_count = 0
        
        for device in devices:
            ip = device.get("ip")
            if ip and ip in self.annotations:
                annotation = self.annotations[ip]
                
                # Apply annotation fields
                device["critical"] = annotation.critical
                device["notes"] = annotation.notes
                device["tags"] = annotation.tags.copy()
                device["location"] = annotation.location
                device["owner"] = annotation.owner
                device["department"] = annotation.department
                device["annotation_modified"] = annotation.last_modified
                
                # Apply custom fields
                for key, value in annotation.custom_fields.items():
                    device[f"custom_{key}"] = value
                    
                annotated_count += 1
                
        logger.info(f"Applied annotations to {annotated_count} devices")
        return devices
    
    def _display_device_info(self, device: Dict) -> None:
        """Display device information."""
        self.console.print(f"\n[bold]Device Information[/bold]")
        self.console.print(f"IP: [yellow]{device.get('ip', 'N/A')}[/yellow]")
        self.console.print(f"Hostname: {device.get('hostname', 'N/A')}")
        self.console.print(f"Type: {device.get('type', 'unknown')}")
        self.console.print(f"Vendor: {device.get('vendor', 'N/A')}")
        self.console.print(f"OS: {device.get('os', 'N/A')}")
        
        if device.get('services'):
            self.console.print(f"Services: {', '.join(device['services'][:5])}...")
            
    def _display_annotation(self, annotation: DeviceAnnotation) -> None:
        """Display existing annotation."""
        self.console.print(f"Critical: [red]{'✓' if annotation.critical else '✗'}[/red]")
        if annotation.notes:
            self.console.print(f"Notes: {annotation.notes}")
        if annotation.tags:
            self.console.print(f"Tags: {', '.join(annotation.tags)}")
        if annotation.location:
            self.console.print(f"Location: {annotation.location}")
        if annotation.owner:
            self.console.print(f"Owner: {annotation.owner}")
        if annotation.department:
            self.console.print(f"Department: {annotation.department}")
            
    def _parse_selection(self, selection: str, max_value: int) -> List[int]:
        """Parse user selection string into indices."""
        indices = []
        
        if selection.lower() == 'all':
            return list(range(max_value))
            
        for part in selection.split(','):
            part = part.strip()
            
            if '-' in part:
                # Range
                try:
                    start, end = map(int, part.split('-'))
                    indices.extend(range(start - 1, min(end, max_value)))
                except ValueError:
                    continue
            else:
                # Single number
                try:
                    idx = int(part) - 1
                    if 0 <= idx < max_value:
                        indices.append(idx)
                except ValueError:
                    continue
                    
        return list(set(indices))  # Remove duplicates
    
    def _save_to_history(self) -> None:
        """Save current state to history for undo."""
        # Limit history size
        if len(self._history) >= 10:
            self._history.pop(0)
            
        # Deep copy current state
        current_state = {
            ip: DeviceAnnotation.from_dict(ann.to_dict())
            for ip, ann in self.annotations.items()
        }
        self._history.append(current_state)
    
    def get_annotation_stats(self) -> Dict[str, int]:
        """Get statistics about annotations."""
        stats = {
            "total": len(self.annotations),
            "critical": sum(1 for ann in self.annotations.values() if ann.critical),
            "with_notes": sum(1 for ann in self.annotations.values() if ann.notes),
            "with_tags": sum(1 for ann in self.annotations.values() if ann.tags),
            "with_location": sum(1 for ann in self.annotations.values() if ann.location),
            "with_owner": sum(1 for ann in self.annotations.values() if ann.owner),
        }
        
        # Count unique tags
        all_tags = set()
        for ann in self.annotations.values():
            all_tags.update(ann.tags)
        stats["unique_tags"] = len(all_tags)
        
        return stats
