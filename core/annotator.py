import json
from pathlib import Path
from typing import Dict, List, Optional
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

class DeviceAnnotator:
    def __init__(self, output_path: Path = Path("output")):
        self.output_path = output_path
        self.annotations_file = output_path / "device_annotations.json"
        self.console = Console()
        self.load_annotations()
    
    def load_annotations(self):
        """Load existing annotations"""
        if self.annotations_file.exists():
            with open(self.annotations_file) as f:
                self.annotations = json.load(f)
        else:
            self.annotations = {}
    
    def save_annotations(self):
        """Save annotations to file"""
        with open(self.annotations_file, 'w') as f:
            json.dump(self.annotations, f, indent=2)
    
    def annotate_device(self, device: Dict):
        """Interactive device annotation"""
        ip = device['ip']
        
        self.console.print(f"\n[bold]Annotating Device: {ip}[/bold]")
        self.console.print(f"Hostname: {device.get('hostname', 'N/A')}")
        self.console.print(f"Type: {device.get('type', 'unknown')}")
        self.console.print(f"Vendor: {device.get('vendor', 'N/A')}")
        
        # Get or create annotation
        annotation = self.annotations.get(ip, {
            'critical': False,
            'notes': '',
            'tags': [],
            'location': '',
            'owner': ''
        })
        
        # Critical flag
        annotation['critical'] = Confirm.ask(
            "Mark as critical infrastructure?",
            default=annotation['critical']
        )
        
        # Notes
        current_notes = annotation.get('notes', '')
        if current_notes:
            self.console.print(f"Current notes: {current_notes}")
            if Confirm.ask("Update notes?"):
                annotation['notes'] = Prompt.ask("Enter notes")
        else:
            annotation['notes'] = Prompt.ask("Enter notes (optional)", default="")
        
        # Tags
        current_tags = annotation.get('tags', [])
        if current_tags:
            self.console.print(f"Current tags: {', '.join(current_tags)}")
        
        new_tags = Prompt.ask(
            "Enter tags (comma-separated, optional)",
            default=''
        )
        if new_tags:
            annotation['tags'] = [t.strip() for t in new_tags.split(',')]
        
        # Location
        annotation['location'] = Prompt.ask(
            "Physical location",
            default=annotation.get('location', '')
        )
        
        # Owner
        annotation['owner'] = Prompt.ask(
            "Owner/Department",
            default=annotation.get('owner', '')
        )
        
        # Save
        self.annotations[ip] = annotation
        self.save_annotations()
        
        self.console.print("[green]✓ Annotation saved![/green]")
    
    def bulk_annotate(self, devices: List[Dict]):
        """Annotate multiple devices"""
        table = Table(title="Select Devices to Annotate")
        table.add_column("#", style="cyan")
        table.add_column("IP", style="yellow")
        table.add_column("Hostname")
        table.add_column("Type")
        table.add_column("Annotated", style="green")
        
        for i, device in enumerate(devices):
            annotated = "✓" if device['ip'] in self.annotations else ""
            table.add_row(
                str(i + 1),
                device['ip'],
                device.get('hostname', ''),
                device.get('type', 'unknown'),
                annotated
            )
        
        self.console.print(table)
        
        selections = Prompt.ask(
            "Enter device numbers to annotate (comma-separated)"
        )
        
        for num in selections.split(','):
            try:
                idx = int(num.strip()) - 1
                if 0 <= idx < len(devices):
                    self.annotate_device(devices[idx])
            except ValueError:
                continue
    
    def apply_annotations(self, devices: List[Dict]) -> List[Dict]:
        """Apply saved annotations to device list"""
        for device in devices:
            ip = device['ip']
            if ip in self.annotations:
                annotation = self.annotations[ip]
                device.update({
                    'critical': annotation.get('critical', False),
                    'notes': annotation.get('notes', ''),
                    'tags': annotation.get('tags', []),
                    'location': annotation.get('location', ''),
                    'owner': annotation.get('owner', '')
                })
        return devices
