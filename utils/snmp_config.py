"""
SNMP Configuration Manager - Interactive SNMP setup and configuration persistence
"""

import json
import logging
from pathlib import Path
from typing import Dict, Optional, Tuple

from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.panel import Panel
from rich.table import Table

logger = logging.getLogger(__name__)


class SNMPConfig:
    """Manages SNMP configuration with interactive setup and persistence"""
    
    def __init__(self, config_dir: Path):
        """Initialize SNMP configuration manager
        
        Args:
            config_dir: Directory to store configuration files
        """
        self.config_dir = Path(config_dir)
        self.config_file = self.config_dir / "snmp_config.json"
        self.console = Console()
        
        # Ensure config directory exists
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
    def interactive_setup(self, force_prompt: bool = False) -> Tuple[bool, Dict]:
        """Interactive SNMP configuration setup
        
        Args:
            force_prompt: Force prompting even if config exists
            
        Returns:
            Tuple of (enabled, config_dict)
        """
        self.console.print()  # Add spacing
        
        # Check for existing configuration
        existing_config = self.load_config() if not force_prompt else None
        
        if existing_config and not force_prompt:
            return self._handle_existing_config(existing_config)
        
        # Ask if user wants SNMP enrichment with better formatting
        self.console.print("\n[bold]SNMP Enrichment[/bold]")
        self.console.print("Collect detailed device information via SNMP protocol")
        self.console.print("[dim]Provides hostname, uptime, interface counts, and system details[/dim]")
        
        enable_snmp = Confirm.ask("Enable SNMP enrichment", default=False)
        
        if not enable_snmp:
            self.console.print("[dim]→ SNMP enrichment disabled[/dim]")
            return False, {}
            
        # Get SNMP configuration
        config = self._get_snmp_config()
        
        if not config:
            self.console.print("[yellow]SNMP configuration cancelled - proceeding without enrichment[/yellow]")
            return False, {}
            
        # Ask if user wants to save settings
        save_config = Confirm.ask("Save these settings for future scans", default=True)
        
        if save_config:
            self.save_config(config)
            self.console.print("[green]→ Settings saved for future use[/green]")
        else:
            self.console.print("[dim]→ Settings will be used for this scan only[/dim]")
            
        self._display_config_summary(config)
        return True, config
        
    def _handle_existing_config(self, existing_config: Dict) -> Tuple[bool, Dict]:
        """Handle existing SNMP configuration
        
        Args:
            existing_config: Previously saved configuration
            
        Returns:
            Tuple of (enabled, config_dict)
        """
        self._display_existing_config(existing_config)
        
        choices = [
            ("use", "Use saved settings"),
            ("new", "Configure new settings"),
            ("skip", "Skip SNMP enrichment")
        ]
        
        self.console.print("\n[bold]Options:[/bold]")
        for i, (_, description) in enumerate(choices, 1):
            self.console.print(f"{i}. {description}")
            
        while True:
            try:
                choice_num = Prompt.ask("Select option", choices=["1", "2", "3"], default="1")
                choice_idx = int(choice_num) - 1
                action, _ = choices[choice_idx]
                break
            except (ValueError, IndexError):
                self.console.print("[red]Please select a valid option (1-3)[/red]")
        
        if action == "use":
            self.console.print("[green]✓ Using saved SNMP settings[/green]")
            self._display_config_summary(existing_config)
            return True, existing_config
        elif action == "new":
            return self.interactive_setup(force_prompt=True)
        else:  # skip
            self.console.print("[dim]SNMP enrichment disabled[/dim]")
            return False, {}
            
    def _get_snmp_config(self) -> Optional[Dict]:
        """Get SNMP configuration from user input
        
        Returns:
            SNMP configuration dictionary or None if cancelled
        """
        config = {}
        
        # Get SNMP version
        version = self._get_snmp_version()
        if not version:
            return None
            
        config['version'] = version
        
        if version in ['v1', 'v2c']:
            # Get community string
            community = self._get_community_string()
            if community is None:
                return None
            config['community'] = community
            
        elif version == 'v3':
            # Get SNMPv3 credentials
            v3_config = self._get_snmpv3_config()
            if not v3_config:
                return None
            config.update(v3_config)
            
        # Additional settings
        config['timeout'] = 2
        config['retries'] = 1
        
        return config
        
    def _get_snmp_version(self) -> Optional[str]:
        """Get SNMP version from user
        
        Returns:
            SNMP version string or None if cancelled
        """
        self.console.print("\n[bold]SNMP Version[/bold]")
        versions = [
            ("v1", "SNMP v1", "Least secure, widest compatibility"),
            ("v2c", "SNMP v2c", "Recommended for most devices"),
            ("v3", "SNMP v3", "Most secure, requires authentication")
        ]
        
        for i, (version, name, desc) in enumerate(versions, 1):
            self.console.print(f"{i}. [bold]{name}[/bold] – {desc}")
            
        while True:
            try:
                choice = Prompt.ask("Select SNMP version", choices=["1", "2", "3"], default="2")
                choice_idx = int(choice) - 1
                version, name, _ = versions[choice_idx]
                self.console.print(f"[green]→ Using {name}[/green]")
                return version
            except (ValueError, IndexError):
                self.console.print("[red]Please select a valid option (1-3)[/red]")
            
    def _get_community_string(self) -> Optional[str]:
        """Get SNMP community string
        
        Returns:
            Community string or None if cancelled
        """
        self.console.print("\n[bold]SNMP Community String[/bold]")
        while True:
            community = Prompt.ask("Community string", default="public")
            
            if not community or community.isspace():
                self.console.print("[red]Community string cannot be empty[/red]")
                continue
                
            # Basic validation
            if len(community) > 32:
                self.console.print("[red]Community string too long (max 32 characters)[/red]")
                continue
                
            if any(c in community for c in [' ', '\t', '\n', '\r']):
                self.console.print("[red]Community string cannot contain whitespace[/red]")
                continue
                
            return community.strip()
            
    def _get_snmpv3_config(self) -> Optional[Dict]:
        """Get SNMPv3 configuration
        
        Returns:
            SNMPv3 configuration dictionary or None if cancelled
        """
        config = {}
        
        # Username
        while True:
            username = Prompt.ask("\n[bold]SNMPv3 Username[/bold]")
            if username and not username.isspace():
                config['username'] = username.strip()
                break
            self.console.print("[red]Username cannot be empty[/red]")
            
        # Authentication password
        while True:
            auth_password = Prompt.ask(
                "[bold]Authentication Password[/bold]",
                password=True
            )
            if auth_password and len(auth_password) >= 8:
                config['auth_password'] = auth_password
                break
            self.console.print("[red]Authentication password must be at least 8 characters[/red]")
            
        # Privacy (encryption) password
        use_privacy = Confirm.ask(
            "[bold]Enable encryption (privacy)?[/bold]",
            default=True
        )
        
        if use_privacy:
            while True:
                priv_password = Prompt.ask(
                    "[bold]Encryption Password[/bold] (leave blank to use auth password)",
                    password=True,
                    default=""
                )
                if not priv_password:
                    config['priv_password'] = config['auth_password']
                    break
                elif len(priv_password) >= 8:
                    config['priv_password'] = priv_password
                    break
                else:
                    self.console.print("[red]Encryption password must be at least 8 characters[/red]")
        else:
            config['priv_password'] = None
            
        return config
        
    def _display_existing_config(self, config: Dict) -> None:
        """Display existing SNMP configuration
        
        Args:
            config: SNMP configuration dictionary
        """
        table = Table(title="Saved SNMP Configuration", show_header=False, box=None)
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="yellow")
        
        table.add_row("Version", config.get('version', 'Unknown'))
        
        if config.get('version') in ['v1', 'v2c']:
            community = config.get('community', 'public')
            # Mask community string for security
            masked = community[0] + '*' * (len(community) - 2) + community[-1] if len(community) > 2 else '*' * len(community)
            table.add_row("Community", masked)
        elif config.get('version') == 'v3':
            table.add_row("Username", config.get('username', 'Unknown'))
            table.add_row("Authentication", "✓ Enabled")
            if config.get('priv_password'):
                table.add_row("Encryption", "✓ Enabled")
            else:
                table.add_row("Encryption", "✗ Disabled")
                
        table.add_row("Timeout", f"{config.get('timeout', 2)}s")
        table.add_row("Retries", str(config.get('retries', 1)))
        
        self.console.print(table)
        
    def _display_config_summary(self, config: Dict) -> None:
        """Display configuration summary
        
        Args:
            config: SNMP configuration dictionary
        """
        version = config.get('version', 'Unknown')
        
        if version in ['v1', 'v2c']:
            summary = f"SNMP {version} with community '{config.get('community', 'public')}'"
        elif version == 'v3':
            encryption = "with encryption" if config.get('priv_password') else "without encryption"
            summary = f"SNMP v3 user '{config.get('username')}' {encryption}"
        else:
            summary = f"SNMP {version}"
            
        self.console.print(f"\n[green]✓ SNMP enrichment enabled: {summary}[/green]")
        
    def save_config(self, config: Dict) -> None:
        """Save SNMP configuration to file
        
        Args:
            config: SNMP configuration dictionary
        """
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            logger.info(f"SNMP configuration saved to {self.config_file}")
        except Exception as e:
            logger.error(f"Failed to save SNMP configuration: {e}")
            self.console.print(f"[red]Warning: Could not save SNMP configuration: {e}[/red]")
            
    def load_config(self) -> Optional[Dict]:
        """Load SNMP configuration from file
        
        Returns:
            SNMP configuration dictionary or None if not found/invalid
        """
        if not self.config_file.exists():
            return None
            
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            logger.info(f"SNMP configuration loaded from {self.config_file}")
            return config
        except Exception as e:
            logger.warning(f"Failed to load SNMP configuration: {e}")
            return None
            
    def delete_config(self) -> bool:
        """Delete saved SNMP configuration
        
        Returns:
            True if deleted successfully
        """
        try:
            if self.config_file.exists():
                self.config_file.unlink()
                logger.info("SNMP configuration deleted")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete SNMP configuration: {e}")
            return False