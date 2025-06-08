#!/usr/bin/env python3
"""
NetworkMapper v2 - Automated Setup Script
"""

import platform
import subprocess
import sys
from pathlib import Path


class SetupManager:
    def __init__(self):
        self.base_path = Path(__file__).parent
        self.venv_path = self.base_path / "venv"
        self.os_type = platform.system().lower()

    def run(self):
        """Run complete setup process"""
        print("NetworkMapper v2 - Setup")
        print("=" * 50)

        # Check Python version
        if not self.check_python_version():
            return False

        # Check/install system dependencies
        if not self.check_system_deps():
            return False

        # Create virtual environment
        if not self.create_venv():
            return False

        # Install Python packages
        if not self.install_packages():
            return False

        # Create output directories
        self.create_directories()

        # Create config file
        self.create_config()

        print("\n✓ Setup complete!")
        print("\nTo start using NetworkMapper:")
        print("  1. Activate virtual environment: source venv/bin/activate")
        print("  2. Run the tool: python3 mapper.py")

        return True

    def check_python_version(self):
        """Check Python version >= 3.8"""
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 8):
            print(f"❌ Python 3.8+ required (found {version.major}.{version.minor})")
            return False
        print(f"✓ Python {version.major}.{version.minor} detected")
        return True

    def check_system_deps(self):
        """Check and install system dependencies"""
        print("\nChecking system dependencies...")

        # ALL dependencies are now required for full functionality
        deps = {
            "nmap": "Network scanner",
            "masscan": "Fast host discovery",
            "arp-scan": "Layer 2 discovery",
        }

        missing = []

        for cmd, desc in deps.items():
            if self.command_exists(cmd):
                print(f"  ✓ {cmd}: {desc}")
            else:
                missing.append(cmd)
                print(f"  ❌ {cmd}: {desc}")

        if missing:
            print(f"\n❌ Missing required dependencies: {', '.join(missing)}")
            print("\nThese tools are required for full NetworkMapper functionality.")

            if self.os_type == "linux":
                print("\nTo install on Ubuntu/Debian:")
                print(f"  sudo apt update && sudo apt install -y {' '.join(missing)}")
            elif self.os_type == "darwin":
                print("\nTo install on macOS (using Homebrew):")
                print(f"  brew install {' '.join(missing)}")

            print("\nPlease install all missing dependencies and run setup again.")
            return False

        print("\n✓ All system dependencies installed!")
        return True

    def command_exists(self, cmd):
        """Check if command exists in PATH"""
        return subprocess.run(["which", cmd], capture_output=True).returncode == 0

    def create_venv(self):
        """Create virtual environment"""
        print("\nCreating virtual environment...")

        if self.venv_path.exists():
            print("  ✓ Virtual environment already exists")
            return True

        try:
            subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
            print("  ✓ Virtual environment created")
            return True
        except subprocess.CalledProcessError as e:
            print(f"  ❌ Failed to create venv: {e}")
            return False

    def install_packages(self):
        """Install Python packages"""
        print("\nInstalling Python packages...")

        pip_cmd = str(self.venv_path / "bin" / "pip")
        if self.os_type == "windows":
            pip_cmd = str(self.venv_path / "Scripts" / "pip.exe")

        try:
            # Upgrade pip first
            subprocess.run(
                [pip_cmd, "install", "--upgrade", "pip"], check=True, capture_output=True
            )

            # Install requirements
            subprocess.run([pip_cmd, "install", "-r", "requirements.txt"], check=True)
            print("  ✓ Python packages installed")
            return True
        except subprocess.CalledProcessError as e:
            print(f"  ❌ Failed to install packages: {e}")
            return False

    def create_directories(self):
        """Create output directory structure"""
        print("\nCreating directory structure...")

        dirs = [
            "output/scans",
            "output/reports",
            "output/changes",
            "templates",
            "static/css",
            "static/js",
        ]

        for dir_path in dirs:
            full_path = self.base_path / dir_path
            full_path.mkdir(parents=True, exist_ok=True)
            print(f"  ✓ Created {dir_path}")

    def create_config(self):
        """Create default configuration file"""
        print("\nCreating default configuration...")

        config_content = """# NetworkMapper v2 Configuration

# Scan settings
scan:
  example_target: "192.168.1.0/24"  # Just an example format
  default_type: "discovery"
  timeout: 300  # seconds

# Scanner preferences
scanners:
  prefer_masscan: false  # Use masscan for discovery when available
  nmap_timing: "-T4"     # Nmap timing template (T0-T5)

# Report settings
report:
  auto_open: true
  include_3d_view: true

# Device classification thresholds
classification:
  confidence_threshold: 70

# Change detection
changes:
  track_services: true
  track_ports: true
  track_os: true
"""

        config_path = self.base_path / "config.yaml"
        if not config_path.exists():
            with open(config_path, "w") as f:
                f.write(config_content)
            print("  ✓ Created config.yaml")
        else:
            print("  ✓ config.yaml already exists")


if __name__ == "__main__":
    setup = SetupManager()
    if not setup.run():
        sys.exit(1)
