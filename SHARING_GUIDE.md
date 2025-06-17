# NetworkMapper v2 - Quick Start Guide for Colleagues

## What is This?
NetworkMapper is an internal tool for discovering and analyzing devices on our network. It's like a friendly, more powerful version of nmap with nice reports.

## Two Ways to Use This Tool

### Option 1: Docker (Easiest - No Setup Required!)

If you have Docker installed, you only need 2 commands:

```bash
# 1. Build the tool (only needed once)
make docker-build

# 2. Run the tool
make docker-run
```

That's it! The tool will start in interactive mode.

### Option 2: Local Installation

If you prefer to install locally:

```bash
# 1. Set everything up
make setup

# 2. Run the tool
./venv/bin/python mapper.py
```

## Common Commands

```bash
# See all available commands
make help

# Run the tool in Docker
make docker-run

# Open a shell in Docker (for advanced users)
make docker-shell

# Clean up old scan data
make clean

# Run tests
make test
```

## What These Files Do

### Dockerfile
- **What it is**: A recipe for building a container with NetworkMapper
- **Why use it**: Ensures everyone has the exact same environment
- **What it does**:
  1. Starts with Ubuntu Linux
  2. Installs all required tools (Python, nmap, etc.)
  3. Copies our code
  4. Sets everything up automatically

### Makefile
- **What it is**: A collection of shortcuts for common tasks
- **Why use it**: Instead of typing long commands, just type `make [task]`
- **Examples**:
  - `make setup` = Install everything
  - `make docker-build` = Build Docker image
  - `make test` = Run tests

## Scanning Your First Network

1. Start the tool:
   ```bash
   make docker-run
   ```

2. Choose option 1 (Network Scanner)

3. Select "Deep Scan" for quick results

4. Enter your network (e.g., `192.168.1.0/24`)

5. Wait for results - reports will open automatically!

## Where Are My Results?

All scan results are saved in the `output/` directory:
- `output/reports/` - HTML reports with network maps
- `output/scans/` - Raw scan data (JSON)
- `output/exports/` - PDF and Excel exports

## Need Sudo/Admin Access?

Some network scans require elevated privileges. When using Docker, it handles this automatically. For local installation, you may need to run with `sudo`.

## Troubleshooting

### "Docker not found"
Install Docker from https://docs.docker.com/get-docker/

### "Permission denied"
The tool needs admin access for network scanning:
```bash
# For local installation
sudo ./venv/bin/python mapper.py
```

### "No devices found"
- Check your network range is correct
- Ensure you're on the network you're trying to scan
- Try the "Deeper Scan" option for better discovery

## Getting Help

- Run `python3 mapper.py --help` for command options
- Check `CLAUDE.md` for detailed documentation
- Look at scan reports for network insights

## Sharing This Tool

To share with a colleague:
1. Send them this entire folder (or Git repository)
2. Tell them to run: `make docker-build` then `make docker-run`
3. That's it!

The Docker approach means they don't need to worry about Python versions, dependencies, or system setup - it just works!