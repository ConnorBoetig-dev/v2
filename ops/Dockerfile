#
# Dockerfile for NetworkMapper v2
# Creates a self-contained environment with all dependencies.
#

# --- Stage 1: Base image with system tools ---
# Use a slim, modern Python base image
FROM python:3.11-slim-bookworm AS base

# Prevent apt-get from asking for user input
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies: network tools and Python build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # REQUIRED SCANNING TOOLS
    nmap \
    masscan \
    arp-scan \
    # Required for scapy (passive analysis)
    libpcap-dev \
    # Needed for some Python packages to build
    gcc \
    # Other useful utilities
    sudo \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# --- Stage 2: Final Application Image ---
FROM base

# Set the working directory inside the container
WORKDIR /app

COPY ops/requirements.txt .

# Install Python dependencies from the copied file
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

# Copy the rest of the application code into the container
COPY . .

# Create a non-root user to run the application for better security
RUN useradd -ms /bin/bash netmapper && \
    # Give the user passwordless sudo permissions, necessary for scanning
    echo "netmapper ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/netmapper-sudo

# Ensure host-open script is executable if mounted
RUN chmod +x /usr/local/bin/host-open || true

# Switch to the non-root user
USER netmapper

# Set the default command to run when the container starts
ENTRYPOINT ["python3", "mapper.py"]

