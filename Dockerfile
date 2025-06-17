# Dockerfile for NetworkMapper v2
# This file defines how to build a Docker container for the NetworkMapper tool

# Start with Ubuntu 22.04 as our base image (stable and widely used)
FROM ubuntu:22.04

# Set environment variables to prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install system dependencies
# This runs apt-get update and installs all the tools we need
RUN apt-get update && apt-get install -y \
    # Python and pip for running our tool
    python3 \
    python3-pip \
    python3-venv \
    # Network scanning tools
    nmap \
    arp-scan \
    # Tools for building some Python packages
    build-essential \
    python3-dev \
    # Network utilities
    net-tools \
    iputils-ping \
    # Git for cloning repos (if needed)
    git \
    # Clean up apt cache to reduce image size
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install masscan from source (not in Ubuntu repos)
# This gives us the high-speed scanner
RUN git clone https://github.com/robertdavidgraham/masscan /tmp/masscan \
    && cd /tmp/masscan \
    && make \
    && make install \
    && rm -rf /tmp/masscan

# Set the working directory inside the container
WORKDIR /app

# Copy requirements first (Docker caches this layer if requirements don't change)
COPY requirements.txt .

# Create a virtual environment and install Python packages
# Using a venv keeps things clean and isolated
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy the entire project into the container
COPY . .

# Create output directories with proper permissions
RUN mkdir -p output/{scans,reports,changes,annotations,cache,config,exports} \
    && chmod -R 777 output

# Set the default command to run when container starts
# This shows the help menu
CMD ["python3", "mapper.py", "--help"]

# To use this container for scanning, you'll need to run with:
# --network host  (to access the host network)
# --privileged    (for raw packet access)
# -v $(pwd)/output:/app/output  (to save results on your host machine)