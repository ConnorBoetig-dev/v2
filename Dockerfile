FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    masscan \
    arp-scan \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create output directories
RUN mkdir -p output/scans output/reports output/changes

# Set environment variable for non-interactive mode
ENV PYTHONUNBUFFERED=1

# Run as non-root user (optional, but nmap/masscan need root for some scans)
# RUN useradd -m -s /bin/bash netmapper
# USER netmapper

# Entry point
ENTRYPOINT ["python3", "mapper.py"]