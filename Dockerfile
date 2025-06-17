# NetworkMapper v2 Dockerfile
# Multi-stage build for optimal image size and security

# Stage 1: Base system with all dependencies
FROM python:3.11-slim-bookworm AS base

# Install system dependencies and network tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network scanning tools
    nmap \
    masscan \
    arp-scan \
    # Network utilities
    iputils-ping \
    net-tools \
    dnsutils \
    tcpdump \
    tshark \
    # Build dependencies
    gcc \
    g++ \
    make \
    libpcap-dev \
    libssl-dev \
    libffi-dev \
    # Other utilities
    sudo \
    wget \
    curl \
    git \
    vim-tiny \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for running the application
RUN useradd -m -s /bin/bash netmapper && \
    echo "netmapper ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Stage 2: Python dependencies
FROM base AS python-deps

# Copy requirements file
COPY requirements.txt /tmp/

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r /tmp/requirements.txt

# Stage 3: Final application image
FROM base AS final

# Copy Python dependencies from previous stage
COPY --from=python-deps /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=python-deps /usr/local/bin /usr/local/bin

# Set working directory
WORKDIR /app

# Copy application code
COPY . /app/

# Create necessary directories with proper permissions
RUN mkdir -p /app/output /app/logs /app/cache && \
    chown -R netmapper:netmapper /app && \
    chmod -R 755 /app && \
    # Special permissions for network tools
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap && \
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/masscan && \
    setcap cap_net_raw,cap_net_admin+eip /usr/sbin/arp-scan && \
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump && \
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NETWORKMAPPER_DOCKER=1 \
    PATH="/app:${PATH}"

# Copy and set up entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Copy and set up healthcheck script
COPY docker-healthcheck.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-healthcheck.sh

# Switch to non-root user
USER netmapper

# Volume for output data
VOLUME ["/app/output"]

# Expose Flask port for web reports
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /usr/local/bin/docker-healthcheck.sh

# Default entrypoint
ENTRYPOINT ["docker-entrypoint.sh"]

# Default command - show help
CMD ["python3", "mapper.py", "--help"]