# TowerIQ Backend Services Container
FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    supervisor \
    curl \
    wget \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Create directories for logs and data
RUN mkdir -p /var/log/supervisor /app/logs /app/data

# Copy supervisord configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Create a simple health check script
RUN echo '#!/bin/bash\nsupervisorctl status | grep -q RUNNING' > /app/healthcheck.sh \
    && chmod +x /app/healthcheck.sh

# Expose ports (for future services)
EXPOSE 8080 8081

# Set proper permissions
RUN chown -R nobody:nogroup /app /var/log/supervisor

# Use supervisor to manage processes
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /app/healthcheck.sh 