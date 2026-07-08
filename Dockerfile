# Dockerfile for Dockerized Kali + BountyKit
FROM kalilinux/kali-rolling:latest

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/go/bin:${PATH}"
ENV PYTHONUNBUFFERED=1

# Install dependencies and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    git \
    golang-go \
    nmap \
    sqlmap \
    curl \
    ca-certificates \
    whois \
    && rm -rf /var/lib/apt/lists/*

# Install subfinder v2 and nuclei v3 from ProjectDiscovery via Go
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Set working directory
WORKDIR /app

# Copy project files
COPY . /app

# Install project dependencies (container = safe to break system packages)
RUN pip install --break-system-packages --upgrade pip && \
    pip install --break-system-packages -e .[dev]

# Pre-pull nuclei templates
RUN bountykit setup 2>/dev/null || true

# Create non-root user
RUN groupadd -r bountykit && useradd -r -g bountykit -d /app -s /bin/bash bountykit && \
    chown -R bountykit:bountykit /app
USER bountykit

# Healthcheck — verify bountykit CLI starts
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD ["bountykit", "version"]

# Set the default entrypoint
ENTRYPOINT ["bountykit"]
CMD ["--help"]
