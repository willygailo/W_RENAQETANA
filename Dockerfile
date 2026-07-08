# Dockerfile for Dockerized Kali + BountyKit
FROM kalilinux/kali-rolling:latest

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV GOBIN=/usr/local/bin

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

# Install Go security tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/tomnomnom/anew@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/tomnomnom/qsreplace@latest && \
    go install -v github.com/hakluke/hakrawler@latest && \
    go install -v github.com/sensepost/gowitness@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest && \
    go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest && \
    go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest

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
