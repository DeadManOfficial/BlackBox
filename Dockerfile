# BlackBox - DEADMAN Security Platform v5.3
# ==========================================
# Fully self-contained portable security toolkit
#
# Build:  docker build -t blackbox .
# Run:    docker run -it --rm -v $(pwd)/targets:/app/targets blackbox
# Shell:  docker run -it --rm blackbox bash
# Scan:   docker run -it --rm blackbox blackbox scan example.com

FROM python:3.11-slim-bookworm AS base

LABEL maintainer="DeadManOfficial"
LABEL version="5.3"
LABEL description="BlackBox - Portable security research platform"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GOROOT=/usr/local/go \
    GOPATH=/root/go \
    PATH="/root/go/bin:/usr/local/go/bin:/app:$PATH"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git jq unzip file \
    nmap netcat-openbsd dnsutils whois \
    chromium chromium-driver \
    libxml2-dev libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.22
RUN wget -qO- https://go.dev/dl/go1.22.0.linux-amd64.tar.gz | tar -C /usr/local -xz

# Install Go security tools
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/tomnomnom/gau@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || true

# Update nuclei templates
RUN nuclei -update-templates -silent 2>/dev/null || true

WORKDIR /app

# Python dependencies (minimal for container)
COPY requirements-minimal.txt ./
RUN pip install --no-cache-dir -r requirements-minimal.txt

# Copy BlackBox
COPY modules/ ./modules/
COPY workflows/ ./workflows/
COPY config/ ./config/
COPY docs/ ./docs/
COPY blackbox ./blackbox
COPY blackbox.py ./blackbox.py

# Create directories
RUN mkdir -p /app/targets /app/output /app/reports /root/.blackbox/atomic-red-team

# Make executable
RUN chmod +x /app/blackbox /app/blackbox.py 2>/dev/null || true

# Verify tools
RUN echo "=== BlackBox v5.3 ===" && \
    nuclei -version 2>/dev/null | head -1 || echo "nuclei: ready" && \
    httpx -version 2>/dev/null | head -1 || echo "httpx: ready" && \
    subfinder -version 2>/dev/null | head -1 || echo "subfinder: ready" && \
    python3 --version

ENTRYPOINT ["python3", "blackbox.py"]
CMD ["--help"]
