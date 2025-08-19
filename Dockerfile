FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV GO_VERSION=1.21.5

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    git \
    curl \
    wget \
    unzip \
    build-essential \
    ca-certificates \
    ruby-full \
    nodejs \
    npm \
    sqlmap \
    libpcap-dev \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget -q https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz

# Set Go environment
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Create app directory
WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Install Go-based security tools (install individually to catch any failures)
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest  
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
RUN go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
RUN go install -v github.com/ffuf/ffuf/v2@latest
RUN go install -v github.com/OJ/gobuster/v3@latest

# Install nuclei separately (sometimes has dependency issues)
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || \
    (echo "Nuclei installation failed, trying alternative..." && \
     curl -L https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_*_linux_amd64.zip -o nuclei.zip && \
     unzip nuclei.zip && mv nuclei /go/bin/ && rm nuclei.zip)

# Install naabu (needs libpcap)
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || echo "Naabu installation failed - continuing without it"

# Install dalfox
RUN go install -v github.com/hahwul/dalfox/v2@latest || echo "Dalfox installation failed - continuing without it"

# Install kiterunner  
RUN go install -v github.com/assetnote/kiterunner@latest || echo "Kiterunner installation failed - continuing without it"

# Install TruffleHog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Install Commix
RUN git clone https://github.com/commixproject/commix.git /opt/commix && \
    chmod +x /opt/commix/commix.py && \
    ln -sf /opt/commix/commix.py /usr/local/bin/commix

# Install BeEF Framework (optional - may fail in some environments)
RUN gem install bundler || true
RUN git clone https://github.com/beefproject/beef /opt/beef || echo "BeEF clone failed"
RUN cd /opt/beef && bundle install --without test development || echo "BeEF installation failed - continuing without it"

# Update Nuclei templates (if nuclei is available)
RUN which nuclei && nuclei -update-templates -silent || echo "Nuclei templates update skipped"

# Verify tool installations and create summary
RUN echo "=== Security Tools Installation Summary ===" && \
    echo "Core tools:" && \
    (which subfinder && echo "✅ subfinder" || echo "❌ subfinder") && \
    (which httpx && echo "✅ httpx" || echo "❌ httpx") && \
    (which katana && echo "✅ katana" || echo "❌ katana") && \
    (which ffuf && echo "✅ ffuf" || echo "❌ ffuf") && \
    (which nuclei && echo "✅ nuclei" || echo "❌ nuclei") && \
    (which naabu && echo "✅ naabu" || echo "❌ naabu") && \
    (which sqlmap && echo "✅ sqlmap" || echo "❌ sqlmap") && \
    (which commix && echo "✅ commix" || echo "❌ commix") && \
    (which trufflehog && echo "✅ trufflehog" || echo "❌ trufflehog") && \
    echo "=== End Summary ==="

# Copy application files
COPY . .

# Create necessary directories
RUN mkdir -p /tmp/scan_results /tmp/wordlists /app/logs

# Create startup script for container
RUN echo '#!/bin/bash\n\
echo "🚀 Starting ExternalAttacker-MCP on Fly.io..."\n\
echo "Starting integrated Flask + MCP app on port $PORT..."\n\
echo "MCP endpoints: /mcp/tools and /mcp/call"\n\
echo "Web interface: /"\n\
python3 ExternalAttacker-App.py\n\
' > /app/start-container.sh && chmod +x /app/start-container.sh

# Expose port
EXPOSE 6991

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:6991/ || exit 1

# Start the application
CMD ["/app/start-container.sh"] 