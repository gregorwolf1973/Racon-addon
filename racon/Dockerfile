ARG BUILD_FROM
FROM $BUILD_FROM

# Install dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip \
    nmap \
    nmap-scripts \
    wireless-tools \
    iw \
    aircrack-ng \
    curl \
    bash

RUN pip3 install flask --break-system-packages

# Try to install RustScan (best effort, falls back to nmap-only if unavailable)
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then RSARCH="amd64"; \
    elif [ "$ARCH" = "aarch64" ]; then RSARCH="arm64"; \
    else RSARCH=""; fi && \
    if [ -n "$RSARCH" ]; then \
        curl -sLO "https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_linux_${RSARCH}.tar.gz" && \
        tar xzf rustscan_*.tar.gz && \
        mv rustscan /usr/local/bin/ && \
        rm -f rustscan_*.tar.gz; \
    fi || echo "RustScan not available for this arch"

# Copy rootfs into container
COPY rootfs /
