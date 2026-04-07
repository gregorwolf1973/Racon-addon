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

# Install RustScan via cargo (compiles from source - works on all archs including aarch64)
RUN apk add --no-cache rust cargo openssl-dev musl-dev && \
    cargo install rustscan --root /usr/local && \
    apk del rust cargo openssl-dev musl-dev && \
    rm -rf /root/.cargo/registry /root/.cargo/git && \
    rustscan --version && echo "RustScan installed OK"


# Copy rootfs into container
COPY rootfs /

# Ensure all s6 service scripts are executable (also shows what was copied for debugging)
RUN ls -la /etc/services.d/ && \
    find /etc/services.d -name "run" -exec chmod a+x {} \;
