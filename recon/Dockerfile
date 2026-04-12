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
    hydra \
    nikto \
    ffuf \
    curl \
    bash

RUN pip3 install flask requests --break-system-packages

# Copy rootfs into container
COPY rootfs /

# Ensure all s6 service scripts are executable
RUN find /etc/services.d -name "run" -exec chmod a+x {} \;
