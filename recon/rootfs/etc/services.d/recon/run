#!/usr/bin/with-contenv bashio

bashio::log.info "Starting Recon..."

# Read port from addon config (with fallback to 8765)
PORT=$(bashio::config 'port' 2>/dev/null || echo "8765")
export INGRESS_PORT=${PORT}

# Ingress path from supervisor
INGRESS_PATH=$(bashio::addon.ingress_entry 2>/dev/null || echo "")
export INGRESS_PATH

bashio::log.info "Port: ${PORT}"
bashio::log.info "Ingress path: ${INGRESS_PATH}"

exec python3 /app/app.py
