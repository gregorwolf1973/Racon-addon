#!/usr/bin/with-contenv bashio

bashio::log.info "Starting Recon addon..."

# Get ingress path from HA supervisor
INGRESS_PATH=$(bashio::addon.ingress_entry)
export INGRESS_PATH

INGRESS_PORT=$(bashio::addon.ingress_port)
export INGRESS_PORT

bashio::log.info "Ingress path: ${INGRESS_PATH}"
bashio::log.info "Ingress port: ${INGRESS_PORT}"

# Start Flask app
exec python3 /app/app.py
