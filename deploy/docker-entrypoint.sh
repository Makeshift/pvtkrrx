#!/bin/sh
# PVTKRRX Docker entrypoint.
#
# Mirrors the key steps of scripts/install-selfhost.sh for a containerised
# environment where:
#   - qBittorrent and Prowlarr run in separate containers (not on localhost)
#   - systemd is not available (service installation is skipped automatically)
#
# What this script does on every container start:
#
#   1. Creates PVTKRRX_RUNTIME_DIR on the persistent data volume.
#   2. Symlinks /app/.env → <runtime_dir>/.env so that generated secrets
#      (ENCRYPTION_SECRET, AUTH_TOKEN_SECRET, admin token) survive container
#      re-creates.  Secrets provided via docker-compose environment: take
#      priority over the .env file (loadLocalEnv only fills in absent keys).
#   3. Runs `node scripts/server-installer.js --auto` — the same auto-config
#      step the shell installer calls.  It:
#        • generates ENCRYPTION_SECRET / AUTH_TOKEN_SECRET if not already set
#        • writes local-config.json with service URLs (read from
#          PVTKRRX_PROWLARR_URL / PVTKRRX_QBIT_URL env vars when local
#          discovery finds nothing — standard in Docker)
#        • preserves all existing secrets and URLs on subsequent starts
#        • tries systemd service install; fails gracefully (expected in Docker)
#   4. Starts the app with `exec node index.js`.

set -e

RUNTIME_DIR="${PVTKRRX_RUNTIME_DIR:-/data/pvtkrrx}"

# Step 1: ensure the data directory exists on the persistent volume.
mkdir -p "$RUNTIME_DIR"

# Step 2: persist the .env (secrets) on the data volume so they survive
# container image updates.  A symlink is used so server-installer.js writes
# directly to the volume path, and loadLocalEnv() reads from it on startup.
ln -sf "${RUNTIME_DIR}/.env" /app/.env

# Step 3: run the auto-configurator.
#   • On first boot: generates secrets, writes .env and local-config.json.
#   • On subsequent boots: reads existing secrets from the volume .env,
#     preserves all saved config, optionally re-syncs Prowlarr download client.
echo "[pvtkrrx-entrypoint] Running auto-configurator..."
node /app/scripts/server-installer.js --auto
echo "[pvtkrrx-entrypoint] Auto-configuration complete."

# Step 4: start the application.
exec node /app/index.js
