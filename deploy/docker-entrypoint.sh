#!/bin/sh
# PVTKRRX Docker entrypoint.
#
# Fully automated service connection — no /configure UI interaction needed:
#
#   1. Creates PVTKRRX_RUNTIME_DIR on the persistent data volume.
#   2. Symlinks /app/.env → <runtime_dir>/.env so generated secrets survive
#      container re-creates.
#   3. Waits for Prowlarr to initialise and reads its API key from the config
#      volume (mounted read-only at /prowlarr-config/config.xml).  Exports the
#      key as PVTKRRX_PROWLARR_API_KEY so server-installer.js writes it into
#      local-config.json.
#   4. Waits for qBittorrent's WebUI to respond.
#   5. Runs `node scripts/server-installer.js --auto` (idempotent: preserves
#      existing config on subsequent starts).
#   6. Starts the app with `exec node index.js`.  The app prints the Stremio
#      install URL and a pre-authenticated configure URL to stdout once the
#      HTTP server is listening.

set -e

RUNTIME_DIR="${PVTKRRX_RUNTIME_DIR:-/data/pvtkrrx}"
PROWLARR_CONFIG="${PROWLARR_CONFIG_PATH:-/prowlarr-config/config.xml}"
QBIT_URL="${PVTKRRX_QBIT_URL:-http://qbittorrent:8080}"
PROWLARR_WAIT_SECS="${PVTKRRX_PROWLARR_WAIT_SECS:-120}"
QBIT_WAIT_SECS="${PVTKRRX_QBIT_WAIT_SECS:-60}"

# ── Step 1: ensure the data directory exists on the persistent volume ─────────
mkdir -p "$RUNTIME_DIR"

# ── Step 2: symlink .env onto the volume so secrets persist across rebuilds ───
ln -sf "${RUNTIME_DIR}/.env" /app/.env

# ── Step 3: wait for Prowlarr and read its API key ────────────────────────────
if [ -z "${PVTKRRX_PROWLARR_API_KEY:-}" ] && [ -n "$PROWLARR_CONFIG" ]; then
  echo "[pvtkrrx-entrypoint] Waiting for Prowlarr config at $PROWLARR_CONFIG ..."
  waited=0
  while [ ! -f "$PROWLARR_CONFIG" ] && [ "$waited" -lt "$PROWLARR_WAIT_SECS" ]; do
    sleep 2
    waited=$((waited + 2))
  done

  if [ -f "$PROWLARR_CONFIG" ]; then
    # grep -oP is not available in busybox; use sed for portability.
    PVTKRRX_PROWLARR_API_KEY="$(sed -n 's|.*<ApiKey>\([^<]*\)</ApiKey>.*|\1|p' "$PROWLARR_CONFIG" | head -1 | tr -d '[:space:]')"
    export PVTKRRX_PROWLARR_API_KEY
    if [ -n "$PVTKRRX_PROWLARR_API_KEY" ]; then
      echo "[pvtkrrx-entrypoint] Prowlarr API key read from config (${PVTKRRX_PROWLARR_API_KEY%%????????????????*}...)."
    else
      echo "[pvtkrrx-entrypoint] Warning: Prowlarr config found but API key was empty."
    fi
  else
    echo "[pvtkrrx-entrypoint] Warning: Prowlarr config not found after ${PROWLARR_WAIT_SECS}s — API key not set."
    echo "[pvtkrrx-entrypoint] Set it later via the /configure UI or PVTKRRX_PROWLARR_API_KEY env var."
  fi
fi

# ── Step 4: wait for qBittorrent WebUI ───────────────────────────────────────
echo "[pvtkrrx-entrypoint] Waiting for qBittorrent at $QBIT_URL ..."
waited=0
while [ "$waited" -lt "$QBIT_WAIT_SECS" ]; do
  if wget -q --spider --timeout=3 "${QBIT_URL}/" 2>/dev/null; then
    echo "[pvtkrrx-entrypoint] qBittorrent is up."
    break
  fi
  sleep 3
  waited=$((waited + 3))
done
if [ "$waited" -ge "$QBIT_WAIT_SECS" ]; then
  echo "[pvtkrrx-entrypoint] Warning: qBittorrent did not respond after ${QBIT_WAIT_SECS}s — continuing anyway."
fi

# ── Step 5: run the auto-configurator ────────────────────────────────────────
# All relevant env vars are already exported:
#   PVTKRRX_PROWLARR_API_KEY  — from step 3 (or pre-set in compose)
#   PVTKRRX_PROWLARR_URL      — from compose (http://prowlarr:9696)
#   PVTKRRX_QBIT_URL          — from compose (http://qbittorrent:8080)
#   PVTKRRX_QBIT_USERNAME     — from compose / .env
#   PVTKRRX_QBIT_PASSWORD     — from compose / .env
echo "[pvtkrrx-entrypoint] Running auto-configurator..."
node /app/scripts/server-installer.js --auto
echo "[pvtkrrx-entrypoint] Auto-configuration complete."

# ── Step 6: start the application ────────────────────────────────────────────
# The app prints the Stremio install URL and configure URL to stdout once
# the HTTP server is listening.
exec node /app/index.js
