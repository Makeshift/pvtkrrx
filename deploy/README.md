# PVTKRRX — Docker Compose self-host stack

A three-container setup that runs PVTKRRX, qBittorrent, and Prowlarr without
systemd, without a privileged container, and without `curl | sudo bash`.

```
┌─────────────┐   Torznab    ┌──────────────┐
│   Stremio   │ ──────────►  │    PVTKRRX   │ :7000
│  (client)   │ ◄──────────  │  (self-host) │
└─────────────┘  manifests / └──────────────┘
                  streams          │  │
                               search│  │ manage
                                    ▼  ▼
                             ┌──────────────┐   ┌──────────────┐
                             │   Prowlarr   │   │  qBittorrent │
                             │  indexers    │   │  WebUI       │
                             │  :9696       │   │  :8080       │
                             └──────────────┘   └──────────────┘
```

## Requirements

- Docker Engine ≥ 24 with the Compose plugin (`docker compose`)
- A clone of this repository

## Quick start

```bash
# 1. Copy the env template and fill in your values
cp deploy/.env.example deploy/.env
$EDITOR deploy/.env

# 2. Start the stack (from the repository root)
docker compose -f deploy/docker-compose.selfhost.yml up -d

# 3. Tail logs to confirm startup
docker compose -f deploy/docker-compose.selfhost.yml logs -f pvtkrrx
```

## Environment file

All user-configurable settings live in `deploy/.env` (copied from
`deploy/.env.example`).  The most important ones:

| Variable | Purpose | Required for remote use? |
|---|---|---|
| `PVTKRRX_PUBLIC_BASE_URL` | Public HTTPS URL Stremio clients connect to | **Yes** |
| `PVTKRRX_PLAYBACK_BASE_URL` | Stream playback origin (defaults to public URL) | No |
| `PVTKRRX_SERVER_ADMIN_TOKEN` | Admin password for the configure UI | Recommended |
| `PVTKRRX_SELF_HOST_HTTPS_MODE` | `skip` (default) or `domain` (built-in TLS) | No |
| `PUID` / `PGID` | UID/GID for qBittorrent + Prowlarr file ownership | No (default 1000) |
| `TZ` | Timezone for qBittorrent + Prowlarr | No (default UTC) |
| `DOWNLOADS_PATH` | Host path for completed downloads (bind-mount variant) | No |

## URLs

After the stack starts, open:

| Service | URL |
|---|---|
| PVTKRRX configure UI | http://localhost:7000/configure |
| PVTKRRX self-host manifest | http://localhost:7000/selfhost/manifest.json |
| qBittorrent WebUI | http://localhost:8080 |
| Prowlarr UI | http://localhost:9696 |

## Configuring Prowlarr and qBittorrent inside PVTKRRX

PVTKRRX talks to Prowlarr and qBittorrent using Docker's internal service DNS.
In the PVTKRRX configure UI use these URLs:

- **Prowlarr URL:** `http://prowlarr:9696`
- **qBittorrent URL:** `http://qbittorrent:8080`

These are also set as default environment variables in the compose file so
PVTKRRX can suggest them in the configure UI automatically.

### qBittorrent first-run credentials

The LinuxServer qBittorrent image prints the temporary admin password to its
container logs on first start:

```bash
docker logs qbittorrent 2>&1 | grep -i 'temporary password'
```

Log in at http://localhost:8080, change the password, and then enter the new
credentials in the PVTKRRX configure UI.

### Prowlarr setup

1. Open http://localhost:9696 and complete the Prowlarr setup wizard.
2. Add your private tracker indexers.
3. Note the **Prowlarr API key** from *Settings → General*.
4. In the PVTKRRX configure UI enter the Prowlarr URL (`http://prowlarr:9696`)
   and API key.

## Remote Stremio installs and HTTPS

Stremio clients outside your LAN **require a real HTTPS origin** — plain HTTP
will not work for remote installs.  Options:

1. **Reverse proxy (recommended):** place nginx, Caddy, or Traefik in front of
   the `pvtkrrx` container and terminate TLS there.  Set
   `PVTKRRX_PUBLIC_BASE_URL=https://your-domain.example` in `deploy/.env`.

2. **Built-in TLS:** set `PVTKRRX_SELF_HOST_HTTPS_MODE=domain` and
   `PVTKRRX_PUBLIC_BASE_URL=https://your-domain.example`.  The app will use a
   self-signed certificate unless you mount a real certificate.

For local-only or LAN use, HTTP on port 7000 is fine — install the addon via
the configure UI on a device on the same network.

## Security warnings

> ⚠️ **Do not expose qBittorrent or Prowlarr directly to the public internet.**
>
> - qBittorrent's WebUI and Prowlarr's UI are designed for trusted-network access
>   only.  If you need remote access to them, use a VPN or SSH tunnel.
> - The default compose file binds qBittorrent `:8080` and Prowlarr `:9696` to
>   all host interfaces (`0.0.0.0`).  Restrict these with a firewall
>   (`ufw`, `iptables`, cloud security-group rules) if your host is internet-facing.
> - Keep `PVTKRRX_SERVER_ADMIN_TOKEN` secret; it controls access to the
>   self-host configure UI.

## Volumes

| Volume | Contents |
|---|---|
| `pvtkrrx_data` | PVTKRRX runtime state: saved config, tokens, poster raster cache, logs |
| `qbittorrent_config` | qBittorrent settings, torrents, resume data |
| `prowlarr_config` | Prowlarr database, indexer config |
| `downloads` | Completed torrent downloads (shared between qBittorrent and PVTKRRX) |

All volumes are Docker-managed by default.  To use a host bind-mount for
downloads (e.g. to an existing media directory), see the commented-out
`downloads` volume variant at the bottom of `docker-compose.selfhost.yml`.

## Updating

```bash
# Pull new images for qBittorrent + Prowlarr
docker compose -f deploy/docker-compose.selfhost.yml pull qbittorrent prowlarr

# Rebuild the PVTKRRX image from the latest source
docker compose -f deploy/docker-compose.selfhost.yml build pvtkrrx

# Restart with the new images
docker compose -f deploy/docker-compose.selfhost.yml up -d
```

## Stopping the stack

```bash
docker compose -f deploy/docker-compose.selfhost.yml down
```

Add `--volumes` to also delete all persistent data (irreversible).
