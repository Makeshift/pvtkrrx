# PVTKRRX — Docker Compose self-host stack

A three-container setup that mirrors what `scripts/install-selfhost.sh` does on
a bare Linux host, but without systemd, without privileged containers, and
without `curl | sudo bash`.

```
┌─────────────┐   Torznab    ┌──────────────┐
│   Stremio   │ ──────────►  │    PVTKRRX   │ :7000
│  (client)   │ ◄──────────  │  (self-host) │
└─────────────┘  manifests / └──────┬───┬───┘
                  streams           │   │
                               search   manage
                                    ↓   ↓
                             ┌──────────────┐   ┌──────────────┐
                             │   Prowlarr   │   │  qBittorrent │
                             │  indexers    │   │  WebUI       │
                             │  :9696       │   │  :8080       │
                             └──────────────┘   └──────────────┘
```

## How it maps to install-selfhost.sh

| install-selfhost.sh step | Docker equivalent |
|---|---|
| Install qBittorrent-nox via apt, write systemd unit | `lscr.io/linuxserver/qbittorrent` container |
| Install Prowlarr binary, write systemd unit | `lscr.io/linuxserver/prowlarr` container |
| Download Node.js | `node:22-slim` base image in `Dockerfile.selfhost` |
| Download PVTKRRX source, run `npm install` | `COPY . .` + `npm ci` in `Dockerfile.selfhost` |
| Run `node scripts/server-installer.js --auto` | `docker-entrypoint.sh` runs this on every container start |

The entrypoint (`deploy/docker-entrypoint.sh`) runs `server-installer.js --auto`
on every container start.  It is idempotent: existing secrets and saved config
are preserved; only missing values are filled in.

## Requirements

- Docker Engine ≥ 24 with the Compose plugin (`docker compose`)
- A clone of this repository

## Quick start

```bash
# 1. Copy the env template and fill in the secrets section at minimum
cp deploy/.env.example deploy/.env
$EDITOR deploy/.env        # set ENCRYPTION_SECRET, AUTH_TOKEN_SECRET at minimum

# 2. Build and start the stack (from the repository root)
docker compose -f deploy/docker-compose.selfhost.yml up -d --build

# 3. Tail logs to confirm startup and find the admin token
docker compose -f deploy/docker-compose.selfhost.yml logs -f pvtkrrx
```

## Environment file

All user-configurable settings live in `deploy/.env` (copied from
`deploy/.env.example`).

### Required before first start

| Variable | Why |
|---|---|
| `ENCRYPTION_SECRET` | Encrypts `local-config.json` (Prowlarr API key, qBit credentials). Must be stable across container rebuilds. |
| `AUTH_TOKEN_SECRET` | Signs install tokens. Must be stable. |

Generate strong values with:
```bash
openssl rand -base64 32   # run twice — once for each secret
```

### Other important variables

| Variable | Purpose | Default |
|---|---|---|
| `PVTKRRX_SERVER_ADMIN_TOKEN` | Admin password for `/configure` UI | auto-generated |
| `PVTKRRX_PUBLIC_BASE_URL` | Public HTTPS URL for remote Stremio installs | *(empty — local only)* |
| `PVTKRRX_PLAYBACK_BASE_URL` | Stream playback origin | same as public URL |
| `PVTKRRX_SELF_HOST_HTTPS_MODE` | `skip` or `domain` | `skip` |
| `PVTKRRX_PROWLARR_URL` | Prowlarr URL inside Docker network | `http://prowlarr:9696` |
| `PVTKRRX_QBIT_URL` | qBittorrent URL inside Docker network | `http://qbittorrent:8080` |
| `PUID` / `PGID` | UID/GID for qBittorrent + Prowlarr file ownership | `1000` |
| `TZ` | Timezone for qBittorrent + Prowlarr | `Etc/UTC` |

## URLs

After the stack starts:

| Service | URL |
|---|---|
| PVTKRRX configure UI | http://localhost:7000/configure |
| PVTKRRX self-host manifest | http://localhost:7000/selfhost/manifest.json |
| qBittorrent WebUI | http://localhost:8080 |
| Prowlarr UI | http://localhost:9696 |

## Configuring Prowlarr and qBittorrent in PVTKRRX

The entrypoint pre-fills the PVTKRRX config with Docker service DNS URLs
(`http://prowlarr:9696` and `http://qbittorrent:8080`) on first boot.
You still need to add the API key and credentials after each service starts.

### qBittorrent

1. Find the temporary admin password in the container logs:
   ```bash
   docker logs qbittorrent 2>&1 | grep -i 'temporary password'
   ```
2. Log into http://localhost:8080, change the password.
3. In the PVTKRRX configure UI, set:
   - **qBittorrent URL:** `http://qbittorrent:8080`
   - **Username / password:** your new credentials

### Prowlarr

1. Open http://localhost:9696 and complete the setup wizard.
2. Add your private tracker indexers under *Indexers*.
3. Copy the **API key** from *Settings → General*.
4. In the PVTKRRX configure UI, set:
   - **Prowlarr URL:** `http://prowlarr:9696`
   - **API key:** the key from step 3

## Remote Stremio installs and HTTPS

Stremio clients outside your LAN **require a real HTTPS origin** — plain HTTP
will not work for remote installs.  Options:

1. **Reverse proxy (recommended):** place nginx, Caddy, or Traefik in front of
   the `pvtkrrx` container and terminate TLS there.  Set
   `PVTKRRX_PUBLIC_BASE_URL=https://your-domain.example` in `deploy/.env`.

2. **Built-in TLS:** set `PVTKRRX_SELF_HOST_HTTPS_MODE=domain` and
   `PVTKRRX_PUBLIC_BASE_URL=https://your-domain.example`.

For local-only or LAN use, HTTP on port 7000 is fine.

## Security warnings

> ⚠️ **Do not expose qBittorrent or Prowlarr directly to the public internet.**
>
> - Both services are designed for trusted-network access only.
> - The compose file binds their ports to all host interfaces (`0.0.0.0`).
>   Restrict them with a firewall rule if your host is internet-facing:
>   ```
>   ufw deny 8080
>   ufw deny 9696
>   ```
> - Keep `PVTKRRX_SERVER_ADMIN_TOKEN` and the two secrets (`ENCRYPTION_SECRET`,
>   `AUTH_TOKEN_SECRET`) out of source control.  Add `deploy/.env` to your
>   `.gitignore` if you manage this stack in a git repo.

## Volumes

| Volume | Contents |
|---|---|
| `pvtkrrx_data` | Runtime dir: `.env` (secrets), `local-config.json`, admin token, poster cache |
| `qbittorrent_config` | qBittorrent settings, torrents, resume data |
| `prowlarr_config` | Prowlarr database, indexer config |
| `downloads` | Completed torrent files (shared between qBittorrent and PVTKRRX) |

To use a host bind-mount for `downloads`, see the commented-out volume variant
at the bottom of `docker-compose.selfhost.yml`.

## Updating

```bash
# Pull new upstream images for qBittorrent + Prowlarr
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

Add `--volumes` to also delete all persistent data (this is irreversible).
