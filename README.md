# Manta

<p align="center">
  <img src="assets/manta-icon.png" alt="Manta" width="160" />
</p>

Caddy v2 Reverse Proxy & CrowdSec AppSec WAF Bouncer for the media stack (`Emby`, `Jellyfin`, `Seerr`, `*arr`), built from first principles on **Zero Trust**:

1. **Assume every inbound request is hostile.** Every virtual host enforces real-time **CrowdSec LAPI IP bouncing** (`order crowdsec first`) and **CrowdSec AppSec WAF** inspection (`order appsec after crowdsec`). Internal API schema endpoints (`/swagger*`, `/api-docs*`, `/openapi*`) are blocked with `403 Forbidden` at the edge before reaching Emby, Jellyfin, or Seerr, while heavy media streams (`/Videos/*`, `/Audio/*`, `/socket*`) bypass deep body inspection for zero-buffering playback.
2. **Assume proxy headers are forged unless cryptographically or network-pinned.** Spoofed `X-Forwarded-For` and `CF-Connecting-IP` headers are rejected unless the packet originates from the 22 official Cloudflare IPv4/IPv6 CIDR ranges (`assets/cloudflare-ips.txt`) or your explicitly pinned LAN/Tailscale subnets (`TRUSTED_PROXIES`). Mandatory `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, and `-Server` stripping are verified by `manta-config` before `caddy` is allowed to start or reload.
3. **Assume the container runtime is hostile.** Built with **GNU Guix**, a static `caddy` v2.11.7 binary (`caddy-crowdsec-bouncer` `http`, `appsec`, and `layer4`), and **3 static, zero-dependency Rust binaries** (`#![forbid(unsafe_code)]`). There is no `apt`, `apk`, `pacman`, `bash` supervision loop, or third-party Rust crate supply chain inside the supervision plane.

---

## 1. Install

### Option A: Unraid (WebUI Template)
```bash
curl -fsSL https://raw.githubusercontent.com/UberMetroid/manta/main/unraid-template.xml \
  -o /boot/config/plugins/dockerMan/templates-user/my-manta.xml
```
In Unraid: **Docker** -> **Add Container** -> select **`manta`** -> fill in `CROWDSEC_API_KEY` -> **Apply** (pulls `ghcr.io/ubermetroid/manta:latest` automatically). Default host ports (`8280`, `8281`, `9199`) run side-by-side with an existing `caddy` container without conflict.

### Option B: Docker / Podman CLI
```bash
docker run -d \
  --name=manta \
  --restart=unless-stopped \
  --entrypoint=/bin/manta-init \
  -p 8280:80/tcp \
  -p 8281:81/tcp \
  -p 9199:9199/tcp \
  -e CROWDSEC_API_KEY="your_crowdsec_bouncer_key" \
  -e CROWDSEC_URL="http://172.17.0.1:8091" \
  -e APPSEC_URL="http://172.17.0.1:7422" \
  -v /mnt/cache/appdata/manta/config:/config:rw \
  -v /mnt/cache/appdata/manta/data:/data:rw \
  -v /mnt/cache/appdata/manta/logs:/var/log/caddy:rw \
  ghcr.io/ubermetroid/manta:latest
```

---

## 2. Connect Your Media & Security Stack

| Port | Service | How to Connect |
| :--- | :--- | :--- |
| **`8280` -> `80`** | **HTTP Reverse Proxy** | Point your Cloudflare Tunnel (`cloudflared`) or LAN reverse proxy entrypoints for Emby (`EMBY_DOMAIN`), Jellyfin (`JELLYFIN_DOMAIN`), and Seerr (`SEERR_DOMAIN`) to `<host-ip>:8280`. |
| **`8281` -> `81`** | **Secondary HTTP Listener** | Direct secondary listener (used by default for `http://:81` Jellyfin/Tailscale routing). |
| **`9199` -> `9199`** | **Health & WAF Status API** | `curl http://<host-ip>:9199/status` returns JSON (`healthy`, `caddy_http_up`, `caddy_admin_up`, `crowdsec_lapi_up`, `appsec_up`, `access_log_bytes`). Also supports `/bin/manta-health --check` for Docker `HEALTHCHECK`. |

---

## 3. Configuration

Supply either a custom `/etc/caddy/Caddyfile` (or `/config/Caddyfile`) **or** let `manta-init` auto-generate a hardened CrowdSec+AppSec `Caddyfile` from environment variables:

| Variable | Required | Default | Purpose |
| :--- | :---: | :--- | :--- |
| `CROWDSEC_API_KEY` | **Yes** | — | CrowdSec LAPI bouncer key (`{env.CROWDSEC_API_KEY}`) |
| `CROWDSEC_URL` | **Yes** | `http://172.17.0.1:8091` | CrowdSec Local API (`LAPI`) endpoint |
| `APPSEC_URL` | **Yes** | `http://172.17.0.1:7422` | CrowdSec AppSec WAF engine endpoint |
| `TRUSTED_PROXIES` | No | `127.0.0.1/32 172.17.0.1/32 100.64.0.0/10` | Local/Tailscale CIDRs merged with `assets/cloudflare-ips.txt` |
| `EMBY_DOMAIN` / `EMBY_UPSTREAM` | No | `http://:80` / `172.17.0.1:9096` | Emby site block address(es) and backend `host:port` |
| `JELLYFIN_DOMAIN` / `JELLYFIN_UPSTREAM` | No | `http://:81` / `172.17.0.1:8096` | Jellyfin site block address(es) and backend `host:port` |
| `SEERR_DOMAIN` / `SEERR_UPSTREAM` | No | `http://seerr.localhost` / `172.17.0.1:5055` | Seerr site block address(es) and backend `host:port` |
| `PUID` / `PGID` / `UMASK` | No | `99` / `100` / `002` | Unprivileged runtime UID, GID, and file creation mask |

---

## 4. Automatic Upstream Updates (GitHub Actions -> GHCR -> Unraid)

`.github/workflows/build-and-publish.yml` runs daily (`cron: '0 6 * * *'`) as well as on every push to `main`:
1. Runs the Rust Verification Ladder (`cargo test`, strict `cargo clippy`, `cargo fmt`).
2. Compiles static `manta-init`, `manta-config`, and `manta-health` binaries plus the latest upstream `caddy` + `caddy-crowdsec-bouncer` (`http`, `appsec`, `layer4`) via `xcaddy`.
3. Packs the reproducible image with **GNU Guix** (`guix pack -f docker`) and pushes `ghcr.io/ubermetroid/manta:latest` so Unraid Docker automatically detects new digests and notifies you when an update is ready.

---

## 5. Verify It Yourself (Don't Trust Us)

### Check Proxy, CrowdSec LAPI & WAF Status
```bash
curl -s http://localhost:9199/status
docker exec manta /bin/manta-config --config /etc/caddy/Caddyfile
```

### Build from Source & Reproduce the Image
```bash
cargo test --workspace --all-targets
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --workspace --target x86_64-unknown-linux-gnu
mkdir -p prebuilt && cp target/x86_64-unknown-linux-gnu/release/manta-* prebuilt/
guix pack -f docker -S /bin=bin -S /etc=etc -S /share=share -m manifest.scm
```
