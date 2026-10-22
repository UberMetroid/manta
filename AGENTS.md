# manta — House Laws & Agent Engineering Standards

This document is the **single canonical source of truth** for all code, architecture, and system integration standards for `manta` (hardened GNU Guix + zero-dependency Rust Caddy v2 Reverse Proxy & CrowdSec AppSec WAF Bouncer appliance for `Emby`, `Jellyfin`, `Seerr`, and the `*arr` media stack). Every human contributor and AI agent must strictly follow these rules without exception.

**Precedence:** Where this file and CI disagree, this file wins. A rule not enforced anywhere is a bug in this file, not a suggestion to ignore.

**Rule Markers:**
- `[GATE:<tool>]` — Machine-enforced by automated compiler flags, clippy, or `cargo test`. Must pass in CI.
- `[POLICY]` — Enforced during code review. Dictates architecture, naming taste, restraint, and ergonomics.

---

## 1. The Page Rule (Code Layout & Sizing)

A **page** is one committed Rust file. Every page holds one idea, fits in one head, and carries its own weight.

- `[GATE:test]` **16–256 Lines**: Every committed `.rs` file must be between **16 and 256 lines** (`content.lines().count()`, blank lines and comments count). Enforced by `tests/page_rules.rs`.
- `[GATE:test]` **Shim Exemption (Floor Only)**: A file is a shim if every non-empty, non-comment, non-attribute line starts with `mod `, `use `, `pub mod `, or `pub use `. Shims skip the 16-line floor; the 256-line ceiling still strictly applies.
- `[GATE:test]` **Directory Density (≤ 8 files)**: At most 8 `.rs` files per directory. Crowded directories split into functional subdirectories grouped by domain.
- `[GATE:test]` **Banned Drawer Filenames**: `util.rs`, `utils.rs`, `helper.rs`, `helpers.rs`, `common.rs`, `misc.rs`, `shared.rs`, `base.rs`, `core.rs`.
- `[POLICY]` **Domain Naming Recipe**: Name pages after their concrete noun or verb:
  - Action pages: `validate_caddyfile.rs`, `probe_crowdsec.rs`, `spawn_daemon.rs`, `upstream_probe.rs`.
  - State pages: `caddy_config.rs`, `status_server.rs`.
- `[POLICY]` **Blobs Out**: Move static configurations, IP lists, and icons into `assets/` and load with `include_str!`.
- `[POLICY]` **Never Pad**: Do not add comments or blank lines to clear 16 lines. Fold small files into their single caller or nearest sibling.

---

## 2. Architecture & Zero-Dependency Discipline

- `[GATE:test]` **Zero External Dependencies**: All 3 workspace crates (`manta-init`, `manta-config`, `manta-health`) must compile with zero external crates in `[dependencies]` (`std` only) for reproducible offline GNU Guix builds.
- `[POLICY]` **Deep Modules over Speculative Traits (Rule of Two)**: Do not define traits or generic type parameters unless at least two distinct implementations exist in the repository today. Prefer concrete structs with private fields and cohesive public methods.
- `[POLICY]` **Clean Implementation & Attribution**: All code is original, written against Linux networking and POSIX standards under the MIT license.

---

## 3. Pure Rust & Crash-Resilience Standards

- `[GATE:clippy]` **Zero-Panic Invariant**: No bare `.unwrap()`, `.expect()`, or `panic!()` in production code (`#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`). `.unwrap()` and `.expect()` are permitted **only** inside `#[cfg(test)]` modules.
- `[GATE:rustc]` **`#![forbid(unsafe_code)]`**: Unsafe code is strictly forbidden across all crate roots and test modules.
- `[GATE:test]` **No Shell Invocations**: Subprocesses must never invoke `sh -c` or `bash -c`. Use direct `std::process::Command::new(argv0).args(...)`. Enforced by `tests/lint.rs`.

---

## 4. Zero-Trust Reverse Proxy & WAF Security Invariants

- `[GATE:test]` **Fail-Closed Pre-Flight Validation (`manta-config`)**:
  1. Before `caddy` starts or reloads, `manta-config` validates balanced braces, quotation hygiene, and `caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile`.
  2. Every active `Caddyfile` must enforce `order crowdsec first` and `order appsec after crowdsec`.
  3. All 22 official Cloudflare IPv4/IPv6 CIDR blocks (`assets/cloudflare-ips.txt`) plus configured LAN/Tailscale proxies must be pinned in `trusted_proxies static` with `CF-Connecting-IP` client IP extraction.
- `[GATE:test]` **Mandatory Security Headers & API Schema Lockdown**:
  1. `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, and `-Server` header stripping are enforced on every virtual host.
  2. Internal Swagger and OpenAPI schema routes (`/swagger*`, `/api-docs*`, `/openapi*`) return `403 Forbidden` at the edge before reaching Emby, Jellyfin, or Seerr.
  3. Heavy media streaming and websocket routes (`/Videos/*`, `/Audio/*`, `/socket*`) bypass full-body AppSec inspection to eliminate buffering while remaining protected by L3/L7 CrowdSec IP bouncer rules.
- `[GATE:test]` **Live Telemetry & Healthcheck (`manta-health`)**:
  `manta-health` exposes JSON telemetry on `:9199/status` and CLI `--check` mode reporting Caddy HTTP/Admin state, CrowdSec LAPI connectivity, AppSec WAF status, and certificate/log state.

---

## 5. Verification Ladder

Order matters. Each step must pass completely before running the next:

1. `cargo test --workspace --all-targets` — All unit, integration, and Page Rule lint tests pass.
2. `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic` — Zero warnings, zero panics.
3. `cargo fmt --all -- --check` — Standard formatting verified.
4. `cargo build --release --workspace` — Stripped release binaries built cleanly.

---

## 6. Known Gaps — Not Enforced

- **Live CrowdSec LAPI Bouncer Stream**: Full bouncer ticker streaming requires a live CrowdSec LAPI key (`CROWDSEC_API_KEY`) and reachable `CROWDSEC_URL`/`APPSEC_URL` endpoints in the container runtime; CI verifies Caddyfile generation, CIDR pinning, header enforcement, and TCP/HTTP probes headlessly.

---

## 7. Multi-Engine Audit Protocol (Pre-Release)

Advisory tiered audit run before tagging releases, budgeted by token capacity:
1. **`mcode`** (Abundant tokens): Full codebase scan for contract mismatches, packaging specs, and CI gates.  
   `mcode exec --permission full "<prompt>"`
2. **`vibe`** (Moderate tokens): Adversarial diff inspection for subtle regressions, security bypasses, and API validity.  
   `vibe -p "<prompt>" --trust --auto-approve`
3. **`grok`** (Strict quota): High-value referee and final sanity check on critical release diffs.  
   `grok -p "<prompt>" --always-approve`
4. **`gemma4`** (Local offline): On-device validation pass with local weights.  
   `gemma4 -p "<prompt>"`

**Rule:** External audits are strictly advisory; all findings must be verified against source code. External LLMs never gate CI—the §5 Verification Ladder is the sole canonical authority.
