#!/usr/bin/env bash
# scripts/multi_engine_audit.sh — Pre-release multi-engine LLM audit protocol for manta
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"

info()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
ok()    { echo -e "\033[1;32m[OK]\033[0m $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()   { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; }

TARGET_ENGINE="${1:-all}"

case "$TARGET_ENGINE" in
    -h|--help)
        echo "Usage: $0 [all|mcode|vibe|grok|gemma4]"
        echo "Runs advisory tiered LLM audits per AGENTS.md Section 7."
        exit 0
        ;;
esac

cd "$ROOT_DIR"

info "Starting pre-release multi-engine audit in $ROOT_DIR..."

# Engine 1: mcode (Abundant tokens - full codebase scan)
run_mcode() {
    if command -v mcode >/dev/null 2>&1; then
        info "Running Tier 1 audit with mcode (code-review skill)..."
        mcode exec --permission full "Use the code-review skill to audit /home/ubermetroid/Projects/manta against AGENTS.md: verify Page Rule (16-256 lines), directory density (<= 8), zero banned filenames, #![forbid(unsafe_code)], zero unwrap/expect/panic in production, and Caddyfile/CrowdSec WAF security." || warn "mcode audit finished with remarks."
        ok "mcode audit complete."
    else
        warn "mcode binary not found in PATH; skipping."
    fi
}

# Engine 2: vibe (Moderate tokens - adversarial diff inspection)
run_vibe() {
    if command -v vibe >/dev/null 2>&1; then
        info "Running Tier 2 audit with vibe..."
        vibe -p "Review /home/ubermetroid/Projects/manta against AGENTS.md for security, correctness, Page Rule compliance, and edge cases." --trust --auto-approve || warn "vibe audit finished with remarks."
        ok "vibe audit complete."
    else
        warn "vibe binary not found in PATH; skipping."
    fi
}

# Engine 3: grok (Strict quota - final sanity check)
run_grok() {
    if command -v grok >/dev/null 2>&1; then
        info "Running Tier 3 audit with grok..."
        grok -p "Sanity check the manta Caddy supervisor, Cloudflare trusted proxy validator, CrowdSec LAPI/AppSec probe, and health status server against AGENTS.md." --always-approve || warn "grok audit finished with remarks."
        ok "grok audit complete."
    else
        warn "grok binary not found in PATH; skipping."
    fi
}

# Engine 4: gemma4 (Local weights - offline pass)
run_gemma4() {
    if command -v gemma4 >/dev/null 2>&1; then
        info "Running Tier 4 audit with gemma4..."
        gemma4 -p "Audit manta crates for zero unwrap/expect/panic in production code, #![forbid(unsafe_code)], and 16-256 line Page Rule compliance." || warn "gemma4 audit finished with remarks."
        ok "gemma4 audit complete."
    else
        info "gemma4 not locally installed; skipping Tier 4 local pass."
    fi
}

case "$TARGET_ENGINE" in
    mcode)  run_mcode ;;
    vibe)   run_vibe ;;
    grok)   run_grok ;;
    gemma4) run_gemma4 ;;
    all)
        run_mcode
        run_vibe
        run_grok
        run_gemma4
        ;;
    *)
        err "Unknown engine: $TARGET_ENGINE. Choose from all, mcode, vibe, grok, gemma4."
        exit 1
        ;;
esac

ok "Multi-engine audit execution cycle complete."
