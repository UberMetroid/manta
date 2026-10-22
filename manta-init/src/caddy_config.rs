//! Directory provisioning, `caddy.env` loader, and hardened CrowdSec+AppSec Caddyfile generator.

use std::env;
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const DEFAULT_CADDYFILE: &str = include_str!("../../assets/default-Caddyfile");
const CLOUDFLARE_IPS: &str = include_str!("../../assets/cloudflare-ips.txt");
const GENERATED_HEADER: &str = "# MANTA_AUTO_GENERATED_CADDYFILE\n";

#[derive(Debug, Clone)]
pub struct CaddyEnvConfig {
    pub crowdsec_url: String,
    pub appsec_url: String,
    pub trusted_proxies_extra: String,
    pub emby_domain: String,
    pub emby_upstream: String,
    pub jellyfin_domain: String,
    pub jellyfin_upstream: String,
    pub seerr_domain: String,
    pub seerr_upstream: String,
}

impl CaddyEnvConfig {
    pub fn from_env() -> Self {
        Self {
            crowdsec_url: sanitize_endpoint_token(
                &env::var("CROWDSEC_URL").unwrap_or_else(|_| "http://172.17.0.1:8091".to_string()),
                "http://172.17.0.1:8091",
            ),
            appsec_url: sanitize_endpoint_token(
                &env::var("APPSEC_URL").unwrap_or_else(|_| "http://172.17.0.1:7422".to_string()),
                "http://172.17.0.1:7422",
            ),
            trusted_proxies_extra: env::var("TRUSTED_PROXIES")
                .unwrap_or_else(|_| "127.0.0.1/32 172.17.0.1/32 100.64.0.0/10".to_string()),
            emby_domain: sanitize_site_addresses(
                &env::var("EMBY_DOMAIN").unwrap_or_else(|_| "http://:80".to_string()),
                "http://:80",
            ),
            emby_upstream: sanitize_endpoint_token(
                &env::var("EMBY_UPSTREAM").unwrap_or_else(|_| "172.17.0.1:9096".to_string()),
                "172.17.0.1:9096",
            ),
            jellyfin_domain: sanitize_site_addresses(
                &env::var("JELLYFIN_DOMAIN").unwrap_or_else(|_| "http://:81".to_string()),
                "http://:81",
            ),
            jellyfin_upstream: sanitize_endpoint_token(
                &env::var("JELLYFIN_UPSTREAM").unwrap_or_else(|_| "172.17.0.1:8096".to_string()),
                "172.17.0.1:8096",
            ),
            seerr_domain: sanitize_site_addresses(
                &env::var("SEERR_DOMAIN").unwrap_or_else(|_| "http://seerr.localhost".to_string()),
                "http://seerr.localhost",
            ),
            seerr_upstream: sanitize_endpoint_token(
                &env::var("SEERR_UPSTREAM").unwrap_or_else(|_| "172.17.0.1:5055".to_string()),
                "172.17.0.1:5055",
            ),
        }
    }
}

pub fn sanitize_endpoint_token(raw: &str, fallback: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '/' | '-' | '_'))
    {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn sanitize_site_addresses(raw: &str, fallback: &str) -> String {
    let mut valid_addrs = Vec::new();
    for part in raw.split(',') {
        let item = part.trim();
        if !item.is_empty()
            && item
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '/' | '-' | '_'))
        {
            valid_addrs.push(item);
        }
    }
    if valid_addrs.is_empty() {
        fallback.to_string()
    } else {
        valid_addrs.join(", ")
    }
}

pub fn build_trusted_proxies_list(extra: &str) -> String {
    let mut list: Vec<String> = Vec::new();
    for item in extra.split(|c: char| c == ',' || c.is_whitespace()) {
        let t = item.trim();
        if !t.is_empty()
            && t.chars()
                .all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':' || c == '/')
            && !list.iter().any(|existing| existing == t)
        {
            list.push(t.to_string());
        }
    }
    for cf in CLOUDFLARE_IPS.lines().map(str::trim) {
        if !cf.is_empty() && !cf.starts_with('#') && !list.iter().any(|e| e == cf) {
            list.push(cf.to_string());
        }
    }
    list.join(" ")
}

pub fn render_caddyfile(cfg: &CaddyEnvConfig) -> String {
    let trusted = build_trusted_proxies_list(&cfg.trusted_proxies_extra);
    let body = DEFAULT_CADDYFILE
        .replace("__TRUSTED_PROXIES__", &trusted)
        .replace("__CROWDSEC_URL__", &cfg.crowdsec_url)
        .replace("__APPSEC_URL__", &cfg.appsec_url)
        .replace("__EMBY_DOMAIN__", &cfg.emby_domain)
        .replace("__EMBY_UPSTREAM__", &cfg.emby_upstream)
        .replace("__JELLYFIN_DOMAIN__", &cfg.jellyfin_domain)
        .replace("__JELLYFIN_UPSTREAM__", &cfg.jellyfin_upstream)
        .replace("__SEERR_DOMAIN__", &cfg.seerr_domain)
        .replace("__SEERR_UPSTREAM__", &cfg.seerr_upstream);
    format!("{GENERATED_HEADER}{body}")
}

pub fn load_caddy_env_file(path: &Path) -> Vec<(String, String)> {
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut vars = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let clean = line.strip_prefix("export ").unwrap_or(line).trim();
        if let Some((k, v)) = clean.split_once('=') {
            let key = k.trim();
            let val = v.trim().trim_matches('"').trim_matches('\'');
            if !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                vars.push((key.to_string(), val.to_string()));
            }
        }
    }
    vars
}

pub fn ensure_directories_and_ownership(puid: u32, pgid: u32, umask_val: u32) {
    let dir_mode = 0o777 & !umask_val;
    let file_mode = 0o666 & !umask_val;
    for d in [
        "/config",
        "/config/caddy",
        "/data",
        "/data/caddy",
        "/etc/caddy",
        "/var/log/caddy",
        "/tmp",
    ] {
        let _ = fs::create_dir_all(d);
        if d != "/tmp" {
            let _ = fs::set_permissions(d, Permissions::from_mode(dir_mode));
        }
    }
    let _ = fs::set_permissions("/tmp", Permissions::from_mode(0o1777));
    let access_log = Path::new("/var/log/caddy/access.log");
    if !access_log.exists() {
        let _ = fs::write(access_log, b"");
    }
    let _ = fs::set_permissions(access_log, Permissions::from_mode(file_mode));
    let owner = format!("{puid}:{pgid}");
    let _ = Command::new("chown")
        .args(["-R", &owner, "/config", "/data", "/var/log/caddy"])
        .status();
}

pub fn ensure_active_caddyfile(
    caddyfile_path: &Path,
    user_override_path: &Path,
    cfg: &CaddyEnvConfig,
    umask_val: u32,
) -> Result<String, String> {
    let file_mode = 0o666 & !umask_val;
    if user_override_path.exists() {
        if let Ok(user_cf) = fs::read_to_string(user_override_path) {
            if !user_cf.trim().is_empty() {
                fs::write(caddyfile_path, &user_cf)
                    .map_err(|e| format!("Failed writing {}: {e}", caddyfile_path.display()))?;
                let _ = fs::set_permissions(caddyfile_path, Permissions::from_mode(file_mode));
                return Ok(user_cf);
            }
        }
    }
    if caddyfile_path.exists() {
        if let Ok(existing) = fs::read_to_string(caddyfile_path) {
            if !existing.trim().is_empty() && !existing.starts_with(GENERATED_HEADER) {
                return Ok(existing);
            }
        }
    }
    let generated = render_caddyfile(cfg);
    fs::write(caddyfile_path, &generated)
        .map_err(|e| format!("Failed writing {}: {e}", caddyfile_path.display()))?;
    let _ = fs::set_permissions(caddyfile_path, Permissions::from_mode(file_mode));
    Ok(generated)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_render_and_re_render_generated_caddyfile() {
        let dir = std::env::temp_dir().join("manta_caddy_cfg_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cf_path = dir.join("Caddyfile");
        let override_path = dir.join("user-Caddyfile");

        let mut cfg = CaddyEnvConfig::from_env();
        cfg.emby_domain = "http://first.local".to_string();
        let out1 = ensure_active_caddyfile(&cf_path, &override_path, &cfg, 0o002).unwrap();
        assert!(out1.contains("http://first.local"));

        cfg.emby_domain = "http://second.local".to_string();
        let out2 = ensure_active_caddyfile(&cf_path, &override_path, &cfg, 0o002).unwrap();
        assert!(out2.contains("http://second.local"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sanitize_blocks_whitespace_and_comment_injection() {
        assert_eq!(
            sanitize_endpoint_token("172.17.0.1:9096 # injected", "safe"),
            "safe"
        );
        assert_eq!(
            sanitize_site_addresses("http://a.io, http://b.io", "safe"),
            "http://a.io, http://b.io"
        );
    }
}
