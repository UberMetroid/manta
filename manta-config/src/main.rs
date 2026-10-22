//! Manta configuration & CrowdSec/AppSec pre-flight validator binary.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod probe_crowdsec;
mod validate_caddyfile;

use std::env;
use std::fs;
use std::process::{exit, Command};
use std::time::Duration;

use probe_crowdsec::{probe_crowdsec_lapi, probe_tcp_endpoint};
use validate_caddyfile::verify_security_directives;

fn log(msg: &str) {
    eprintln!("[manta-config] {msg}");
}

fn find_caddy_binary() -> Option<&'static str> {
    ["/bin/caddy", "/usr/bin/caddy", "/var/lib/caddy/bin/caddy"]
        .into_iter()
        .find(|candidate| std::path::Path::new(candidate).exists())
}

fn run_caddy_validate(caddyfile_path: &str) -> Result<(), String> {
    let caddy_bin = find_caddy_binary().ok_or_else(|| {
        "Caddy binary not found at /bin/caddy, /usr/bin/caddy, or /var/lib/caddy/bin/caddy"
            .to_string()
    })?;
    let output = Command::new(caddy_bin)
        .args([
            "validate",
            "--config",
            caddyfile_path,
            "--adapter",
            "caddyfile",
        ])
        .output()
        .map_err(|e| format!("Failed to execute {caddy_bin} validate: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("caddy validate failed: {}", stderr.trim()));
    }
    Ok(())
}

fn execute_config_validation() -> Result<(), String> {
    let mut caddyfile_path =
        env::var("CADDYFILE_PATH").unwrap_or_else(|_| "/etc/caddy/Caddyfile".to_string());
    let mut skip_network_probes = env::var("MANTA_SKIP_PROBES")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut skip_caddy_bin = env::var("MANTA_SKIP_CADDY_VALIDATE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let args: Vec<String> = env::args().skip(1).collect();
    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--config" => {
                idx = idx.saturating_add(1);
                if let Some(p) = args.get(idx) {
                    caddyfile_path = p.clone();
                } else {
                    return Err("--config requires a file path argument".to_string());
                }
            }
            "--skip-probes" => {
                skip_network_probes = true;
            }
            "--skip-caddy-validate" => {
                skip_caddy_bin = true;
            }
            other => {
                return Err(format!("Unknown argument: {other}"));
            }
        }
        idx = idx.saturating_add(1);
    }

    let raw_content = fs::read_to_string(&caddyfile_path)
        .map_err(|e| format!("Failed to read Caddyfile at {caddyfile_path}: {e}"))?;

    let report = verify_security_directives(&raw_content)?;
    log(&format!(
        "Validated {caddyfile_path}: {} sites, {} Cloudflare CIDRs, CrowdSec={}, AppSec={}, HSTS/Headers={}, SwaggerBlock={}",
        report.site_count,
        report.trusted_proxy_count,
        report.has_crowdsec,
        report.has_appsec,
        report.has_security_headers,
        report.has_swagger_block
    ));

    if !skip_caddy_bin {
        run_caddy_validate(&caddyfile_path)?;
    }

    if !skip_network_probes {
        let crowdsec_url =
            env::var("CROWDSEC_URL").unwrap_or_else(|_| "http://172.17.0.1:8091".to_string());
        let appsec_url =
            env::var("APPSEC_URL").unwrap_or_else(|_| "http://172.17.0.1:7422".to_string());
        let timeout = Duration::from_secs(3);

        match probe_crowdsec_lapi(&crowdsec_url, timeout) {
            Ok(code) => log(&format!(
                "CrowdSec LAPI reachable at {crowdsec_url} (HTTP {code})"
            )),
            Err(e) => log(&format!("WARN: CrowdSec LAPI probe ({crowdsec_url}): {e}")),
        }

        match probe_tcp_endpoint(&appsec_url, timeout) {
            Ok(()) => log(&format!("CrowdSec AppSec reachable at {appsec_url}")),
            Err(e) => log(&format!("WARN: CrowdSec AppSec probe ({appsec_url}): {e}")),
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = execute_config_validation() {
        log(&format!("ERROR: {e}"));
        exit(1);
    }
}
