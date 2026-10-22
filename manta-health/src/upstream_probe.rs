//! TCP/HTTP upstream probes for Caddy, CrowdSec LAPI, AppSec WAF, and access log state.

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthSnapshot {
    pub caddy_admin_up: bool,
    pub caddy_http_up: bool,
    pub crowdsec_lapi_up: bool,
    pub appsec_up: bool,
    pub access_log_bytes: u64,
    pub certificates_count: usize,
    pub uptime_seconds: u64,
}

impl HealthSnapshot {
    pub fn is_healthy(&self) -> bool {
        (self.caddy_http_up || self.caddy_admin_up) && self.crowdsec_lapi_up && self.appsec_up
    }
}

pub fn parse_host_port(url_or_addr: &str, default_port: u16) -> Option<(String, u16)> {
    let trimmed = url_or_addr.trim();
    if trimmed.is_empty() {
        return None;
    }
    let without_scheme = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed);
    let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
    if authority.is_empty() {
        return None;
    }
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        let port = port_str.parse::<u16>().ok()?;
        if host.is_empty() || port == 0 {
            return None;
        }
        Some((host.to_string(), port))
    } else {
        Some((authority.to_string(), default_port))
    }
}

pub fn tcp_reachable(url_or_addr: &str, default_port: u16, timeout: Duration) -> bool {
    let Some((host, port)) = parse_host_port(url_or_addr, default_port) else {
        return false;
    };
    let spec = format!("{host}:{port}");
    let Ok(mut addrs) = spec.to_socket_addrs() else {
        return false;
    };
    let Some(sock): Option<SocketAddr> = addrs.next() else {
        return false;
    };
    TcpStream::connect_timeout(&sock, timeout).is_ok()
}

pub fn probe_http_status(addr: &str, path: &str, timeout: Duration) -> bool {
    let Some((host, port)) = parse_host_port(addr, 80) else {
        return false;
    };
    let spec = format!("{host}:{port}");
    let Ok(mut addrs) = spec.to_socket_addrs() else {
        return false;
    };
    let Some(sock) = addrs.next() else {
        return false;
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&sock, timeout) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: manta-health/0.1\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 128];
    let Ok(n) = stream.read(&mut buf) else {
        return false;
    };
    n > 0 && String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.")
}

pub fn count_files_recursively(dir: &Path) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut total = 0usize;
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            total = total.saturating_add(count_files_recursively(&p));
        } else if p.extension().and_then(|e| e.to_str()) == Some("crt") {
            total = total.saturating_add(1);
        }
    }
    total
}

pub fn collect_snapshot(
    caddy_admin: &str,
    caddy_http: &str,
    crowdsec_url: &str,
    appsec_url: &str,
    uptime_seconds: u64,
) -> HealthSnapshot {
    let timeout = Duration::from_millis(1500);
    let caddy_admin_up = probe_http_status(caddy_admin, "/config/", timeout);
    let caddy_http_up = tcp_reachable(caddy_http, 80, timeout);
    let crowdsec_lapi_up = tcp_reachable(crowdsec_url, 8091, timeout);
    let appsec_up = tcp_reachable(appsec_url, 7422, timeout);

    let access_log_bytes = fs::metadata("/var/log/caddy/access.log")
        .map(|m| m.len())
        .unwrap_or(0);
    let certificates_count = count_files_recursively(Path::new("/data/caddy/certificates"));

    HealthSnapshot {
        caddy_admin_up,
        caddy_http_up,
        crowdsec_lapi_up,
        appsec_up,
        access_log_bytes,
        certificates_count,
        uptime_seconds,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port() {
        assert_eq!(
            parse_host_port("http://172.17.0.1:8091", 80),
            Some(("172.17.0.1".to_string(), 8091))
        );
        assert_eq!(
            parse_host_port("127.0.0.1:2019", 2019),
            Some(("127.0.0.1".to_string(), 2019))
        );
        assert_eq!(parse_host_port("", 80), None);
    }
}
