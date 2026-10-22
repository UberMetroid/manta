//! CrowdSec LAPI (`CROWDSEC_URL`) and AppSec WAF (`APPSEC_URL`) endpoint parser and TCP/HTTP probe.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
pub struct EndpointTarget {
    pub host: String,
    pub port: u16,
    pub path: String,
}

pub fn parse_http_endpoint(raw_url: &str) -> Result<EndpointTarget, String> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return Err("Endpoint URL cannot be empty".to_string());
    }
    let without_scheme = if let Some(rest) = trimmed.strip_prefix("http://") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("https://") {
        rest
    } else {
        return Err(format!(
            "Endpoint URL '{trimmed}' must start with http:// or https://"
        ));
    };

    if without_scheme.chars().any(char::is_whitespace) {
        return Err("Endpoint URL contains illegal whitespace".to_string());
    }

    let (authority, path) = match without_scheme.find('/') {
        Some(idx) => (&without_scheme[..idx], &without_scheme[idx..]),
        None => (without_scheme, "/"),
    };

    if authority.is_empty() {
        return Err("Endpoint URL has empty host".to_string());
    }

    let (host, port) = if let Some((h, p_str)) = authority.rsplit_once(':') {
        let p = p_str
            .parse::<u16>()
            .map_err(|_| format!("Invalid port in endpoint URL: '{p_str}'"))?;
        if p == 0 {
            return Err("Endpoint port cannot be 0".to_string());
        }
        (h.to_string(), p)
    } else if trimmed.starts_with("https://") {
        (authority.to_string(), 443)
    } else {
        (authority.to_string(), 80)
    };

    if host.is_empty() {
        return Err("Endpoint host cannot be empty".to_string());
    }

    Ok(EndpointTarget {
        host,
        port,
        path: path.to_string(),
    })
}

pub fn resolve_first_addr(target: &EndpointTarget) -> Result<SocketAddr, String> {
    let addr_spec = format!("{}:{}", target.host, target.port);
    let mut addrs = addr_spec
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve {addr_spec}: {e}"))?;
    addrs
        .next()
        .ok_or_else(|| format!("No socket addresses resolved for {addr_spec}"))
}

pub fn probe_tcp_endpoint(raw_url: &str, timeout: Duration) -> Result<(), String> {
    let target = parse_http_endpoint(raw_url)?;
    let sock_addr = resolve_first_addr(&target)?;
    let _stream = TcpStream::connect_timeout(&sock_addr, timeout).map_err(|e| {
        format!(
            "Unable to connect to {}:{} ({sock_addr}): {e}",
            target.host, target.port
        )
    })?;
    Ok(())
}

pub fn probe_crowdsec_lapi(raw_url: &str, timeout: Duration) -> Result<u16, String> {
    let target = parse_http_endpoint(raw_url)?;
    let sock_addr = resolve_first_addr(&target)?;
    let mut stream = TcpStream::connect_timeout(&sock_addr, timeout)
        .map_err(|e| format!("CrowdSec LAPI connection failed ({sock_addr}): {e}"))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let req = format!(
        "GET /v1/heartbeat HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: manta-config/0.1\r\nConnection: close\r\n\r\n",
        target.host, target.port
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("Failed sending LAPI probe: {e}"))?;

    let mut buf = [0u8; 256];
    let n = stream
        .read(&mut buf)
        .map_err(|e| format!("Failed reading LAPI probe response: {e}"))?;
    if n == 0 {
        return Err("Empty response from CrowdSec LAPI".to_string());
    }
    let text = String::from_utf8_lossy(&buf[..n]);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| "Invalid HTTP status line from CrowdSec LAPI".to_string())?;
    Ok(status)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn test_parse_http_endpoint() {
        let ep = parse_http_endpoint("http://172.17.0.1:8091").unwrap();
        assert_eq!(ep.host, "172.17.0.1");
        assert_eq!(ep.port, 8091);
        assert_eq!(ep.path, "/");

        assert!(parse_http_endpoint("ftp://1.2.3.4").is_err());
        assert!(parse_http_endpoint("http://1.2.3.4:0").is_err());
    }

    #[test]
    fn test_probe_crowdsec_lapi_local_mock() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut b = [0u8; 128];
                let _ = s.read(&mut b);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
            }
        });
        let url = format!("http://127.0.0.1:{}", addr.port());
        let code = probe_crowdsec_lapi(&url, Duration::from_secs(2)).unwrap();
        assert_eq!(code, 200);
    }
}
