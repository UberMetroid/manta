//! HTTP status server for `:9199/status` and JSON telemetry formatter.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::upstream_probe::{collect_snapshot, HealthSnapshot};

pub fn format_status_http_response(snap: &HealthSnapshot) -> String {
    let healthy = snap.is_healthy();
    let status_code = if healthy {
        "200 OK"
    } else {
        "503 Service Unavailable"
    };
    let status_label = if healthy { "healthy" } else { "unhealthy" };

    let body = format!(
        "{{\"status\":\"{status_label}\",\"caddy_http_up\":{},\"caddy_admin_up\":{},\"crowdsec_lapi_up\":{},\"appsec_up\":{},\"access_log_bytes\":{},\"certificates_count\":{},\"uptime_seconds\":{}}}\n",
        snap.caddy_http_up,
        snap.caddy_admin_up,
        snap.crowdsec_lapi_up,
        snap.appsec_up,
        snap.access_log_bytes,
        snap.certificates_count,
        snap.uptime_seconds
    );

    format!(
        "HTTP/1.1 {status_code}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

pub fn handle_status_client(
    mut client: TcpStream,
    start_epoch: u64,
    caddy_admin: &str,
    caddy_http: &str,
    crowdsec_url: &str,
    appsec_url: &str,
) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(3)));
    let mut req_buf = [0u8; 1024];
    let _ = client.read(&mut req_buf);

    let now_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let uptime = now_epoch.saturating_sub(start_epoch);

    let snap = collect_snapshot(caddy_admin, caddy_http, crowdsec_url, appsec_url, uptime);
    let resp = format_status_http_response(&snap);
    let _ = client.write_all(resp.as_bytes());
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_format_status_http_response() {
        let ok_snap = HealthSnapshot {
            caddy_admin_up: true,
            caddy_http_up: true,
            crowdsec_lapi_up: true,
            appsec_up: true,
            access_log_bytes: 4096,
            certificates_count: 2,
            uptime_seconds: 95,
        };
        let resp = format_status_http_response(&ok_snap);
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("\"status\":\"healthy\""));
        assert!(resp.contains("\"crowdsec_lapi_up\":true"));

        let down_snap = HealthSnapshot {
            caddy_admin_up: false,
            caddy_http_up: false,
            crowdsec_lapi_up: false,
            appsec_up: false,
            access_log_bytes: 0,
            certificates_count: 0,
            uptime_seconds: 5,
        };
        let down_resp = format_status_http_response(&down_snap);
        assert!(down_resp.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(down_resp.contains("\"status\":\"unhealthy\""));
    }
}
