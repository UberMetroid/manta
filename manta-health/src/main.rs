//! Manta zero-dependency TCP/HTTP healthcheck CLI (`--check`) and `:9199/status` server.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod status_server;
mod upstream_probe;

use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::exit;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use status_server::handle_status_client;
use upstream_probe::collect_snapshot;

fn log(msg: &str) {
    eprintln!("[manta-health] {msg}");
}

fn run_cli_check(
    bind_port: u16,
    caddy_admin: &str,
    caddy_http: &str,
    crowdsec_url: &str,
    appsec_url: &str,
) -> Result<(), String> {
    let addr = format!("127.0.0.1:{bind_port}");
    if let Ok(mut stream) = TcpStream::connect_timeout(
        &addr
            .parse()
            .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], bind_port))),
        Duration::from_secs(2),
    ) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
        let _ = stream
            .write_all(b"GET /status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let mut buf = [0u8; 1024];
        if let Ok(n) = stream.read(&mut buf) {
            let reply = String::from_utf8_lossy(&buf[..n]);
            if reply.starts_with("HTTP/1.1 200") {
                return Ok(());
            }
            return Err(format!(
                "Status server returned unhealthy response: {}",
                reply.lines().next().unwrap_or("")
            ));
        }
    }

    let snap = collect_snapshot(caddy_admin, caddy_http, crowdsec_url, appsec_url, 0);
    if snap.is_healthy() {
        Ok(())
    } else {
        Err(format!(
            "Unhealthy snapshot: caddy_http={}, caddy_admin={}, crowdsec_lapi={}, appsec={}",
            snap.caddy_http_up, snap.caddy_admin_up, snap.crowdsec_lapi_up, snap.appsec_up
        ))
    }
}

fn main() {
    let bind_port: u16 = env::var("HEALTH_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9199);
    let caddy_admin = env::var("CADDY_ADMIN").unwrap_or_else(|_| "127.0.0.1:2019".to_string());
    let caddy_http = env::var("CADDY_HTTP_ADDR").unwrap_or_else(|_| "127.0.0.1:80".to_string());
    let crowdsec_url =
        env::var("CROWDSEC_URL").unwrap_or_else(|_| "http://172.17.0.1:8091".to_string());
    let appsec_url =
        env::var("APPSEC_URL").unwrap_or_else(|_| "http://172.17.0.1:7422".to_string());

    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "--check") {
        match run_cli_check(
            bind_port,
            &caddy_admin,
            &caddy_http,
            &crowdsec_url,
            &appsec_url,
        ) {
            Ok(()) => exit(0),
            Err(e) => {
                log(&format!("UNHEALTHY: {e}"));
                exit(1);
            }
        }
    }

    let listen_addr = format!("0.0.0.0:{bind_port}");
    let listener = match TcpListener::bind(&listen_addr) {
        Ok(l) => l,
        Err(e) => {
            log(&format!("FATAL: Failed to bind {listen_addr}: {e}"));
            exit(1);
        }
    };

    log(&format!("Listening on http://{listen_addr}/status"));
    let start_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for incoming in listener.incoming().flatten() {
        let admin = caddy_admin.clone();
        let http = caddy_http.clone();
        let cs = crowdsec_url.clone();
        let appsec = appsec_url.clone();
        thread::spawn(move || {
            handle_status_client(incoming, start_epoch, &admin, &http, &cs, &appsec);
        });
    }
}
