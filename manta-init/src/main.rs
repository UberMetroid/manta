//! Manta PID 1 container supervisor, Caddyfile provisioner, and live auto-reload watchdog.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod caddy_config;
mod spawn_daemon;

use std::env;
use std::path::Path;
use std::process::{exit, Child};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use caddy_config::{
    ensure_active_caddyfile, ensure_directories_and_ownership, load_caddy_env_file, CaddyEnvConfig,
};
use spawn_daemon::{
    file_mtime, find_caddy_bin, format_umask, parse_octal_umask, reload_caddy, run_validator,
    spawn_daemon_process, terminate_children, DaemonContext,
};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

fn log(msg: &str) {
    eprintln!("[manta-init] {msg}");
}

fn spawn_or_exit(res: Result<Child, String>) -> Child {
    match res {
        Ok(c) => c,
        Err(e) => {
            log(&format!("FATAL: {e}"));
            exit(1);
        }
    }
}

fn supervise_loop(ctx: &DaemonContext<'_>, mut caddy_child: Child, mut health_child: Child) {
    let caddy_bin = find_caddy_bin();
    let cf_path = Path::new(ctx.caddyfile_path);
    let mut last_mtime = file_mtime(cf_path);
    let mut last_watch = Instant::now();

    while !SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
        if Path::new("/run/manta.shutdown").exists() {
            SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
            break;
        }

        if let Ok(Some(st)) = caddy_child.try_wait() {
            log(&format!("WARN: caddy exited with {st}; restarting..."));
            ensure_directories_and_ownership(ctx.puid, ctx.pgid, ctx.umask_val);
            if let Ok(c) = spawn_daemon_process(
                caddy_bin,
                &[
                    "run",
                    "--config",
                    ctx.caddyfile_path,
                    "--adapter",
                    "caddyfile",
                ],
                ctx.puid,
                ctx.pgid,
                ctx.umask_val,
                ctx.drop_caddy_privs,
                ctx.extra_env,
            ) {
                caddy_child = c;
            }
        }

        if let Ok(Some(st)) = health_child.try_wait() {
            log(&format!(
                "WARN: manta-health exited with {st}; restarting..."
            ));
            if let Ok(c) = spawn_daemon_process(
                "/bin/manta-health",
                &[],
                ctx.puid,
                ctx.pgid,
                ctx.umask_val,
                true,
                ctx.extra_env,
            ) {
                health_child = c;
            }
        }

        if last_watch.elapsed() >= Duration::from_secs(5) {
            last_watch = Instant::now();
            let current_mtime = file_mtime(cf_path);
            if current_mtime.is_some() && current_mtime != last_mtime {
                log("Detected Caddyfile change; validating before reload...");
                if run_validator(ctx.caddyfile_path, true, ctx.extra_env) {
                    ensure_directories_and_ownership(ctx.puid, ctx.pgid, ctx.umask_val);
                    if reload_caddy(ctx.caddyfile_path, ctx.extra_env) {
                        log("Caddy reloaded cleanly with updated Caddyfile.");
                    } else {
                        log("WARN: Caddy reload returned non-zero status.");
                    }
                } else {
                    log(
                        "ERROR: Updated Caddyfile failed manta-config validation; skipping reload!",
                    );
                }
                last_mtime = current_mtime;
            }
        }

        thread::sleep(Duration::from_millis(500));
    }

    log("Shutdown requested; terminating caddy and manta-health gracefully...");
    let mut children = [caddy_child, health_child];
    terminate_children(&mut children);
    log("Clean shutdown complete.");
}

fn main() {
    let puid: u32 = env::var("PUID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(99);
    let pgid: u32 = env::var("PGID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);
    let umask_str = env::var("UMASK").unwrap_or_else(|_| "002".to_string());
    let umask_val = parse_octal_umask(&umask_str);
    let drop_caddy_privs = env::var("DROP_PRIVS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let caddyfile_path =
        env::var("CADDYFILE_PATH").unwrap_or_else(|_| "/etc/caddy/Caddyfile".to_string());

    log(&format!(
        "Starting manta-init supervisor (PUID={puid}, PGID={pgid}, UMASK={})",
        format_umask(umask_val)
    ));

    ensure_directories_and_ownership(puid, pgid, umask_val);

    let mut extra_env = load_caddy_env_file(Path::new("/config/caddy.env"));
    for (k, v) in load_caddy_env_file(Path::new("/etc/caddy/caddy.env")) {
        extra_env.push((k, v));
    }

    let cfg = CaddyEnvConfig::from_env();
    if let Err(e) = ensure_active_caddyfile(
        Path::new(&caddyfile_path),
        Path::new("/config/Caddyfile"),
        &cfg,
        umask_val,
    ) {
        log(&format!("FATAL: {e}"));
        exit(1);
    }

    log("Running manta-config pre-flight security & CrowdSec validation...");
    if !run_validator(&caddyfile_path, false, &extra_env) {
        log("FATAL: manta-config validation failed. Refusing to start Caddy (fail-closed).");
        exit(1);
    }

    // Re-ensure ownership after caddy validate (which runs as root and may create access.log)
    ensure_directories_and_ownership(puid, pgid, umask_val);

    let caddy_bin = find_caddy_bin();
    let caddy_child = spawn_or_exit(spawn_daemon_process(
        caddy_bin,
        &["run", "--config", &caddyfile_path, "--adapter", "caddyfile"],
        puid,
        pgid,
        umask_val,
        drop_caddy_privs,
        &extra_env,
    ));
    let health_child = spawn_or_exit(spawn_daemon_process(
        "/bin/manta-health",
        &[],
        puid,
        pgid,
        umask_val,
        true,
        &extra_env,
    ));

    log("Launched caddy reverse proxy and manta-health (:9199/status).");
    let ctx = DaemonContext {
        puid,
        pgid,
        umask_val,
        drop_caddy_privs,
        caddyfile_path: &caddyfile_path,
        extra_env: &extra_env,
    };
    supervise_loop(&ctx, caddy_child, health_child);
}
