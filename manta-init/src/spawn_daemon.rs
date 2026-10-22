//! Daemon spawning, privilege dropping, and live Caddy reload helper.

use std::fs;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, SystemTime};

pub struct DaemonContext<'a> {
    pub puid: u32,
    pub pgid: u32,
    pub umask_val: u32,
    pub drop_caddy_privs: bool,
    pub caddyfile_path: &'a str,
    pub extra_env: &'a [(String, String)],
}

pub fn parse_octal_umask(s: &str) -> u32 {
    u32::from_str_radix(s.trim(), 8).unwrap_or(0o002)
}

pub fn format_umask(umask_val: u32) -> String {
    format!("{umask_val:03o}")
}

pub fn find_caddy_bin() -> &'static str {
    ["/bin/caddy", "/usr/bin/caddy", "/var/lib/caddy/bin/caddy"]
        .into_iter()
        .find(|candidate| Path::new(candidate).exists())
        .unwrap_or("/bin/caddy")
}

pub fn run_validator(
    caddyfile_path: &str,
    skip_probes: bool,
    extra_env: &[(String, String)],
) -> bool {
    let mut cmd = Command::new("/bin/manta-config");
    cmd.args(["--config", caddyfile_path]);
    if skip_probes {
        cmd.arg("--skip-probes");
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    matches!(cmd.status(), Ok(s) if s.success())
}

pub fn spawn_daemon_process(
    prog: &str,
    args: &[&str],
    puid: u32,
    pgid: u32,
    umask_val: u32,
    drop_privs: bool,
    extra_env: &[(String, String)],
) -> Result<Child, String> {
    if drop_privs && puid != 0 {
        let uid_arg = format!("--reuid={puid}");
        let gid_arg = format!("--regid={pgid}");

        let mut setpriv_cmd = Command::new("setpriv");
        setpriv_cmd
            .arg(&uid_arg)
            .arg(&gid_arg)
            .arg("--clear-groups")
            .arg("--")
            .arg(prog)
            .args(args)
            .env("HOME", "/config")
            .env("XDG_CONFIG_HOME", "/config")
            .env("XDG_DATA_HOME", "/data")
            .env("UMASK", format_umask(umask_val));
        for (k, v) in extra_env {
            setpriv_cmd.env(k, v);
        }

        if let Ok(mut child) = setpriv_cmd.spawn() {
            thread::sleep(Duration::from_millis(50));
            if matches!(child.try_wait(), Ok(None)) {
                return Ok(child);
            }
        }

        let mut fallback = Command::new(prog);
        fallback
            .args(args)
            .env("HOME", "/config")
            .env("XDG_CONFIG_HOME", "/config")
            .env("XDG_DATA_HOME", "/data")
            .env("UMASK", format_umask(umask_val))
            .uid(puid)
            .gid(pgid);
        for (k, v) in extra_env {
            fallback.env(k, v);
        }
        return fallback
            .spawn()
            .map_err(|e| format!("Failed to spawn unprivileged {prog}: {e}"));
    }

    let mut cmd = Command::new(prog);
    cmd.args(args)
        .env("HOME", "/config")
        .env("XDG_CONFIG_HOME", "/config")
        .env("XDG_DATA_HOME", "/data")
        .env("UMASK", format_umask(umask_val));
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.spawn()
        .map_err(|e| format!("Failed to spawn {prog}: {e}"))
}

pub fn file_mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

pub fn reload_caddy(caddyfile_path: &str, extra_env: &[(String, String)]) -> bool {
    let caddy_bin = find_caddy_bin();
    let mut cmd = Command::new(caddy_bin);
    cmd.args([
        "reload",
        "--config",
        caddyfile_path,
        "--adapter",
        "caddyfile",
    ])
    .env("XDG_CONFIG_HOME", "/config")
    .env("XDG_DATA_HOME", "/data");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    matches!(cmd.status(), Ok(s) if s.success())
}

pub fn terminate_children(children: &mut [Child]) {
    for child in children.iter() {
        let pid_str = child.id().to_string();
        let _ = Command::new("kill").args(["-TERM", &pid_str]).status();
    }
    thread::sleep(Duration::from_secs(2));
    for child in children.iter_mut() {
        let _ = child.kill();
        if let Ok(st) = child.wait() {
            let _ = st.signal();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_octal_umask() {
        assert_eq!(parse_octal_umask("002"), 0o002);
        assert_eq!(parse_octal_umask("022"), 0o022);
        assert_eq!(parse_octal_umask("bad"), 0o002);
        assert_eq!(format_umask(0o002), "002");
    }
}
