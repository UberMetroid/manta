//! Workspace-wide gate tests validating the Page Rule (16-256 lines), directory density (<= 8),
//! banned drawer filenames, and zero external dependencies.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

const BANNED_FILENAMES: &[&str] = &[
    "util.rs",
    "utils.rs",
    "helper.rs",
    "helpers.rs",
    "common.rs",
    "misc.rs",
    "shared.rs",
    "base.rs",
    "core.rs",
];

const WORKSPACE_CRATES: &[&str] = &["manta-init", "manta-config", "manta-health"];

fn is_shim(content: &str) -> bool {
    content.lines().all(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return true;
        }
        if trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
            || trimmed.starts_with("*/")
        {
            return true;
        }
        if trimmed.starts_with("#[") || trimmed.starts_with("#![") {
            return true;
        }
        trimmed.starts_with("mod ")
            || trimmed.starts_with("use ")
            || trimmed.starts_with("pub mod ")
            || trimmed.starts_with("pub use ")
    })
}

fn collect_rs_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name != "target" && name != ".git" && name != "prebuilt" {
                collect_rs_files(&path, files);
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            files.push(path);
        }
    }
}

#[test]
fn test_workspace_page_rules_and_line_limits() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .ok_or("Could not find workspace root")?;

    let mut rs_files = Vec::new();
    collect_rs_files(workspace_root, &mut rs_files);

    assert!(!rs_files.is_empty(), "No .rs files found to validate");

    let mut dir_counts: HashMap<PathBuf, usize> = HashMap::new();

    for file in &rs_files {
        let file_name = file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();

        assert!(
            !BANNED_FILENAMES.contains(&file_name),
            "Banned drawer filename found: {}",
            file.display()
        );

        if let Some(parent) = file.parent() {
            *dir_counts.entry(parent.to_path_buf()).or_insert(0) += 1;
        }

        let content = fs::read_to_string(file)?;
        let line_count = content.lines().count();

        assert!(
            line_count <= 256,
            "File {} exceeds 256 lines: {} lines",
            file.display(),
            line_count
        );

        if !is_shim(&content) {
            assert!(
                line_count >= 16,
                "File {} has {} lines, which is below the 16-line floor (and is not a shim)",
                file.display(),
                line_count
            );
        }
    }

    for (dir, count) in dir_counts {
        assert!(
            count <= 8,
            "Directory {} contains {} .rs files (maximum allowed is 8)",
            dir.display(),
            count
        );
    }

    Ok(())
}

#[test]
fn test_zero_external_dependencies_and_naming() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .ok_or("Could not find workspace root")?;

    for crate_name in WORKSPACE_CRATES {
        let cargo_toml_path = workspace_root.join(crate_name).join("Cargo.toml");
        assert!(
            cargo_toml_path.exists(),
            "Missing Cargo.toml for {crate_name}"
        );
        let content = fs::read_to_string(&cargo_toml_path)?;
        assert!(
            content.contains(&format!("name = \"{crate_name}\"")),
            "{crate_name}/Cargo.toml missing expected package name"
        );
        assert!(
            !content.contains("dev-dependencies") && !content.contains("build-dependencies"),
            "{crate_name}/Cargo.toml must not declare dev or build dependencies"
        );
        if let Some(dep_idx) = content.find("[dependencies]") {
            let after_deps = content[dep_idx + "[dependencies]".len()..].trim();
            assert!(
                after_deps.is_empty(),
                "Crate {crate_name} must have zero external dependencies, found: {after_deps}"
            );
        }

        let main_rs_path = workspace_root.join(crate_name).join("src/main.rs");
        let main_rs = fs::read_to_string(&main_rs_path)?;
        assert!(
            main_rs.contains("#![forbid(unsafe_code)]"),
            "{crate_name}/src/main.rs must include #![forbid(unsafe_code)]"
        );
        assert!(
            main_rs.contains("#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]"),
            "{crate_name}/src/main.rs must deny unwrap_used, expect_used, and panic"
        );
    }

    let cargo_lock = fs::read_to_string(workspace_root.join("Cargo.lock"))?;
    let pkg_count = cargo_lock.matches("[[package]]").count();
    assert_eq!(
        pkg_count, 3,
        "Cargo.lock must contain only the 3 workspace crates (found {pkg_count})"
    );

    assert!(
        workspace_root.join("assets/default-Caddyfile").exists(),
        "assets/default-Caddyfile must exist"
    );
    assert!(
        workspace_root.join("assets/cloudflare-ips.txt").exists(),
        "assets/cloudflare-ips.txt must exist"
    );
    assert!(
        workspace_root.join("assets/manta-icon.png").exists(),
        "assets/manta-icon.png must exist"
    );

    Ok(())
}
