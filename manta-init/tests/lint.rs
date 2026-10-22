//! Workspace-wide lint tests ensuring zero shell invocations ("sh -c", "bash -c", "zsh -c")
//! and validating Guix manifest and Unraid template consistency.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

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
fn test_no_shell_invocations_in_workspace() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .ok_or("Could not find workspace root")?;

    let mut rs_files = Vec::new();
    collect_rs_files(workspace_root, &mut rs_files);
    assert!(!rs_files.is_empty(), "No .rs files found to lint");

    for file in rs_files {
        if file.ends_with("tests/lint.rs") {
            continue;
        }
        let content = fs::read_to_string(&file)?;

        let forbidden_patterns = [
            ("Command::new(", "\"sh\")"),
            ("Command::new(", "\"/bin/sh\")"),
            ("Command::new(", "\"bash\")"),
            ("Command::new(", "\"/bin/bash\")"),
            ("Command::new(", "\"zsh\")"),
            ("Command::new(", "\"/bin/zsh\")"),
        ];
        for (prefix, suffix) in forbidden_patterns {
            let pat = format!("{prefix}{suffix}");
            assert!(
                !content.contains(&pat),
                "Forbidden shell invocation {pat} detected in {}",
                file.display()
            );
        }

        let has_dash_c = content.contains("\"-c\"");
        let has_shell_bin = content.contains("\"sh\"")
            || content.contains("\"bash\"")
            || content.contains("\"zsh\"");
        assert!(
            !(has_dash_c && has_shell_bin),
            "Forbidden shell -c invocation detected in {}",
            file.display()
        );
    }
    Ok(())
}

#[test]
fn test_manta_manifest_and_unraid_template() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .ok_or("Could not find workspace root")?;

    let guix_scm = fs::read_to_string(workspace_root.join("manifest.scm"))?;
    for bin_name in ["manta-init", "manta-config", "manta-health", "caddy"] {
        assert!(
            guix_scm.contains(bin_name),
            "manifest.scm missing binary {bin_name}"
        );
    }

    let template_xml = fs::read_to_string(workspace_root.join("unraid-template.xml"))?;
    assert!(template_xml.contains("<Name>manta</Name>"));
    assert!(template_xml.contains("assets/manta-icon.png"));

    Ok(())
}
