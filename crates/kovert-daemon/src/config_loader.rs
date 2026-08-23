use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use kovert_core::config::Config;
use kovert_core::validate_config;

pub fn load(path: &Path, allow_unsafe: bool) -> Result<Config> {
    if !allow_unsafe {
        verify_permissions(path)?;
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read configuration {}", path.display()))?;
    let config = Config::from_toml(&text)
        .with_context(|| format!("parse configuration {}", path.display()))?;
    if let Err(errors) = validate_config(&config) {
        let message = errors
            .into_iter()
            .map(|error| format!("- {error}"))
            .collect::<Vec<_>>()
            .join("\n");
        bail!("configuration validation failed:\n{message}")
    }
    Ok(config)
}

fn verify_permissions(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect configuration {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("configuration must be a regular file, not a symlink")
    }
    if metadata.uid() != 0 {
        bail!("configuration must be owned by root")
    }
    if metadata.mode() & 0o022 != 0 {
        bail!("configuration must not be writable by group or others")
    }
    if let Some(parent) = path.parent() {
        let parent_metadata = std::fs::metadata(parent)
            .with_context(|| format!("inspect configuration directory {}", parent.display()))?;
        if parent_metadata.uid() != 0 || parent_metadata.mode() & 0o022 != 0 {
            bail!("configuration directory must be root-owned and not group/world writable")
        }
    }
    Ok(())
}

