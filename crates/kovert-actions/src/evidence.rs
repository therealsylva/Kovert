use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use kovert_core::event::Event;
use serde::Serialize;

#[derive(Serialize)]
struct EvidenceBundle<'a> {
    captured_at: chrono::DateTime<Utc>,
    event: &'a Event,
    files: Vec<FileMetadata>,
}

#[derive(Serialize)]
struct FileMetadata {
    path: PathBuf,
    exists: bool,
    file_type: Option<String>,
    length: Option<u64>,
    readonly: Option<bool>,
    modified: Option<String>,
}

/// Capture metadata only. File contents are intentionally never copied.
pub fn capture_metadata(paths: &[PathBuf], destination: &Path, event: &Event) -> Result<PathBuf> {
    if !destination.is_absolute() || paths.iter().any(|path| !path.is_absolute()) {
        bail!("evidence paths must be absolute")
    }
    std::fs::create_dir_all(destination)
        .with_context(|| format!("create evidence directory {}", destination.display()))?;
    let files = paths.iter().map(metadata).collect();
    let bundle = EvidenceBundle {
        captured_at: Utc::now(),
        event,
        files,
    };
    let filename = format!("{}-{}.json", Utc::now().format("%Y%m%dT%H%M%S%.3fZ"), event.id);
    let output = destination.join(filename);
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&output)
        .with_context(|| format!("create evidence file {}", output.display()))?;
    serde_json::to_writer_pretty(file, &bundle).context("serialize evidence metadata")?;
    Ok(output)
}

fn metadata(path: &PathBuf) -> FileMetadata {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            let kind = if metadata.file_type().is_symlink() {
                "symlink"
            } else if metadata.is_dir() {
                "directory"
            } else if metadata.is_file() {
                "file"
            } else {
                "other"
            };
            FileMetadata {
                path: path.clone(),
                exists: true,
                file_type: Some(kind.to_owned()),
                length: Some(metadata.len()),
                readonly: Some(metadata.permissions().readonly()),
                modified: metadata
                    .modified()
                    .ok()
                    .map(|time| chrono::DateTime::<Utc>::from(time).to_rfc3339()),
            }
        }
        Err(_) => FileMetadata {
            path: path.clone(),
            exists: false,
            file_type: None,
            length: None,
            readonly: None,
            modified: None,
        },
    }
}

