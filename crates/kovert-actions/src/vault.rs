use std::ffi::OsString;
use std::time::Duration;

use crate::command::{CommandResult, read_command_bytes, resolve_tool, run_command};
use anyhow::{Context, Result, bail};
use kovert_core::config::{VaultAdapter, VaultConfig};

pub async fn lock_vault(vault: &VaultConfig, timeout: Duration) -> Result<CommandResult> {
    match vault.adapter {
        VaultAdapter::Fscrypt => {
            let executable = resolve_tool("fscrypt")?;
            let args = vec!["lock".into(), vault.path.as_os_str().to_owned()];
            run_command(&executable, &args, None, &[], timeout).await
        }
        VaultAdapter::Gocryptfs => {
            let mount_path = vault
                .mount_path
                .as_ref()
                .context("gocryptfs vault has no mount_path")?;
            let executable = resolve_tool("fusermount3").or_else(|_| resolve_tool("fusermount"))?;
            let args = vec!["-u".into(), mount_path.as_os_str().to_owned()];
            run_command(&executable, &args, None, &[], timeout).await
        }
    }
}

pub async fn unlock_vault(vault: &VaultConfig, timeout: Duration) -> Result<CommandResult> {
    let description = vault
        .keyring_description
        .as_deref()
        .context("automatic unlock requires keyring_description")?;
    let key = read_keyring(description, timeout).await?;
    match vault.adapter {
        VaultAdapter::Fscrypt => {
            let executable = resolve_tool("fscrypt")?;
            let args = vec!["unlock".into(), vault.path.as_os_str().to_owned()];
            run_command(&executable, &args, Some(key), &[], timeout).await
        }
        VaultAdapter::Gocryptfs => {
            let encrypted_path = vault
                .encrypted_path
                .as_ref()
                .context("gocryptfs vault has no encrypted_path")?;
            let mount_path = vault
                .mount_path
                .as_ref()
                .context("gocryptfs vault has no mount_path")?;
            let executable = resolve_tool("gocryptfs")?;
            let args = vec![
                "-quiet".into(),
                "-passfile".into(),
                "/dev/stdin".into(),
                encrypted_path.as_os_str().to_owned(),
                mount_path.as_os_str().to_owned(),
            ];
            run_command(&executable, &args, Some(key), &[], timeout).await
        }
    }
}

async fn read_keyring(description: &str, timeout: Duration) -> Result<Vec<u8>> {
    if description.is_empty()
        || description.len() > 128
        || description.chars().any(char::is_control)
    {
        bail!("invalid kernel-keyring description")
    }
    let keyctl = resolve_tool("keyctl")?;
    let search_args = vec![
        OsString::from("search"),
        OsString::from("@u"),
        OsString::from("user"),
        OsString::from(description),
    ];
    let search = run_command(&keyctl, &search_args, None, &[], timeout).await?;
    if !search.success {
        bail!("kernel-keyring lookup failed: {}", search.stderr)
    }
    let serial = search.stdout.trim();
    if serial.is_empty() || !serial.chars().all(|character| character.is_ascii_digit()) {
        bail!("kernel-keyring lookup returned an invalid serial")
    }
    let pipe_args = vec![OsString::from("pipe"), OsString::from(serial)];
    let key = read_command_bytes(&keyctl, &pipe_args, timeout)
        .await
        .context("read kernel key")?;
    if key.is_empty() {
        bail!("kernel-keyring key is empty")
    }
    Ok(key)
}
