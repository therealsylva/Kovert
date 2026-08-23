use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::time::timeout;
use zeroize::Zeroize;

use crate::OUTPUT_LIMIT;

#[derive(Debug)]
pub struct CommandResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub output_truncated: bool,
}

struct RawCommandResult {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    output_truncated: bool,
}

/// Resolve a fixed system utility without consulting an inherited PATH.
pub fn resolve_tool(name: &str) -> Result<PathBuf> {
    if name.contains('/') || name.contains('\0') {
        bail!("invalid tool name")
    }
    for directory in ["/usr/bin", "/usr/sbin", "/bin", "/sbin"] {
        let candidate = Path::new(directory).join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!("required adapter tool is unavailable: {name}")
}

pub async fn run_command(
    executable: &Path,
    args: &[OsString],
    secret_stdin: Option<Vec<u8>>,
    environment: &[(OsString, OsString)],
    command_timeout: Duration,
) -> Result<CommandResult> {
    let raw = run_raw_command(executable, args, secret_stdin, environment, command_timeout).await?;
    Ok(CommandResult {
        success: raw.success,
        stdout: String::from_utf8_lossy(&raw.stdout).trim().to_owned(),
        stderr: String::from_utf8_lossy(&raw.stderr).trim().to_owned(),
        output_truncated: raw.output_truncated,
    })
}

/// Read binary command output without a lossy UTF-8 conversion. This is used
/// only for key material returned by a trusted adapter.
pub async fn read_command_bytes(
    executable: &Path,
    args: &[OsString],
    command_timeout: Duration,
) -> Result<Vec<u8>> {
    let mut raw = run_raw_command(executable, args, None, &[], command_timeout).await?;
    if !raw.success {
        let message = String::from_utf8_lossy(&raw.stderr).trim().to_owned();
        raw.stdout.zeroize();
        raw.stderr.zeroize();
        bail!("command failed: {message}")
    }
    if raw.output_truncated {
        raw.stdout.zeroize();
        raw.stderr.zeroize();
        bail!("command output exceeded the security limit")
    }
    raw.stderr.zeroize();
    Ok(raw.stdout)
}

async fn run_raw_command(
    executable: &Path,
    args: &[OsString],
    secret_stdin: Option<Vec<u8>>,
    environment: &[(OsString, OsString)],
    command_timeout: Duration,
) -> Result<RawCommandResult> {
    if !executable.is_absolute() {
        bail!("executable path must be absolute")
    }
    let mut command = Command::new(executable);
    command
        .args(args)
        .env_clear()
        .envs(environment.iter().cloned())
        .stdin(if secret_stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .with_context(|| format!("spawn {}", executable.display()))?;

    if let Some(mut secret) = secret_stdin {
        let mut stdin = child.stdin.take().context("adapter stdin unavailable")?;
        let write_result = async {
            stdin
                .write_all(&secret)
                .await
                .context("write adapter key")?;
            stdin.write_all(b"\n").await.context("finish adapter key")?;
            stdin.shutdown().await.context("close adapter stdin")
        }
        .await;
        secret.zeroize();
        write_result?;
    }

    let stdout = child.stdout.take().context("command stdout unavailable")?;
    let stderr = child.stderr.take().context("command stderr unavailable")?;
    let stdout_task = tokio::spawn(read_limited(stdout));
    let stderr_task = tokio::spawn(read_limited(stderr));

    let status = match timeout(command_timeout, child.wait()).await {
        Ok(status) => status.context("wait for adapter")?,
        Err(_) => {
            child.kill().await.context("kill timed-out adapter")?;
            bail!(
                "command timed out after {} seconds: {}",
                command_timeout.as_secs(),
                executable.display()
            )
        }
    };
    let (stdout, stdout_truncated) = stdout_task.await.context("join stdout reader")??;
    let (stderr, stderr_truncated) = stderr_task.await.context("join stderr reader")??;
    Ok(RawCommandResult {
        success: status.success(),
        stdout,
        stderr,
        output_truncated: stdout_truncated || stderr_truncated,
    })
}

async fn read_limited(reader: impl AsyncRead + Unpin) -> Result<(Vec<u8>, bool)> {
    let mut bytes = Vec::new();
    reader
        .take((OUTPUT_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .context("read command output")?;
    let truncated = bytes.len() > OUTPUT_LIMIT;
    bytes.truncate(OUTPUT_LIMIT);
    Ok((bytes, truncated))
}
