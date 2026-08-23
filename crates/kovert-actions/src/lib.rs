//! Typed, shell-free defensive actions and external vault adapters.

mod command;
mod evidence;
mod vault;

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use kovert_core::config::{
    ActionSpec, NotificationUrgency, ProcessSignal, ServiceAction, VaultConfig,
};
use kovert_core::event::Event;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::command::{CommandResult, run_command};
use crate::evidence::capture_metadata;
use crate::vault::{lock_vault, unlock_vault};

/// Maximum stdout or stderr retained from an approved process.
pub const OUTPUT_LIMIT: usize = 64 * 1024;

/// Runtime context shared by action executions.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub dry_run: bool,
    pub command_timeout: Duration,
    pub allowed_executables: HashSet<PathBuf>,
    pub managed_processes: HashSet<String>,
    pub vaults: Vec<VaultConfig>,
    pub desktop_notifications: bool,
}

/// State transition the daemon applies after a successful action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ActionEffect {
    None,
    SetMode { mode: String },
    NetworkIsolation { enabled: bool },
}

/// Auditable result of one action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionOutcome {
    pub success: bool,
    pub dry_run: bool,
    pub message: String,
    pub duration_ms: u128,
    pub effect: ActionEffect,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
    pub output_truncated: bool,
}

impl ActionOutcome {
    fn dry_run(message: impl Into<String>) -> Self {
        Self {
            success: true,
            dry_run: true,
            message: message.into(),
            duration_ms: 0,
            effect: ActionEffect::None,
            stdout: None,
            stderr: None,
            output_truncated: false,
        }
    }

    fn internal(message: impl Into<String>, effect: ActionEffect, started: Instant) -> Self {
        Self {
            success: true,
            dry_run: false,
            message: message.into(),
            duration_ms: started.elapsed().as_millis(),
            effect,
            stdout: None,
            stderr: None,
            output_truncated: false,
        }
    }

    fn command(message: impl Into<String>, result: CommandResult, started: Instant) -> Self {
        Self {
            success: result.success,
            dry_run: false,
            message: message.into(),
            duration_ms: started.elapsed().as_millis(),
            effect: ActionEffect::None,
            stdout: nonempty(result.stdout),
            stderr: nonempty(result.stderr),
            output_truncated: result.output_truncated,
        }
    }
}

fn nonempty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

/// Executes already-validated typed actions without invoking a shell.
pub struct ActionExecutor {
    context: ExecutionContext,
}

impl ActionExecutor {
    pub fn new(context: ExecutionContext) -> Self {
        Self { context }
    }

    pub fn context(&self) -> &ExecutionContext {
        &self.context
    }

    /// Execute one action. Failures are returned for the daemon to audit.
    pub async fn execute(&self, action: &ActionSpec, event: &Event) -> Result<ActionOutcome> {
        if self.context.dry_run {
            return Ok(ActionOutcome::dry_run(format!("would execute {action:?}")));
        }
        let started = Instant::now();
        match action {
            ActionSpec::LockVault { vault } => {
                let vault = self.vault(vault)?;
                let result = lock_vault(vault, self.context.command_timeout).await?;
                Ok(ActionOutcome::command(
                    format!("locked vault {}", vault.name),
                    result,
                    started,
                ))
            }
            ActionSpec::UnlockVault { vault } => {
                let vault = self.vault(vault)?;
                let result = unlock_vault(vault, self.context.command_timeout).await?;
                Ok(ActionOutcome::command(
                    format!("unlocked vault {}", vault.name),
                    result,
                    started,
                ))
            }
            ActionSpec::Unmount { path } => {
                ensure_absolute(path)?;
                let executable = command::resolve_tool("umount")?;
                let args = vec![path.as_os_str().to_owned()];
                let result =
                    run_command(&executable, &args, None, &[], self.context.command_timeout)
                        .await?;
                Ok(ActionOutcome::command(
                    format!("unmounted {}", path.display()),
                    result,
                    started,
                ))
            }
            ActionSpec::NetworkIsolation { enabled } => {
                let executable = command::resolve_tool("nmcli")?;
                let state = if *enabled { "off" } else { "on" };
                let args = vec!["networking".into(), state.into()];
                let result =
                    run_command(&executable, &args, None, &[], self.context.command_timeout)
                        .await?;
                let mut outcome = ActionOutcome::command(
                    if *enabled {
                        "isolated networking"
                    } else {
                        "restored networking"
                    },
                    result,
                    started,
                );
                if outcome.success {
                    outcome.effect = ActionEffect::NetworkIsolation { enabled: *enabled };
                }
                Ok(outcome)
            }
            ActionSpec::InterfaceState { interface, up } => {
                validate_interface(interface)?;
                let executable = command::resolve_tool("ip")?;
                let state = if *up { "up" } else { "down" };
                let args = vec![
                    "link".into(),
                    "set".into(),
                    "dev".into(),
                    interface.into(),
                    state.into(),
                ];
                let result =
                    run_command(&executable, &args, None, &[], self.context.command_timeout)
                        .await?;
                Ok(ActionOutcome::command(
                    format!("set interface {interface} {state}"),
                    result,
                    started,
                ))
            }
            ActionSpec::Service { name, state } => {
                validate_unit(name)?;
                let executable = command::resolve_tool("systemctl")?;
                let verb = match state {
                    ServiceAction::Start => "start",
                    ServiceAction::Stop => "stop",
                    ServiceAction::Restart => "restart",
                };
                let args = vec![verb.into(), name.into(), "--no-block".into()];
                let result =
                    run_command(&executable, &args, None, &[], self.context.command_timeout)
                        .await?;
                Ok(ActionOutcome::command(
                    format!("requested {verb} for {name}"),
                    result,
                    started,
                ))
            }
            ActionSpec::TerminateProcess { process, signal } => {
                if !self.context.managed_processes.contains(process) {
                    bail!("process {process} is not in the managed-process allowlist");
                }
                let count = terminate_named_processes(process, *signal)?;
                Ok(ActionOutcome::internal(
                    format!("signalled {count} instance(s) of {process}"),
                    ActionEffect::None,
                    started,
                ))
            }
            ActionSpec::Notify {
                title,
                message,
                urgency,
            } => {
                match urgency {
                    NotificationUrgency::Critical => warn!(%title, %message, "notification"),
                    NotificationUrgency::Low | NotificationUrgency::Normal => {
                        info!(%title, %message, "notification");
                    }
                }
                if !self.context.desktop_notifications {
                    return Ok(ActionOutcome::internal(
                        "notification recorded in the local journal",
                        ActionEffect::None,
                        started,
                    ));
                }
                let executable = command::resolve_tool("notify-send")?;
                let urgency = match urgency {
                    NotificationUrgency::Low => "low",
                    NotificationUrgency::Normal => "normal",
                    NotificationUrgency::Critical => "critical",
                };
                let args = vec![
                    "--app-name=Kovert".into(),
                    format!("--urgency={urgency}").into(),
                    title.into(),
                    message.into(),
                ];
                let result =
                    run_command(&executable, &args, None, &[], self.context.command_timeout)
                        .await?;
                Ok(ActionOutcome::command(
                    "sent local notification",
                    result,
                    started,
                ))
            }
            ActionSpec::CaptureEvidence { paths, destination } => {
                let output = capture_metadata(paths, destination, event)?;
                Ok(ActionOutcome::internal(
                    format!("captured metadata at {}", output.display()),
                    ActionEffect::None,
                    started,
                ))
            }
            ActionSpec::SetMode { mode } => Ok(ActionOutcome::internal(
                format!("set security mode to {mode}"),
                ActionEffect::SetMode { mode: mode.clone() },
                started,
            )),
            ActionSpec::Exec {
                executable,
                args,
                expected_sha256,
                environment,
            } => {
                if !self.context.allowed_executables.contains(executable) {
                    bail!(
                        "executable {} is not in the approved allowlist",
                        executable.display()
                    );
                }
                verify_executable_security(executable)?;
                if let Some(expected) = expected_sha256 {
                    verify_sha256(executable, expected)?;
                }
                let args: Vec<_> = args.iter().map(Into::into).collect();
                let environment: Vec<_> = environment
                    .iter()
                    .map(|(key, value)| (key.clone().into(), value.clone().into()))
                    .collect();
                let result = run_command(
                    executable,
                    &args,
                    None,
                    &environment,
                    self.context.command_timeout,
                )
                .await?;
                Ok(ActionOutcome::command(
                    format!("executed {}", executable.display()),
                    result,
                    started,
                ))
            }
        }
    }

    fn vault(&self, name: &str) -> Result<&VaultConfig> {
        self.context
            .vaults
            .iter()
            .find(|vault| vault.name == name)
            .ok_or_else(|| anyhow!("unknown vault {name}"))
    }
}

fn ensure_absolute(path: &Path) -> Result<()> {
    if path.is_absolute() {
        Ok(())
    } else {
        bail!("privileged path must be absolute: {}", path.display())
    }
}

fn validate_interface(value: &str) -> Result<()> {
    if !value.is_empty()
        && value.len() <= 15
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':'))
    {
        Ok(())
    } else {
        bail!("invalid network interface name")
    }
}

fn validate_unit(value: &str) -> Result<()> {
    if !value.is_empty()
        && value.len() <= 255
        && !value.contains('/')
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '@'))
    {
        Ok(())
    } else {
        bail!("invalid systemd unit name")
    }
}

fn terminate_named_processes(name: &str, signal: ProcessSignal) -> Result<usize> {
    let own_pid = std::process::id();
    let signal = match signal {
        ProcessSignal::Term => Signal::SIGTERM,
        ProcessSignal::Kill => Signal::SIGKILL,
        ProcessSignal::Hup => Signal::SIGHUP,
        ProcessSignal::Int => Signal::SIGINT,
    };
    let mut count = 0;
    for entry in std::fs::read_dir("/proc").context("read /proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        if pid <= 1 || pid == own_pid {
            continue;
        }
        let comm = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
        if comm.trim() != name {
            continue;
        }
        kill(Pid::from_raw(pid as i32), signal).with_context(|| format!("signal process {pid}"))?;
        count += 1;
    }
    Ok(count)
}

fn verify_sha256(path: &Path, expected: &str) -> Result<()> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("read {}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let actual = hex::encode(hasher.finalize());
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        bail!("executable digest mismatch for {}", path.display())
    }
}

fn verify_executable_security(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect executable {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!(
            "approved executable must be a regular file: {}",
            path.display()
        )
    }
    if metadata.uid() != 0 {
        bail!(
            "approved executable must be owned by root: {}",
            path.display()
        )
    }
    if metadata.mode() & 0o022 != 0 {
        bail!(
            "approved executable cannot be group- or world-writable: {}",
            path.display()
        )
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dry_run_never_executes() {
        let executor = ActionExecutor::new(ExecutionContext {
            dry_run: true,
            command_timeout: Duration::from_secs(1),
            allowed_executables: HashSet::new(),
            managed_processes: HashSet::new(),
            vaults: Vec::new(),
            desktop_notifications: false,
        });
        let event = Event::new("test", kovert_core::event::EventKind::Tick);
        let outcome = executor
            .execute(
                &ActionSpec::Exec {
                    executable: PathBuf::from("/does/not/exist"),
                    args: Vec::new(),
                    expected_sha256: None,
                    environment: Default::default(),
                },
                &event,
            )
            .await
            .unwrap_or_else(|error| panic!("dry-run failed: {error}"));
        assert!(outcome.dry_run);
        assert!(outcome.success);
    }
}
