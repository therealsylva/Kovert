use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use kovert_core::ipc::{IPC_VERSION, RequestEnvelope, Response};
use nix::unistd::{Group, chown};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, mpsc, oneshot, watch};
use tokio::time::timeout;
use tracing::{info, warn};

use crate::runtime::ControlMessage;

const MAX_REQUEST_SIZE: u64 = 1024 * 1024;
const MAX_CLIENTS: usize = 64;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(20);

pub async fn serve(
    socket_path: &Path,
    socket_group: &str,
    allow_unsafe_dev: bool,
    control_sender: mpsc::Sender<ControlMessage>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    prepare_socket(socket_path, allow_unsafe_dev)?;
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind control socket {}", socket_path.display()))?;
    if allow_unsafe_dev {
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    } else {
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
        let group = Group::from_name(socket_group)
            .context("resolve socket group")?
            .ok_or_else(|| anyhow::anyhow!("socket group does not exist: {socket_group}"))?;
        chown(socket_path, None, Some(group.gid)).context("set control socket group")?;
    }
    info!(path = %socket_path.display(), group = socket_group, "control socket ready");
    let permits = Arc::new(Semaphore::new(MAX_CLIENTS));

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accept control client")?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    warn!("control client limit reached");
                    continue;
                };
                let sender = control_sender.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    match timeout(CLIENT_TIMEOUT, handle_connection(stream, sender)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => warn!(%error, "control client failed"),
                        Err(_) => warn!("control client timed out"),
                    }
                });
            }
        }
    }
    drop(listener);
    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

fn prepare_socket(path: &Path, allow_unsafe_dev: bool) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("control socket has no parent directory"))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create socket directory {}", parent.display()))?;
    if !allow_unsafe_dev {
        let metadata = std::fs::symlink_metadata(parent)
            .with_context(|| format!("inspect socket directory {}", parent.display()))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            bail!(
                "socket directory must be root-owned and not group/world writable: {}",
                parent.display()
            )
        }
    }
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            bail!("refusing to replace non-socket path: {}", path.display())
        }
        std::fs::remove_file(path).context("remove stale control socket")?;
    }
    Ok(())
}

async fn handle_connection(
    stream: UnixStream,
    control_sender: mpsc::Sender<ControlMessage>,
) -> Result<()> {
    let credentials = stream.peer_cred().context("read peer credentials")?;
    let peer_uid = credentials.uid();
    let (reader, mut writer) = stream.into_split();
    let mut input = Vec::new();
    BufReader::new(reader)
        .take(MAX_REQUEST_SIZE + 1)
        .read_to_end(&mut input)
        .await
        .context("read control request")?;
    if input.len() as u64 > MAX_REQUEST_SIZE {
        write_response(&mut writer, &Response::error("request exceeds 1 MiB")).await?;
        bail!("oversized request from uid {peer_uid}")
    }
    let envelope: RequestEnvelope =
        serde_json::from_slice(&input).context("parse control request")?;
    if envelope.version != IPC_VERSION {
        write_response(
            &mut writer,
            &Response::error(format!(
                "unsupported protocol version {}; daemon supports {IPC_VERSION}",
                envelope.version
            )),
        )
        .await?;
        return Ok(());
    }
    let (response_sender, response_receiver) = oneshot::channel();
    control_sender
        .send(ControlMessage {
            request: envelope.request,
            response: response_sender,
        })
        .await
        .context("runtime control channel closed")?;
    let response = response_receiver
        .await
        .context("runtime response dropped")?;
    write_response(&mut writer, &response).await?;
    info!(peer_uid, ok = response.ok, "served control request");
    Ok(())
}

async fn write_response(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    response: &Response,
) -> Result<()> {
    let mut bytes = serde_json::to_vec(response)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.shutdown().await?;
    Ok(())
}
