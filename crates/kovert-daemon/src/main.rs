mod audit;
mod config_loader;
mod runtime;
mod server;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use audit::AuditStore;
use clap::Parser;
use kovert_sensors::SensorHub;
use nix::unistd::Uid;
use runtime::Runtime;
use tokio::sync::{mpsc, watch};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "kovert-daemon", version, about = "Kovert host-security daemon")]
struct Arguments {
    /// Path to the root-owned policy file.
    #[arg(long, default_value = "/etc/kovert/kovert.toml")]
    config: PathBuf,
    /// Permit non-root execution and relaxed file permissions for local development.
    #[arg(long)]
    allow_unsafe_dev: bool,
    /// Emit structured JSON logs.
    #[arg(long)]
    json_logs: bool,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        error!(%error, "Kovert daemon failed");
        eprintln!("kovert-daemon: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let arguments = Arguments::parse();
    init_tracing(arguments.json_logs)?;
    if !arguments.allow_unsafe_dev && !Uid::effective().is_root() {
        bail!("kovert-daemon must run as root; use --allow-unsafe-dev only for development")
    }

    let config = Arc::new(config_loader::load(
        &arguments.config,
        arguments.allow_unsafe_dev,
    )?);
    let audit = Arc::new(AuditStore::open(
        &config.daemon.state_path,
        config.audit.max_records,
        arguments.allow_unsafe_dev,
    )?);
    if config.audit.verify_on_start {
        let verified = audit.verify().context("audit chain verification failed")?;
        info!(verified, "audit chain verified");
    }

    let (event_sender, event_receiver) = mpsc::channel(config.daemon.event_buffer);
    let (control_sender, control_receiver) = mpsc::channel(64);
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let sensor_handles = SensorHub::new(config.clone(), arguments.config.clone())
        .start(event_sender.clone())
        .context("start sensors")?;

    let runtime = Runtime::new(
        arguments.config.clone(),
        arguments.allow_unsafe_dev,
        config.clone(),
        audit,
        event_sender,
        event_receiver,
        control_receiver,
        sensor_handles,
    )?;
    let mut runtime_task = tokio::spawn(runtime.run(shutdown_receiver.clone()));
    let mut server_task = tokio::spawn(server::serve(
        &config.daemon.socket_path,
        &config.daemon.socket_group,
        arguments.allow_unsafe_dev,
        control_sender,
        shutdown_receiver,
    ));

    tokio::select! {
        signal = wait_for_shutdown() => signal?,
        result = &mut runtime_task => {
            let _ = shutdown_sender.send(true);
            server_task.abort();
            return result.context("join runtime")?;
        }
        result = &mut server_task => {
            let _ = shutdown_sender.send(true);
            runtime_task.abort();
            return result.context("join control server")?;
        }
    }
    let _ = shutdown_sender.send(true);
    runtime_task.await.context("join runtime")??;
    server_task.await.context("join control server")??;
    Ok(())
}

async fn wait_for_shutdown() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("install SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("wait for Ctrl-C")?,
            _ = terminate.recv() => {},
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.context("wait for Ctrl-C")
    }
}

fn init_tracing(json: bool) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if json {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .try_init()
            .context("initialize tracing")?;
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .try_init()
            .context("initialize tracing")?;
    }
    Ok(())
}
