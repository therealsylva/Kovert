use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use kovert_core::config::Config;
use kovert_core::event::Event;
use kovert_core::ipc::{Request, Response};
use kovert_core::validate_config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const MAX_RESPONSE_SIZE: u64 = 8 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "kovert", version, about = "Control and inspect the Kovert daemon")]
struct Arguments {
    /// Kovert control socket.
    #[arg(long, default_value = "/run/kovert/kovert.sock", global = true)]
    socket: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show daemon and sensor state.
    Status,
    /// List active rules.
    Rules,
    /// Read recent hash-chained audit records.
    Audit {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Validate a policy file without contacting the daemon.
    Validate {
        #[arg(default_value = "/etc/kovert/kovert.toml")]
        config: PathBuf,
    },
    /// Reload and revalidate the active configuration.
    Reload,
    /// Emit a configured manual event.
    Trigger { name: String },
    /// Evaluate an event without executing its actions.
    Simulate {
        /// JSON event file, or '-' for standard input.
        event: PathBuf,
    },
    /// Change the current security mode.
    Mode { name: String },
    /// Suspend or resume automatic policy execution.
    Recovery {
        #[command(subcommand)]
        state: RecoveryState,
    },
    /// Verify the local audit hash chain.
    VerifyAudit,
    /// Start the interactive control shell.
    Repl,
}

#[derive(Debug, Subcommand)]
enum RecoveryState {
    On,
    Off,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("kovert: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let arguments = Arguments::parse();
    let command = arguments.command.unwrap_or(Command::Repl);
    match command {
        Command::Validate { config } => validate(&config, arguments.json),
        Command::Repl => repl(&arguments.socket, arguments.json).await,
        command => {
            let request = request_from_command(command)?;
            let response = send(&arguments.socket, &request).await?;
            print_response(&response, arguments.json)?;
            if response.ok {
                Ok(())
            } else {
                bail!(response.message)
            }
        }
    }
}

fn request_from_command(command: Command) -> Result<Request> {
    Ok(match command {
        Command::Status => Request::Status,
        Command::Rules => Request::Rules,
        Command::Audit { limit } => Request::Audit { limit },
        Command::Reload => Request::Reload,
        Command::Trigger { name } => Request::Trigger { name },
        Command::Simulate { event } => Request::Simulate {
            event: read_event(&event)?,
        },
        Command::Mode { name } => Request::SetMode { mode: name },
        Command::Recovery { state } => Request::Recovery {
            enabled: matches!(state, RecoveryState::On),
        },
        Command::VerifyAudit => Request::VerifyAudit,
        Command::Validate { .. } | Command::Repl => {
            return Err(anyhow!("command is handled locally"));
        }
    })
}

async fn send(socket: &Path, request: &Request) -> Result<Response> {
    let mut stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connect to {}", socket.display()))?;
    let bytes = serde_json::to_vec(request)?;
    stream.write_all(&bytes).await.context("write request")?;
    stream.shutdown().await.context("finish request")?;
    let mut response = Vec::new();
    stream
        .take(MAX_RESPONSE_SIZE + 1)
        .read_to_end(&mut response)
        .await
        .context("read response")?;
    if response.len() as u64 > MAX_RESPONSE_SIZE {
        bail!("daemon response exceeds 8 MiB")
    }
    serde_json::from_slice(&response).context("parse daemon response")
}

fn validate(path: &Path, json: bool) -> Result<()> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read configuration {}", path.display()))?;
    let config = Config::from_toml(&text)
        .with_context(|| format!("parse configuration {}", path.display()))?;
    match validate_config(&config) {
        Ok(()) => {
            if json {
                println!("{}", serde_json::json!({"ok": true, "rules": config.rules.len()}));
            } else {
                println!("valid configuration: {} rule(s)", config.rules.len());
            }
            Ok(())
        }
        Err(errors) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": false,
                        "errors": errors.iter().map(ToString::to_string).collect::<Vec<_>>()
                    })
                );
            }
            let message = errors
                .into_iter()
                .map(|error| format!("- {error}"))
                .collect::<Vec<_>>()
                .join("\n");
            bail!("configuration is invalid:\n{message}")
        }
    }
}

fn read_event(path: &Path) -> Result<Event> {
    let text = if path == Path::new("-") {
        let mut value = String::new();
        let mut stdin = io::stdin().lock();
        stdin.read_to_string(&mut value)?;
        value
    } else {
        std::fs::read_to_string(path)
            .with_context(|| format!("read event {}", path.display()))?
    };
    serde_json::from_str(&text).context("parse event JSON")
}

fn print_response(response: &Response, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(response)?);
    } else {
        println!("{}", response.message);
        if let Some(data) = &response.data {
            println!("{}", serde_json::to_string_pretty(data)?);
        }
    }
    Ok(())
}

async fn repl(socket: &Path, json: bool) -> Result<()> {
    println!("Kovert interactive shell. Type 'help' for commands; 'quit' to exit.");
    loop {
        print!("kovert> ");
        io::stdout().flush()?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line)? == 0 {
            break;
        }
        let words: Vec<_> = line.split_whitespace().collect();
        let Some(command) = words.first().copied() else {
            continue;
        };
        if matches!(command, "quit" | "exit") {
            break;
        }
        if command == "help" {
            println!(
                "status | rules | audit [limit] | reload | trigger <name> | mode <name> | recovery <on|off> | verify-audit | quit"
            );
            continue;
        }
        let request = match command {
            "status" => Request::Status,
            "rules" => Request::Rules,
            "audit" => Request::Audit {
                limit: words.get(1).and_then(|value| value.parse().ok()).unwrap_or(50),
            },
            "reload" => Request::Reload,
            "trigger" => Request::Trigger {
                name: required(&words, 1, "trigger name")?.to_owned(),
            },
            "mode" => Request::SetMode {
                mode: required(&words, 1, "mode name")?.to_owned(),
            },
            "recovery" => Request::Recovery {
                enabled: match required(&words, 1, "on or off")? {
                    "on" => true,
                    "off" => false,
                    _ => {
                        eprintln!("expected 'on' or 'off'");
                        continue;
                    }
                },
            },
            "verify-audit" => Request::VerifyAudit,
            _ => {
                eprintln!("unknown command: {command}");
                continue;
            }
        };
        match send(socket, &request).await {
            Ok(response) => {
                print_response(&response, json)?;
            }
            Err(error) => eprintln!("error: {error:#}"),
        }
    }
    Ok(())
}

fn required<'a>(words: &'a [&str], index: usize, name: &str) -> Result<&'a str> {
    words
        .get(index)
        .copied()
        .ok_or_else(|| anyhow!("missing {name}"))
}
