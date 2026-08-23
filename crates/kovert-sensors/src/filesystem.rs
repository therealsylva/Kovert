use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use kovert_core::config::FileOperation;
use kovert_core::event::{Event, EventKind};
use notify::event::ModifyKind;
use notify::{Config, EventKind as NotifyKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub fn spawn(
    paths: BTreeMap<PathBuf, bool>,
    sender: mpsc::Sender<Event>,
) -> Result<JoinHandle<()>> {
    let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
    let (stop_sender, stop_receiver) = std::sync::mpsc::channel();
    let thread = std::thread::Builder::new()
        .name("kovert-filesystem".to_owned())
        .spawn(move || {
            let event_sender = sender.clone();
            let watcher = RecommendedWatcher::new(
                move |result: notify::Result<notify::Event>| match result {
                    Ok(event) => {
                        let operation = map_operation(&event.kind);
                        for path in event.paths {
                            if event_sender
                                .blocking_send(Event::new(
                                    "filesystem",
                                    EventKind::File { path, operation },
                                ))
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        let _ = event_sender.blocking_send(Event::new(
                            "filesystem",
                            EventKind::SensorFailure {
                                sensor: "filesystem".to_owned(),
                                message: error.to_string(),
                            },
                        ));
                    }
                },
                Config::default(),
            );
            let mut watcher = match watcher {
                Ok(watcher) => watcher,
                Err(error) => {
                    let _ = ready_sender.send(Err(error.to_string()));
                    return;
                }
            };
            for (path, recursive) in paths {
                let mode = if recursive {
                    RecursiveMode::Recursive
                } else {
                    RecursiveMode::NonRecursive
                };
                if let Err(error) = watcher.watch(&path, mode) {
                    let _ = ready_sender.send(Err(format!("watch {}: {error}", path.display())));
                    return;
                }
            }
            let _ = ready_sender.send(Ok(()));
            let _ = stop_receiver.recv();
        })
        .context("spawn filesystem sensor")?;
    ready_receiver
        .recv()
        .context("filesystem sensor startup")?
        .map_err(anyhow::Error::msg)?;
    Ok(tokio::spawn(async move {
        let _thread = thread;
        let _stop_sender = stop_sender;
        std::future::pending::<()>().await;
    }))
}

fn map_operation(kind: &NotifyKind) -> FileOperation {
    match kind {
        NotifyKind::Create(_) => FileOperation::Create,
        NotifyKind::Remove(_) => FileOperation::Delete,
        NotifyKind::Modify(ModifyKind::Name(_)) => FileOperation::Rename,
        NotifyKind::Modify(ModifyKind::Metadata(_)) => FileOperation::Metadata,
        NotifyKind::Modify(_) => FileOperation::Modify,
        NotifyKind::Access(_) => FileOperation::Access,
        _ => FileOperation::Other,
    }
}
