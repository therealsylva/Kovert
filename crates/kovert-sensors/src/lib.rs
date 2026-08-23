//! Linux sensor providers that normalize host events for the Kovert engine.

mod filesystem;
mod hotkey;
mod polling;
mod requirements;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use kovert_core::config::Config;
use kovert_core::event::{Event, EventKind};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub use requirements::SensorRequirements;

/// Starts only the providers required by the active configuration.
pub struct SensorHub {
    config: Arc<Config>,
    config_path: PathBuf,
}

impl SensorHub {
    pub fn new(config: Arc<Config>, config_path: PathBuf) -> Self {
        Self {
            config,
            config_path,
        }
    }

    pub fn start(&self, sender: mpsc::Sender<Event>) -> Result<Vec<JoinHandle<()>>> {
        let requirements = SensorRequirements::from_config(&self.config);
        let mut handles = Vec::new();
        if !requirements.file_watches.is_empty() {
            handles.push(filesystem::spawn(
                requirements.file_watches.clone(),
                sender.clone(),
            )?);
        }
        for hotkey in &self.config.hotkeys {
            match hotkey::spawn(hotkey.clone(), sender.clone()) {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    let _ = sender.try_send(Event::new(
                        "hotkeys",
                        EventKind::SensorFailure {
                            sensor: "hotkeys".to_owned(),
                            message: error.to_string(),
                        },
                    ));
                }
            }
        }
        handles.push(polling::spawn(
            requirements,
            self.config.daemon.poll_interval,
            self.config_path.clone(),
            sender,
        )?);
        Ok(handles)
    }
}
