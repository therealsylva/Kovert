use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{DeviceAction, FileOperation, NetworkProtocol, SessionState};

/// One normalized event produced by a sensor or the local control socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub kind: EventKind,
}

impl Event {
    /// Construct an event with a fresh identifier and the current UTC timestamp.
    pub fn new(source: impl Into<String>, kind: EventKind) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source: source.into(),
            kind,
        }
    }
}

/// Normalized event payloads understood by the policy engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventKind {
    Tick,
    File {
        path: PathBuf,
        operation: FileOperation,
    },
    Wifi {
        connected: bool,
        ssid: Option<String>,
        bssid: Option<String>,
    },
    Network {
        online: bool,
        interface: Option<String>,
        vpn: bool,
    },
    Usb {
        action: DeviceAction,
        vendor_id: Option<String>,
        product_id: Option<String>,
        serial: Option<String>,
    },
    Mount {
        action: DeviceAction,
        path: PathBuf,
        source: Option<String>,
    },
    Process {
        name: String,
        running: bool,
        pid: Option<u32>,
    },
    Service {
        name: String,
        active: bool,
    },
    Port {
        port: u16,
        protocol: NetworkProtocol,
        open: bool,
    },
    Session {
        state: SessionState,
        user: Option<String>,
        remote: bool,
    },
    Power {
        on_ac: Option<bool>,
        battery_percent: Option<u8>,
        lid_closed: Option<bool>,
    },
    Hotkey {
        name: String,
    },
    Integrity {
        component: String,
        valid: bool,
        detail: Option<String>,
    },
    Manual {
        name: String,
    },
    SensorFailure {
        sensor: String,
        message: String,
    },
}

/// Latest known host state used by policy conditions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub now: DateTime<Utc>,
    pub wifi_connected: bool,
    pub wifi_ssid: Option<String>,
    pub wifi_bssid: Option<String>,
    pub network_online: bool,
    pub active_interface: Option<String>,
    pub vpn_active: bool,
    pub mounts: BTreeSet<PathBuf>,
    pub processes: BTreeSet<String>,
    pub services: BTreeMap<String, bool>,
    pub ports: BTreeSet<(NetworkProtocol, u16)>,
    pub session_state: Option<SessionState>,
    pub session_user: Option<String>,
    pub session_remote: bool,
    pub on_ac: Option<bool>,
    pub battery_percent: Option<u8>,
    pub lid_closed: Option<bool>,
    pub mode: String,
    pub sensor_health: BTreeMap<String, bool>,
}

impl Default for SystemSnapshot {
    fn default() -> Self {
        Self {
            now: Utc::now(),
            wifi_connected: false,
            wifi_ssid: None,
            wifi_bssid: None,
            network_online: false,
            active_interface: None,
            vpn_active: false,
            mounts: BTreeSet::new(),
            processes: BTreeSet::new(),
            services: BTreeMap::new(),
            ports: BTreeSet::new(),
            session_state: None,
            session_user: None,
            session_remote: false,
            on_ac: None,
            battery_percent: None,
            lid_closed: None,
            mode: "normal".to_owned(),
            sensor_health: BTreeMap::new(),
        }
    }
}

impl SystemSnapshot {
    /// Apply a normalized event to the latest-known state.
    pub fn apply(&mut self, event: &Event) {
        self.now = event.timestamp;
        self.sensor_health.insert(event.source.clone(), true);
        match &event.kind {
            EventKind::Wifi {
                connected,
                ssid,
                bssid,
            } => {
                self.wifi_connected = *connected;
                self.wifi_ssid.clone_from(ssid);
                self.wifi_bssid.clone_from(bssid);
            }
            EventKind::Network {
                online,
                interface,
                vpn,
            } => {
                self.network_online = *online;
                self.active_interface.clone_from(interface);
                self.vpn_active = *vpn;
            }
            EventKind::Mount { action, path, .. } => match action {
                DeviceAction::Added | DeviceAction::Changed => {
                    self.mounts.insert(path.clone());
                }
                DeviceAction::Removed => {
                    self.mounts.remove(path);
                }
            },
            EventKind::Process { name, running, .. } => {
                if *running {
                    self.processes.insert(name.clone());
                } else {
                    self.processes.remove(name);
                }
            }
            EventKind::Service { name, active } => {
                self.services.insert(name.clone(), *active);
            }
            EventKind::Port {
                port,
                protocol,
                open,
            } => {
                if *open {
                    self.ports.insert((*protocol, *port));
                } else {
                    self.ports.remove(&(*protocol, *port));
                }
            }
            EventKind::Session {
                state,
                user,
                remote,
            } => {
                self.session_state = Some(*state);
                self.session_user.clone_from(user);
                self.session_remote = *remote;
            }
            EventKind::Power {
                on_ac,
                battery_percent,
                lid_closed,
            } => {
                self.on_ac = *on_ac;
                self.battery_percent = *battery_percent;
                self.lid_closed = *lid_closed;
            }
            EventKind::Integrity {
                component, valid, ..
            } => {
                self.sensor_health.insert(component.clone(), *valid);
            }
            EventKind::SensorFailure { sensor, .. } => {
                self.sensor_health.insert(sensor.clone(), false);
            }
            EventKind::Tick
            | EventKind::File { .. }
            | EventKind::Usb { .. }
            | EventKind::Hotkey { .. }
            | EventKind::Manual { .. } => {}
        }
    }
}

