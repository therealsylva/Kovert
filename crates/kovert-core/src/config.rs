use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

fn default_poll_interval() -> Duration {
    Duration::from_secs(5)
}

fn default_command_timeout() -> Duration {
    Duration::from_secs(15)
}

fn default_event_buffer() -> usize {
    1_024
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/kovert/kovert.sock")
}

fn default_state_path() -> PathBuf {
    PathBuf::from("/var/lib/kovert/state.db")
}

fn default_audit_limit() -> usize {
    10_000
}

/// Complete Kovert configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub modes: Vec<ModeConfig>,
    #[serde(default)]
    pub vaults: Vec<VaultConfig>,
    #[serde(default)]
    pub hotkeys: Vec<HotkeyConfig>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl Config {
    /// Parse a TOML configuration document.
    pub fn from_toml(input: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(input)
    }
}

/// Daemon runtime and privilege-boundary settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub state_path: PathBuf,
    pub dry_run: bool,
    #[serde(with = "humantime_serde")]
    pub poll_interval: Duration,
    #[serde(with = "humantime_serde")]
    pub command_timeout: Duration,
    pub event_buffer: usize,
    pub socket_group: String,
    pub allowed_executables: Vec<PathBuf>,
    pub managed_processes: Vec<String>,
    pub desktop_notifications: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            state_path: default_state_path(),
            dry_run: true,
            poll_interval: default_poll_interval(),
            command_timeout: default_command_timeout(),
            event_buffer: default_event_buffer(),
            socket_group: "kovert".to_owned(),
            allowed_executables: Vec::new(),
            managed_processes: Vec::new(),
            desktop_notifications: false,
        }
    }
}

/// Audit retention settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    pub max_records: usize,
    pub verify_on_start: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            max_records: default_audit_limit(),
            verify_on_start: true,
        }
    }
}

/// A named security mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModeConfig {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub initial: bool,
}

/// Adapter-backed encrypted vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    pub name: String,
    pub adapter: VaultAdapter,
    pub path: PathBuf,
    pub encrypted_path: Option<PathBuf>,
    pub mount_path: Option<PathBuf>,
    pub keyring_description: Option<String>,
}

/// Supported external vault implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultAdapter {
    Fscrypt,
    Gocryptfs,
}

/// One configured emergency input sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotkeyConfig {
    pub name: String,
    pub device: PathBuf,
    pub sequence: Vec<String>,
    #[serde(default = "default_hotkey_window", with = "humantime_serde")]
    pub within: Duration,
}

fn default_hotkey_window() -> Duration {
    Duration::from_secs(3)
}

/// A policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
    #[serde(default, with = "humantime_serde")]
    pub cooldown: Duration,
    #[serde(default, with = "humantime_serde")]
    pub sustain_for: Duration,
    #[serde(default)]
    pub once_per_boot: bool,
    #[serde(default)]
    pub on_sensor_failure: SensorFailurePolicy,
    pub trigger: TriggerSpec,
    #[serde(default)]
    pub when: Option<ConditionSpec>,
    pub actions: Vec<ActionSpec>,
}

/// Behaviour when a required sensor becomes unavailable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorFailurePolicy {
    #[default]
    Alert,
    Ignore,
    FailClosed,
}

/// Event matcher. Composite forms are evaluated without executing code.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TriggerSpec {
    Tick,
    File {
        path: PathBuf,
        #[serde(default)]
        operations: Vec<FileOperation>,
        #[serde(default)]
        recursive: bool,
    },
    WifiChanged {
        ssid: Option<String>,
        bssid: Option<String>,
        connected: Option<bool>,
    },
    NetworkChanged {
        interface: Option<String>,
        online: Option<bool>,
        vpn: Option<bool>,
    },
    Usb {
        action: Option<DeviceAction>,
        vendor_id: Option<String>,
        product_id: Option<String>,
        serial: Option<String>,
    },
    Mount {
        action: Option<DeviceAction>,
        path: Option<PathBuf>,
    },
    Process {
        name: Option<String>,
        running: Option<bool>,
    },
    Service {
        name: Option<String>,
        active: Option<bool>,
    },
    Port {
        port: Option<u16>,
        open: Option<bool>,
        protocol: Option<NetworkProtocol>,
    },
    Session {
        state: Option<SessionState>,
        user: Option<String>,
        remote: Option<bool>,
    },
    Power {
        on_ac: Option<bool>,
        battery_below: Option<u8>,
        lid_closed: Option<bool>,
    },
    Hotkey {
        name: String,
    },
    IntegrityFailure {
        component: Option<String>,
    },
    Manual {
        name: String,
    },
    SensorFailure {
        sensor: Option<String>,
    },
    All {
        triggers: Vec<TriggerSpec>,
    },
    Any {
        triggers: Vec<TriggerSpec>,
    },
    Not {
        trigger: Box<TriggerSpec>,
    },
    Sequence {
        steps: Vec<TriggerSpec>,
        #[serde(with = "humantime_serde")]
        within: Duration,
    },
}

/// Persistent-state predicate evaluated after an event is received.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConditionSpec {
    All {
        conditions: Vec<ConditionSpec>,
    },
    Any {
        conditions: Vec<ConditionSpec>,
    },
    Not {
        condition: Box<ConditionSpec>,
    },
    TimeWindow {
        start: String,
        end: String,
        #[serde(default)]
        outside: bool,
        #[serde(default)]
        weekdays: Vec<Weekday>,
    },
    Wifi {
        ssid: Option<String>,
        bssid: Option<String>,
        connected: Option<bool>,
    },
    Network {
        online: Option<bool>,
        interface: Option<String>,
        vpn: Option<bool>,
    },
    Mode {
        name: String,
    },
    PathExists {
        path: PathBuf,
        exists: bool,
    },
    Mounted {
        path: PathBuf,
        mounted: bool,
    },
    Process {
        name: String,
        running: bool,
    },
    Service {
        name: String,
        active: bool,
    },
    Port {
        port: u16,
        open: bool,
        #[serde(default)]
        protocol: NetworkProtocol,
    },
    Session {
        state: Option<SessionState>,
        user: Option<String>,
        remote: Option<bool>,
    },
    Power {
        on_ac: Option<bool>,
        battery_below: Option<u8>,
        lid_closed: Option<bool>,
    },
    SensorHealthy {
        sensor: String,
        healthy: bool,
    },
}

/// Operation observed by the file sensor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOperation {
    Create,
    Modify,
    Rename,
    Delete,
    Access,
    Metadata,
    Other,
}

/// Add/remove state for devices and mounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceAction {
    Added,
    Removed,
    Changed,
}

/// Network transport used by port policies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProtocol {
    #[default]
    Tcp,
    Udp,
}

/// Session state exposed by the session sensor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    LoggedIn,
    LoggedOut,
    Locked,
    Unlocked,
}

/// Weekday used by time-window conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Weekday {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

/// Typed defensive operation. Shell strings are intentionally unsupported.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionSpec {
    LockVault {
        vault: String,
    },
    UnlockVault {
        vault: String,
    },
    Unmount {
        path: PathBuf,
    },
    NetworkIsolation {
        enabled: bool,
    },
    InterfaceState {
        interface: String,
        up: bool,
    },
    Service {
        name: String,
        state: ServiceAction,
    },
    TerminateProcess {
        process: String,
        #[serde(default)]
        signal: ProcessSignal,
    },
    Notify {
        title: String,
        message: String,
        #[serde(default)]
        urgency: NotificationUrgency,
    },
    CaptureEvidence {
        paths: Vec<PathBuf>,
        destination: PathBuf,
    },
    SetMode {
        mode: String,
    },
    Exec {
        executable: PathBuf,
        #[serde(default)]
        args: Vec<String>,
        expected_sha256: Option<String>,
        #[serde(default)]
        environment: BTreeMap<String, String>,
    },
}

impl ActionSpec {
    /// Key used to resolve mutually exclusive actions in one evaluation cycle.
    pub fn conflict_key(&self) -> Option<String> {
        match self {
            Self::LockVault { vault } | Self::UnlockVault { vault } => {
                Some(format!("vault:{vault}"))
            }
            Self::NetworkIsolation { .. } => Some("network:isolation".to_owned()),
            Self::InterfaceState { interface, .. } => Some(format!("interface:{interface}")),
            Self::Service { name, .. } => Some(format!("service:{name}")),
            Self::SetMode { .. } => Some("mode".to_owned()),
            Self::Unmount { path } => Some(format!("mount:{}", path.display())),
            Self::TerminateProcess { process, .. } => Some(format!("process:{process}")),
            Self::Notify { .. } | Self::CaptureEvidence { .. } | Self::Exec { .. } => None,
        }
    }
}

/// Requested systemd service transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
}

/// Signal used by the managed-process action.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessSignal {
    #[default]
    Term,
    Kill,
    Hup,
    Int,
}

/// Desktop-notification severity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationUrgency {
    Low,
    #[default]
    Normal,
    Critical,
}
