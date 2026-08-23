use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use kovert_core::config::{DeviceAction, NetworkProtocol, SessionState};
use kovert_core::event::{Event, EventKind};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::requirements::SensorRequirements;

#[derive(Debug, Clone, PartialEq, Eq)]
struct WifiState {
    connected: bool,
    ssid: Option<String>,
    bssid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkState {
    online: bool,
    interface: Option<String>,
    vpn: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct UsbDevice {
    vendor_id: Option<String>,
    product_id: Option<String>,
    serial: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionInfo {
    state: SessionState,
    user: Option<String>,
    remote: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PowerState {
    on_ac: Option<bool>,
    battery_percent: Option<u8>,
    lid_closed: Option<bool>,
}

#[derive(Default)]
struct PollState {
    initialized: bool,
    wifi: Option<WifiState>,
    network: Option<NetworkState>,
    usb: BTreeSet<UsbDevice>,
    mounts: BTreeMap<PathBuf, Option<String>>,
    processes: BTreeMap<String, bool>,
    services: BTreeMap<String, bool>,
    ports: BTreeSet<(NetworkProtocol, u16)>,
    session: Option<SessionInfo>,
    power: Option<PowerState>,
    config_hash: Option<blake3::Hash>,
    binary_hash: Option<blake3::Hash>,
    failed: BTreeSet<String>,
}

pub fn spawn(
    requirements: SensorRequirements,
    interval: Duration,
    config_path: PathBuf,
    sender: mpsc::Sender<Event>,
) -> Result<JoinHandle<()>> {
    let executable = std::env::current_exe().context("resolve current executable")?;
    Ok(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut state = PollState::default();
        loop {
            ticker.tick().await;
            if sender
                .send(Event::new("time", EventKind::Tick))
                .await
                .is_err()
            {
                return;
            }
            let requirements = requirements.clone();
            let config_path = config_path.clone();
            let executable = executable.clone();
            let result = tokio::task::spawn_blocking(move || {
                let mut state = state;
                let events = poll_cycle(&requirements, &config_path, &executable, &mut state);
                (state, events)
            })
            .await;
            match result {
                Ok((next_state, events)) => {
                    state = next_state;
                    for event in events {
                        if sender.send(event).await.is_err() {
                            return;
                        }
                    }
                }
                Err(error) => {
                    if sender
                        .send(Event::new(
                            "polling",
                            EventKind::SensorFailure {
                                sensor: "polling".to_owned(),
                                message: error.to_string(),
                            },
                        ))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    state = PollState::default();
                }
            }
        }
    }))
}

fn poll_cycle(
    requirements: &SensorRequirements,
    config_path: &Path,
    executable: &Path,
    state: &mut PollState,
) -> Vec<Event> {
    let mut events = Vec::new();
    let first = !state.initialized;
    if requirements.wifi {
        if let Some(value) = probe_value("wifi", probe_wifi(), state, &mut events) {
            if first || state.wifi.as_ref() != Some(&value) {
                events.push(Event::new(
                    "wifi",
                    EventKind::Wifi {
                        connected: value.connected,
                        ssid: value.ssid.clone(),
                        bssid: value.bssid.clone(),
                    },
                ));
            }
            state.wifi = Some(value);
        }
    }
    if requirements.network {
        if let Some(value) = probe_value("network", probe_network(), state, &mut events) {
            if first || state.network.as_ref() != Some(&value) {
                events.push(Event::new(
                    "network",
                    EventKind::Network {
                        online: value.online,
                        interface: value.interface.clone(),
                        vpn: value.vpn,
                    },
                ));
            }
            state.network = Some(value);
        }
    }
    if requirements.usb {
        if let Some(value) = probe_value("usb", probe_usb(), state, &mut events) {
            if first {
                for device in &value {
                    events.push(usb_event(DeviceAction::Added, device));
                }
            } else {
                for device in value.difference(&state.usb) {
                    events.push(usb_event(DeviceAction::Added, device));
                }
                for device in state.usb.difference(&value) {
                    events.push(usb_event(DeviceAction::Removed, device));
                }
            }
            state.usb = value;
        }
    }
    if requirements.mounts {
        if let Some(value) = probe_value("mounts", probe_mounts(), state, &mut events) {
            if first {
                for (path, source) in &value {
                    events.push(Event::new(
                        "mounts",
                        EventKind::Mount {
                            action: DeviceAction::Added,
                            path: path.clone(),
                            source: source.clone(),
                        },
                    ));
                }
            } else {
                for (path, source) in value
                    .iter()
                    .filter(|(path, _)| !state.mounts.contains_key(*path))
                {
                    events.push(Event::new(
                        "mounts",
                        EventKind::Mount {
                            action: DeviceAction::Added,
                            path: path.clone(),
                            source: source.clone(),
                        },
                    ));
                }
                for (path, source) in state
                    .mounts
                    .iter()
                    .filter(|(path, _)| !value.contains_key(*path))
                {
                    events.push(Event::new(
                        "mounts",
                        EventKind::Mount {
                            action: DeviceAction::Removed,
                            path: path.clone(),
                            source: source.clone(),
                        },
                    ));
                }
            }
            state.mounts = value;
        }
    }
    if !requirements.processes.is_empty() {
        if let Some(value) = probe_value(
            "processes",
            probe_processes(&requirements.processes),
            state,
            &mut events,
        ) {
            for (name, running) in &value {
                if first || state.processes.get(name) != Some(running) {
                    events.push(Event::new(
                        "processes",
                        EventKind::Process {
                            name: name.clone(),
                            running: *running,
                            pid: None,
                        },
                    ));
                }
            }
            state.processes = value;
        }
    }
    if !requirements.services.is_empty() {
        if let Some(value) = probe_value(
            "services",
            probe_services(&requirements.services),
            state,
            &mut events,
        ) {
            for (name, active) in &value {
                if first || state.services.get(name) != Some(active) {
                    events.push(Event::new(
                        "services",
                        EventKind::Service {
                            name: name.clone(),
                            active: *active,
                        },
                    ));
                }
            }
            state.services = value;
        }
    }
    if !requirements.ports.is_empty() {
        if let Some(value) = probe_value(
            "ports",
            probe_ports(&requirements.ports),
            state,
            &mut events,
        ) {
            if first {
                for (protocol, port) in &requirements.ports {
                    events.push(Event::new(
                        "ports",
                        EventKind::Port {
                            port: *port,
                            protocol: *protocol,
                            open: value.contains(&(*protocol, *port)),
                        },
                    ));
                }
            } else {
                for item in value.symmetric_difference(&state.ports) {
                    events.push(Event::new(
                        "ports",
                        EventKind::Port {
                            port: item.1,
                            protocol: item.0,
                            open: value.contains(item),
                        },
                    ));
                }
            }
            state.ports = value;
        }
    }
    if requirements.sessions {
        if let Some(value) = probe_value("sessions", probe_session(), state, &mut events) {
            if first || state.session.as_ref() != Some(&value) {
                if value.state != SessionState::LoggedOut
                    && (first
                        || state
                            .session
                            .as_ref()
                            .is_some_and(|previous| previous.state == SessionState::LoggedOut))
                {
                    events.push(Event::new(
                        "sessions",
                        EventKind::Session {
                            state: SessionState::LoggedIn,
                            user: value.user.clone(),
                            remote: value.remote,
                        },
                    ));
                }
                events.push(Event::new(
                    "sessions",
                    EventKind::Session {
                        state: value.state,
                        user: value.user.clone(),
                        remote: value.remote,
                    },
                ));
            }
            state.session = Some(value);
        }
    }
    if requirements.power {
        if let Some(value) = probe_value("power", probe_power(), state, &mut events) {
            if first || state.power.as_ref() != Some(&value) {
                events.push(Event::new(
                    "power",
                    EventKind::Power {
                        on_ac: value.on_ac,
                        battery_percent: value.battery_percent,
                        lid_closed: value.lid_closed,
                    },
                ));
            }
            state.power = Some(value);
        }
    }

    if requirements.integrity {
        probe_integrity(config_path, executable, state, &mut events);
    }
    state.initialized = true;
    events
}

fn probe_value<T>(
    sensor: &str,
    result: Result<T>,
    state: &mut PollState,
    events: &mut Vec<Event>,
) -> Option<T> {
    match result {
        Ok(value) => {
            state.failed.remove(sensor);
            Some(value)
        }
        Err(error) => {
            if state.failed.insert(sensor.to_owned()) {
                events.push(Event::new(
                    sensor,
                    EventKind::SensorFailure {
                        sensor: sensor.to_owned(),
                        message: error.to_string(),
                    },
                ));
            }
            None
        }
    }
}

fn usb_event(action: DeviceAction, device: &UsbDevice) -> Event {
    Event::new(
        "usb",
        EventKind::Usb {
            action,
            vendor_id: device.vendor_id.clone(),
            product_id: device.product_id.clone(),
            serial: device.serial.clone(),
        },
    )
}

fn probe_wifi() -> Result<WifiState> {
    let nmcli = resolve_tool("nmcli")?;
    let output = Command::new(nmcli)
        .env_clear()
        .args(["-t", "-f", "ACTIVE,SSID,BSSID", "device", "wifi"])
        .output()
        .context("run nmcli")?;
    if !output.status.success() {
        bail!("nmcli failed")
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let fields = parse_nmcli_fields(line);
        if fields.first().map(String::as_str) != Some("yes") {
            continue;
        }
        return Ok(WifiState {
            connected: true,
            ssid: fields.get(1).filter(|value| !value.is_empty()).cloned(),
            bssid: fields.get(2).filter(|value| !value.is_empty()).cloned(),
        });
    }
    Ok(WifiState {
        connected: false,
        ssid: None,
        bssid: None,
    })
}

fn parse_nmcli_fields(line: &str) -> Vec<String> {
    let mut fields = vec![String::new()];
    let mut escaped = false;
    for character in line.chars() {
        let last = fields.len() - 1;
        if escaped {
            fields[last].push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == ':' {
            fields.push(String::new());
        } else {
            fields[last].push(character);
        }
    }
    if escaped {
        let last = fields.len() - 1;
        fields[last].push('\\');
    }
    fields
}

fn probe_network() -> Result<NetworkState> {
    let mut online = false;
    let mut interface = None;
    let mut vpn = false;
    for entry in fs::read_dir("/sys/class/net").context("read network interfaces")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "lo" {
            continue;
        }
        let state = fs::read_to_string(entry.path().join("operstate")).unwrap_or_default();
        if state.trim() == "up" {
            online = true;
            if interface.is_none() {
                interface = Some(name.clone());
            }
            if name.starts_with("tun")
                || name.starts_with("tap")
                || name.starts_with("wg")
                || name.starts_with("vpn")
            {
                vpn = true;
            }
        }
    }
    Ok(NetworkState {
        online,
        interface,
        vpn,
    })
}

fn probe_usb() -> Result<BTreeSet<UsbDevice>> {
    let mut devices = BTreeSet::new();
    for entry in fs::read_dir("/sys/bus/usb/devices").context("read USB devices")? {
        let entry = entry?;
        let vendor = read_trimmed(entry.path().join("idVendor"));
        let product = read_trimmed(entry.path().join("idProduct"));
        if vendor.is_none() && product.is_none() {
            continue;
        }
        devices.insert(UsbDevice {
            vendor_id: vendor,
            product_id: product,
            serial: read_trimmed(entry.path().join("serial")),
        });
    }
    Ok(devices)
}

fn probe_mounts() -> Result<BTreeMap<PathBuf, Option<String>>> {
    let text = fs::read_to_string("/proc/self/mountinfo").context("read mountinfo")?;
    let mut mounts = BTreeMap::new();
    for line in text.lines() {
        let Some((prefix, suffix)) = line.split_once(" - ") else {
            continue;
        };
        let fields: Vec<_> = prefix.split_whitespace().collect();
        let suffix_fields: Vec<_> = suffix.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let path = PathBuf::from(unescape_mount(fields[4]));
        let source = suffix_fields.get(1).map(|value| unescape_mount(value));
        mounts.insert(path, source);
    }
    Ok(mounts)
}

fn probe_processes(names: &BTreeSet<String>) -> Result<BTreeMap<String, bool>> {
    let mut result: BTreeMap<_, _> = names.iter().map(|name| (name.clone(), false)).collect();
    for entry in fs::read_dir("/proc").context("read /proc")? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        let name = fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
        if let Some(running) = result.get_mut(name.trim()) {
            *running = true;
        }
    }
    Ok(result)
}

fn probe_services(names: &BTreeSet<String>) -> Result<BTreeMap<String, bool>> {
    let systemctl = resolve_tool("systemctl")?;
    let mut result = BTreeMap::new();
    for name in names {
        let output = Command::new(&systemctl)
            .env_clear()
            .args(["is-active", "--quiet", name])
            .status()
            .with_context(|| format!("query service {name}"))?;
        result.insert(name.clone(), output.success());
    }
    Ok(result)
}

fn probe_ports(
    required: &BTreeSet<(NetworkProtocol, u16)>,
) -> Result<BTreeSet<(NetworkProtocol, u16)>> {
    let mut open = BTreeSet::new();
    for (path, protocol) in [
        ("/proc/net/tcp", NetworkProtocol::Tcp),
        ("/proc/net/tcp6", NetworkProtocol::Tcp),
        ("/proc/net/udp", NetworkProtocol::Udp),
        ("/proc/net/udp6", NetworkProtocol::Udp),
    ] {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let fields: Vec<_> = line.split_whitespace().collect();
            let Some(address) = fields.get(1) else {
                continue;
            };
            let Some((_, port)) = address.rsplit_once(':') else {
                continue;
            };
            let Ok(port) = u16::from_str_radix(port, 16) else {
                continue;
            };
            let listening = protocol == NetworkProtocol::Udp || fields.get(3) == Some(&"0A");
            if listening && required.contains(&(protocol, port)) {
                open.insert((protocol, port));
            }
        }
    }
    Ok(open)
}

fn probe_session() -> Result<SessionInfo> {
    let loginctl = resolve_tool("loginctl")?;
    let output = Command::new(&loginctl)
        .env_clear()
        .args(["list-sessions", "--no-legend"])
        .output()
        .context("list login sessions")?;
    if !output.status.success() {
        bail!("loginctl list-sessions failed")
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let Some(line) = text.lines().next() else {
        return Ok(SessionInfo {
            state: SessionState::LoggedOut,
            user: None,
            remote: false,
        });
    };
    let fields: Vec<_> = line.split_whitespace().collect();
    let session_id = *fields
        .first()
        .ok_or_else(|| anyhow!("invalid loginctl output"))?;
    let user = fields.get(2).map(|value| (*value).to_owned());
    let properties = Command::new(&loginctl)
        .env_clear()
        .args([
            "show-session",
            session_id,
            "--property=LockedHint",
            "--property=Remote",
            "--value",
        ])
        .output()
        .context("query login session")?;
    if !properties.status.success() {
        bail!("loginctl show-session failed")
    }
    let values: Vec<_> = String::from_utf8_lossy(&properties.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    let locked = values.first().is_some_and(|value| value == "yes");
    let remote = values.get(1).is_some_and(|value| value == "yes");
    Ok(SessionInfo {
        state: if locked {
            SessionState::Locked
        } else {
            SessionState::Unlocked
        },
        user,
        remote,
    })
}

fn probe_power() -> Result<PowerState> {
    let mut on_ac = None;
    let mut battery_percent = None;
    let power_root = Path::new("/sys/class/power_supply");
    if power_root.exists() {
        for entry in fs::read_dir(power_root).context("read power supplies")? {
            let entry = entry?;
            let kind = read_trimmed(entry.path().join("type")).unwrap_or_default();
            if kind == "Mains" || kind == "USB" || kind == "USB_C" {
                let supply_online = read_trimmed(entry.path().join("online"))
                    .and_then(|value| value.parse::<u8>().ok())
                    .map(|value| value == 1);
                if let Some(supply_online) = supply_online {
                    on_ac = Some(on_ac.unwrap_or(false) || supply_online);
                }
            } else if kind == "Battery" {
                if battery_percent.is_none() {
                    battery_percent = read_trimmed(entry.path().join("capacity"))
                        .and_then(|value| value.parse::<u8>().ok());
                }
            }
        }
    }
    let lid_closed = fs::read_dir("/proc/acpi/button/lid")
        .ok()
        .and_then(|mut entries| entries.next())
        .and_then(|entry| entry.ok())
        .and_then(|entry| read_trimmed(entry.path().join("state")))
        .map(|value| value.to_ascii_lowercase().contains("closed"));
    Ok(PowerState {
        on_ac,
        battery_percent,
        lid_closed,
    })
}

fn probe_integrity(
    config_path: &Path,
    executable: &Path,
    state: &mut PollState,
    events: &mut Vec<Event>,
) {
    check_integrity("configuration", config_path, &mut state.config_hash, events);
    check_integrity("binary", executable, &mut state.binary_hash, events);
}

fn check_integrity(
    component: &str,
    path: &Path,
    slot: &mut Option<blake3::Hash>,
    events: &mut Vec<Event>,
) {
    match fs::read(path) {
        Ok(bytes) => {
            let current = blake3::hash(&bytes);
            if let Some(previous) = slot {
                if *previous != current {
                    events.push(Event::new(
                        "integrity",
                        EventKind::Integrity {
                            component: component.to_owned(),
                            valid: false,
                            detail: Some(format!("{} changed on disk", path.display())),
                        },
                    ));
                }
            }
            *slot = Some(current);
        }
        Err(error) => events.push(Event::new(
            "integrity",
            EventKind::SensorFailure {
                sensor: "integrity".to_owned(),
                message: format!("read {}: {error}", path.display()),
            },
        )),
    }
}

fn resolve_tool(name: &str) -> Result<PathBuf> {
    for directory in ["/usr/bin", "/usr/sbin", "/bin", "/sbin"] {
        let candidate = Path::new(directory).join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!("required sensor tool is unavailable: {name}")
}

fn read_trimmed(path: PathBuf) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn unescape_mount(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_mountinfo_paths() {
        assert_eq!(unescape_mount("/srv/secure\\040files"), "/srv/secure files");
    }

    #[test]
    fn reads_listening_tcp_ports() {
        let required = BTreeSet::from([(NetworkProtocol::Tcp, 22)]);
        let result = probe_ports(&required);
        assert!(result.is_ok());
    }

    #[test]
    fn parses_escaped_nmcli_fields() {
        assert_eq!(
            parse_nmcli_fields(r"yes:ops\:secure:AA\:BB\:CC\:DD\:EE\:FF"),
            vec!["yes", "ops:secure", "AA:BB:CC:DD:EE:FF"]
        );
    }
}
