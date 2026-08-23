use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use kovert_core::config::{
    ConditionSpec, Config, NetworkProtocol, TriggerSpec,
};

/// Minimal sensor surface derived from configured rules.
#[derive(Debug, Clone, Default)]
pub struct SensorRequirements {
    pub file_watches: BTreeMap<PathBuf, bool>,
    pub wifi: bool,
    pub network: bool,
    pub usb: bool,
    pub mounts: bool,
    pub processes: BTreeSet<String>,
    pub services: BTreeSet<String>,
    pub ports: BTreeSet<(NetworkProtocol, u16)>,
    pub sessions: bool,
    pub power: bool,
}

impl SensorRequirements {
    pub fn from_config(config: &Config) -> Self {
        let mut value = Self::default();
        for rule in &config.rules {
            collect_trigger(&rule.trigger, &mut value);
            if let Some(condition) = &rule.when {
                collect_condition(condition, &mut value);
            }
        }
        value
    }
}

fn collect_trigger(trigger: &TriggerSpec, value: &mut SensorRequirements) {
    match trigger {
        TriggerSpec::File {
            path, recursive, ..
        } => {
            value.file_watches.insert(path.clone(), *recursive);
        }
        TriggerSpec::WifiChanged { .. } => value.wifi = true,
        TriggerSpec::NetworkChanged { .. } => value.network = true,
        TriggerSpec::Usb { .. } => value.usb = true,
        TriggerSpec::Mount { .. } => value.mounts = true,
        TriggerSpec::Process { name, .. } => {
            if let Some(name) = name {
                value.processes.insert(name.clone());
            }
        }
        TriggerSpec::Service { name, .. } => {
            if let Some(name) = name {
                value.services.insert(name.clone());
            }
        }
        TriggerSpec::Port { port, protocol, .. } => {
            if let Some(port) = port {
                value.ports.insert((protocol.unwrap_or_default(), *port));
            }
        }
        TriggerSpec::Session { .. } => value.sessions = true,
        TriggerSpec::Power { .. } => value.power = true,
        TriggerSpec::All { triggers }
        | TriggerSpec::Any { triggers }
        | TriggerSpec::Sequence {
            steps: triggers, ..
        } => {
            for item in triggers {
                collect_trigger(item, value);
            }
        }
        TriggerSpec::Not { trigger } => collect_trigger(trigger, value),
        TriggerSpec::Tick
        | TriggerSpec::Hotkey { .. }
        | TriggerSpec::IntegrityFailure { .. }
        | TriggerSpec::Manual { .. }
        | TriggerSpec::SensorFailure { .. } => {}
    }
}

fn collect_condition(condition: &ConditionSpec, value: &mut SensorRequirements) {
    match condition {
        ConditionSpec::Wifi { .. } => value.wifi = true,
        ConditionSpec::Network { .. } => value.network = true,
        ConditionSpec::Mounted { .. } => value.mounts = true,
        ConditionSpec::Process { name, .. } => {
            value.processes.insert(name.clone());
        }
        ConditionSpec::Service { name, .. } => {
            value.services.insert(name.clone());
        }
        ConditionSpec::Port { port, protocol, .. } => {
            value.ports.insert((*protocol, *port));
        }
        ConditionSpec::Session { .. } => value.sessions = true,
        ConditionSpec::Power { .. } => value.power = true,
        ConditionSpec::All { conditions } | ConditionSpec::Any { conditions } => {
            for item in conditions {
                collect_condition(item, value);
            }
        }
        ConditionSpec::Not { condition } => collect_condition(condition, value),
        ConditionSpec::TimeWindow { .. }
        | ConditionSpec::Mode { .. }
        | ConditionSpec::PathExists { .. }
        | ConditionSpec::SensorHealthy { .. } => {}
    }
}

