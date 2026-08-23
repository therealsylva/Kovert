use std::collections::HashSet;

use chrono::NaiveTime;
use regex::Regex;
use thiserror::Error;

use crate::config::{ActionSpec, ConditionSpec, Config, TriggerSpec, VaultAdapter};

/// Configuration validation failure.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("unsupported configuration version {0}; expected 1")]
    Version(u32),
    #[error("duplicate {kind} name: {name}")]
    Duplicate { kind: &'static str, name: String },
    #[error("invalid rule {rule}: {message}")]
    Rule { rule: String, message: String },
    #[error("invalid vault {vault}: {message}")]
    Vault { vault: String, message: String },
    #[error("invalid hotkey {hotkey}: {message}")]
    Hotkey { hotkey: String, message: String },
    #[error("invalid daemon setting: {0}")]
    Daemon(String),
}

/// Validate structural, privilege-boundary, and cross-reference invariants.
pub fn validate_config(config: &Config) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();
    if config.version != 1 {
        errors.push(ValidationError::Version(config.version));
    }
    if !config.daemon.socket_path.is_absolute() {
        errors.push(ValidationError::Daemon(
            "socket_path must be absolute".to_owned(),
        ));
    }
    if !config.daemon.state_path.is_absolute() {
        errors.push(ValidationError::Daemon(
            "state_path must be absolute".to_owned(),
        ));
    }
    if config.daemon.poll_interval.is_zero() {
        errors.push(ValidationError::Daemon(
            "poll_interval must be greater than zero".to_owned(),
        ));
    }
    if config.daemon.event_buffer < 16 {
        errors.push(ValidationError::Daemon(
            "event_buffer must be at least 16".to_owned(),
        ));
    }
    for path in &config.daemon.allowed_executables {
        if !path.is_absolute() {
            errors.push(ValidationError::Daemon(format!(
                "allowed executable must be absolute: {}",
                path.display()
            )));
        }
    }

    let mut modes = HashSet::new();
    let mut initial_modes = 0;
    for mode in &config.modes {
        if !valid_identifier(&mode.name) {
            errors.push(ValidationError::Duplicate {
                kind: "invalid mode",
                name: mode.name.clone(),
            });
        }
        if !modes.insert(mode.name.clone()) {
            errors.push(ValidationError::Duplicate {
                kind: "mode",
                name: mode.name.clone(),
            });
        }
        if mode.initial {
            initial_modes += 1;
        }
    }
    if initial_modes > 1 {
        errors.push(ValidationError::Daemon(
            "only one mode may be marked initial".to_owned(),
        ));
    }

    let mut vaults = HashSet::new();
    for vault in &config.vaults {
        if !valid_identifier(&vault.name) {
            errors.push(ValidationError::Vault {
                vault: vault.name.clone(),
                message: "name must match [A-Za-z0-9_.-]+".to_owned(),
            });
        }
        if !vaults.insert(vault.name.clone()) {
            errors.push(ValidationError::Duplicate {
                kind: "vault",
                name: vault.name.clone(),
            });
        }
        if !vault.path.is_absolute() {
            errors.push(ValidationError::Vault {
                vault: vault.name.clone(),
                message: "path must be absolute".to_owned(),
            });
        }
        if vault.adapter == VaultAdapter::Gocryptfs
            && (vault
                .encrypted_path
                .as_ref()
                .is_none_or(|path| !path.is_absolute())
                || vault
                    .mount_path
                    .as_ref()
                    .is_none_or(|path| !path.is_absolute()))
        {
            errors.push(ValidationError::Vault {
                vault: vault.name.clone(),
                message: "gocryptfs requires absolute encrypted_path and mount_path".to_owned(),
            });
        }
        if vault
            .keyring_description
            .as_ref()
            .is_some_and(|description| {
                description.is_empty()
                    || description.len() > 128
                    || description.chars().any(char::is_control)
            })
        {
            errors.push(ValidationError::Vault {
                vault: vault.name.clone(),
                message: "keyring_description must be 1..=128 printable characters".to_owned(),
            });
        }
    }

    let mut hotkeys = HashSet::new();
    for hotkey in &config.hotkeys {
        if !valid_identifier(&hotkey.name) {
            errors.push(ValidationError::Hotkey {
                hotkey: hotkey.name.clone(),
                message: "name must match [A-Za-z0-9_.-]+".to_owned(),
            });
        }
        if !hotkeys.insert(hotkey.name.clone()) {
            errors.push(ValidationError::Duplicate {
                kind: "hotkey",
                name: hotkey.name.clone(),
            });
        }
        if !hotkey.device.is_absolute() {
            errors.push(ValidationError::Hotkey {
                hotkey: hotkey.name.clone(),
                message: "device path must be absolute".to_owned(),
            });
        }
        if hotkey.sequence.is_empty() || hotkey.sequence.len() > 32 {
            errors.push(ValidationError::Hotkey {
                hotkey: hotkey.name.clone(),
                message: "sequence must contain between 1 and 32 keys".to_owned(),
            });
        }
        if hotkey.within.is_zero() {
            errors.push(ValidationError::Hotkey {
                hotkey: hotkey.name.clone(),
                message: "within must be non-zero".to_owned(),
            });
        }
        if let Some(key) = hotkey.sequence.iter().find(|key| !valid_key_name(key)) {
            errors.push(ValidationError::Hotkey {
                hotkey: hotkey.name.clone(),
                message: format!("unsupported key name: {key}"),
            });
        }
    }

    let mut rules = HashSet::new();
    for rule in &config.rules {
        if !valid_identifier(&rule.id) {
            errors.push(rule_error(&rule.id, "id must match [A-Za-z0-9_.-]+"));
        }
        if !rules.insert(rule.id.clone()) {
            errors.push(ValidationError::Duplicate {
                kind: "rule",
                name: rule.id.clone(),
            });
        }
        if rule.actions.is_empty() {
            errors.push(rule_error(&rule.id, "at least one action is required"));
        }
        validate_trigger(&rule.trigger, &rule.id, 0, &hotkeys, &mut errors);
        if let Some(condition) = &rule.when {
            validate_condition(condition, &rule.id, 0, &mut errors);
        }
        for action in &rule.actions {
            validate_action(
                action,
                rule.id.as_str(),
                config,
                &vaults,
                &modes,
                &mut errors,
            );
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_trigger(
    trigger: &TriggerSpec,
    rule: &str,
    depth: usize,
    hotkeys: &HashSet<String>,
    errors: &mut Vec<ValidationError>,
) {
    if depth > 16 {
        errors.push(rule_error(rule, "trigger nesting exceeds 16 levels"));
        return;
    }
    match trigger {
        TriggerSpec::File { path, .. } if !path.is_absolute() => {
            errors.push(rule_error(rule, "file trigger path must be absolute"));
        }
        TriggerSpec::Power {
            battery_below: Some(value),
            ..
        } if *value > 100 => errors.push(rule_error(rule, "battery threshold must be 0..=100")),
        TriggerSpec::Process { name: None, .. } => {
            errors.push(rule_error(rule, "process trigger requires name"));
        }
        TriggerSpec::Service { name: None, .. } => {
            errors.push(rule_error(rule, "service trigger requires name"));
        }
        TriggerSpec::Port { port: None, .. } => {
            errors.push(rule_error(rule, "port trigger requires port"));
        }
        TriggerSpec::Hotkey { name } if !hotkeys.contains(name) => {
            errors.push(rule_error(rule, format!("unknown hotkey {name}")));
        }
        TriggerSpec::All { triggers } | TriggerSpec::Any { triggers } => {
            if triggers.is_empty() {
                errors.push(rule_error(rule, "composite trigger cannot be empty"));
            }
            for item in triggers {
                validate_trigger(item, rule, depth + 1, hotkeys, errors);
            }
        }
        TriggerSpec::Not { trigger } => {
            validate_trigger(trigger, rule, depth + 1, hotkeys, errors);
        }
        TriggerSpec::Sequence { steps, within } => {
            if steps.len() < 2 {
                errors.push(rule_error(rule, "sequence requires at least two steps"));
            }
            if within.is_zero() {
                errors.push(rule_error(rule, "sequence window must be non-zero"));
            }
            for item in steps {
                if matches!(item, TriggerSpec::Sequence { .. }) {
                    errors.push(rule_error(rule, "nested sequences are not supported"));
                }
                validate_trigger(item, rule, depth + 1, hotkeys, errors);
            }
        }
        _ => {}
    }
}

fn validate_condition(
    condition: &ConditionSpec,
    rule: &str,
    depth: usize,
    errors: &mut Vec<ValidationError>,
) {
    if depth > 16 {
        errors.push(rule_error(rule, "condition nesting exceeds 16 levels"));
        return;
    }
    match condition {
        ConditionSpec::All { conditions } | ConditionSpec::Any { conditions } => {
            if conditions.is_empty() {
                errors.push(rule_error(rule, "composite condition cannot be empty"));
            }
            for item in conditions {
                validate_condition(item, rule, depth + 1, errors);
            }
        }
        ConditionSpec::Not { condition } => {
            validate_condition(condition, rule, depth + 1, errors);
        }
        ConditionSpec::TimeWindow { start, end, .. } => {
            if NaiveTime::parse_from_str(start, "%H:%M").is_err()
                || NaiveTime::parse_from_str(end, "%H:%M").is_err()
            {
                errors.push(rule_error(rule, "time windows require HH:MM values"));
            }
        }
        ConditionSpec::PathExists { path, .. } | ConditionSpec::Mounted { path, .. }
            if !path.is_absolute() =>
        {
            errors.push(rule_error(rule, "condition paths must be absolute"));
        }
        ConditionSpec::Power {
            battery_below: Some(value),
            ..
        } if *value > 100 => errors.push(rule_error(rule, "battery threshold must be 0..=100")),
        ConditionSpec::SensorHealthy { sensor, .. }
            if !matches!(
                sensor.as_str(),
                "wifi"
                    | "network"
                    | "usb"
                    | "mounts"
                    | "processes"
                    | "services"
                    | "ports"
                    | "sessions"
                    | "power"
                    | "hotkeys"
                    | "filesystem"
                    | "integrity"
                    | "configuration"
                    | "binary"
                    | "polling"
                    | "time"
                    | "manual"
            ) =>
        {
            errors.push(rule_error(rule, format!("unknown sensor {sensor}")));
        }
        _ => {}
    }
}

fn validate_action(
    action: &ActionSpec,
    rule: &str,
    config: &Config,
    vaults: &HashSet<String>,
    modes: &HashSet<String>,
    errors: &mut Vec<ValidationError>,
) {
    match action {
        ActionSpec::LockVault { vault } | ActionSpec::UnlockVault { vault }
            if !vaults.contains(vault) =>
        {
            errors.push(rule_error(rule, format!("unknown vault {vault}")));
        }
        ActionSpec::Unmount { path } if !path.is_absolute() => {
            errors.push(rule_error(rule, "unmount path must be absolute"));
        }
        ActionSpec::InterfaceState { interface, .. } if !valid_interface_name(interface) => {
            errors.push(rule_error(rule, "invalid network interface name"));
        }
        ActionSpec::Service { name, .. } if !valid_unit_name(name) => {
            errors.push(rule_error(rule, "invalid systemd service name"));
        }
        ActionSpec::TerminateProcess { process, .. }
            if !config.daemon.managed_processes.contains(process) =>
        {
            errors.push(rule_error(
                rule,
                format!("process {process} is not in daemon.managed_processes"),
            ));
        }
        ActionSpec::CaptureEvidence { paths, destination } => {
            if !destination.is_absolute() || paths.iter().any(|path| !path.is_absolute()) {
                errors.push(rule_error(rule, "evidence paths must be absolute"));
            }
        }
        ActionSpec::SetMode { mode } if !modes.contains(mode) => {
            errors.push(rule_error(rule, format!("unknown mode {mode}")));
        }
        ActionSpec::Exec {
            executable,
            expected_sha256,
            environment,
            ..
        } => {
            if !executable.is_absolute() || !config.daemon.allowed_executables.contains(executable)
            {
                errors.push(rule_error(
                    rule,
                    format!(
                        "executable {} is not in daemon.allowed_executables",
                        executable.display()
                    ),
                ));
            }
            if expected_sha256.as_ref().is_some_and(|digest| {
                digest.len() != 64 || !digest.chars().all(|ch| ch.is_ascii_hexdigit())
            }) {
                errors.push(rule_error(
                    rule,
                    "expected_sha256 must be 64 hex characters",
                ));
            }
            if expected_sha256.is_none() {
                errors.push(rule_error(
                    rule,
                    "exec actions require expected_sha256 pinning",
                ));
            }
            if environment.keys().any(|key| {
                !key.chars()
                    .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
            }) {
                errors.push(rule_error(
                    rule,
                    "environment keys must use uppercase ASCII, digits, and underscores",
                ));
            }
        }
        _ => {}
    }
}

fn rule_error(rule: &str, message: impl Into<String>) -> ValidationError {
    ValidationError::Rule {
        rule: rule.to_owned(),
        message: message.into(),
    }
}

fn valid_identifier(value: &str) -> bool {
    Regex::new(r"^[A-Za-z0-9_.-]+$").is_ok_and(|regex| regex.is_match(value))
}

fn valid_key_name(value: &str) -> bool {
    let normalized = value.trim().to_ascii_uppercase();
    let key = normalized.strip_prefix("KEY_").unwrap_or(&normalized);
    (key.len() == 1 && key.as_bytes()[0].is_ascii_alphanumeric())
        || matches!(
            key,
            "ESC"
                | "ENTER"
                | "LEFTCTRL"
                | "CTRL"
                | "LEFTSHIFT"
                | "SHIFT"
                | "LEFTALT"
                | "ALT"
                | "SPACE"
                | "F1"
                | "F2"
                | "F3"
                | "F4"
                | "F5"
                | "F6"
                | "F7"
                | "F8"
                | "F9"
                | "F10"
                | "F11"
                | "F12"
                | "RIGHTCTRL"
                | "RIGHTALT"
                | "HOME"
                | "UP"
                | "PAGEUP"
                | "LEFT"
                | "RIGHT"
                | "END"
                | "DOWN"
                | "PAGEDOWN"
                | "INSERT"
                | "DELETE"
                | "LEFTMETA"
                | "META"
                | "RIGHTMETA"
        )
}

fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':'))
}

fn valid_unit_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.contains('/')
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '@'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_privileged_paths() {
        let config = Config::from_toml(
            r#"
version = 1

[[rules]]
id = "bad"
actions = [{ type = "unmount", path = "relative" }]

[rules.trigger]
type = "tick"
"#,
        )
        .unwrap_or_else(|error| panic!("fixture must parse: {error}"));
        let errors = validate_config(&config).expect_err("relative path must fail");
        assert!(
            errors
                .iter()
                .any(|error| error.to_string().contains("absolute"))
        );
    }
}
