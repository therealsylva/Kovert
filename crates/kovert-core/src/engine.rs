use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Datelike, Local, NaiveTime, Utc};

use crate::config::{ActionSpec, ConditionSpec, Rule, SensorFailurePolicy, TriggerSpec, Weekday};
use crate::event::{Event, EventKind, SystemSnapshot};

#[derive(Debug, Clone)]
struct RuleRuntime {
    last_fired: Option<DateTime<Utc>>,
    armed_at: Option<DateTime<Utc>>,
    fired_once: bool,
    sequence_index: usize,
    sequence_started: Option<DateTime<Utc>>,
}

impl Default for RuleRuntime {
    fn default() -> Self {
        Self {
            last_fired: None,
            armed_at: None,
            fired_once: false,
            sequence_index: 0,
            sequence_started: None,
        }
    }
}

/// One action selected after priority and conflict resolution.
#[derive(Debug, Clone)]
pub struct ActionPlan {
    pub rule_id: String,
    pub priority: i32,
    pub event_id: uuid::Uuid,
    pub action: ActionSpec,
}

/// Stateful event-condition-action evaluator.
#[derive(Clone)]
pub struct PolicyEngine {
    rules: Vec<Rule>,
    runtime: HashMap<String, RuleRuntime>,
    snapshot: SystemSnapshot,
    recovery_mode: bool,
}

impl PolicyEngine {
    /// Create an engine. Rules are sorted by descending priority and stable ID.
    pub fn new(mut rules: Vec<Rule>, initial_mode: impl Into<String>) -> Self {
        rules.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| left.id.cmp(&right.id))
        });
        let runtime = rules
            .iter()
            .map(|rule| (rule.id.clone(), RuleRuntime::default()))
            .collect();
        let snapshot = SystemSnapshot {
            mode: initial_mode.into(),
            ..SystemSnapshot::default()
        };
        Self {
            rules,
            runtime,
            snapshot,
            recovery_mode: false,
        }
    }

    pub fn snapshot(&self) -> &SystemSnapshot {
        &self.snapshot
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn recovery_mode(&self) -> bool {
        self.recovery_mode
    }

    pub fn set_recovery_mode(&mut self, enabled: bool) {
        self.recovery_mode = enabled;
        if enabled {
            for state in self.runtime.values_mut() {
                state.armed_at = None;
                state.sequence_index = 0;
                state.sequence_started = None;
            }
        }
    }

    pub fn set_mode(&mut self, mode: impl Into<String>) {
        self.snapshot.mode = mode.into();
    }

    /// Replace rules after a validated configuration reload.
    pub fn replace_rules(&mut self, mut rules: Vec<Rule>) {
        rules.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| left.id.cmp(&right.id))
        });
        let mut next_runtime = HashMap::new();
        for rule in &rules {
            next_runtime.insert(
                rule.id.clone(),
                self.runtime.remove(&rule.id).unwrap_or_default(),
            );
        }
        self.rules = rules;
        self.runtime = next_runtime;
    }

    /// Evaluate one event and return a conflict-free plan.
    pub fn handle(&mut self, event: &Event) -> Vec<ActionPlan> {
        self.snapshot.apply(event);
        if self.recovery_mode {
            return Vec::new();
        }

        let mut candidates = Vec::new();
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            let runtime = self.runtime.entry(rule.id.clone()).or_default();
            if rule.once_per_boot && runtime.fired_once {
                continue;
            }
            if runtime
                .last_fired
                .is_some_and(|last| elapsed(event.timestamp, last) < rule.cooldown)
            {
                continue;
            }

            if let EventKind::SensorFailure { sensor, message } = &event.kind {
                if trigger_uses_sensor(&rule.trigger, sensor) {
                    match rule.on_sensor_failure {
                        SensorFailurePolicy::Ignore => continue,
                        SensorFailurePolicy::Alert => {
                            candidates.push(ActionPlan {
                                rule_id: rule.id.clone(),
                                priority: rule.priority,
                                event_id: event.id,
                                action: ActionSpec::Notify {
                                    title: "Kovert sensor failure".to_owned(),
                                    message: format!("{sensor}: {message}"),
                                    urgency: crate::config::NotificationUrgency::Critical,
                                },
                            });
                            continue;
                        }
                        SensorFailurePolicy::FailClosed => {
                            for action in rule.actions.iter().filter(|action| {
                                matches!(
                                    action,
                                    ActionSpec::LockVault { .. }
                                        | ActionSpec::NetworkIsolation { enabled: true }
                                        | ActionSpec::SetMode { .. }
                                )
                            }) {
                                candidates.push(ActionPlan {
                                    rule_id: rule.id.clone(),
                                    priority: rule.priority,
                                    event_id: event.id,
                                    action: action.clone(),
                                });
                            }
                            continue;
                        }
                    }
                }
            }

            let conditions_match = rule
                .when
                .as_ref()
                .is_none_or(|condition| condition_matches(condition, &self.snapshot));

            if let Some(armed_at) = runtime.armed_at {
                if !conditions_match {
                    runtime.armed_at = None;
                    continue;
                }
                if elapsed(event.timestamp, armed_at) < rule.sustain_for {
                    continue;
                }
                runtime.armed_at = None;
                append_actions(&mut candidates, rule, event);
                runtime.last_fired = Some(event.timestamp);
                runtime.fired_once = true;
                continue;
            }

            let trigger_matches = match &rule.trigger {
                TriggerSpec::Sequence { steps, within } => {
                    sequence_matches(runtime, steps, *within, event, &self.snapshot)
                }
                trigger => trigger_matches(trigger, event, &self.snapshot),
            };

            if !trigger_matches || !conditions_match {
                continue;
            }

            if rule.sustain_for.is_zero() {
                append_actions(&mut candidates, rule, event);
                runtime.last_fired = Some(event.timestamp);
                runtime.fired_once = true;
            } else {
                runtime.armed_at = Some(event.timestamp);
            }
        }

        resolve_conflicts(candidates)
    }
}

fn append_actions(candidates: &mut Vec<ActionPlan>, rule: &Rule, event: &Event) {
    for action in &rule.actions {
        candidates.push(ActionPlan {
            rule_id: rule.id.clone(),
            priority: rule.priority,
            event_id: event.id,
            action: action.clone(),
        });
    }
}

fn resolve_conflicts(mut candidates: Vec<ActionPlan>) -> Vec<ActionPlan> {
    candidates.sort_by(|left, right| right.priority.cmp(&left.priority));
    let mut claimed = HashSet::new();
    candidates
        .into_iter()
        .filter(|plan| {
            plan.action
                .conflict_key()
                .is_none_or(|key| claimed.insert(key))
        })
        .collect()
}

fn sequence_matches(
    runtime: &mut RuleRuntime,
    steps: &[TriggerSpec],
    within: Duration,
    event: &Event,
    snapshot: &SystemSnapshot,
) -> bool {
    if steps.is_empty() {
        return false;
    }
    if runtime
        .sequence_started
        .is_some_and(|start| elapsed(event.timestamp, start) > within)
    {
        runtime.sequence_index = 0;
        runtime.sequence_started = None;
    }
    let expected = &steps[runtime.sequence_index];
    if !trigger_matches(expected, event, snapshot) {
        if trigger_matches(&steps[0], event, snapshot) {
            runtime.sequence_index = 1;
            runtime.sequence_started = Some(event.timestamp);
        }
        return false;
    }
    if runtime.sequence_index == 0 {
        runtime.sequence_started = Some(event.timestamp);
    }
    runtime.sequence_index += 1;
    if runtime.sequence_index == steps.len() {
        runtime.sequence_index = 0;
        runtime.sequence_started = None;
        return true;
    }
    false
}

fn elapsed(later: DateTime<Utc>, earlier: DateTime<Utc>) -> Duration {
    (later - earlier).to_std().unwrap_or_default()
}

fn trigger_matches(trigger: &TriggerSpec, event: &Event, snapshot: &SystemSnapshot) -> bool {
    match (trigger, &event.kind) {
        (TriggerSpec::Tick, EventKind::Tick) => true,
        (
            TriggerSpec::File {
                path,
                operations,
                recursive,
            },
            EventKind::File {
                path: event_path,
                operation,
            },
        ) => {
            path_matches(path, event_path, *recursive)
                && (operations.is_empty() || operations.contains(operation))
        }
        (
            TriggerSpec::WifiChanged {
                ssid,
                bssid,
                connected,
            },
            EventKind::Wifi {
                connected: event_connected,
                ssid: event_ssid,
                bssid: event_bssid,
            },
        ) => {
            connected.is_none_or(|value| value == *event_connected)
                && ssid
                    .as_ref()
                    .is_none_or(|value| event_ssid.as_ref() == Some(value))
                && bssid.as_ref().is_none_or(|value| {
                    event_bssid
                        .as_ref()
                        .is_some_and(|actual| actual.eq_ignore_ascii_case(value))
                })
        }
        (
            TriggerSpec::NetworkChanged {
                interface,
                online,
                vpn,
            },
            EventKind::Network {
                online: event_online,
                interface: event_interface,
                vpn: event_vpn,
            },
        ) => {
            online.is_none_or(|value| value == *event_online)
                && vpn.is_none_or(|value| value == *event_vpn)
                && interface
                    .as_ref()
                    .is_none_or(|value| event_interface.as_ref() == Some(value))
        }
        (
            TriggerSpec::Usb {
                action,
                vendor_id,
                product_id,
                serial,
            },
            EventKind::Usb {
                action: event_action,
                vendor_id: event_vendor,
                product_id: event_product,
                serial: event_serial,
            },
        ) => {
            action.is_none_or(|value| value == *event_action)
                && eq_optional_ci(vendor_id.as_ref(), event_vendor.as_ref())
                && eq_optional_ci(product_id.as_ref(), event_product.as_ref())
                && eq_optional(serial.as_ref(), event_serial.as_ref())
        }
        (
            TriggerSpec::Mount { action, path },
            EventKind::Mount {
                action: event_action,
                path: event_path,
                ..
            },
        ) => {
            action.is_none_or(|value| value == *event_action)
                && path.as_ref().is_none_or(|value| value == event_path)
        }
        (
            TriggerSpec::Process { name, running },
            EventKind::Process {
                name: event_name,
                running: event_running,
                ..
            },
        ) => {
            running.is_none_or(|value| value == *event_running)
                && name.as_ref().is_none_or(|value| value == event_name)
        }
        (
            TriggerSpec::Service { name, active },
            EventKind::Service {
                name: event_name,
                active: event_active,
            },
        ) => {
            active.is_none_or(|value| value == *event_active)
                && name.as_ref().is_none_or(|value| value == event_name)
        }
        (
            TriggerSpec::Port {
                port,
                open,
                protocol,
            },
            EventKind::Port {
                port: event_port,
                open: event_open,
                protocol: event_protocol,
            },
        ) => {
            port.is_none_or(|value| value == *event_port)
                && open.is_none_or(|value| value == *event_open)
                && protocol.is_none_or(|value| value == *event_protocol)
        }
        (
            TriggerSpec::Session {
                state,
                user,
                remote,
            },
            EventKind::Session {
                state: event_state,
                user: event_user,
                remote: event_remote,
            },
        ) => {
            state.is_none_or(|value| value == *event_state)
                && remote.is_none_or(|value| value == *event_remote)
                && user
                    .as_ref()
                    .is_none_or(|value| event_user.as_ref() == Some(value))
        }
        (
            TriggerSpec::Power {
                on_ac,
                battery_below,
                lid_closed,
            },
            EventKind::Power {
                on_ac: event_ac,
                battery_percent,
                lid_closed: event_lid,
            },
        ) => {
            on_ac.is_none_or(|value| event_ac == &Some(value))
                && lid_closed.is_none_or(|value| event_lid == &Some(value))
                && battery_below
                    .is_none_or(|limit| battery_percent.is_some_and(|actual| actual < limit))
        }
        (TriggerSpec::Hotkey { name }, EventKind::Hotkey { name: event_name }) => {
            name == event_name
        }
        (
            TriggerSpec::IntegrityFailure { component },
            EventKind::Integrity {
                component: event_component,
                valid,
                ..
            },
        ) => {
            !valid
                && component
                    .as_ref()
                    .is_none_or(|value| value == event_component)
        }
        (TriggerSpec::Manual { name }, EventKind::Manual { name: event_name }) => {
            name == event_name
        }
        (
            TriggerSpec::SensorFailure { sensor },
            EventKind::SensorFailure {
                sensor: event_sensor,
                ..
            },
        ) => sensor.as_ref().is_none_or(|value| value == event_sensor),
        (TriggerSpec::All { triggers }, _) => triggers
            .iter()
            .all(|item| trigger_matches(item, event, snapshot)),
        (TriggerSpec::Any { triggers }, _) => triggers
            .iter()
            .any(|item| trigger_matches(item, event, snapshot)),
        (TriggerSpec::Not { trigger }, _) => !trigger_matches(trigger, event, snapshot),
        (TriggerSpec::Sequence { .. }, _) => false,
        _ => false,
    }
}

fn condition_matches(condition: &ConditionSpec, snapshot: &SystemSnapshot) -> bool {
    match condition {
        ConditionSpec::All { conditions } => conditions
            .iter()
            .all(|item| condition_matches(item, snapshot)),
        ConditionSpec::Any { conditions } => conditions
            .iter()
            .any(|item| condition_matches(item, snapshot)),
        ConditionSpec::Not { condition } => !condition_matches(condition, snapshot),
        ConditionSpec::TimeWindow {
            start,
            end,
            outside,
            weekdays,
        } => {
            let Ok(start) = NaiveTime::parse_from_str(start, "%H:%M") else {
                return false;
            };
            let Ok(end) = NaiveTime::parse_from_str(end, "%H:%M") else {
                return false;
            };
            let local_now = snapshot.now.with_timezone(&Local);
            let now = local_now.time();
            let inside = if start <= end {
                now >= start && now <= end
            } else {
                now >= start || now <= end
            };
            let weekday_matches =
                weekdays.is_empty() || weekdays.contains(&weekday_from_chrono(local_now.weekday()));
            weekday_matches && if *outside { !inside } else { inside }
        }
        ConditionSpec::Wifi {
            ssid,
            bssid,
            connected,
        } => {
            connected.is_none_or(|value| value == snapshot.wifi_connected)
                && ssid
                    .as_ref()
                    .is_none_or(|value| snapshot.wifi_ssid.as_ref() == Some(value))
                && bssid.as_ref().is_none_or(|value| {
                    snapshot
                        .wifi_bssid
                        .as_ref()
                        .is_some_and(|actual| actual.eq_ignore_ascii_case(value))
                })
        }
        ConditionSpec::Network {
            online,
            interface,
            vpn,
        } => {
            online.is_none_or(|value| value == snapshot.network_online)
                && vpn.is_none_or(|value| value == snapshot.vpn_active)
                && interface
                    .as_ref()
                    .is_none_or(|value| snapshot.active_interface.as_ref() == Some(value))
        }
        ConditionSpec::Mode { name } => name == &snapshot.mode,
        ConditionSpec::PathExists { path, exists } => path.exists() == *exists,
        ConditionSpec::Mounted { path, mounted } => snapshot.mounts.contains(path) == *mounted,
        ConditionSpec::Process { name, running } => snapshot.processes.contains(name) == *running,
        ConditionSpec::Service { name, active } => {
            snapshot.services.get(name).copied().unwrap_or(false) == *active
        }
        ConditionSpec::Port {
            port,
            open,
            protocol,
        } => snapshot.ports.contains(&(*protocol, *port)) == *open,
        ConditionSpec::Session {
            state,
            user,
            remote,
        } => {
            state.is_none_or(|value| snapshot.session_state == Some(value))
                && remote.is_none_or(|value| snapshot.session_remote == value)
                && user
                    .as_ref()
                    .is_none_or(|value| snapshot.session_user.as_ref() == Some(value))
        }
        ConditionSpec::Power {
            on_ac,
            battery_below,
            lid_closed,
        } => {
            on_ac.is_none_or(|value| snapshot.on_ac == Some(value))
                && lid_closed.is_none_or(|value| snapshot.lid_closed == Some(value))
                && battery_below.is_none_or(|limit| {
                    snapshot
                        .battery_percent
                        .is_some_and(|actual| actual < limit)
                })
        }
        ConditionSpec::SensorHealthy { sensor, healthy } => {
            snapshot.sensor_health.get(sensor).copied().unwrap_or(false) == *healthy
        }
    }
}

fn path_matches(configured: &Path, actual: &Path, recursive: bool) -> bool {
    if recursive {
        actual.starts_with(configured)
    } else {
        actual == configured
    }
}

fn eq_optional(expected: Option<&String>, actual: Option<&String>) -> bool {
    expected.is_none_or(|value| actual == Some(value))
}

fn eq_optional_ci(expected: Option<&String>, actual: Option<&String>) -> bool {
    expected
        .is_none_or(|value| actual.is_some_and(|candidate| candidate.eq_ignore_ascii_case(value)))
}

fn weekday_from_chrono(value: chrono::Weekday) -> Weekday {
    match value {
        chrono::Weekday::Mon => Weekday::Mon,
        chrono::Weekday::Tue => Weekday::Tue,
        chrono::Weekday::Wed => Weekday::Wed,
        chrono::Weekday::Thu => Weekday::Thu,
        chrono::Weekday::Fri => Weekday::Fri,
        chrono::Weekday::Sat => Weekday::Sat,
        chrono::Weekday::Sun => Weekday::Sun,
    }
}

fn trigger_uses_sensor(trigger: &TriggerSpec, sensor: &str) -> bool {
    match trigger {
        TriggerSpec::Tick => sensor == "time",
        TriggerSpec::File { .. } => sensor == "filesystem",
        TriggerSpec::WifiChanged { .. } => sensor == "wifi",
        TriggerSpec::NetworkChanged { .. } => sensor == "network",
        TriggerSpec::Usb { .. } => sensor == "usb",
        TriggerSpec::Mount { .. } => sensor == "mounts",
        TriggerSpec::Process { .. } => sensor == "processes",
        TriggerSpec::Service { .. } => sensor == "services",
        TriggerSpec::Port { .. } => sensor == "ports",
        TriggerSpec::Session { .. } => sensor == "sessions",
        TriggerSpec::Power { .. } => sensor == "power",
        TriggerSpec::Hotkey { .. } => sensor == "hotkeys",
        TriggerSpec::IntegrityFailure { .. } => sensor == "integrity",
        TriggerSpec::Manual { .. } => sensor == "manual",
        TriggerSpec::SensorFailure { sensor: expected } => {
            expected.as_ref().is_none_or(|value| value == sensor)
        }
        TriggerSpec::All { triggers }
        | TriggerSpec::Any { triggers }
        | TriggerSpec::Sequence {
            steps: triggers, ..
        } => triggers
            .iter()
            .any(|item| trigger_uses_sensor(item, sensor)),
        TriggerSpec::Not { trigger } => trigger_uses_sensor(trigger, sensor),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use chrono::TimeZone;

    use super::*;
    use crate::config::{FileOperation, NotificationUrgency};

    fn event_at(kind: EventKind, second: i64) -> Event {
        Event {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc
                .timestamp_opt(second, 0)
                .single()
                .unwrap_or_else(Utc::now),
            source: "test".to_owned(),
            kind,
        }
    }

    fn rule(trigger: TriggerSpec) -> Rule {
        Rule {
            id: "test".to_owned(),
            description: String::new(),
            enabled: true,
            priority: 10,
            cooldown: Duration::ZERO,
            sustain_for: Duration::ZERO,
            once_per_boot: false,
            on_sensor_failure: SensorFailurePolicy::Ignore,
            trigger,
            when: None,
            actions: vec![ActionSpec::Notify {
                title: "test".to_owned(),
                message: "matched".to_owned(),
                urgency: NotificationUrgency::Normal,
            }],
        }
    }

    #[test]
    fn matches_recursive_file_rule() {
        let mut engine = PolicyEngine::new(
            vec![rule(TriggerSpec::File {
                path: PathBuf::from("/srv/secure"),
                operations: vec![FileOperation::Delete],
                recursive: true,
            })],
            "normal",
        );
        let plans = engine.handle(&event_at(
            EventKind::File {
                path: PathBuf::from("/srv/secure/record.txt"),
                operation: FileOperation::Delete,
            },
            100,
        ));
        assert_eq!(plans.len(), 1);
    }

    #[test]
    fn sequence_requires_order() {
        let mut engine = PolicyEngine::new(
            vec![rule(TriggerSpec::Sequence {
                steps: vec![
                    TriggerSpec::Manual {
                        name: "alpha".to_owned(),
                    },
                    TriggerSpec::Manual {
                        name: "bravo".to_owned(),
                    },
                ],
                within: Duration::from_secs(5),
            })],
            "normal",
        );
        assert!(
            engine
                .handle(&event_at(
                    EventKind::Manual {
                        name: "alpha".to_owned(),
                    },
                    100,
                ))
                .is_empty()
        );
        assert_eq!(
            engine
                .handle(&event_at(
                    EventKind::Manual {
                        name: "bravo".to_owned(),
                    },
                    103,
                ))
                .len(),
            1
        );
    }

    #[test]
    fn higher_priority_action_wins_conflict() {
        let mut low = rule(TriggerSpec::Tick);
        low.id = "low".to_owned();
        low.priority = 1;
        low.actions = vec![ActionSpec::NetworkIsolation { enabled: false }];
        let mut high = rule(TriggerSpec::Tick);
        high.id = "high".to_owned();
        high.priority = 100;
        high.actions = vec![ActionSpec::NetworkIsolation { enabled: true }];
        let mut engine = PolicyEngine::new(vec![low, high], "normal");
        let plans = engine.handle(&event_at(EventKind::Tick, 100));
        assert_eq!(plans.len(), 1);
        assert!(matches!(
            plans[0].action,
            ActionSpec::NetworkIsolation { enabled: true }
        ));
    }
}
