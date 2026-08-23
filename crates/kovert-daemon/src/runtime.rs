use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use kovert_actions::{ActionEffect, ActionExecutor, ExecutionContext};
use kovert_core::config::Config;
use kovert_core::event::{Event, EventKind};
use kovert_core::ipc::{Request, Response};
use kovert_core::{ActionPlan, PolicyEngine};
use kovert_sensors::SensorHub;
use serde_json::json;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::audit::AuditStore;
use crate::config_loader;

pub struct ControlMessage {
    pub request: Request,
    pub response: oneshot::Sender<Response>,
}

pub struct Runtime {
    config_path: PathBuf,
    allow_unsafe_config: bool,
    config: Arc<Config>,
    engine: PolicyEngine,
    executor: ActionExecutor,
    audit: Arc<AuditStore>,
    event_sender: mpsc::Sender<Event>,
    event_receiver: mpsc::Receiver<Event>,
    control_receiver: mpsc::Receiver<ControlMessage>,
    sensor_handles: Vec<JoinHandle<()>>,
}

impl Runtime {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config_path: PathBuf,
        allow_unsafe_config: bool,
        config: Arc<Config>,
        audit: Arc<AuditStore>,
        event_sender: mpsc::Sender<Event>,
        event_receiver: mpsc::Receiver<Event>,
        control_receiver: mpsc::Receiver<ControlMessage>,
        sensor_handles: Vec<JoinHandle<()>>,
    ) -> Result<Self> {
        let configured_mode = config
            .modes
            .iter()
            .find(|mode| mode.initial)
            .or_else(|| config.modes.first())
            .map(|mode| mode.name.clone())
            .unwrap_or_else(|| "normal".to_owned());
        let stored_mode = audit.get_state("mode")?;
        let initial_mode = stored_mode
            .filter(|mode| config.modes.is_empty() || config.modes.iter().any(|item| item.name == *mode))
            .unwrap_or(configured_mode);
        let mut engine = PolicyEngine::new(config.rules.clone(), initial_mode);
        let recovery = audit
            .get_state("recovery_mode")?
            .is_some_and(|value| value == "true");
        engine.set_recovery_mode(recovery);
        let executor = executor_for(&config);
        Ok(Self {
            config_path,
            allow_unsafe_config,
            config,
            engine,
            executor,
            audit,
            event_sender,
            event_receiver,
            control_receiver,
            sensor_handles,
        })
    }

    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        self.audit.append(
            None,
            "daemon_started",
            None,
            &json!({
                "version": env!("CARGO_PKG_VERSION"),
                "dry_run": self.config.daemon.dry_run,
                "recovery_mode": self.engine.recovery_mode(),
            }),
        )?;
        info!(
            dry_run = self.config.daemon.dry_run,
            recovery_mode = self.engine.recovery_mode(),
            "Kovert runtime started"
        );
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                event = self.event_receiver.recv() => {
                    let Some(event) = event else { break; };
                    if let Err(error) = self.process_event(event).await {
                        error!(%error, "event processing failed");
                    }
                }
                control = self.control_receiver.recv() => {
                    let Some(control) = control else { break; };
                    let response = self.handle_control(control.request).await;
                    let _ = control.response.send(response);
                }
            }
        }
        for handle in &self.sensor_handles {
            handle.abort();
        }
        self.audit
            .append(None, "daemon_stopped", None, &json!({"graceful": true}))?;
        info!("Kovert runtime stopped");
        Ok(())
    }

    async fn process_event(&mut self, event: Event) -> Result<usize> {
        let event_id = event.id.to_string();
        self.audit.append(
            Some(&event_id),
            "event",
            None,
            &serde_json::to_value(&event)?,
        )?;
        let plans = self.engine.handle(&event);
        let count = plans.len();
        for plan in plans {
            self.execute_plan(&event, plan).await?;
        }
        Ok(count)
    }

    async fn execute_plan(&mut self, event: &Event, plan: ActionPlan) -> Result<()> {
        let event_id = event.id.to_string();
        let action_bytes = serde_json::to_vec(&plan.action)?;
        let action_hash = blake3::hash(&action_bytes).to_hex().to_string();
        if self
            .audit
            .action_completed(&event_id, &plan.rule_id, &action_hash)?
        {
            warn!(
                event_id,
                rule = plan.rule_id,
                "skipping previously completed action"
            );
            return Ok(());
        }
        self.audit.record_action(
            &event_id,
            &plan.rule_id,
            &action_hash,
            "started",
            None,
        )?;
        self.audit.append(
            Some(&event_id),
            "action_started",
            Some(&plan.rule_id),
            &serde_json::to_value(&plan.action)?,
        )?;

        match self.executor.execute(&plan.action, event).await {
            Ok(outcome) => {
                let outcome_value = serde_json::to_value(&outcome)?;
                let status = if outcome.success { "succeeded" } else { "failed" };
                self.audit.record_action(
                    &event_id,
                    &plan.rule_id,
                    &action_hash,
                    status,
                    Some(&outcome_value),
                )?;
                self.audit.append(
                    Some(&event_id),
                    if outcome.success {
                        "action_succeeded"
                    } else {
                        "action_failed"
                    },
                    Some(&plan.rule_id),
                    &outcome_value,
                )?;
                if outcome.success && !outcome.dry_run {
                    self.apply_effect(outcome.effect)?;
                }
                if !outcome.success {
                    warn!(rule = plan.rule_id, message = outcome.message, "action failed");
                }
            }
            Err(error) => {
                let outcome = json!({"error": error.to_string()});
                self.audit.record_action(
                    &event_id,
                    &plan.rule_id,
                    &action_hash,
                    "failed",
                    Some(&outcome),
                )?;
                self.audit.append(
                    Some(&event_id),
                    "action_failed",
                    Some(&plan.rule_id),
                    &outcome,
                )?;
                warn!(rule = plan.rule_id, %error, "action execution failed");
            }
        }
        Ok(())
    }

    fn apply_effect(&mut self, effect: ActionEffect) -> Result<()> {
        match effect {
            ActionEffect::SetMode { mode } => {
                self.engine.set_mode(mode.clone());
                self.audit.set_state("mode", &mode)?;
            }
            ActionEffect::NetworkIsolation { enabled } => {
                self.audit
                    .set_state("network_isolated", if enabled { "true" } else { "false" })?;
            }
            ActionEffect::None => {}
        }
        Ok(())
    }

    async fn handle_control(&mut self, request: Request) -> Response {
        match self.handle_control_result(request).await {
            Ok(response) => response,
            Err(error) => {
                warn!(%error, "control request failed");
                Response::error(error.to_string())
            }
        }
    }

    async fn handle_control_result(&mut self, request: Request) -> Result<Response> {
        match request {
            Request::Status => Ok(Response::success(
                "Kovert is running",
                Some(json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "dry_run": self.config.daemon.dry_run,
                    "recovery_mode": self.engine.recovery_mode(),
                    "rules": self.engine.rules().len(),
                    "snapshot": self.engine.snapshot(),
                })),
            )),
            Request::Rules => Ok(Response::success(
                "active rules",
                Some(serde_json::to_value(self.engine.rules())?),
            )),
            Request::Audit { limit } => Ok(Response::success(
                "audit records",
                Some(serde_json::to_value(self.audit.recent(limit)?)?),
            )),
            Request::Reload => {
                self.reload()?;
                Ok(Response::success("configuration reloaded", None))
            }
            Request::Trigger { name } => {
                let event = Event::new("manual", EventKind::Manual { name });
                let count = self.process_event(event).await?;
                Ok(Response::success(
                    format!("manual event processed; {count} action(s) planned"),
                    None,
                ))
            }
            Request::Simulate { event } => {
                let mut simulated = self.engine.clone();
                let plans = simulated.handle(&event);
                Ok(Response::success(
                    format!("simulation produced {} action(s)", plans.len()),
                    Some(json!({
                        "plans": plans.iter().map(|plan| json!({
                            "rule_id": plan.rule_id,
                            "priority": plan.priority,
                            "action": plan.action,
                        })).collect::<Vec<_>>()
                    })),
                ))
            }
            Request::SetMode { mode } => {
                if !self.config.modes.iter().any(|item| item.name == mode) {
                    return Err(anyhow!("unknown security mode {mode}"));
                }
                self.engine.set_mode(mode.clone());
                self.audit.set_state("mode", &mode)?;
                self.audit
                    .append(None, "mode_changed", None, &json!({"mode": mode}))?;
                Ok(Response::success("security mode changed", None))
            }
            Request::Recovery { enabled } => {
                self.engine.set_recovery_mode(enabled);
                self.audit
                    .set_state("recovery_mode", if enabled { "true" } else { "false" })?;
                self.audit.append(
                    None,
                    "recovery_mode_changed",
                    None,
                    &json!({"enabled": enabled}),
                )?;
                Ok(Response::success(
                    if enabled {
                        "recovery mode enabled; automatic rules are suspended"
                    } else {
                        "recovery mode disabled; automatic rules are active"
                    },
                    None,
                ))
            }
            Request::VerifyAudit => {
                let verified = self.audit.verify()?;
                Ok(Response::success(
                    format!("verified {verified} audit record(s)"),
                    Some(json!({"verified": verified})),
                ))
            }
        }
    }

    fn reload(&mut self) -> Result<()> {
        let config = Arc::new(config_loader::load(
            &self.config_path,
            self.allow_unsafe_config,
        )?);
        let new_handles = SensorHub::new(config.clone(), self.config_path.clone())
            .start(self.event_sender.clone())
            .context("restart sensors")?;
        for handle in &self.sensor_handles {
            handle.abort();
        }
        self.sensor_handles = new_handles;
        self.engine.replace_rules(config.rules.clone());
        self.executor = executor_for(&config);
        self.config = config;
        self.audit.append(
            None,
            "configuration_reloaded",
            None,
            &json!({"rules": self.engine.rules().len()}),
        )?;
        Ok(())
    }
}

fn executor_for(config: &Config) -> ActionExecutor {
    ActionExecutor::new(ExecutionContext {
        dry_run: config.daemon.dry_run,
        command_timeout: config.daemon.command_timeout,
        allowed_executables: config
            .daemon
            .allowed_executables
            .iter()
            .cloned()
            .collect::<HashSet<_>>(),
        managed_processes: config
            .daemon
            .managed_processes
            .iter()
            .cloned()
            .collect::<HashSet<_>>(),
        vaults: config.vaults.clone(),
        desktop_notifications: config.daemon.desktop_notifications,
    })
}
