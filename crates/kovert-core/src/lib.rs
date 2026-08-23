//! Shared policy, configuration, event, and IPC types for Kovert.

pub mod config;
pub mod engine;
pub mod event;
pub mod ipc;
pub mod validation;

pub use config::{ActionSpec, Config, Rule, TriggerSpec};
pub use engine::{ActionPlan, PolicyEngine};
pub use event::{Event, EventKind, SystemSnapshot};
pub use validation::{ValidationError, validate_config};
