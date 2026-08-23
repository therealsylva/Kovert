use serde::{Deserialize, Serialize};

use crate::event::Event;

/// Current local control protocol version.
pub const IPC_VERSION: u32 = 1;

/// Versioned request envelope sent over the local control socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    pub version: u32,
    pub request: Request,
}

impl RequestEnvelope {
    pub fn new(request: Request) -> Self {
        Self {
            version: IPC_VERSION,
            request,
        }
    }
}

/// Versioned request accepted by the local Unix socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Status,
    Rules,
    Audit { limit: usize },
    Reload,
    Trigger { name: String },
    Simulate { event: Event },
    SetMode { mode: String },
    Recovery { enabled: bool },
    VerifyAudit,
}

/// Versioned response sent over the local Unix socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u32,
    pub ok: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl Response {
    pub fn success(message: impl Into<String>, data: Option<serde_json::Value>) -> Self {
        Self {
            version: IPC_VERSION,
            ok: true,
            message: message.into(),
            data,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            version: IPC_VERSION,
            ok: false,
            message: message.into(),
            data: None,
        }
    }
}
