//! Transport abstraction: anything that can speak JSON-RPC to an MCP server.
//!
//! Two concrete implementations live alongside this module:
//!
//! * [`stdio`] — spawn a subprocess and frame messages with
//!   newline-delimited JSON-RPC over its stdin/stdout.
//! * [`http`] — Streamable HTTP (MCP 2025-03-26+) where the server responds
//!   either with a single JSON body or with an SSE stream.
//!
//! Both implementations share framing primitives from [`jsonrpc`] and both
//! enforce a `max_response_bytes` hard cap **before** parsing each inbound
//! message. Parse-time enforcement means rules and reporters never see an
//! oversized payload — the scanner cannot OOM on a pathological server.
//!
//! Everything is synchronous by design: `std::thread` + `mpsc` for stdio,
//! blocking `ureq` for HTTP. No `tokio`, no `async fn`, no runtime.

pub mod http;
pub mod jsonrpc;
pub mod stdio;

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

use crate::error::Result;
use crate::models::{NormalizedServer, NormalizedTool};
use crate::{MCP_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS};

pub use jsonrpc::{JsonRpcError, JsonRpcId, JsonRpcMessage};

/// Information about the client, sent as `clientInfo` in `initialize`.
///
/// Wire shape is `{"name": "...", "version": "..."}` — the minimum the
/// MCP spec requires. Servers that sniff the client identity will see
/// `mcpunit` + this crate's version.
#[derive(Debug, Clone, Serialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

impl ClientInfo {
    /// Default client identity: `mcpunit` + crate version.
    pub fn default_for_crate() -> Self {
        Self {
            name: crate::TOOL_NAME.to_string(),
            version: crate::PACKAGE_VERSION.to_string(),
        }
    }
}

/// Outcome of a successful `initialize` round-trip.
///
/// Only the fields rules actually read are modelled. Anything else in the
/// server's response is preserved in `raw` for debugging and for passthrough
/// into the normalized server metadata.
#[derive(Debug, Clone)]
pub struct InitializeResult {
    pub protocol_version: String,
    pub server_name: Option<String>,
    pub server_version: Option<String>,
    pub instructions: Option<String>,
    pub raw: serde_json::Value,
}

/// Anything that can talk JSON-RPC to an MCP server.
///
/// Implementations own the underlying connection (subprocess, HTTP client
/// session, etc.) and surface the handshake + discovery surface as
/// high-level methods. Response bytes observed on the wire are forwarded
/// into `NormalizedServer::response_sizes` so the
/// `response_too_large` rule can report on them.
pub trait Transport {
    /// Perform the MCP `initialize` handshake and return the server's
    /// advertised metadata.
    fn initialize(&mut self, client_info: ClientInfo) -> Result<InitializeResult>;

    /// Send the fire-and-forget `notifications/initialized` notification.
    fn notify_initialized(&mut self) -> Result<()>;

    /// Enumerate tools via one or more `tools/list` calls, following
    /// `nextCursor` pagination if present.
    fn list_tools(&mut self) -> Result<Vec<NormalizedTool>>;

    /// Populate and return a [`NormalizedServer`] by chaining the above
    /// methods in the right order. Default impl covers the common case;
    /// transports that need to short-circuit (e.g. HTTP with a cached
    /// session) can override.
    fn scan(&mut self, target: String) -> Result<NormalizedServer> {
        let client_info = ClientInfo::default_for_crate();
        let init = self.initialize(client_info)?;
        self.notify_initialized()?;
        let tools = self.list_tools()?;

        let mut server = NormalizedServer::new(target);
        server.name = init.server_name.clone();
        server.version = init.server_version.clone();
        server.tools = tools;
        if let Some(instructions) = init.instructions {
            server.metadata.insert(
                "instructions".to_string(),
                serde_json::Value::String(instructions),
            );
        }
        server.metadata.insert(
            "protocol_version".to_string(),
            serde_json::Value::String(init.protocol_version),
        );
        server.response_sizes.extend(self.take_response_sizes());
        Ok(server)
    }

    /// Drain and return the `(method → bytes)` map recorded since the last
    /// call. The `scan` default impl uses this to populate
    /// `NormalizedServer::response_sizes`.
    fn take_response_sizes(&mut self) -> std::collections::BTreeMap<String, u64>;

    /// Release the underlying connection (kill subprocess, drop HTTP session).
    /// Implementations must be idempotent: calling `shutdown` twice is safe.
    fn shutdown(&mut self) -> Result<()>;
}

/// Validate a protocol version string returned by the server's `initialize`
/// response. Returns the supported version the server chose, or an error.
pub fn validate_protocol_version(server_version: &str) -> Result<&'static str> {
    SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .copied()
        .find(|v| *v == server_version)
        .ok_or_else(|| {
            crate::error::TransportError::protocol(format!(
                "server advertised unsupported protocol version {server_version:?}; \
                 mcpunit supports {:?} (client sent {MCP_PROTOCOL_VERSION})",
                SUPPORTED_PROTOCOL_VERSIONS
            ))
        })
}

/// Monotonic JSON-RPC request id generator.
///
/// Each transport owns one of these; ids start at 1 and strictly increase.
/// Using `AtomicU64` keeps the generator thread-safe which matters for the
/// stdio transport where the pump threads may read before the main thread
/// writes the next request.
#[derive(Debug, Default)]
pub struct RequestIdGenerator {
    next: AtomicU64,
}

impl RequestIdGenerator {
    pub fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
        }
    }

    /// Reserve the next id. Returns `1` on the first call.
    pub fn next_id(&self) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        if id == 0 {
            // Overflow wrapped; extraordinarily unlikely in practice because
            // we would need 2^64 requests in a single session. Reset to 1 so
            // no caller ever observes a `0` id (the spec uses 1-based ids).
            self.next.store(2, Ordering::Relaxed);
            1
        } else {
            id
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TransportError;

    #[test]
    fn request_id_generator_starts_at_one_and_increments() {
        let gen = RequestIdGenerator::new();
        assert_eq!(gen.next_id(), 1);
        assert_eq!(gen.next_id(), 2);
        assert_eq!(gen.next_id(), 3);
    }

    #[test]
    fn validate_protocol_version_accepts_supported() {
        for version in SUPPORTED_PROTOCOL_VERSIONS {
            assert_eq!(validate_protocol_version(version).unwrap(), *version);
        }
    }

    #[test]
    fn validate_protocol_version_rejects_unknown() {
        let err = validate_protocol_version("1999-01-01").unwrap_err();
        match err {
            TransportError::Protocol { reason, .. } => {
                assert!(reason.contains("1999-01-01"));
                assert!(reason.contains("mcpunit supports"));
            }
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn client_info_default_uses_crate_constants() {
        let info = ClientInfo::default_for_crate();
        assert_eq!(info.name, crate::TOOL_NAME);
        assert_eq!(info.version, crate::PACKAGE_VERSION);
    }
}
