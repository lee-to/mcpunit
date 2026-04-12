//! mcpunit — CI-first deterministic quality audit for MCP servers.
//!
//! This crate scans an MCP server over a supported transport (`stdio` or
//! Streamable HTTP), runs a static registry of rules against its advertised
//! tools, and emits JSON / SARIF / terminal / Markdown reports.
//!
//! The public surface is intentionally small: higher-level orchestration lives
//! in [`bin/mcpunit.rs`](../bin/mcpunit.rs) and downstream consumers can call
//! into [`scan`] directly if they need in-process scanning.

pub mod error;
pub mod models;
pub mod reporters;
pub mod rules;
pub mod scoring;
pub mod transport;

pub use error::{Result as TransportResult, StderrTail, TransportError};
pub use models::{
    Finding, FindingCategory, MetadataMap, NormalizedServer, NormalizedTool, RiskCategory,
    ScoreBucket, Severity,
};
pub use transport::{
    ClientInfo, InitializeResult, JsonRpcError, JsonRpcId, JsonRpcMessage, RequestIdGenerator,
    Transport,
};

pub const PRODUCT_NAME: &str = "mcpunit";
pub const TOOL_NAME: &str = "mcpunit";
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const REPORT_SCHEMA_ID: &str = "https://mcpunit.cutcode.dev/schema/audit/v1";
pub const REPORT_SCHEMA_VERSION: &str = "1";

/// Default hard cap for a single JSON-RPC response or SSE event (1 MiB).
///
/// Enforced by every transport. Matches the default value surfaced on the CLI
/// as `--max-response-bytes`. Agents calling into `mcpunit` as a library
/// should override this via `ScanOptions` when scanning servers that are
/// expected to return large payloads.
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// MCP protocol version advertised by this client during `initialize`.
pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";

/// Protocol versions this client is willing to accept in an `initialize`
/// response. Order matters only for logging; presence in the slice is the
/// compatibility predicate.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

pub use scoring::{scan as scan_registry, Report, RuleDescriptor, ScoreBreakdown};
