//! Error types for the transport and test layers.
//!
//! Every failure that can surface from a [`Transport`](crate::Transport)
//! collapses into one of four variants:
//!
//! * [`TransportError::ServerStartup`] — the subprocess refused to start,
//!   died before `initialize`, or gave us no stdin/stdout handle.
//! * [`TransportError::Protocol`] — wire-level contract violation:
//!   malformed JSON-RPC, unexpected id, wrong protocol version, or a
//!   server-error reply.
//! * [`TransportError::Timeout`] — per-request deadline elapsed. Carries
//!   the actual elapsed wall-clock.
//! * [`TransportError::ResponseTooLarge`] — a single response (or SSE
//!   event) crossed [`crate::DEFAULT_MAX_RESPONSE_BYTES`]. Raised before
//!   the oversized payload is parsed, so the scanner can never OOM on it.
//!
//! Every stdio error carries a [`StderrTail`] — the last ~20 stderr lines
//! captured by the pump thread — because the most common reason for a
//! server to die mid-handshake is an uncaught exception or crash trace
//! printed to stderr. Surfacing it directly saves a diagnosis round-trip.

use std::io;
use std::time::Duration;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, TransportError>;

/// Container for the tail of a subprocess stderr stream.
///
/// Built by the stdio transport's stderr pump thread; empty for HTTP where
/// there is no subprocess. Limited to 20 lines in practice (see
/// `src/transport/stdio.rs`) — we treat the contents as opaque here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StderrTail {
    pub lines: Vec<String>,
}

impl StderrTail {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    pub fn join(&self) -> String {
        self.lines.join("\n")
    }
}

impl std::fmt::Display for StderrTail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_empty() {
            write!(f, "<no stderr>")
        } else {
            write!(f, "{}", self.join())
        }
    }
}

/// Every failure a transport can surface to the scan layer.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Process spawn or startup failure — `Popen` failed, stdin missing,
    /// process already dead, or binary not on `$PATH`.
    #[error("failed to start MCP server: {reason}\nstderr:\n{stderr_tail}")]
    ServerStartup {
        reason: String,
        stderr_tail: StderrTail,
        #[source]
        source: Option<io::Error>,
    },

    /// Malformed JSON-RPC, unexpected response id, unsupported protocol
    /// version, server-error reply, or any other contract violation.
    #[error("protocol error: {reason}\nstderr:\n{stderr_tail}")]
    Protocol {
        reason: String,
        stderr_tail: StderrTail,
    },

    /// Deadline elapsed before a response arrived. `elapsed` is the actual
    /// wall-clock duration the main thread waited.
    #[error("transport timeout after {elapsed:.3?} waiting for {method}\nstderr:\n{stderr_tail}")]
    Timeout {
        method: String,
        elapsed: Duration,
        stderr_tail: StderrTail,
    },

    /// A single JSON-RPC response (or SSE event / session total for the HTTP
    /// transport) exceeded the configured hard cap.
    ///
    /// This variant is **always** raised by the transport itself before the
    /// oversized payload is parsed — the purpose is to protect the scanner
    /// from OOM and to give agents a clear, actionable error instead of an
    /// ambiguous stall.
    #[error(
        "response to {method} is {size} bytes, exceeds limit of {limit} bytes (raise with --max-response-bytes)"
    )]
    ResponseTooLarge {
        method: String,
        size: u64,
        limit: u64,
    },

    /// An I/O error that could not be classified as any of the above (e.g.
    /// a `write!` to the child's stdin failing while framing a request).
    #[error("transport I/O error: {0}")]
    Io(#[from] io::Error),
}

impl TransportError {
    /// Convenience constructor for protocol errors that do not have a
    /// stderr tail handy (e.g. HTTP transport).
    pub fn protocol(reason: impl Into<String>) -> Self {
        Self::Protocol {
            reason: reason.into(),
            stderr_tail: StderrTail::new(),
        }
    }

    /// Convenience constructor for startup errors without a captured stderr.
    pub fn startup(reason: impl Into<String>, source: Option<io::Error>) -> Self {
        Self::ServerStartup {
            reason: reason.into(),
            stderr_tail: StderrTail::new(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_too_large_message_mentions_limit_and_size() {
        let err = TransportError::ResponseTooLarge {
            method: "tools/list".to_string(),
            size: 2_097_152,
            limit: 1_048_576,
        };
        let msg = err.to_string();
        assert!(msg.contains("tools/list"));
        assert!(msg.contains("2097152"));
        assert!(msg.contains("1048576"));
        assert!(msg.contains("--max-response-bytes"));
    }

    #[test]
    fn stderr_tail_display_handles_empty() {
        let tail = StderrTail::new();
        assert_eq!(tail.to_string(), "<no stderr>");
    }

    #[test]
    fn stderr_tail_joins_lines_with_newlines() {
        let tail = StderrTail {
            lines: vec!["first".into(), "second".into()],
        };
        assert_eq!(tail.to_string(), "first\nsecond");
    }

    #[test]
    fn io_error_auto_converts_via_from() {
        let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed");
        let err: TransportError = io_err.into();
        assert!(matches!(err, TransportError::Io(_)));
    }

    #[test]
    fn protocol_helper_leaves_stderr_tail_empty() {
        let err = TransportError::protocol("unexpected message");
        match err {
            TransportError::Protocol {
                reason,
                stderr_tail,
            } => {
                assert_eq!(reason, "unexpected message");
                assert!(stderr_tail.is_empty());
            }
            other => panic!("expected Protocol, got {other:?}"),
        }
    }
}
