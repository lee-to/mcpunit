//! JSON-RPC 2.0 framing primitives shared by every transport.
//!
//! The core type is [`JsonRpcMessage`], an `untagged` enum that
//! discriminates between `Response`, `Request` (server-initiated), and
//! `Notification` based on which fields are present. Serde resolves
//! variant order at compile time and the tests in this module freeze the
//! exact discrimination rules — forgetting to add a new variant to the
//! cascade will fail CI rather than silently misroute a message.

use serde::{Deserialize, Serialize};

/// JSON-RPC request id — MCP servers may use either ints or strings, but
/// mcpunit only ever sends ints (a monotonic `u64` from
/// [`crate::transport::RequestIdGenerator`]). Both shapes are accepted on
/// input so a well-formed server reply round-trips.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcId {
    Int(i64),
    Str(String),
}

impl JsonRpcId {
    pub fn as_int(&self) -> Option<i64> {
        match self {
            JsonRpcId::Int(v) => Some(*v),
            JsonRpcId::Str(_) => None,
        }
    }
}

impl From<u64> for JsonRpcId {
    fn from(value: u64) -> Self {
        JsonRpcId::Int(value as i64)
    }
}

/// JSON-RPC error payload returned inside `Response::error`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Any JSON-RPC 2.0 message mcpunit may observe on the wire.
///
/// `#[serde(untagged)]` tries each variant in declaration order and picks
/// the first one whose required fields all match. Order matters:
///
/// 1. **`Request`** — has `id` AND `method` AND `jsonrpc`. Matched first so a
///    server-initiated request never gets misclassified as a Response.
/// 2. **`Notification`** — has `method` AND `jsonrpc` but no `id`.
/// 3. **`Response`** — has `id` AND `jsonrpc`; `result` / `error` are
///    optional at the schema level because a response must carry exactly one
///    of them but serde can't express that cleanly with untagged enums.
///    The transport layer validates the `result`/`error` invariant after
///    deserialisation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcMessage {
    Request {
        jsonrpc: JsonRpcVersion,
        id: JsonRpcId,
        method: String,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        params: Option<serde_json::Value>,
    },
    Notification {
        jsonrpc: JsonRpcVersion,
        method: String,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        params: Option<serde_json::Value>,
    },
    Response {
        jsonrpc: JsonRpcVersion,
        id: JsonRpcId,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<serde_json::Value>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<JsonRpcError>,
    },
}

/// Strongly-typed `"2.0"` marker so serde refuses to parse messages with a
/// missing or wrong `jsonrpc` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JsonRpcVersion {
    #[serde(rename = "2.0")]
    V2,
}

impl JsonRpcMessage {
    /// Serialise an outbound request for a method.
    pub fn request(id: u64, method: impl Into<String>, params: serde_json::Value) -> Self {
        JsonRpcMessage::Request {
            jsonrpc: JsonRpcVersion::V2,
            id: JsonRpcId::Int(id as i64),
            method: method.into(),
            params: Some(params),
        }
    }

    /// Serialise an outbound notification (no response expected).
    pub fn notification(method: impl Into<String>, params: serde_json::Value) -> Self {
        JsonRpcMessage::Notification {
            jsonrpc: JsonRpcVersion::V2,
            method: method.into(),
            params: Some(params),
        }
    }

    /// Serialise a JSON-RPC error reply to a server-initiated request.
    pub fn error_response(id: JsonRpcId, code: i64, message: impl Into<String>) -> Self {
        JsonRpcMessage::Response {
            jsonrpc: JsonRpcVersion::V2,
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    /// Serialise a bare `{"result":{}}` reply — used for auto-acking
    /// server-initiated `ping` calls during discovery.
    pub fn empty_result(id: JsonRpcId) -> Self {
        JsonRpcMessage::Response {
            jsonrpc: JsonRpcVersion::V2,
            id,
            result: Some(serde_json::json!({})),
            error: None,
        }
    }
}

/// Encode a message as a single newline-terminated JSON line (the wire
/// format for stdio transport and for single-JSON HTTP responses).
pub fn encode_line(msg: &JsonRpcMessage) -> Result<String, serde_json::Error> {
    let mut out = serde_json::to_string(msg)?;
    out.push('\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_response_with_result() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        let msg: JsonRpcMessage = serde_json::from_str(raw).unwrap();
        match msg {
            JsonRpcMessage::Response {
                id, result, error, ..
            } => {
                assert_eq!(id.as_int(), Some(1));
                assert!(result.is_some());
                assert!(error.is_none());
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn parses_response_with_error() {
        let raw =
            r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"method not found"}}"#;
        let msg: JsonRpcMessage = serde_json::from_str(raw).unwrap();
        match msg {
            JsonRpcMessage::Response {
                id, result, error, ..
            } => {
                assert_eq!(id.as_int(), Some(7));
                assert!(result.is_none());
                let err = error.unwrap();
                assert_eq!(err.code, -32601);
                assert_eq!(err.message, "method not found");
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn parses_server_initiated_request() {
        let raw = r#"{"jsonrpc":"2.0","id":42,"method":"ping","params":{}}"#;
        let msg: JsonRpcMessage = serde_json::from_str(raw).unwrap();
        match msg {
            JsonRpcMessage::Request { id, method, .. } => {
                assert_eq!(id.as_int(), Some(42));
                assert_eq!(method, "ping");
            }
            other => panic!("expected Request, got {other:?}"),
        }
    }

    #[test]
    fn parses_notification() {
        let raw = r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#;
        let msg: JsonRpcMessage = serde_json::from_str(raw).unwrap();
        match msg {
            JsonRpcMessage::Notification { method, .. } => {
                assert_eq!(method, "notifications/initialized");
            }
            other => panic!("expected Notification, got {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_jsonrpc_version() {
        let raw = r#"{"jsonrpc":"1.0","id":1,"result":{}}"#;
        assert!(serde_json::from_str::<JsonRpcMessage>(raw).is_err());
    }

    #[test]
    fn encode_line_appends_newline() {
        let msg = JsonRpcMessage::request(1, "initialize", serde_json::json!({"a": 1}));
        let line = encode_line(&msg).unwrap();
        assert!(line.ends_with('\n'));
        assert!(line.contains("\"method\":\"initialize\""));
        assert!(line.contains("\"id\":1"));
        assert!(line.contains("\"jsonrpc\":\"2.0\""));
    }

    #[test]
    fn notification_has_no_id_field() {
        let msg = JsonRpcMessage::notification("notifications/initialized", serde_json::json!({}));
        let encoded = serde_json::to_string(&msg).unwrap();
        assert!(!encoded.contains("\"id\""));
        assert!(encoded.contains("\"method\":\"notifications/initialized\""));
    }

    #[test]
    fn error_response_carries_error_field() {
        let msg = JsonRpcMessage::error_response(JsonRpcId::Int(5), -32601, "method not found");
        let encoded = serde_json::to_string(&msg).unwrap();
        assert!(encoded.contains("\"code\":-32601"));
        assert!(encoded.contains("\"message\":\"method not found\""));
    }

    #[test]
    fn empty_result_uses_empty_object() {
        let msg = JsonRpcMessage::empty_result(JsonRpcId::Int(99));
        let encoded = serde_json::to_string(&msg).unwrap();
        assert!(encoded.contains("\"result\":{}"));
    }
}
