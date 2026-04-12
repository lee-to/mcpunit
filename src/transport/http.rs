//! Streamable HTTP transport (MCP 2025-03-26+).
//!
//! The Streamable HTTP spec lets an MCP server answer a single POST either
//! with:
//!
//! * `Content-Type: application/json` — a single JSON-RPC message (response,
//!   notification, or request), OR
//! * `Content-Type: text/event-stream` — an SSE stream carrying one or more
//!   JSON-RPC messages before the stream closes.
//!
//! Both paths funnel through the same [`read_response`] function which:
//!
//! 1. Enforces `max_response_bytes` **before** handing bytes to `serde_json`.
//!    For SSE each event is capped individually; for a single JSON body the
//!    whole body is capped in one shot.
//! 2. Auto-acks server-initiated `ping` requests by POSTing back an empty
//!    result, mirroring the stdio path for protocol consistency.
//! 3. Threads the `Mcp-Session-Id` header through every subsequent request
//!    once the server advertises one on `initialize`.
//!
//! We deliberately stay on the **blocking** `ureq` client. No async runtime
//! is a hard constraint from the research doc — SSE parsing here is a tiny
//! hand-rolled loop rather than an `eventsource-client`/`tokio` dep.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read};
use std::time::Duration;

use serde_json::Value;
use tracing::{debug, info, trace, warn};

use crate::error::{Result, StderrTail, TransportError};
use crate::models::{MetadataMap, NormalizedTool};
use crate::transport::jsonrpc::{JsonRpcId, JsonRpcMessage, JsonRpcVersion};
use crate::transport::{
    validate_protocol_version, ClientInfo, InitializeResult, RequestIdGenerator, Transport,
};
use crate::{DEFAULT_MAX_RESPONSE_BYTES, MCP_PROTOCOL_VERSION};

/// Default per-request timeout for HTTP. Matches the stdio default.
pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Accept header advertised on every POST so servers pick the right response
/// flavour.
const ACCEPT_HEADER: &str = "application/json, text/event-stream";
const SESSION_ID_HEADER: &str = "Mcp-Session-Id";

/// Configuration for a Streamable HTTP MCP endpoint.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Target URL (must be a full `http[s]://` URL that accepts POSTs).
    pub url: String,
    /// Extra headers set on every request (e.g. `Authorization: Bearer ...`).
    pub headers: Vec<(String, String)>,
    /// Per-request timeout.
    pub timeout: Duration,
    /// Hard cap enforced per JSON body and per SSE event before JSON parse.
    pub max_response_bytes: u64,
    /// Multiplier on `max_response_bytes` for the cumulative session cap.
    /// Defaults to 16 — generous enough for paginated `tools/list` responses
    /// but still bounds total memory use for a single scan.
    pub session_multiplier: u64,
}

impl HttpConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            headers: Vec::new(),
            timeout: DEFAULT_HTTP_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            session_multiplier: 16,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_response_bytes(mut self, max: u64) -> Self {
        self.max_response_bytes = max;
        self
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Reporting target string: `http:<url>`. Embedded as-is in the
    /// audit `scan.target.raw` field.
    pub fn target(&self) -> String {
        format!("http:{}", self.url)
    }

    fn session_limit(&self) -> u64 {
        self.max_response_bytes
            .saturating_mul(self.session_multiplier.max(1))
    }
}

/// Streamable HTTP transport. One instance = one logical MCP session.
#[derive(Debug)]
pub struct HttpTransport {
    config: HttpConfig,
    agent: ureq::Agent,
    session_id: Option<String>,
    id_gen: RequestIdGenerator,
    response_sizes: BTreeMap<String, u64>,
    session_bytes: u64,
}

impl HttpTransport {
    /// Build a transport around a fresh `ureq::Agent`. No network activity
    /// happens until the first `Transport` trait method is called.
    pub fn new(config: HttpConfig) -> Result<Self> {
        Self::validate_config(&config)?;
        info!(
            url = %config.url,
            timeout_ms = config.timeout.as_millis() as u64,
            max_response_bytes = config.max_response_bytes,
            "streamable http transport configured"
        );
        let agent = ureq::AgentBuilder::new()
            .timeout(config.timeout)
            .user_agent(concat!("mcpunit/", env!("CARGO_PKG_VERSION")))
            .build();
        Ok(Self {
            config,
            agent,
            session_id: None,
            id_gen: RequestIdGenerator::new(),
            response_sizes: BTreeMap::new(),
            session_bytes: 0,
        })
    }

    fn validate_config(config: &HttpConfig) -> Result<()> {
        if config.url.is_empty() {
            return Err(TransportError::startup("http url must not be empty", None));
        }
        if !(config.url.starts_with("http://") || config.url.starts_with("https://")) {
            return Err(TransportError::startup(
                format!(
                    "http url must start with http:// or https:// (got {:?})",
                    config.url
                ),
                None,
            ));
        }
        if config.timeout.is_zero() {
            return Err(TransportError::startup(
                "http timeout must be greater than zero",
                None,
            ));
        }
        if config.max_response_bytes == 0 {
            return Err(TransportError::startup(
                "http max_response_bytes must be greater than zero",
                None,
            ));
        }
        Ok(())
    }

    fn protocol_error(reason: impl Into<String>) -> TransportError {
        TransportError::Protocol {
            reason: reason.into(),
            stderr_tail: StderrTail::new(),
        }
    }

    fn build_post(&self, body_len: usize) -> ureq::Request {
        let mut req = self
            .agent
            .post(&self.config.url)
            .set("Accept", ACCEPT_HEADER)
            .set("Content-Type", "application/json")
            .set("Content-Length", &body_len.to_string());
        for (name, value) in &self.config.headers {
            req = req.set(name, value);
        }
        if let Some(sid) = self.session_id.as_deref() {
            req = req.set(SESSION_ID_HEADER, sid);
        }
        req
    }

    fn post_json(&mut self, method: &str, body: &str) -> Result<PostResponse> {
        trace!(method, bytes = body.len(), "http → server");
        let request = self.build_post(body.len());
        match request.send_string(body) {
            Ok(resp) => {
                let session_id = resp.header(SESSION_ID_HEADER).map(|s| s.to_string());
                if let Some(new_sid) = session_id.as_deref() {
                    if self.session_id.as_deref() != Some(new_sid) {
                        debug!(session_id = new_sid, "http session id assigned");
                    }
                    self.session_id = Some(new_sid.to_string());
                }
                let content_type = resp
                    .header("content-type")
                    .map(|s| s.to_ascii_lowercase())
                    .unwrap_or_default();
                let kind = classify_content_type(&content_type);
                let reader = resp.into_reader();
                Ok(PostResponse {
                    kind,
                    content_type,
                    reader,
                })
            }
            Err(ureq::Error::Status(code, resp)) => {
                let body_preview = resp.into_string().unwrap_or_default();
                Err(Self::protocol_error(format!(
                    "http {method} returned {code}: {}",
                    truncate(&body_preview, 512)
                )))
            }
            Err(ureq::Error::Transport(err)) => Err(Self::protocol_error(format!(
                "http {method} transport error: {err}"
            ))),
        }
    }

    fn record_bytes(&mut self, method: &str, size: u64) -> Result<()> {
        self.response_sizes.insert(method.to_string(), size);
        self.session_bytes = self.session_bytes.saturating_add(size);
        let limit = self.config.session_limit();
        if self.session_bytes > limit {
            warn!(
                session_bytes = self.session_bytes,
                limit, "http session total bytes exceeded limit"
            );
            return Err(TransportError::ResponseTooLarge {
                method: format!("session:{method}"),
                size: self.session_bytes,
                limit,
            });
        }
        Ok(())
    }

    fn read_single_json(
        reader: Box<dyn Read + Send + Sync + 'static>,
        max: u64,
        method: &str,
    ) -> Result<(JsonRpcMessage, u64)> {
        let cap = max.saturating_add(1);
        let mut buf = Vec::with_capacity(1024);
        reader.take(cap).read_to_end(&mut buf).map_err(|err| {
            Self::protocol_error(format!("http {method} body read failed: {err}"))
        })?;
        if (buf.len() as u64) > max {
            return Err(TransportError::ResponseTooLarge {
                method: method.to_string(),
                size: buf.len() as u64,
                limit: max,
            });
        }
        let size = buf.len() as u64;
        let msg: JsonRpcMessage = serde_json::from_slice(&buf).map_err(|err| {
            Self::protocol_error(format!(
                "http {method} response body is not valid JSON-RPC: {err}"
            ))
        })?;
        Ok((msg, size))
    }

    /// Drive one request end-to-end: POST the body, then loop on whatever the
    /// server sent back (single JSON or SSE events) until we see the response
    /// that matches `expected_id`. Ping requests are auto-acked mid-stream.
    fn do_request(
        &mut self,
        method: &str,
        params: Option<Value>,
        expected_id: u64,
    ) -> Result<Value> {
        let outgoing = JsonRpcMessage::Request {
            jsonrpc: JsonRpcVersion::V2,
            id: JsonRpcId::Int(expected_id as i64),
            method: method.to_string(),
            params,
        };
        let body = serde_json::to_string(&outgoing).map_err(|err| {
            Self::protocol_error(format!("failed to serialise http {method} body: {err}"))
        })?;

        let response = self.post_json(method, &body)?;
        let max = self.config.max_response_bytes;

        match response.kind {
            ContentKind::Json => {
                let (msg, size) = Self::read_single_json(response.reader, max, method)?;
                self.record_bytes(method, size)?;
                self.handle_message(method, expected_id, msg)
            }
            ContentKind::Sse => self.drive_sse_stream(method, expected_id, response.reader),
            ContentKind::Unknown => Err(Self::protocol_error(format!(
                "http {method} returned unsupported Content-Type {:?}",
                response.content_type
            ))),
        }
    }

    fn drive_sse_stream(
        &mut self,
        method: &str,
        expected_id: u64,
        reader: Box<dyn Read + Send + Sync + 'static>,
    ) -> Result<Value> {
        let max = self.config.max_response_bytes;
        let mut parser = SseParser::new(BufReader::new(reader), max);
        loop {
            let event = parser.next_event().map_err(|err| match err {
                SseError::TooLarge(size) => TransportError::ResponseTooLarge {
                    method: method.to_string(),
                    size,
                    limit: max,
                },
                SseError::Io(io) => {
                    Self::protocol_error(format!("http {method} SSE read failed: {io}"))
                }
            })?;

            let Some(raw) = event else {
                return Err(Self::protocol_error(format!(
                    "http {method} SSE stream ended before a matching response was seen"
                )));
            };

            let size = raw.data.len() as u64;
            if size == 0 {
                continue;
            }
            trace!(method, bytes = size, "http ← server sse event");
            self.record_bytes(method, size)?;

            let msg: JsonRpcMessage = serde_json::from_slice(&raw.data).map_err(|err| {
                let preview = String::from_utf8_lossy(&raw.data).into_owned();
                Self::protocol_error(format!(
                    "http {method} SSE event is not valid JSON-RPC: {preview:?} ({err})"
                ))
            })?;

            match self.route_message(method, expected_id, msg)? {
                MessageOutcome::Resolved(value) => return Ok(value),
                MessageOutcome::Continue => continue,
            }
        }
    }

    fn handle_message(
        &mut self,
        method: &str,
        expected_id: u64,
        msg: JsonRpcMessage,
    ) -> Result<Value> {
        match self.route_message(method, expected_id, msg)? {
            MessageOutcome::Resolved(value) => Ok(value),
            MessageOutcome::Continue => Err(Self::protocol_error(format!(
                "http {method} response did not contain a matching JSON-RPC reply"
            ))),
        }
    }

    fn route_message(
        &mut self,
        method: &str,
        expected_id: u64,
        msg: JsonRpcMessage,
    ) -> Result<MessageOutcome> {
        match msg {
            JsonRpcMessage::Request {
                id,
                method: req_method,
                ..
            } => {
                if req_method == "ping" {
                    debug!("http auto-ack server ping id={:?}", id);
                    let ack = JsonRpcMessage::empty_result(id);
                    let body = serde_json::to_string(&ack).map_err(|err| {
                        Self::protocol_error(format!("failed to serialise http ping ack: {err}"))
                    })?;
                    // Fire-and-forget: don't block the stream on the ack
                    // response. If the server cares it will resend.
                    let _ = self.build_post(body.len()).send_string(&body);
                    Ok(MessageOutcome::Continue)
                } else {
                    Err(Self::protocol_error(format!(
                        "server sent unsupported request {req_method:?} during http discovery"
                    )))
                }
            }
            JsonRpcMessage::Notification {
                method: notif_method,
                ..
            } => {
                debug!(
                    method = %notif_method,
                    "ignoring server notification during http discovery"
                );
                Ok(MessageOutcome::Continue)
            }
            JsonRpcMessage::Response {
                id, result, error, ..
            } => {
                let matches_id = matches!(id.as_int(), Some(got) if got == expected_id as i64);
                if !matches_id {
                    return Err(Self::protocol_error(format!(
                        "http {method} received unexpected response id {id:?}"
                    )));
                }
                if let Some(err) = error {
                    return Err(Self::protocol_error(format!(
                        "server returned JSON-RPC error for {method}: [{}] {}",
                        err.code, err.message
                    )));
                }
                let value = result.unwrap_or(Value::Null);
                if !value.is_object() {
                    return Err(Self::protocol_error(format!(
                        "{method} result must be an object"
                    )));
                }
                Ok(MessageOutcome::Resolved(value))
            }
        }
    }

    fn send_request(&mut self, method: &str, params: Option<Value>) -> Result<Value> {
        let id = self.id_gen.next_id();
        debug!(method, id, "http request");
        self.do_request(method, params, id)
    }

    fn send_notification(&mut self, method: &str, params: Option<Value>) -> Result<()> {
        let outgoing = JsonRpcMessage::Notification {
            jsonrpc: JsonRpcVersion::V2,
            method: method.to_string(),
            params,
        };
        let body = serde_json::to_string(&outgoing).map_err(|err| {
            Self::protocol_error(format!(
                "failed to serialise http {method} notification: {err}"
            ))
        })?;
        debug!(method, "http notify");
        match self.build_post(body.len()).send_string(&body) {
            Ok(resp) => {
                // Drain the body so the connection can be reused and any
                // status-carrying response headers are observed.
                if let Some(sid) = resp.header(SESSION_ID_HEADER) {
                    self.session_id = Some(sid.to_string());
                }
                let _ = resp.into_string();
                Ok(())
            }
            Err(ureq::Error::Status(code, resp)) => {
                let body_preview = resp.into_string().unwrap_or_default();
                Err(Self::protocol_error(format!(
                    "http {method} notification returned {code}: {}",
                    truncate(&body_preview, 512)
                )))
            }
            Err(ureq::Error::Transport(err)) => Err(Self::protocol_error(format!(
                "http {method} notification transport error: {err}"
            ))),
        }
    }
}

impl Transport for HttpTransport {
    fn initialize(&mut self, client_info: ClientInfo) -> Result<InitializeResult> {
        let params = serde_json::json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {
                "name": client_info.name,
                "version": client_info.version,
            },
        });
        let raw = self.send_request("initialize", Some(params))?;

        let obj = raw
            .as_object()
            .ok_or_else(|| Self::protocol_error("initialize result must be an object"))?;

        let protocol_version = obj
            .get("protocolVersion")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Self::protocol_error("initialize result.protocolVersion must be a string")
            })?
            .to_string();
        validate_protocol_version(&protocol_version)?;

        let capabilities = obj
            .get("capabilities")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                Self::protocol_error("initialize result.capabilities must be an object")
            })?;
        if !capabilities
            .get("tools")
            .map(Value::is_object)
            .unwrap_or(false)
        {
            return Err(Self::protocol_error(
                "server did not advertise tools capability during initialize",
            ));
        }

        let server_info = obj
            .get("serverInfo")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                Self::protocol_error("initialize result.serverInfo must be an object")
            })?;

        let server_name = server_info
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Self::protocol_error("initialize result.serverInfo.name must be a string")
            })?
            .to_string();

        let server_version = match server_info.get("version") {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Null) | None => None,
            Some(_) => {
                return Err(Self::protocol_error(
                    "initialize result.serverInfo.version must be a string when present",
                ));
            }
        };

        let instructions = match obj.get("instructions") {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Null) | None => None,
            Some(_) => {
                return Err(Self::protocol_error(
                    "initialize result.instructions must be a string when present",
                ));
            }
        };

        info!(
            server = %server_name,
            protocol_version = %protocol_version,
            "http initialize complete"
        );

        Ok(InitializeResult {
            protocol_version,
            server_name: Some(server_name),
            server_version,
            instructions,
            raw,
        })
    }

    fn notify_initialized(&mut self) -> Result<()> {
        self.send_notification("notifications/initialized", Some(serde_json::json!({})))
    }

    fn list_tools(&mut self) -> Result<Vec<NormalizedTool>> {
        let mut tools: Vec<NormalizedTool> = Vec::new();
        let mut seen_cursors: BTreeSet<String> = BTreeSet::new();
        let mut cursor: Option<String> = None;

        loop {
            let params = cursor.as_ref().map(|c| serde_json::json!({ "cursor": c }));
            let result = self.send_request("tools/list", params)?;
            let obj = result
                .as_object()
                .ok_or_else(|| Self::protocol_error("tools/list result must be an object"))?;
            let raw_tools = obj
                .get("tools")
                .and_then(Value::as_array)
                .ok_or_else(|| Self::protocol_error("tools/list result.tools must be a list"))?;
            for payload in raw_tools {
                let tool = normalize_tool_payload(payload).map_err(Self::protocol_error)?;
                tools.push(tool);
            }
            match obj.get("nextCursor") {
                None | Some(Value::Null) => {
                    debug!(count = tools.len(), "http tools/list complete");
                    return Ok(tools);
                }
                Some(Value::String(next)) => {
                    if next.trim().is_empty() {
                        return Err(Self::protocol_error(
                            "tools/list result.nextCursor must be a non-empty string when present",
                        ));
                    }
                    if !seen_cursors.insert(next.clone()) {
                        return Err(Self::protocol_error(format!(
                            "tools/list returned repeated cursor {next:?}"
                        )));
                    }
                    cursor = Some(next.clone());
                }
                Some(_) => {
                    return Err(Self::protocol_error(
                        "tools/list result.nextCursor must be a non-empty string when present",
                    ));
                }
            }
        }
    }

    fn take_response_sizes(&mut self) -> BTreeMap<String, u64> {
        std::mem::take(&mut self.response_sizes)
    }

    fn shutdown(&mut self) -> Result<()> {
        self.session_id = None;
        Ok(())
    }
}

struct PostResponse {
    kind: ContentKind,
    content_type: String,
    reader: Box<dyn Read + Send + Sync + 'static>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentKind {
    Json,
    Sse,
    Unknown,
}

enum MessageOutcome {
    Resolved(Value),
    Continue,
}

fn classify_content_type(content_type: &str) -> ContentKind {
    let ct = content_type.split(';').next().unwrap_or("").trim();
    match ct {
        "application/json" | "application/json-rpc" => ContentKind::Json,
        "text/event-stream" => ContentKind::Sse,
        _ => ContentKind::Unknown,
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut out = s.as_bytes()[..max].to_vec();
        // pop any partial UTF-8 code unit at the boundary
        while !out.is_empty() && (out[out.len() - 1] & 0b1100_0000) == 0b1000_0000 {
            out.pop();
        }
        let mut s = String::from_utf8_lossy(&out).into_owned();
        s.push('…');
        s
    }
}

fn normalize_tool_payload(value: &Value) -> std::result::Result<NormalizedTool, String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "tools/list result.tools entries must be objects".to_string())?;

    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "tool.name must be a string".to_string())?
        .to_string();

    let description = match obj.get("description") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Null) | None => None,
        Some(_) => {
            return Err(format!(
                "tool {name:?} description must be a string when present"
            ));
        }
    };

    let input_schema = match obj.get("inputSchema") {
        Some(v @ Value::Object(_)) => v.clone(),
        _ => {
            return Err(format!("tool {name:?} inputSchema must be an object"));
        }
    };

    let mut metadata: MetadataMap = BTreeMap::new();
    if let Some(title) = obj.get("title") {
        match title {
            Value::String(_) => {
                metadata.insert("title".to_string(), title.clone());
            }
            Value::Null => {}
            _ => {
                return Err(format!("tool {name:?} title must be a string when present"));
            }
        }
    }
    if let Some(annotations) = obj.get("annotations") {
        match annotations {
            Value::Object(_) => {
                metadata.insert("annotations".to_string(), annotations.clone());
            }
            Value::Null => {}
            _ => {
                return Err(format!(
                    "tool {name:?} annotations must be an object when present"
                ));
            }
        }
    }

    Ok(NormalizedTool {
        name,
        description,
        input_schema,
        metadata,
    })
}

// ---------- SSE parser ----------------------------------------------------
//
// Spec reference: https://html.spec.whatwg.org/multipage/server-sent-events.html
// We only need the `data:` and `event:` fields; the rest (id, retry) is
// parsed and discarded. One event is emitted when a blank line is seen, and
// its payload is the concatenation of all `data:` field values joined with
// `\n` (with the trailing newline stripped, per spec).

#[derive(Debug)]
enum SseError {
    Io(std::io::Error),
    TooLarge(u64),
}

impl From<std::io::Error> for SseError {
    fn from(value: std::io::Error) -> Self {
        SseError::Io(value)
    }
}

#[derive(Debug)]
struct SseEvent {
    data: Vec<u8>,
}

struct SseParser<R: BufRead> {
    reader: R,
    max_bytes: u64,
}

impl<R: BufRead> SseParser<R> {
    fn new(reader: R, max_bytes: u64) -> Self {
        Self { reader, max_bytes }
    }

    fn next_event(&mut self) -> std::result::Result<Option<SseEvent>, SseError> {
        let mut data: Vec<u8> = Vec::new();
        let mut saw_any = false;

        loop {
            // Cap the line read so one pathological line cannot OOM us. The
            // cap sits one byte over `max_bytes` so we can detect an actual
            // overflow vs a line that exactly fills the budget.
            let cap = self.max_bytes.saturating_add(2);
            let mut raw: Vec<u8> = Vec::new();
            let n = (&mut self.reader).take(cap).read_until(b'\n', &mut raw)?;
            if n == 0 {
                // EOF before a blank line — if we had partial state, return
                // it anyway so a server that forgets the trailing blank line
                // still works.
                if saw_any && !data.is_empty() {
                    return Ok(Some(SseEvent { data }));
                }
                return Ok(None);
            }
            let had_newline = raw.last() == Some(&b'\n');
            if !had_newline && (n as u64) > self.max_bytes {
                return Err(SseError::TooLarge(n as u64));
            }
            if had_newline {
                raw.pop();
                if raw.last() == Some(&b'\r') {
                    raw.pop();
                }
            }

            if raw.is_empty() {
                // Blank line → dispatch event (even if data is empty, per
                // spec, so the caller can use this as a keep-alive signal).
                if saw_any {
                    // strip the spec-mandated single trailing '\n' if one
                    // was added during the `data:` concatenation
                    if data.last() == Some(&b'\n') {
                        data.pop();
                    }
                    return Ok(Some(SseEvent { data }));
                }
                continue;
            }

            saw_any = true;

            if raw[0] == b':' {
                // Comment / keep-alive line.
                continue;
            }

            let (field, value) = split_field(&raw);
            match field {
                b"data" => {
                    if !data.is_empty() {
                        data.push(b'\n');
                    }
                    data.extend_from_slice(value);
                    if (data.len() as u64) > self.max_bytes {
                        return Err(SseError::TooLarge(data.len() as u64));
                    }
                }
                b"event" | b"id" | b"retry" => {
                    // silently ignored for now — not surfaced to callers
                }
                _ => {
                    // unknown fields are ignored per spec
                }
            }
        }
    }
}

fn split_field(line: &[u8]) -> (&[u8], &[u8]) {
    match line.iter().position(|b| *b == b':') {
        Some(i) => {
            let field = &line[..i];
            let mut rest = &line[i + 1..];
            if rest.first() == Some(&b' ') {
                rest = &rest[1..];
            }
            (field, rest)
        }
        None => (line, &[]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn config_target_is_http_url_form() {
        let cfg = HttpConfig::new("https://example.com/mcp");
        assert_eq!(cfg.target(), "http:https://example.com/mcp");
    }

    #[test]
    fn config_rejects_empty_url() {
        let err = HttpTransport::new(HttpConfig::new("")).unwrap_err();
        assert!(matches!(err, TransportError::ServerStartup { .. }));
    }

    #[test]
    fn config_rejects_bad_scheme() {
        let err = HttpTransport::new(HttpConfig::new("ftp://example.com")).unwrap_err();
        match err {
            TransportError::ServerStartup { reason, .. } => {
                assert!(reason.contains("http"));
            }
            other => panic!("expected ServerStartup, got {other:?}"),
        }
    }

    #[test]
    fn config_rejects_zero_timeout() {
        let err = HttpTransport::new(
            HttpConfig::new("http://localhost:1").with_timeout(Duration::from_secs(0)),
        )
        .unwrap_err();
        assert!(matches!(err, TransportError::ServerStartup { .. }));
    }

    #[test]
    fn content_type_classification() {
        assert_eq!(classify_content_type("application/json"), ContentKind::Json);
        assert_eq!(
            classify_content_type("application/json; charset=utf-8"),
            ContentKind::Json
        );
        assert_eq!(classify_content_type("text/event-stream"), ContentKind::Sse);
        assert_eq!(
            classify_content_type("text/event-stream;charset=utf-8"),
            ContentKind::Sse
        );
        assert_eq!(classify_content_type("text/html"), ContentKind::Unknown);
        assert_eq!(classify_content_type(""), ContentKind::Unknown);
    }

    #[test]
    fn sse_parser_handles_single_event() {
        let stream = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n".as_bytes();
        let mut parser = SseParser::new(BufReader::new(stream), 1024);
        let event = parser.next_event().unwrap().expect("event");
        assert_eq!(event.data, b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        assert!(parser.next_event().unwrap().is_none());
    }

    #[test]
    fn sse_parser_concatenates_multiline_data() {
        let stream = "data: {\"a\":1,\ndata: \"b\":2}\n\n".as_bytes();
        let mut parser = SseParser::new(BufReader::new(stream), 1024);
        let event = parser.next_event().unwrap().expect("event");
        assert_eq!(event.data, b"{\"a\":1,\n\"b\":2}");
    }

    #[test]
    fn sse_parser_ignores_comments_and_metadata() {
        let stream = ": keepalive\nevent: ping\nid: 42\nretry: 1000\ndata: hello\n\n".as_bytes();
        let mut parser = SseParser::new(BufReader::new(stream), 1024);
        let event = parser.next_event().unwrap().expect("event");
        assert_eq!(event.data, b"hello");
    }

    #[test]
    fn sse_parser_rejects_oversized_event() {
        let payload = "x".repeat(4096);
        let stream = format!("data: {payload}\n\n");
        let mut parser = SseParser::new(BufReader::new(stream.as_bytes()), 256);
        match parser.next_event() {
            Err(SseError::TooLarge(size)) => assert!(size > 256),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn normalize_tool_payload_roundtrip() {
        let payload = serde_json::json!({
            "name": "ping",
            "description": "returns pong",
            "inputSchema": {"type": "object"}
        });
        let tool = normalize_tool_payload(&payload).unwrap();
        assert_eq!(tool.name, "ping");
        assert_eq!(tool.description.as_deref(), Some("returns pong"));
    }

    #[test]
    fn truncate_handles_ascii_and_utf8() {
        assert_eq!(truncate("short", 100), "short");
        assert_eq!(truncate("exactly10!", 10), "exactly10!");
        let out = truncate("hello world", 5);
        assert!(out.starts_with("hello"));
        assert!(out.ends_with('…'));
    }

    /// Boot a trivial single-shot HTTP server that returns `response_body`
    /// verbatim. Returns the port and a join handle; the thread exits after
    /// serving exactly N requests.
    fn spawn_mock_http(responses: Vec<Vec<u8>>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for response in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                // Read the request until the blank line. We don't parse it;
                // we only need to consume it so ureq sees a clean response.
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut total = 0usize;
                loop {
                    let mut line = String::new();
                    let n = reader.read_line(&mut line).unwrap_or(0);
                    if n == 0 || line == "\r\n" || line == "\n" {
                        break;
                    }
                    if let Some(rest) = line.strip_prefix("Content-Length:") {
                        total = rest.trim().parse().unwrap_or(0);
                    }
                }
                if total > 0 {
                    let mut body = vec![0u8; total];
                    let _ = reader.read_exact(&mut body);
                }
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        port
    }

    fn http_ok_json(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn http_ok_sse(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{}",
            chunked_body(body)
        )
        .into_bytes()
    }

    fn chunked_body(body: &str) -> String {
        let mut out = String::new();
        out.push_str(&format!("{:x}\r\n{body}\r\n0\r\n\r\n", body.len()));
        out
    }

    #[test]
    fn scan_round_trips_against_json_mock() {
        let init_body = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"mock","version":"0.1.0"}}}"#;
        let tools_body = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object"}}]}}"#;
        // initialize → POST; notify_initialized → POST; tools/list → POST
        let port = spawn_mock_http(vec![
            http_ok_json(init_body),
            http_ok_json(""),
            http_ok_json(tools_body),
        ]);
        // Give the listener a beat to bind
        thread::sleep(Duration::from_millis(20));

        let cfg = HttpConfig::new(format!("http://127.0.0.1:{port}/mcp"))
            .with_timeout(Duration::from_secs(5));
        let mut transport = HttpTransport::new(cfg).unwrap();
        let init = transport
            .initialize(ClientInfo::default_for_crate())
            .unwrap();
        assert_eq!(init.server_name.as_deref(), Some("mock"));
        transport.notify_initialized().unwrap();
        let tools = transport.list_tools().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "echo");
        let sizes = transport.take_response_sizes();
        assert!(sizes.contains_key("initialize"));
        assert!(sizes.contains_key("tools/list"));
    }

    #[test]
    fn scan_parses_sse_response() {
        let init_body = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"mock","version":"0.1.0"}}}"#;
        let sse_frame = format!("data: {init_body}\n\n");
        let port = spawn_mock_http(vec![http_ok_sse(&sse_frame)]);
        thread::sleep(Duration::from_millis(20));

        let cfg = HttpConfig::new(format!("http://127.0.0.1:{port}/mcp"))
            .with_timeout(Duration::from_secs(5));
        let mut transport = HttpTransport::new(cfg).unwrap();
        let init = transport
            .initialize(ClientInfo::default_for_crate())
            .unwrap();
        assert_eq!(init.server_name.as_deref(), Some("mock"));
    }

    #[test]
    fn scan_rejects_oversized_json_body() {
        let pad = "x".repeat(4096);
        let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"pad":"{pad}"}}}}"#);
        let port = spawn_mock_http(vec![http_ok_json(&body)]);
        thread::sleep(Duration::from_millis(20));

        let cfg = HttpConfig::new(format!("http://127.0.0.1:{port}/mcp"))
            .with_max_response_bytes(256)
            .with_timeout(Duration::from_secs(5));
        let mut transport = HttpTransport::new(cfg).unwrap();
        let err = transport
            .initialize(ClientInfo::default_for_crate())
            .unwrap_err();
        match err {
            TransportError::ResponseTooLarge { method, limit, .. } => {
                assert_eq!(method, "initialize");
                assert_eq!(limit, 256);
            }
            other => panic!("expected ResponseTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn session_id_header_round_trips() {
        // First response sets Mcp-Session-Id; second response must have the
        // client echo it back. Our mock doesn't verify headers, but it does
        // let us assert the local state update.
        let init_body = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"mock","version":"0.1.0"}}}"#;
        let with_session = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nMcp-Session-Id: abc-123\r\nConnection: close\r\n\r\n{init_body}",
            init_body.len()
        )
        .into_bytes();
        let port = spawn_mock_http(vec![with_session]);
        thread::sleep(Duration::from_millis(20));

        let cfg = HttpConfig::new(format!("http://127.0.0.1:{port}/mcp"))
            .with_timeout(Duration::from_secs(5));
        let mut transport = HttpTransport::new(cfg).unwrap();
        transport
            .initialize(ClientInfo::default_for_crate())
            .unwrap();
        assert_eq!(transport.session_id.as_deref(), Some("abc-123"));
    }
}
