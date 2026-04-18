//! Stdio transport — subprocess + newline-delimited JSON-RPC.
//!
//! Design:
//!
//! * Two pump threads drain the child's stdout / stderr into a channel and
//!   a rolling tail respectively. Both pumps exit automatically when the
//!   underlying pipe closes.
//! * The main thread uses [`std::sync::mpsc::Receiver::recv_timeout`]
//!   against an [`Instant`]-based deadline so a deadlocked server surfaces
//!   as [`TransportError::Timeout`] with the real elapsed wall-clock.
//! * `max_response_bytes` is enforced inside the pump **before** the JSON
//!   body is handed to `serde_json`, via a capped [`std::io::Read::take`].
//!   A pathological server that streams an unbounded line without a
//!   newline cannot OOM the scanner.
//! * Graceful shutdown chain: drop stdin → `try_wait` loop → `kill` →
//!   `wait`. [`Drop`] calls [`Transport::shutdown`] so `?` early-returns
//!   never leak children.
//! * The stderr pump keeps the last 20 non-empty lines. Every
//!   [`TransportError`] the session raises carries that tail so CI logs
//!   have useful diagnostic context when a server dies mid-handshake.
//!
//! Protocol quirks: server-initiated `ping` requests during discovery are
//! auto-acknowledged with an empty `{}` result. Any other server-initiated
//! request aborts the scan with [`TransportError::Protocol`]; a `-32601`
//! reply is best-effort written back before the error is returned.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::Value;
use tracing::{debug, error, info, trace, warn};

use crate::error::{Result, StderrTail, TransportError};
use crate::models::{MetadataMap, NormalizedTool};
use crate::transport::jsonrpc::{encode_line, JsonRpcId, JsonRpcMessage, JsonRpcVersion};
use crate::transport::{
    validate_protocol_version, ClientInfo, InitializeResult, RequestIdGenerator, Transport,
};
use crate::{DEFAULT_MAX_RESPONSE_BYTES, MCP_PROTOCOL_VERSION};

const STDERR_TAIL_LINES: usize = 20;
const CLOSE_WAIT_INITIAL: Duration = Duration::from_millis(200);
const CLOSE_WAIT_POLL: Duration = Duration::from_millis(20);

/// Default per-request timeout. Long enough for a cold-start subprocess
/// to finish booting on a slow CI runner, short enough that the scan
/// never hangs past a reasonable budget.
pub const DEFAULT_STDIO_TIMEOUT: Duration = Duration::from_secs(10);

/// Configuration for launching a local MCP server over stdio.
///
/// Constructed by the CLI from `--cmd` (split into argv) plus `--timeout` and
/// `--max-response-bytes`. Use [`StdioConfig::new`] for the common case and
/// the `with_*` builders to override individual fields.
#[derive(Debug, Clone)]
pub struct StdioConfig {
    /// `argv` for the subprocess. Must be non-empty and contain no empty
    /// arguments — validated on [`StdioTransport::spawn`].
    pub command: Vec<String>,
    /// Deadline for every blocking request. Zero is rejected.
    pub timeout: Duration,
    /// Hard cap enforced on every inbound stdout line before JSON parse.
    pub max_response_bytes: u64,
    /// Working directory for the subprocess. `None` inherits the parent's cwd.
    pub cwd: Option<PathBuf>,
    /// Extra environment variables to set on the subprocess.
    pub envs: Vec<(String, String)>,
}

impl StdioConfig {
    pub fn new(command: Vec<String>) -> Self {
        Self {
            command,
            timeout: DEFAULT_STDIO_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            cwd: None,
            envs: Vec::new(),
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

    pub fn with_cwd(mut self, cwd: PathBuf) -> Self {
        self.cwd = Some(cwd);
        self
    }

    pub fn with_envs(mut self, envs: Vec<(String, String)>) -> Self {
        self.envs = envs;
        self
    }

    /// Deterministic reporting target of the form
    /// `stdio:["part","part",...]`. Embedded as-is in the audit `scan.target.raw`
    /// field so downstream tools can de-dupe scans of the same server.
    pub fn target(&self) -> String {
        let parts: Vec<&str> = self.command.iter().map(String::as_str).collect();
        let serialized = serde_json::to_string(&parts).unwrap_or_else(|_| "[]".to_string());
        format!("stdio:{serialized}")
    }
}

/// Stdio transport: owns one subprocess for its whole lifetime.
#[derive(Debug)]
pub struct StdioTransport {
    config: StdioConfig,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout_rx: Option<Receiver<StdoutEvent>>,
    stderr_tail: Arc<Mutex<VecDeque<String>>>,
    stdout_pump: Option<JoinHandle<()>>,
    stderr_pump: Option<JoinHandle<()>>,
    id_gen: RequestIdGenerator,
    response_sizes: BTreeMap<String, u64>,
}

/// Message a stdout pump thread forwards to the main loop.
#[derive(Debug)]
enum StdoutEvent {
    /// One complete JSON-RPC line from the server, with the size observed on
    /// the wire (newline stripped).
    Line { bytes: Vec<u8>, size: u64 },
    /// A single stdout line exceeded `max_response_bytes` before JSON parse.
    /// The main thread converts this to [`TransportError::ResponseTooLarge`].
    TooLarge { size: u64 },
    /// Pump exited. No further events will arrive on this channel.
    Closed,
}

impl StdioTransport {
    /// Spawn the child process, set up the pump threads, and return a live
    /// transport. `spawn` does **not** perform the MCP handshake — callers
    /// drive that through the [`Transport`] trait.
    pub fn spawn(config: StdioConfig) -> Result<Self> {
        Self::validate_config(&config)?;

        info!(
            command = ?config.command,
            timeout_ms = config.timeout.as_millis() as u64,
            max_response_bytes = config.max_response_bytes,
            "spawning stdio mcp server"
        );

        let mut cmd = Command::new(&config.command[0]);
        cmd.args(&config.command[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(cwd) = &config.cwd {
            cmd.current_dir(cwd);
        }
        for (key, value) in &config.envs {
            cmd.env(key, value);
        }

        let mut child = cmd.spawn().map_err(|err| TransportError::ServerStartup {
            reason: format!("failed to spawn stdio server {:?}: {err}", config.command),
            stderr_tail: StderrTail::new(),
            source: Some(err),
        })?;

        let stdin = child.stdin.take().ok_or_else(|| {
            TransportError::startup("child process did not expose a stdin pipe", None)
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            TransportError::startup("child process did not expose a stdout pipe", None)
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            TransportError::startup("child process did not expose a stderr pipe", None)
        })?;

        let stderr_tail = Arc::new(Mutex::new(VecDeque::with_capacity(STDERR_TAIL_LINES)));

        let (tx, rx) = mpsc::channel::<StdoutEvent>();
        let max_bytes = config.max_response_bytes;
        let stdout_pump = thread::Builder::new()
            .name("mcpunit-stdio-stdout".into())
            .spawn(move || pump_stdout(stdout, tx, max_bytes))
            .map_err(|err| {
                TransportError::startup(format!("failed to spawn stdout pump thread: {err}"), None)
            })?;

        let stderr_tail_clone = Arc::clone(&stderr_tail);
        let stderr_pump = thread::Builder::new()
            .name("mcpunit-stdio-stderr".into())
            .spawn(move || pump_stderr(stderr, stderr_tail_clone))
            .map_err(|err| {
                TransportError::startup(format!("failed to spawn stderr pump thread: {err}"), None)
            })?;

        debug!("stdio transport ready");

        Ok(Self {
            config,
            child: Some(child),
            stdin: Some(stdin),
            stdout_rx: Some(rx),
            stderr_tail,
            stdout_pump: Some(stdout_pump),
            stderr_pump: Some(stderr_pump),
            id_gen: RequestIdGenerator::new(),
            response_sizes: BTreeMap::new(),
        })
    }

    fn validate_config(config: &StdioConfig) -> Result<()> {
        if config.command.is_empty() {
            return Err(TransportError::startup(
                "stdio command must not be empty",
                None,
            ));
        }
        if config.command.iter().any(|p| p.is_empty()) {
            return Err(TransportError::startup(
                "stdio command must not contain empty arguments",
                None,
            ));
        }
        if config.timeout.is_zero() {
            return Err(TransportError::startup(
                "stdio timeout must be greater than zero",
                None,
            ));
        }
        if config.max_response_bytes == 0 {
            return Err(TransportError::startup(
                "stdio max_response_bytes must be greater than zero",
                None,
            ));
        }
        Ok(())
    }

    fn stderr_tail_snapshot(&self) -> StderrTail {
        let guard = match self.stderr_tail.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        StderrTail {
            lines: guard.iter().cloned().collect(),
        }
    }

    fn protocol_error(&self, reason: impl Into<String>) -> TransportError {
        TransportError::Protocol {
            reason: reason.into(),
            stderr_tail: self.stderr_tail_snapshot(),
        }
    }

    fn startup_error(&self, reason: impl Into<String>) -> TransportError {
        TransportError::ServerStartup {
            reason: reason.into(),
            stderr_tail: self.stderr_tail_snapshot(),
            source: None,
        }
    }

    fn attach_stderr_tail(&self, err: TransportError) -> TransportError {
        match err {
            TransportError::Protocol { reason, .. } => self.protocol_error(reason),
            other => other,
        }
    }

    fn write_message(&mut self, msg: &JsonRpcMessage) -> Result<()> {
        let line = encode_line(msg).map_err(|err| {
            self.protocol_error(format!("failed to encode outbound JSON-RPC message: {err}"))
        })?;
        trace!(bytes = line.len(), "stdio → server");

        let stderr_tail = self.stderr_tail_snapshot();
        let command = self.config.command.clone();
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| TransportError::ServerStartup {
                reason: "stdin pipe already closed".to_string(),
                stderr_tail: stderr_tail.clone(),
                source: None,
            })?;
        stdin
            .write_all(line.as_bytes())
            .map_err(|err| TransportError::ServerStartup {
                reason: format!("failed to write to stdio server {command:?}: {err}"),
                stderr_tail: stderr_tail.clone(),
                source: Some(err),
            })?;
        stdin.flush().map_err(|err| TransportError::ServerStartup {
            reason: format!("failed to flush stdio server {command:?}: {err}"),
            stderr_tail,
            source: Some(err),
        })?;
        Ok(())
    }

    fn recv_event(&self, deadline: Instant, method: &str) -> Result<StdoutEvent> {
        let rx = self
            .stdout_rx
            .as_ref()
            .ok_or_else(|| self.protocol_error("stdout channel already closed"))?;
        let now = Instant::now();
        if now >= deadline {
            return Err(TransportError::Timeout {
                method: method.to_string(),
                elapsed: self.config.timeout,
                stderr_tail: self.stderr_tail_snapshot(),
            });
        }
        match rx.recv_timeout(deadline - now) {
            Ok(ev) => Ok(ev),
            Err(RecvTimeoutError::Timeout) => Err(TransportError::Timeout {
                method: method.to_string(),
                elapsed: self.config.timeout,
                stderr_tail: self.stderr_tail_snapshot(),
            }),
            Err(RecvTimeoutError::Disconnected) => Ok(StdoutEvent::Closed),
        }
    }

    fn read_response(&mut self, expected_id: u64, method: &str) -> Result<Value> {
        let deadline = Instant::now() + self.config.timeout;

        loop {
            let event = self.recv_event(deadline, method)?;
            let (bytes, size) = match event {
                StdoutEvent::Line { bytes, size } => (bytes, size),
                StdoutEvent::TooLarge { size } => {
                    warn!(
                        method,
                        size,
                        limit = self.config.max_response_bytes,
                        "stdio response exceeded max_response_bytes"
                    );
                    return Err(TransportError::ResponseTooLarge {
                        method: method.to_string(),
                        size,
                        limit: self.config.max_response_bytes,
                    });
                }
                StdoutEvent::Closed => {
                    let exit_status = self
                        .child
                        .as_mut()
                        .and_then(|c| c.try_wait().ok().flatten());
                    let suffix = exit_status
                        .map(|s| format!(" with status {s}"))
                        .unwrap_or_default();
                    let reason =
                        format!("server exited{suffix} while waiting for response to {method}");
                    return if method == "initialize" {
                        Err(self.startup_error(reason))
                    } else {
                        Err(self.protocol_error(reason))
                    };
                }
            };

            let trimmed = trim_ascii_whitespace(&bytes);
            if trimmed.is_empty() {
                continue;
            }

            let msg: JsonRpcMessage = match serde_json::from_slice(trimmed) {
                Ok(m) => m,
                Err(_) => {
                    let preview = String::from_utf8_lossy(trimmed);
                    warn!(
                        "ignoring non-JSON-RPC line on stdout: {}",
                        if preview.len() > 200 {
                            format!("{}…", &preview[..200])
                        } else {
                            preview.into_owned()
                        }
                    );
                    continue;
                }
            };

            trace!("stdio ← server {size} bytes");

            match msg {
                JsonRpcMessage::Request {
                    id,
                    method: req_method,
                    ..
                } => {
                    if req_method == "ping" {
                        debug!("auto-ack server ping id={:?}", id);
                        let ack = JsonRpcMessage::empty_result(id);
                        self.write_message(&ack)?;
                        continue;
                    }
                    // Best-effort reject; still fail the scan.
                    let reply = JsonRpcMessage::error_response(
                        id,
                        -32601,
                        format!(
                            "Client does not support server request method {req_method:?} during discovery."
                        ),
                    );
                    let _ = self.write_message(&reply);
                    return Err(self.protocol_error(format!(
                        "server sent unsupported request {req_method:?} during discovery"
                    )));
                }
                JsonRpcMessage::Notification {
                    method: notif_method,
                    ..
                } => {
                    debug!(
                        method = %notif_method,
                        "ignoring server notification during discovery"
                    );
                    continue;
                }
                JsonRpcMessage::Response {
                    id, result, error, ..
                } => {
                    let matches_id = match id.as_int() {
                        Some(got) => got == expected_id as i64,
                        None => false,
                    };
                    if !matches_id {
                        return Err(self.protocol_error(format!(
                            "received unexpected response id {id:?} while waiting for {method}"
                        )));
                    }
                    self.response_sizes.insert(method.to_string(), size);
                    if let Some(err) = error {
                        return Err(self.protocol_error(format!(
                            "server returned JSON-RPC error for {method}: [{}] {}",
                            err.code, err.message
                        )));
                    }
                    let value = result.unwrap_or(Value::Null);
                    if !value.is_object() {
                        return Err(
                            self.protocol_error(format!("{method} result must be an object"))
                        );
                    }
                    return Ok(value);
                }
            }
        }
    }

    fn send_request(&mut self, method: &str, params: Option<Value>) -> Result<Value> {
        let id = self.id_gen.next_id();
        let msg = JsonRpcMessage::Request {
            jsonrpc: JsonRpcVersion::V2,
            id: JsonRpcId::Int(id as i64),
            method: method.to_string(),
            params,
        };
        debug!(method, id, "stdio request");
        self.write_message(&msg)?;
        self.read_response(id, method)
    }

    fn send_notification(&mut self, method: &str, params: Option<Value>) -> Result<()> {
        let msg = JsonRpcMessage::Notification {
            jsonrpc: JsonRpcVersion::V2,
            method: method.to_string(),
            params,
        };
        debug!(method, "stdio notify");
        self.write_message(&msg)
    }
}

impl Transport for StdioTransport {
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
            .ok_or_else(|| self.protocol_error("initialize result must be an object"))?;

        let protocol_version = obj
            .get("protocolVersion")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                self.protocol_error("initialize result.protocolVersion must be a string")
            })?
            .to_string();
        validate_protocol_version(&protocol_version).map_err(|err| self.attach_stderr_tail(err))?;

        let capabilities = obj
            .get("capabilities")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                self.protocol_error("initialize result.capabilities must be an object")
            })?;
        // MCP servers may advertise any subset of tools/prompts/resources —
        // record which is present so `scan` can skip `tools/list` for
        // prompts-only or resources-only servers instead of treating them
        // as a protocol violation.
        let has_tools_capability = capabilities
            .get("tools")
            .map(Value::is_object)
            .unwrap_or(false);

        let server_info = obj
            .get("serverInfo")
            .and_then(Value::as_object)
            .ok_or_else(|| self.protocol_error("initialize result.serverInfo must be an object"))?;

        let server_name = server_info
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                self.protocol_error("initialize result.serverInfo.name must be a string")
            })?
            .to_string();

        let server_version = match server_info.get("version") {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Null) | None => None,
            Some(_) => {
                return Err(self.protocol_error(
                    "initialize result.serverInfo.version must be a string when present",
                ));
            }
        };

        let instructions = match obj.get("instructions") {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Null) | None => None,
            Some(_) => {
                return Err(self.protocol_error(
                    "initialize result.instructions must be a string when present",
                ));
            }
        };

        info!(
            server = %server_name,
            protocol_version = %protocol_version,
            has_tools_capability,
            "stdio initialize complete"
        );

        Ok(InitializeResult {
            protocol_version,
            server_name: Some(server_name),
            server_version,
            instructions,
            has_tools_capability,
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
                .ok_or_else(|| self.protocol_error("tools/list result must be an object"))?;

            let raw_tools = obj
                .get("tools")
                .and_then(Value::as_array)
                .ok_or_else(|| self.protocol_error("tools/list result.tools must be a list"))?;

            for payload in raw_tools {
                let tool = normalize_tool_payload(payload)
                    .map_err(|reason| self.protocol_error(reason))?;
                tools.push(tool);
            }

            match obj.get("nextCursor") {
                None | Some(Value::Null) => {
                    debug!(count = tools.len(), "stdio tools/list complete");
                    return Ok(tools);
                }
                Some(Value::String(next)) => {
                    if next.trim().is_empty() {
                        return Err(self.protocol_error(
                            "tools/list result.nextCursor must be a non-empty string when present",
                        ));
                    }
                    if !seen_cursors.insert(next.clone()) {
                        return Err(self.protocol_error(format!(
                            "tools/list returned repeated cursor {next:?}"
                        )));
                    }
                    cursor = Some(next.clone());
                }
                Some(_) => {
                    return Err(self.protocol_error(
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
        // Closing stdin lets the server drain its read loop and exit cleanly.
        if self.stdin.take().is_some() {
            trace!("stdio stdin closed");
        }

        if let Some(mut child) = self.child.take() {
            let deadline = Instant::now() + CLOSE_WAIT_INITIAL;
            let mut exited = false;
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        debug!(?status, "stdio child exited gracefully");
                        exited = true;
                        break;
                    }
                    Ok(None) => {
                        if Instant::now() >= deadline {
                            break;
                        }
                        thread::sleep(CLOSE_WAIT_POLL);
                    }
                    Err(err) => {
                        error!("stdio child try_wait failed: {err}");
                        break;
                    }
                }
            }
            if !exited {
                warn!("stdio child did not exit within deadline; sending kill");
                let _ = child.kill();
                let _ = child.wait();
            }
        }

        // Drop the receiver so the pump's send() returns on the next iteration
        // if the child is still draining stdout.
        self.stdout_rx.take();
        if let Some(handle) = self.stdout_pump.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.stderr_pump.take() {
            let _ = handle.join();
        }
        Ok(())
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        let _ = self.shutdown();
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

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

fn pump_stdout(stdout: ChildStdout, tx: Sender<StdoutEvent>, max_bytes: u64) {
    let mut reader = BufReader::new(stdout);
    // One extra slot for the trailing `\n` plus one probe byte. If the line
    // fills the buffer without a newline, we know it has exceeded the limit.
    let cap = max_bytes.saturating_add(2);

    loop {
        let mut buf: Vec<u8> = Vec::new();
        let read = reader.by_ref().take(cap).read_until(b'\n', &mut buf);
        match read {
            Ok(0) => {
                let _ = tx.send(StdoutEvent::Closed);
                return;
            }
            Ok(_) => {
                let had_newline = buf.last() == Some(&b'\n');
                if had_newline {
                    buf.pop();
                    if buf.last() == Some(&b'\r') {
                        buf.pop();
                    }
                }
                let content_size = buf.len() as u64;
                if content_size > max_bytes || !had_newline {
                    let reported = if !had_newline { cap } else { content_size };
                    let _ = tx.send(StdoutEvent::TooLarge { size: reported });
                    let _ = tx.send(StdoutEvent::Closed);
                    return;
                }
                if tx
                    .send(StdoutEvent::Line {
                        bytes: buf,
                        size: content_size,
                    })
                    .is_err()
                {
                    // Main thread dropped the receiver — session is shutting
                    // down, nothing else to do.
                    return;
                }
            }
            Err(err) => {
                debug!("stdio stdout read error: {err}");
                let _ = tx.send(StdoutEvent::Closed);
                return;
            }
        }
    }
}

fn pump_stderr(stderr: ChildStderr, tail: Arc<Mutex<VecDeque<String>>>) {
    let reader = BufReader::new(stderr);
    for line in reader.lines() {
        match line {
            Ok(raw) => {
                let trimmed = raw.trim_end();
                if trimmed.is_empty() {
                    continue;
                }
                let owned = trimmed.to_string();
                if let Ok(mut guard) = tail.lock() {
                    if guard.len() == STDERR_TAIL_LINES {
                        guard.pop_front();
                    }
                    guard.push_back(owned);
                }
            }
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_target_is_stdio_json_array() {
        let cfg = StdioConfig::new(vec!["mock-server".into(), "--flag".into()]);
        assert_eq!(cfg.target(), r#"stdio:["mock-server","--flag"]"#);
    }

    #[test]
    fn config_defaults_pin_timeout_and_size() {
        let cfg = StdioConfig::new(vec!["echo".into()]);
        assert_eq!(cfg.timeout, DEFAULT_STDIO_TIMEOUT);
        assert_eq!(cfg.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
    }

    #[test]
    fn spawn_rejects_empty_command() {
        let err = StdioTransport::spawn(StdioConfig::new(vec![])).unwrap_err();
        assert!(matches!(err, TransportError::ServerStartup { .. }));
    }

    #[test]
    fn spawn_rejects_empty_argument() {
        let err =
            StdioTransport::spawn(StdioConfig::new(vec!["echo".into(), "".into()])).unwrap_err();
        match err {
            TransportError::ServerStartup { reason, .. } => {
                assert!(reason.contains("empty"));
            }
            other => panic!("expected ServerStartup, got {other:?}"),
        }
    }

    #[test]
    fn spawn_rejects_zero_timeout() {
        let cfg = StdioConfig::new(vec!["echo".into()]).with_timeout(Duration::from_secs(0));
        let err = StdioTransport::spawn(cfg).unwrap_err();
        assert!(matches!(err, TransportError::ServerStartup { .. }));
    }

    #[test]
    fn spawn_rejects_zero_max_response_bytes() {
        let cfg = StdioConfig::new(vec!["echo".into()]).with_max_response_bytes(0);
        let err = StdioTransport::spawn(cfg).unwrap_err();
        assert!(matches!(err, TransportError::ServerStartup { .. }));
    }

    #[test]
    fn trim_ascii_whitespace_strips_both_ends() {
        assert_eq!(trim_ascii_whitespace(b"  hi  "), b"hi");
        assert_eq!(trim_ascii_whitespace(b"\r\n"), b"");
        assert_eq!(trim_ascii_whitespace(b""), b"");
        assert_eq!(trim_ascii_whitespace(b"x"), b"x");
    }

    #[test]
    fn normalize_tool_payload_accepts_minimal_tool() {
        let payload = serde_json::json!({
            "name": "echo",
            "inputSchema": {"type": "object"}
        });
        let tool = normalize_tool_payload(&payload).unwrap();
        assert_eq!(tool.name, "echo");
        assert!(tool.description.is_none());
        assert!(tool.metadata.is_empty());
    }

    #[test]
    fn normalize_tool_payload_copies_title_and_annotations() {
        let payload = serde_json::json!({
            "name": "echo",
            "description": "repeats input",
            "inputSchema": {"type": "object"},
            "title": "Echo",
            "annotations": {"readOnly": true}
        });
        let tool = normalize_tool_payload(&payload).unwrap();
        assert_eq!(tool.description.as_deref(), Some("repeats input"));
        assert_eq!(
            tool.metadata.get("title").and_then(Value::as_str),
            Some("Echo")
        );
        assert!(tool.metadata.contains_key("annotations"));
    }

    #[test]
    fn normalize_tool_payload_rejects_missing_input_schema() {
        let payload = serde_json::json!({"name": "echo"});
        let err = normalize_tool_payload(&payload).unwrap_err();
        assert!(err.contains("inputSchema"));
    }

    #[test]
    fn normalize_tool_payload_rejects_non_string_description() {
        let payload = serde_json::json!({
            "name": "echo",
            "description": 42,
            "inputSchema": {"type": "object"}
        });
        let err = normalize_tool_payload(&payload).unwrap_err();
        assert!(err.contains("description"));
    }

    /// End-to-end smoke test against a tiny shell-driven mock server.
    /// Unix-only (uses `/bin/sh`); the cross-platform integration suite
    /// lives under `tests/transport_stdio.rs`.
    #[cfg(unix)]
    #[test]
    fn scan_round_trips_against_shell_mock() {
        let script = r#"
set -e
read init_line
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"mock","version":"0.1.0"}}}'
read notif_line
read list_line
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"repeats","inputSchema":{"type":"object"}}]}}'
"#;
        let cfg = StdioConfig::new(vec!["/bin/sh".into(), "-c".into(), script.into()])
            .with_timeout(Duration::from_secs(5));

        let mut transport = StdioTransport::spawn(cfg).unwrap();
        let server = transport.scan("stdio:mock".to_string()).unwrap();

        assert_eq!(server.name.as_deref(), Some("mock"));
        assert_eq!(server.version.as_deref(), Some("0.1.0"));
        assert_eq!(server.tools.len(), 1);
        assert_eq!(server.tools[0].name, "echo");
        assert!(server.response_sizes.contains_key("initialize"));
        assert!(server.response_sizes.contains_key("tools/list"));
    }

    /// A server-initiated `ping` mid-discovery is auto-acked and the scan
    /// keeps going without observable symptoms.
    #[cfg(unix)]
    #[test]
    fn scan_auto_acks_server_ping() {
        let script = r#"
set -e
read init_line
printf '%s\n' '{"jsonrpc":"2.0","id":99,"method":"ping","params":{}}'
read ping_ack
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"mock","version":"0.1.0"}}}'
read notif_line
read list_line
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}'
"#;
        let cfg = StdioConfig::new(vec!["/bin/sh".into(), "-c".into(), script.into()])
            .with_timeout(Duration::from_secs(5));
        let mut transport = StdioTransport::spawn(cfg).unwrap();
        let server = transport.scan("stdio:mock".to_string()).unwrap();
        assert_eq!(server.tools.len(), 0);
        assert_eq!(server.name.as_deref(), Some("mock"));
    }

    /// An oversized stdout line is caught inside the pump before serde sees
    /// it and surfaces as `ResponseTooLarge`.
    #[cfg(unix)]
    #[test]
    fn oversized_line_surfaces_response_too_large() {
        // 4 KiB of 'x' plus the JSON-RPC envelope — well over the 256-byte
        // limit we configure below.
        let script = r#"
read init_line
padding=$(printf 'x%.0s' $(seq 1 4096))
printf '{"jsonrpc":"2.0","id":1,"result":{"pad":"%s"}}\n' "$padding"
"#;
        let cfg = StdioConfig::new(vec!["/bin/sh".into(), "-c".into(), script.into()])
            .with_timeout(Duration::from_secs(5))
            .with_max_response_bytes(256);

        let mut transport = StdioTransport::spawn(cfg).unwrap();
        let err = transport
            .initialize(ClientInfo::default_for_crate())
            .unwrap_err();
        match err {
            TransportError::ResponseTooLarge {
                method,
                size,
                limit,
            } => {
                assert_eq!(method, "initialize");
                assert_eq!(limit, 256);
                assert!(size > 256, "size {size} should exceed limit");
            }
            other => panic!("expected ResponseTooLarge, got {other:?}"),
        }
    }
}
