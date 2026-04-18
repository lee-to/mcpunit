//! Demo MCP server that exercises every audit category in one run.
//!
//! Built with `cargo build --example demo` and scanned by mcpunit to
//! regenerate the golden reports under `.reports/`. Four tools, each
//! chosen so the scan reliably trips a mix of rules:
//!
//! * `exec_command`  → `dangerous_exec_tool`
//! * `write_file`    → `dangerous_fs_write_tool` + `write_tool_without_scope_hint`
//! * `debug_payload` → `weak_input_schema` + `schema_allows_arbitrary_properties`
//! * `do_it`         → `overly_generic_tool_name` + `vague_tool_description`
//!
//! Speaks newline-delimited JSON-RPC 2.0 over stdio, compatible with the
//! mcpunit stdio transport. The "dangerous" bits live purely in tool
//! *metadata* (names, descriptions, schemas) — this binary never touches
//! the shell or the filesystem, so scanning it is completely safe.

use std::io::{self, BufRead, Write};

use serde_json::{json, Value};

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let mut initialized = false;

    for line in stdin.lock().lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let message: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("demo server received invalid JSON");
                return Ok(());
            }
        };

        let method = message.get("method").and_then(Value::as_str);
        let request_id = message.get("id").cloned();

        match method {
            Some("initialize") => {
                send(
                    &mut stdout,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {"tools": {}},
                            "serverInfo": {
                                "name": "mcpunit demo server",
                                "version": "0.1.0"
                            },
                            "instructions": "Demo server used by mcpunit to regenerate the reports under `.reports/`."
                        }
                    }),
                )?;
            }
            Some("notifications/initialized") => {
                initialized = true;
            }
            Some("tools/list") => {
                if !initialized {
                    send_error(
                        &mut stdout,
                        request_id,
                        -32000,
                        "Client did not send initialized.",
                    )?;
                    continue;
                }
                send(
                    &mut stdout,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {"tools": tools()}
                    }),
                )?;
            }
            Some("ping") if request_id.is_some() => {
                send(
                    &mut stdout,
                    &json!({"jsonrpc": "2.0", "id": request_id, "result": {}}),
                )?;
            }
            Some(other) if request_id.is_some() => {
                send_error(
                    &mut stdout,
                    request_id,
                    -32601,
                    &format!("Unknown method: {other}"),
                )?;
            }
            Some(_) => {
                // Notification for an unknown method — JSON-RPC says we
                // must not reply to notifications, so silently ignore.
            }
            None => {
                // Notification with no method — ignore.
            }
        }
    }

    Ok(())
}

fn send(out: &mut impl Write, value: &Value) -> io::Result<()> {
    let line = serde_json::to_string(value).unwrap();
    out.write_all(line.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()
}

fn send_error(
    out: &mut impl Write,
    request_id: Option<Value>,
    code: i32,
    message: &str,
) -> io::Result<()> {
    send(
        out,
        &json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message}
        }),
    )
}

fn tools() -> Value {
    json!([
        {
            "name": "exec_command",
            "description": "Execute an arbitrary shell command on the host machine.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute exactly as provided."
                    }
                },
                "required": ["command"],
                "additionalProperties": false
            }
        },
        {
            "name": "write_file",
            "description": "Write text content to any file path on disk.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute or relative path to write."
                    },
                    "content": {
                        "type": "string",
                        "description": "Content to write to the target file."
                    },
                    "overwrite": {
                        "type": "boolean",
                        "description": "Overwrite the file if it already exists."
                    }
                },
                "required": ["path", "content"],
                "additionalProperties": false
            }
        },
        {
            "name": "do_it",
            "description": "Helps with stuff.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Thing to process."
                    }
                },
                "required": ["target"],
                "additionalProperties": false
            }
        },
        {
            "name": "debug_payload",
            "description": "Debug helper that accepts whatever input is available.",
            "inputSchema": {
                "type": "object",
                "description": "Arbitrary debug payload.",
                "additionalProperties": true
            }
        }
    ])
}
