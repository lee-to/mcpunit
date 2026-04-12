//! Insta snapshot tests for the terminal and markdown reporters.
//!
//! These tests pin the human-readable output against three representative
//! fixtures so reviewers can see at a glance what a given change does to
//! audit text. The generated timestamp and any volatile numeric fields
//! are redacted via insta filters so the snapshots stay stable across runs.
//!
//! To regenerate after an intentional change:
//!
//! ```bash
//! cargo insta review
//! ```

use std::collections::BTreeMap;

use mcpunit::models::{NormalizedServer, NormalizedTool};
use mcpunit::reporters::{MarkdownReporter, Reporter, TerminalReporter};
use mcpunit::scoring::{scan, Report};

fn tool(name: &str, description: Option<&str>, schema: serde_json::Value) -> NormalizedTool {
    NormalizedTool {
        name: name.to_string(),
        description: description.map(|s| s.to_string()),
        input_schema: schema,
        metadata: BTreeMap::new(),
    }
}

fn clean_server_report() -> Report {
    let mut server = NormalizedServer::new("stdio:clean");
    server.name = Some("clean-mock".to_string());
    server.version = Some("1.0.0".to_string());
    server.tools.push(tool(
        "search_documents",
        Some("search the indexed document corpus for matching titles"),
        serde_json::json!({
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "full text query"}
            },
            "required": ["query"]
        }),
    ));
    server.tools.push(tool(
        "fetch_document",
        Some("fetch a single document by id from the indexed corpus"),
        serde_json::json!({
            "type": "object",
            "properties": {"document_id": {"type": "string"}},
            "required": ["document_id"]
        }),
    ));
    scan(server, 100)
}

fn noisy_server_report() -> Report {
    let mut server = NormalizedServer::new("stdio:noisy");
    server.name = Some("noisy-mock".to_string());
    server.version = Some("0.1.0".to_string());
    // Empty schema on an inputful tool + vague description
    server
        .tools
        .push(tool("helper", Some("does things"), serde_json::json!({})));
    // Duplicate name to fire `duplicate_tool_names`
    server
        .tools
        .push(tool("helper", None, serde_json::json!({})));
    // Dangerous shell exec
    server.tools.push(tool(
        "shell_exec",
        Some("execute arbitrary shell commands on the host machine"),
        serde_json::json!({
            "type": "object",
            "properties": {"command": {"type": "string"}}
        }),
    ));
    scan(server, 100)
}

fn dangerous_server_report() -> Report {
    let mut server = NormalizedServer::new("stdio:dangerous");
    server.name = Some("danger-mock".to_string());
    server.version = Some("2.3.1".to_string());
    server.tools.push(tool(
        "delete_file",
        Some("delete any file on the host machine without validation"),
        serde_json::json!({
            "type": "object",
            "properties": {"path": {"type": "string"}}
        }),
    ));
    server.tools.push(tool(
        "http_download",
        Some("download arbitrary payloads from any remote URL"),
        serde_json::json!({
            "type": "object",
            "properties": {"url": {"type": "string"}, "command": {"type": "string"}}
        }),
    ));
    scan(server, 100)
}

fn normalise(text: &str) -> String {
    // Strip the scan timestamp line so snapshots are stable across runs.
    text.lines()
        .map(|line| {
            if line.starts_with("Scan Timestamp: ") {
                "Scan Timestamp: [REDACTED]".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#[test]
fn terminal_clean_server() {
    let rendered = TerminalReporter.render(&clean_server_report());
    insta::assert_snapshot!("terminal_clean", normalise(&rendered));
}

#[test]
fn terminal_noisy_server() {
    let rendered = TerminalReporter.render(&noisy_server_report());
    insta::assert_snapshot!("terminal_noisy", normalise(&rendered));
}

#[test]
fn terminal_dangerous_server() {
    let rendered = TerminalReporter.render(&dangerous_server_report());
    insta::assert_snapshot!("terminal_dangerous", normalise(&rendered));
}

#[test]
fn markdown_clean_server() {
    let rendered = MarkdownReporter.render(&clean_server_report());
    insta::assert_snapshot!("markdown_clean", rendered);
}

#[test]
fn markdown_dangerous_server() {
    let rendered = MarkdownReporter.render(&dangerous_server_report());
    insta::assert_snapshot!("markdown_dangerous", rendered);
}
