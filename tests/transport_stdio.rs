//! End-to-end stdio transport tests.
//!
//! Drives the real [`StdioTransport::spawn`] + `scan` path against shell
//! scripts that act as mock MCP servers. Unix-only — the scripts rely on
//! `/bin/sh`, so Windows CI skips this file entirely via the top-level
//! `#![cfg(unix)]`.

#![cfg(unix)]

use std::time::Duration;

use mcpunit::error::TransportError;
use mcpunit::transport::stdio::{StdioConfig, StdioTransport};
use mcpunit::transport::{ClientInfo, Transport};

fn config(script: &str) -> StdioConfig {
    StdioConfig::new(vec!["/bin/sh".into(), "-c".into(), script.into()])
        .with_timeout(Duration::from_secs(5))
}

#[test]
fn scan_happy_path_with_paginated_tools_list() {
    let script = r#"
set -e
read _init
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"pager","version":"0.1.0"}}}'
read _notif
read _list1
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a","inputSchema":{"type":"object"}}],"nextCursor":"page-2"}}'
read _list2
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"b","inputSchema":{"type":"object"}}]}}'
"#;
    let mut transport = StdioTransport::spawn(config(script)).unwrap();
    let server = transport.scan("stdio:mock".into()).unwrap();
    assert_eq!(server.name.as_deref(), Some("pager"));
    assert_eq!(server.tools.len(), 2);
    assert_eq!(server.tools[0].name, "a");
    assert_eq!(server.tools[1].name, "b");
}

#[test]
fn unknown_protocol_version_fails_initialize() {
    let script = r#"
set -e
read _init
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"1999-01-01","capabilities":{"tools":{}},"serverInfo":{"name":"x","version":"0.1"}}}'
"#;
    let mut transport = StdioTransport::spawn(config(script)).unwrap();
    let err = transport
        .initialize(ClientInfo::default_for_crate())
        .unwrap_err();
    match err {
        TransportError::Protocol { reason, .. } => {
            assert!(reason.contains("1999-01-01"));
        }
        other => panic!("expected Protocol, got {other:?}"),
    }
}

#[test]
fn server_error_reply_propagates_as_protocol_error() {
    let script = r#"
set -e
read _init
printf '%s\n' '{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"initialize blew up"}}'
"#;
    let mut transport = StdioTransport::spawn(config(script)).unwrap();
    let err = transport
        .initialize(ClientInfo::default_for_crate())
        .unwrap_err();
    match err {
        TransportError::Protocol { reason, .. } => {
            assert!(reason.contains("initialize blew up"));
        }
        other => panic!("expected Protocol, got {other:?}"),
    }
}

#[test]
fn server_exit_before_response_raises_startup_error() {
    // `exit 7` drops the child before initialize gets a response.
    let script = "exit 7";
    let mut transport = StdioTransport::spawn(config(script)).unwrap();
    let err = transport
        .initialize(ClientInfo::default_for_crate())
        .unwrap_err();
    assert!(matches!(err, TransportError::ServerStartup { .. }));
}

#[test]
fn prompts_only_server_scans_without_protocol_error() {
    // Regression: MCP spec allows servers to advertise only `prompts`
    // (or `resources`). Treating that as a protocol error rejected
    // legitimate servers — now `scan` must succeed with an empty tool
    // list and skip `tools/list` entirely.
    let script = r#"
set -e
read _init
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"prompts":{}},"serverInfo":{"name":"prompts-only","version":"0.1.0"}}}'
read _notif
# No `tools/list` request must arrive; if the scanner sends one the
# shell read below will consume it and the test will see a phantom
# `.tools` entry. We reply with an error to make the regression loud.
if IFS= read -r _unexpected; then
    printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":2,\"error\":{\"code\":-32601,\"message\":\"unexpected tools/list\"}}"
fi
"#;
    let mut transport = StdioTransport::spawn(config(script)).unwrap();
    let server = transport.scan("stdio:prompts-only".into()).unwrap();
    assert_eq!(server.name.as_deref(), Some("prompts-only"));
    assert!(
        server.tools.is_empty(),
        "prompts-only server must scan with no tools"
    );
    assert_eq!(
        server.metadata.get("has_tools_capability"),
        Some(&serde_json::Value::Bool(false)),
        "metadata must surface that tools capability is absent"
    );
}

#[test]
fn resources_only_server_scans_without_protocol_error() {
    let script = r#"
set -e
read _init
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"resources":{}},"serverInfo":{"name":"res-only","version":"0.1.0"}}}'
read _notif
"#;
    let mut transport = StdioTransport::spawn(config(script)).unwrap();
    let server = transport.scan("stdio:res-only".into()).unwrap();
    assert!(server.tools.is_empty());
    assert_eq!(
        server.metadata.get("has_tools_capability"),
        Some(&serde_json::Value::Bool(false))
    );
}

#[test]
fn repeated_cursor_is_rejected() {
    let script = r#"
set -e
read _init
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"x","version":"0.1"}}}'
read _notif
read _list1
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[],"nextCursor":"page"}}'
read _list2
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"tools":[],"nextCursor":"page"}}'
"#;
    let mut transport = StdioTransport::spawn(config(script)).unwrap();
    let err = transport.scan("stdio:mock".into()).unwrap_err();
    match err {
        TransportError::Protocol { reason, .. } => {
            assert!(reason.contains("repeated cursor"));
        }
        other => panic!("expected Protocol, got {other:?}"),
    }
}
