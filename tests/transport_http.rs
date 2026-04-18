//! End-to-end Streamable HTTP transport tests.
//!
//! Uses a hand-rolled blocking TCP server so the test binary stays
//! async-runtime-free (wiremock 0.6 is async-only and we deliberately have
//! no tokio). The helper serves one canned response per request in strict
//! order — enough for scripted handshake exercises.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use mcpunit::error::TransportError;
use mcpunit::transport::http::{HttpConfig, HttpTransport};
use mcpunit::transport::{ClientInfo, Transport};

fn spawn_mock(responses: Vec<Vec<u8>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for response in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                let n = reader.read_line(&mut line).unwrap_or(0);
                if n == 0 || line == "\r\n" || line == "\n" {
                    break;
                }
                if let Some(rest) = line.strip_prefix("Content-Length:") {
                    content_length = rest.trim().parse().unwrap_or(0);
                }
            }
            if content_length > 0 {
                let mut body = vec![0u8; content_length];
                let _ = reader.read_exact(&mut body);
            }
            let _ = stream.write_all(&response);
            let _ = stream.flush();
        }
    });
    thread::sleep(Duration::from_millis(20));
    port
}

fn ok_json(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn ok_sse(body: &str) -> Vec<u8> {
    let chunk = format!("{:x}\r\n{body}\r\n0\r\n\r\n", body.len());
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{chunk}"
    )
    .into_bytes()
}

const INIT_RESULT: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"mock","version":"0.1.0"}}}"#;
const TOOLS_RESULT: &str = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"ping","inputSchema":{"type":"object"}}]}}"#;

#[test]
fn scan_round_trips_json_responses() {
    let port = spawn_mock(vec![
        ok_json(INIT_RESULT),
        ok_json(""),
        ok_json(TOOLS_RESULT),
    ]);
    let mut transport = HttpTransport::new(
        HttpConfig::new(format!("http://127.0.0.1:{port}/mcp"))
            .with_timeout(Duration::from_secs(5)),
    )
    .unwrap();
    let server = transport.scan("http:mock".into()).unwrap();
    assert_eq!(server.name.as_deref(), Some("mock"));
    assert_eq!(server.tools.len(), 1);
    assert_eq!(server.tools[0].name, "ping");
}

#[test]
fn scan_round_trips_sse_responses() {
    let init_frame = format!("data: {INIT_RESULT}\n\n");
    let tools_frame = format!("data: {TOOLS_RESULT}\n\n");
    let port = spawn_mock(vec![ok_sse(&init_frame), ok_json(""), ok_sse(&tools_frame)]);
    let mut transport = HttpTransport::new(
        HttpConfig::new(format!("http://127.0.0.1:{port}/mcp"))
            .with_timeout(Duration::from_secs(5)),
    )
    .unwrap();
    let server = transport.scan("http:mock".into()).unwrap();
    assert_eq!(server.tools.len(), 1);
}

#[test]
fn prompts_only_server_scans_without_protocol_error() {
    // Regression: MCP spec allows servers to advertise only `prompts`
    // or `resources` without tools. The scan must succeed, skip
    // `tools/list` entirely, and surface the missing capability via
    // server metadata.
    const PROMPTS_ONLY_INIT: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"prompts":{}},"serverInfo":{"name":"prompts-only","version":"0.1.0"}}}"#;
    // Only two responses are queued — `initialize` and the
    // `notifications/initialized` ack. If the transport erroneously
    // issues `tools/list`, the mock will fail to accept the connection
    // and the scan will surface a transport error.
    let port = spawn_mock(vec![ok_json(PROMPTS_ONLY_INIT), ok_json("")]);
    let mut transport = HttpTransport::new(
        HttpConfig::new(format!("http://127.0.0.1:{port}/mcp"))
            .with_timeout(Duration::from_secs(5)),
    )
    .unwrap();
    let server = transport.scan("http:prompts-only".into()).unwrap();
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
fn non_2xx_response_surfaces_protocol_error() {
    let status =
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 9\r\nConnection: close\r\n\r\nbad stuff"
            .to_vec();
    let port = spawn_mock(vec![status]);
    let mut transport = HttpTransport::new(
        HttpConfig::new(format!("http://127.0.0.1:{port}/mcp"))
            .with_timeout(Duration::from_secs(5)),
    )
    .unwrap();
    let err = transport
        .initialize(ClientInfo::default_for_crate())
        .unwrap_err();
    match err {
        TransportError::Protocol { reason, .. } => {
            assert!(reason.contains("503"));
        }
        other => panic!("expected Protocol, got {other:?}"),
    }
}
