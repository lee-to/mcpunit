//! Audit regression tests.
//!
//! Each fixture under `tests/fixtures/*.json` describes a
//! [`NormalizedServer`] snapshot that can be replayed without spawning a real
//! MCP server. We run the static rule registry against each fixture and
//! assert structural invariants — finding count, rule ids present, score
//! boundaries — so any regression that changes the rule set or scoring
//! contract fails loudly.

use std::collections::BTreeMap;
use std::path::PathBuf;

use mcpunit::models::{NormalizedServer, NormalizedTool};
use mcpunit::scoring::{scan, Report};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{name}.json"))
}

fn load_fixture(name: &str) -> NormalizedServer {
    let raw = std::fs::read_to_string(fixture_path(name))
        .unwrap_or_else(|e| panic!("failed to read fixture {name}: {e}"));
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();

    let mut server = NormalizedServer::new(
        value["target"]
            .as_str()
            .expect("target must be a string")
            .to_string(),
    );
    server.name = value.get("name").and_then(|v| v.as_str()).map(String::from);
    server.version = value
        .get("version")
        .and_then(|v| v.as_str())
        .map(String::from);
    if let Some(metadata) = value.get("metadata").and_then(|v| v.as_object()) {
        for (k, v) in metadata {
            server.metadata.insert(k.clone(), v.clone());
        }
    }
    if let Some(tools) = value.get("tools").and_then(|v| v.as_array()) {
        for tool in tools {
            let name = tool["name"].as_str().expect("tool name").to_string();
            let description = tool
                .get("description")
                .and_then(|v| v.as_str())
                .map(String::from);
            let input_schema = tool
                .get("input_schema")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            server.tools.push(NormalizedTool {
                name,
                description,
                input_schema,
                metadata: BTreeMap::new(),
            });
        }
    }
    server
}

fn scan_fixture(name: &str) -> Report {
    scan(load_fixture(name), 100)
}

#[test]
fn clean_server_has_minimal_findings() {
    let report = scan_fixture("clean_server");
    assert_eq!(
        report.score.total_score, 100,
        "clean fixture should score 100 but got {}",
        report.score.total_score
    );
    assert_eq!(report.findings.len(), 0);
}

#[test]
fn dangerous_server_fires_expected_rules() {
    let report = scan_fixture("dangerous_server");
    let expected = [
        "dangerous_fs_delete_tool",
        "dangerous_http_request_tool",
        "dangerous_shell_download_exec",
        "tool_description_mentions_destructive_access",
        "missing_tool_description",
        "overly_generic_tool_name",
    ];
    for rule in expected {
        assert!(
            report.findings.iter().any(|f| f.rule_id == rule),
            "expected rule {rule} to fire on dangerous fixture; got {:?}",
            report
                .findings
                .iter()
                .map(|f| f.rule_id.as_str())
                .collect::<Vec<_>>()
        );
    }
    assert!(
        report.score.total_score < 80,
        "dangerous fixture should score << 100 but got {}",
        report.score.total_score
    );
}

#[test]
fn fixture_loader_handles_missing_optional_fields() {
    // Exercise the `load_fixture` helper so refactors of that helper stay
    // covered.
    let p = fixture_path("clean_server");
    assert!(
        p.exists(),
        "clean fixture should ship with the repo: {:?}",
        p
    );
    let server = load_fixture("clean_server");
    assert_eq!(server.tools.len(), 2);
}
