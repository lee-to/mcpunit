//! Plain-text terminal reporter — plain-text terminal reporter.

use serde_json::Value;

use crate::models::{NormalizedServer, ScoreBucket};
use crate::reporters::summary::{build_report_summary, BucketFindingsGroup, SummaryFinding};
use crate::reporters::Reporter;
use crate::scoring::Report;

pub struct TerminalReporter;

impl Reporter for TerminalReporter {
    fn id(&self) -> &'static str {
        "terminal"
    }

    fn render(&self, report: &Report) -> String {
        let summary = build_report_summary(report);
        let severity = &summary.severity_counts;
        let timestamp = report.generated_at.to_rfc3339();
        let protocol = protocol_version(&report.server);

        let mut lines: Vec<String> = vec![
            format!(
                "Generator: {} ({} {})",
                crate::PRODUCT_NAME,
                crate::TOOL_NAME,
                report.toolkit_version
            ),
            format!(
                "Report Schema: {}@{}",
                crate::REPORT_SCHEMA_ID,
                report.schema_version
            ),
            format!("Scan Timestamp: {timestamp}"),
            format!(
                "Server: {}",
                report.server.name.as_deref().unwrap_or("<unknown>")
            ),
            format!(
                "Version: {}",
                report.server.version.as_deref().unwrap_or("<unknown>")
            ),
            format!("Target: {}", report.server.target),
            format!("Target Description: {}", target_description(report)),
            format!("Tools: {}", summary.tool_count),
            format!(
                "Finding Counts: total={}, error={}, warning={}, info={}",
                summary.finding_count, severity.error, severity.warning, severity.info
            ),
            format!(
                "Total Score: {}/{}",
                report.score.total_score, report.score.max_score
            ),
            format!("Why This Score: {}", summary.why_score),
            format!("Score Meaning: {}", summary.score_meaning),
            "Category Scores:".to_string(),
        ];
        if let Some(p) = protocol {
            lines.insert(5, format!("Protocol: {p}"));
        }

        for bucket in ScoreBucket::ALL {
            let b = report.score.breakdown_for(*bucket);
            lines.push(format!(
                "- {}: {}/{} (findings: {}, penalties: {})",
                bucket.as_str(),
                b.score,
                b.max_score,
                b.finding_count,
                b.penalty_points
            ));
        }

        lines.push("Findings By Bucket:".to_string());
        if summary.findings_by_bucket.is_empty() {
            lines.push("- none".to_string());
        } else {
            for group in &summary.findings_by_bucket {
                lines.extend(format_bucket_group(group));
            }
        }

        lines.push("Limitations:".to_string());
        for note in summary.score_limits {
            lines.push(format!("- {note}"));
        }

        let mut out = lines.join("\n");
        out.push('\n');
        out
    }
}

fn format_finding_line(finding: &SummaryFinding) -> String {
    let suffix = finding
        .tool_name
        .as_deref()
        .map(|t| format!(" [{t}]"))
        .unwrap_or_default();
    format!(
        "- {} {}{}: {}",
        finding.severity.as_str().to_ascii_uppercase(),
        finding.id,
        suffix,
        finding.message
    )
}

fn format_bucket_group(group: &BucketFindingsGroup) -> Vec<String> {
    let word = if group.finding_count == 1 {
        "finding"
    } else {
        "findings"
    };
    let mut out = vec![format!(
        "- {}: {} {word}, penalties: {}",
        group.label, group.finding_count, group.penalty_points
    )];
    for finding in &group.findings {
        out.push(format!("  {}", format_finding_line(finding)));
    }
    out
}

fn protocol_version(server: &NormalizedServer) -> Option<String> {
    server
        .metadata
        .get("mcp")?
        .as_object()?
        .get("protocolVersion")?
        .as_str()
        .map(String::from)
}

fn target_description(report: &Report) -> String {
    let mcp = report.server.metadata.get("mcp").and_then(Value::as_object);
    if let Some(mcp) = mcp {
        if let Some(t) = mcp.get("transport").and_then(Value::as_str) {
            if t == "stdio" {
                return "Local MCP server launched over stdio.".to_string();
            }
            if !t.trim().is_empty() {
                return format!("MCP server target evaluated over {}.", t.trim());
            }
        }
    }
    match report.server.target.split_once(':') {
        Some(("stdio", _)) => "Local MCP server launched over stdio.".to_string(),
        Some((prefix, _)) if !prefix.is_empty() => {
            format!("MCP server target evaluated over {prefix}.")
        }
        _ => "MCP server target under evaluation.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::NormalizedTool;
    use crate::scoring::scan;

    fn sample_report() -> Report {
        let mut server = NormalizedServer::new("stdio:test");
        server.tools.push(NormalizedTool {
            name: "helper".to_string(),
            description: None,
            input_schema: serde_json::json!({}),
            metadata: Default::default(),
        });
        scan(server, 100)
    }

    #[test]
    fn render_contains_expected_sections() {
        let out = TerminalReporter.render(&sample_report());
        assert!(out.contains("Generator:"));
        assert!(out.contains("Category Scores:"));
        assert!(out.contains("Findings By Bucket:"));
        assert!(out.contains("Limitations:"));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn severity_is_uppercase_in_finding_lines() {
        let out = TerminalReporter.render(&sample_report());
        assert!(out.contains("- WARNING "));
    }
}
