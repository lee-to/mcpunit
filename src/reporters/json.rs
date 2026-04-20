//! JSON report reporter.
//!
//! Serialises a [`Report`] as 2-space indented JSON with a trailing
//! newline. Object key order is deterministic — `serde_json` with the
//! `preserve_order` feature honours insertion order in every
//! [`serde_json::Map`] we build here.
//!
//! ## Top-level shape
//!
//! ```json
//! {
//!   "schema":   { ... identity + generator },
//!   "test":     { timestamp, target },
//!   "inventory":{ tool_count, tools[] },
//!   "audit":    { total_score, category_scores, finding_counts, ... },
//!   "rules":    [ ... registered rule descriptors ],
//!   "findings": [ ... fired findings ],
//!   "findings_by_bucket": [ ... same findings grouped ]
//! }
//! ```
//!
//! The split is deliberate:
//!
//! * `schema` is self-identification: schema id/version plus generator name
//!   and version. One merged block, not two.
//! * `test` is "how the test was invoked".
//! * `inventory` is "what the target advertised".
//! * `audit` is "what the scorer concluded".
//! * `rules` is the static check catalogue (one entry per registered
//!   rule, whether it fired or not).
//! * `findings` / `findings_by_bucket` are two views of the same data —
//!   reporters downstream can pick whichever shape they need.

use serde_json::{json, Map, Value};

use crate::models::{Finding, NormalizedServer, NormalizedTool, ScoreBucket};
use crate::reporters::summary::{
    build_report_summary, BucketFindingsGroup, ReportSummary, SeverityCounts, SummaryFinding,
};
use crate::reporters::Reporter;
use crate::scoring::{CategoryScoreBreakdown, Report, RuleDescriptor, ScoreBreakdown};

pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn id(&self) -> &'static str {
        "json"
    }

    fn render(&self, report: &Report) -> String {
        let value = report_to_json(report);
        let mut out = serde_json::to_string_pretty(&value)
            .expect("JSON serialisation is infallible for owned maps");
        out.push('\n');
        out
    }
}

pub fn report_to_json(report: &Report) -> Value {
    let summary = build_report_summary(report);
    let scan_timestamp = report.generated_at.to_rfc3339();

    let mut root = Map::new();

    // --- schema (self-identification) --------------------------------------
    root.insert(
        "schema".to_string(),
        json!({
            "id": crate::REPORT_SCHEMA_ID,
            "version": report.schema_version,
            "generator": {
                "name": crate::TOOL_NAME,
                "version": report.toolkit_version,
            },
        }),
    );

    // --- test (invocation context) -----------------------------------------
    root.insert(
        "test".to_string(),
        json!({
            "timestamp": scan_timestamp,
            "target": serialize_target(&report.server),
        }),
    );

    // --- inventory (what the server advertised) ----------------------------
    root.insert(
        "inventory".to_string(),
        json!({
            "tool_count": summary.tool_count,
            "tools": report.server.tools.iter().map(serialize_tool).collect::<Vec<_>>(),
        }),
    );

    // --- audit (the scored verdict) ----------------------------------------
    root.insert("audit".to_string(), serialize_audit(report, &summary));

    // --- rules (the static catalogue) --------------------------------------
    root.insert(
        "rules".to_string(),
        Value::Array(
            report
                .rule_descriptors
                .iter()
                .map(serialize_rule_descriptor)
                .collect(),
        ),
    );

    // --- findings (flat list) ----------------------------------------------
    root.insert(
        "findings".to_string(),
        Value::Array(
            report
                .findings
                .iter()
                .map(|f| serialize_finding(f, report.rule_descriptor(&f.rule_id)))
                .collect(),
        ),
    );

    // --- findings_by_bucket (grouped view) ---------------------------------
    root.insert(
        "findings_by_bucket".to_string(),
        Value::Array(
            summary
                .findings_by_bucket
                .iter()
                .map(serialize_bucket_findings_group)
                .collect(),
        ),
    );

    Value::Object(root)
}

fn serialize_target(server: &NormalizedServer) -> Value {
    let transport = infer_transport(server);
    json!({
        "raw": server.target,
        "transport": transport,
        "description": target_description(transport.as_deref()),
        "server": {
            "name": server.name,
            "version": server.version,
            "protocol_version": protocol_version(server),
        },
        "metadata": server.metadata.clone(),
    })
}

fn serialize_tool(tool: &NormalizedTool) -> Value {
    json!({
        "name": tool.name,
        "description": tool.description,
        "input_schema": tool.input_schema.clone(),
        "metadata": tool.metadata.clone(),
    })
}

fn serialize_rule_descriptor(descriptor: &RuleDescriptor) -> Value {
    json!({
        "id": descriptor.rule_id,
        "title": descriptor.title,
        "bucket": descriptor.bucket.as_str(),
        "severity": descriptor.severity.as_str(),
        "rationale": descriptor.rationale,
        "category": descriptor.category.as_str(),
        "risk_category": descriptor.risk_category.as_str(),
        "score_impact": descriptor.score_impact,
        "tags": descriptor.tags,
    })
}

fn serialize_finding(finding: &Finding, descriptor: Option<&RuleDescriptor>) -> Value {
    let title = finding
        .title
        .clone()
        .or_else(|| descriptor.map(|d| d.title.to_string()));
    let rationale = descriptor.map(|d| d.rationale.to_string());
    json!({
        "rule_id": finding.rule_id,
        "title": title,
        "bucket": finding.bucket.as_str(),
        "severity": finding.level.as_str(),
        "rationale": rationale,
        "category": finding.category.as_str(),
        "risk_category": finding.risk_category.as_str(),
        "tool_name": finding.tool_name,
        "message": finding.message,
        "evidence": finding.evidence.clone(),
        "score_impact": finding.penalty,
    })
}

fn serialize_audit(report: &Report, summary: &ReportSummary) -> Value {
    json!({
        "total_score": {
            "value": report.score.total_score,
            "max": report.score.max_score,
            "penalty_points": report.score.total_penalty_points,
        },
        "category_scores": serialize_category_breakdown(&report.score),
        "finding_counts": serialize_finding_counts(summary),
        "why_this_score": summary.why_score,
        "methodology": summary.score_meaning,
        "caveats": summary.score_limits,
    })
}

fn serialize_category_breakdown(score: &ScoreBreakdown) -> Value {
    // Iterate ScoreBucket::ALL in declaration order so the output is stable.
    let mut map = Map::new();
    for bucket in ScoreBucket::ALL {
        let breakdown = score.breakdown_for(*bucket);
        map.insert(
            bucket.as_str().to_string(),
            serialize_category_score(breakdown),
        );
    }
    Value::Object(map)
}

fn serialize_category_score(breakdown: &CategoryScoreBreakdown) -> Value {
    let mut penalties = Map::new();
    for (rule_id, penalty) in &breakdown.rule_penalties {
        penalties.insert(rule_id.clone(), json!(penalty));
    }
    json!({
        "score": breakdown.score,
        "max_score": breakdown.max_score,
        "penalty_points": breakdown.penalty_points,
        "finding_count": breakdown.finding_count,
        "rule_penalties": Value::Object(penalties),
    })
}

fn serialize_finding_counts(summary: &ReportSummary) -> Value {
    let mut by_bucket = Map::new();
    for bucket in &summary.bucket_summary {
        by_bucket.insert(
            bucket.bucket.as_str().to_string(),
            json!({
                "finding_count": bucket.finding_count,
                "penalty_points": bucket.penalty_points,
            }),
        );
    }
    json!({
        "total": summary.finding_count,
        "by_severity": serialize_severity_counts(&summary.severity_counts),
        "by_bucket": Value::Object(by_bucket),
    })
}

fn serialize_severity_counts(counts: &SeverityCounts) -> Value {
    json!({
        "info": counts.info,
        "warning": counts.warning,
        "error": counts.error,
    })
}

fn serialize_bucket_findings_group(group: &BucketFindingsGroup) -> Value {
    json!({
        "bucket": group.bucket.as_str(),
        "label": group.label,
        "finding_count": group.finding_count,
        "penalty_points": group.penalty_points,
        "findings": group.findings.iter().map(serialize_summary_finding).collect::<Vec<_>>(),
    })
}

pub(crate) fn serialize_summary_finding(finding: &SummaryFinding) -> Value {
    json!({
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity.as_str(),
        "bucket": finding.bucket.as_str(),
        "risk_category": finding.risk_category.as_str(),
        "tool_name": finding.tool_name,
        "rationale": finding.rationale,
        "message": finding.message,
        "score_impact": finding.score_impact,
    })
}

fn infer_transport(server: &NormalizedServer) -> Option<String> {
    if let Some(Value::Object(mcp)) = server.metadata.get("mcp") {
        if let Some(Value::String(t)) = mcp.get("transport") {
            if !t.trim().is_empty() {
                return Some(t.trim().to_string());
            }
        }
    }
    server.target.split_once(':').and_then(|(prefix, _)| {
        let t = prefix.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    })
}

fn target_description(transport: Option<&str>) -> String {
    match transport {
        Some("stdio") => "Local MCP server launched over stdio.".to_string(),
        Some(other) => format!("MCP server target evaluated over {other}."),
        None => "MCP server target under evaluation.".to_string(),
    }
}

fn protocol_version(server: &NormalizedServer) -> Option<String> {
    server
        .metadata
        .get("mcp")
        .and_then(Value::as_object)
        .and_then(|m| m.get("protocolVersion"))
        .and_then(Value::as_str)
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::NormalizedServer;
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
    fn render_has_trailing_newline_and_valid_json() {
        let out = JsonReporter.render(&sample_report());
        assert!(out.ends_with('\n'));
        let parsed: Value = serde_json::from_str(out.trim_end()).unwrap();
        assert!(parsed["schema"]["id"].as_str().unwrap().contains("mcpunit"));
        assert_eq!(parsed["audit"]["total_score"]["max"], 100);
    }

    #[test]
    fn schema_section_contains_merged_generator() {
        let out = JsonReporter.render(&sample_report());
        let parsed: Value = serde_json::from_str(out.trim_end()).unwrap();
        assert_eq!(parsed["schema"]["generator"]["name"], "mcpunit");
        assert!(parsed["schema"]["generator"]["version"].is_string());
        // `generator` is nested inside `schema`, not a top-level sibling.
        assert!(parsed.get("generator").is_none());
    }

    #[test]
    fn top_level_keys_are_in_expected_order() {
        let out = JsonReporter.render(&sample_report());
        // A deterministic key order lets diff tools align audits across
        // runs cleanly. This test freezes the order.
        let expected = [
            "\"schema\"",
            "\"test\"",
            "\"inventory\"",
            "\"audit\"",
            "\"rules\"",
            "\"findings\"",
            "\"findings_by_bucket\"",
        ];
        let mut cursor = 0;
        for key in expected {
            let idx = out[cursor..]
                .find(key)
                .unwrap_or_else(|| panic!("missing {key} in JSON output"));
            cursor += idx + key.len();
        }
        // `metadata` empty object must not appear at the top level.
        let meta_at_top = out.contains("\n  \"metadata\": {}");
        assert!(!meta_at_top, "top-level `metadata` should be gone");
    }

    #[test]
    fn category_scores_are_in_declaration_order() {
        let out = JsonReporter.render(&sample_report());
        let start = out
            .find("\"category_scores\"")
            .expect("category_scores key");
        let slice = &out[start..];
        let end_of_section = slice.find("\"finding_counts\"").unwrap_or(slice.len());
        let section = &slice[..end_of_section];
        let pos_conf = section.find("\"conformance\"").unwrap();
        let pos_sec = section.find("\"security\"").unwrap();
        let pos_erg = section.find("\"ergonomics\"").unwrap();
        let pos_meta = section.find("\"metadata\"").unwrap();
        assert!(pos_conf < pos_sec);
        assert!(pos_sec < pos_erg);
        assert!(pos_erg < pos_meta);
    }

    #[test]
    fn rules_section_has_all_registered_rules() {
        let report = sample_report();
        let out = JsonReporter.render(&report);
        let parsed: Value = serde_json::from_str(out.trim_end()).unwrap();
        let rules = parsed["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 23);
    }

    #[test]
    fn finding_severity_is_lowercase_string() {
        let report = sample_report();
        let out = JsonReporter.render(&report);
        assert!(out.contains("\"severity\": \"warning\""));
    }

    #[test]
    fn finding_uses_rule_id_key() {
        let report = sample_report();
        let out = JsonReporter.render(&report);
        assert!(out.contains("\"rule_id\""));
        assert!(!out.contains("\"check_id\""));
    }

    #[test]
    fn audit_section_uses_methodology_and_caveats() {
        let out = JsonReporter.render(&sample_report());
        let parsed: Value = serde_json::from_str(out.trim_end()).unwrap();
        assert!(parsed["audit"]["methodology"].is_string());
        assert!(parsed["audit"]["caveats"].is_array());
    }
}
