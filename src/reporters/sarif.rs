//! SARIF 2.1.0 reporter.
//!
//! Emits one `runs[0]` entry with every registered rule under
//! `tool.driver.rules[]`, one `results[]` entry per finding, and compact
//! per-category scores on `runs[0].properties`. The `workingDirectory`
//! URI reflects the host process CWD at render time, which makes output
//! location-aware — two renders from different directories will differ
//! in that field alone.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::models::{Finding, NormalizedServer, Severity};
use crate::reporters::summary::build_report_summary;
use crate::reporters::Reporter;
use crate::scoring::{Report, RuleDescriptor};

pub const SARIF_SCHEMA_URI: &str = "https://json.schemastore.org/sarif-2.1.0.json";
pub const SARIF_VERSION: &str = "2.1.0";
pub const DRIVER_NAME: &str = "mcpunit";

pub struct SarifReporter;

impl Reporter for SarifReporter {
    fn id(&self) -> &'static str {
        "sarif"
    }

    fn render(&self, report: &Report) -> String {
        let value = report_to_sarif(report);
        let mut out = serde_json::to_string_pretty(&value)
            .expect("SARIF serialisation is infallible for owned maps");
        out.push('\n');
        out
    }
}

pub fn report_to_sarif(report: &Report) -> Value {
    let artifact_uri = infer_artifact_uri(&report.server);
    let scan_timestamp = report.generated_at.to_rfc3339();
    let summary = build_report_summary(report);

    let mut rules = Vec::new();
    for descriptor in &report.rule_descriptors {
        rules.push(serialize_rule_descriptor(descriptor));
    }

    let mut results = Vec::new();
    for finding in &report.findings {
        results.push(serialize_result(
            finding,
            &report.rule_descriptors,
            artifact_uri.as_deref(),
            &report.server.target,
        ));
    }

    let mut category_scores = Map::new();
    for bucket in crate::models::ScoreBucket::ALL {
        let breakdown = report.score.breakdown_for(*bucket);
        category_scores.insert(
            bucket.as_str().to_string(),
            json!({
                "score": breakdown.score,
                "max_score": breakdown.max_score,
                "penalty_points": breakdown.penalty_points,
                "finding_count": breakdown.finding_count,
            }),
        );
    }

    let working_directory_uri = std::env::current_dir()
        .ok()
        .and_then(|p| url_from_path(&p))
        .unwrap_or_else(|| "file:///".to_string());

    json!({
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": DRIVER_NAME,
                        "semanticVersion": report.toolkit_version,
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": true,
                        "endTimeUtc": scan_timestamp,
                        "workingDirectory": {"uri": working_directory_uri},
                    }
                ],
                "properties": {
                    "product_name": crate::PRODUCT_NAME,
                    "tool_name": crate::TOOL_NAME,
                    "report_schema_id": crate::REPORT_SCHEMA_ID,
                    "report_schema_version": report.schema_version,
                    "scan_timestamp": scan_timestamp,
                    "total_score": report.score.total_score,
                    "category_scores": Value::Object(category_scores),
                    "why_this_score": summary.why_score,
                    "limitations": summary.score_limits,
                },
                "results": results,
            }
        ],
    })
}

fn serialize_rule_descriptor(descriptor: &RuleDescriptor) -> Value {
    let level = sarif_level(descriptor.severity);
    let mut tags: Vec<String> = descriptor.tags.iter().map(|t| t.to_string()).collect();
    tags.push(descriptor.category.as_str().to_string());
    tags.push(descriptor.risk_category.as_str().to_string());
    tags.push(descriptor.bucket.as_str().to_string());
    let tags = dedup_preserve_order(tags);

    json!({
        "id": descriptor.rule_id,
        "name": descriptor.title,
        "shortDescription": {"text": descriptor.title},
        "fullDescription": {"text": descriptor.rationale},
        "defaultConfiguration": {"level": level},
        "help": {
            "text": format!(
                "{} Severity: {}. Score impact: {}.",
                descriptor.rationale,
                descriptor.severity.as_str(),
                descriptor.score_impact
            )
        },
        "properties": {
            "tags": tags,
            "precision": "medium",
            "problem.severity": sarif_problem_severity(descriptor.severity),
            "risk_category": descriptor.risk_category.as_str(),
            "bucket": descriptor.bucket.as_str(),
            "score_impact": descriptor.score_impact,
        },
    })
}

fn serialize_result(
    finding: &Finding,
    descriptors: &[RuleDescriptor],
    artifact_uri: Option<&str>,
    server_target: &str,
) -> Value {
    let rule_index = descriptors
        .iter()
        .position(|d| d.rule_id == finding.rule_id)
        .unwrap_or(0);
    let descriptor = descriptors.iter().find(|d| d.rule_id == finding.rule_id);

    let fingerprint = compute_fingerprint(finding, artifact_uri);

    let mut result = Map::new();
    result.insert("ruleId".to_string(), json!(finding.rule_id));
    result.insert("ruleIndex".to_string(), json!(rule_index));
    result.insert("level".to_string(), json!(sarif_level(finding.level)));
    result.insert("message".to_string(), json!({"text": finding.message}));
    result.insert(
        "partialFingerprints".to_string(),
        json!({"primaryLocationLineHash": fingerprint}),
    );

    let mut properties = Map::new();
    properties.insert(
        "risk_category".to_string(),
        json!(finding.risk_category.as_str()),
    );
    properties.insert("bucket".to_string(), json!(finding.bucket.as_str()));
    properties.insert("score_impact".to_string(), json!(finding.penalty));
    properties.insert("tool_name".to_string(), json!(finding.tool_name));
    properties.insert(
        "finding_category".to_string(),
        json!(finding.category.as_str()),
    );
    properties.insert("evidence".to_string(), json!(finding.evidence));
    if let Some(desc) = descriptor {
        properties.insert("check_title".to_string(), json!(desc.title));
        properties.insert("check_rationale".to_string(), json!(desc.rationale));
    }
    result.insert("properties".to_string(), Value::Object(properties));

    let (location_uri, is_synthetic) = match artifact_uri {
        Some(uri) => (uri.to_string(), false),
        None => (synthetic_location_uri(finding, server_target), true),
    };
    let mut location = Map::new();
    let mut physical = Map::new();
    physical.insert("artifactLocation".to_string(), json!({"uri": location_uri}));
    physical.insert("region".to_string(), json!({"startLine": 1}));
    location.insert("physicalLocation".to_string(), Value::Object(physical));
    if is_synthetic {
        let name = finding
            .tool_name
            .clone()
            .unwrap_or_else(|| server_target.to_string());
        location.insert(
            "logicalLocations".to_string(),
            Value::Array(vec![json!({
                "name": name,
                "kind": if finding.tool_name.is_some() { "function" } else { "module" },
            })]),
        );
    }
    if let Some(first) = finding.evidence.first() {
        location.insert("message".to_string(), json!({"text": first}));
    }
    result.insert(
        "locations".to_string(),
        Value::Array(vec![Value::Object(location)]),
    );

    if let Some(desc) = descriptor {
        result.insert("rule".to_string(), json!({"id": desc.rule_id}));
    }

    Value::Object(result)
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

fn sarif_problem_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "recommendation",
    }
}

fn dedup_preserve_order(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

fn compute_fingerprint(finding: &Finding, artifact_uri: Option<&str>) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(4 + finding.evidence.len());
    parts.push(finding.rule_id.clone());
    parts.push(finding.tool_name.clone().unwrap_or_default());
    parts.push(finding.message.clone());
    parts.push(artifact_uri.unwrap_or("").to_string());
    for ev in &finding.evidence {
        parts.push(ev.clone());
    }
    let source = parts.join("|");
    let mut hasher = Sha256::new();
    hasher.update(source.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn synthetic_location_uri(finding: &Finding, server_target: &str) -> String {
    if let Some(tool) = finding.tool_name.as_deref() {
        let encoded = tool.replace(' ', "%20");
        return format!("mcp-tool://{encoded}");
    }
    let encoded = server_target.replace(' ', "%20");
    format!("mcp-server://{encoded}")
}

fn infer_artifact_uri(server: &NormalizedServer) -> Option<String> {
    let mcp = server.metadata.get("mcp")?.as_object()?;
    let command = mcp.get("command")?.as_array()?;
    for part in command.iter().skip(1) {
        if let Some(p) = part.as_str() {
            if let Some(uri) = normalize_path_candidate(p) {
                return Some(uri);
            }
        }
    }
    command
        .first()
        .and_then(|v| v.as_str())
        .and_then(normalize_path_candidate)
}

fn normalize_path_candidate(candidate: &str) -> Option<String> {
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lowered = trimmed.to_ascii_lowercase();
    let suffixes = [
        ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".rb", ".go", ".java",
    ];
    let looks_like_file = suffixes.iter().any(|s| lowered.ends_with(s));
    let has_sep = trimmed.contains('/') || trimmed.contains('\\');
    if !looks_like_file && !has_sep {
        return None;
    }
    Some(trimmed.replace('\\', "/"))
}

fn url_from_path(path: &std::path::Path) -> Option<String> {
    let s = path.to_str()?;
    // Very minimal file:// URI encoding — good enough for SARIF
    // workingDirectory which is purely informational.
    let encoded = s.replace(' ', "%20");
    if encoded.starts_with('/') {
        Some(format!("file://{encoded}"))
    } else {
        Some(format!("file:///{}", encoded.replace('\\', "/")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{FindingCategory, NormalizedTool, RiskCategory, ScoreBucket};
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
    fn render_produces_valid_sarif() {
        let out = SarifReporter.render(&sample_report());
        let parsed: Value = serde_json::from_str(out.trim_end()).unwrap();
        assert_eq!(parsed["version"], SARIF_VERSION);
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], DRIVER_NAME);
    }

    #[test]
    fn rules_section_has_all_registered_rules() {
        let report = sample_report();
        let out = SarifReporter.render(&report);
        let parsed: Value = serde_json::from_str(out.trim_end()).unwrap();
        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 24);
    }

    #[test]
    fn every_result_has_at_least_one_location() {
        let report = sample_report();
        let out = SarifReporter.render(&report);
        let parsed: Value = serde_json::from_str(out.trim_end()).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert!(!results.is_empty(), "sample report should produce findings");
        for result in results {
            let locations = result["locations"].as_array().unwrap_or_else(|| {
                panic!("result missing locations[]: {result}");
            });
            assert!(
                !locations.is_empty(),
                "result has empty locations[]: {result}"
            );
            let uri = locations[0]["physicalLocation"]["artifactLocation"]["uri"].as_str();
            assert!(uri.is_some() && !uri.unwrap().is_empty());
        }
    }

    #[test]
    fn synthetic_uri_uses_tool_name_then_server_target() {
        let finding_with_tool = Finding {
            rule_id: "r".into(),
            level: Severity::Warning,
            title: None,
            message: "m".into(),
            category: FindingCategory::ToolIdentity,
            risk_category: RiskCategory::MetadataHygiene,
            bucket: ScoreBucket::Metadata,
            evidence: vec![],
            penalty: 1,
            tool_name: Some("helper".into()),
            prompt_name: None,
            metadata: Default::default(),
        };
        assert_eq!(
            synthetic_location_uri(&finding_with_tool, "stdio:test"),
            "mcp-tool://helper"
        );

        let mut finding_no_tool = finding_with_tool.clone();
        finding_no_tool.tool_name = None;
        assert_eq!(
            synthetic_location_uri(&finding_no_tool, "stdio:test"),
            "mcp-server://stdio:test"
        );
    }

    #[test]
    fn fingerprint_is_sha256_hex() {
        let finding = Finding {
            rule_id: "a".to_string(),
            level: Severity::Warning,
            title: None,
            message: "m".to_string(),
            category: FindingCategory::ToolIdentity,
            risk_category: RiskCategory::MetadataHygiene,
            bucket: ScoreBucket::Metadata,
            evidence: vec!["e".to_string()],
            penalty: 10,
            tool_name: Some("t".to_string()),
            prompt_name: None,
            metadata: Default::default(),
        };
        let fp = compute_fingerprint(&finding, None);
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
