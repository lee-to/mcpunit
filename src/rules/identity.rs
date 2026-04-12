//! Identity rules — checks that live on the tool's **name**.
//!
//! A tool name is the first thing an agent sees when browsing an MCP
//! server, so ambiguity here has an outsized cost: duplicate names collide
//! in tool-choice prompts, and generic names ("helper", "do_it", ...)
//! carry zero information. Both rules scored here are catalogue hygiene —
//! they do not look at capabilities.

use std::collections::BTreeMap;

use crate::models::{
    Finding, FindingCategory, NormalizedServer, RiskCategory, ScoreBucket, Severity,
};
use crate::rules::helpers::{normalize_text, single_quoted_repr};
use crate::rules::Rule;

// --- duplicate_tool_names -------------------------------------------------

/// Rule: `duplicate_tool_names`. Fires once per duplicated name.
pub struct DuplicateNames;

impl Rule for DuplicateNames {
    fn id(&self) -> &'static str {
        "duplicate_tool_names"
    }
    fn title(&self) -> &'static str {
        "Duplicate tool names"
    }
    fn rationale(&self) -> &'static str {
        "Tool names should be unique within one MCP server."
    }
    fn severity(&self) -> Severity {
        Severity::Error
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::ToolIdentity
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::MetadataHygiene
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Conformance
    }
    fn tags(&self) -> &'static [&'static str] {
        &["tools", "identity"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        // Count tool names while preserving first-seen order so evidence
        // ordering is deterministic across runs.
        let mut order: Vec<String> = Vec::new();
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for tool in &server.tools {
            if !counts.contains_key(&tool.name) {
                order.push(tool.name.clone());
            }
            *counts.entry(tool.name.clone()).or_insert(0) += 1;
        }

        let mut findings = Vec::new();
        for name in order {
            let count = counts[&name];
            if count < 2 {
                continue;
            }
            let message = format!(
                "Tool name {} appears {count} times in the server tool list.",
                single_quoted_repr(&name)
            );
            findings.push(self.make_finding(
                message,
                vec![
                    format!("duplicate_count={count}"),
                    format!("tool_name={name}"),
                ],
                Some(name),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

// --- overly_generic_tool_name ---------------------------------------------

/// Rule: `overly_generic_tool_name`. Fires on known-noise names like
/// `helper`, `do_it`, `tool`, etc.
pub struct GenericName;

/// Names so generic they carry no behaviour information at all. Matched
/// after lowercasing and normalising separators (`-`, space → `_`).
const GENERIC_NAMES: &[&str] = &[
    "do_it",
    "helper",
    "tool",
    "utility",
    "misc",
    "misc_tool",
    "action",
    "process",
    "handler",
    "run",
];

impl Rule for GenericName {
    fn id(&self) -> &'static str {
        "overly_generic_tool_name"
    }
    fn title(&self) -> &'static str {
        "Overly generic tool name"
    }
    fn rationale(&self) -> &'static str {
        "Tool names should communicate behavior clearly."
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::ToolIdentity
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::MetadataHygiene
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Ergonomics
    }
    fn tags(&self) -> &'static [&'static str] {
        &["tools", "identity"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for tool in &server.tools {
            let normalized = normalize_text(Some(&tool.name)).replace(['-', ' '], "_");
            if !GENERIC_NAMES.contains(&normalized.as_str()) {
                continue;
            }
            let message = format!(
                "Tool {} uses an overly generic name that hides its behavior.",
                single_quoted_repr(&tool.name)
            );
            findings.push(self.make_finding(
                message,
                vec![format!("tool_name={}", single_quoted_repr(&tool.name))],
                Some(tool.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::NormalizedTool;

    fn bare_tool(name: &str) -> NormalizedTool {
        NormalizedTool {
            name: name.to_string(),
            description: None,
            input_schema: serde_json::json!({}),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn duplicate_names_fires_once_per_collision() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(bare_tool("echo"));
        server.tools.push(bare_tool("echo"));
        server.tools.push(bare_tool("unique"));
        let findings = DuplicateNames.evaluate(&server);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("'echo'"));
        assert!(findings[0]
            .evidence
            .contains(&"duplicate_count=2".to_string()));
    }

    #[test]
    fn duplicate_names_is_silent_when_all_unique() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(bare_tool("a"));
        server.tools.push(bare_tool("b"));
        assert!(DuplicateNames.evaluate(&server).is_empty());
    }

    #[test]
    fn generic_name_flags_known_noise() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(bare_tool("helper"));
        server.tools.push(bare_tool("do-it"));
        server.tools.push(bare_tool("read_invoices"));
        let findings = GenericName.evaluate(&server);
        assert_eq!(findings.len(), 2);
    }
}
