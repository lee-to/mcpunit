//! Description rules — checks that live on the tool's free-text
//! `description` field. Missing or vague descriptions leave agents unable
//! to pick the right tool; both rules here flag that class of problem.

use std::collections::BTreeMap;

use crate::models::{
    Finding, FindingCategory, NormalizedServer, RiskCategory, ScoreBucket, Severity,
};
use crate::rules::helpers::{alnum_tokens, single_quoted_repr};
use crate::rules::Rule;

// --- missing_tool_description ---------------------------------------------

/// Rule: `missing_tool_description`. Fires on tools where
/// `description` is absent or null.
pub struct MissingDescription;

impl Rule for MissingDescription {
    fn id(&self) -> &'static str {
        "missing_tool_description"
    }
    fn title(&self) -> &'static str {
        "Missing tool description"
    }
    fn rationale(&self) -> &'static str {
        "Each tool should include a non-empty description."
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::ToolDescription
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::MetadataHygiene
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Metadata
    }
    fn tags(&self) -> &'static [&'static str] {
        &["tools", "description"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for tool in &server.tools {
            if tool.description.is_some() {
                continue;
            }
            let message = format!(
                "Tool {} does not provide a description.",
                single_quoted_repr(&tool.name)
            );
            findings.push(self.make_finding(
                message,
                vec![
                    format!("tool_name={}", tool.name),
                    "description=<missing>".to_string(),
                ],
                Some(tool.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

// --- vague_tool_description -----------------------------------------------

/// Rule: `vague_tool_description`. Fires on descriptions that are either
/// a known vague phrase (`"helps with stuff"`) or a three-word-or-less
/// string containing a vague keyword (`misc`, `helper`, ...).
pub struct VagueDescription;

/// Full phrases we recognise as zero-information placeholders.
const VAGUE_PHRASES: &[&str] = &[
    "helps with stuff",
    "does things",
    "tool",
    "utility tool",
    "misc helper",
    "general helper",
];

/// Words that, when combined with a short description, flag it as vague.
const VAGUE_WORDS: &[&str] = &["stuff", "things", "helper", "misc", "various", "general"];

impl Rule for VagueDescription {
    fn id(&self) -> &'static str {
        "vague_tool_description"
    }
    fn title(&self) -> &'static str {
        "Vague tool description"
    }
    fn rationale(&self) -> &'static str {
        "Tool descriptions should clearly explain what the tool does."
    }
    fn severity(&self) -> Severity {
        Severity::Warning
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::ToolDescription
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::MetadataHygiene
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Ergonomics
    }
    fn tags(&self) -> &'static [&'static str] {
        &["tools", "description"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for tool in &server.tools {
            let Some(raw_description) = tool.description.as_deref() else {
                continue;
            };
            let tokens = alnum_tokens(&raw_description.to_ascii_lowercase());
            if tokens.is_empty() {
                continue;
            }
            let normalized: String = tokens.join(" ");
            let words: Vec<&str> = normalized.split_whitespace().collect();

            let is_known_phrase = VAGUE_PHRASES.iter().any(|p| *p == normalized);
            let is_short_and_generic =
                words.len() <= 3 && words.iter().any(|w| VAGUE_WORDS.contains(w));

            if !(is_known_phrase || is_short_and_generic) {
                continue;
            }

            let mut evidence = vec![
                format!("description={}", single_quoted_repr(raw_description)),
                format!("word_count={}", words.len()),
            ];
            if is_known_phrase {
                evidence.push(format!(
                    "matched_phrase={}",
                    single_quoted_repr(&normalized)
                ));
            } else {
                evidence.push("matched_heuristic=short_generic_description".to_string());
            }

            let message = format!(
                "Tool {} uses a vague description that does not explain its behavior clearly.",
                single_quoted_repr(&tool.name)
            );
            findings.push(self.make_finding(
                message,
                evidence,
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

    fn with_description(name: &str, desc: Option<&str>) -> NormalizedTool {
        NormalizedTool {
            name: name.to_string(),
            description: desc.map(String::from),
            input_schema: serde_json::json!({}),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn missing_description_fires_when_absent() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_description("bare", None));
        server
            .tools
            .push(with_description("ok", Some("does real work")));
        let findings = MissingDescription.evaluate(&server);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name.as_deref(), Some("bare"));
    }

    #[test]
    fn vague_description_flags_known_phrase() {
        let mut server = NormalizedServer::new("test");
        server
            .tools
            .push(with_description("a", Some("Helps with stuff")));
        let findings = VagueDescription.evaluate(&server);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|e| e.contains("matched_phrase='helps with stuff'")));
    }

    #[test]
    fn vague_description_flags_short_generic() {
        let mut server = NormalizedServer::new("test");
        server
            .tools
            .push(with_description("a", Some("misc things")));
        assert_eq!(VagueDescription.evaluate(&server).len(), 1);
    }

    #[test]
    fn vague_description_ignores_specific_text() {
        let mut server = NormalizedServer::new("test");
        server.tools.push(with_description(
            "a",
            Some("fetches purchase orders for the specified customer"),
        ));
        assert!(VagueDescription.evaluate(&server).is_empty());
    }
}
