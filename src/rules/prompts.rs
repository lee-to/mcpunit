//! Prompt rules — catalogue hygiene for the `prompts/list` surface.
//!
//! MCP servers may expose prompts (parameterised message templates) in
//! addition to — or instead of — tools. An agent sees prompt name,
//! description, and arguments the same way it sees a tool; the same
//! cost structure applies: bad metadata → wrong selection → broken
//! user flow. These rules mirror the shape of the tool-identity and
//! tool-description families but operate on [`NormalizedServer::prompts`].
//!
//! Six rules live here, split between identity (`prompt_duplicate_name`,
//! `prompt_duplicate_argument_name`) and description
//! (`prompt_missing_description`, `prompt_description_too_short`,
//! `prompt_description_matches_name`,
//! `prompt_argument_missing_description`). Conformance-critical rules
//! (duplicate names and argument names) fall in [`ScoreBucket::Conformance`];
//! the rest are hygiene in [`ScoreBucket::Metadata`].
//!
//! Severity tracks the MCP spec (2025-11-25) strictly: all four
//! description rules are `Severity::Info` because (a) the spec marks
//! `Prompt.description` and `PromptArgument.description` as optional,
//! and (b) the spec imposes no length, originality, or quality
//! requirement on the field when it **is** present. `Info` keeps the
//! findings visible (terminal, markdown, SARIF `note`) without
//! penalising the score — spec-silent heuristics should not gate CI.
//! The two identity rules stay `Error` because duplicate names break
//! `prompts/get` resolution and duplicate argument names are physically
//! unrepresentable in the `prompts/get` argument dict.
//!
//! Prompt naming is deliberately not linted: the MCP spec puts no
//! casing or regex constraint on `name`, so snake_case checks would be
//! opinion, not conformance.

use std::collections::BTreeMap;

use crate::models::{
    Finding, FindingCategory, NormalizedServer, RiskCategory, ScoreBucket, Severity,
};
use crate::rules::helpers::{normalize_text, single_quoted_repr};
use crate::rules::Rule;

// --- prompt_duplicate_name -----------------------------------------------

/// Rule: `prompt_duplicate_name`. Fires once per duplicated prompt name.
/// Duplicate names make `prompts/get` non-deterministic on the server —
/// the spec implies per-server uniqueness.
pub struct DuplicatePromptNames;

impl Rule for DuplicatePromptNames {
    fn id(&self) -> &'static str {
        "prompt_duplicate_name"
    }
    fn title(&self) -> &'static str {
        "Duplicate prompt names"
    }
    fn rationale(&self) -> &'static str {
        "Prompt names should be unique within one MCP server."
    }
    fn severity(&self) -> Severity {
        Severity::Error
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::PromptIdentity
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::MetadataHygiene
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Conformance
    }
    fn tags(&self) -> &'static [&'static str] {
        &["prompts", "identity"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut order: Vec<String> = Vec::new();
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for prompt in &server.prompts {
            if !counts.contains_key(&prompt.name) {
                order.push(prompt.name.clone());
            }
            *counts.entry(prompt.name.clone()).or_insert(0) += 1;
        }

        let mut findings = Vec::new();
        for name in order {
            let count = counts[&name];
            if count < 2 {
                continue;
            }
            findings.push(self.make_prompt_finding(
                format!(
                    "Prompt name {} appears {count} times in the server prompt list.",
                    single_quoted_repr(&name)
                ),
                vec![
                    format!("duplicate_count={count}"),
                    format!("prompt_name={name}"),
                ],
                Some(name),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

// --- prompt_missing_description ------------------------------------------

/// Rule: `prompt_missing_description`. Fires when a prompt has no
/// description or the description is empty after trimming. The MCP spec
/// (2025-11-25) marks `Prompt.description` explicitly as *Optional*, so
/// omitting it is spec-valid. This rule surfaces the absence as an
/// advisory — agents without a description have to guess intent from the
/// name alone — but does not penalise the score. Contrast with the
/// tool-side `missing_tool_description`, where the spec does **not**
/// mark `Tool.description` as optional and the severity stays `WARNING`.
pub struct MissingPromptDescription;

impl Rule for MissingPromptDescription {
    fn id(&self) -> &'static str {
        "prompt_missing_description"
    }
    fn title(&self) -> &'static str {
        "Prompt missing description"
    }
    fn rationale(&self) -> &'static str {
        "Prompts without descriptions force the agent to guess intent from the name alone. The MCP spec marks the field optional, so this is advisory only."
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::PromptDescription
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::MetadataHygiene
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Metadata
    }
    fn tags(&self) -> &'static [&'static str] {
        &["prompts", "description"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for prompt in &server.prompts {
            let empty = prompt
                .description
                .as_deref()
                .map(|s| s.trim().is_empty())
                .unwrap_or(true);
            if !empty {
                continue;
            }
            findings.push(self.make_prompt_finding(
                format!(
                    "Prompt {} has no description.",
                    single_quoted_repr(&prompt.name)
                ),
                vec![format!("prompt_name={}", prompt.name)],
                Some(prompt.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

// --- prompt_description_matches_name -------------------------------------

/// Rule: `prompt_description_matches_name`. Fires when the description
/// is literally the prompt name (case-insensitive, ignoring whitespace
/// and punctuation). That pattern usually indicates a stub description
/// autogenerated from the name. The MCP spec does not require
/// originality (or presence) of `description`, so this is advisory only
/// — `Severity::Info`, zero score penalty. Since an empty description
/// is spec-valid, a description that merely restates the name cannot
/// be *stricter* than empty.
pub struct PromptDescriptionMatchesName;

impl Rule for PromptDescriptionMatchesName {
    fn id(&self) -> &'static str {
        "prompt_description_matches_name"
    }
    fn title(&self) -> &'static str {
        "Prompt description restates the name"
    }
    fn rationale(&self) -> &'static str {
        "Descriptions should add information beyond the prompt's identifier. Advisory only — the MCP spec does not require descriptions to differ from names."
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::PromptDescription
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::MetadataHygiene
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Metadata
    }
    fn tags(&self) -> &'static [&'static str] {
        &["prompts", "description"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for prompt in &server.prompts {
            let Some(description) = prompt.description.as_deref() else {
                continue;
            };
            let normalized_name = normalize_text(Some(&prompt.name));
            let normalized_desc = normalize_text(Some(description));
            if normalized_desc.is_empty() {
                continue;
            }
            // Strip non-alphanumeric characters so "write_file" matches
            // "Write File" and "write-file." alike.
            let compact =
                |s: &str| -> String { s.chars().filter(|c| c.is_alphanumeric()).collect() };
            if compact(&normalized_name) != compact(&normalized_desc) {
                continue;
            }
            findings.push(self.make_prompt_finding(
                format!(
                    "Prompt {} description only restates the prompt name.",
                    single_quoted_repr(&prompt.name)
                ),
                vec![
                    format!("prompt_name={}", prompt.name),
                    format!("description={description}"),
                ],
                Some(prompt.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

// --- prompt_duplicate_argument_name --------------------------------------

/// Rule: `prompt_duplicate_argument_name`. Flags prompts that declare
/// two or more arguments with the same `name`. The MCP spec implies
/// per-prompt argument uniqueness — duplicates make `prompts/get` param
/// routing ambiguous and break every client that maps arguments into a
/// dict by name.
pub struct PromptDuplicateArgumentName;

impl Rule for PromptDuplicateArgumentName {
    fn id(&self) -> &'static str {
        "prompt_duplicate_argument_name"
    }
    fn title(&self) -> &'static str {
        "Duplicate prompt argument name"
    }
    fn rationale(&self) -> &'static str {
        "Argument names must be unique within a single prompt so client-side dictionaries do not silently overwrite values."
    }
    fn severity(&self) -> Severity {
        Severity::Error
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::PromptIdentity
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::MetadataHygiene
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Conformance
    }
    fn tags(&self) -> &'static [&'static str] {
        &["prompts", "identity", "arguments"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for prompt in &server.prompts {
            let mut order: Vec<String> = Vec::new();
            let mut counts: BTreeMap<String, usize> = BTreeMap::new();
            for arg in &prompt.arguments {
                if !counts.contains_key(&arg.name) {
                    order.push(arg.name.clone());
                }
                *counts.entry(arg.name.clone()).or_insert(0) += 1;
            }
            let duplicates: Vec<String> = order.into_iter().filter(|n| counts[n] > 1).collect();
            if duplicates.is_empty() {
                continue;
            }
            findings.push(self.make_prompt_finding(
                format!(
                    "Prompt {} declares duplicate argument names: {}.",
                    single_quoted_repr(&prompt.name),
                    duplicates
                        .iter()
                        .map(|n| format!("'{n}'"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                vec![
                    format!("prompt_name={}", prompt.name),
                    format!(
                        "duplicate_arguments=[{}]",
                        duplicates
                            .iter()
                            .map(|n| format!("'{n}'"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ],
                Some(prompt.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

// --- prompt_description_too_short ----------------------------------------

/// Rule: `prompt_description_too_short`. Flags descriptions that are
/// non-empty but under [`PROMPT_DESC_MIN_CHARS`] characters. A very
/// short description usually conveys no actionable information beyond
/// the name (e.g. "Summarise." for a prompt named `summarize`).
///
/// The threshold is deliberately conservative — the aim is to catch
/// one-word stubs, not penalise terse-but-informative descriptions.
/// The MCP spec defines **no** minimum length for `description` (and
/// the field itself is optional), so this is advisory only —
/// `Severity::Info`, zero score penalty. Since an empty description is
/// spec-valid, a short-but-present one cannot be *stricter*.
pub struct PromptDescriptionTooShort;

/// Minimum character count for a useful prompt description. Threshold
/// picked by scanning public MCP-prompt repositories: virtually every
/// hand-written description crosses 20 characters, while autogenerated
/// stubs sit well below. The MCP spec itself imposes no such minimum.
pub const PROMPT_DESC_MIN_CHARS: usize = 20;

impl Rule for PromptDescriptionTooShort {
    fn id(&self) -> &'static str {
        "prompt_description_too_short"
    }
    fn title(&self) -> &'static str {
        "Prompt description too short"
    }
    fn rationale(&self) -> &'static str {
        "Very short descriptions do not give the agent enough signal to pick the right prompt. Advisory only — the MCP spec does not impose a minimum length."
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::PromptDescription
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::MetadataHygiene
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Metadata
    }
    fn tags(&self) -> &'static [&'static str] {
        &["prompts", "description"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for prompt in &server.prompts {
            let Some(description) = prompt.description.as_deref() else {
                continue;
            };
            let trimmed = description.trim();
            if trimmed.is_empty() {
                // `prompt_missing_description` covers the empty case;
                // skipping here avoids double-counting the same issue.
                continue;
            }
            let chars = trimmed.chars().count();
            if chars >= PROMPT_DESC_MIN_CHARS {
                continue;
            }
            findings.push(self.make_prompt_finding(
                format!(
                    "Prompt {} description is only {} character(s); under {} is treated as a stub.",
                    single_quoted_repr(&prompt.name),
                    chars,
                    PROMPT_DESC_MIN_CHARS,
                ),
                vec![
                    format!("prompt_name={}", prompt.name),
                    format!("description_chars={chars}"),
                    format!("threshold={PROMPT_DESC_MIN_CHARS}"),
                ],
                Some(prompt.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

// --- prompt_argument_missing_description ---------------------------------

/// Rule: `prompt_argument_missing_description`. Fires for any declared
/// argument that has no description. One finding per offending prompt
/// (not per argument) to keep reports terse. The MCP spec (2025-11-25)
/// does not mark `PromptArgument.description` as required — the
/// Prompts data-type section only formalises prompt-level fields — so
/// by default we treat it as optional, matching `Prompt.description`.
/// Severity is `Info`: advisory, zero score penalty.
pub struct PromptArgumentMissingDescription;

impl Rule for PromptArgumentMissingDescription {
    fn id(&self) -> &'static str {
        "prompt_argument_missing_description"
    }
    fn title(&self) -> &'static str {
        "Prompt argument missing description"
    }
    fn rationale(&self) -> &'static str {
        "Agents have no way to fill prompt arguments correctly if each is undocumented. The MCP spec does not require argument descriptions, so this is advisory only."
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::PromptDescription
    }
    fn risk_category(&self) -> RiskCategory {
        RiskCategory::MetadataHygiene
    }
    fn bucket(&self) -> ScoreBucket {
        ScoreBucket::Metadata
    }
    fn tags(&self) -> &'static [&'static str] {
        &["prompts", "description", "arguments"]
    }

    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding> {
        let mut findings = Vec::new();
        for prompt in &server.prompts {
            let missing: Vec<&str> = prompt
                .arguments
                .iter()
                .filter(|a| {
                    a.description
                        .as_deref()
                        .map(|s| s.trim().is_empty())
                        .unwrap_or(true)
                })
                .map(|a| a.name.as_str())
                .collect();
            if missing.is_empty() {
                continue;
            }
            let evidence = vec![
                format!("prompt_name={}", prompt.name),
                format!(
                    "arguments_missing_description=[{}]",
                    missing
                        .iter()
                        .map(|n| format!("'{n}'"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ];
            findings.push(self.make_prompt_finding(
                format!(
                    "Prompt {} has {} argument(s) without description.",
                    single_quoted_repr(&prompt.name),
                    missing.len()
                ),
                evidence,
                Some(prompt.name.clone()),
                BTreeMap::new(),
            ));
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{NormalizedPrompt, NormalizedPromptArgument};

    fn prompt(name: &str, description: Option<&str>) -> NormalizedPrompt {
        NormalizedPrompt {
            name: name.to_string(),
            description: description.map(String::from),
            arguments: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    fn prompt_with_args(
        name: &str,
        description: Option<&str>,
        args: Vec<NormalizedPromptArgument>,
    ) -> NormalizedPrompt {
        NormalizedPrompt {
            name: name.to_string(),
            description: description.map(String::from),
            arguments: args,
            metadata: BTreeMap::new(),
        }
    }

    fn arg(name: &str, description: Option<&str>) -> NormalizedPromptArgument {
        NormalizedPromptArgument {
            name: name.to_string(),
            description: description.map(String::from),
            required: None,
        }
    }

    #[test]
    fn duplicate_prompt_names_fires_once_per_duplicate() {
        let mut server = NormalizedServer::new("test");
        server.prompts.push(prompt("summarize", Some("desc")));
        server.prompts.push(prompt("summarize", Some("desc2")));
        server.prompts.push(prompt("translate", Some("d")));
        let findings = DuplicatePromptNames.evaluate(&server);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].prompt_name.as_deref(), Some("summarize"));
        assert_eq!(findings[0].tool_name, None);
    }

    #[test]
    fn missing_description_fires_on_none_and_empty() {
        let mut server = NormalizedServer::new("test");
        server.prompts.push(prompt("a", None));
        server.prompts.push(prompt("b", Some("   ")));
        server.prompts.push(prompt("c", Some("real description")));
        let findings = MissingPromptDescription.evaluate(&server);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].prompt_name.as_deref(), Some("a"));
        assert_eq!(findings[1].prompt_name.as_deref(), Some("b"));
    }

    #[test]
    fn description_matches_name_detects_stub() {
        let mut server = NormalizedServer::new("test");
        server
            .prompts
            .push(prompt("write_file", Some("Write File")));
        server
            .prompts
            .push(prompt("summarize", Some("Summarises input text")));
        let findings = PromptDescriptionMatchesName.evaluate(&server);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].prompt_name.as_deref(), Some("write_file"));
    }

    #[test]
    fn argument_missing_description_fires_per_prompt() {
        let mut server = NormalizedServer::new("test");
        server.prompts.push(prompt_with_args(
            "translate",
            Some("translate text"),
            vec![arg("text", None), arg("lang", Some("target language"))],
        ));
        let findings = PromptArgumentMissingDescription.evaluate(&server);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence[1].contains("'text'"));
    }

    #[test]
    fn argument_rule_silent_when_all_described() {
        let mut server = NormalizedServer::new("test");
        server.prompts.push(prompt_with_args(
            "translate",
            Some("translate"),
            vec![
                arg("text", Some("source text")),
                arg("lang", Some("target language")),
            ],
        ));
        assert!(PromptArgumentMissingDescription
            .evaluate(&server)
            .is_empty());
    }

    #[test]
    fn duplicate_argument_name_fires_once_per_prompt() {
        let mut server = NormalizedServer::new("test");
        server.prompts.push(prompt_with_args(
            "merge",
            Some("merge two inputs"),
            vec![
                arg("input", Some("first")),
                arg("input", Some("second")),
                arg("output", Some("destination")),
            ],
        ));
        let findings = PromptDuplicateArgumentName.evaluate(&server);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].prompt_name.as_deref(), Some("merge"));
        assert!(findings[0].evidence[1].contains("'input'"));
    }

    #[test]
    fn description_too_short_threshold() {
        let mut server = NormalizedServer::new("test");
        server.prompts.push(prompt("a", Some("Summarise."))); // 10 chars → fires
        server
            .prompts
            .push(prompt("b", Some("Summarise the input text."))); // 25 chars → clean
        server.prompts.push(prompt("c", None)); // skipped — other rule handles
        let findings = PromptDescriptionTooShort.evaluate(&server);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].prompt_name.as_deref(), Some("a"));
    }
}
