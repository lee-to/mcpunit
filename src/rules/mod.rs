//! Rules engine — trait definition and the static registry.
//!
//! Every check mcpunit performs is a type implementing [`Rule`]. Rules are
//! registered in [`REGISTRY`] as `&'static dyn Rule`, which gives us:
//!
//! * zero heap allocation per scan (the whole registry is compile-time),
//! * deterministic iteration order (slice declaration = on-wire order),
//! * exhaustive compile-time discovery — forgetting to register a rule is
//!   loud because [`REGISTRY`] is the only way anything reaches
//!   [`crate::scoring`].
//!
//! Rules are grouped by [`FindingCategory`] into four sub-modules so a
//! reader can see every identity rule, every schema rule, and so on in one
//! place:
//!
//! * [`identity`]    — 2 rules on tool names.
//! * [`description`] — 2 rules on tool descriptions.
//! * [`schema`]      — 4 rules on input schemas.
//! * [`capability`]  — 9 rules on what the tool can actually do.
//!
//! Adding a new rule is a three-step dance: implement the trait on a
//! zero-sized struct in the right sub-module, add it to [`REGISTRY`], add
//! at least one unit test.

use crate::models::{
    Finding, FindingCategory, MetadataMap, NormalizedServer, RiskCategory, ScoreBucket, Severity,
};

pub mod helpers;

pub mod capability;
pub mod description;
pub mod identity;
pub mod schema;

/// A single audit check.
///
/// Rules are zero-sized unit structs implementing this trait; all of their
/// state lives in their type so `&'static dyn Rule` references are cheap.
///
/// The [`Rule::make_finding`] helper is the only sanctioned way to build a
/// [`Finding`] from inside a rule — it stamps every finding with the rule's
/// metadata (id, title, category, bucket, severity-derived penalty) so the
/// reporters can trust the fields without re-validating them.
pub trait Rule: Sync {
    /// Stable identifier (JSON `rule_id` / SARIF `ruleId`). Must never
    /// change after a rule ships — users track findings by this string.
    fn id(&self) -> &'static str;

    /// Short human-readable title.
    fn title(&self) -> &'static str;

    /// One-paragraph rationale shown in SARIF `help.text` and terminal
    /// output.
    fn rationale(&self) -> &'static str;

    /// Severity — drives score penalty and SARIF level.
    fn severity(&self) -> Severity;

    /// Orthogonal classification of what part of the tool contract is
    /// being checked.
    fn category(&self) -> FindingCategory;

    /// Which risk surface this rule covers.
    fn risk_category(&self) -> RiskCategory;

    /// Score bucket for aggregation.
    fn bucket(&self) -> ScoreBucket;

    /// Optional free-form tags (SARIF `properties.tags`).
    fn tags(&self) -> &'static [&'static str] {
        &[]
    }

    /// Run the check and return zero or more findings.
    fn evaluate(&self, server: &NormalizedServer) -> Vec<Finding>;

    /// Build a [`Finding`] with all of this rule's metadata filled in.
    ///
    /// `evidence` is the list of heuristic tokens / patterns that triggered
    /// the finding — reporters serialise it verbatim, so rules must produce
    /// stable strings.
    ///
    /// Takes owned `String` / `Vec<String>` rather than `impl Into<String>`
    /// because the trait must stay object-safe for the `&'static dyn Rule`
    /// references in [`REGISTRY`].
    fn make_finding(
        &self,
        message: String,
        evidence: Vec<String>,
        tool_name: Option<String>,
        metadata: MetadataMap,
    ) -> Finding {
        let severity = self.severity();
        Finding {
            rule_id: self.id().to_string(),
            level: severity,
            message,
            title: Some(self.title().to_string()),
            category: self.category(),
            risk_category: self.risk_category(),
            bucket: self.bucket(),
            evidence,
            penalty: severity.score_impact(),
            tool_name,
            metadata,
        }
    }
}

/// Static, zero-allocation rule registry.
///
/// Rules land here in the exact order they should appear in audit output.
/// **Do not sort this slice at runtime** — the scoring contract uses this
/// order and reporters serialise `findings` + `rules` + `category_scores`
/// in this exact sequence.
pub const REGISTRY: &[&'static dyn Rule] = &[
    &identity::DuplicateNames,
    &description::MissingDescription,
    &identity::GenericName,
    &description::VagueDescription,
    &schema::MissingType,
    &schema::ArbitraryProperties,
    &schema::WeakInput,
    &schema::MissingRequiredCritical,
    &capability::ExecTool,
    &capability::ShellDownloadExec,
    &capability::FsWrite,
    &capability::FsDelete,
    &capability::HttpRequest,
    &capability::Network,
    &capability::UnscopedWrite,
    &capability::DestructiveDescription,
    &capability::ResponseTooLarge,
];

/// Iterate the registry in declaration order.
pub fn all() -> impl Iterator<Item = &'static dyn Rule> {
    REGISTRY.iter().copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct DummyRule;

    impl Rule for DummyRule {
        fn id(&self) -> &'static str {
            "dummy_rule"
        }
        fn title(&self) -> &'static str {
            "Dummy title"
        }
        fn rationale(&self) -> &'static str {
            "For tests only"
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
            ScoreBucket::Metadata
        }
        fn evaluate(&self, _server: &NormalizedServer) -> Vec<Finding> {
            vec![self.make_finding(
                "example".to_string(),
                vec!["evidence-1".into()],
                Some("sample_tool".into()),
                BTreeMap::new(),
            )]
        }
    }

    #[test]
    fn make_finding_stamps_rule_metadata() {
        let rule = DummyRule;
        let server = NormalizedServer::new("target");
        let findings = rule.evaluate(&server);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.rule_id, "dummy_rule");
        assert_eq!(f.title.as_deref(), Some("Dummy title"));
        assert_eq!(f.level, Severity::Warning);
        assert_eq!(f.penalty, 10);
        assert_eq!(f.category, FindingCategory::ToolIdentity);
        assert_eq!(f.bucket, ScoreBucket::Metadata);
        assert_eq!(f.tool_name.as_deref(), Some("sample_tool"));
        assert_eq!(f.evidence, vec!["evidence-1".to_string()]);
    }

    #[test]
    fn registry_has_seventeen_rules_in_declared_order() {
        // 4 catalogue-hygiene rules (identity + description) +
        // 4 schema rules + 9 capability rules = 17.
        assert_eq!(REGISTRY.len(), 17);

        // Head: catalogue hygiene (identity + description interleaved).
        assert_eq!(REGISTRY[0].id(), "duplicate_tool_names");
        assert_eq!(REGISTRY[1].id(), "missing_tool_description");
        assert_eq!(REGISTRY[2].id(), "overly_generic_tool_name");

        // Tail: the newest rule.
        assert_eq!(REGISTRY.last().unwrap().id(), "response_too_large");
    }

    #[test]
    fn registry_ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for rule in REGISTRY.iter() {
            assert!(seen.insert(rule.id()), "duplicate rule id: {}", rule.id());
        }
    }

    #[test]
    fn all_iterates_registry_length() {
        assert_eq!(all().count(), REGISTRY.len());
    }
}
